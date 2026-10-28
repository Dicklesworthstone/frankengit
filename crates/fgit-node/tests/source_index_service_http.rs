#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real TCP serving and native persisted source writes while the listener's
//! runtime owns incremental maintenance. No subprocess or replacement index.
#[path = "source_http/support.rs"]
mod support;
use fgit_forge::patch::PatchLimits;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::index_maintenance::{IndexKind, MaintenanceConfig, MaintenanceGroup};
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
use std::fs;
use std::io;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use support::*;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn progress(root: &Scratch) -> PathBuf {
    named_progress(root, "maintenance")
}
fn named_progress(root: &Scratch, name: &str) -> PathBuf {
    let directory = root.0.join(name);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    directory
}
fn maintenance(
    kind: IndexKind,
    format: GitHashAlgorithm,
    directory: &Path,
    initialize: bool,
) -> MaintenanceConfig {
    MaintenanceConfig::try_new(
        kind,
        format,
        directory.into(),
        initialize,
        Duration::from_secs(1),
        vec![reference()],
    )
    .unwrap()
}
fn add_file(node: &OneNode, base: GitOid, name: &str, contents: &str, ordinal: u8) -> GitOid {
    let patch = format!(
        "diff --git a/{name} b/{name}\nnew file mode 100644\n--- /dev/null\n+++ b/{name}\n@@ -0,0 +1 @@\n+{contents}\n"
    );
    let metadata = MergeMetadata {
        author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(),
        timestamp: u64::from(ordinal) + 2,
        message: b"maintained source fixture\n".to_vec(),
    };
    let context = node.request_context();
    let prepared = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &context,
            &reference(),
            base,
            [ordinal; 16],
            patch.as_bytes(),
            &metadata,
            PatchLimits::default(),
        ))
        .unwrap();
    let key = format!("http-maintained-source-{ordinal}");
    let result = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &context,
            OWNER,
            key.as_bytes(),
            &reference(),
            base,
            prepared.candidate_commit,
            prepared.bundle_bytes(),
        ))
        .unwrap();
    assert!(!result.commands.is_empty());
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    prepared.candidate_commit
}
struct MaintainedServer {
    client: Endpoint,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<GitDaemonServerReceipt, String>>>,
}
impl MaintainedServer {
    fn start(node: OneNode, root: &Scratch, config: impl Into<MaintenanceGroup>) -> Self {
        let config = config.into();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint {
            address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec())
                .unwrap(),
        };
        let credentials_path = root.0.join("credentials");
        credentials(&node, &credentials_path);
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = Arc::clone(&stop);
        let (sender, ready) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let result = node
                .serve_repository_http_with_index_maintenance_until_stopped(
                    &listener,
                    2,
                    &credentials_path,
                    false,
                    true,
                    false,
                    false,
                    config,
                    &|| Ok(child_stop.load(Ordering::Acquire)),
                    &|| {
                        sender
                            .send(())
                            .map_err(|_| io::Error::other("test readiness receiver left"))
                    },
                )
                .map_err(|error| error.to_string());
            let cleanup = node.shutdown().map_err(|error| error.to_string());
            match (result, cleanup) {
                (Ok(receipt), Ok(())) => Ok(receipt),
                (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
                (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
            }
        });
        let server = Self {
            client,
            stop,
            worker: Some(worker),
        };
        ready
            .recv_timeout(Duration::from_secs(30))
            .expect("authenticated controller readiness");
        server
    }
    fn finish(mut self) -> GitDaemonServerReceipt {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap()
    }
}
impl Drop for MaintainedServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn query(
    client: &Endpoint,
    kind: IndexKind,
    format: GitHashAlgorithm,
    word: &[u8],
    commit: GitOid,
) -> Reply {
    let (route, input) = match kind {
        IndexKind::Lexical => ("search-index", format!("term_hex={}", hex(word))),
        IndexKind::Symbols => (
            "search-symbols-index",
            format!("name_hex={}&match=exact", hex(word)),
        ),
    };
    post(
        client,
        route,
        'a',
        &format!("{}&{input}&expected_commit={commit}", common(format)),
        false,
    )
}
fn wait_for_index(
    client: &Endpoint,
    kind: IndexKind,
    format: GitHashAlgorithm,
    word: &[u8],
    commit: GitOid,
) -> Reply {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let reply = query(client, kind, format, word, commit);
        if reply.status == 200 {
            assert_eq!(text(&reply.body, "source_commit"), commit.to_string());
            match kind {
                IndexKind::Lexical => {
                    assert!(number(&reply.body, "returned_hits") > 0, "{}", reply.raw)
                }
                IndexKind::Symbols => {
                    assert!(number(&reply.body, "returned_matches") > 0, "{}", reply.raw)
                }
            }
            return reply;
        }
        assert_eq!(reply.status, 409, "{}", reply.raw);
        assert!(
            Instant::now() < deadline,
            "maintenance did not catch up: {}",
            reply.raw
        );
        thread::sleep(Duration::from_millis(300));
    }
}

fn group(
    format: GitHashAlgorithm,
    directories: &[PathBuf; 2],
    initialize: bool,
) -> MaintenanceGroup {
    MaintenanceGroup::try_new(vec![
        maintenance(IndexKind::Lexical, format, &directories[0], initialize),
        maintenance(IndexKind::Symbols, format, &directories[1], initialize),
    ])
    .unwrap()
}

fn initial_form(format: GitHashAlgorithm, word: &[u8], commit: GitOid) -> String {
    format!(
        "{}&term_hex={}&symbol_name_hex={}&symbol_match=exact&symbol_policy=required&expected_commit={commit}",
        common(format),
        hex(word),
        hex(word),
    )
}

fn wait_for_initial(
    client: &Endpoint,
    format: GitHashAlgorithm,
    word: &[u8],
    commit: GitOid,
) -> Reply {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let reply = post(
            client,
            "search-initial",
            'a',
            &initial_form(format, word, commit),
            false,
        );
        if reply.status == 200 {
            assert_eq!(text(&reply.body, "type"), "source_search_initial");
            assert_eq!(text(&reply.body, "phase"), "Initial");
            assert!(
                reply
                    .body
                    .split_once("\"complete\":")
                    .unwrap()
                    .1
                    .starts_with("true"),
                "{}",
                reply.raw
            );
            assert_eq!(text(&reply.body, "source_commit"), commit.to_string());
            assert!(number(&reply.body, "returned_hits") > 0, "{}", reply.raw);
            assert_eq!(number(&reply.body, "returned_matches"), 1, "{}", reply.raw);
            assert!(
                reply
                    .body
                    .contains("\"symbols\":{\"state\":\"available\",\"result\":{"),
                "{}",
                reply.raw
            );
            // Top-level and every returned channel retain the exact current
            // commit; catch-up cannot serve a vector assembled from old source.
            let mut sources = 0;
            for field in reply.body.split("\"source_commit\":\"").skip(1) {
                assert_eq!(field.split('"').next().unwrap(), commit.to_string());
                sources += 1;
            }
            assert!(sources >= 4, "missing channel provenance: {}", reply.raw);
            return reply;
        }
        assert_eq!(reply.status, 409, "{}", reply.raw);
        assert!(
            Instant::now() < deadline,
            "both maintained channels did not catch up: {}",
            reply.raw
        );
        thread::sleep(Duration::from_millis(300));
    }
}

fn generation_vector(reply: &Reply) -> &str {
    reply
        .body
        .split_once("\"generation_vector\":")
        .unwrap()
        .1
        .split_once(",\"max_results_per_channel\":")
        .unwrap()
        .0
}

fn channel_token<'a>(reply: &'a Reply, channel: &str) -> &'a str {
    text(
        generation_vector(reply)
            .split_once(&format!("\"{channel}\":"))
            .unwrap()
            .1,
        "index_token",
    )
}

#[test]
fn dual_profile_http_maintenance_keeps_required_initial_current_and_resumes_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, original) = fixture(&root, format);
        let base = add_file(&node, original, "before.rs", "pub fn ServiceBefore() {}", 1);
        let canonical_before = generation(&node);
        let directories = [
            named_progress(&root, "lexical-maintenance"),
            named_progress(&root, "symbol-maintenance"),
        ];
        let server = MaintainedServer::start(node, &root, group(format, &directories, true));
        let first = wait_for_initial(&server.client, format, b"ServiceBefore", base);
        status(
            &post(
                &server.client,
                "search-initial",
                'b',
                &initial_form(format, b"ServiceBefore", base),
                false,
            ),
            403,
        );
        let writer = reopen(&config);
        assert_eq!(generation(&writer), canonical_before);
        let commit = add_file(&writer, base, "after.rs", "pub fn ServiceAfter() {}", 2);
        let canonical_after = generation(&writer);
        writer.shutdown().unwrap();
        let updated = wait_for_initial(&server.client, format, b"ServiceAfter", commit);
        for channel in ["lexical", "symbols"] {
            assert_ne!(
                channel_token(&first, channel),
                channel_token(&updated, channel)
            );
        }
        assert!(server.finish().accepted_sessions() >= 3);
        let checkpoints = directories.each_ref().map(|directory| {
            assert!(!directory.join("run.lock").exists());
            assert!(directory.join("owner.lock").is_file());
            fs::read(directory.join("checkpoint")).unwrap()
        });

        let node = reopen(&config);
        assert_eq!(generation(&node), canonical_after);
        let resumed = MaintainedServer::start(node, &root, group(format, &directories, false));
        let again = wait_for_initial(&resumed.client, format, b"ServiceAfter", commit);
        assert_eq!(generation_vector(&updated), generation_vector(&again));
        resumed.finish();
        for (directory, checkpoint) in directories.iter().zip(checkpoints) {
            assert!(!directory.join("run.lock").exists());
            assert_eq!(fs::read(directory.join("checkpoint")).unwrap(), checkpoint);
        }
        let node = reopen(&config);
        assert_eq!(generation(&node), canonical_after);
        node.shutdown().unwrap();
    }
}

#[test]
fn second_live_progress_owner_refuses_group_readiness_and_drains_first_owner() {
    let root = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let config = root.config(format);
    let (node, original) = fixture(&root, format);
    let commit = add_file(&node, original, "owned.rs", "pub fn AlreadyOwned() {}", 1);
    let before = generation(&node);
    let directories = [
        named_progress(&root, "lexical-maintenance"),
        named_progress(&root, "symbol-maintenance"),
    ];
    // A real separate serving lifetime owns Symbols. The attempted group may
    // neither steal it nor strand its own earlier Lexical child on refusal.
    let owner = MaintainedServer::start(
        reopen(&config),
        &root,
        maintenance(IndexKind::Symbols, format, &directories[1], true),
    );
    let original_symbols = wait_for_index(
        &owner.client,
        IndexKind::Symbols,
        format,
        b"AlreadyOwned",
        commit,
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let ready = AtomicBool::new(false);
    let requested = MaintenanceGroup::try_new(vec![
        maintenance(IndexKind::Lexical, format, &directories[0], true),
        maintenance(IndexKind::Symbols, format, &directories[1], false),
    ])
    .unwrap();
    let error = node
        .serve_repository_http_with_index_maintenance_bounded(
            &listener,
            GitDaemonServerLimits::try_new(1, 1).unwrap(),
            &root.0.join("credentials"),
            false,
            false,
            false,
            false,
            Duration::from_secs(1),
            requested,
            &|| {
                ready.store(true, Ordering::Release);
                Ok(())
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("maintenance"));
    assert!(!ready.load(Ordering::Acquire));
    assert!(directories[0].join("checkpoint").is_file());
    assert!(!directories[0].join("run.lock").exists());
    assert!(directories[1].join("run.lock").is_file());
    assert_eq!(generation(&node), before);
    let absent_lexical = query(
        &owner.client,
        IndexKind::Lexical,
        format,
        b"AlreadyOwned",
        commit,
    );
    status(&absent_lexical, 409);
    assert!(absent_lexical.body.contains("source_index_uninitialized"));
    let still_owned = wait_for_index(
        &owner.client,
        IndexKind::Symbols,
        format,
        b"AlreadyOwned",
        commit,
    );
    assert_eq!(
        text(&original_symbols.body, "index_token"),
        text(&still_owned.body, "index_token")
    );
    owner.finish();
    assert!(!directories[1].join("run.lock").exists());

    let resumed = MaintainedServer::start(node, &root, group(format, &directories, false));
    wait_for_initial(&resumed.client, format, b"AlreadyOwned", commit);
    resumed.finish();
    for directory in &directories {
        assert!(!directory.join("run.lock").exists());
    }
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn readiness_output_failure_drains_both_owners_before_any_native_index_attempt() {
    let root = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let config = root.config(format);
    let (node, original) = fixture(&root, format);
    let commit = add_file(&node, original, "ready.rs", "pub fn ReadyFailure() {}", 1);
    let before = generation(&node);
    let directories = [
        named_progress(&root, "lexical-maintenance"),
        named_progress(&root, "symbol-maintenance"),
    ];
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let both_owned_at_readiness = AtomicBool::new(false);
    let error = node
        .serve_repository_http_with_index_maintenance_bounded(
            &listener,
            GitDaemonServerLimits::try_new(1, 1).unwrap(),
            &path,
            false,
            false,
            false,
            false,
            Duration::from_secs(1),
            group(format, &directories, true),
            &|| {
                both_owned_at_readiness.store(
                    directories
                        .iter()
                        .all(|directory| directory.join("run.lock").is_file()),
                    Ordering::Release,
                );
                Err(io::Error::other("readiness output unavailable"))
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("readiness output unavailable"));
    assert!(both_owned_at_readiness.load(Ordering::Acquire));
    for directory in &directories {
        assert!(directory.join("checkpoint").is_file());
        assert!(directory.join("owner.lock").is_file());
        assert!(!directory.join("run.lock").exists());
    }
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
    // Read through the ordinary production HTTP path with maintenance disabled:
    // neither first nor second controller may publish before global readiness.
    let reader = Server::start(reopen(&config), &path, 2, true, false);
    for (kind, code) in [
        (IndexKind::Lexical, "source_index_uninitialized"),
        (IndexKind::Symbols, "symbol_index_uninitialized"),
    ] {
        let reply = query(&reader.client, kind, format, b"ReadyFailure", commit);
        status(&reply, 409);
        assert!(reply.body.contains(code), "{}", reply.raw);
    }
    reader.finish();
    let resumed =
        MaintainedServer::start(reopen(&config), &root, group(format, &directories, false));
    wait_for_initial(&resumed.client, format, b"ReadyFailure", commit);
    resumed.finish();
    for directory in &directories {
        assert!(!directory.join("run.lock").exists());
    }
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
#[test]
fn live_http_maintenance_builds_and_refreshes_lexical_and_symbols_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for kind in [IndexKind::Lexical, IndexKind::Symbols] {
            let root = Scratch::new();
            let config = root.config(format);
            let (node, original) = fixture(&root, format);
            let (base, before_word) = match kind {
                IndexKind::Lexical => (original, b"needle".as_slice()),
                IndexKind::Symbols => (
                    add_file(&node, original, "before.rs", "pub fn ServiceBefore() {}", 1),
                    b"ServiceBefore".as_slice(),
                ),
            };
            let before_generation = generation(&node);
            let directory = progress(&root);
            let server =
                MaintainedServer::start(node, &root, maintenance(kind, format, &directory, true));
            let first = wait_for_index(&server.client, kind, format, before_word, base);
            let refused = post(&server.client, "tree", 'b', &common(format), false);
            status(&refused, 403);
            let writer = reopen(&config);
            assert_eq!(generation(&writer), before_generation);
            let (name, contents, word) = match kind {
                IndexKind::Lexical => ("after.txt", "serviceafter", b"serviceafter".as_slice()),
                IndexKind::Symbols => (
                    "after.rs",
                    "pub fn ServiceAfter() {}",
                    b"ServiceAfter".as_slice(),
                ),
            };
            let commit = add_file(&writer, base, name, contents, 2);
            let after_generation = generation(&writer);
            writer.shutdown().unwrap();
            let updated = wait_for_index(&server.client, kind, format, word, commit);
            assert_ne!(
                text(&first.body, "index_token"),
                text(&updated.body, "index_token")
            );
            assert!(server.finish().accepted_sessions() >= 3);
            assert!(
                !directory.join("run.lock").exists(),
                "stop releases progress after drain"
            );
            assert!(directory.join("checkpoint").is_file());
            let node = reopen(&config);
            assert_eq!(
                generation(&node),
                after_generation,
                "index maintenance must not advance repository authority"
            );
            let resumed =
                MaintainedServer::start(node, &root, maintenance(kind, format, &directory, false));
            let again = wait_for_index(&resumed.client, kind, format, word, commit);
            assert_eq!(
                text(&updated.body, "index_token"),
                text(&again.body, "index_token")
            );
            resumed.finish();
            assert!(!directory.join("run.lock").exists());
        }
    }
}
#[test]
fn invalid_maintenance_progress_refuses_http_readiness_and_preserves_checkpoint() {
    let root = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let (node, _) = fixture(&root, format);
    let before = generation(&node);
    let directory = progress(&root);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let ready = AtomicBool::new(false);
    let error = node
        .serve_repository_http_with_index_maintenance_bounded(
            &listener,
            GitDaemonServerLimits::try_new(1, 1).unwrap(),
            &path,
            false,
            false,
            false,
            false,
            Duration::from_secs(1),
            maintenance(IndexKind::Lexical, format, &directory, false),
            &|| {
                ready.store(true, Ordering::Release);
                Ok(())
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("maintenance"));
    assert!(!ready.load(Ordering::Acquire));
    assert!(!directory.join("checkpoint").exists());
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
#[test]
fn http_stop_control_failure_still_drains_and_releases_maintenance() {
    let root = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let (node, _) = fixture(&root, format);
    let directory = progress(&root);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let error = node
        .serve_repository_http_with_index_maintenance_until_stopped(
            &listener,
            1,
            &path,
            false,
            false,
            false,
            false,
            maintenance(IndexKind::Lexical, format, &directory, true),
            &|| Err(io::Error::other("operator stop unavailable")),
            &|| Ok(()),
        )
        .unwrap_err();
    assert!(error.to_string().contains("operator stop unavailable"));
    assert!(!directory.join("run.lock").exists());
    assert!(directory.join("checkpoint").is_file());
    node.shutdown().unwrap();
}
