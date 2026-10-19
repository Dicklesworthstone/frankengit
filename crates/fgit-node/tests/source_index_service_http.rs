#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real TCP serving and native persisted source writes while the listener's
//! runtime owns incremental maintenance. No subprocess or replacement index.
#[path = "source_http/support.rs"]
mod support;
use fgit_forge::patch::PatchLimits;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::index_maintenance::{IndexKind, MaintenanceConfig};
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
    let directory = root.0.join("maintenance");
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
    fn start(node: OneNode, root: &Scratch, config: MaintenanceConfig) -> Self {
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
