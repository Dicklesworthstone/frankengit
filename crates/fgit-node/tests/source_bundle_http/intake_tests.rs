use super::*;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};
use fgit_types::{DecisionOutcome, GitOid, RefName};
use std::path::Path;
use std::thread::{self, JoinHandle};

struct WriteServer {
    client: Endpoint,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
    count: usize,
}
impl WriteServer {
    fn start(node: OneNode, path: &Path, count: usize, receive: bool) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint {
            address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec())
                .unwrap(),
        };
        let path = path.to_path_buf();
        let worker = thread::spawn(move || {
            let result = node.serve_repository_http_with_source_bounded(
                &listener,
                GitDaemonServerLimits::try_new(count, 2).unwrap(),
                &path,
                receive,
                false,
                true,
                false,
                Duration::from_secs(5),
            );
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self {
            client,
            worker: Some(worker),
            count,
        }
    }
    fn finish(mut self) {
        assert_eq!(
            self.worker
                .take()
                .unwrap()
                .join()
                .unwrap()
                .accepted_sessions(),
            self.count
        );
    }
}
impl Drop for WriteServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn empty(root: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}
fn source_bundle(root: &Scratch, format: GitHashAlgorithm) -> (Vec<u8>, GitOid, GitOid) {
    let (node, main) = fixture(root, format);
    let tree = git_object_id(format, GitObjectKind::Tree, b"");
    let body = format!(
        "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nbase\n"
    );
    let base = git_object_id(format, GitObjectKind::Commit, body.as_bytes());
    assert!(node.read_git_object(base).is_ok());
    let command = RefCommand {
        name: RefName::try_new(b"refs/heads/base").unwrap(),
        expected_old: ExpectedOld::Absent,
        proposed_new: ProposedNew::Update(base),
        force: false,
    };
    let session = LoopbackReceiveSession::authenticated(
        OWNER,
        IdempotencyKey::new(b"export-base-branch".to_vec()).unwrap(),
    );
    let result = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &node.request_context(),
            &session,
            &[command],
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, false);
    let reply = export(
        &server.client,
        'a',
        &format!("object_format={}", format.as_str()),
        "",
        false,
    );
    assert_eq!(reply.status, 200);
    assert_eq!(server.finish().accepted_sessions(), 1);
    (reply.body, base, main)
}
fn form(bundle: &[u8], format: GitHashAlgorithm) -> String {
    format!(
        "object_format={}&artifact_sha256={}",
        format.as_str(),
        hex(&sha256_digest(bundle))
    )
}
fn mapped(bundle: &[u8], format: GitHashAlgorithm, source: &str, old: Option<GitOid>) -> String {
    format!(
        "{}&mapping={}:{}:{}",
        form(bundle, format),
        hex(source.as_bytes()),
        hex(b"refs/remotes/transfer/main"),
        old.map_or_else(|| "absent".into(), |id| id.to_string())
    )
}
fn upload(
    client: &Endpoint,
    action: &str,
    token: char,
    key: Option<&str>,
    form: &str,
    bundle: &[u8],
    chunked: bool,
) -> Vec<u8> {
    let mut body = b"--transfer\r\nContent-Disposition: form-data; name=\"command\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n".to_vec();
    body.extend_from_slice(form.as_bytes());
    body.extend_from_slice(b"\r\n--transfer\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"../../ignored.bundle\"\r\nContent-Type: application/x-git-bundle\r\n\r\n");
    body.extend_from_slice(bundle);
    body.extend_from_slice(b"\r\n--transfer--\r\n");
    let (body, framing) = if chunked {
        let mut wire = Vec::new();
        for part in body.chunks(23) {
            wire.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            wire.extend_from_slice(part);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".into())
    } else {
        let length = body.len();
        (body, format!("Content-Length: {length}\r\n"))
    };
    let key = key.map_or_else(String::new, |key| format!("Idempotency-Key: {key}\r\n"));
    request(
        client,
        &format!("/api/v1/source/bundle/{action}"),
        token,
        &format!("Content-Type: multipart/form-data; boundary=transfer\r\n{framing}{key}"),
        &body,
    )
}
fn send(
    server: &WriteServer,
    action: &str,
    key: &str,
    form: &str,
    bundle: &[u8],
    chunked: bool,
) -> Reply {
    exchange(
        &server.client,
        &upload(
            &server.client,
            action,
            'b',
            Some(key),
            form,
            bundle,
            chunked,
        ),
        true,
    )
}
fn refs(node: &OneNode) -> std::collections::BTreeMap<RefName, GitOid> {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
        .snapshot()
        .refs
        .clone()
}

#[test]
fn export_import_roundtrip_is_atomic_and_terminal_replay_survives_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let origin = Scratch::new();
        let (bundle, base, main) = source_bundle(&origin, format);
        let root = Scratch::new();
        let config = root.config(format);
        let node = empty(&root, format);
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap();
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = WriteServer::start(node, &path, 2, true);
        let form = form(&bundle, format);
        let first = send(&server, "import", "whole-transfer", &form, &bundle, false);
        status(&first, 200);
        assert_eq!(text(&first.body, "outcome"), "committed");
        assert_eq!(number(&first.body, "command_count"), 2);
        assert!(first.body.contains("\"atomic\":true,\"terminal\":true"));
        assert_eq!(text(&first.body, "principal_id"), FOREIGN.to_string());
        let replay = send(&server, "import", "whole-transfer", &form, &bundle, true);
        assert_eq!(replay, first);
        server.finish();
        let node = reopen(&config);
        let committed = generation(&node);
        let snapshot = node
            .runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap();
        assert_eq!(snapshot.snapshot().refs.len(), 2);
        assert_eq!(
            snapshot.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()],
            main
        );
        assert_eq!(
            snapshot.snapshot().refs[&RefName::try_new(b"refs/heads/base").unwrap()],
            base
        );
        assert_eq!(
            snapshot.snapshot().head_target,
            before.snapshot().head_target
        );
        assert_eq!(
            snapshot.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_eq!(snapshot.snapshot().outbox, before.snapshot().outbox);
        let server = WriteServer::start(node, &path, 2, true);
        assert_eq!(
            send(&server, "import", "whole-transfer", &form, &bundle, false),
            first
        );
        let blob = post(
            &server.client,
            "blob",
            'a',
            &(common(format) + "&path_hex=" + &hex(BINARY_PATH)),
            false,
        );
        status(&blob, 200);
        assert_eq!(text(&blob.body, "content_hex"), hex(BINARY));
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), committed);
        node.shutdown().unwrap();
    }
}

#[test]
fn one_existing_destination_ref_refuses_the_whole_import_without_a_new_ref_prefix() {
    let origin = Scratch::new();
    let (bundle, _, _) = source_bundle(&origin, GitHashAlgorithm::Sha1);
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let before = refs(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = WriteServer::start(node, &path, 2, true);
    let form = form(&bundle, GitHashAlgorithm::Sha1);
    let refused = send(&server, "import", "collision", &form, &bundle, false);
    status(&refused, 409);
    assert_eq!(text(&refused.body, "outcome"), "refused");
    assert_eq!(number(&refused.body, "command_count"), 2);
    assert_eq!(
        send(&server, "import", "collision", &form, &bundle, true),
        refused
    );
    server.finish();
    let node = reopen(&config);
    assert_eq!(refs(&node), before);
    assert!(!refs(&node).contains_key(&RefName::try_new(b"refs/heads/base").unwrap()));
    node.shutdown().unwrap();
}

#[test]
fn mapped_fetch_selects_only_named_objects_fast_forwards_and_preserves_old_replays() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let origin = Scratch::new();
        let (bundle, base, main) = source_bundle(&origin, format);
        let root = Scratch::new();
        let config = root.config(format);
        let node = empty(&root, format);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = WriteServer::start(node, &path, 1, true);
        let initial = mapped(&bundle, format, "refs/heads/base", None);
        let first = send(&server, "fetch", "fetch-base", &initial, &bundle, false);
        status(&first, 200);
        assert_eq!(number(&first.body, "command_count"), 1);
        server.finish();
        let node = reopen(&config);
        assert_eq!(refs(&node).len(), 1);
        assert_eq!(
            refs(&node)[&RefName::try_new(b"refs/remotes/transfer/main").unwrap()],
            base
        );
        assert!(node.read_git_object(base).is_ok());
        assert!(
            node.read_git_object(main).is_err(),
            "unselected exclusive object was imported"
        );
        let server = WriteServer::start(node, &path, 3, true);
        let advance = mapped(&bundle, format, "refs/heads/main", Some(base));
        let next = send(&server, "fetch", "fetch-main", &advance, &bundle, true);
        status(&next, 200);
        assert_eq!(text(&next.body, "outcome"), "committed");
        // An old terminal replay must not reinterpret its expected-absent lease
        // against the now-advanced destination or attempt to roll it back.
        assert_eq!(
            send(&server, "fetch", "fetch-base", &initial, &bundle, false),
            first
        );
        let stale = send(&server, "fetch", "stale-lease", &advance, &bundle, false);
        status(&stale, 409);
        assert_eq!(text(&stale.body, "outcome"), "refused");
        server.finish();
        let node = reopen(&config);
        assert_eq!(refs(&node).len(), 1);
        assert_eq!(
            refs(&node)[&RefName::try_new(b"refs/remotes/transfer/main").unwrap()],
            main
        );
        assert!(node.read_git_object(main).is_ok());
        node.shutdown().unwrap();
    }
}

#[test]
fn malformed_uploads_artifact_mismatch_and_read_only_credentials_do_not_publish() {
    let origin = Scratch::new();
    let (bundle, _, _) = source_bundle(&origin, GitHashAlgorithm::Sha1);
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let node = empty(&root, GitHashAlgorithm::Sha1);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = WriteServer::start(node, &path, 6, true);
    let form = form(&bundle, GitHashAlgorithm::Sha1);
    for (token, key, expected) in [
        ('a', Some("read-may-not-write"), 403),
        ('b', None, 400),
        ('f', Some("unknown"), 401),
    ] {
        let reply = exchange(
            &server.client,
            &upload(&server.client, "import", token, key, &form, &bundle, false),
            true,
        );
        status(&reply, expected);
    }
    let mut changed = bundle.clone();
    changed[0] ^= 1;
    let mismatch = send(&server, "import", "hash-mismatch", &form, &changed, false);
    status(&mismatch, 400);
    assert!(mismatch.body.contains("bundle_artifact_mismatch"));
    let mut truncated = upload(
        &server.client,
        "import",
        'b',
        Some("truncated"),
        &form,
        &bundle,
        true,
    );
    truncated.truncate(truncated.len() - 4);
    status(&exchange(&server.client, &truncated, true), 400);
    let malformed = b"not a Git bundle";
    status(
        &send(
            &server,
            "import",
            "malformed",
            &self::form(malformed, GitHashAlgorithm::Sha1),
            malformed,
            false,
        ),
        400,
    );
    server.finish();
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    assert!(refs(&node).is_empty());
    let server = WriteServer::start(node, &path, 1, false);
    status(
        &send(&server, "import", "write-disabled", &form, &bundle, false),
        403,
    );
    server.finish();
}

#[test]
fn disconnect_after_publication_recovers_the_original_transaction_without_duplicate_effects() {
    let origin = Scratch::new();
    let (bundle, _, _) = source_bundle(&origin, GitHashAlgorithm::Sha1);
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let node = empty(&root, GitHashAlgorithm::Sha1);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let form = form(&bundle, GitHashAlgorithm::Sha1);
    let server = WriteServer::start(node, &path, 1, true);
    let bytes = upload(
        &server.client,
        "import",
        'b',
        Some("lost-reply"),
        &form,
        &bundle,
        false,
    );
    let mut socket = TcpStream::connect(server.client.address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    socket.write_all(&bytes).unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    // One HTTP prefix byte proves the response started, but reveals no terminal
    // JSON receipt. Deliberately discard the rest rather than infer rollback.
    let mut prefix = [0];
    socket.read_exact(&mut prefix).unwrap();
    assert_eq!(prefix, [b'H']);
    drop(socket);
    server.finish();
    let node = reopen(&config);
    let committed = generation(&node);
    assert_eq!(refs(&node).len(), 2);
    let server = WriteServer::start(node, &path, 2, true);
    let recovered = send(&server, "import", "lost-reply", &form, &bundle, true);
    status(&recovered, 200);
    assert_eq!(text(&recovered.body, "outcome"), "committed");
    assert_eq!(
        send(&server, "import", "lost-reply", &form, &bundle, false),
        recovered
    );
    server.finish();
    let node = reopen(&config);
    assert_eq!(generation(&node), committed);
    assert_eq!(refs(&node).len(), 2);
    node.shutdown().unwrap();
}

#[test]
fn matching_transport_digest_cannot_admit_a_corrupt_pack_and_a_valid_retry_still_commits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let origin = Scratch::new();
        let (bundle, _, main) = source_bundle(&origin, format);
        let root = Scratch::new();
        let config = root.config(format);
        let node = empty(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = WriteServer::start(node, &path, 1, true);
        let mut corrupt = bundle.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        // Compute the correct transport digest OF the corrupt bytes: only native
        // pack verification can detect this, not the outer artifact check.
        let refused = send(
            &server,
            "import",
            "quarantine-retry",
            &form(&corrupt, format),
            &corrupt,
            false,
        );
        status(&refused, 503);
        assert!(refused.body.contains("\"outcome_unknown\":true"));
        assert!(!refused.body.contains("\"terminal\":true"));
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        assert!(refs(&node).is_empty());
        assert!(node.read_git_object(main).is_err());
        let server = WriteServer::start(node, &path, 1, true);
        let valid = send(
            &server,
            "import",
            "quarantine-retry",
            &form(&bundle, format),
            &bundle,
            true,
        );
        status(&valid, 200);
        assert_eq!(text(&valid.body, "outcome"), "committed");
        server.finish();
        let node = reopen(&config);
        assert_eq!(refs(&node).len(), 2);
        assert!(node.read_git_object(main).is_ok());
        node.shutdown().unwrap();
    }
}
