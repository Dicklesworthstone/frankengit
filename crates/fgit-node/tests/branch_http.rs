#![forbid(unsafe_code)]
//! Real TCP -> native empty-pack quarantine -> sealed atomic admission -> reopen.
//! Reuse the source API's imported native-object fixture and HTTP client.
#[path = "source_http/support.rs"]
mod support;
use support::*;

use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

struct BranchServer { client: Endpoint, worker: Option<JoinHandle<GitDaemonServerReceipt>> }
impl BranchServer {
    fn start(node: OneNode, path: &Path, count: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint { address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap() };
        let path = path.to_owned();
        let worker = thread::spawn(move || {
            let result = node.serve_repository_http_with_source_bounded(&listener,
                GitDaemonServerLimits::try_new(count, 2).unwrap(), &path,
                true, false, true, false, Duration::from_secs(5));
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self { client, worker: Some(worker) }
    }
    fn finish(mut self) -> GitDaemonServerReceipt { self.worker.take().unwrap().join().unwrap() }
}
impl Drop for BranchServer {
    fn drop(&mut self) { if let Some(worker) = self.worker.take() { let _ = worker.join(); } }
}
fn grants(node: &OneNode, path: &Path) -> String {
    let header = credentials(node, path);
    replace(path, &(header.clone() + &row('a', OWNER, "read") + &row('b', OWNER, "receive")
        + &row('c', OWNER, "outcomes-read") + &row('d', FOREIGN, "receive") + &row('e', FOREIGN, "outcomes-read")));
    header
}
fn base(node: &OneNode, commit: GitOid) -> GitOid {
    let object = node.read_git_object(commit).unwrap();
    let text = std::str::from_utf8(object.payload()).unwrap();
    GitOid::from_hex(commit.algorithm(), text.lines().find_map(|line| line.strip_prefix("parent ")).unwrap()).unwrap()
}
fn create(format: GitHashAlgorithm, name: &str, new: GitOid) -> String {
    format!("object_format={}&ref={name}&new_commit={new}", format.as_str())
}
fn update(format: GitHashAlgorithm, name: &str, old: GitOid, new: GitOid) -> String {
    format!("object_format={}&ref={name}&expected_commit={old}&new_commit={new}", format.as_str())
}
fn delete(format: GitHashAlgorithm, name: &str, old: GitOid) -> String {
    format!("object_format={}&ref={name}&expected_commit={old}", format.as_str())
}
fn rename(format: GitHashAlgorithm, old_name: &str, new_name: &str, old: GitOid) -> String {
    delete(format, old_name, old) + &format!("&new_ref={new_name}")
}
fn wire(client: &Endpoint, action: &str, token: char, key: &str, form: &str, chunked: bool) -> Vec<u8> {
    let (body, framing) = if chunked {
        let mut body = Vec::new();
        for part in form.as_bytes().chunks(11) {
            body.extend(format!("{:x}\r\n", part.len()).as_bytes());
            body.extend(part); body.extend(b"\r\n");
        }
        body.extend(b"0\r\n\r\n"); (body, "Transfer-Encoding: chunked\r\n".to_owned())
    } else { (form.as_bytes().to_vec(), format!("Content-Length: {}\r\n", form.len())) };
    request(client, &format!("/api/v1/source/branches/{action}"), token,
        &format!("Content-Type: application/x-www-form-urlencoded\r\nIdempotency-Key: {key}\r\n{framing}"), &body)
}
fn change(client: &Endpoint, action: &str, key: &str, form: &str, chunked: bool) -> Reply {
    exchange(client, &wire(client, action, 'b', key, form, chunked), true)
}
fn accepted(reply: &Reply) {
    status(reply, 200);
    assert!(reply.body.contains("\"type\":\"branch_publication\""));
    assert!(reply.body.contains("\"atomic\":true,\"terminal\":true"));
    assert!(reply.body.contains("\"outcome\":\"committed\""));
    assert_eq!(reply.body.matches("\"tx_id\"").count(), 1);
}
fn refused(reply: &Reply) {
    status(reply, 409); assert!(reply.body.contains("\"outcome\":\"refused\""));
    assert!(reply.body.contains("\"atomic\":true"));
}
fn list(client: &Endpoint, format: GitHashAlgorithm, extra: &str) -> Reply {
    post(client, "refs", 'a', &format!("object_format={}{extra}", format.as_str()), false)
}
fn recover(client: &Endpoint, token: char, key: &str) -> Reply {
    exchange(client, &request(client, "/api/v1/outcomes", token,
        &format!("Content-Length: 0\r\nIdempotency-Key: {key}\r\n"), &[]), true)
}
fn contains_ref(reply: &Reply, name: &str, oid: GitOid) -> bool {
    reply.body.contains(&format!("\"ref\":\"{name}\",\"ref_hex\":\"{}\",\"object_id\":\"{oid}\"", hex(name.as_bytes())))
}

#[test]
fn branch_lifecycle_and_original_transactions_survive_rename_delete_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, tip) = fixture(&root, format); let parent = base(&node, tip);
        let original = node.runtime().block_on(node.materialize_admission()).unwrap();
        let before = generation(&node);
        let path = root.0.join("credentials"); grants(&node, &path);
        let server = BranchServer::start(node, &path, 14);
        let initial = list(&server.client, format, "&limit=1"); // 1
        status(&initial, 200); assert!(contains_ref(&initial, "refs/heads/main", tip));
        let creation = create(format, "refs/heads/topic", parent);
        let created = change(&server.client, "create", "topic-create", &creation, true); // 2
        accepted(&created);
        let first = list(&server.client, format, "&namespace=branches&limit=1"); // 3
        status(&first, 200); assert_eq!(text(&first.body, "next_after"), "refs/heads/main");
        let advance = update(format, "refs/heads/topic", parent, tip);
        let advanced = change(&server.client, "update", "topic-update", &advance, false); // 4
        accepted(&advanced);
        let stale = list(&server.client, format, &format!("&namespace=branches&after=refs/heads/main&expected_head={}", token(&first))); // 5
        status(&stale, 409); assert!(stale.body.contains("source_snapshot_moved"));
        let renaming = rename(format, "refs/heads/topic", "refs/heads/renamed", tip);
        let renamed = change(&server.client, "rename", "topic-rename", &renaming, false); // 6
        accepted(&renamed); assert_eq!(renamed.body.matches("\"force\":false").count(), 2);
        assert_eq!(change(&server.client, "rename", "topic-rename", &renaming, true), renamed); // 7
        let rows = list(&server.client, format, ""); // 8
        status(&rows, 200); assert!(contains_ref(&rows, "refs/heads/renamed", tip));
        assert!(!rows.body.contains("\"ref\":\"refs/heads/topic\""));
        let removal = delete(format, "refs/heads/renamed", tip);
        let removed = change(&server.client, "delete", "topic-delete", &removal, true); // 9
        accepted(&removed);
        assert_eq!(change(&server.client, "create", "topic-create", &creation, false), created); // 10
        assert_eq!(change(&server.client, "rename", "topic-rename", &renaming, false), renamed); // 11
        let conflict = change(&server.client, "create", "topic-create", &create(format, "refs/heads/different", tip), false); // 12
        status(&conflict, 409); assert!(conflict.body.contains("idempotency_key_reuse"));
        let tags = list(&server.client, format, "&namespace=tags"); // 13
        status(&tags, 200); assert!(tags.body.contains("\"refs\":[]"));
        let final_page = list(&server.client, format, ""); // 14
        status(&final_page, 200); assert!(contains_ref(&final_page, "refs/heads/main", tip));
        assert_eq!(server.finish().accepted_sessions(), 14);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 4);
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs, original.snapshot().refs);
        assert_eq!(selected.snapshot().head_target, original.snapshot().head_target);
        assert_eq!(selected.snapshot().outbox, original.snapshot().outbox);
        assert_eq!(selected.basis().body().forge_position_root, original.basis().body().forge_position_root);
        assert_eq!(selected.selected_closure().closure(), original.selected_closure().closure());
        let server = BranchServer::start(node, &path, 3);
        assert_eq!(change(&server.client, "delete", "topic-delete", &removal, false), removed);
        assert_eq!(change(&server.client, "update", "topic-update", &advance, true), advanced);
        assert_eq!(list(&server.client, format, ""), final_page);
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 4); node.shutdown().unwrap();
    }
}

#[test]
fn conflicting_and_competing_renames_never_publish_half_a_move() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, tip) = fixture(&root, format); let parent = base(&node, tip); let before = generation(&node);
        let path = root.0.join("credentials"); grants(&node, &path);
        let server = BranchServer::start(node, &path, 11);
        accepted(&change(&server.client, "create", "source", &create(format, "refs/heads/source", parent), false)); // 1
        accepted(&change(&server.client, "create", "occupied", &create(format, "refs/heads/occupied", tip), false)); // 2
        let collision = rename(format, "refs/heads/source", "refs/heads/occupied", parent);
        let collided = change(&server.client, "rename", "collision", &collision, true); // 3
        refused(&collided);
        let rows = list(&server.client, format, ""); // 4
        status(&rows, 200); assert!(contains_ref(&rows, "refs/heads/source", parent));
        assert!(contains_ref(&rows, "refs/heads/occupied", tip));
        assert_eq!(change(&server.client, "rename", "collision", &collision, false), collided); // 5
        refused(&change(&server.client, "rename", "stale-tip",
            &rename(format, "refs/heads/source", "refs/heads/unused", tip), false)); // 6
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for destination in ["refs/heads/winner-a", "refs/heads/winner-b"] {
            let client = server.client.clone(); let barrier = Arc::clone(&barrier);
            let form = rename(format, "refs/heads/source", destination, parent);
            workers.push(thread::spawn(move || {
                barrier.wait();
                (destination, form.clone(), change(&client, "rename", destination, &form, true))
            }));
        } // 7, 8: actual competing TCP publications, not a local state model.
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|(_, _, reply)| reply.status == 200).count(), 1);
        assert_eq!(results.iter().filter(|(_, _, reply)| reply.status == 409).count(), 1);
        let winner = results.iter().find(|(_, _, reply)| reply.status == 200).unwrap().0;
        for (_, _, reply) in &results { if reply.status == 200 { accepted(reply); } else { refused(reply); } }
        let rows = list(&server.client, format, ""); // 9
        status(&rows, 200); assert!(contains_ref(&rows, winner, parent));
        assert!(!rows.body.contains("\"ref\":\"refs/heads/source\""));
        for (destination, form, reply) in &results {
            assert_eq!(change(&server.client, "rename", destination, form, false), *reply); // 10, 11
        }
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 6);
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs.len(), 3);
        assert_eq!(selected.snapshot().refs[&RefName::try_new(winner.as_bytes()).unwrap()], parent);
        assert_eq!(selected.snapshot().refs[&RefName::try_new(b"refs/heads/occupied").unwrap()], tip);
        node.shutdown().unwrap();
    }
}

#[test]
fn client_lost_rename_receipts_recover_read_only_and_keys_remain_principal_scoped() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, tip) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); let header = grants(&node, &path);
        let server = BranchServer::start(node, &path, 2);
        accepted(&change(&server.client, "create", "create", &create(format, "refs/heads/source", tip), false));
        let form = rename(format, "refs/heads/source", "refs/heads/recovered", tip);
        let mut socket = TcpStream::connect(server.client.address).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
        socket.write_all(&wire(&server.client, "rename", 'b', "lost-rename", &form, false)).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        // The server finishes while the client never reads/stores its receipt.
        // This models a lost client receipt, not an injected pre-CAS crash.
        server.finish(); drop(socket);
        let node = reopen(&config); assert_eq!(generation(&node), before + 2);
        replace(&path, &(header.clone() + &row('a', OWNER, "read") + &row('c', OWNER, "outcomes-read")));
        let readonly = Server::start(node, &path, 4, true, false);
        let recovered = recover(&readonly.client, 'c', "lost-rename"); // 1
        status(&recovered, 200); assert!(recovered.body.contains("\"state\":\"committed\""));
        let rows = list(&readonly.client, format, ""); // 2
        status(&rows, 200); assert!(contains_ref(&rows, "refs/heads/recovered", tip));
        status(&exchange(&readonly.client, &wire(&readonly.client, "rename", 'b', "lost-rename", &form, false), true), 401); // 3
        replace(&path, &(header + &row('a', OWNER, "read") + &row('9', OWNER, "receive")
            + &row('c', OWNER, "outcomes-read") + &row('d', FOREIGN, "receive") + &row('e', FOREIGN, "outcomes-read")));
        status(&exchange(&readonly.client, &wire(&readonly.client, "rename", '9', "lost-rename", &form, false), true), 403); // 4
        readonly.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 2);
        let server = BranchServer::start(node, &path, 4);
        let retried = exchange(&server.client, &wire(&server.client, "rename", '9', "lost-rename", &form, true), true); // 1
        accepted(&retried); assert_eq!(text(&retried.body, "tx_id"), text(&recovered.body, "tx_id"));
        assert_eq!(number(&retried.body, "decision_sequence"), number(&recovered.body, "decision_sequence"));
        let other = exchange(&server.client, &wire(&server.client, "create", 'd', "lost-rename",
            &create(format, "refs/heads/foreign", tip), false), true); // 2
        accepted(&other); assert_ne!(text(&other.body, "tx_id"), text(&retried.body, "tx_id"));
        let foreign = recover(&server.client, 'e', "lost-rename"); // 3
        assert_eq!(text(&foreign.body, "tx_id"), text(&other.body, "tx_id"));
        assert_eq!(recover(&server.client, 'c', "lost-rename"), recovered); // 4
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 3); node.shutdown().unwrap();
    }
}

#[test]
fn scopes_default_branch_native_kind_and_complete_envelopes_precede_publication() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new(); let config = root.config(format);
    let (node, tip) = fixture(&root, format); let before = generation(&node);
    let path = root.0.join("credentials"); grants(&node, &path);
    let disabled = Server::start(node, &path, 1, false, false);
    status(&list(&disabled.client, format, ""), 403); disabled.finish();
    let node = reopen(&config); let server = BranchServer::start(node, &path, 13);
    let command = create(format, "refs/heads/new", tip);
    let denied = request(&server.client, "/api/v1/source/branches/create", 'a',
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\nIdempotency-Key: denied\r\n", &[]);
    let reply = exchange(&server.client, &denied, false); // 1
    status(&reply, 403); assert!(!reply.raw.contains("100 Continue"));
    status(&post(&server.client, "refs", 'b', "object_format=sha256", false), 403); // 2
    let missing_key = request(&server.client, "/api/v1/source/branches/create", 'b',
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\n", &[]);
    let reply = exchange(&server.client, &missing_key, false); // 3
    status(&reply, 400); assert!(!reply.raw.contains("100 Continue"));
    status(&change(&server.client, "create", "force", &(command.clone() + "&force=true"), false), 400); // 4
    status(&change(&server.client, "create", "tag", &create(format, "refs/tags/no", tip), false), 400); // 5
    let reply = change(&server.client, "delete", "default-delete", &delete(format, "refs/heads/main", tip), false); // 6
    status(&reply, 409); assert!(reply.body.contains("branch_operation_refused"));
    status(&change(&server.client, "rename", "default-rename", &rename(format, "refs/heads/main", "refs/heads/other", tip), false), 409); // 7
    let blob = git_object_id(format, GitObjectKind::Blob, TEXT);
    let reply = change(&server.client, "create", "blob", &create(format, "refs/heads/blob", blob), false); // 8
    status(&reply, 409); assert!(reply.body.contains("branch_target_not_commit"));
    let truncated = request(&server.client, "/api/v1/source/branches/create", 'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: truncated\r\n", command.len() + 1), command.as_bytes());
    status(&exchange(&server.client, &truncated, true), 400); // 9
    let chunked = format!("{:x}\r\n{command}\r\n0\r\n", command.len());
    status(&exchange(&server.client, &request(&server.client, "/api/v1/source/branches/create", 'b',
        "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nIdempotency-Key: chunk-truncated\r\n", chunked.as_bytes()), true), 400); // 10
    let absent = recover(&server.client, 'c', "truncated"); // 11
    status(&absent, 200); assert!(absent.body.contains("\"state\":\"key_not_observed\""));
    status(&post(&server.client, "tree", 'a', &common(format), false), 200); // 12: existing source reader unaffected.
    let rows = list(&server.client, format, ""); // 13
    status(&rows, 200); assert!(contains_ref(&rows, "refs/heads/main", tip));
    assert_eq!(rows.body.matches("\"object_id\"").count(), 1);
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before); node.shutdown().unwrap();
}
