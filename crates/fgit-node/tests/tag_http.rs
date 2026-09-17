#![forbid(unsafe_code)]
//! Actual HTTP -> native tag objects/quarantine -> authority -> reopened reads.
//! No test-local ref store, synthetic tag admission, or signature trust oracle.
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
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryId, TenantId};

const INNER: &[u8] = b"refs/tags/release/\xff";
const MESSAGE: &[u8] = b"\xffrelease\r\nwithout-final-LF";
struct TagServer { client: Endpoint, worker: Option<JoinHandle<GitDaemonServerReceipt>> }
impl TagServer {
    fn start(node: OneNode, path: &Path, count: usize, source: bool, receive: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint { address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap() };
        let path = path.to_path_buf();
        let worker = thread::spawn(move || {
            let limits = GitDaemonServerLimits::try_new(count, 2).unwrap();
            let served = if source {
                node.serve_repository_http_with_source_bounded(&listener, limits, &path,
                    receive, false, true, false, Duration::from_secs(5))
            } else {
                node.serve_repository_http_with_credentials_file_bounded(&listener, limits, &path,
                    receive, false, true, Duration::from_secs(5))
            };
            node.shutdown().unwrap(); served.unwrap()
        });
        Self { client, worker: Some(worker) }
    }
    fn finish(mut self) -> GitDaemonServerReceipt { self.worker.take().unwrap().join().unwrap() }
}
impl Drop for TagServer { fn drop(&mut self) { if let Some(worker) = self.worker.take() { let _ = worker.join(); } } }
fn grants(node: &OneNode, path: &Path) -> String {
    let header = format!("frankengit-http-credentials-v1 {} {} {}\n", TenantId::from_bytes([0x31; 16]),
        RepositoryId::from_bytes([0x32; 16]), node.repository_incarnation_id());
    replace(path, &(header.clone() + &row('a', OWNER, "read") + &row('b', OWNER, "receive")
        + &row('c', OWNER, "outcomes-read") + &row('d', FOREIGN, "outcomes-read")));
    header
}
fn selection(format: GitHashAlgorithm, reference: &[u8]) -> String {
    format!("object_format={}&ref_hex={}", format.as_str(), hex(reference))
}
fn annotation(format: GitHashAlgorithm, reference: &[u8], target: GitOid, kind: &str, message: &[u8]) -> String {
    format!("{}&target={target}&target_kind={kind}&tagger=Release+Bot+%3Crelease%40example.invalid%3E&timestamp=0&message_hex={}",
        selection(format, reference), hex(message))
}
fn tag_body(reference: &[u8], target: GitOid, kind: &str, message: &[u8]) -> Vec<u8> {
    [format!("object {target}\ntype {kind}\ntag ").as_bytes(),
        reference.strip_prefix(b"refs/tags/").unwrap(),
        b"\ntagger Release Bot <release@example.invalid> 0 +0000\n\n", message].concat()
}
fn wire(client: &Endpoint, action: &str, token: char, key: Option<&str>, form: &str, chunked: bool) -> Vec<u8> {
    let mut headers = String::from("Content-Type: application/x-www-form-urlencoded\r\n");
    if let Some(key) = key { headers.push_str(&format!("Idempotency-Key: {key}\r\n")); }
    let body = if chunked {
        headers.push_str("Transfer-Encoding: chunked\r\n");
        let mut body = Vec::new();
        for part in form.as_bytes().chunks(17) {
            body.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            body.extend_from_slice(part); body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"0\r\n\r\n"); body
    } else {
        headers.push_str(&format!("Content-Length: {}\r\n", form.len())); form.as_bytes().to_vec()
    };
    request(client, &format!("/api/v1/source/tags/{action}"), token, &headers, &body)
}
fn send(client: &Endpoint, action: &str, token: char, key: Option<&str>, form: &str, chunked: bool) -> Reply {
    exchange(client, &wire(client, action, token, key, form, chunked), true)
}
fn inspect(client: &Endpoint, format: GitHashAlgorithm, reference: &[u8], extra: &str) -> Reply {
    send(client, "inspect", 'a', None, &(selection(format, reference) + extra), false)
}
fn committed(reply: &Reply) {
    status(reply, 200); assert!(reply.body.contains("\"type\":\"tag_publication\""));
    assert!(reply.body.contains("\"outcome\":\"committed\""));
    assert!(reply.body.contains("\"atomic\":true,\"terminal\":true"));
    assert!(reply.body.contains("\"force\":false"));
}
fn refused(reply: &Reply) {
    status(reply, 409); assert!(reply.body.contains("\"outcome\":\"refused\""));
    assert!(reply.body.contains("\"terminal\":true"));
}
fn recovered(client: &Endpoint, token: char, key: &str) -> Reply {
    exchange(client, &request(client, "/api/v1/outcomes", token,
        &format!("Content-Length: 0\r\nIdempotency-Key: {key}\r\n"), &[]), true)
}

#[test]
fn nested_tags_preserve_native_bytes_and_exact_delete_retries_do_not_resurrect() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, main) = fixture(&root, format); let before = generation(&node);
        let original = node.runtime().block_on(node.materialize_admission()).unwrap();
        let original_outbox = original.snapshot().outbox.clone();
        let original_forge = original.basis().body().forge_position_root;
        let path = root.0.join("credentials"); grants(&node, &path);
        let body = tag_body(INNER, main, "commit", MESSAGE);
        let inner = git_object_id(format, GitObjectKind::Tag, &body);
        let form = annotation(format, INNER, main, "commit", MESSAGE);
        let server = TagServer::start(node, &path, 14, true, true);
        let created = send(&server.client, "annotated", 'b', Some("inner"), &form, true); // 1
        committed(&created); assert_eq!(text(&created.body, "new_object"), inner.to_string());
        let read = inspect(&server.client, format, INNER, ""); // 2
        status(&read, 200); assert_eq!(text(&read.body, "body_hex"), hex(&body));
        assert_eq!(text(&read.body, "peeled_object"), main.to_string());
        assert_eq!(text(&read.body, "ref_hex"), hex(INNER));
        assert_eq!(send(&server.client, "annotated", 'b', Some("inner"), &form, false), created); // 3
        let alias = b"refs/tags/alias";
        committed(&send(&server.client, "lightweight", 'b', Some("alias"),
            &format!("{}&target={inner}", selection(format, alias)), false)); // 4
        let outer_name = b"refs/tags/outer";
        let outer_body = tag_body(outer_name, inner, "tag", b"outer\n");
        let outer = git_object_id(format, GitObjectKind::Tag, &outer_body);
        committed(&send(&server.client, "annotated", 'b', Some("outer"),
            &annotation(format, outer_name, inner, "tag", b"outer\n"), false)); // 5
        let outer_read = inspect(&server.client, format, outer_name, ""); // 6
        status(&outer_read, 200); assert_eq!(number(&outer_read.body, "annotation_count"), 2);
        assert_eq!(text(&outer_read.body, "object_id"), outer.to_string());
        assert_eq!(text(&outer_read.body, "peeled_object"), main.to_string());
        assert!(outer_read.body.contains(&hex(&body))); assert!(outer_read.body.contains(&hex(&outer_body)));
        let alias_read = inspect(&server.client, format, alias, ""); // 7
        status(&alias_read, 200); assert_eq!(number(&alias_read.body, "annotation_count"), 1);
        status(&inspect(&server.client, format, outer_name, "&max_tags=1"), 413); // 8
        let wrong_delete = selection(format, INNER) + &format!("&expected_object={main}");
        refused(&send(&server.client, "delete", 'b', Some("wrong-object"), &wrong_delete, false)); // 9
        status(&inspect(&server.client, format, INNER, &format!("&expected_object={inner}")), 200); // 10
        let deletion = selection(format, INNER) + &format!("&expected_object={inner}");
        committed(&send(&server.client, "delete", 'b', Some("delete"), &deletion, true)); // 11
        status(&inspect(&server.client, format, INNER, ""), 404); // 12
        assert_eq!(send(&server.client, "annotated", 'b', Some("inner"), &form, false), created); // 13
        let final_alias = inspect(&server.client, format, alias, ""); // 14
        status(&final_alias, 200);
        assert_eq!(server.finish().accepted_sessions(), 14);
        let node = reopen(&config); assert_eq!(generation(&node), before + 5);
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert!(!selected.snapshot().refs.contains_key(&RefName::try_new(INNER).unwrap()));
        assert_eq!(selected.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()], main);
        assert_eq!(selected.snapshot().outbox, original_outbox);
        assert_eq!(selected.basis().body().forge_position_root, original_forge);
        let server = TagServer::start(node, &path, 3, true, false);
        assert_eq!(inspect(&server.client, format, alias, ""), final_alias); // 1
        status(&inspect(&server.client, format, outer_name, &format!("&expected_head={}", token(&outer_read))), 409); // 2
        status(&inspect(&server.client, format, outer_name, ""), 200); // 3
        server.finish(); let node = reopen(&config); assert_eq!(generation(&node), before + 5); node.shutdown().unwrap();
    }
}

#[test]
fn competing_release_tags_have_one_winner_and_stable_refused_and_committed_retries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, main) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); grants(&node, &path);
        let server = TagServer::start(node, &path, 5, true, true);
        let barrier = Arc::new(Barrier::new(2)); let mut workers = Vec::new();
        for key in ["candidate-a", "candidate-b"] {
            let client = server.client.clone(); let barrier = Arc::clone(&barrier);
            let form = annotation(format, b"refs/tags/release", main, "commit", key.as_bytes());
            workers.push(thread::spawn(move || {
                barrier.wait(); let reply = send(&client, "annotated", 'b', Some(key), &form, true);
                (key, form, reply)
            }));
        } // 1, 2: two native requests race through real TCP and authority CAS.
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|(_, _, reply)| reply.status == 200).count(), 1);
        assert_eq!(results.iter().filter(|(_, _, reply)| reply.status == 409).count(), 1);
        let winner = results.iter().find(|(_, _, reply)| reply.status == 200).unwrap();
        let winner_id = text(&winner.2.body, "new_object").to_owned();
        let read = inspect(&server.client, format, b"refs/tags/release", ""); // 3
        status(&read, 200); assert_eq!(text(&read.body, "object_id"), winner_id);
        assert_eq!(text(&read.body, "body_hex"), hex(&tag_body(b"refs/tags/release", main, "commit", winner.0.as_bytes())));
        for (key, form, result) in &results { // 4, 5
            if result.status == 200 { committed(result); } else { refused(result); }
            assert_eq!(send(&server.client, "annotated", 'b', Some(key), form, false), *result);
        }
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 2);
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs[&RefName::try_new(b"refs/tags/release").unwrap()].to_string(), winner_id);
        assert_eq!(selected.snapshot().refs.len(), 2); node.shutdown().unwrap();
    }
}

#[test]
fn lost_release_receipt_recovers_after_restart_rotation_and_withdrawn_write_access() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, main) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); let header = grants(&node, &path);
        let name = b"refs/tags/lost";
        let form = annotation(format, name, main, "commit", MESSAGE);
        let object = git_object_id(format, GitObjectKind::Tag, &tag_body(name, main, "commit", MESSAGE));
        let server = TagServer::start(node, &path, 1, true, true);
        let mut socket = TcpStream::connect(server.client.address).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
        socket.write_all(&wire(&server.client, "annotated", 'b', Some("lost-tag"), &form, false)).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();
        // Client never reads the receipt. This is receipt loss, not a simulated
        // pre-CAS crash or an assertion that disconnect cancelled publication.
        server.finish(); drop(socket);
        let node = reopen(&config); assert_eq!(generation(&node), before + 1);
        replace(&path, &(header.clone() + &row('a', OWNER, "read") + &row('c', OWNER, "outcomes-read")
            + &row('d', FOREIGN, "outcomes-read")));
        let server = TagServer::start(node, &path, 5, true, false);
        let outcome = recovered(&server.client, 'c', "lost-tag"); // 1
        status(&outcome, 200); assert!(outcome.body.contains("\"state\":\"committed\""));
        status(&inspect(&server.client, format, name, ""), 200); // 2
        status(&send(&server.client, "annotated", 'b', Some("lost-tag"), &form, false), 401); // 3
        replace(&path, &(header + &row('a', OWNER, "read") + &row('9', OWNER, "receive")
            + &row('c', OWNER, "outcomes-read") + &row('d', FOREIGN, "outcomes-read")));
        status(&send(&server.client, "annotated", '9', Some("lost-tag"), &form, true), 403); // 4
        let foreign = recovered(&server.client, 'd', "lost-tag"); // 5
        status(&foreign, 200); assert!(foreign.body.contains("\"state\":\"key_not_observed\""));
        server.finish(); let node = reopen(&config); assert_eq!(generation(&node), before + 1);
        let server = TagServer::start(node, &path, 4, true, true);
        let retry = send(&server.client, "annotated", '9', Some("lost-tag"), &form, false); // 1
        committed(&retry); assert_eq!(text(&retry.body, "tx_id"), text(&outcome.body, "tx_id"));
        committed(&send(&server.client, "delete", '9', Some("remove"),
            &(selection(format, name) + &format!("&expected_object={object}")), false)); // 2
        assert_eq!(send(&server.client, "annotated", '9', Some("lost-tag"), &form, true), retry); // 3
        status(&inspect(&server.client, format, name, ""), 404); // 4
        server.finish(); let node = reopen(&config); assert_eq!(generation(&node), before + 2); node.shutdown().unwrap();
    }
}

fn withheld(client: &Endpoint, action: &str, token: char, key: Option<&str>, length: usize) -> Reply {
    let mut headers = format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n");
    if let Some(key) = key { headers.push_str(&format!("Idempotency-Key: {key}\r\n")); }
    let reply = exchange(client, &request(client, &format!("/api/v1/source/tags/{action}"), token, &headers, &[]), false);
    assert!(!reply.raw.contains("100 Continue")); reply
}
#[test]
fn scopes_complete_bodies_and_actual_kinds_gate_creation_and_signatures_never_grant_trust() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new(); let config = root.config(format);
    let (node, main) = fixture(&root, format); let before = generation(&node);
    let path = root.0.join("credentials"); grants(&node, &path);
    let disabled = TagServer::start(node, &path, 1, false, true);
    status(&withheld(&disabled.client, "annotated", 'b', Some("disabled"), 10), 403);
    disabled.finish();
    let node = reopen(&config); let server = TagServer::start(node, &path, 14, true, true);
    status(&withheld(&server.client, "lightweight", 'a', Some("read-cannot-write"), 10), 403); // 1
    status(&withheld(&server.client, "inspect", 'b', None, 10), 403); // 2
    status(&withheld(&server.client, "annotated", 'b', None, 10), 400); // 3
    status(&withheld(&server.client, "inspect", 'a', Some("not-a-mutation"), 10), 400); // 4
    let form = annotation(format, b"refs/tags/signed-looking", main, "commit", b"release\n-----BEGIN SSH SIGNATURE-----\nnot-a-signature\n-----END SSH SIGNATURE-----\n");
    status(&send(&server.client, "annotated", 'b', Some("kind-mismatch"),
        &form.replace("target_kind=commit", "target_kind=blob"), false), 503); // 5
    status(&send(&server.client, "annotated", 'b', Some("wrong-domain"), &form.replace("sha256", "sha1"), false), 400); // 6
    let incomplete = request(&server.client, "/api/v1/source/tags/annotated", 'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: incomplete\r\n", form.len() + 1), form.as_bytes());
    status(&exchange(&server.client, &incomplete, true), 400); // 7
    let chunks = format!("{:x}\r\n{form}\r\n0\r\n", form.len());
    let incomplete = request(&server.client, "/api/v1/source/tags/annotated", 'b',
        "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nIdempotency-Key: truncated-chunks\r\n", chunks.as_bytes());
    status(&exchange(&server.client, &incomplete, true), 400); // 8
    status(&withheld(&server.client, "annotated", 'b', Some("oversize"), 256 * 1024 + 1), 413); // 9
    committed(&send(&server.client, "annotated", 'b', Some("opaque"), &form, true)); // 10
    let narrow = inspect(&server.client, format, b"refs/tags/signed-looking", "&max_total_bytes=1"); // 11
    assert!(matches!(narrow.status, 413 | 503)); assert!(!narrow.body.contains("\"annotations\":[]"));
    let read = inspect(&server.client, format, b"refs/tags/signed-looking", ""); // 12
    status(&read, 200); assert!(read.body.contains("\"signature\":\"opaque_unverifiable\""));
    assert!(!read.body.contains("\"signature_verified\":true"));
    assert!(read.body.contains("\"tagger_is_authenticated_principal\":false"));
    status(&inspect(&server.client, format, b"refs/tags/signed-looking", &format!("&expected_object={main}")), 409); // 13
    status(&inspect(&server.client, format, b"refs/heads/main", ""), 400); // 14
    server.finish(); let node = reopen(&config); assert_eq!(generation(&node), before + 1);
    assert_eq!(node.runtime().block_on(node.materialize_admission()).unwrap().snapshot().refs.len(), 2);
    node.shutdown().unwrap();
}
