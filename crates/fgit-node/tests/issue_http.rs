#![forbid(unsafe_code)]
//! TCP -> authenticated issue API -> real embedded authority -> reopened state.
//! No replacement HTTP server, fake projection, or synthetic issue database.

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fgit_crypto::sha256_digest;
use fgit_forge::IssueNumber;
use fgit_forge::event::issue::IssueState;
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionTimeout, NodeConfig, OneNode};
use fgit_types::{GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-issue-http-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn config(root: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.0.join("node"), TenantId::from_bytes([0x91; 16]), RepositoryId::from_bytes([0x92; 16]))
        .with_object_format(format)
        .with_git_daemon_session_timeout(GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap())
}
fn start_node(config: NodeConfig) -> OneNode {
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}
fn reopened(config: NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config).unwrap();
    let generation = node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation();
    node.bring_into_service(generation).unwrap();
    node
}
fn principal(byte: u8) -> PrincipalId { PrincipalId::from_bytes([byte; 16]) }
fn row(token: char, principal: u8, scope: &str) -> String {
    let digest: String = sha256_digest(token.to_string().repeat(64).as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    format!("{digest} {} {scope}\n", self::principal(principal))
}
fn replace(path: &Path, text: &str) {
    let next = path.with_extension("next");
    fs::write(&next, text).unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::rename(next, path).unwrap();
}
fn grants(node: &OneNode, path: &Path) -> String {
    let header = format!("frankengit-http-credentials-v1 {} {} {}\n",
        TenantId::from_bytes([0x91; 16]), RepositoryId::from_bytes([0x92; 16]), node.repository_incarnation_id());
    replace(path, &(header.clone() + &row('a', 0xa1, "issues-read") + &row('b', 0xb1, "issues-write")
        + &row('c', 0xc1, "issues-read,issues-write") + &row('d', 0xd1, "read,receive")));
    header
}
struct Server {
    address: SocketAddr,
    route: String,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Server {
    fn start(node: OneNode, path: PathBuf, requests: usize, issues: bool) -> Self {
        let route = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let limits = GitDaemonServerLimits::try_new(requests, 2).unwrap();
            let served = if issues {
                node.serve_git_and_issue_http_with_credentials_file_bounded(&listener, limits, &path, false, Duration::from_secs(3))
            } else {
                node.serve_smart_http_with_credentials_file_bounded(&listener, limits, &path, false, Duration::from_secs(3))
            };
            node.shutdown().unwrap();
            served.unwrap()
        });
        Self { address, route, worker: Some(worker) }
    }
    fn finish(mut self) -> GitDaemonServerReceipt { self.worker.take().unwrap().join().unwrap() }
}
impl Drop for Server {
    fn drop(&mut self) { if let Some(worker) = self.worker.take() { let _ = worker.join(); } }
}
#[derive(Debug)]
struct Reply { status: u16, body: String, raw: String }
fn exchange(address: SocketAddr, bytes: &[u8], half_close: bool) -> Reply {
    let mut socket = TcpStream::connect(address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
    for chunk in bytes.chunks(13) { socket.write_all(chunk).unwrap(); }
    if half_close { socket.shutdown(Shutdown::Write).unwrap(); }
    let mut response = Vec::new();
    (&mut socket).take(8 * 1024 * 1024).read_to_end(&mut response).unwrap();
    let raw = String::from_utf8(response).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length: usize = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().trim().parse().unwrap();
    assert_eq!(length, body.len());
    Reply { status, body: body.to_owned(), raw }
}
fn auth(token: char) -> String { format!("Authorization: Bearer {}\r\n", token.to_string().repeat(64)) }
fn request(server: &Server, method: &str, suffix: &str, token: char, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{method} {}{suffix} HTTP/1.1\r\nHost: local\r\n{}{headers}\r\n", server.route, auth(token)).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn get(server: &Server, suffix: &str, token: char) -> Reply {
    exchange(server.address, &request(server, "GET", suffix, token, "", b""), false)
}
fn post(server: &Server, suffix: &str, token: char, key: &str, body: &str, chunked: bool) -> Reply {
    let wire = if chunked {
        let mut out = Vec::new();
        for bytes in body.as_bytes().chunks(5) {
            out.extend_from_slice(format!("{:x}\r\n", bytes.len()).as_bytes());
            out.extend_from_slice(bytes);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    } else { body.as_bytes().to_vec() };
    let framing = if chunked { "Transfer-Encoding: chunked\r\n".to_owned() }
        else { format!("Content-Length: {}\r\n", wire.len()) };
    let headers = format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}Idempotency-Key: {key}\r\n");
    exchange(server.address, &request(server, "POST", suffix, token, &headers, &wire), false)
}
fn status(reply: &Reply, expected: u16) { assert_eq!(reply.status, expected, "{}", reply.raw); }
fn token(reply: &Reply) -> String {
    reply.body.split_once("\"snapshot_token\":\"").unwrap().1.split('"').next().unwrap().to_owned()
}
fn committed(reply: &Reply) {
    status(reply, 200);
    assert!(reply.body.contains("\"type\":\"issue_publication\""));
    assert!(reply.body.contains("\"outcome\":\"committed\""));
}

#[test]
fn full_issue_lifecycle_has_stable_retries_exact_pages_and_reopened_authority_state() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = start_node(configuration.clone());
        let before = node.runtime().block_on(node.materialize_admission()).unwrap().basis().generation();
        let path = root.0.join("credentials");
        grants(&node, &path);
        let server = Server::start(node, path, 18, true);
        let open = "expected_version=0&title=Alpha&body=hello+%F0%9F%A6%80%0A%22quoted%22&label=z&label=a";
        let original = post(&server, "/api/v1/issues/1/open", 'b', "open-one", open, true); // 1
        committed(&original);
        assert!(original.body.contains(&principal(0xb1).to_string()));
        let retry = post(&server, "/api/v1/issues/1/open", 'b', "open-one", open, false); // 2
        assert_eq!(retry.body, original.body);
        let first = get(&server, "/api/v1/issues/1?limit=1", 'a'); // 3
        status(&first, 200);
        assert!(first.body.contains("hello 🦀\\u000a\\\"quoted\\\""));
        assert!(first.body.contains("\"labels\":[\"a\",\"z\"]"));
        let old = token(&first);
        committed(&post(&server, "/api/v1/issues/1/comment", 'b', "comment-one", "expected_version=1&body=first+comment", false)); // 4
        let stale_page = get(&server, &format!("/api/v1/issues/1?expected_head={old}"), 'a'); // 5
        status(&stale_page, 409);
        assert!(stale_page.body.contains("\"code\":\"snapshot_moved\""));
        committed(&post(&server, "/api/v1/issues/1/edit", 'b', "edit-one", "expected_version=2&title=Beta&body=&clear_labels=true", true)); // 6
        committed(&post(&server, "/api/v1/issues/1/close", 'b', "close-one", "expected_version=3", false)); // 7
        committed(&post(&server, "/api/v1/issues/1/reopen", 'b', "reopen-one", "expected_version=4", false)); // 8
        committed(&post(&server, "/api/v1/issues/2/open", 'c', "open-two", "expected_version=0&title=Second&body=", false)); // 9
        let page = get(&server, "/api/v1/issues?limit=1", 'a'); // 10
        status(&page, 200);
        assert!(page.body.contains("\"next_after\":1"));
        let continuation = get(&server, &format!("/api/v1/issues?limit=1&after=1&expected_head={}", token(&page)), 'a'); // 11
        status(&continuation, 200);
        assert!(continuation.body.contains("\"number\":2"));
        assert!(continuation.body.contains("\"next_after\":null"));
        let history = get(&server, "/api/v1/issues/1?limit=2", 'a'); // 12
        status(&history, 200);
        assert!(history.body.contains("\"version\":5"));
        assert!(history.body.contains("\"next_after_version\":2"));
        let history_token = token(&history);
        let second = get(&server, &format!("/api/v1/issues/1?limit=2&after_version=2&expected_head={history_token}"), 'a'); // 13
        status(&second, 200);
        assert!(second.body.contains("\"name\":\"edit\""));
        assert!(second.body.contains("\"next_after_version\":4"));
        let last = get(&server, &format!("/api/v1/issues/1?limit=2&after_version=4&expected_head={history_token}"), 'a'); // 14
        status(&last, 200);
        assert!(last.body.contains("\"name\":\"reopen\""));
        assert!(last.body.contains("\"next_after_version\":null"));
        let stale = post(&server, "/api/v1/issues/1/edit", 'b', "stale-edit", "expected_version=1&title=Overwrite", false); // 15
        status(&stale, 409);
        assert!(stale.body.contains("\"outcome\":\"refused\""));
        let retried = post(&server, "/api/v1/issues/1/edit", 'b', "stale-edit", "expected_version=1&title=Overwrite", true); // 16
        assert_eq!(retried.body, stale.body);
        let conflict = post(&server, "/api/v1/issues/1/open", 'b', "open-one", "expected_version=0&title=Changed&body=", false); // 17
        status(&conflict, 409);
        assert!(conflict.body.contains("\"code\":\"idempotency_key_reuse\""));
        let missing = get(&server, "/api/v1/issues/999", 'a'); // 18
        status(&missing, 404);
        assert!(missing.body.contains("\"found\":false"));
        assert_eq!(server.finish().accepted_sessions(), 18);

        let node = reopened(configuration);
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.basis().generation().get(), before.get() + 7, "six commits and one refusal, no retry publications");
        assert!(selected.snapshot().refs.is_empty());
        let history = node.runtime().block_on(node.read_issue_history_in(&node.request_context(),
            IssueNumber::try_new(1).unwrap(), 0, 10, None)).unwrap();
        let issue = history.issue.unwrap();
        assert_eq!(issue.version.get(), 5);
        assert_eq!(history.events.len(), 5);
        assert_eq!(issue.title, "Beta");
        assert!(issue.body.is_empty() && issue.labels.is_empty());
        assert_eq!(issue.comments, 1);
        assert_eq!(issue.state, IssueState::Open);
        assert_eq!(issue.opened_by, principal(0xb1));
        node.shutdown().unwrap();
    }
}

fn withheld(server: &Server, token: char, key: bool, length: usize) -> Reply {
    let key = if key { "Idempotency-Key: withheld\r\n" } else { "" };
    let headers = format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n{key}");
    // Neither body nor EOF: denial must precede 100 Continue and body reads.
    let reply = exchange(server.address, &request(server, "POST", "/api/v1/issues/1/open", token, &headers, b""), false);
    assert!(!reply.raw.contains("100 Continue"));
    reply
}

#[test]
fn scope_denial_spoofed_identity_and_incomplete_http_never_publish_issue_state() {
    let root = Scratch::new();
    let configuration = config(&root, GitHashAlgorithm::Sha1);
    let node = start_node(configuration.clone());
    let before = node.runtime().block_on(node.materialize_admission()).unwrap().basis().generation();
    let path = root.0.join("credentials");
    grants(&node, &path);
    let server = Server::start(node, path, 12, true);
    status(&get(&server, "/api/v1/issues", 'd'), 403); // 1: Git rights are not issue rights.
    status(&withheld(&server, 'a', true, 64), 403); // 2: reader cannot write.
    status(&get(&server, "/api/v1/issues", 'b'), 403); // 3: writer cannot read.
    status(&get(&server, "/info/refs?service=git-upload-pack", 'c'), 403); // 4: issue rights are not Git rights.
    status(&withheld(&server, 'c', false, 64), 400); // 5: no retry key.
    status(&post(&server, "/api/v1/issues/1/open", 'c', "spoof", "expected_version=0&title=t&body=b&principal=admin", false), 400); // 6
    status(&withheld(&server, 'e', true, 64), 401); // 7
    let wrong = format!("GET /other.git/api/v1/issues HTTP/1.1\r\nHost: local\r\n{}\r\n", auth('a'));
    status(&exchange(server.address, wrong.as_bytes(), false), 404); // 8
    status(&withheld(&server, 'c', true, 256 * 1024 + 1), 413); // 9
    let body = b"expected_version=0&title=t&body=b";
    let headers = format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: truncated\r\n", body.len() + 1);
    status(&exchange(server.address, &request(&server, "POST", "/api/v1/issues/1/open", 'c', &headers, body), true), 400); // 10
    let headers = "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nIdempotency-Key: no-terminal\r\n";
    let wire = format!("{:x}\r\n{}\r\n0\r\n", body.len(), std::str::from_utf8(body).unwrap());
    status(&exchange(server.address, &request(&server, "POST", "/api/v1/issues/1/open", 'c', headers, wire.as_bytes()), true), 400); // 11
    let empty = get(&server, "/api/v1/issues", 'a'); // 12
    status(&empty, 200);
    assert!(empty.body.contains("\"issues\":[]"));
    assert_eq!(server.finish().accepted_sessions(), 12);
    let node = reopened(configuration);
    assert_eq!(node.runtime().block_on(node.materialize_admission()).unwrap().basis().generation(), before);
    node.shutdown().unwrap();
}

#[test]
fn legacy_server_entry_point_keeps_issue_endpoints_disabled() {
    let root = Scratch::new();
    let node = start_node(config(&root, GitHashAlgorithm::Sha1));
    let path = root.0.join("credentials");
    grants(&node, &path);
    let server = Server::start(node, path, 2, false);
    status(&get(&server, "/api/v1/issues", 'a'), 403);
    status(&withheld(&server, 'c', true, 64), 403);
    assert_eq!(server.finish().refused_sessions(), 2);
}

#[test]
fn rotating_issue_credentials_preserves_the_principals_canonical_retry() {
    let root = Scratch::new();
    let configuration = config(&root, GitHashAlgorithm::Sha256);
    let node = start_node(configuration.clone());
    let before = node.runtime().block_on(node.materialize_admission()).unwrap().basis().generation();
    let path = root.0.join("credentials");
    let header = grants(&node, &path);
    let server = Server::start(node, path.clone(), 4, true);
    let body = "expected_version=0&title=Rotated&body=retained";
    let original = post(&server, "/api/v1/issues/1/open", 'c', "rotation", body, false); // 1
    committed(&original);
    replace(&path, &(header + &row('a', 0xa1, "issues-read") + &row('f', 0xc1, "issues-write")));
    status(&post(&server, "/api/v1/issues/1/open", 'c', "rotation", body, false), 401); // 2
    let retry = post(&server, "/api/v1/issues/1/open", 'f', "rotation", body, true); // 3
    committed(&retry);
    assert_eq!(retry.body, original.body);
    status(&get(&server, "/api/v1/issues/1", 'a'), 200); // 4
    server.finish();
    let node = reopened(configuration);
    assert_eq!(node.runtime().block_on(node.materialize_admission()).unwrap().basis().generation().get(), before.get() + 1);
    node.shutdown().unwrap();
}
