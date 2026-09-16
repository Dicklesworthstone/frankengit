#![forbid(unsafe_code)]
//! The live TCP endpoint recovers a whole push after its report was lost.
//! No command count, ref list, object bytes, or mutation permission is sent to
//! recovery. The descriptor and original child outcomes come from native intake.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fgit_admission::AdmissionResult;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionTimeout,
    LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TENANT: TenantId = TenantId::from_bytes([0xc1; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0xc2; 16]);
const OWNER: PrincipalId = PrincipalId::from_bytes([0xc3; 16]);
const FOREIGN: PrincipalId = PrincipalId::from_bytes([0xc4; 16]);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-whole-session-http-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn configuration(root: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.0.join("node"), TENANT, REPOSITORY).with_object_format(format)
        .with_git_daemon_session_timeout(GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap())
}
fn start(config: NodeConfig, existing: bool) -> OneNode {
    let mut node = if existing { OneNode::open_existing(config).unwrap() }
        else { OneNode::init(config).unwrap().0 };
    let generation = node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation();
    node.bring_into_service(generation).unwrap();
    node
}
fn generation(node: &OneNode) -> u64 {
    node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation().get()
}
fn header(node: &OneNode) -> String {
    format!("frankengit-http-credentials-v1 {TENANT} {REPOSITORY} {}\n", node.repository_incarnation_id())
}
fn row(token: char, principal: PrincipalId, scopes: &str) -> String {
    let token = token.to_string().repeat(64);
    let digest: String = sha256_digest(token.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{digest} {principal} {scopes}\n")
}
fn replace(path: &Path, text: &str) {
    let temporary = path.with_extension("new");
    fs::write(&temporary, text).unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::rename(temporary, path).unwrap();
}
struct Server {
    address: SocketAddr,
    route: String,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Server {
    fn new(node: OneNode, path: &Path, requests: usize, allow_outcomes: bool) -> Self {
        let route = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let path = path.to_path_buf();
        let worker = thread::spawn(move || {
            // Mutation services are disabled throughout the entire recovery run.
            let result = node.serve_repository_http_with_credentials_file_bounded(&listener,
                GitDaemonServerLimits::try_new(requests, 2).unwrap(), &path,
                false, false, allow_outcomes, Duration::from_secs(10));
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self { address, route, worker: Some(worker) }
    }
    fn finish(mut self) -> GitDaemonServerReceipt { self.worker.take().unwrap().join().unwrap() }
}
impl Drop for Server {
    fn drop(&mut self) { if let Some(worker) = self.worker.take() { let _ = worker.join(); } }
}
fn exchange(server: &Server, token: char, key: &str, suffix: &str, headers: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(server.address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
    write!(stream, "POST {}/api/v1/outcomes{suffix} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\nIdempotency-Key: {key}\r\n{headers}\r\n",
        server.route, token.to_string().repeat(64)).unwrap();
    // Even malformed envelope probes withhold their declared body. Refusal
    // must not wait for bytes that recovery has no reason to accept.
    let mut bytes = Vec::new();
    (&mut stream).take(1024 * 1024 + 32768).read_to_end(&mut bytes).unwrap();
    let response = String::from_utf8(bytes).unwrap();
    assert_eq!(response.matches("HTTP/1.1 ").count(), 1, "no interim or second final reply");
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let length: usize = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().trim().parse().unwrap();
    assert_eq!(length, body.len());
    assert!(head.contains("Cache-Control: no-store"));
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, body.to_owned())
}
fn query(server: &Server, token: char, key: &str) -> (u16, String) {
    exchange(server, token, key, "/receive", "Content-Length: 0\r\n")
}
fn assert_complete(reply: &(u16, String), original: &AdmissionResult) {
    assert_eq!(reply.0, 200, "{}", reply.1);
    let prefix = reply.1.split_once("\"commands\":[").unwrap().0;
    assert!(prefix.contains("\"type\":\"receive_session_outcome\""));
    assert!(prefix.contains("\"command_count\":3,\"command_count_verified\":true"));
    assert!(prefix.contains("\"all_terminal\":true,\"session_completeness_established\":true"));
    assert!(prefix.contains("\"state\":\"complete\""));
    assert!(prefix.contains("\"single_snapshot\":false"));
    assert!(prefix.contains("\"request_reexecuted\":false"));
    let mut previous = 0;
    for (index, name) in ["refs/tags/z-stale", "refs/tags/a-good", "refs/tags/m-good"].into_iter().enumerate() {
        let position = reply.1.find(&format!("\"command_index\":{index},\"ref_name\":\"{name}\"")).unwrap();
        assert!(position > previous, "original wire order, not canonical ref-name order");
        previous = position;
        assert!(reply.1.contains(&format!("\"tx_id\":\"{}\"", original.commands[index].tx_id)));
    }
    assert!(!reply.1.contains("original-private-session-key"));
}
fn seed_lost_push(node: &OneNode, format: GitHashAlgorithm) -> AdmissionResult {
    let oid = git_object_id(format, GitObjectKind::Blob, b"x");
    let zero = "0".repeat(format.digest_len() * 2);
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.extend_from_slice(&[0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121]);
    let trailer = match format { GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(), GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec() };
    pack.extend_from_slice(&trailer);
    let mut body = encode_packets(&[
        Packet::Data(format!("{oid} {oid} refs/tags/z-stale\0report-status object-format={}", format.as_str()).into_bytes()),
        Packet::Data(format!("{zero} {oid} refs/tags/a-good").into_bytes()),
        Packet::Data(format!("{zero} {oid} refs/tags/m-good").into_bytes()), Packet::Flush,
    ], &WireLimits::default()).unwrap();
    body.extend_from_slice(&pack);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head = format!("POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n", body.len());
    let request = parse_head(head.as_bytes(), HttpLimits::default()).unwrap().unwrap();
    let session = LoopbackReceiveSession::authenticated(OWNER,
        IdempotencyKey::new(b"original-private-session-key".to_vec()).unwrap());
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::BrokenPipe.into()) }
        fn flush(&mut self) -> io::Result<()> { Err(io::ErrorKind::BrokenPipe.into()) }
    }
    let error = node.smart_http_receive_rpc_in(&request, &session, &body,
        HttpLimits::default(), Default::default(), &mut || true, &mut Broken).unwrap_err();
    let NodeSmartHttpRefusal::ReceiveResponse { outcome, .. } = error else { panic!("native admission must complete before broken report") };
    assert!(matches!(outcome.commands[0].terminal.outcome, DecisionOutcome::Refused { .. }));
    assert!(outcome.commands[1..].iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    *outcome
}

#[test]
fn whole_push_recovery_survives_restart_rotation_and_lost_reports_without_write_permission() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = configuration(&root, format);
        let node = start(config.clone(), false);
        let known = seed_lost_push(&node, format);
        let before = generation(&node);
        let header = header(&node);
        node.shutdown().unwrap();
        let node = start(config.clone(), true);
        let path = root.0.join("credentials");
        replace(&path, &(header.clone() + &row('a', OWNER, "outcomes-read")
            + &row('b', FOREIGN, "outcomes-read") + &row('c', OWNER, "receive")));
        let server = Server::new(node, &path, 8, true);
        let first = query(&server, 'a', "original-private-session-key"); // 1
        assert_complete(&first, &known);
        assert_eq!(query(&server, 'a', "original-private-session-key"), first); // 2
        let indexed = exchange(&server, 'a', "original-private-session-key", "/receive/1", "Content-Length: 0\r\n"); // 3
        assert_eq!(indexed.0, 200);
        assert!(indexed.1.contains(&format!("\"tx_id\":\"{}\"", known.commands[1].tx_id)));
        let foreign = query(&server, 'b', "original-private-session-key"); // 4
        assert_eq!(foreign.0, 200);
        assert!(foreign.1.contains("\"state\":\"session_not_observed\""));
        assert!(foreign.1.contains("\"command_count\":null,\"command_count_verified\":false"));
        assert!(!foreign.1.contains("refs/tags/"));
        assert!(!foreign.1.contains(&known.commands[1].tx_id.to_string()));
        let absent = query(&server, 'a', "never-submitted"); // 5
        assert_eq!(absent.0, 200);
        assert!(absent.1.contains("\"session_completeness_established\":false"));
        assert!(absent.1.contains("\"all_terminal\":null"));
        assert_eq!(query(&server, 'c', "original-private-session-key").0, 403); // 6
        replace(&path, &(header + &row('d', OWNER, "outcomes-read")));
        assert_eq!(query(&server, 'a', "original-private-session-key").0, 401); // 7
        assert_eq!(query(&server, 'd', "original-private-session-key"), first); // 8
        assert_eq!(server.finish().accepted_sessions(), 8);
        let node = OneNode::open_existing(config).unwrap();
        assert_eq!(generation(&node), before, "recovery cannot publish or resubmit commands");
        assert_eq!(node.runtime().block_on(node.materialize_admission()).unwrap().snapshot().refs.len(), 2);
        node.shutdown().unwrap();
    }
}

#[test]
fn whole_session_selector_retains_bodyless_envelopes_and_explicit_deployment_gate() {
    let root = Scratch::new();
    let config = configuration(&root, GitHashAlgorithm::Sha1);
    let node = start(config.clone(), false);
    let path = root.0.join("credentials");
    replace(&path, &(header(&node) + &row('a', OWNER, "outcomes-read")));
    let before = generation(&node);
    let server = Server::new(node, &path, 4, true);
    for (suffix, extra) in [
        ("/receive", "Content-Length: 1\r\n"),
        ("/receive", "Content-Length: 0\r\nExpect: 100-continue\r\n"),
        ("/receive?key=secret", "Content-Length: 0\r\n"),
        ("/receive/", "Content-Length: 0\r\n"),
    ] {
        let reply = exchange(&server, 'a', "never-submitted", suffix, extra);
        assert!(matches!(reply.0, 400 | 404));
        assert!(!reply.1.contains("secret"));
        assert!(!reply.1.contains("\"state\":\"complete\""));
    }
    server.finish();
    let node = start(config.clone(), true);
    let disabled = Server::new(node, &path, 1, false);
    assert_eq!(query(&disabled, 'a', "never-submitted").0, 403);
    disabled.finish();
    let node = OneNode::open_existing(config).unwrap();
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
