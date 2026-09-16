#![forbid(unsafe_code)]
//! Real TCP recovery over the embedded authority. Recovery never receives the
//! original issue command or PACK, and reopened state must not advance.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fgit_admission::AdmissionResult;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionTimeout,
    LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};

static NEXT: AtomicU64 = AtomicU64::new(0);
const OWNER: PrincipalId = PrincipalId::from_bytes([0x93; 16]);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-outcome-http-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn config(root: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.0.join("node"), TenantId::from_bytes([0x91; 16]), RepositoryId::from_bytes([0x92; 16]))
        .with_object_format(format)
        .with_git_daemon_session_timeout(GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap())
}
fn init(config: NodeConfig) -> OneNode {
    let (mut node, _) = OneNode::init(config).unwrap();
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
    node
}
fn reopen(config: &NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config.clone()).unwrap();
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
    node
}
fn header(node: &OneNode) -> String {
    format!("frankengit-http-credentials-v1 {} {} {}\n", TenantId::from_bytes([0x91; 16]),
        RepositoryId::from_bytes([0x92; 16]), node.repository_incarnation_id())
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
fn session(principal: PrincipalId, key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(principal, IdempotencyKey::new(key.to_vec()).unwrap())
}
fn generation(node: &OneNode) -> u64 {
    node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation().get()
}
struct Server {
    address: SocketAddr,
    route: String,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Server {
    fn start(node: OneNode, credentials: &Path, requests: usize, services: [bool; 3]) -> Self {
        let route = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let credentials = credentials.to_path_buf();
        let worker = thread::spawn(move || {
            let result = node.serve_repository_http_with_credentials_file_bounded(&listener,
                GitDaemonServerLimits::try_new(requests, 2).unwrap(), &credentials,
                services[0], services[1], services[2], Duration::from_secs(10));
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self { address, route, worker: Some(worker) }
    }
    fn finish(mut self) -> GitDaemonServerReceipt { self.worker.take().unwrap().join().unwrap() }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}
fn connection(server: &Server) -> TcpStream {
    let stream = TcpStream::connect(server.address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
    stream
}
fn request(server: &Server, method: &str, suffix: &str, token: char, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{method} {}{suffix} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\n{extra}\r\n",
        server.route, token.to_string().repeat(64)).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn exchange(server: &Server, request: &[u8]) -> (u16, String) {
    let mut stream = connection(server);
    stream.write_all(request).unwrap();
    let mut bytes = Vec::new();
    (&mut stream).take(128 * 1024).read_to_end(&mut bytes).unwrap();
    let response = String::from_utf8(bytes).unwrap();
    assert_eq!(response.matches("HTTP/1.1 ").count(), 1, "never append a second response");
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length: usize = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().trim().parse().unwrap();
    assert_eq!(length, body.len());
    assert!(head.contains("Cache-Control: no-store"));
    (status, body.to_owned())
}
fn lookup(server: &Server, token: char, key: &str, index: Option<usize>) -> (u16, String) {
    let suffix = index.map_or_else(|| "/api/v1/outcomes".to_owned(), |index| format!("/api/v1/outcomes/receive/{index}"));
    exchange(server, &request(server, "POST", &suffix, token,
        &format!("Content-Length: 0\r\nIdempotency-Key: {key}\r\n"), &[]))
}
fn observation(reply: &(u16, String), state: &str) {
    assert_eq!(reply.0, 200, "{}", reply.1);
    assert!(reply.1.contains(&format!("\"state\":\"{state}\"")), "{}", reply.1);
    assert!(reply.1.contains("\"request_reexecuted\":false"));
    assert!(reply.1.contains("\"read_only\":true"));
    assert!(reply.1.contains("\"absence_proves_non_commit\":false"));
}
fn terminal(reply: &(u16, String), tx: fgit_types::TxId, known: TerminalOutcome) {
    observation(reply, match known.outcome { DecisionOutcome::Committed { .. } => "committed", DecisionOutcome::Refused { .. } => "refused" });
    assert!(reply.1.contains(&format!("\"tx_id\":\"{tx}\"")));
    assert!(reply.1.contains(&format!("\"decision_sequence\":{}", known.decision_sequence.get())));
    assert!(reply.1.contains("\"terminal\":true"));
}

#[test]
fn an_issue_reply_lost_at_the_client_is_recovered_after_restart_without_write_access() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = init(configuration.clone());
        let credential_header = header(&node);
        let path = root.0.join("credentials");
        replace(&path, &(credential_header.clone() + &row('a', OWNER, "issues-write")));
        let before = generation(&node);
        let server = Server::start(node, &path, 1, [false, true, false]);
        let body = b"expected_version=0&title=Committed&body=No+client+receipt";
        let bytes = request(&server, "POST", "/api/v1/issues/41/open", 'a',
            &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: issue-lost\r\n", body.len()), body);
        let mut stream = connection(&server);
        stream.write_all(&bytes).unwrap();
        // One header byte proves the server reached response production, but
        // conveys neither a TxId nor a terminal JSON result to the client.
        let mut first = [0; 1];
        stream.read_exact(&mut first).unwrap();
        assert_eq!(first, [b'H']);
        drop(stream);
        assert_eq!(server.finish().accepted_sessions(), 1);
        let node = reopen(&configuration);
        let owner_session = session(OWNER, b"issue-lost");
        let known = node.runtime().block_on(node.recover_transaction_in(&node.request_context(), &owner_session)).unwrap();
        let fgit_authority::key_recovery::RequestRecovery::Recovered(known) = known else { panic!("real issue publication must exist") };
        let fgit_authority::OutcomeLookup::Decided(decision) = known.outcome() else { panic!("issue must be terminal") };
        assert!(matches!(decision.outcome, DecisionOutcome::Committed { .. }));
        assert_eq!(generation(&node), before + 1);
        // A rotated token for the same principal has ONLY recovery authority.
        replace(&path, &(credential_header + &row('b', OWNER, "outcomes-read")));
        let server = Server::start(node, &path, 3, [false, false, true]);
        let recovered = lookup(&server, 'b', "issue-lost", None);
        terminal(&recovered, known.tx_id(), decision);
        assert!(!recovered.1.contains("issue-lost"));
        assert_eq!(lookup(&server, 'b', "issue-lost", None), recovered);
        let forbidden = exchange(&server, &request(&server, "POST", "/api/v1/issues/41/close", 'b',
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 18\r\nIdempotency-Key: forbidden\r\nExpect: 100-continue\r\n", &[]));
        assert_eq!(forbidden.0, 403);
        server.finish();
        let node = reopen(&configuration);
        assert_eq!(generation(&node), before + 1, "recovery and denied mutation publish nothing");
        node.shutdown().unwrap();
    }
}

fn seed_mixed_push(node: &OneNode, format: GitHashAlgorithm) -> AdmissionResult {
    let oid = git_object_id(format, GitObjectKind::Blob, b"x");
    let zero = "0".repeat(format.digest_len() * 2);
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.extend_from_slice(&[0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121]);
    let trailer = match format { GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(), GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec() };
    pack.extend_from_slice(&trailer);
    let mut body = encode_packets(&[
        Packet::Data(format!("{oid} {oid} refs/tags/stale\0report-status object-format={}", format.as_str()).into_bytes()),
        Packet::Data(format!("{zero} {oid} refs/tags/good").into_bytes()), Packet::Flush,
    ], &WireLimits::default()).unwrap();
    body.extend_from_slice(&pack);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let bytes = format!("POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n", body.len());
    let request = parse_head(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::BrokenPipe.into()) }
        fn flush(&mut self) -> io::Result<()> { Err(io::ErrorKind::BrokenPipe.into()) }
    }
    let error = node.smart_http_receive_rpc_in(&request, &session(OWNER, b"mixed-lost"), &body,
        HttpLimits::default(), Default::default(), &mut || true, &mut Broken).unwrap_err();
    let NodeSmartHttpRefusal::ReceiveResponse { outcome, .. } = error else { panic!("broken reply must retain canonical outcomes") };
    assert!(matches!(outcome.commands[0].terminal.outcome, DecisionOutcome::Refused { .. }));
    assert!(matches!(outcome.commands[1].terminal.outcome, DecisionOutcome::Committed { .. }));
    *outcome
}

#[test]
fn mixed_push_outcomes_are_read_by_original_key_and_index_without_another_pack() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = init(configuration.clone());
        let known = seed_mixed_push(&node, format);
        let before = generation(&node);
        let credential_header = header(&node);
        node.shutdown().unwrap();
        let node = reopen(&configuration);
        let path = root.0.join("credentials");
        let stranger = PrincipalId::from_bytes([0x94; 16]);
        replace(&path, &(credential_header + &row('a', OWNER, "outcomes-read") + &row('b', stranger, "outcomes-read")));
        let server = Server::start(node, &path, 7, [false, false, true]);
        for index in 0..2 {
            terminal(&lookup(&server, 'a', "mixed-lost", Some(index)),
                known.commands[index].tx_id, known.commands[index].terminal);
        }
        // The original non-atomic key binds the session but is not a child seal.
        observation(&lookup(&server, 'a', "mixed-lost", None), "seal_not_observed");
        let absent = lookup(&server, 'a', "mixed-lost", Some(2));
        observation(&absent, "key_not_observed");
        assert!(absent.1.contains("\"session_completeness_established\":false"));
        let foreign = lookup(&server, 'b', "mixed-lost", Some(1));
        observation(&foreign, "key_not_observed");
        assert!(foreign.1.contains("\"transaction\":null,\"decision\":null"));
        assert!(!foreign.1.contains(&known.commands[1].tx_id.to_string()));
        let missing = lookup(&server, 'a', "never-submitted", Some(0));
        observation(&missing, "key_not_observed");
        assert_eq!(lookup(&server, 'a', "never-submitted", Some(0)), missing,
            "a lookup must not create the missing binding or seal");
        server.finish();
        let node = reopen(&configuration);
        assert_eq!(generation(&node), before);
        let refs = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(refs.snapshot().refs.len(), 1);
        node.shutdown().unwrap();
    }
}

#[test]
fn recovery_scopes_reload_and_mutation_bodies_or_identity_overrides_are_not_accepted() {
    let root = Scratch::new();
    let configuration = config(&root, GitHashAlgorithm::Sha1);
    let node = init(configuration.clone());
    let before = generation(&node);
    let credential_header = header(&node);
    let path = root.0.join("credentials");
    replace(&path, &(credential_header.clone() + &row('a', OWNER, "read,receive,issues-read,issues-write")
        + &row('b', OWNER, "outcomes-read")));
    let server = Server::start(node, &path, 8, [true, true, true]);
    assert_eq!(lookup(&server, 'a', "unknown", None).0, 403);
    assert_eq!(lookup(&server, 'c', "unknown", None).0, 401);
    for (suffix, extra) in [
        ("/api/v1/outcomes", "Content-Length: 1000000\r\nExpect: 100-continue\r\n"),
        ("/api/v1/outcomes?principal=other", "Content-Length: 0\r\n"),
        ("/api/v1/outcomes/receive/64", "Content-Length: 0\r\n"),
    ] {
        let refused = exchange(&server, &request(&server, "POST", suffix, 'b',
            &format!("Idempotency-Key: unknown\r\n{extra}"), &[]));
        assert!(matches!(refused.0, 400 | 404));
    }
    replace(&path, &credential_header);
    assert_eq!(lookup(&server, 'b', "unknown", None).0, 401);
    replace(&path, "corrupt table\n");
    let unavailable = lookup(&server, 'b', "unknown", None);
    assert_eq!(unavailable.0, 503);
    assert!(unavailable.1.contains("\"outcome_unknown\":true"));
    replace(&path, &(credential_header + &row('d', OWNER, "outcomes-read")));
    observation(&lookup(&server, 'd', "unknown", None), "key_not_observed");
    server.finish();
    let node = reopen(&configuration);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn a_credential_cannot_enable_recovery_against_the_deployment_ceiling() {
    let root = Scratch::new();
    let configuration = config(&root, GitHashAlgorithm::Sha1);
    let node = init(configuration.clone());
    let before = generation(&node);
    let path = root.0.join("credentials");
    replace(&path, &(header(&node) + &row('a', OWNER, "outcomes-read")));
    let server = Server::start(node, &path, 1, [false, false, false]);
    assert_eq!(lookup(&server, 'a', "unknown", None).0, 403);
    server.finish();
    let node = reopen(&configuration);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
