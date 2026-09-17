//! Real repository fixture and TCP client. Native objects are imported through
//! the node's production importer; no alternate HTTP or authority server exists.

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::event::pull_request::PullRequestData;
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionTimeout, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};

pub const OWNER: PrincipalId = PrincipalId::from_bytes([0x42; 16]);
pub const FOREIGN: PrincipalId = PrincipalId::from_bytes([0x43; 16]);
static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-pr-http-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0x31; 16]), RepositoryId::from_bytes([0x32; 16]))
            .with_object_format(format).with_worker_threads(2)
            .with_git_daemon_session_timeout(GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
pub fn reopen(config: &NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config.clone()).unwrap();
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
    node
}
pub fn generation(node: &OneNode) -> u64 {
    node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation().get()
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, name: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&hex[2..]), encoded).unwrap();
    id
}
fn commit(tree: GitOid, parent: Option<GitOid>, message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    if let Some(parent) = parent { body.push_str(&format!("parent {parent}\n")); }
    body.push_str("author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n");
    body.push_str(message);
    body.push('\n');
    body.into_bytes()
}
pub fn fixture(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, PullRequestData) {
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
    let source = root.0.join("source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(source.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let tree = loose(&source, format, GitObjectKind::Tree, "tree", &[]);
    let main = loose(&source, format, GitObjectKind::Commit, "commit", &commit(tree, None, "base"));
    let topic = loose(&source, format, GitObjectKind::Commit, "commit", &commit(tree, Some(main), "topic"));
    fs::write(source.join("refs/heads/main"), format!("{main}\n")).unwrap();
    fs::write(source.join("refs/heads/topic"), format!("{topic}\n")).unwrap();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &node.request_context(), &source, OWNER, b"pr-http-fixture",
    )).unwrap();
    assert!(imported.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    (node, PullRequestData { source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(), source_tip: topic, target_tip: main,
        title: "Original 🦀".into(), body: "Untrusted <script>\nExact \"text\"".into() })
}
pub fn header(node: &OneNode) -> String {
    format!("frankengit-http-credentials-v1 {} {} {}\n", TenantId::from_bytes([0x31; 16]),
        RepositoryId::from_bytes([0x32; 16]), node.repository_incarnation_id())
}
pub fn row(token: char, principal: PrincipalId, scopes: &str) -> String {
    let token = token.to_string().repeat(64);
    let digest: String = sha256_digest(token.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{digest} {principal} {scopes}\n")
}
pub fn replace(path: &Path, text: &str) {
    let next = path.with_extension("next");
    fs::write(&next, text).unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::rename(next, path).unwrap();
}
pub fn grants(node: &OneNode, path: &Path) -> String {
    let head = header(node);
    replace(path, &(head.clone() + &row('a', OWNER, "pulls-read") + &row('b', OWNER, "pulls-write")
        + &row('c', OWNER, "outcomes-read,pulls-read,pulls-write")
        + &row('d', FOREIGN, "read,receive,issues-read,issues-write,outcomes-read")
        + &row('e', FOREIGN, "outcomes-read")));
    head
}

#[derive(Clone)]
pub struct Endpoint { pub address: SocketAddr, pub route: String }
pub struct Server {
    pub client: Endpoint,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Server {
    pub fn start(node: OneNode, path: &Path, requests: usize, pulls: bool, outcomes: bool) -> Self {
        let route = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let path = path.to_path_buf();
        let worker = thread::spawn(move || {
            let limits = GitDaemonServerLimits::try_new(requests, 2).unwrap();
            let result = if pulls {
                node.serve_repository_http_with_pull_requests_bounded(&listener, limits, &path,
                    false, false, outcomes, Duration::from_secs(5))
            } else {
                node.serve_repository_http_with_credentials_file_bounded(&listener, limits, &path,
                    false, false, outcomes, Duration::from_secs(5))
            };
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self { client: Endpoint { address, route }, worker: Some(worker) }
    }
    pub fn finish(mut self) -> GitDaemonServerReceipt { self.worker.take().unwrap().join().unwrap() }
}
impl Drop for Server {
    fn drop(&mut self) { if let Some(worker) = self.worker.take() { let _ = worker.join(); } }
}
pub fn connection(endpoint: &Endpoint) -> TcpStream {
    let socket = TcpStream::connect(endpoint.address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
    socket
}
pub fn request(endpoint: &Endpoint, method: &str, suffix: &str, token: char, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{method} {}{suffix} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\n{headers}\r\n",
        endpoint.route, token.to_string().repeat(64)).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply { pub status: u16, pub body: String, pub raw: String }
pub fn exchange(endpoint: &Endpoint, bytes: &[u8], half_close: bool) -> Reply {
    let mut socket = connection(endpoint);
    socket.write_all(bytes).unwrap();
    if half_close { socket.shutdown(Shutdown::Write).unwrap(); }
    let mut response = Vec::new();
    (&mut socket).take(2 * 1024 * 1024).read_to_end(&mut response).unwrap();
    let raw = String::from_utf8(response).unwrap();
    assert_eq!(raw.matches("HTTP/1.1 ").count(), 1, "{raw}");
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length: usize = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().trim().parse().unwrap();
    assert_eq!(length, body.len());
    Reply { status, body: body.to_owned(), raw }
}
pub fn get(endpoint: &Endpoint, suffix: &str, token: char) -> Reply {
    exchange(endpoint, &request(endpoint, "GET", suffix, token, "", &[]), true)
}
pub fn post(endpoint: &Endpoint, number: u64, action: &str, token: char, key: &str, body: &str, chunked: bool) -> Reply {
    let (wire, framing) = if chunked {
        let mut wire = Vec::new();
        for chunk in body.as_bytes().chunks(11) {
            wire.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            wire.extend_from_slice(chunk);
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        (wire, "Transfer-Encoding: chunked\r\n".to_owned())
    } else { (body.as_bytes().to_vec(), format!("Content-Length: {}\r\n", body.len())) };
    let headers = format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}Idempotency-Key: {key}\r\n");
    exchange(endpoint, &request(endpoint, "POST", &format!("/api/v1/pulls/{number}/{action}"), token, &headers, &wire), true)
}
fn encode(bytes: &[u8]) -> String {
    bytes.iter().copied().map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
        (byte as char).to_string()
    } else { format!("%{byte:02X}") }).collect()
}
pub fn form(data: &PullRequestData, version: u64) -> String {
    format!("expected_version={version}&object_format={}&source_ref={}&target_ref={}&source_tip={}&target_tip={}&title={}&body={}",
        data.source_tip.algorithm().as_str(), encode(data.source_ref.as_bytes()), encode(data.target_ref.as_bytes()),
        data.source_tip, data.target_tip, encode(data.title.as_bytes()), encode(data.body.as_bytes()))
}
pub fn status(reply: &Reply, expected: u16) { assert_eq!(reply.status, expected, "{}", reply.raw); }
pub fn committed(reply: &Reply) {
    status(reply, 200);
    assert!(reply.body.contains("\"type\":\"pull_request_publication\""));
    assert!(reply.body.contains("\"outcome\":\"committed\""));
    assert!(reply.body.contains("\"delivery_acknowledged\":null"));
}
pub fn token(reply: &Reply) -> String {
    reply.body.split_once("\"snapshot_token\":\"").unwrap().1.split('"').next().unwrap().to_owned()
}
