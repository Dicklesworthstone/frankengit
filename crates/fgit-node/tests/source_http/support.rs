//! Real imported Git trees and the production TCP listener. No substitute
//! searcher, filesystem checkout, HTTP implementation or authority is used.

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionTimeout, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RepositoryId, TenantId};

pub const OWNER: PrincipalId = PrincipalId::from_bytes([0x42; 16]);
pub const FOREIGN: PrincipalId = PrincipalId::from_bytes([0x43; 16]);
pub const TEXT: &[u8] = b"Needle needle\r\nababa\n";
pub const BINARY: &[u8] = b"\0\xffneedle\r\n";
pub const BINARY_PATH: &[u8] = b"bin\xff.dat";
pub const LINK: &[u8] = b"../../outside-secret";
static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-source-http-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0x31; 16]), RepositoryId::from_bytes([0x32; 16]))
            .with_object_format(format).with_worker_threads(2)
            .with_git_daemon_session_timeout(GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap())
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
pub fn reopen(config: &NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config.clone()).unwrap();
    let selected = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(selected.receipt().generation()).unwrap();
    node
}
pub fn generation(node: &OneNode) -> u64 {
    node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation().get()
}
pub fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, name: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes()); encoded.extend((!length).to_le_bytes()); encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521; (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string();
    fs::create_dir_all(root.join("objects").join(&text[..2])).unwrap();
    fs::write(root.join("objects").join(&text[..2]).join(&text[2..]), encoded).unwrap();
    id
}
pub fn fixture(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, GitOid) {
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let selected = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(selected.receipt().generation()).unwrap();
    let git = root.0.join("git-source");
    fs::create_dir_all(git.join("refs/heads")).unwrap();
    fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(git.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let blob = |bytes: &[u8]| loose(&git, format, GitObjectKind::Blob, "blob", bytes);
    let tree = |bytes: &[u8]| loose(&git, format, GitObjectKind::Tree, "tree", bytes);
    let commit = |tree: GitOid, parent: Option<GitOid>, message: &str| {
        let mut body = format!("tree {tree}\n");
        if let Some(parent) = parent { body.push_str(&format!("parent {parent}\n")); }
        body.push_str("author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n");
        body.push_str(message); body.push('\n');
        loose(&git, format, GitObjectKind::Commit, "commit", body.as_bytes())
    };
    let base = commit(tree(&[]), None, "base");
    let nested = tree(&[b"100644 nested.txt\0".as_slice(), blob(b"needle in nested\n").as_bytes()].concat());
    let mut entries = Vec::new();
    // Git order and ordinary byte order agree for these distinct names.
    for (mode, name, id) in [
        ("100644", b"alpha.txt".as_slice(), blob(TEXT)),
        ("100644", BINARY_PATH, blob(BINARY)),
        ("40000", b"dir".as_slice(), nested),
        ("100644", b"empty".as_slice(), blob(&[])),
        ("120000", b"link".as_slice(), blob(LINK)),
        ("160000", b"module".as_slice(), base),
        ("100755", b"run".as_slice(), blob(b"#!/bin/sh\nneedle\n")),
    ] {
        entries.extend_from_slice(mode.as_bytes()); entries.push(b' ');
        entries.extend_from_slice(name); entries.push(0); entries.extend_from_slice(id.as_bytes());
    }
    let main = commit(tree(&entries), Some(base), "browse fixture");
    fs::write(git.join("refs/heads/main"), format!("{main}\n")).unwrap();
    fs::write(root.0.join("outside-secret"), b"must never be read through a repository link").unwrap();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &node.request_context(), &git, OWNER, b"source-http-fixture")).unwrap();
    assert!(imported.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    (node, main)
}
pub fn row(token: char, principal: PrincipalId, scopes: &str) -> String {
    format!("{} {principal} {scopes}\n", hex(&sha256_digest(token.to_string().repeat(64).as_bytes())))
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
pub fn credentials(node: &OneNode, path: &Path) -> String {
    let header = format!("frankengit-http-credentials-v1 {} {} {}\n", TenantId::from_bytes([0x31; 16]),
        RepositoryId::from_bytes([0x32; 16]), node.repository_incarnation_id());
    replace(path, &(header.clone() + &row('a', OWNER, "read") + &row('c', OWNER, "outcomes-read")
        + &row('b', FOREIGN, "receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write")));
    header
}
#[derive(Clone)]
pub struct Endpoint { pub address: SocketAddr, pub route: String }
pub struct Server { pub client: Endpoint, worker: Option<JoinHandle<GitDaemonServerReceipt>> }
impl Server {
    pub fn start(node: OneNode, path: &Path, count: usize, source: bool, issues: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint { address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap() };
        let path = path.to_path_buf();
        let worker = thread::spawn(move || {
            let limits = GitDaemonServerLimits::try_new(count, 2).unwrap();
            let result = if source {
                node.serve_repository_http_with_source_bounded(&listener, limits, &path,
                    false, issues, true, false, Duration::from_secs(5))
            } else {
                node.serve_repository_http_with_credentials_file_bounded(&listener, limits, &path,
                    false, issues, true, Duration::from_secs(5))
            };
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self { client, worker: Some(worker) }
    }
    pub fn finish(mut self) -> GitDaemonServerReceipt { self.worker.take().unwrap().join().unwrap() }
}
impl Drop for Server { fn drop(&mut self) { if let Some(worker) = self.worker.take() { let _ = worker.join(); } } }
#[derive(Debug, Eq, PartialEq)]
pub struct Reply { pub status: u16, pub body: String, pub raw: String }
pub fn request(client: &Endpoint, suffix: &str, token: char, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("POST {}{suffix} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\n{headers}\r\n",
        client.route, token.to_string().repeat(64)).into_bytes();
    bytes.extend_from_slice(body); bytes
}
pub fn exchange(client: &Endpoint, bytes: &[u8], half_close: bool) -> Reply {
    let mut socket = TcpStream::connect(client.address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.write_all(bytes).unwrap();
    if half_close { socket.shutdown(Shutdown::Write).unwrap(); }
    let mut response = Vec::new();
    (&mut socket).take(9 * 1024 * 1024).read_to_end(&mut response).unwrap();
    let raw = String::from_utf8(response).unwrap();
    assert_eq!(raw.matches("HTTP/1.1 ").count(), 1, "{raw}");
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length: usize = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().trim().parse().unwrap();
    assert_eq!(length, body.len());
    Reply { status, body: body.to_owned(), raw }
}
pub fn post(client: &Endpoint, operation: &str, token: char, form: &str, chunked: bool) -> Reply {
    let (body, framing) = if chunked {
        let mut out = Vec::new();
        for part in form.as_bytes().chunks(13) {
            out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            out.extend_from_slice(part); out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n"); (out, "Transfer-Encoding: chunked\r\n".into())
    } else { (form.as_bytes().to_vec(), format!("Content-Length: {}\r\n", form.len())) };
    exchange(client, &request(client, &format!("/api/v1/source/{operation}"), token,
        &format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}"), &body), true)
}
pub fn common(format: GitHashAlgorithm) -> String { format!("object_format={}&ref=refs/heads/main", format.as_str()) }
pub fn status(reply: &Reply, expected: u16) { assert_eq!(reply.status, expected, "{}", reply.raw); }
pub fn text<'a>(json: &'a str, key: &str) -> &'a str {
    json.split_once(&format!("\"{key}\":\"")).unwrap().1.split('"').next().unwrap()
}
pub fn token(reply: &Reply) -> String { text(&reply.body, "snapshot_token").to_owned() }
pub fn number(json: &str, key: &str) -> u64 {
    json.split_once(&format!("\"{key}\":")).unwrap().1.split(|c: char| !c.is_ascii_digit()).next().unwrap().parse().unwrap()
}
