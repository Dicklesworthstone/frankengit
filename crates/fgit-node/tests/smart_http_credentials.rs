#![forbid(unsafe_code)]
//! Real TCP authentication and durable pushes with a live operator grant file.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, NodeConfig, OneNode};
use fgit_types::{GitHashAlgorithm, HeadGeneration, PrincipalId, RefName, RepositoryId, TenantId};
use fgit_wire::{Packet, WireLimits, encode_packets};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-http-principals-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn configuration(root: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.0.join("node"),
        TenantId::from_bytes([0x81; 16]),
        RepositoryId::from_bytes([0x82; 16]),
    )
    .with_object_format(format)
}
fn node(config: NodeConfig) -> OneNode {
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}
fn header(node: &OneNode) -> String {
    format!(
        "frankengit-http-credentials-v1 {} {} {}\n",
        TenantId::from_bytes([0x81; 16]),
        RepositoryId::from_bytes([0x82; 16]),
        node.repository_incarnation_id()
    )
}
fn row(token: char, principal: u8, scopes: &str) -> String {
    let hash: String = sha256_digest(token.to_string().repeat(64).as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "{hash} {} {scopes}\n",
        PrincipalId::from_bytes([principal; 16])
    )
}
fn replace_file(path: &Path, body: &str) {
    let next = path.with_extension("next");
    fs::write(&next, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::rename(next, path).unwrap();
}
struct Server {
    address: SocketAddr,
    route: String,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Server {
    fn start(node: OneNode, path: PathBuf, count: usize, allow_receive: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let route =
            String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let worker = thread::spawn(move || {
            let outcome = node.serve_smart_http_with_credentials_file_bounded(
                &listener,
                GitDaemonServerLimits::try_new(count, 2).unwrap(),
                &path,
                allow_receive,
                Duration::from_secs(30),
            );
            node.shutdown().unwrap();
            outcome.unwrap()
        });
        Self {
            address,
            route,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> GitDaemonServerReceipt {
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn exchange(
    server: &Server,
    method: &str,
    suffix: &str,
    token: char,
    extra: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut stream = TcpStream::connect(server.address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let head = format!(
        "{method} {}{suffix} HTTP/1.1\r\nHost: loopback\r\nAuthorization: Bearer {}\r\n{extra}\r\n",
        server.route,
        token.to_string().repeat(64)
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.take(1024 * 1024).read_to_end(&mut response).unwrap();
    response
}
fn status(response: &[u8], expected: u16) {
    assert!(
        response.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()),
        "expected {expected}, got {}",
        String::from_utf8_lossy(response)
    );
}
/// Discovery as a stock client performs it. An authenticated,
/// receive-permitted receive discovery is redirected once to its scoped
/// attempt URL (03d42b79), which must then answer by itself; every refusal
/// happens before any redirect.
fn discovery(server: &Server, token: char, receive: bool) -> Vec<u8> {
    let first = exchange(
        server,
        "GET",
        if receive {
            "/info/refs?service=git-receive-pack"
        } else {
            "/info/refs?service=git-upload-pack"
        },
        token,
        "",
        &[],
    );
    if !(receive && first.starts_with(b"HTTP/1.1 307 ")) {
        return first;
    }
    let text = String::from_utf8_lossy(&first);
    let location = text
        .lines()
        .find_map(|line| line.strip_prefix("Location: "))
        .expect("a redirect names its scoped attempt URL")
        .trim();
    let suffix = location
        .strip_prefix(server.route.as_str())
        .expect("the attempt URL stays on this repository route");
    assert!(suffix.starts_with("/.fgit-receive/"), "{location}");
    exchange(server, "GET", suffix, token, "", &[])
}
fn push_body(format: GitHashAlgorithm, name: &str) -> Vec<u8> {
    let oid = git_object_id(format, GitObjectKind::Blob, b"x");
    let zero = "0".repeat(format.digest_len() * 2);
    let mut body = encode_packets(
        &[
            Packet::Data(
                format!(
                    "{zero} {oid} {name}\0report-status object-format={}",
                    format.as_str()
                )
                .into_bytes(),
            ),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.extend_from_slice(&[
        0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121,
    ]);
    let trailer = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&trailer);
    body.extend_from_slice(&pack);
    body
}
fn push(server: &Server, token: char, body: &[u8]) -> Vec<u8> {
    exchange(
        server,
        "POST",
        "/git-receive-pack",
        token,
        &format!(
            "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\nIdempotency-Key: shared-client-key\r\n",
            body.len()
        ),
        body,
    )
}
fn withheld_push(server: &Server, token: char) -> Vec<u8> {
    exchange(
        server,
        "POST",
        "/git-receive-pack",
        token,
        "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: 1048576\r\nExpect: 100-continue\r\nIdempotency-Key: shared-client-key\r\nX-Forwarded-User: administrator\r\n",
        &[],
    )
}

#[test]
fn scoped_principals_rotate_and_revoke_without_restarting_or_republishing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = configuration(&root, format);
        let node = node(config.clone());
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .basis()
            .generation();
        let header = header(&node);
        let path = root.0.join("credentials");
        let original = header.clone()
            + &row('a', 1, "read")
            + &row('b', 2, "receive")
            + &row('c', 3, "read,receive");
        replace_file(&path, &original);
        node.validate_smart_http_credentials_file(&path).unwrap();
        // Thirteen requests; the two permitted receive discoveries (9, 13)
        // each follow one redirect, so fifteen connections.
        let server = Server::start(node, path.clone(), 15, true);
        status(&discovery(&server, 'a', false), 200); // 1
        let denied = withheld_push(&server, 'a'); // 2
        status(&denied, 403);
        assert!(!denied.windows(12).any(|w| w == b"100 Continue"));
        status(&discovery(&server, 'b', false), 403); // 3
        let first = push_body(format, "refs/tags/principal-two");
        let second = push_body(format, "refs/tags/principal-three");
        let committed = push(&server, 'b', &first); // 4
        status(&committed, 200);
        assert!(
            committed
                .windows(27)
                .any(|w| w == b"ok refs/tags/principal-two\n")
        );
        let other = push(&server, 'c', &second); // 5
        status(&other, 200);
        // The same key with DIFFERENT semantics must work for a different
        // principal. Mapping every token to the operator would reject this.
        assert!(
            other
                .windows(29)
                .any(|w| w == b"ok refs/tags/principal-three\n")
        );
        let rotated = header.clone()
            + &row('a', 1, "read")
            + &row('d', 2, "receive")
            + &row('c', 3, "read,receive");
        replace_file(&path, &rotated);
        let revoked = withheld_push(&server, 'b'); // 6
        status(&revoked, 401);
        assert!(!revoked.windows(12).any(|w| w == b"100 Continue"));
        assert_eq!(push(&server, 'd', &first), committed); // 7
        replace_file(&path, "broken credential table\n");
        status(&discovery(&server, 'c', true), 503); // 8
        replace_file(&path, &rotated);
        status(&discovery(&server, 'c', true), 200); // 9
        let foreign = rotated.replacen(
            &TenantId::from_bytes([0x81; 16]).to_string(),
            &"00".repeat(16),
            1,
        );
        replace_file(&path, &foreign);
        status(&discovery(&server, 'c', true), 503); // 10
        replace_file(&path, &header);
        status(&discovery(&server, 'c', true), 401); // 11
        fs::remove_file(&path).unwrap();
        status(&discovery(&server, 'c', true), 503); // 12
        replace_file(&path, &rotated);
        status(&discovery(&server, 'c', true), 200); // 13
        let receipt = server.finish();
        assert_eq!(receipt.accepted_sessions(), 15);
        assert_eq!(receipt.completed_sessions(), 8);
        assert_eq!(receipt.refused_sessions(), 7);
        let node = OneNode::open_existing(config).unwrap();
        let state = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            state.basis().generation().get(),
            before.get() + 2,
            "only the two distinct principals' original pushes publish"
        );
        assert_eq!(state.snapshot().refs.len(), 2);
        for name in [
            b"refs/tags/principal-two".as_slice(),
            b"refs/tags/principal-three",
        ] {
            assert!(
                state
                    .snapshot()
                    .refs
                    .contains_key(&RefName::try_new(name).unwrap())
            );
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn deployment_read_only_gate_cannot_be_overridden_by_a_receive_grant() {
    let root = Scratch::new();
    let node = node(configuration(&root, GitHashAlgorithm::Sha1));
    let path = root.0.join("credentials");
    replace_file(&path, &(header(&node) + &row('a', 1, "read,receive")));
    let server = Server::start(node, path, 2, false);
    status(&withheld_push(&server, 'a'), 403);
    status(&discovery(&server, 'a', false), 200);
    let receipt = server.finish();
    assert_eq!(receipt.refused_sessions(), 1);
    assert_eq!(receipt.completed_sessions(), 1);
}
