#![forbid(unsafe_code)]
#![cfg(unix)]
//! Public native listener, real TCP, and a generated payload above the buffered
//! ceiling. The client retains only bounded chunks and the small HTTP headers.

#[path = "lfs_streaming_http/receive_policy.rs"]
mod receive_policy;
#[path = "lfs_streaming_http/tus.rs"]
mod tus;

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fgit_crypto::{DigestHasher, Sha256Hasher, sha256_digest};
use fgit_node::{
    GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionTimeout, NodeConfig, OneNode,
};
use fgit_object_fabric::artifact::storage::MAX_BUFFERED_PAYLOAD_BYTES;
use fgit_object_fabric::artifact::storage::lfs::{LfsObject, LfsOid};
use fgit_types::{
    GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId,
};
use fgit_wire::receive::ReceiveLimits;

const TENANT: TenantId = TenantId::from_bytes([0x51; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x52; 16]);
const CHUNK: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(180);
static NEXT: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
        let path = base.join(format!(
            "fg-lfs-streaming-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.join("lfs"))
            .unwrap();
        Self(path)
    }
    fn config(&self) -> NodeConfig {
        // The public listener must select its independent LFS input envelope;
        // widening only the private route fixture would still fail this upload.
        let mut receive = ReceiveLimits::default();
        receive.pack.max_input_bytes = 1024 * 1024;
        receive.max_quarantine_bytes = receive.pack.max_input_bytes;
        NodeConfig::new(self.0.join("node"), TENANT, REPOSITORY)
            .with_worker_threads(2)
            .with_object_format(GitHashAlgorithm::Sha256)
            .with_http_lfs_root(self.0.join("lfs"))
            .with_git_daemon_receive_limits(receive)
            .with_git_daemon_session_timeout(GitDaemonSessionTimeout::try_new(TIMEOUT).unwrap())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn credentials(path: &Path, incarnation: RepositoryIncarnationId, reader_active: bool) {
    let mut table = format!("frankengit-http-credentials-v1 {TENANT} {REPOSITORY} {incarnation}\n");
    for (token, scopes) in [
        ('a', "lfs-read,lfs-write"),
        ('b', "lfs-read"),
        ('c', "lfs-write"),
    ] {
        if token == 'b' && !reader_active {
            continue;
        }
        table.push_str(&format!(
            "{} {} {scopes}\n",
            hex(&sha256_digest(token.to_string().repeat(64).as_bytes())),
            PrincipalId::from_bytes([token as u8; 16]),
        ));
    }
    let replacement = path.with_extension("next");
    fs::write(&replacement, table).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(replacement, path).unwrap();
}
struct Server {
    address: SocketAddr,
    route: String,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Server {
    fn start(node: OneNode, credentials: PathBuf, sessions: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let route =
            String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let worker = thread::spawn(move || {
            let result = node.serve_smart_http_with_credentials_file_bounded(
                &listener,
                GitDaemonServerLimits::try_new(sessions, 1).unwrap(),
                &credentials,
                false,
                Duration::from_secs(15),
            );
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self {
            address,
            route,
            worker: Some(worker),
        }
    }
    fn request(&self, method: &str, suffix: &str, token: char, headers: &str) -> TcpStream {
        let mut stream = TcpStream::connect(self.address).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        write!(
            stream,
            "{method} {}{suffix} HTTP/1.1\r\nHost: loopback\r\nAuthorization: Bearer {}\r\n{headers}\r\n",
            self.route,
            token.to_string().repeat(64),
        ).unwrap();
        stream
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
fn head(stream: &mut TcpStream, status: u16) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 8192, "bounded response headers");
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.starts_with(&format!("HTTP/1.1 {status} ")), "{text}");
    text
}
fn content_length(head: &str) -> u64 {
    head.lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}
fn small_response(stream: &mut TcpStream, status: u16) -> String {
    let header = head(stream, status);
    let length = content_length(&header);
    assert!(
        length <= 64 * 1024,
        "small response cannot buffer a payload"
    );
    let mut body = vec![0; length as usize];
    stream.read_exact(&mut body).unwrap();
    assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0, "exact response EOF");
    String::from_utf8(body).unwrap()
}
fn generated_object(size: u64) -> LfsObject {
    let chunk = [0xd3; CHUNK];
    let mut hash = Sha256Hasher::new();
    let mut remaining = size;
    while remaining != 0 {
        let count = chunk.len().min(remaining as usize);
        hash.update(&chunk[..count]);
        remaining -= count as u64;
    }
    LfsObject {
        oid: LfsOid::parse(&hex(&hash.finish())).unwrap(),
        size,
    }
}

#[test]
fn real_listener_streams_large_lfs_independently_of_git_limits_and_survives_cold_reopen() {
    let scratch = Scratch::new();
    let object = generated_object(MAX_BUFFERED_PAYLOAD_BYTES + 257);
    let config = scratch.config();
    let (mut node, _) = OneNode::init(config.clone()).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let incarnation = node.repository_incarnation_id();
    let before = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    let grants = scratch.0.join("credentials");
    credentials(&grants, incarnation, true);
    let suffix = format!("/info/lfs/objects/{}/{}", object.oid, object.size);
    let server = Server::start(node, grants.clone(), 1);
    let mut upload = server.request("PUT", &suffix, 'a', &format!(
        "Content-Type: application/octet-stream\r\nContent-Length: {}\r\nExpect: 100-continue\r\n",
        object.size,
    ));
    assert_eq!(head(&mut upload, 100), "HTTP/1.1 100 Continue\r\n\r\n");
    let chunk = [0xd3; CHUNK];
    let mut remaining = object.size;
    while remaining != 0 {
        let count = chunk.len().min(remaining as usize);
        upload.write_all(&chunk[..count]).unwrap();
        remaining -= count as u64;
    }
    // The request completes through Content-Length, without a client half-close.
    assert_eq!(small_response(&mut upload, 200), "");
    assert_eq!(server.finish().completed_sessions(), 1);

    let mut reopened = OneNode::open_existing(config.clone()).unwrap();
    assert_eq!(reopened.repository_incarnation_id(), incarnation);
    let selected = reopened
        .runtime()
        .block_on(reopened.authenticate_authority_head())
        .unwrap();
    assert_eq!(
        selected.receipt().generation(),
        before,
        "LFS upload does not publish Git authority"
    );
    reopened
        .bring_into_service(selected.receipt().generation())
        .unwrap();
    let server = Server::start(reopened, grants.clone(), 4);
    let batch = format!(
        "{{\"operation\":\"download\",\"objects\":[{{\"oid\":\"{}\",\"size\":{}}}]}}",
        object.oid, object.size
    );
    let mut request = server.request(
        "POST",
        "/info/lfs/objects/batch",
        'b',
        &format!(
            "Content-Type: application/vnd.git-lfs+json\r\nContent-Length: {}\r\n",
            batch.len(),
        ),
    );
    request.write_all(batch.as_bytes()).unwrap();
    let batch = small_response(&mut request, 200);
    assert!(batch.contains("\"download\":"), "{batch}");
    assert!(!batch.contains("\"error\":"), "{batch}");
    assert!(
        batch.contains(&format!(
            "http://{}{}{}",
            server.address, server.route, suffix
        )),
        "{batch}"
    );

    let mut download = server.request("GET", &suffix, 'b', "");
    let response = head(&mut download, 200);
    assert_eq!(content_length(&response), object.size);
    assert!(response.contains("Content-Type: application/octet-stream\r\n"));
    let mut chunk = [0; CHUNK];
    let mut hash = Sha256Hasher::new();
    let mut bytes = 0_u64;
    loop {
        let count = download.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        bytes += count as u64;
        assert!(bytes <= object.size);
        hash.update(&chunk[..count]);
    }
    assert_eq!(bytes, object.size);
    assert_eq!(hex(&hash.finish()), object.oid.to_string());

    small_response(&mut server.request("GET", &suffix, 'c', ""), 403);
    credentials(&grants, incarnation, false);
    small_response(&mut server.request("GET", &suffix, 'b', ""), 401);
    let receipt = server.finish();
    assert_eq!(receipt.accepted_sessions(), 4);
    assert_eq!(receipt.completed_sessions(), 2);
    assert_eq!(receipt.refused_sessions(), 2);
    let reopened = OneNode::open_existing(config).unwrap();
    assert_eq!(
        reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation(),
        before
    );
    reopened.shutdown().unwrap();
}
