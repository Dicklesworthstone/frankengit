use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::smart_http::server::HttpRepositoryRoute;
use fgit_node::{
    GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionTimeout, NodeConfig, OneNode,
};
use fgit_types::{GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use fgit_wire::{Packet, WireLimits, encode_packets};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        for _ in 0..128 {
            let path = std::env::temp_dir().join(format!(
                "fg-http-routes-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create HTTP route fixture: {error}"),
            }
        }
        panic!("HTTP route fixture collision budget exhausted")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn configuration(
    root: &Scratch,
    name: &str,
    tenant: u8,
    format: GitHashAlgorithm,
) -> NodeConfig {
    NodeConfig::new(
        root.0.join(name),
        TenantId::from_bytes([tenant; 16]),
        RepositoryId::from_bytes([0x72; 16]),
    )
    .with_object_format(format)
    .with_worker_threads(2)
    .with_git_daemon_session_timeout(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
    )
}
pub fn start_node(config: NodeConfig) -> OneNode {
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}
pub fn reopen_node(config: NodeConfig) -> OneNode {
    let mut node = OneNode::open_existing(config).unwrap();
    let generation = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation();
    node.bring_into_service(generation).unwrap();
    node
}
pub fn header(node: &OneNode) -> String {
    format!(
        "frankengit-http-credentials-v1 {} {} {}\n",
        node.tenant_id(),
        node.repository_id(),
        node.repository_incarnation_id()
    )
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn row(token: char, scopes: &str) -> String {
    format!(
        "{} {} {scopes}\n",
        hex(&sha256_digest(token.to_string().repeat(64).as_bytes())),
        PrincipalId::from_bytes([1; 16])
    )
}
pub fn replace(path: &Path, body: &str) {
    let next = path.with_extension("next");
    fs::write(&next, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::rename(next, path).unwrap();
}

pub struct Endpoint {
    pub address: SocketAddr,
}
pub trait Address {
    fn address(&self) -> SocketAddr;
}
impl Address for Endpoint {
    fn address(&self) -> SocketAddr {
        self.address
    }
}
pub struct Server {
    pub address: SocketAddr,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Address for Server {
    fn address(&self) -> SocketAddr {
        self.address
    }
}
impl Server {
    pub fn start(node: OneNode, routes: Vec<HttpRepositoryRoute>, requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let result = node.serve_http_repositories_bounded(
                &listener,
                GitDaemonServerLimits::try_new(requests, 2).unwrap(),
                routes,
                Duration::from_secs(5),
            );
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self {
            address,
            worker: Some(worker),
        }
    }
    pub fn finish(mut self) -> GitDaemonServerReceipt {
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
pub fn connect(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
}
pub fn request_head(method: &str, target: &str, token: char, extra: &str) -> String {
    format!(
        "{method} {target} HTTP/1.1\r\nHost: loopback\r\nAuthorization: Bearer {}\r\n{extra}\r\n",
        token.to_string().repeat(64)
    )
}
pub fn read_reply(stream: TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    stream
        .take(2 * 1024 * 1024)
        .read_to_end(&mut response)
        .unwrap();
    response
}
pub fn exchange(
    server: &impl Address,
    method: &str,
    target: &str,
    token: char,
    extra: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut stream = connect(server.address());
    stream
        .write_all(request_head(method, target, token, extra).as_bytes())
        .unwrap();
    stream.write_all(body).unwrap();
    read_reply(stream)
}
pub fn get(server: &impl Address, path: &str, suffix: &str, token: char) -> Vec<u8> {
    exchange(server, "GET", &format!("{path}{suffix}"), token, "", &[])
}
pub fn status(reply: &[u8], expected: u16) {
    assert!(
        reply.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()),
        "expected {expected}, got {}",
        text(reply)
    );
}
pub fn text(reply: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(reply)
}
pub fn push(server: &impl Address, path: &str, token: char, key: &str, body: &[u8]) -> Vec<u8> {
    exchange(
        server,
        "POST",
        &format!("{path}/git-receive-pack"),
        token,
        &format!(
            "Content-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\nIdempotency-Key: {key}\r\n",
            body.len()
        ),
        body,
    )
}
pub fn push_body(format: GitHashAlgorithm, byte: u8, reference: &str) -> (GitOid, Vec<u8>) {
    let oid = git_object_id(format, GitObjectKind::Blob, &[byte]);
    let zero = "0".repeat(format.digest_len() * 2);
    let mut bytes = encode_packets(
        &[
            Packet::Data(
                format!(
                    "{zero} {oid} {reference}\0report-status object-format={}",
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
    pack.extend_from_slice(&[0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, byte]);
    let sum = u32::from(byte) + 1;
    pack.extend_from_slice(&((sum << 16) | sum).to_be_bytes());
    let digest = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&digest);
    bytes.extend_from_slice(&pack);
    (oid, bytes)
}
