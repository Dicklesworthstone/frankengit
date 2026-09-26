#![forbid(unsafe_code)]
//! Real TCP -> HTTP -> native Git -> durable authority round trips.
//! No subprocess Git, fake authority, or fabricated quarantine is used here.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{
    GitDaemonServerLimits, GitDaemonServerReceipt, GitDaemonSessionTimeout, NodeConfig, OneNode,
};
use fgit_types::{
    GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId, TenantId,
};
use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpLimits};
use fgit_wire::{Packet, PktLineDecoder, WireLimits, encode_packets};

const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-http-server-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn config(scratch: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        scratch.0.clone(),
        TenantId::from_bytes([0xc1; 16]),
        RepositoryId::from_bytes([0xc2; 16]),
    )
    .with_object_format(format)
    .with_git_daemon_session_timeout(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
    )
}
fn initialized(config: NodeConfig) -> OneNode {
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}
struct Server {
    address: SocketAddr,
    route: String,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Server {
    fn start(node: OneNode, sessions: usize, receive: bool, in_flight: usize) -> Self {
        let route =
            String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let result = node.serve_smart_http_bounded(
                &listener,
                GitDaemonServerLimits::try_new(sessions, in_flight).unwrap(),
                sha256_digest(TOKEN.as_bytes()),
                PrincipalId::from_bytes([0xc3; 16]),
                receive,
                Duration::from_secs(30),
            );
            let cleanup = node.shutdown();
            cleanup.expect("HTTP parent and children shut down");
            result.expect("bounded HTTP listener completes")
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
fn client(address: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    stream
}
fn exchange(server: &Server, request: &[u8], fragment: usize) -> Vec<u8> {
    let mut stream = client(server.address);
    for bytes in request.chunks(fragment) {
        stream.write_all(bytes).unwrap();
    }
    // Ordinary HTTP clients do NOT half-close their upload. The server must
    // finish from Content-Length/chunk termination rather than transport EOF.
    let mut response = Vec::new();
    (&mut stream)
        .take(4 * 1024 * 1024)
        .read_to_end(&mut response)
        .unwrap();
    response
}
fn request(server: &Server, method: &str, suffix: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "{method} {}{suffix} HTTP/1.1\r\nHost: loopback\r\n{headers}\r\n",
        server.route
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn auth() -> String {
    format!("Authorization: Bearer {TOKEN}\r\n")
}
fn post_headers(service: &str, length: usize, extra: &str) -> String {
    format!(
        "{}Content-Type: application/x-git-{service}-request\r\nContent-Length: {length}\r\n{extra}",
        auth()
    )
}
fn response_body(response: &[u8]) -> Vec<u8> {
    let split = response
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .expect("complete HTTP response");
    let head = std::str::from_utf8(&response[..split]).unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let wire = &response[split + 4..];
    if head.contains("Transfer-Encoding: chunked") {
        let mut decoder = BodyDecoder::new(BodyFraming::Chunked, HttpLimits::default()).unwrap();
        let mut decoded = Vec::new();
        let mut cursor = 0;
        while cursor < wire.len() {
            let step = decoder.push(&wire[cursor..]).unwrap();
            assert!(step.consumed > 0);
            cursor += step.consumed;
            decoded.extend_from_slice(step.data);
        }
        decoder.finish().unwrap();
        decoded
    } else {
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(wire.len(), length);
        wire.to_vec()
    }
}
fn packets(command: Vec<u8>, pack: &[u8]) -> Vec<u8> {
    let mut bytes = encode_packets(
        &[Packet::Data(command), Packet::Flush],
        &WireLimits::default(),
    )
    .unwrap();
    bytes.extend_from_slice(pack);
    bytes
}
fn chunked(body: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    for fragment in body.chunks(7) {
        wire.extend_from_slice(format!("{:x}\r\n", fragment.len()).as_bytes());
        wire.extend_from_slice(fragment);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}
fn object_header(kind: u8, size: usize) -> Vec<u8> {
    let mut remaining = size >> 4;
    let mut first = (kind << 4) | (size & 15) as u8;
    if remaining != 0 {
        first |= 128;
    }
    let mut header = vec![first];
    while remaining != 0 {
        let mut byte = (remaining & 127) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 128;
        }
        header.push(byte);
    }
    header
}
fn stored_zlib(body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(body.len()).unwrap();
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&(!length).to_le_bytes());
    out.extend_from_slice(body);
    let (a, b) = body.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521;
        (a, (b + a) % 65521)
    });
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}
fn commit_pack(format: GitHashAlgorithm) -> (GitOid, Vec<u8>, BTreeSet<Vec<u8>>) {
    let blob = b"native HTTP round trip\n".to_vec();
    let blob_id = git_object_id(format, GitObjectKind::Blob, &blob);
    let mut tree = b"100644 README\0".to_vec();
    tree.extend_from_slice(blob_id.as_bytes());
    let tree_id = git_object_id(format, GitObjectKind::Tree, &tree);
    let commit = format!("tree {tree_id}\nauthor HTTP <http@example.test> 1 +0000\ncommitter HTTP <http@example.test> 1 +0000\n\nHTTP test\n").into_bytes();
    let commit_id = git_object_id(format, GitObjectKind::Commit, &commit);
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x03".to_vec();
    for (kind, body) in [(1, &commit), (2, &tree), (3, &blob)] {
        pack.extend_from_slice(&object_header(kind, body.len()));
        pack.extend_from_slice(&stored_zlib(body));
    }
    let checksum = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&checksum);
    (commit_id, pack, BTreeSet::from([blob, tree, commit]))
}
fn generation(config: &NodeConfig, expected: Option<GitOid>) -> HeadGeneration {
    let node = OneNode::open_existing(config.clone()).unwrap();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    assert_eq!(
        materialized.snapshot().refs.get(&reference).copied(),
        expected
    );
    let generation = materialized.basis().generation();
    node.shutdown().unwrap();
    generation
}
fn round_trip(format: GitHashAlgorithm) {
    let scratch = Scratch::new();
    let config = config(&scratch, format);
    let server = Server::start(initialized(config.clone()), 6, true, 2);
    let discovery = request(
        &server,
        "GET",
        "/info/refs?service=git-upload-pack",
        &format!("{}Git-Protocol: version=2\r\n", auth()),
        b"",
    );
    let body = response_body(&exchange(&server, &discovery, 1));
    assert!(
        body.windows(b"fetch=shallow filter".len())
            .any(|b| b == b"fetch=shallow filter")
    );
    assert!(
        body.windows(format!("object-format={}", format.as_str()).len())
            .any(|b| b == format!("object-format={}", format.as_str()).as_bytes())
    );

    let (commit, pack, payloads) = commit_pack(format);
    let zero = "0".repeat(commit.as_bytes().len() * 2);
    let create = packets(
        format!(
            "{zero} {commit} refs/heads/main\0report-status object-format={}",
            format.as_str()
        )
        .into_bytes(),
        &pack,
    );
    let encoded = chunked(&create);
    let headers = format!(
        "{}Content-Type: application/x-git-receive-pack-request\r\nTransfer-Encoding: chunked\r\nIdempotency-Key: http-create-1\r\nExpect: 100-continue\r\n",
        auth()
    );
    let head = request(&server, "POST", "/git-receive-pack", &headers, b"");
    let mut connection = client(server.address);
    connection.write_all(&head).unwrap();
    let mut interim = Vec::new();
    while !interim.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        connection.read_exact(&mut byte).unwrap();
        interim.push(byte[0]);
        assert!(interim.len() <= 1024);
    }
    assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    for fragment in encoded.chunks(3) {
        connection.write_all(fragment).unwrap();
    }
    let mut response = Vec::new();
    connection.read_to_end(&mut response).unwrap();
    drop(connection);
    assert!(
        response_body(&response)
            .windows(b"ok refs/heads/main".len())
            .any(|b| b == b"ok refs/heads/main")
    );
    let published = generation(&config, Some(commit));
    assert_ne!(published, HeadGeneration::FIRST);

    // The same semantic request/key across a different HTTP framing resolves
    // the existing terminal result, without a second head advancement.
    let retry = request(
        &server,
        "POST",
        "/git-receive-pack",
        &post_headers(
            "receive-pack",
            create.len(),
            "Idempotency-Key: http-create-1\r\n",
        ),
        &create,
    );
    assert!(
        response_body(&exchange(&server, &retry, 4096))
            .windows(b"ok refs/heads/main".len())
            .any(|b| b == b"ok refs/heads/main")
    );
    assert_eq!(generation(&config, Some(commit)), published);

    let legacy = request(
        &server,
        "GET",
        "/info/refs?service=git-upload-pack",
        &auth(),
        b"",
    );
    let body = response_body(&exchange(&server, &legacy, 4096));
    assert!(body.starts_with(b"001e# service=git-upload-pack\n0000"));
    assert!(
        body.windows(commit.to_string().len())
            .any(|b| b == commit.to_string().as_bytes())
    );

    let fetch = encode_packets(
        &[
            Packet::Data(b"command=fetch\n".to_vec()),
            Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
            Packet::Delimiter,
            Packet::Data(format!("want {commit}\n").into_bytes()),
            Packet::Data(b"done\n".to_vec()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    let fetch = request(
        &server,
        "POST",
        "/git-upload-pack",
        &post_headers("upload-pack", fetch.len(), "Git-Protocol: version=2\r\n"),
        &fetch,
    );
    let body = response_body(&exchange(&server, &fetch, 2));
    let mut decoder = PktLineDecoder::new(WireLimits::default()).unwrap();
    let decoded = decoder.push(&body).unwrap();
    decoder.finish().unwrap();
    let mut selected = Vec::new();
    for packet in decoded {
        if let Packet::Data(bytes) = packet
            && bytes.first() == Some(&1)
        {
            selected.extend_from_slice(&bytes[1..]);
        }
    }
    let received = fgit_pack::read_verified_pack(
        &selected,
        format,
        &fgit_pack::PackLimits::default(),
        &mut || true,
        &fgit_pack::NativeChecksumVerifier,
    )
    .expect("HTTP fetch returns a native checksum-verified pack");
    assert_eq!(received.entries().len(), 3);
    assert_eq!(
        received
            .entries()
            .iter()
            .map(|entry| entry.inflated.clone())
            .collect::<BTreeSet<_>>(),
        payloads
    );

    let delete = packets(
        format!(
            "{commit} {zero} refs/heads/main\0report-status delete-refs object-format={}",
            format.as_str()
        )
        .into_bytes(),
        b"",
    );
    let delete = request(
        &server,
        "POST",
        "/git-receive-pack",
        &post_headers(
            "receive-pack",
            delete.len(),
            "Idempotency-Key: http-delete-1\r\n",
        ),
        &delete,
    );
    response_body(&exchange(&server, &delete, 4096));
    let receipt = server.finish();
    assert_eq!(receipt.accepted_sessions(), 6);
    assert_eq!(receipt.completed_sessions(), 6);
    assert_eq!(receipt.refused_sessions(), 0);
    assert!(generation(&config, None) > published);
}
#[test]
fn sha1_push_fetch_delete_and_retry_cross_the_real_http_listener() {
    round_trip(GitHashAlgorithm::Sha1);
}
#[test]
fn sha256_push_fetch_delete_and_retry_cross_the_real_http_listener() {
    round_trip(GitHashAlgorithm::Sha256);
}

#[test]
fn authentication_and_framing_fail_before_continue_or_publication() {
    let scratch = Scratch::new();
    let config = config(&scratch, GitHashAlgorithm::Sha1);
    let server = Server::start(initialized(config.clone()), 6, true, 2);
    let cases = [
        (
            request(
                &server,
                "GET",
                "/info/refs?service=git-upload-pack",
                "",
                b"",
            ),
            "401",
        ),
        (
            request(
                &server,
                "GET",
                "/info/refs?service=git-upload-pack",
                "X-Forwarded-User: admin\r\nX-Forwarded-Proto: https\r\n",
                b"",
            ),
            "401",
        ),
        (
            request(
                &server,
                "GET",
                "/info/refs?service=git-upload-pack",
                &format!("{}{}", auth(), auth()),
                b"",
            ),
            "400",
        ),
        (
            request(
                &server,
                "POST",
                "/git-receive-pack",
                &post_headers("receive-pack", 4, "Expect: 100-continue\r\n"),
                b"",
            ),
            "400",
        ),
        (
            request(
                &server,
                "POST",
                "/git-receive-pack",
                &post_headers(
                    "receive-pack",
                    128 * 1024 * 1024 + 1,
                    "Idempotency-Key: oversized\r\nExpect: 100-continue\r\n",
                ),
                b"",
            ),
            "413",
        ),
        (
            request(
                &server,
                "POST",
                "/git-receive-pack",
                &post_headers(
                    "receive-pack",
                    4,
                    "Transfer-Encoding: chunked\r\nIdempotency-Key: ambiguous\r\nExpect: 100-continue\r\n",
                ),
                b"",
            ),
            "400",
        ),
    ];
    for (request, status) in cases {
        let response = exchange(&server, &request, 4096);
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with(&format!("HTTP/1.1 {status}")), "{text}");
        assert!(!text.contains("100 Continue"));
        assert!(!text.contains(TOKEN));
    }
    let receipt = server.finish();
    assert_eq!(receipt.refused_sessions(), 6);
    assert_eq!(generation(&config, None), HeadGeneration::FIRST);
}

#[test]
fn readonly_service_accepts_fetch_discovery_but_not_receive_routes() {
    let scratch = Scratch::new();
    let config = config(&scratch, GitHashAlgorithm::Sha1);
    let server = Server::start(initialized(config.clone()), 3, false, 1);
    let fetch = request(
        &server,
        "GET",
        "/info/refs?service=git-upload-pack",
        &auth(),
        b"",
    );
    response_body(&exchange(&server, &fetch, 4096));
    for request in [
        request(
            &server,
            "GET",
            "/info/refs?service=git-receive-pack",
            &auth(),
            b"",
        ),
        request(
            &server,
            "POST",
            "/git-receive-pack",
            &post_headers("receive-pack", 4, "Idempotency-Key: denied\r\n"),
            b"0000",
        ),
    ] {
        assert!(exchange(&server, &request, 4096).starts_with(b"HTTP/1.1 403"));
    }
    let receipt = server.finish();
    assert_eq!(receipt.completed_sessions(), 1);
    assert_eq!(receipt.refused_sessions(), 2);
    assert_eq!(generation(&config, None), HeadGeneration::FIRST);
}

#[test]
fn an_idle_service_exits_with_no_accepted_children() {
    let scratch = Scratch::new();
    let node = initialized(config(&scratch, GitHashAlgorithm::Sha1));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let result = node.serve_smart_http_bounded(
        &listener,
        GitDaemonServerLimits::try_new(10, 2).unwrap(),
        sha256_digest(TOKEN.as_bytes()),
        PrincipalId::from_bytes([0xc3; 16]),
        false,
        Duration::from_millis(25),
    );
    let cleanup = node.shutdown();
    let receipt = result.unwrap();
    cleanup.unwrap();
    assert_eq!(receipt.accepted_sessions(), 0);
    assert_eq!(receipt.completed_sessions(), 0);
    assert_eq!(receipt.refused_sessions(), 0);
}

#[test]
fn a_partial_header_expires_and_releases_the_only_worker_slot() {
    let scratch = Scratch::new();
    let config = config(&scratch, GitHashAlgorithm::Sha1).with_git_daemon_session_timeout(
        GitDaemonSessionTimeout::try_new(Duration::from_millis(100)).unwrap(),
    );
    let server = Server::start(initialized(config), 2, false, 1);
    let mut stalled = client(server.address);
    stalled.write_all(b"GET ").unwrap();
    let second = request(
        &server,
        "GET",
        "/info/refs?service=git-upload-pack",
        "",
        b"",
    );
    assert!(exchange(&server, &second, 4096).starts_with(b"HTTP/1.1 401"));
    let mut response = Vec::new();
    stalled.read_to_end(&mut response).unwrap();
    drop(stalled);
    assert!(response.starts_with(b"HTTP/1.1 408"));
    let receipt = server.finish();
    assert_eq!(receipt.refused_sessions(), 2);
}

#[test]
fn a_stalled_push_upload_holds_no_writer_admission_while_another_push_commits() {
    // The server admits one writer at a time (x2mv.4.27), but a receive
    // takes that admission only after its upload completes. Client A stops
    // halfway through its body; client B's complete push must still be
    // decided promptly, and A is then admitted once its upload completes.
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = config(&scratch, format);
        let server = Server::start(initialized(config.clone()), 2, true, 2);
        let (commit, pack, _) = commit_pack(format);
        let zero = "0".repeat(commit.as_bytes().len() * 2);
        let body = |name: &str| {
            packets(
                format!(
                    "{zero} {commit} {name}\0report-status object-format={}",
                    format.as_str()
                )
                .into_bytes(),
                &pack,
            )
        };
        let has = |reply: &[u8], line: &[u8]| reply.windows(line.len()).any(|b| b == line);

        let stalled_body = body("refs/heads/stalled");
        let (half, rest) = stalled_body.split_at(stalled_body.len() / 2);
        let mut stalled = client(server.address);
        stalled
            .write_all(&request(
                &server,
                "POST",
                "/git-receive-pack",
                &post_headers(
                    "receive-pack",
                    stalled_body.len(),
                    "Idempotency-Key: http-stalled\r\n",
                ),
                half,
            ))
            .unwrap();

        let started = std::time::Instant::now();
        let prompt_body = body("refs/heads/main");
        let prompt = request(
            &server,
            "POST",
            "/git-receive-pack",
            &post_headers(
                "receive-pack",
                prompt_body.len(),
                "Idempotency-Key: http-prompt\r\n",
            ),
            &prompt_body,
        );
        let reply = response_body(&exchange(&server, &prompt, 4096));
        assert!(has(&reply, b"ok refs/heads/main"));
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "a stalled upload delayed an unrelated push by {:?}",
            started.elapsed()
        );

        // Twin: the stalled client finishes its upload and is admitted too.
        stalled.write_all(rest).unwrap();
        let mut response = Vec::new();
        stalled.read_to_end(&mut response).unwrap();
        assert!(has(&response_body(&response), b"ok refs/heads/stalled"));

        let receipt = server.finish();
        assert_eq!(receipt.completed_sessions(), 2);
        assert_eq!(receipt.refused_sessions(), 0);
        generation(&config, Some(commit));
    }
}
