#![forbid(unsafe_code)]
//! Streaming transport -> native quarantine -> durable authority regressions.
//! These tests use the real node and native PACK grammar, not a publishing mock.

use std::cell::Cell;
use std::io::{self, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{
    GitDaemonServerLimits, GitDaemonSessionTimeout, LoopbackReceiveSession, NodeConfig,
    NodeReceiveTransportRefusal, NodeSmartHttpRefusal, OneNode,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RepositoryId, TenantId,
};
use fgit_wire::smart_http::rpc::RpcError;
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};

static NEXT: AtomicU64 = AtomicU64::new(1);
const BLOB: &[u8] = b"stream payload\n";
const TAG: &str = "refs/tags/streamed";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-http-stream-{}-{}",
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
        TenantId::from_bytes([0xd1; 16]),
        RepositoryId::from_bytes([0xd2; 16]),
    )
    .with_object_format(format)
    .with_git_daemon_session_timeout(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap(),
    )
}
fn node(scratch: &Scratch, format: GitHashAlgorithm, serving: bool) -> OneNode {
    let (mut node, _) = OneNode::init(config(scratch, format)).unwrap();
    if serving {
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
    }
    node
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xd3; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    )
}
fn header(node: &OneNode, service: &str, length: usize, chunked: bool) -> Vec<u8> {
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let framing = if chunked {
        "Transfer-Encoding: chunked".to_owned()
    } else {
        format!("Content-Length: {length}")
    };
    format!("POST {route}/git-{service} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-{service}-request\r\n{framing}\r\n\r\n").into_bytes()
}
fn command(text: String, pack: &[u8]) -> Vec<u8> {
    let mut bytes = encode_packets(
        &[Packet::Data(text.into_bytes()), Packet::Flush],
        &WireLimits::default(),
    )
    .unwrap();
    bytes.extend_from_slice(pack);
    bytes
}
fn create(format: GitHashAlgorithm) -> (GitOid, Vec<u8>) {
    let oid = git_object_id(format, GitObjectKind::Blob, BLOB);
    let length = u16::try_from(BLOB.len()).unwrap();
    assert!(BLOB.len() < 16);
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.push(0x30 | BLOB.len() as u8);
    pack.extend_from_slice(&[0x78, 0x01, 0x01]);
    pack.extend_from_slice(&length.to_le_bytes());
    pack.extend_from_slice(&(!length).to_le_bytes());
    pack.extend_from_slice(BLOB);
    let (a, b) = BLOB.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    pack.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let digest = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&digest);
    let zero = "0".repeat(oid.as_bytes().len() * 2);
    (
        oid,
        command(
            format!(
                "{zero} {oid} {TAG}\0report-status object-format={}",
                format.as_str()
            ),
            &pack,
        ),
    )
}
fn chunked(bytes: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    for bytes in bytes.chunks(7) {
        wire.extend_from_slice(format!("{:x}\r\n", bytes.len()).as_bytes());
        wire.extend_from_slice(bytes);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}
struct Fragmented<'a> {
    bytes: &'a [u8],
    width: usize,
    consumed: &'a Cell<usize>,
    interrupt: bool,
}
impl Read for Fragmented<'_> {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        assert!(target.len() <= 16 * 1024);
        if self.interrupt {
            self.interrupt = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = self.bytes.len().min(self.width).min(target.len());
        target[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        self.consumed.set(self.consumed.get() + count);
        self.interrupt = true;
        Ok(count)
    }
}
struct NoRead;
impl Read for NoRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("request must finish/refuse before another transport read")
    }
}
fn assert_committed(outcome: &AdmissionResult) {
    assert_eq!(outcome.commands.len(), 1);
    assert!(matches!(
        outcome.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}
fn assert_unstaged(node: &OneNode, oid: GitOid) {
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    assert!(materialized.snapshot().refs.is_empty());
    assert!(
        node.read_git_object(oid).is_err(),
        "incomplete HTTP cannot stage verified objects"
    );
}

#[test]
fn fragmented_push_retry_delete_and_reopen_work_in_both_formats_and_framings() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for chunks in [false, true] {
            let scratch = Scratch::new();
            let node = node(&scratch, format, true);
            let (oid, payload) = create(format);
            let wire = if chunks {
                chunked(&payload)
            } else {
                payload.clone()
            };
            let head = header(&node, "receive-pack", wire.len(), chunks);
            let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
            let consumed = Cell::new(0);
            let mut fragmented = Fragmented {
                bytes: &wire,
                width: 1,
                consumed: &consumed,
                interrupt: true,
            };
            let mut response = Vec::new();
            let first = node
                .smart_http_receive_stream_in(
                    &request,
                    &session(b"create"),
                    &mut fragmented,
                    HttpLimits::default(),
                    AdmissionLimits::default(),
                    &mut || true,
                    &mut response,
                )
                .unwrap();
            assert_committed(&first);
            assert_eq!(consumed.get(), wire.len());
            assert!(response.ends_with(b"0000"));
            assert!(
                response
                    .windows(b"ok refs/tags/streamed\n".len())
                    .any(|w| w == b"ok refs/tags/streamed\n")
            );
            let generation = node
                .runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .generation();
            // No additional read after the final HTTP byte, even with a live
            // peer that has not sent socket EOF. Retry returns the same decision.
            let mut retry_body = Cursor::new(&wire).chain(NoRead);
            let mut retry_response = Vec::new();
            let retry = node
                .smart_http_receive_stream_in(
                    &request,
                    &session(b"create"),
                    &mut retry_body,
                    HttpLimits::default(),
                    AdmissionLimits::default(),
                    &mut || true,
                    &mut retry_response,
                )
                .unwrap();
            assert_committed(&retry);
            assert_eq!(first.commands[0].tx_id, retry.commands[0].tx_id);
            assert_eq!(response, retry_response);
            assert_eq!(
                generation,
                node.runtime()
                    .block_on(node.materialize_admission())
                    .unwrap()
                    .basis()
                    .generation()
            );
            node.shutdown().unwrap();

            let mut reopened = OneNode::open_existing(config(&scratch, format)).unwrap();
            reopened.bring_into_service(generation).unwrap();
            let before = reopened
                .runtime()
                .block_on(reopened.materialize_admission())
                .unwrap();
            assert!(before.snapshot().refs.values().any(|id| *id == oid));
            reopened.read_git_object(oid).unwrap();
            let zero = "0".repeat(oid.as_bytes().len() * 2);
            let deletion = command(
                format!(
                    "{oid} {zero} {TAG}\0report-status delete-refs object-format={}",
                    format.as_str()
                ),
                &[],
            );
            let wire = if chunks { chunked(&deletion) } else { deletion };
            let head = header(&reopened, "receive-pack", wire.len(), chunks);
            let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
            let result = reopened
                .smart_http_receive_stream_in(
                    &request,
                    &session(b"delete"),
                    &mut Cursor::new(wire),
                    HttpLimits::default(),
                    AdmissionLimits::default(),
                    &mut || true,
                    &mut Vec::new(),
                )
                .unwrap();
            assert_committed(&result);
            assert!(
                reopened
                    .runtime()
                    .block_on(reopened.materialize_admission())
                    .unwrap()
                    .snapshot()
                    .refs
                    .is_empty()
            );
            reopened.shutdown().unwrap();
        }
    }
}

#[test]
fn complete_pack_inside_unfinished_or_invalid_http_never_stages_objects() {
    for chunks in [false, true] {
        for suffix in [b"".as_slice(), b"NEXT".as_slice()] {
            let scratch = Scratch::new();
            let node = node(&scratch, GitHashAlgorithm::Sha1, true);
            let (oid, payload) = create(GitHashAlgorithm::Sha1);
            let mut wire = if chunks { chunked(&payload) } else { payload };
            let declared = wire.len();
            if suffix.is_empty() {
                wire.pop(); // With chunked framing the PACK itself stays complete.
            } else {
                wire.extend_from_slice(suffix);
            }
            let head = header(&node, "receive-pack", declared, chunks);
            let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
            let mut response = Vec::new();
            let result = node.smart_http_receive_stream_in(
                &request,
                &session(b"invalid-http"),
                &mut Cursor::new(wire),
                HttpLimits::default(),
                AdmissionLimits::default(),
                &mut || true,
                &mut response,
            );
            assert!(result.is_err());
            assert!(response.is_empty());
            assert_unstaged(&node, oid);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn authentication_cell_and_cancellation_gates_precede_stream_reads() {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha1, false);
    let head = header(&node, "receive-pack", 1024, false);
    let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
    let call = |session: &LoopbackReceiveSession, live: bool| {
        node.smart_http_receive_stream_in(
            &request,
            session,
            &mut NoRead,
            HttpLimits::default(),
            AdmissionLimits::default(),
            &mut || live,
            &mut Vec::new(),
        )
    };
    assert!(matches!(
        call(&LoopbackReceiveSession::anonymous(), true),
        Err(NodeSmartHttpRefusal::UnauthenticatedReceive)
    ));
    assert!(
        matches!(call(&session(b"bootstrapping"), true), Err(NodeSmartHttpRefusal::ReceiveTransport(error))
        if matches!(*error, NodeReceiveTransportRefusal::CellState(_)))
    );
    assert!(
        matches!(call(&session(b"cancelled"), false), Err(NodeSmartHttpRefusal::Rpc(error))
        if matches!(*error, RpcError::Cancelled))
    );
    node.shutdown().unwrap();
}

#[test]
fn malformed_git_is_refused_without_reading_the_remainder_of_the_declared_body() {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha1, true);
    for service in ["receive-pack", "upload-pack"] {
        let head = header(&node, service, 1024 * 1024, false);
        let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
        let mut reader = Cursor::new(b"zzzz").chain(NoRead);
        let mut response = Vec::new();
        let result = if service == "receive-pack" {
            node.smart_http_receive_stream_in(
                &request,
                &session(b"malformed"),
                &mut reader,
                HttpLimits::default(),
                AdmissionLimits::default(),
                &mut || true,
                &mut response,
            )
            .map(|_| ())
        } else {
            node.smart_http_upload_stream_in(
                &request,
                &mut reader,
                WireLimits::default(),
                HttpLimits::default(),
                1024 * 1024,
                &mut || true,
                &mut response,
            )
            .map(|_| ())
        };
        assert!(matches!(result, Err(NodeSmartHttpRefusal::Rpc(_))));
        assert!(response.is_empty());
    }
    node.shutdown().unwrap();
}

#[test]
fn cancellation_during_fragmented_ingress_cannot_stage_or_publish() {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha256, true);
    let (oid, payload) = create(GitHashAlgorithm::Sha256);
    let head = header(&node, "receive-pack", payload.len(), false);
    let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
    let consumed = Cell::new(0);
    let mut reader = Fragmented {
        bytes: &payload,
        width: 7,
        consumed: &consumed,
        interrupt: true,
    };
    let mut response = Vec::new();
    let result = node.smart_http_receive_stream_in(
        &request,
        &session(b"cancel-in-body"),
        &mut reader,
        HttpLimits::default(),
        AdmissionLimits::default(),
        &mut || consumed.get() < 21,
        &mut response,
    );
    assert!(
        matches!(result, Err(NodeSmartHttpRefusal::Rpc(error)) if matches!(*error, RpcError::Cancelled))
    );
    assert!(consumed.get() < payload.len());
    assert!(response.is_empty());
    assert_unstaged(&node, oid);
    node.shutdown().unwrap();
}

#[test]
fn fragmented_upload_matches_slice_response_without_waiting_for_eof() {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha256, true);
    let body = encode_packets(
        &[
            Packet::Data(b"command=ls-refs\n".to_vec()),
            Packet::Data(b"object-format=sha256\n".to_vec()),
            Packet::Delimiter,
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    let head = String::from_utf8(header(&node, "upload-pack", body.len(), false))
        .unwrap()
        .replace(
            "Host: local\r\n",
            "Host: local\r\nGit-Protocol: version=2\r\n",
        );
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let mut expected = Vec::new();
    node.smart_http_upload_rpc_in(
        &request,
        &body,
        WireLimits::default(),
        HttpLimits::default(),
        1024 * 1024,
        &mut || true,
        &mut expected,
    )
    .unwrap();
    let consumed = Cell::new(0);
    let reader = Fragmented {
        bytes: &body,
        width: 1,
        consumed: &consumed,
        interrupt: true,
    };
    let mut actual = Vec::new();
    let receipt = node
        .smart_http_upload_stream_in(
            &request,
            &mut reader.chain(NoRead),
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut || true,
            &mut actual,
        )
        .unwrap();
    assert!(!receipt.pack_requested());
    assert_eq!(actual, expected);
    node.shutdown().unwrap();
}

#[test]
fn lost_streamed_reply_retains_the_actual_canonical_result() {
    struct BrokenWriter;
    impl Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha1, true);
    let (oid, payload) = create(GitHashAlgorithm::Sha1);
    let head = header(&node, "receive-pack", payload.len(), false);
    let request = parse_head(&head, HttpLimits::default()).unwrap().unwrap();
    let result = node.smart_http_receive_stream_in(
        &request,
        &session(b"lost-reply"),
        &mut Cursor::new(payload),
        HttpLimits::default(),
        AdmissionLimits::default(),
        &mut || true,
        &mut BrokenWriter,
    );
    let Err(NodeSmartHttpRefusal::ReceiveResponse { outcome, .. }) = result else {
        panic!("lost reply must retain its canonical outcome")
    };
    assert_committed(&outcome);
    let after = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    assert!(after.snapshot().refs.values().any(|id| *id == oid));
    node.shutdown().unwrap();
}

#[test]
fn tcp_server_rejects_bad_git_before_client_finishes_uploading() {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha1, true);
    let route = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let result = node.serve_smart_http_bounded(
            &listener,
            GitDaemonServerLimits::try_new(2, 2).unwrap(),
            sha256_digest(&[b'a'; 64]),
            PrincipalId::from_bytes([0xd3; 16]),
            true,
            Duration::from_secs(30),
        );
        node.shutdown().unwrap();
        result.unwrap()
    });
    let mut responses = Vec::new();
    for service in ["receive-pack", "upload-pack"] {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        write!(stream, "POST {route}/git-{service} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\nIdempotency-Key: bad-stream\r\nContent-Type: application/x-git-{service}-request\r\nContent-Length: 1048576\r\n\r\nzzzz", "a".repeat(64)).unwrap();
        // Keep the write half OPEN and deliberately withhold the remaining
        // declared megabyte. A buffering gateway waits for it and times out;
        // the streaming parser must instead return its grammar refusal now.
        let mut response = Vec::new();
        stream.take(4096).read_to_end(&mut response).unwrap();
        responses.push(response);
    }
    let receipt = worker.join().unwrap();
    assert_eq!(receipt.accepted_sessions(), 2);
    assert_eq!(receipt.refused_sessions(), 2);
    for response in responses {
        assert!(
            response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(!response.windows(4).any(|w| w == b"zzzz"));
    }
}
