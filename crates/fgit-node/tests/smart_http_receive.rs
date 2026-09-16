#![forbid(unsafe_code)]
//! Real HTTP framing, native pack quarantine and durable authority, without a
//! fake admission backend. Tags intentionally permit the fixture blob roots.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{
    LoopbackReceiveSession, NodeConfig, NodeReceiveTransportRefusal, NodeSmartHttpRefusal, OneNode,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use fgit_wire::smart_http::rpc::RpcError;
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};

static NEXT: AtomicU64 = AtomicU64::new(1);
const TAG: &str = "refs/tags/http-blob";
const BLOB: &[u8] = b"http blob\n";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-http-receive-{}-{sequence}",
            std::process::id()
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
        TenantId::from_bytes([0x91; 16]),
        RepositoryId::from_bytes([0x92; 16]),
    )
    .with_object_format(format)
}

fn serving_node(scratch: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(config(scratch, format)).expect("node initializes");
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}

fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x93; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    )
}

fn refs(node: &OneNode) -> BTreeMap<RefName, GitOid> {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .expect("canonical head materializes")
        .snapshot()
        .refs
        .clone()
}

fn head_bytes(node: &OneNode, length: Option<usize>) -> Vec<u8> {
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let framing = match length {
        Some(length) => format!("Content-Length: {length}\r\n"),
        None => "Transfer-Encoding: chunked\r\n".to_owned(),
    };
    format!(
        "POST {route}/git-receive-pack HTTP/1.1\r\nHost: loopback\r\nContent-Type: application/x-git-receive-pack-request\r\n{framing}\r\n"
    )
    .into_bytes()
}

fn chunked(body: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    // Split pkt-line length prefixes, command bodies and the PACK trailer.
    for fragment in body.chunks(3) {
        wire.extend_from_slice(format!("{:x}\r\n", fragment.len()).as_bytes());
        wire.extend_from_slice(fragment);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"0\r\n\r\n");
    wire
}

fn post<W: Write>(
    node: &OneNode,
    session: &LoopbackReceiveSession,
    body: &[u8],
    use_chunks: bool,
    output: &mut W,
) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
    let header = head_bytes(node, if use_chunks { None } else { Some(body.len()) });
    let head = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    let wire = if use_chunks { chunked(body) } else { body.to_vec() };
    node.smart_http_receive_rpc_in(
        &head,
        session,
        &wire,
        HttpLimits::default(),
        AdmissionLimits::default(),
        &mut || true,
        output,
    )
}

fn packets(command: String, pack: &[u8]) -> Vec<u8> {
    let mut body = encode_packets(
        &[Packet::Data(command.into_bytes()), Packet::Flush],
        &WireLimits::default(),
    )
    .unwrap();
    body.extend_from_slice(pack);
    body
}

fn blob_pack(format: GitHashAlgorithm, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 16, "fixture uses a one-byte object header");
    let length = u16::try_from(body.len()).unwrap();
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.push(0x30 | u8::try_from(body.len()).unwrap());
    // Zlib containing one final, uncompressed DEFLATE block.
    pack.extend_from_slice(&[0x78, 0x01, 0x01]);
    pack.extend_from_slice(&length.to_le_bytes());
    pack.extend_from_slice(&(!length).to_le_bytes());
    pack.extend_from_slice(body);
    let (a, b) = body.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    pack.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let trailer = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&trailer);
    pack
}

fn create(format: GitHashAlgorithm) -> (GitOid, Vec<u8>) {
    let oid = git_object_id(format, GitObjectKind::Blob, BLOB);
    let zero = "0".repeat(oid.as_bytes().len() * 2);
    let command = format!(
        "{zero} {oid} {TAG}\0report-status object-format={}",
        format.as_str()
    );
    (oid, packets(command, &blob_pack(format, BLOB)))
}

fn assert_committed(outcome: &AdmissionResult) {
    assert_eq!(outcome.commands.len(), 1);
    assert!(matches!(
        outcome.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn assert_report(output: &[u8], record: &[u8]) {
    assert!(output.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let boundary = output.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let header = std::str::from_utf8(&output[..boundary]).unwrap();
    assert!(header.contains("application/x-git-receive-pack-result"));
    let length = header.lines().find_map(|line| {
        line.strip_prefix("Content-Length: ").map(|value| value.trim().parse::<usize>().unwrap())
    }).expect("fixed response length");
    assert_eq!(length, output.len() - boundary);
    assert!(output[boundary..].windows(record.len()).any(|w| w == record));
    assert!(output.ends_with(b"0000"));
}

#[test]
fn sha1_and_sha256_pushes_survive_both_http_framings_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for use_chunks in [false, true] {
            let scratch = Scratch::new();
            let node = serving_node(&scratch, format);
            let (oid, body) = create(format);
            let mut output = Vec::new();
            let outcome = post(&node, &session(b"create"), &body, use_chunks, &mut output).unwrap();
            assert_committed(&outcome);
            assert_report(&output, b"ok refs/tags/http-blob\n");
            assert_eq!(refs(&node).get(&RefName::try_new(TAG.as_bytes()).unwrap()), Some(&oid));
            node.shutdown().unwrap();
            let reopened = OneNode::open_existing(config(&scratch, format)).unwrap();
            assert_eq!(refs(&reopened).get(&RefName::try_new(TAG.as_bytes()).unwrap()), Some(&oid));
            reopened.shutdown().unwrap();
        }
    }
}

#[test]
fn delete_only_push_needs_no_pack_in_either_object_domain() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = serving_node(&scratch, format);
        let (oid, body) = create(format);
        assert_committed(&post(&node, &session(b"create"), &body, false, &mut Vec::new()).unwrap());
        let zero = "0".repeat(oid.as_bytes().len() * 2);
        let delete = packets(format!("{oid} {zero} {TAG}\0report-status delete-refs"), &[]);
        let mut output = Vec::new();
        assert_committed(&post(&node, &session(b"delete"), &delete, true, &mut output).unwrap());
        assert_report(&output, b"ok refs/tags/http-blob\n");
        assert!(refs(&node).is_empty());
        node.shutdown().unwrap();
    }
}

#[test]
fn incomplete_or_pipelined_bodies_never_stage_or_publish() {
    for use_chunks in [false, true] {
        for trailing in [false, true] {
            let scratch = Scratch::new();
            let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
            let (oid, body) = create(GitHashAlgorithm::Sha1);
            let header = head_bytes(&node, if use_chunks { None } else { Some(body.len()) });
            let head = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
            let mut wire = if use_chunks { chunked(&body) } else { body };
            if trailing {
                wire.extend_from_slice(b"NEXT");
            } else {
                wire.pop();
            }
            let mut output = Vec::new();
            let result = node.smart_http_receive_rpc_in(
                &head, &session(b"incomplete"), &wire, HttpLimits::default(),
                AdmissionLimits::default(), &mut || true, &mut output,
            );
            if trailing {
                assert!(matches!(result, Err(NodeSmartHttpRefusal::TrailingRequestBytes { count: 4 })));
            } else {
                assert!(matches!(result, Err(NodeSmartHttpRefusal::Rpc(error))
                    if matches!(error.as_ref(), RpcError::IncompleteRequest)));
            }
            assert!(output.is_empty());
            assert!(refs(&node).is_empty());
            assert!(node.read_git_object(oid).is_err(), "no quarantine handoff before HTTP EOF");
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn authentication_and_cell_state_precede_untrusted_git_parsing() {
    let scratch = Scratch::new();
    let (node, _) = OneNode::init(config(&scratch, GitHashAlgorithm::Sha1)).unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        post(&node, &LoopbackReceiveSession::Anonymous, b"not git", false, &mut output),
        Err(NodeSmartHttpRefusal::UnauthenticatedReceive)
    ));
    assert!(matches!(
        post(&node, &session(b"bootstrap"), b"not git", false, &mut output),
        Err(NodeSmartHttpRefusal::ReceiveTransport(error))
            if matches!(error.as_ref(), NodeReceiveTransportRefusal::CellState(_))
    ));
    assert!(output.is_empty());
    assert!(refs(&node).is_empty());
    node.shutdown().unwrap();
}

#[test]
fn cancellation_before_intake_never_stages_objects() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let (oid, body) = create(GitHashAlgorithm::Sha1);
    let header = head_bytes(&node, Some(body.len()));
    let head = parse_head(&header, HttpLimits::default()).unwrap().unwrap();
    let mut output = Vec::new();
    assert!(matches!(
        node.smart_http_receive_rpc_in(
            &head, &session(b"cancel"), &body, HttpLimits::default(),
            AdmissionLimits::default(), &mut || false, &mut output,
        ),
        Err(NodeSmartHttpRefusal::Rpc(error)) if matches!(error.as_ref(), RpcError::Cancelled)
    ));
    assert!(output.is_empty());
    assert!(refs(&node).is_empty());
    assert!(node.read_git_object(oid).is_err());
    node.shutdown().unwrap();
}

#[test]
fn a_corrupt_pack_is_refused_without_an_http_success_or_publication() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let (oid, mut body) = create(GitHashAlgorithm::Sha1);
    *body.last_mut().unwrap() ^= 1;
    let mut output = Vec::new();
    assert!(post(&node, &session(b"corrupt"), &body, true, &mut output).is_err());
    assert!(output.is_empty());
    assert!(refs(&node).is_empty());
    assert!(node.read_git_object(oid).is_err());
    node.shutdown().unwrap();
}

struct FailingWriter {
    remaining: usize,
}
impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "simulated lost response"));
        }
        let count = bytes.len().min(self.remaining);
        self.remaining -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "simulated flush failure"))
    }
}

#[test]
fn lost_response_retains_the_canonical_outcome_and_same_key_recovers_it() {
    // Fail before any response, during the response, and only at final flush.
    for remaining in [0, 64, usize::MAX] {
        let scratch = Scratch::new();
        let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
        let (_, body) = create(GitHashAlgorithm::Sha1);
        let authenticated = session(b"ambiguous-response");
        let result = post(&node, &authenticated, &body, false, &mut FailingWriter { remaining });
        let first = match result {
            Err(NodeSmartHttpRefusal::ReceiveResponse { outcome, .. }) => outcome,
            other => panic!("expected a preserved canonical result, got {other:?}"),
        };
        assert_committed(&first);
        let before_retry = refs(&node);
        assert_eq!(before_retry.len(), 1);
        let mut output = Vec::new();
        // Changing transport framing must not change client retry identity.
        let retried = post(&node, &authenticated, &body, true, &mut output).unwrap();
        assert_committed(&retried);
        assert_eq!(retried.commands[0].terminal.outcome, first.commands[0].terminal.outcome);
        assert_eq!(refs(&node), before_retry);
        assert_report(&output, b"ok refs/tags/http-blob\n");
        node.shutdown().unwrap();
    }
}

#[test]
fn a_new_key_does_not_turn_stale_expected_old_into_a_second_success() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let (_, body) = create(GitHashAlgorithm::Sha1);
    assert_committed(&post(&node, &session(b"first"), &body, false, &mut Vec::new()).unwrap());
    let before = refs(&node);
    let mut output = Vec::new();
    let refused = post(&node, &session(b"different-request"), &body, false, &mut output).unwrap();
    assert_eq!(refused.commands.len(), 1);
    assert!(!matches!(refused.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
    assert_report(&output, b"ng refs/tags/http-blob ");
    assert_eq!(refs(&node), before);
    node.shutdown().unwrap();
}
