#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{AdmissionError, AdmissionLimits};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest};
use fgit_git_object::ParseLimits;
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeReceiveTransportRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use fgit_wire::receive::{ReceiveContext, ReceiveError, ReceiveLimits, SignedPushProfile};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits, encode_packets};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory {
    root: PathBuf,
}

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "frankengit-production-receive-handoff-{}-{sequence}",
            std::process::id()
        ));
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn node(root: PathBuf) -> OneNode {
    OneNode::init(NodeConfig::new(
        root,
        TenantId::from_bytes([0x41; 16]),
        RepositoryId::from_bytes([0x42; 16]),
    ))
    .expect("node initializes")
    .0
}

fn receive_context() -> ReceiveContext {
    let limits = ReceiveLimits::default();
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(b"report-status delete-refs", &limits.wire)
            .expect("fixed capabilities parse"),
        limits,
        SignedPushProfile::Refuse,
    )
    .expect("fixed receive context is coherent")
}

fn packet_line(command: Vec<u8>, pack: &[u8]) -> Vec<u8> {
    let mut input = encode_packets(
        &[Packet::Data(command), Packet::Flush],
        &WireLimits::default(),
    )
    .expect("bounded command packet encodes");
    input.extend_from_slice(pack);
    input
}

fn object_header(kind: u8, declared_size: usize) -> Vec<u8> {
    let mut remaining = declared_size;
    let mut first = (kind << 4) | u8::try_from(remaining & 0x0f).expect("masked size");
    remaining >>= 4;
    if remaining == 0 {
        return vec![first];
    }
    first |= 0x80;
    let mut header = vec![first];
    while remaining != 0 {
        let mut next = u8::try_from(remaining & 0x7f).expect("masked size");
        remaining >>= 7;
        if remaining != 0 {
            next |= 0x80;
        }
        header.push(next);
    }
    header
}

fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("small bounded fixture");
    let mut output = vec![0x78, 0x01, 0x01];
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(&(!length).to_le_bytes());
    output.extend_from_slice(bytes);
    let (adler_a, adler_b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next_a = (a + u32::from(*byte)) % 65_521;
        (next_a, (b + next_a) % 65_521)
    });
    output.extend_from_slice(&((adler_b << 16) | adler_a).to_be_bytes());
    output
}

fn one_blob_pack(body: &[u8]) -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.extend_from_slice(&object_header(3, body.len()));
    pack.extend_from_slice(&zlib_stored(body));
    let trailer = sha1_digest(&pack);
    pack.extend_from_slice(&trailer);
    pack
}

fn authenticated_session() -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x73; 16]),
        IdempotencyKey::new(b"production-receive-handoff-retry-key".to_vec())
            .expect("bounded retry key constructs"),
    )
}

fn zero_oid() -> &'static str {
    "0000000000000000000000000000000000000000"
}

#[test]
fn raw_object_bearing_receive_is_quarantined_then_durably_admitted() {
    let scratch = ScratchDirectory::new();
    let node = node(scratch.path().join("node"));
    let materialization_request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&materialization_request))
        .expect("empty genesis state materializes");
    let blob = b"quarantined production blob\n";
    let object_id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, blob);
    let command = format!("{} {object_id} refs/heads/main\0report-status", zero_oid()).into_bytes();
    let input = packet_line(command, &one_blob_pack(blob));
    let request = node.request_context();
    let mut live = || true;

    let outcome = node
        .runtime()
        .block_on(node.receive_loopback_pack_durable_in(
            &request,
            &authenticated_session(),
            &materialized,
            receive_context(),
            &input,
            ParseLimits::default(),
            AdmissionLimits::default(),
            &mut live,
        ))
        .expect("verified raw pack reaches durable admission");

    assert_eq!(outcome.commands.len(), 1);
    assert!(matches!(
        outcome.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    let after_request = node.request_context();
    let after = node
        .runtime()
        .block_on(node.materialize_admission_in(&after_request))
        .expect("committed receive rematerializes");
    assert_eq!(after.snapshot().refs.len(), 1);
    assert!(
        after.snapshot().refs.values().any(|oid| *oid == object_id),
        "the authority-selected ref must name the native object verified from the raw pack"
    );
    node.shutdown().expect("node closes cleanly");
}

#[test]
fn raw_receive_refuses_anonymous_session_before_unpacking() {
    let scratch = ScratchDirectory::new();
    let node = node(scratch.path().join("node"));
    let materialization_request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&materialization_request))
        .expect("empty genesis state materializes");
    let request = node.request_context();
    let mut live = || true;

    let refusal = node
        .runtime()
        .block_on(node.receive_loopback_pack_durable_in(
            &request,
            &LoopbackReceiveSession::anonymous(),
            &materialized,
            receive_context(),
            b"not parsed for anonymous callers",
            ParseLimits::default(),
            AdmissionLimits::default(),
            &mut live,
        ));

    assert!(matches!(
        refusal,
        Err(NodeReceiveTransportRefusal::Unauthenticated)
    ));
    node.shutdown().expect("node closes cleanly");
}

#[test]
fn raw_receive_cancellation_prevents_quarantine_handoff_and_publication() {
    let scratch = ScratchDirectory::new();
    let node = node(scratch.path().join("node"));
    let materialization_request = node.request_context();
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission_in(&materialization_request))
        .expect("empty genesis state materializes");
    let blob = b"cancelled quarantine blob\n";
    let object_id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, blob);
    let command = format!("{} {object_id} refs/heads/main\0report-status", zero_oid()).into_bytes();
    let input = packet_line(command, &one_blob_pack(blob));
    let request = node.request_context();
    let mut cancelled = || false;

    let refusal = node
        .runtime()
        .block_on(node.receive_loopback_pack_durable_in(
            &request,
            &authenticated_session(),
            &materialized,
            receive_context(),
            &input,
            ParseLimits::default(),
            AdmissionLimits::default(),
            &mut cancelled,
        ));

    assert!(matches!(
        refusal,
        Err(NodeReceiveTransportRefusal::Admission(error))
            if matches!(error.as_ref(), AdmissionError::Receive(ReceiveError::Cancelled))
    ));
    let after_request = node.request_context();
    let after = node
        .runtime()
        .block_on(node.materialize_admission_in(&after_request))
        .expect("cancelled receive leaves the empty head materializable");
    assert!(after.snapshot().refs.is_empty());
    node.shutdown().expect("node closes cleanly");
}
