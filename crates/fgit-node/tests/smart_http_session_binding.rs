#![forbid(unsafe_code)]
//! Whole-session key reuse must fail before any new per-command publication.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{AdmissionError, AdmissionLimits, AdmissionResult};
use fgit_authority::{IdempotencyKey, SealFailure};
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId,
    RefName, RepositoryId, TenantId};
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fg-session-binding-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn config(root: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.0.clone(), TenantId::from_bytes([0x71; 16]), RepositoryId::from_bytes([0x72; 16]))
        .with_object_format(format)
}
fn state(node: &OneNode) -> (HeadGeneration, BTreeMap<RefName, GitOid>) {
    let materialized = node.runtime().block_on(node.materialize_admission()).unwrap();
    (materialized.basis().generation(), materialized.snapshot().refs.clone())
}
fn fixture(format: GitHashAlgorithm, byte: u8) -> (GitOid, Vec<u8>) {
    let oid = git_object_id(format, GitObjectKind::Blob, &[byte]);
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.extend_from_slice(&[0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, byte]);
    let a = 1 + u32::from(byte);
    pack.extend_from_slice(&((a << 16) | a).to_be_bytes());
    let trailer = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&trailer);
    (oid, pack)
}
fn perform(node: &OneNode, format: GitHashAlgorithm, names: &[&str], byte: u8,
    key: &[u8], atomic: bool) -> Result<AdmissionResult, NodeSmartHttpRefusal>
{
    let (oid, pack) = fixture(format, byte);
    let zero = "0".repeat(format.digest_len() * 2);
    let mut packets = Vec::new();
    for (index, name) in names.iter().enumerate() {
        let mut command = format!("{zero} {oid} {name}");
        if index == 0 {
            command.push_str(&format!("\0report-status object-format={}{}", format.as_str(),
                if atomic { " atomic" } else { "" }));
        }
        packets.push(Packet::Data(command.into_bytes()));
    }
    packets.push(Packet::Flush);
    let mut body = encode_packets(&packets, &WireLimits::default()).unwrap();
    body.extend_from_slice(&pack);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head = format!("POST {route}/git-receive-pack HTTP/1.1\r\nHost: loopback\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n", body.len());
    let request = parse_head(head.as_bytes(), HttpLimits::default()).unwrap().unwrap();
    let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0x73; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap());
    node.smart_http_receive_rpc_in(&request, &session, &body, HttpLimits::default(),
        AdmissionLimits::default(), &mut || true, &mut Vec::new())
}
fn key_reuse(error: NodeSmartHttpRefusal) {
    let NodeSmartHttpRefusal::ReceiveInterrupted(interrupted) = error else {
        panic!("session coordinator must preserve the typed key-reuse rejection");
    };
    assert!(interrupted.completed_commands().is_empty(), "no child was admitted in this attempt");
    assert!(matches!(interrupted.admission_error(), AdmissionError::Seal(error)
        if matches!(error.as_ref(), SealFailure::Rejected(_))));
}

#[test]
fn changed_shape_content_and_atomicity_cannot_repurpose_a_session_key_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let (mut node, _) = OneNode::init(configuration.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let names = ["refs/tags/first", "refs/tags/second"];
        let original = perform(&node, format, &names, b'x', b"whole-session", false).unwrap();
        assert!(original.commands.iter().all(|command|
            matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
        let published = state(&node);
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(configuration).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        for (offered, byte, atomic) in [
            (vec![names[0], names[1], "refs/tags/appended"], b'x', false),
            (vec![names[0]], b'x', false),
            (vec![names[0], names[1]], b'y', false),
            (vec![names[0], names[1]], b'x', true),
            (vec![names[1], names[0]], b'x', false),
        ] {
            key_reuse(perform(&node, format, &offered, byte, b"whole-session", atomic).unwrap_err());
            assert_eq!(state(&node), published, "key conflict cannot move the head or refs");
        }
        let retry = perform(&node, format, &names, b'x', b"whole-session", false).unwrap();
        assert_eq!(retry, original);
        assert_eq!(state(&node), published);
        let fresh = perform(&node, format, &["refs/tags/appended"], b'x', b"new-session", false).unwrap();
        assert!(matches!(fresh.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        assert_eq!(state(&node).0.get(), published.0.get() + 1);
        node.shutdown().unwrap();
    }
}

#[test]
fn an_atomic_key_cannot_be_reused_as_a_non_atomic_session() {
    let root = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let (mut node, _) = OneNode::init(config(&root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let names = ["refs/tags/one", "refs/tags/two"];
    let original = perform(&node, format, &names, b'x', b"atomic-session", true).unwrap();
    assert_eq!(original.session.tx_ids.len(), 1);
    let published = state(&node);
    key_reuse(perform(&node, format, &names, b'x', b"atomic-session", false).unwrap_err());
    assert_eq!(state(&node), published);
    assert_eq!(perform(&node, format, &names, b'x', b"atomic-session", true).unwrap(), original);
    node.shutdown().unwrap();
}
