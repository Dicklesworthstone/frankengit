#![forbid(unsafe_code)]
//! Atomic Smart HTTP pushes must map every command to one canonical decision.

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};

const A: &str = "refs/tags/atomic-a";
const B: &str = "refs/tags/atomic-b";
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-http-atomic-{}-{}",
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
        TenantId::from_bytes([0xe1; 16]),
        RepositoryId::from_bytes([0xe2; 16]),
    )
    .with_object_format(format)
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xe3; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    )
}
fn blob_pack(format: GitHashAlgorithm) -> (GitOid, Vec<u8>) {
    let body = b"atomic\n";
    let oid = git_object_id(format, GitObjectKind::Blob, body);
    let length = u16::try_from(body.len()).unwrap();
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.push(0x30 | body.len() as u8);
    pack.extend_from_slice(&[0x78, 0x01, 0x01]);
    pack.extend_from_slice(&length.to_le_bytes());
    pack.extend_from_slice(&(!length).to_le_bytes());
    pack.extend_from_slice(body);
    let (a, b) = body.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    pack.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let hash = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&hash);
    (oid, pack)
}
fn body(first: String, second: String, pack: &[u8]) -> Vec<u8> {
    let mut bytes = encode_packets(
        &[
            Packet::Data(first.into_bytes()),
            Packet::Data(second.into_bytes()),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    bytes.extend_from_slice(pack);
    bytes
}
fn push(node: &OneNode, key: &[u8], body: &[u8]) -> (AdmissionResult, Vec<u8>) {
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head = format!(
        "POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let mut response = Vec::new();
    let outcome = node
        .smart_http_receive_stream_in(
            &request,
            &session(key),
            &mut Cursor::new(body),
            HttpLimits::default(),
            AdmissionLimits::default(),
            &mut || true,
            &mut response,
        )
        .unwrap();
    assert_eq!(outcome.commands.len(), 2);
    assert_eq!(outcome.commands[0].tx_id, outcome.commands[1].tx_id);
    assert_eq!(outcome.commands[0].terminal, outcome.commands[1].terminal);
    (outcome, response)
}
fn generation(node: &OneNode) -> u64 {
    node.runtime()
        .block_on(node.materialize_admission())
        .unwrap()
        .basis()
        .generation()
        .get()
}
fn assert_refs(node: &OneNode, expected: Option<GitOid>) {
    let materialized = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    assert_eq!(
        materialized.snapshot().refs.len(),
        if expected.is_some() { 2 } else { 0 }
    );
    for reference in [A, B] {
        let name = RefName::try_new(reference.as_bytes()).unwrap();
        assert_eq!(materialized.snapshot().refs.get(&name).copied(), expected);
    }
}
fn create(format: GitHashAlgorithm) -> (GitOid, Vec<u8>) {
    let (oid, pack) = blob_pack(format);
    let zero = "0".repeat(oid.as_bytes().len() * 2);
    let request = body(
        format!(
            "{zero} {oid} {A}\0report-status atomic object-format={}",
            format.as_str()
        ),
        format!("{zero} {oid} {B}"),
        &pack,
    );
    (oid, request)
}

#[test]
fn atomic_create_retry_reopen_and_delete_preserve_one_decision_for_all_refs() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
        let discovery = format!(
            "GET {route}/info/refs?service=git-receive-pack HTTP/1.1\r\nHost: local\r\n\r\n"
        );
        let request = parse_head(discovery.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let advertisement = node
            .smart_http_receive_discovery_in(
                &request,
                &session(b"discovery"),
                WireLimits::default(),
            )
            .unwrap();
        assert!(
            advertisement
                .body()
                .windows(b" atomic ".len())
                .any(|w| w == b" atomic ")
        );

        let (oid, body) = create(format);
        let before = generation(&node);
        let (first, response) = push(&node, b"atomic-create", &body);
        assert!(matches!(
            first.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(
            generation(&node),
            before + 1,
            "one head transition publishes both refs"
        );
        assert_refs(&node, Some(oid));
        let (retry, retry_response) = push(&node, b"atomic-create", &body);
        assert_eq!(first, retry);
        assert_eq!(response, retry_response);
        assert_eq!(generation(&node), before + 1);
        node.shutdown().unwrap();

        let mut node = OneNode::open_existing(config(&scratch, format)).unwrap();
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(head.receipt().generation())
            .unwrap();
        assert_refs(&node, Some(oid));
        let zero = "0".repeat(oid.as_bytes().len() * 2);
        let deletion = self::body(
            format!(
                "{oid} {zero} {A}\0report-status atomic delete-refs object-format={}",
                format.as_str()
            ),
            format!("{oid} {zero} {B}"),
            &[],
        );
        let before_delete = generation(&node);
        let (outcome, _) = push(&node, b"atomic-delete", &deletion);
        assert!(matches!(
            outcome.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(generation(&node), before_delete + 1);
        assert_refs(&node, None);
        node.shutdown().unwrap();
    }
}

#[test]
fn one_bad_expected_old_refuses_the_whole_atomic_delete_and_the_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(config(&scratch, format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let (oid, creation) = create(format);
        let (created, _) = push(&node, b"establish", &creation);
        assert!(matches!(
            created.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let wrong_old = git_object_id(format, GitObjectKind::Blob, b"different object");
        let zero = "0".repeat(oid.as_bytes().len() * 2);
        let deletion = body(
            format!(
                "{oid} {zero} {A}\0report-status atomic delete-refs object-format={}",
                format.as_str()
            ),
            format!("{wrong_old} {zero} {B}"),
            &[],
        );
        let (refused, response) = push(&node, b"stale-delete", &deletion);
        assert!(matches!(
            refused.commands[0].terminal.outcome,
            DecisionOutcome::Refused { .. }
        ));
        assert_refs(&node, Some(oid));
        for name in [A, B] {
            let record = format!("ng {name} ");
            assert!(
                response
                    .windows(record.len())
                    .any(|w| w == record.as_bytes())
            );
            let success = format!("ok {name}\n");
            assert!(
                !response
                    .windows(success.len())
                    .any(|w| w == success.as_bytes())
            );
        }
        let after = generation(&node);
        let (retry, retry_response) = push(&node, b"stale-delete", &deletion);
        assert_eq!(refused, retry);
        assert_eq!(response, retry_response);
        assert_eq!(generation(&node), after);
        assert_refs(&node, Some(oid));
        node.shutdown().unwrap();
    }
}
