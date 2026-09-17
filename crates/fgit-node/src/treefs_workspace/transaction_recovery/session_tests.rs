//! Native embedded-authority regression cases, not fabricated terminal outcomes.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{AdmissionContext, AdmissionResult};
use fgit_admission::policy_bridge::receive_session::recovery::SessionRecovery;
use fgit_authority::key_recovery::RequestRecovery;
use fgit_authority::{AsyncAuthorityStore, ExpectedOld, IdempotencyKey, ImmutableKey,
    OutcomeLookup, ProposedNew, RefCommand, SealAttempt, SemanticRequest,
    bind_idempotency_key_async, seal_request_async};
use fgit_codec::{Encoder, encode_body};
use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration,
    PrincipalId, RefName, RepositoryId, TenantId};
use fgit_wire::{Packet, WireLimits, encode_packets};
use fgit_wire::smart_http::{HttpLimits, parse_head};

use crate::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fg-session-recovery-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn config(root: &Scratch, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.0.clone(), TenantId::from_bytes([0xb1; 16]),
        RepositoryId::from_bytes([0xb2; 16])).with_object_format(format)
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0xb3; 16]),
        IdempotencyKey::new(key.to_vec()).unwrap())
}
fn context(node: &OneNode, key: &[u8]) -> AdmissionContext {
    AdmissionContext { head_key: node.head_key.clone(), tenant_id: node.tenant_id,
        repository_id: node.repository_id, object_format: node.object_format,
        principal_id: PrincipalId::from_bytes([0xb3; 16]),
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap() }
}
fn generation(node: &OneNode) -> u64 {
    node.runtime.block_on(node.authenticate_authority_head()).unwrap().receipt().generation().get()
}
fn query(node: &OneNode, key: &[u8]) -> SessionRecovery {
    node.runtime.block_on(node.recover_receive_session_in(&node.request_context(), &session(key))).unwrap()
}
fn descriptor_key(context: &AdmissionContext) -> ImmutableKey {
    // Deliberate raw protocol fixture: tests can corrupt the carrier without
    // adding a production API for overwriting immutable recovery metadata.
    let mut bytes = b"fg/receive-session/v1/".to_vec();
    bytes.extend_from_slice(context.tenant_id.as_bytes());
    bytes.extend_from_slice(context.repository_id.as_bytes());
    bytes.extend_from_slice(context.principal_id.as_bytes());
    bytes.extend_from_slice(context.idempotency_key.digest().bytes().as_bytes());
    ImmutableKey::new(bytes).unwrap()
}
fn descriptor(request: &SemanticRequest, order: &[u16]) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.write_scalar(1u32);
    encoder.write_bytes("receive-session.request", &encode_body(request).unwrap()).unwrap();
    encoder.write_sequence("receive-session.wire-order", order, |encoder, index| {
        encoder.write_scalar(*index); Ok(())
    }).unwrap();
    encoder.into_bytes()
}
fn request(format: GitHashAlgorithm, names: &[&[u8]]) -> SemanticRequest {
    let oid = GitOid::from_hex(format, &"1".repeat(format.digest_len() * 2)).unwrap();
    SemanticRequest::build(fgit_authority::RECEIVE_ADMISSION_SCHEMA, format, false,
        names.iter().map(|name| RefCommand {
            name: RefName::try_new(name).unwrap(), expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(oid), force: false,
        }).collect(), Vec::new(), Vec::new()).unwrap()
}
fn attempt(context: &AdmissionContext, key: IdempotencyKey, request: SemanticRequest) -> SealAttempt {
    SealAttempt { tenant_id: context.tenant_id, repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id, idempotency_key: key, request }
}
fn bind_shape(node: &OneNode, context: &AdmissionContext) -> Vec<SealAttempt> {
    let full = request(node.object_format, &[b"refs/tags/z", b"refs/tags/a"]);
    let full = attempt(context, context.idempotency_key.clone(), full);
    let cx = node.request_context();
    node.runtime.block_on(bind_idempotency_key_async(&node.authority, cx.authority(),
        &full, full.derive().unwrap().0)).unwrap();
    let mut children = Vec::new();
    for (index, name) in [b"refs/tags/z".as_slice(), b"refs/tags/a"].into_iter().enumerate() {
        let child = attempt(context, OneNode::receive_command_recovery_key(&context.idempotency_key, index).unwrap(),
            request(node.object_format, &[name]));
        node.runtime.block_on(bind_idempotency_key_async(&node.authority, cx.authority(),
            &child, child.derive().unwrap().0)).unwrap();
        children.push(child);
    }
    children
}

fn push(node: &OneNode, key: &[u8]) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
    let format = node.object_format;
    let oid = git_object_id(format, GitObjectKind::Blob, b"x");
    let zero = "0".repeat(format.digest_len() * 2);
    let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    pack.extend_from_slice(&[0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121]);
    let trailer = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&pack).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&pack).to_vec(),
    };
    pack.extend_from_slice(&trailer);
    let mut body = encode_packets(&[
        Packet::Data(format!("{oid} {oid} refs/tags/z-stale\0report-status object-format={}", format.as_str()).into_bytes()),
        Packet::Data(format!("{zero} {oid} refs/tags/a-good").into_bytes()),
        Packet::Data(format!("{zero} {oid} refs/tags/m-good").into_bytes()), Packet::Flush,
    ], &WireLimits::default()).unwrap();
    body.extend_from_slice(&pack);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head = format!("POST {route}/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: {}\r\n\r\n", body.len());
    let request = parse_head(head.as_bytes(), HttpLimits::default()).unwrap().unwrap();
    node.smart_http_receive_rpc_in(&request, &session(key), &body, HttpLimits::default(),
        Default::default(), &mut || true, &mut Vec::new())
}

#[test]
fn complete_mixed_session_recovers_original_order_after_reopening_without_serving() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let (mut node, _) = OneNode::init(configuration.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let before = generation(&node);
        let original = push(&node, b"original-session").unwrap();
        assert!(matches!(original.commands[0].terminal.outcome, DecisionOutcome::Refused { .. }));
        assert!(original.commands[1..].iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
        assert_eq!(generation(&node), before + 3, "descriptor staging publishes no extra decision");
        node.shutdown().unwrap();
        let node = OneNode::open_existing(configuration).unwrap();
        let recovered = query(&node, b"original-session");
        let SessionRecovery::Recovered(receipt) = &recovered else { panic!("native receive must retain its descriptor") };
        assert!(receipt.all_terminal());
        assert_eq!(receipt.commands().len(), 3);
        for (index, name) in ["refs/tags/z-stale", "refs/tags/a-good", "refs/tags/m-good"].into_iter().enumerate() {
            let command = &receipt.commands()[index];
            assert_eq!(command.index(), index);
            assert_eq!(command.reference().as_str(), Some(name));
            let RequestRecovery::Recovered(known) = command.recovery() else { panic!("all commands must be sealed") };
            assert_eq!(known.tx_id(), original.commands[index].tx_id);
            assert_eq!(known.outcome(), OutcomeLookup::Decided(original.commands[index].terminal));
        }
        assert_eq!(query(&node, b"original-session"), recovered);
        assert_eq!(generation(&node), before + 3);
        let foreign = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0xb4; 16]),
            IdempotencyKey::new(b"original-session".to_vec()).unwrap());
        assert_eq!(node.runtime.block_on(node.recover_receive_session_in(&node.request_context(), &foreign)).unwrap(), SessionRecovery::NotObserved);
        node.shutdown().unwrap();
    }
}

#[test]
fn verified_unsealed_shape_and_undecided_child_do_not_become_empty_or_complete() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, _) = OneNode::init(config(&root, format)).unwrap();
        let context = context(&node, b"interrupted-before-seal");
        let children = bind_shape(&node, &context);
        let cx = node.request_context();
        let bytes = descriptor(&request(format, &[b"refs/tags/z", b"refs/tags/a"]), &[1, 0]);
        node.runtime.block_on(node.authority.put_if_absent(cx.authority(), &descriptor_key(&context), &bytes)).unwrap();
        let before = generation(&node);
        let SessionRecovery::Recovered(receipt) = query(&node, b"interrupted-before-seal") else { panic!("verified shape must be retained") };
        assert_eq!(receipt.commands().len(), 2);
        assert!(!receipt.all_terminal());
        assert!(receipt.commands().iter().all(|command| matches!(command.recovery(), RequestRecovery::SealNotObserved)));
        node.runtime.block_on(seal_request_async(&node.authority, cx.authority(), &children[0])).unwrap();
        let SessionRecovery::Recovered(sealed) = query(&node, b"interrupted-before-seal") else { panic!("shape remains recoverable") };
        assert!(!sealed.all_terminal());
        assert!(matches!(sealed.commands()[0].recovery(), RequestRecovery::Recovered(known) if known.outcome() == OutcomeLookup::Undecided));
        assert!(matches!(sealed.commands()[1].recovery(), RequestRecovery::SealNotObserved));
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn validly_encoded_omission_reordering_and_format_substitution_fail_binding_verification() {
    for variant in 0..4 {
        let root = Scratch::new();
        let (node, _) = OneNode::init(config(&root, GitHashAlgorithm::Sha1)).unwrap();
        let context = context(&node, b"do-not-trust-the-carrier");
        bind_shape(&node, &context);
        let bytes = match variant {
            0 => descriptor(&request(GitHashAlgorithm::Sha1, &[b"refs/tags/a"]), &[0]),
            1 => descriptor(&request(GitHashAlgorithm::Sha1, &[b"refs/tags/z", b"refs/tags/a"]), &[0, 1]),
            2 => descriptor(&request(GitHashAlgorithm::Sha256, &[b"refs/tags/z", b"refs/tags/a"]), &[1, 0]),
            _ => b"not a descriptor".to_vec(),
        };
        node.runtime.block_on(node.authority.put_if_absent(node.request_context().authority(),
            &descriptor_key(&context), &bytes)).unwrap();
        let before = generation(&node);
        assert!(node.runtime.block_on(node.recover_receive_session_in(&node.request_context(),
            &session(b"do-not-trust-the-carrier"))).is_err(), "variant {variant}");
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn conflicting_descriptor_blocks_every_child_before_publication() {
    let root = Scratch::new();
    let (mut node, _) = OneNode::init(config(&root, GitHashAlgorithm::Sha1)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let context = context(&node, b"broken-carrier");
    node.runtime.block_on(node.authority.put_if_absent(node.request_context().authority(),
        &descriptor_key(&context), b"corrupt immutable carrier")).unwrap();
    let before = generation(&node);
    let error = push(&node, b"broken-carrier").unwrap_err();
    let NodeSmartHttpRefusal::ReceiveInterrupted(interrupted) = error else { panic!("descriptor conflict must precede admission") };
    assert!(interrupted.completed_commands().is_empty());
    assert_eq!(generation(&node), before);
    assert!(node.runtime.block_on(node.materialize_admission()).unwrap().snapshot().refs.is_empty());
    node.shutdown().unwrap();
}

#[test]
fn missing_descriptor_and_cancellation_do_not_create_metadata_or_terminal_knowledge() {
    let root = Scratch::new();
    let (node, _) = OneNode::init(config(&root, GitHashAlgorithm::Sha1)).unwrap();
    let before = generation(&node);
    assert_eq!(query(&node, b"never-submitted"), SessionRecovery::NotObserved);
    let request = node.request_context();
    request.cancel();
    assert!(node.runtime.block_on(node.recover_receive_session_in(&request, &session(b"never-submitted"))).is_err());
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
