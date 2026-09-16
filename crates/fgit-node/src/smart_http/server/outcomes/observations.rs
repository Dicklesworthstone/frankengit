//! Exercise the real embedded authority beneath HTTP response construction.
//! Binding/seal writes deliberately stop before admission; no outcome is faked.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_authority::{
    AsyncAuthorityStore, ExpectedOld, IdempotencyKey, ImmutableRead, ProposedNew,
    RefCommand, SealAttempt, SemanticRequest, bind_idempotency_key_async,
    idempotency_binding_key, seal_key, seal_request_async,
};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};

use super::{MAX_REPLY_BYTES, Request, Status, execute};
use crate::{LoopbackReceiveSession, NodeConfig, OneNode};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fg-outcome-observations-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn attempt(node: &OneNode, key: &[u8]) -> SealAttempt {
    let old = GitOid::from_hex(node.object_format, &"1".repeat(node.object_format.digest_len() * 2)).unwrap();
    SealAttempt {
        tenant_id: node.tenant_id,
        repository_id: node.repository_id,
        authenticated_principal_id: PrincipalId::from_bytes([0xa3; 16]),
        idempotency_key: IdempotencyKey::new(key.to_vec()).unwrap(),
        request: SemanticRequest::build(fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            node.object_format, true, vec![RefCommand {
                name: RefName::try_new(b"refs/tags/not-published").unwrap(),
                expected_old: ExpectedOld::Exactly(old), proposed_new: ProposedNew::Delete, force: false,
            }], Vec::new(), Vec::new()).unwrap(),
    }
}
fn query(node: &OneNode, attempt: &SealAttempt) -> String {
    let session = LoopbackReceiveSession::authenticated(attempt.authenticated_principal_id,
        attempt.idempotency_key.clone());
    let request = Request { repository_route: "/unused-after-authentication", command_index: None };
    execute(node, &request, &session, MAX_REPLY_BYTES as u64).unwrap().body
}

#[test]
fn incomplete_attempts_remain_nonterminal_and_lookup_does_not_advance_them() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, _) = OneNode::init(NodeConfig::new(scratch.0.clone(),
            TenantId::from_bytes([0xa1; 16]), RepositoryId::from_bytes([0xa2; 16]))
            .with_object_format(format)).unwrap();
        // Deliberately no bring_into_service: recovery is not mutation intake.
        let request = node.request_context();
        let before = node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation();
        let attempt = attempt(&node, b"never-execute-this-key");
        let (tx, _) = attempt.derive().unwrap();
        let binding = idempotency_binding_key(attempt.tenant_id, attempt.repository_id,
            attempt.authenticated_principal_id, &attempt.idempotency_key).unwrap();
        let seal = seal_key(attempt.tenant_id, attempt.repository_id, tx).unwrap();
        let absent = query(&node, &attempt);
        assert!(absent.contains("\"state\":\"key_not_observed\""));
        assert_eq!(query(&node, &attempt), absent);
        assert!(matches!(node.runtime().block_on(node.authority.read_immutable(request.authority(), &binding)).unwrap(), ImmutableRead::Absent));

        node.runtime().block_on(bind_idempotency_key_async(&node.authority,
            request.authority(), &attempt, tx)).unwrap();
        let bound = query(&node, &attempt);
        assert!(bound.contains("\"state\":\"seal_not_observed\""));
        assert!(!bound.contains(&tx.to_string()), "unverified binding targets are not disclosed");
        assert_eq!(query(&node, &attempt), bound);
        assert!(matches!(node.runtime().block_on(node.authority.read_immutable(request.authority(), &seal)).unwrap(), ImmutableRead::Absent));

        node.runtime().block_on(seal_request_async(&node.authority,
            request.authority(), &attempt)).unwrap();
        let sealed = query(&node, &attempt);
        assert!(sealed.contains("\"state\":\"undecided\""));
        assert!(sealed.contains(&format!("\"tx_id\":\"{tx}\"")));
        assert_eq!(query(&node, &attempt), sealed);
        for response in [absent, bound, sealed] {
            assert!(response.contains("\"terminal\":false"));
            assert!(response.contains("\"decision\":null"));
            assert!(response.contains("\"absence_proves_non_commit\":false"));
            assert!(!response.contains("never-execute-this-key"));
        }
        let after = node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation();
        assert_eq!(after, before, "reads cannot turn a staged seal into a decision");
        node.shutdown().unwrap();
    }
}

#[test]
fn corrupt_seal_is_an_error_not_an_absent_or_undecided_observation() {
    let scratch = Scratch::new();
    let (node, _) = OneNode::init(NodeConfig::new(scratch.0.clone(),
        TenantId::from_bytes([0xa1; 16]), RepositoryId::from_bytes([0xa2; 16]))).unwrap();
    let request = node.request_context();
    let attempt = attempt(&node, b"corrupt-seal-key");
    let (tx, _) = attempt.derive().unwrap();
    node.runtime().block_on(bind_idempotency_key_async(&node.authority,
        request.authority(), &attempt, tx)).unwrap();
    let slot = seal_key(attempt.tenant_id, attempt.repository_id, tx).unwrap();
    node.runtime().block_on(node.authority.put_if_absent(request.authority(), &slot, b"not a canonical seal")).unwrap();
    let session = LoopbackReceiveSession::authenticated(attempt.authenticated_principal_id,
        attempt.idempotency_key.clone());
    let request = Request { repository_route: "/unused-after-authentication", command_index: None };
    let error = match execute(&node, &request, &session, MAX_REPLY_BYTES as u64) {
        Ok(_) => panic!("corrupt required evidence cannot produce an observation"),
        Err(error) => error,
    };
    assert_eq!(error.status, Status::Unavailable);
    assert_eq!(error.code, "recovery_unavailable");
    let mut output = Vec::new();
    error.send(&mut output, fgit_wire::smart_http::HttpVersion::Http11).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("\"outcome_unknown\":true"));
    assert!(!text.contains("\"state\":\"undecided\""));
    assert!(!text.contains("corrupt-seal-key"));
    node.shutdown().unwrap();
}
