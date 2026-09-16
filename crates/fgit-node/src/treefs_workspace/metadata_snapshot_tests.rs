//! Real embedded publications supply the retained head chain; reads may not
//! publish, follow a caller-supplied object directly, or cross their budget.
use super::*;
use crate::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_authority::IdempotencyKey;
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_types::{CANONICAL_CODEC_VERSION, DecisionOutcome, DigestAlgorithmId, DigestBytes,
    GitHashAlgorithm, PrincipalId, RepositoryId, TenantId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("fg-retained-metadata-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
fn node(root: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(NodeConfig::new(root.0.clone(),
        TenantId::from_bytes([0xb1; 16]), RepositoryId::from_bytes([0xb2; 16]))
        .with_object_format(format)).unwrap();
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
    node
}
fn basis(node: &OneNode) -> PublicationBasis {
    node.runtime().block_on(node.materialize_admission()).unwrap().basis().clone()
}
fn publish(node: &OneNode, number: u64) {
    let command = IssueCommand { number: IssueNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open { title: format!("Issue {number}"), body: String::new(), labels: Vec::new() } };
    let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0xb3; 16]),
        IdempotencyKey::new(format!("snapshot-issue-{number}").into_bytes()).unwrap());
    let result = node.runtime().block_on(node.admit_issue_durable_in(&node.request_context(),
        &session, &command, Default::default())).unwrap();
    assert!(matches!(result.1.outcome, DecisionOutcome::Committed { .. }));
}

#[test]
fn exact_ancestors_are_selected_without_changing_authority_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let genesis = basis(&node);
        publish(&node, 1);
        let first = basis(&node);
        publish(&node, 2);
        let current = basis(&node);
        let request = node.request_context();
        for target in [&genesis, &first, &current] {
            let selected = node.runtime().block_on(select(&node.authority, request.authority(),
                &current, Some(target.id()), &|| false)).unwrap();
            assert_eq!(&selected, target);
        }
        assert_eq!(node.runtime().block_on(select(&node.authority, request.authority(),
            &current, None, &|| false)).unwrap(), current);
        assert_eq!(basis(&node), current, "historical reads never replace the authority head");
        node.shutdown().unwrap();
    }
}

#[test]
fn transition_budget_is_exact_and_unknown_tokens_do_not_become_current_reads() {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha1);
    let genesis = basis(&node);
    publish(&node, 1);
    let first = basis(&node);
    publish(&node, 2);
    let current = basis(&node);
    let request = node.request_context();
    assert_eq!(node.runtime().block_on(select_bounded(&node.authority, request.authority(),
        &current, Some(first.id()), 1, &|| false)).unwrap(), first);
    assert!(matches!(node.runtime().block_on(select_bounded(&node.authority, request.authority(),
        &current, Some(genesis.id()), 1, &|| false)), Err(SnapshotReadRefusal::Unavailable)));
    assert_eq!(node.runtime().block_on(select_bounded(&node.authority, request.authority(),
        &current, Some(current.id()), 0, &|| false)).unwrap(), current);
    let unknown = RepositoryAuthorityHeadId::from_digest(DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION, DigestBytes::try_new(&[0xf3; 32]).unwrap());
    assert!(matches!(node.runtime().block_on(select(&node.authority, request.authority(),
        &current, Some(unknown), &|| false)), Err(SnapshotReadRefusal::Unavailable)));
    assert_eq!(basis(&node), current);
    node.shutdown().unwrap();
}

#[test]
fn cancellation_before_or_during_ancestry_does_not_return_a_partial_basis() {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha256);
    let genesis = basis(&node);
    publish(&node, 1);
    publish(&node, 2);
    let current = basis(&node);
    for stop_at in [0, 2, 4] {
        let calls = AtomicUsize::new(0);
        let cancelled = || calls.fetch_add(1, Ordering::SeqCst) >= stop_at;
        let request = node.request_context();
        let result = node.runtime().block_on(select(&node.authority, request.authority(),
            &current, Some(genesis.id()), &cancelled));
        assert!(matches!(result, Err(SnapshotReadRefusal::Admission(error))
            if matches!(*error, AdmissionError::AsyncProjectionUnavailable(RefusalCode::CancellationInProgress))));
    }
    assert_eq!(basis(&node), current);
    node.shutdown().unwrap();
}

#[test]
fn invalid_transition_is_verified_instead_of_followed_as_an_ancestry_hint() {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha1);
    let genesis = basis(&node);
    publish(&node, 1);
    let current = basis(&node);
    // Only this private verifier test can supply an unauthenticated current
    // body. Production callers obtain it from node-owned materialization.
    let mut invalid_body = current.body().clone();
    invalid_body.predecessor_head_id = Some(current.id());
    let cyclic = PublicationBasis::new(current.id(), invalid_body);
    let request = node.request_context();
    assert!(matches!(node.runtime().block_on(select(&node.authority, request.authority(),
        &cyclic, Some(genesis.id()), &|| false)), Err(SnapshotReadRefusal::Admission(_))));
    let mut foreign = current.body().clone();
    foreign.repository_id = RepositoryId::from_bytes([0xff; 16]);
    assert!(!same_read_epoch(current.body(), &foreign));
    assert_eq!(basis(&node), current);
    node.shutdown().unwrap();
}
