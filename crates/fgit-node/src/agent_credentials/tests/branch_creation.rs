//! Scoped task branches reuse native quarantine, protection and durable retry.

use super::*;
use super::source_publication::{
    PATCH, assert_committed, assert_refused, candidate, reference, scope, seed,
};
use crate::NodeWorkspaceRefusal;
use fgit_admission::{AdmissionContext, AdmissionResult, AsyncAdmissionProjection, AsyncProjectionFailure};
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_forge::event::protection::ProtectedBranch;
use fgit_identity::agent::{SOURCE_BRANCH_CREATE, SOURCE_PUBLISH};
use fgit_types::{GitOid, RefName};

fn task() -> RefName {
    RefName::try_new(b"refs/heads/agent/task").unwrap()
}

fn issue_creator(node: &OneNode, token: &str, retry: &str, destination: &RefName) -> AgentCredentialCommand {
    let command = AgentCredentialCommand {
        id: agent_credential_id(token.as_bytes()).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: AgentCredentialAction::issuance(
            AgentCredentialGrant { operations: SOURCE_BRANCH_CREATE, ..grant(node) },
            Some(scope(destination, &[b"src"])),
        ),
    };
    committed(credential(node, &command, actor(1), retry));
    command
}

fn create(node: &OneNode, run: &AgentRequest, destination: &RefName, target: GitOid) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    let creation = run.source_branch_creation(node).unwrap();
    node.runtime().block_on(node.create_agent_branch_in(
        &run.context(node), &creation, destination, target, Default::default(),
    ))
}

fn refs(node: &OneNode) -> std::collections::BTreeMap<RefName, GitOid> {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap().snapshot().refs.clone()
}

fn revoke(node: &OneNode, command: &AgentCredentialCommand, retry: &str) {
    let current = node.runtime()
        .block_on(node.read_agent_credential_in(&node.request_context(), command.id))
        .unwrap().unwrap();
    committed(credential(node, &AgentCredentialCommand {
        id: command.id,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: AgentCredentialAction::revocation(current.grant, current.source_scope),
    }, actor(1), retry));
}

#[test]
fn task_branch_recovers_original_decision_after_tip_changes_rotation_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let base = seed(&node);
        let token = bearer('a');
        let issued = issue_creator(&node, &token, "task-issue", &task());
        let run = authentication(&node, &token, "create-task", SOURCE_BRANCH_CREATE);
        assert!(run.run.allowed_operation_classes().contains(OperationClass::PublishRefTransaction));
        assert!(run.source_publication(&node).is_err());
        let published = create(&node, &run, &task(), base).unwrap();
        assert_committed(&published);
        assert_eq!(refs(&node)[&task()], base);
        assert_eq!(refs(&node)[&reference()], base);
        let original = provenance(&node, actor(2), "create-task");
        assert_eq!(original.agent_provenance(), Some(&run.authentication));

        // Move every visible branch beyond the original tip. The old commit
        // remains history but no longer qualifies for a fresh task branch.
        let next = candidate(&node, base, PATCH);
        assert_committed(&node.runtime().block_on(node.apply_workspace_bundle_durable_in(
            &node.command_request_context(None), actor(1), b"advance-main",
            &reference(), base, next.candidate_commit, next.bundle_bytes(),
        )).unwrap());
        assert_committed(&node.runtime().block_on(node.admit_branch_updates_durable_in(
            &node.command_request_context(None), &operator(actor(1), "advance-task"),
            &[RefCommand { name: task(), expected_old: ExpectedOld::Exactly(base),
                proposed_new: ProposedNew::Update(next.candidate_commit), force: false }],
            Default::default(),
        )).unwrap());
        revoke(&node, &issued, "revoke-creator");
        let replacement = bearer('b');
        let other = RefName::try_new(b"refs/heads/agent/other").unwrap();
        issue_creator(&node, &replacement, "rotated-creator", &other);
        let retry = authentication(&node, &replacement, "create-task", SOURCE_BRANCH_CREATE);
        let recovered = create(&node, &retry, &task(), base).unwrap();
        assert_eq!(recovered.commands, published.commands);
        assert_eq!(provenance(&node, actor(2), "create-task"), original);
        assert_eq!(refs(&node)[&task()], next.candidate_commit);
        assert!(create(&node, &retry, &other, next.candidate_commit).is_err());
        assert!(!refs(&node).contains_key(&other));
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let retry = authentication(&reopened, &replacement, "create-task", SOURCE_BRANCH_CREATE);
        assert_eq!(create(&reopened, &retry, &task(), base).unwrap().commands, published.commands);
        assert_eq!(provenance(&reopened, actor(2), "create-task"), original);
        assert_eq!(refs(&reopened)[&task()], next.candidate_commit);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn task_creation_requires_independent_scope_and_keeps_generic_branch_admission_closed() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let base = seed(&node);
        let token = bearer('a');
        issue_creator(&node, &token, "scope-creator", &task());
        let run = authentication(&node, &token, "scope-task", SOURCE_BRANCH_CREATE);
        let outside = RefName::try_new(b"refs/heads/other/task").unwrap();
        assert_refused(&create(&node, &run, &outside, base).unwrap(), RefusalCode::CapabilityScopeViolation);
        assert!(!refs(&node).contains_key(&outside));
        let generic = node.runtime().block_on(node.admit_branch_updates_durable_in(
            &run.context(&node), &run.session(key("generic-agent-branch")),
            &[RefCommand { name: task(), expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(base), force: false }],
            Default::default(),
        )).unwrap();
        assert_refused(&generic, RefusalCode::CapabilityScopeViolation);
        assert!(!refs(&node).contains_key(&task()));

        // Every formerly assigned operation, including source publication,
        // remains unable to construct the new branch-creation boundary.
        let legacy = bearer('b');
        committed(credential(&node, &AgentCredentialCommand {
            id: agent_credential_id(legacy.as_bytes()).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: AgentCredentialAction::issuance(
                AgentCredentialGrant { operations: 0xffff, ..grant(&node) },
                Some(scope(&task(), &[b"src"])),
            ),
        }, actor(1), "legacy-issue"));
        let legacy_run = authentication(&node, &legacy, "legacy-task", SOURCE_PUBLISH);
        assert!(legacy_run.source_branch_creation(&node).is_err());
        let valid = authentication(&node, &token, "valid-task", SOURCE_BRANCH_CREATE);
        assert_committed(&create(&node, &valid, &task(), base).unwrap());
        let duplicate = authentication(&node, &token, "duplicate-task", SOURCE_BRANCH_CREATE);
        assert!(matches!(create(&node, &duplicate, &task(), base).unwrap().commands[0].terminal.outcome,
            DecisionOutcome::Refused { .. }));
        assert_eq!(refs(&node)[&task()], base);
        node.shutdown().unwrap();
    }
}

#[test]
fn task_creation_rechecks_live_revocation_and_ordinary_branch_protection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let base = seed(&node);
        let token = bearer('a');
        let issued = issue_creator(&node, &token, "live-creator", &task());
        let inflight = authentication(&node, &token, "revoked-task", SOURCE_BRANCH_CREATE);
        revoke(&node, &issued, "inflight-revoke");
        let refused = create(&node, &inflight, &task(), base).unwrap();
        assert_refused(&refused, RefusalCode::CapabilityScopeViolation);
        assert_eq!(create(&node, &inflight, &task(), base).unwrap().commands, refused.commands);
        assert_eq!(provenance(&node, actor(2), "revoked-task").agent_provenance(), Some(&inflight.authentication));
        assert!(!refs(&node).contains_key(&task()));

        let replacement = bearer('b');
        issue_creator(&node, &replacement, "protected-creator", &task());
        let current = node.runtime()
            .block_on(node.read_review_protection_in(&node.request_context())).unwrap();
        let protection = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: current.policy_epoch,
            protection: ReviewProtection {
                administrators: vec![actor(1)],
                branches: vec![ProtectedBranch {
                    name: task(), reviewers: vec![actor(3)], required_approvals: 1,
                    required_checks: Vec::new(), required_candidate_checks: Vec::new(),
                    require_merge_queue: false, path_reviews: Vec::new(),
                }],
                ref_policy: None,
            },
        };
        committed(node.runtime().block_on(node.admit_review_protection_durable_in(
            &node.request_context(), &operator(actor(1), "protect-task"), &protection,
            Default::default(),
        )).unwrap());
        let run = authentication(&node, &replacement, "protected-task", SOURCE_BRANCH_CREATE);
        assert!(matches!(create(&node, &run, &task(), base).unwrap().commands[0].terminal.outcome,
            DecisionOutcome::Refused { .. }));
        assert!(!refs(&node).contains_key(&task()));
        assert_eq!(refs(&node)[&reference()], base);
        node.shutdown().unwrap();
    }
}

#[test]
fn task_branch_deadline_cancels_and_drains_the_original_pending_operation() {
    use std::cell::Cell;
    use std::future::Future;
    use std::task::{Context, Waker};
    use std::time::Duration;

    let scratch = Scratch::new();
    let node = scratch.node(GitHashAlgorithm::Sha256);
    let base = seed(&node);
    let token = bearer('a');
    issue_creator(&node, &token, "deadline-creator", &task());
    let mut run = authentication(&node, &token, "deadline-task", SOURCE_BRANCH_CREATE);
    let original = node.command_request_context(None);
    let mut pending = Box::pin(original.authority().wait_for_local_cancel_request());
    assert!(pending.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    run.constrain_deadline(Instant::now() + Duration::from_millis(100));
    let proof = run.source_branch_creation(&node).unwrap();
    let drained = Cell::new(false);
    let outcome = node.runtime().block_on(proof.drive_in(&node, &original, async {
        pending.await;
        drained.set(true);
        node.create_agent_branch_in(&original, &proof, &task(), base, Default::default()).await
    }));
    assert!(drained.get());
    assert!(original.authority().is_cancel_requested());
    assert!(matches!(outcome, Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None })), "{outcome:?}");
    assert!(!refs(&node).contains_key(&task()));
    let fresh = authentication(&node, &token, "after-deadline-task", SOURCE_BRANCH_CREATE);
    assert_committed(&create(&node, &fresh, &task(), base).unwrap());
    node.shutdown().unwrap();
}

#[test]
fn task_creation_projection_rechecks_current_visible_tip_at_each_deciding_basis() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let base = seed(&node);
        let token = bearer('a');
        issue_creator(&node, &token, "replan-creator", &task());
        let run = authentication(&node, &token, "replanned-task", SOURCE_BRANCH_CREATE);
        let creation = run.source_branch_creation(&node).unwrap();
        let proof = creation.bind_branch(&task(), base);
        let request = run.context(&node);
        let context = AdmissionContext {
            head_key: node.head_key.clone(), tenant_id: node.tenant_id,
            repository_id: node.repository_id, principal_id: run.authentication.agent(),
            idempotency_key: creation.key().clone(), object_format: format,
        };
        let projection = node.durable_admission_projection(&context).unwrap()
            .with_source_publication(&proof);
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        node.runtime().block_on(projection.snapshot_async(
            &node.authority, request.authority(), before.basis(), before.authenticated(),
        )).unwrap();

        // A replan selects real newer authority state; a historical closure
        // membership proof cannot preserve yesterday's branch-tip authority.
        let next = candidate(&node, base, PATCH);
        assert_committed(&node.runtime().block_on(node.apply_workspace_bundle_durable_in(
            &node.command_request_context(None), actor(1), b"replan-advance",
            &reference(), base, next.candidate_commit, next.bundle_bytes(),
        )).unwrap());
        let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert_ne!(after.basis(), before.basis());
        assert!(matches!(node.runtime().block_on(projection.snapshot_async(
            &node.authority, request.authority(), after.basis(), after.authenticated(),
        )), Err(AsyncProjectionFailure::Refuse(RefusalCode::CapabilityScopeViolation))));

        let fresh_proof = creation.bind_branch(&task(), next.candidate_commit);
        let fresh_projection = node.durable_admission_projection(&context).unwrap()
            .with_source_publication(&fresh_proof);
        node.runtime().block_on(fresh_projection.snapshot_async(
            &node.authority, request.authority(), after.basis(), after.authenticated(),
        )).unwrap();
        let hidden = fgit_codec::HiddenRefPolicyBody { rules: vec![reference().as_bytes().to_vec()] };
        node.runtime().block_on(
            fgit_admission::merge::native::protection::publish_hidden_ref_policy_async(
                &node.authority, request.authority(), &node.head_key, node.tenant_id,
                Some(&hidden), fgit_codec::harness::tx_id(),
            ),
        ).unwrap();
        let hidden_basis = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert!(matches!(node.runtime().block_on(fresh_projection.snapshot_async(
            &node.authority, request.authority(), hidden_basis.basis(), hidden_basis.authenticated(),
        )), Err(AsyncProjectionFailure::Refuse(RefusalCode::CapabilityScopeViolation))));
        assert!(!refs(&node).contains_key(&task()));
        node.shutdown().unwrap();
    }
}
