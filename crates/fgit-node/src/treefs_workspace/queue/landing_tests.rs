//! Atomic queue-head publication through the real durable authority. Each source
//! in the shared fixture is an imported child of the selected target commit.
use super::tests::{
    Scratch, accepted, actor, apply, apply_pull, command, dequeue, enqueue, initialize, read,
    session, snapshot,
};
use super::*;
use crate::MaterializedAdmission;
use fgit_admission::evidence::{AdmissionAuthentication, PolicyDecisionRecord};
use fgit_admission::merge::native::queue::QueueLandingCommand;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_crypto::GitObjectKind;
use fgit_forge::ForgeEventPayload;
use fgit_forge::event::protection::{
    ProtectedBranch, ProtectionCommand, RequiredWorkflowCheck, ReviewProtection, compile_ref_policy,
};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand};
use fgit_forge::event::queue::QueueAction;
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::merge_queue::QueueCommandAction;
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{
    DecisionOutcome, Digest, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch, PrincipalId,
};
use std::{future::Future, task::Poll};

mod candidate;
mod protection;

fn version(value: u64) -> AggregateVersion {
    AggregateVersion::try_new(value).unwrap()
}

fn landing(pull: &PullRequestCommand, queue_version: u64) -> QueueLandingCommand {
    QueueLandingCommand {
        number: QueueNumber::FIRST,
        expected_version: version(queue_version),
        expected_policy_epoch: PolicyEpoch::FIRST,
        pull_request: pull.number,
        expected_pull_request_version: AggregateVersion::FIRST,
        source_ref: pull.data.source_ref.clone(),
        head_tip: pull.data.source_tip,
        target_ref: pull.data.target_ref.clone(),
        expected_target_tip: pull.data.target_tip,
    }
}

fn land(
    node: &OneNode,
    command: &QueueLandingCommand,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.land_queue_head_durable_in(
        &request,
        &session(key),
        command,
        AdmissionLimits::default(),
    ))
}

fn unchanged_publication(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(before.snapshot().outbox, after.snapshot().outbox);
    assert_eq!(
        before.basis().body().ref_root,
        after.basis().body().ref_root
    );
    assert_eq!(
        before.basis().body().forge_position_root,
        after.basis().body().forge_position_root
    );
    assert_eq!(
        before.basis().body().outbox_root,
        after.basis().body().outbox_root
    );
    assert_eq!(
        before.basis().body().retention_root,
        after.basis().body().retention_root
    );
    assert_eq!(
        before.basis().body().latest_repository_sequence,
        after.basis().body().latest_repository_sequence,
        "a refusal must not commit either half of a queue landing"
    );
    assert_eq!(
        before.selected_closure().closure(),
        after.selected_closure().closure()
    );
}

fn denied(
    node: &OneNode,
    command: &QueueLandingCommand,
    key: &str,
    expected: RefusalCode,
) -> (TxId, TerminalOutcome) {
    let before = snapshot(node);
    let before_queue = read(node, 1, None).queue;
    let result = land(node, command, key).unwrap();
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
        "expected {expected:?}: {result:?}"
    );
    unchanged_publication(&before, &snapshot(node));
    assert_eq!(read(node, 1, None).queue, before_queue);
    result
}

fn protect(node: &OneNode, branches: Vec<ProtectedBranch>, key: &str) -> PolicyEpoch {
    install_protection(
        node,
        ReviewProtection {
            ref_policy: None,
            administrators: vec![actor()],
            branches,
        },
        key,
    )
}

fn install_protection(node: &OneNode, protection: ReviewProtection, key: &str) -> PolicyEpoch {
    let request = node.request_context();
    let state = node
        .runtime()
        .block_on(node.read_review_protection_in(&request))
        .unwrap();
    let command = ProtectionCommand {
        expected_version: state
            .version()
            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        expected_epoch: state.policy_epoch,
        protection,
    };
    accepted(
        node.runtime()
            .block_on(node.admit_review_protection_durable_in(
                &request,
                &session(key),
                &command,
                AdmissionLimits::default(),
            )),
    );
    state.policy_epoch.next().unwrap()
}

#[test]
fn queue_landing_atomically_moves_one_head_and_recovers_after_queue_edits_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
        accepted(apply(&node, &enqueue(1, 1, &pulls[1], 0), "second"));
        let offered = landing(&pulls[0], 2);
        let before = snapshot(&node);
        let pinned = read(&node, 1, None);
        let original = accepted(land(&node, &offered, "land-first"));
        let after = snapshot(&node);
        let selected = read(&node, 1, None);
        let queue = selected.queue.unwrap();
        assert_eq!(queue.version, version(4));
        assert_eq!(queue.deterministic_order(), vec![pulls[1].number]);
        assert!(queue.active_batch.is_none());
        let mut expected_refs = before.snapshot().refs.clone();
        expected_refs.insert(offered.target_ref.clone(), offered.head_tip);
        assert_eq!(after.snapshot().refs, expected_refs);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(
            after.selected_closure().closure(),
            before.selected_closure().closure(),
            "fast-forward landing uses existing objects and creates no synthetic branch"
        );
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        assert_eq!(
            after
                .basis()
                .body()
                .latest_repository_sequence
                .unwrap()
                .get(),
            before
                .basis()
                .body()
                .latest_repository_sequence
                .unwrap()
                .get()
                + 1
        );
        assert_eq!(
            after.basis().body().latest_decision_sequence.unwrap().get(),
            before
                .basis()
                .body()
                .latest_decision_sequence
                .unwrap()
                .get()
                + 1
        );
        assert_eq!(
            read(&node, 1, Some(pinned.source_head)),
            pinned,
            "historical queue views retain both candidates before landing"
        );
        let request = node.request_context();
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&request))
            .unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.batch.decisions.len(), 1);
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        assert_eq!(last.forge_events.len(), 3);
        let events = &last.forge_events;
        let ForgeEventPayload::MergeQueueChangedNative(formed) = &events[0].payload else {
            panic!("the first canonical event must form the queue batch");
        };
        let QueueAction::BatchFormed { batch_id, entries } = &formed.action else {
            panic!("the first canonical event must form the queue batch");
        };
        assert_eq!(events[0].version, version(3));
        assert_eq!(entries, &[pulls[0].number]);
        let ForgeEventPayload::MergeCommittedNative(merge) = &events[1].payload else {
            panic!("the middle canonical event must merge the exact PR");
        };
        assert_eq!(events[1].version, version(2));
        assert_eq!(merge.source_ref, offered.source_ref);
        assert_eq!(merge.source_tip, offered.head_tip);
        assert_eq!(merge.base_tip, offered.expected_target_tip);
        assert_eq!(merge.target_ref, offered.target_ref);
        assert_eq!(merge.target_tip_before, offered.expected_target_tip);
        assert_eq!(merge.merge_commit, offered.head_tip);
        let ForgeEventPayload::MergeQueueChangedNative(landed) = &events[2].payload else {
            panic!("the final canonical event must retire the landed queue batch");
        };
        assert_eq!(events[2].version, version(4));
        assert_eq!(
            landed.action,
            QueueAction::BatchLanded {
                batch_id: *batch_id,
                entries: vec![pulls[0].number],
                target_tip: offered.head_tip,
            }
        );
        let record = &last.batch.committed_rcrs[0];
        assert_eq!(record.resulting_ref_root, after.basis().body().ref_root);
        assert_eq!(
            record.resulting_forge_position_root,
            after.basis().body().forge_position_root
        );
        let page = node
            .runtime()
            .block_on(node.read_pull_requests_in(&request, &RefVisibility::default(), 0, 100, None))
            .unwrap();
        assert_eq!(
            page.pull_requests
                .iter()
                .find(|row| row.number == pulls[0].number)
                .unwrap()
                .event,
            events[1]
        );
        let untouched = page
            .pull_requests
            .iter()
            .find(|row| row.number == pulls[1].number)
            .unwrap();
        assert_eq!(untouched.event.version, AggregateVersion::FIRST);
        assert!(matches!(
            untouched.event.payload,
            ForgeEventPayload::PullRequestChangedNative(_)
        ));

        accepted(apply(
            &node,
            &dequeue(1, 4, pulls[1].number),
            "withdraw-second",
        ));
        let final_head = snapshot(&node).basis().id();
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(
            land(&reopened, &offered, "land-first").unwrap(),
            original,
            "decided retries work before reopening new-work admission"
        );
        let mut changed = offered.clone();
        changed.expected_policy_epoch = offered.expected_policy_epoch.next().unwrap();
        assert!(land(&reopened, &changed, "land-first").is_err());
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis().id(), final_head);
        let remaining = read(&reopened, 1, None).queue.unwrap();
        assert_eq!(remaining.version, version(5));
        assert!(remaining.entries.is_empty());
        assert_eq!(
            snapshot(&reopened).snapshot().refs[&offered.target_ref],
            offered.head_tip
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn priority_and_explicit_reorder_select_the_only_landable_head() {
    let scratch = Scratch::new();
    let (node, pulls, _) = initialize(&scratch, GitHashAlgorithm::Sha1);
    accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
    accepted(apply(&node, &enqueue(1, 1, &pulls[1], 10), "priority"));
    assert_eq!(
        read(&node, 1, None).queue.unwrap().deterministic_order(),
        vec![pulls[1].number, pulls[0].number]
    );
    let original = landing(&pulls[0], 2);
    denied(
        &node,
        &original,
        "skip-priority-head",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    accepted(apply(
        &node,
        &command(
            1,
            2,
            QueueCommandAction::Reorder {
                order: vec![pulls[0].number, pulls[1].number],
            },
        ),
        "choose-head",
    ));
    denied(
        &node,
        &original,
        "stale-queue-order",
        RefusalCode::EvidenceStale,
    );
    denied(
        &node,
        &landing(&pulls[1], 3),
        "skip-reordered-head",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    accepted(land(&node, &landing(&pulls[0], 3), "land-reordered-head"));
    assert_eq!(
        read(&node, 1, None).queue.unwrap().deterministic_order(),
        vec![pulls[1].number]
    );
    node.shutdown().unwrap();
}

#[test]
fn landing_pins_pr_version_and_policy_even_when_candidate_object_ids_stay_equal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
        let mut offered = landing(&pulls[0], 1);
        let mut updated = pulls[0].clone();
        updated.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        updated.action = PullRequestAction::Update;
        updated.data.title = "Same tips, newer reviewed PR metadata".into();
        apply_pull(&node, &updated, "update-pr");
        denied(
            &node,
            &offered,
            "old-pr-version",
            RefusalCode::EvidenceStale,
        );
        offered.expected_pull_request_version = version(2);
        let epoch = protect(&node, Vec::new(), "install-policy");
        denied(
            &node,
            &offered,
            "old-policy-epoch",
            RefusalCode::EvidenceStale,
        );
        offered.expected_policy_epoch = epoch;
        accepted(land(&node, &offered, "current-pr-policy"));
        let page = node
            .runtime()
            .block_on(node.read_pull_requests_in(
                &node.request_context(),
                &RefVisibility::default(),
                0,
                100,
                None,
            ))
            .unwrap();
        let row = page
            .pull_requests
            .iter()
            .find(|row| row.number == pulls[0].number)
            .unwrap();
        assert_eq!(row.event.version, version(3));
        assert_eq!(row.data.as_ref().unwrap().title, updated.data.title);
        node.shutdown().unwrap();
    }
}

#[test]
fn moved_target_and_refreshed_divergent_candidate_cannot_be_landed() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, advanced) = initialize(&scratch, format);
        accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
        let mut offered = landing(&pulls[0], 1);
        let result = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.request_context(),
                &session("advance-target"),
                &[RefCommand {
                    name: offered.target_ref.clone(),
                    expected_old: ExpectedOld::Exactly(offered.expected_target_tip),
                    proposed_new: ProposedNew::Update(advanced),
                    force: false,
                }],
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        denied(&node, &offered, "target-moved", RefusalCode::TargetRefMoved);
        let mut updated = pulls[0].clone();
        updated.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        updated.action = PullRequestAction::Update;
        updated.data.target_tip = advanced;
        apply_pull(&node, &updated, "refresh-pr-target");
        let mut requeued = enqueue(1, 1, &updated, 0);
        let QueueCommandAction::Enqueue {
            expected_pull_request_version,
            ..
        } = &mut requeued.action
        else {
            unreachable!();
        };
        *expected_pull_request_version = version(2);
        accepted(apply(&node, &requeued, "refresh-queue-target"));
        offered.expected_version = version(2);
        offered.expected_pull_request_version = version(2);
        offered.expected_target_tip = advanced;
        denied(
            &node,
            &offered,
            "still-divergent",
            RefusalCode::NonFastForwardRefused,
        );
        node.shutdown().unwrap();
    }
}

struct SourceCommit(CanonicalPackObject);
impl CanonicalObjectSource for SourceCommit {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        if *id == self.0.id() {
            Ok(self.0.clone())
        } else {
            Err(PackWriteError::MissingCanonicalObject(*id))
        }
    }
}

fn candidate_bundle(node: &OneNode, offered: &QueueLandingCommand) -> Vec<u8> {
    let source = SourceCommit(CanonicalPackObject::new(
        offered.head_tip,
        GitObjectKind::Commit,
        node.read_git_object(offered.head_tip)
            .unwrap()
            .payload()
            .to_vec(),
        Vec::new(),
        0,
        0,
    ));
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        offered.head_tip.algorithm(),
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&source, &[offered.head_tip], &mut || true)
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bytes = format!(
        "# v3 git bundle\n@object-format={}\n-{} target\n{} refs/heads/main\n\n",
        offered.head_tip.algorithm().as_str(),
        offered.expected_target_tip,
        offered.head_tip
    )
    .into_bytes();
    bytes.extend(pack);
    bytes
}

fn review(offered: &QueueLandingCommand) -> CandidateReviewCommand {
    CandidateReviewCommand {
        review: ReviewCommand {
            expected_version: ExpectedVersion::NewStream,
            subject: ReviewSubject {
                pull_request: offered.pull_request,
                pull_request_version: offered.expected_pull_request_version,
                source_ref: offered.source_ref.clone(),
                target_ref: offered.target_ref.clone(),
                source_tip: offered.head_tip,
                target_tip: offered.expected_target_tip,
                policy_epoch: offered.expected_policy_epoch,
            },
            decision: ReviewDecision::Approve,
            reason: "Reviewed the exact imported fast-forward candidate".into(),
        },
        candidate: CandidateBinding {
            merge_base: offered.expected_target_tip,
            commit: offered.head_tip,
        },
    }
}

#[test]
fn queue_landing_requires_current_exact_candidate_approval_and_honors_withdrawal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
        let reviewer = PrincipalId::from_bytes([0xa3; 16]);
        let mut offered = landing(&pulls[0], 1);
        offered.expected_policy_epoch = protect(
            &node,
            vec![ProtectedBranch {
                require_merge_queue: true,
                name: offered.target_ref.clone(),
                required_approvals: 1,
                reviewers: vec![reviewer],
                required_checks: Vec::new(),
            }],
            "protect-reviews",
        );
        let missing = denied(
            &node,
            &offered,
            "missing-review",
            RefusalCode::EvidenceMissing,
        );
        let bytes = candidate_bundle(&node, &offered);
        let mut approval = review(&offered);
        let vote = |command: &CandidateReviewCommand, bytes: Option<&[u8]>, key: &str| {
            let request = node.request_context();
            let session = LoopbackReceiveSession::authenticated(
                reviewer,
                IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
            );
            accepted(
                node.runtime()
                    .block_on(node.admit_candidate_review_durable_in(
                        &request,
                        &session,
                        command,
                        bytes,
                        AdmissionLimits::default(),
                    )),
            )
        };
        vote(&approval, Some(&bytes), "approve-candidate");
        approval.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        approval.review.decision = ReviewDecision::Withdraw;
        vote(&approval, None, "withdraw-candidate");
        denied(
            &node,
            &offered,
            "withdrawn-review",
            RefusalCode::ProtectedRefTransitionDenied,
        );
        approval.review.expected_version = ExpectedVersion::Exactly(version(2));
        approval.review.decision = ReviewDecision::Approve;
        vote(&approval, Some(&bytes), "reapprove-candidate");
        assert_eq!(land(&node, &offered, "missing-review").unwrap(), missing);
        accepted(land(&node, &offered, "reviewed-queue-head"));
        assert!(read(&node, 1, None).queue.unwrap().entries.is_empty());
        node.shutdown().unwrap();
    }
}

#[test]
fn queue_landing_cannot_bypass_a_required_workflow_check_with_a_live_source_ref() {
    let scratch = Scratch::new();
    let (node, pulls, _) = initialize(&scratch, GitHashAlgorithm::Sha256);
    accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
    let mut offered = landing(&pulls[0], 1);
    offered.expected_policy_epoch = protect(
        &node,
        vec![ProtectedBranch {
            require_merge_queue: true,
            name: offered.target_ref.clone(),
            required_approvals: 0,
            reviewers: Vec::new(),
            required_checks: vec![RequiredWorkflowCheck {
                source_ref: offered.source_ref.clone(),
                publisher: actor(),
                graph_root: [0x84; 32],
                job: "test".into(),
            }],
        }],
        "protect-checks",
    );
    assert_eq!(
        snapshot(&node).snapshot().refs[&offered.source_ref],
        offered.head_tip
    );
    denied(
        &node,
        &offered,
        "missing-check",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    node.shutdown().unwrap();
}

fn assert_authenticated_landing_evidence(node: &OneNode, tx: TxId) {
    let request = node.request_context();
    let history = node
        .runtime()
        .block_on(node.snapshot_history_in(&request))
        .unwrap();
    let record = history
        .iter()
        .flat_map(|batch| &batch.batch.committed_rcrs)
        .find(|record| record.tx_id == tx)
        .unwrap();
    let identity = record.principal_snapshot_id.as_internal_object_id();
    let principal = node
        .runtime()
        .block_on(crate::read_principal_snapshot_in(
            &node.authority,
            request.authority(),
            node.repository_id,
            Digest::new(identity.algorithm(), *identity.digest()),
            &|| false,
        ))
        .unwrap();
    assert_eq!(
        principal.authentication(),
        Some(AdmissionAuthentication::HttpToken)
    );
    let policy = node
        .runtime()
        .block_on(crate::read_policy_decision_in(
            &node.authority,
            request.authority(),
            node.repository_id,
            record.policy_decision_root,
            &|| false,
        ))
        .unwrap();
    assert!(matches!(
        policy,
        PolicyDecisionRecord::AuthenticationActivated(_)
    ));
    assert_eq!(
        policy.authentication(),
        Some(AdmissionAuthentication::HttpToken)
    );
}

#[test]
fn activated_authentication_policy_records_real_landing_evidence_and_survives_replacement() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
        let policy = |strength| {
            ReviewProtection {
            ref_policy: Some(compile_ref_policy(&format!(
                "policy queue_credentials {{ rule credential {{ when actor.authentication >= {strength} then allow }} default deny \"verified credential required\" }}",
            )).unwrap()),
            administrators: vec![actor()],
            branches: vec![protection::queue_only(pulls[0].data.target_ref.clone())],
        }
        };
        let mut offered = landing(&pulls[0], 1);
        offered.expected_policy_epoch =
            install_protection(&node, policy("single_factor"), "require-credential");
        let refused = denied(
            &node,
            &offered,
            "operator-assertion",
            RefusalCode::ProtectedRefTransitionDenied,
        );
        // Use the same node-owned verifier attachment exercised by the native
        // merge tests. A public command cannot assert this provenance itself.
        let verified = LoopbackReceiveSession::Authenticated(
            crate::AuthenticatedReceiveSession::new(
                actor(),
                IdempotencyKey::new(b"credential-land".to_vec()).unwrap(),
            )
            .with_authentication(AdmissionAuthentication::HttpToken),
        );
        let original = accepted(node.runtime().block_on(node.land_queue_head_durable_in(
            &node.request_context(),
            &verified,
            &offered,
            AdmissionLimits::default(),
        )));
        assert_eq!(read(&node, 1, None).queue.unwrap().version, version(3));
        assert_eq!(
            snapshot(&node).snapshot().refs[&offered.target_ref],
            offered.head_tip
        );
        assert_authenticated_landing_evidence(&node, original.0);
        install_protection(
            &node,
            policy("multi_factor"),
            "strengthen-credential-policy",
        );
        let selected_head = snapshot(&node).basis().id();
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(
            land(&reopened, &offered, "credential-land").unwrap(),
            original,
            "historical recovery keeps the original authenticated decision under stricter policy"
        );
        assert_eq!(
            land(&reopened, &offered, "operator-assertion").unwrap(),
            refused
        );
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis().id(), selected_head);
        assert_authenticated_landing_evidence(&reopened, original.0);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn competing_landing_requests_commit_one_atomic_batch_and_keep_both_retry_identities() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
        let offered = landing(&pulls[0], 1);
        let before = snapshot(&node);
        let (ra, rb) = (node.request_context(), node.request_context());
        let (sa, sb) = (session("race-a"), session("race-b"));
        let mut fa = Box::pin(node.land_queue_head_durable_in(
            &ra,
            &sa,
            &offered,
            AdmissionLimits::default(),
        ));
        let mut fb = Box::pin(node.land_queue_head_durable_in(
            &rb,
            &sb,
            &offered,
            AdmissionLimits::default(),
        ));
        let (mut left, mut right, mut overlap) = (None, None, false);
        let (a, b) = node.runtime().block_on(std::future::poll_fn(|cx| {
            if left.is_none()
                && let Poll::Ready(value) = fa.as_mut().poll(cx)
            {
                left = Some(value);
            }
            if right.is_none()
                && let Poll::Ready(value) = fb.as_mut().poll(cx)
            {
                right = Some(value);
            }
            overlap |= left.is_none() && right.is_none();
            if left.is_some() && right.is_some() {
                Poll::Ready((
                    left.take().unwrap().unwrap(),
                    right.take().unwrap().unwrap(),
                ))
            } else {
                Poll::Pending
            }
        }));
        drop(fa);
        drop(fb);
        assert!(overlap, "both real admission futures must overlap");
        assert_eq!(
            [&a, &b]
                .iter()
                .filter(|result| matches!(result.1.outcome, DecisionOutcome::Committed { .. }))
                .count(),
            1
        );
        assert_eq!(
            [&a, &b]
                .iter()
                .filter(|result| matches!(
                    result.1.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::EvidenceStale,
                        ..
                    }
                ))
                .count(),
            1
        );
        let after = snapshot(&node);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        assert_eq!(
            after
                .basis()
                .body()
                .latest_repository_sequence
                .unwrap()
                .get(),
            before
                .basis()
                .body()
                .latest_repository_sequence
                .unwrap()
                .get()
                + 1
        );
        assert_eq!(
            after.basis().body().latest_decision_sequence.unwrap().get(),
            before
                .basis()
                .body()
                .latest_decision_sequence
                .unwrap()
                .get()
                + 2
        );
        assert_eq!(after.snapshot().refs[&offered.target_ref], offered.head_tip);
        let queue = read(&node, 1, None).queue.unwrap();
        assert_eq!(queue.version, version(3));
        assert!(queue.entries.is_empty());
        assert!(queue.active_batch.is_none());
        assert_eq!(land(&node, &offered, "race-a").unwrap(), a);
        assert_eq!(land(&node, &offered, "race-b").unwrap(), b);
        assert_eq!(snapshot(&node).basis().id(), after.basis().id());
        node.shutdown().unwrap();
    }
}
