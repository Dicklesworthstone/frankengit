//! Resolved squash candidates use the real review gate and atomic publication.

use super::super::tests::{fixture, metadata};
use super::*;
use crate::{LoopbackReceiveSession, MaterializedAdmission, NodeConfig};
use fgit_admission::merge::native::{NativeMergeIntent, NativeMergeMethod};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::preparation::resolution::ResolutionChoice;
use fgit_forge::preparation::{ConflictKind, MergePreparation};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PolicyEpoch, PrincipalId, RefusalCode,
};

const fn actor(value: u8) -> PrincipalId {
    PrincipalId::from_bytes([value; 16])
}

fn session(value: u8, key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(value), IdempotencyKey::new(key.to_vec()).unwrap())
}

fn references() -> (RefName, RefName) {
    (
        RefName::try_new(b"refs/heads/main").unwrap(),
        RefName::try_new(b"refs/heads/topic").unwrap(),
    )
}

fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
}

fn committed(terminal: &TerminalOutcome) {
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "{terminal:?}"
    );
}

fn coordinates(node: &OneNode) -> ResolutionInputs {
    let request = node.request_context();
    let before = snapshot(node);
    let (target, source) = references();
    let automatic = node
        .runtime()
        .block_on(node.prepare_merge_bundle_in(
            &request,
            &target,
            &source,
            &RefVisibility::new(),
            &metadata(),
            PreparationLimits::default(),
        ))
        .unwrap();
    let MergePreparation::Conflicted { base, conflicts } = automatic.outcome else {
        panic!("the source edits must overlap");
    };
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].path, b"text");
    assert_eq!(conflicts[0].kind, ConflictKind::Content);
    assert!(automatic.bundle.is_none());
    assert_eq!(snapshot(node).basis(), before.basis());
    ResolutionInputs {
        base,
        target: before.snapshot().refs[&target],
        source: before.snapshot().refs[&source],
    }
}

fn open(node: &OneNode, inputs: ResolutionInputs) -> (ReviewSubject, PullRequestData) {
    let (target_ref, source_ref) = references();
    let data = PullRequestData {
        source_ref: source_ref.clone(),
        target_ref: target_ref.clone(),
        source_tip: inputs.source,
        target_tip: inputs.target,
        title: "Resolve and squash".into(),
        body: "Publish exactly the resolved candidate.".into(),
    };
    let request = node.request_context();
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &request,
            &session(1, b"open-resolved-squash"),
            &PullRequestCommand {
                number: PullRequestNumber::FIRST,
                expected_version: ExpectedVersion::NewStream,
                action: PullRequestAction::Open,
                data: data.clone(),
            },
            Default::default(),
        ))
        .unwrap();
    committed(&terminal);
    (
        ReviewSubject {
            pull_request: PullRequestNumber::FIRST,
            pull_request_version: AggregateVersion::FIRST,
            source_ref,
            target_ref,
            source_tip: inputs.source,
            target_tip: inputs.target,
            policy_epoch: PolicyEpoch::FIRST,
        },
        data,
    )
}

fn prepare(
    node: &OneNode,
    subject: &ReviewSubject,
    inputs: ResolutionInputs,
    choices: &[ConflictResolution],
    style: MergeCommitStyle,
) -> ResolvedMergeBundle {
    let request = node.request_context();
    node.runtime()
        .block_on(node.prepare_resolved_pull_request_bundle_with_style_in(
            &request,
            subject,
            inputs.base,
            &RefVisibility::new(),
            choices,
            &metadata(),
            PreparationLimits::default(),
            style,
        ))
        .unwrap()
}

fn candidate(subject: &ReviewSubject, artifact: &ResolvedMergeBundle) -> NativeMerge {
    NativeMerge {
        source_ref: subject.source_ref.clone(),
        source_tip: subject.source_tip,
        base_tip: artifact.resolved.plan.base,
        target_ref: subject.target_ref.clone(),
        target_tip_before: subject.target_tip,
        merge_commit: artifact.resolved.plan.commit,
    }
}

fn vote(
    node: &OneNode,
    subject: &ReviewSubject,
    artifact: &ResolvedMergeBundle,
    expected_version: ExpectedVersion,
    key: &[u8],
) {
    let request = node.request_context();
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_candidate_review_durable_in(
            &request,
            &session(3, key),
            &CandidateReviewCommand {
                review: ReviewCommand {
                    expected_version,
                    subject: subject.clone(),
                    decision: ReviewDecision::Approve,
                    reason: "Reviewed these exact resolved native bytes.".into(),
                },
                candidate: CandidateBinding {
                    merge_base: artifact.resolved.plan.base,
                    commit: artifact.resolved.plan.commit,
                },
            },
            Some(&artifact.bundle),
            Default::default(),
        ))
        .unwrap();
    committed(&terminal);
}

#[test]
fn reviewed_resolved_squash_publishes_one_atomic_transition_and_retries_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, incoming) = fixture(format, true);
        let reopen_config = NodeConfig::new(
            node.storage_root().to_path_buf(),
            node.tenant_id(),
            node.repository_id(),
        )
        .with_object_format(format);
        let inputs = coordinates(&node);
        assert_eq!((inputs.target, inputs.source), (target, incoming));
        let (mut subject, data) = open(&node, inputs);
        let request = node.request_context();
        let (_, protection) = node
            .runtime()
            .block_on(node.admit_review_protection_durable_in(
                &request,
                &session(1, b"protect-resolved-squash"),
                &ProtectionCommand {
                    expected_version: ExpectedVersion::NewStream,
                    expected_epoch: PolicyEpoch::FIRST,
                    protection: ReviewProtection {
                        administrators: vec![actor(1)],
                        branches: vec![ProtectedBranch {
                            required_checks: Vec::new(),
                            name: subject.target_ref.clone(),
                            reviewers: vec![actor(3)],
                        }],
                    },
                },
                Default::default(),
            ))
            .unwrap();
        committed(&protection);
        subject.policy_epoch = PolicyEpoch::FIRST.next().unwrap();
        let before_preparation = snapshot(&node);
        let bytes = b"resolved\0binary\nb\nc\nd\ne\n";
        let choices = [ConflictResolution {
            path: b"text".to_vec(),
            choice: ResolutionChoice::File {
                mode: 0o100755,
                bytes: bytes.to_vec(),
            },
        }];
        let ordinary = prepare(
            &node,
            &subject,
            inputs,
            &choices,
            MergeCommitStyle::TwoParent,
        );
        let legacy = node
            .runtime()
            .block_on(node.prepare_resolved_pull_request_bundle_in(
                &request,
                &subject,
                inputs.base,
                &RefVisibility::new(),
                &choices,
                &metadata(),
                PreparationLimits::default(),
            ))
            .unwrap();
        assert_eq!(legacy.resolved, ordinary.resolved);
        assert_eq!(legacy.bundle, ordinary.bundle);
        assert_eq!(legacy.bundle_sha256, ordinary.bundle_sha256);
        let legacy_branch = node
            .runtime()
            .block_on(node.prepare_resolved_merge_bundle_in(
                &request,
                &subject.target_ref,
                &subject.source_ref,
                &RefVisibility::new(),
                Some(before_preparation.basis().id()),
                inputs,
                &choices,
                &metadata(),
                PreparationLimits::default(),
            ))
            .unwrap();
        assert_eq!(legacy_branch.bundle, ordinary.bundle);
        let squash = prepare(&node, &subject, inputs, &choices, MergeCommitStyle::Squash);
        let repeated = prepare(&node, &subject, inputs, &choices, MergeCommitStyle::Squash);
        assert_eq!(squash.resolved, repeated.resolved);
        assert_eq!(squash.bundle, repeated.bundle);
        assert_eq!(squash.resolved.resolutions, ordinary.resolved.resolutions);
        assert_eq!(squash.resolved.plan.tree, ordinary.resolved.plan.tree);
        assert_ne!(squash.resolved.plan.commit, ordinary.resolved.plan.commit);
        assert_eq!(squash.resolved.plan.style, MergeCommitStyle::Squash);
        assert_eq!(squash.source_head, before_preparation.basis().id());
        assert_eq!(
            squash.bundle_sha256,
            fgit_crypto::sha256_digest(&squash.bundle)
        );
        let merge = candidate(&subject, &squash);
        let expected_body = format!(
            "tree {}\nparent {}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nreviewable merge\n",
            squash.resolved.plan.tree, inputs.target,
        )
        .into_bytes();
        assert_eq!(
            merge.merge_commit,
            git_object_id(format, GitObjectKind::Commit, &expected_body)
        );
        let inspected = node
            .runtime()
            .block_on(node.inspect_pull_request_bundle_in(
                &request,
                &subject,
                CandidateBinding {
                    merge_base: inputs.base,
                    commit: merge.merge_commit,
                },
                &squash.bundle,
                &RefVisibility::new(),
                &Default::default(),
            ))
            .unwrap();
        assert_eq!(inspected.parents, [inputs.target]);
        assert_eq!(inspected.candidate_commit_body, expected_body);
        assert_eq!(
            inspected.review.comparison.requested_after,
            merge.merge_commit
        );
        assert_eq!(inspected.review.comparison.entries.len(), 1);
        assert_eq!(inspected.review.comparison.entries[0].path, b"text");
        assert_eq!(
            inspected.review.comparison.entries[0].after.unwrap().mode,
            0o100755
        );
        assert!(node.read_git_object(merge.merge_commit).is_err());
        assert_eq!(snapshot(&node).basis(), before_preparation.basis());
        assert_eq!(
            coordinates(&node),
            inputs,
            "resolution cannot rewrite source history"
        );

        vote(
            &node,
            &subject,
            &ordinary,
            ExpectedVersion::NewStream,
            b"review-two-parent",
        );
        let before_refusal = snapshot(&node);
        let (_, refused) = node
            .runtime()
            .block_on(node.apply_reviewed_merge_bundle_with_method_durable_in(
                &request,
                actor(2),
                b"wrong-resolved-candidate-review",
                PullRequestNumber::FIRST,
                ExpectedVersion::Exactly(AggregateVersion::FIRST),
                &merge,
                &squash.bundle,
                subject.policy_epoch,
                &[actor(3)],
                NativeMergeMethod::Squash,
            ))
            .unwrap();
        assert!(matches!(
            refused.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        let after_refusal = snapshot(&node);
        assert_eq!(
            after_refusal.snapshot().refs,
            before_refusal.snapshot().refs
        );
        assert_eq!(
            after_refusal.snapshot().outbox,
            before_refusal.snapshot().outbox
        );
        assert_eq!(
            after_refusal.basis().body().forge_position_root,
            before_refusal.basis().body().forge_position_root
        );
        vote(
            &node,
            &subject,
            &squash,
            ExpectedVersion::Exactly(AggregateVersion::FIRST),
            b"review-resolved-squash",
        );
        let before = snapshot(&node);
        let accepted = node
            .runtime()
            .block_on(node.apply_reviewed_merge_bundle_with_method_durable_in(
                &request,
                actor(2),
                b"publish-resolved-squash",
                PullRequestNumber::FIRST,
                ExpectedVersion::Exactly(AggregateVersion::FIRST),
                &merge,
                &squash.bundle,
                subject.policy_epoch,
                &[actor(3)],
                NativeMergeMethod::Squash,
            ))
            .unwrap();
        committed(&accepted.1);
        let after = snapshot(&node);
        assert_eq!(
            after.basis().generation().get(),
            before.basis().generation().get() + 1
        );
        assert_eq!(
            after.snapshot().refs[&subject.target_ref],
            merge.merge_commit
        );
        assert_eq!(after.snapshot().refs[&subject.source_ref], inputs.source);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        assert_ne!(
            after.basis().body().ref_root,
            before.basis().body().ref_root
        );
        assert_ne!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_ne!(
            after.basis().body().outbox_root,
            before.basis().body().outbox_root
        );
        assert_eq!(
            node.read_git_object(merge.merge_commit).unwrap().payload(),
            expected_body
        );
        assert_eq!(
            node.read_git_object(git_object_id(format, GitObjectKind::Blob, bytes))
                .unwrap()
                .payload(),
            bytes
        );
        let intent = NativeMergeIntent::squash(
            PullRequestNumber::FIRST,
            AggregateVersion::FIRST,
            merge.clone(),
        )
        .unwrap();
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&request))
            .unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        assert_eq!(last.batch.committed_rcrs[0].tx_id, accepted.0);
        assert_eq!(last.forge_events, vec![intent.event().clone()]);
        assert_eq!(
            last.batch.committed_rcrs[0].resulting_ref_root,
            after.basis().body().ref_root
        );
        assert_eq!(
            last.batch.committed_rcrs[0].resulting_forge_position_root,
            after.basis().body().forge_position_root
        );
        let page = node
            .runtime()
            .block_on(node.read_pull_requests_in(&request, &RefVisibility::new(), 0, 10, None))
            .unwrap();
        assert_eq!(page.pull_requests[0].event, *intent.event());
        assert_eq!(page.pull_requests[0].data, Some(data));
        assert!(
            node.runtime()
                .block_on(node.apply_reviewed_merge_bundle_with_method_durable_in(
                    &request,
                    actor(2),
                    b"publish-resolved-squash",
                    PullRequestNumber::FIRST,
                    ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    &merge,
                    &squash.bundle,
                    subject.policy_epoch,
                    &[actor(3)],
                    NativeMergeMethod::MergeCommit,
                ))
                .is_err(),
            "the same retry key cannot select another merge method"
        );
        assert_eq!(snapshot(&node).basis(), after.basis());
        assert!(matches!(
            node.runtime()
                .block_on(node.prepare_resolved_merge_bundle_with_style_in(
                    &request,
                    &subject.target_ref,
                    &subject.source_ref,
                    &RefVisibility::new(),
                    None,
                    inputs,
                    &choices,
                    &metadata(),
                    PreparationLimits::default(),
                    MergeCommitStyle::Squash,
                )),
            Err(NodeResolutionRefusal::TipsMoved)
        ));
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(reopen_config).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = reopened.request_context();
        let retry = reopened
            .runtime()
            .block_on(reopened.apply_reviewed_merge_bundle_with_method_durable_in(
                &request,
                actor(2),
                b"publish-resolved-squash",
                PullRequestNumber::FIRST,
                ExpectedVersion::Exactly(AggregateVersion::FIRST),
                &merge,
                &[],
                subject.policy_epoch,
                &[actor(3)],
                NativeMergeMethod::Squash,
            ))
            .unwrap();
        assert_eq!(retry, accepted);
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn choosing_ours_can_publish_a_resolved_squash_with_an_empty_target_diff() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, _, _) = fixture(format, true);
        let inputs = coordinates(&node);
        let (subject, _) = open(&node, inputs);
        let before = snapshot(&node);
        let artifact = prepare(
            &node,
            &subject,
            inputs,
            &[ConflictResolution {
                path: b"text".to_vec(),
                choice: ResolutionChoice::Ours,
            }],
            MergeCommitStyle::Squash,
        );
        let plan = &artifact.resolved.plan;
        let target = node.read_git_object(inputs.target).unwrap();
        assert_eq!(
            target
                .payload()
                .split(|byte| *byte == b'\n')
                .next()
                .unwrap(),
            format!("tree {}", plan.tree).as_bytes()
        );
        assert_eq!(
            artifact.resolved.resolutions[0].result,
            artifact.resolved.resolutions[0].conflict.ours
        );
        assert_eq!(plan.style, MergeCommitStyle::Squash);
        assert_ne!(plan.commit, inputs.target);
        assert_ne!(plan.commit, inputs.source);
        let merge = candidate(&subject, &artifact);
        let request = node.request_context();
        let inspected = node
            .runtime()
            .block_on(node.inspect_pull_request_bundle_in(
                &request,
                &subject,
                CandidateBinding {
                    merge_base: inputs.base,
                    commit: plan.commit,
                },
                &artifact.bundle,
                &RefVisibility::new(),
                &Default::default(),
            ))
            .unwrap();
        assert_eq!(inspected.parents, [inputs.target]);
        assert!(inspected.review.comparison.entries.is_empty());
        assert_eq!(snapshot(&node).basis(), before.basis());
        assert!(node.read_git_object(plan.commit).is_err());
        let accepted = node
            .runtime()
            .block_on(node.apply_merge_bundle_with_method_durable_in(
                &request,
                actor(2),
                b"publish-ours-squash",
                PullRequestNumber::FIRST,
                ExpectedVersion::Exactly(AggregateVersion::FIRST),
                &merge,
                &artifact.bundle,
                NativeMergeMethod::Squash,
            ))
            .unwrap();
        committed(&accepted.1);
        let after = snapshot(&node);
        assert_eq!(
            after.basis().generation().get(),
            before.basis().generation().get() + 1
        );
        assert_eq!(after.snapshot().refs[&subject.target_ref], plan.commit);
        assert_eq!(after.snapshot().refs[&subject.source_ref], inputs.source);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        node.shutdown().unwrap();
    }
}
