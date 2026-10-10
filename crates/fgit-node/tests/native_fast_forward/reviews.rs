//! The permitted twin to protected fast-forward refusal: actual source-tip
//! inspection, exact reviewer admission, withdrawal, restart and publication.
use super::*;
use fgit_admission::ProjectionFailure;
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::review::ReviewOptions;
use fgit_node::treefs_workspace::candidate_inspection::{
    BundleInspectionRefusal, PullRequestInspectionRefusal,
};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_wire::visibility::RefVisibility;

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

fn bundle(f: &Fixture) -> Vec<u8> {
    let source = SourceCommit(CanonicalPackObject::new(
        f.source,
        GitObjectKind::Commit,
        f.node.read_git_object(f.source).unwrap().payload().to_vec(),
        Vec::new(),
        0,
        0,
    ));
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        f.source.algorithm(),
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&source, &[f.source], &mut || true)
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bytes = format!(
        "# v3 git bundle\n@object-format={}\n-{} target\n{} refs/heads/main\n\n",
        f.source.algorithm().as_str(),
        f.target,
        f.source
    )
    .into_bytes();
    bytes.extend(pack);
    bytes
}

fn command(f: &Fixture, epoch: PolicyEpoch) -> CandidateReviewCommand {
    CandidateReviewCommand {
        review: ReviewCommand {
            expected_version: ExpectedVersion::NewStream,
            subject: ReviewSubject {
                pull_request: PullRequestNumber::FIRST,
                pull_request_version: AggregateVersion::FIRST,
                source_ref: topic_ref(),
                target_ref: main_ref(),
                source_tip: f.source,
                target_tip: f.target,
                policy_epoch: epoch,
            },
            decision: ReviewDecision::Approve,
            reason: "Reviewed the exact source commit and resulting tree".into(),
        },
        candidate: CandidateBinding {
            merge_base: f.target,
            commit: f.source,
        },
    }
}

fn vote(
    node: &OneNode,
    command: &CandidateReviewCommand,
    bytes: Option<&[u8]>,
    key: &[u8],
) -> Result<(fgit_types::TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.admit_candidate_review_durable_in(
            &request,
            &session(3, key),
            command,
            bytes,
            Default::default(),
        ))
}

fn protect(node: &OneNode) -> PolicyEpoch {
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection {
            administrators: vec![actor(1)],
            branches: vec![ProtectedBranch {
                name: main_ref(),
                reviewers: vec![actor(3)],
            }],
        },
    };
    let request = node.request_context();
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &request,
            &session(1, b"protect-reviewed-fast-forward"),
            &command,
            Default::default(),
        ))
        .unwrap();
    committed(terminal);
    PolicyEpoch::FIRST.next().unwrap()
}

#[test]
fn protected_fast_forward_accepts_exact_source_review_and_preserves_withdrawal_restart_and_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture_with_history(&scratch.0, format, false, true);
        let epoch = protect(&f.node);
        let offered = intent(&f);
        let original_refs = refs(&f.node);
        let missing = denied(
            apply(&f.node, &offered, b"before-review", Default::default()).unwrap(),
            RefusalCode::EvidenceMissing,
        );
        let bytes = bundle(&f);
        let mut approval = command(&f, epoch);
        let request = f.node.request_context();
        let before = f
            .node
            .runtime()
            .block_on(f.node.materialize_admission_in(&request))
            .unwrap();
        let inspected = f
            .node
            .runtime()
            .block_on(f.node.inspect_pull_request_bundle_in(
                &request,
                &approval.review.subject,
                approval.candidate,
                &bytes,
                &RefVisibility::new(),
                &ReviewOptions::default(),
            ))
            .unwrap();
        assert_eq!(inspected.candidate, approval.candidate);
        assert_eq!(inspected.parents, [f.source_parent]);
        assert_ne!(
            f.source_parent, f.target,
            "fixture spans multiple source commits"
        );
        assert_eq!(
            inspected.candidate_commit_body,
            f.node.read_git_object(f.source).unwrap().payload()
        );
        assert_eq!(inspected.review.comparison.requested_before, f.target);
        assert_eq!(inspected.review.comparison.requested_after, f.source);
        assert_eq!(
            inspected.review.comparison.entries.len(),
            1,
            "the real source tree change is inspected"
        );
        assert_eq!(
            f.node
                .runtime()
                .block_on(f.node.materialize_admission_in(&request))
                .unwrap()
                .basis(),
            before.basis()
        );

        // Missing candidate bytes stay unavailable, not an accepted alias or a
        // permanently fabricated refusal. The exact key succeeds when supplied.
        assert!(vote(&f.node, &approval, None, b"exact-review").is_err());
        let first_vote = vote(&f.node, &approval, Some(&bytes), b"exact-review").unwrap();
        committed(first_vote.1.clone());
        assert_eq!(refs(&f.node), original_refs, "voting never moves a branch");
        let request = f.node.request_context();
        let page = f
            .node
            .runtime()
            .block_on(f.node.read_reviews_in(
                &request,
                &RefVisibility::new(),
                PullRequestNumber::FIRST,
                None,
                10,
                None,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(page.reviews[0].event.candidate, Some(approval.candidate));

        let mut withdrawal = approval.clone();
        withdrawal.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        withdrawal.review.decision = ReviewDecision::Withdraw;
        withdrawal.review.reason = "Withdraw this exact source-tip approval".into();
        committed(
            vote(&f.node, &withdrawal, None, b"withdraw-review")
                .unwrap()
                .1,
        );
        denied(
            apply(&f.node, &offered, b"after-withdrawal", Default::default()).unwrap(),
            RefusalCode::ProtectedRefTransitionDenied,
        );
        assert_eq!(refs(&f.node), original_refs);
        approval.review.expected_version =
            ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        committed(
            vote(&f.node, &approval, Some(&bytes), b"reapprove-source-tip")
                .unwrap()
                .1,
        );
        assert_eq!(
            apply(&f.node, &offered, b"before-review", Default::default()).unwrap(),
            missing
        );

        f.node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = reopened.request_context();
        let before = reopened
            .runtime()
            .block_on(reopened.materialize_admission_in(&request))
            .unwrap();
        let terminal =
            committed(apply(&reopened, &offered, b"reviewed-ff", Default::default()).unwrap());
        let request = reopened.request_context();
        let after = reopened
            .runtime()
            .block_on(reopened.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(after.snapshot().refs[&main_ref()], f.source);
        assert_eq!(after.snapshot().refs[&topic_ref()], f.source);
        assert_eq!(
            after.selected_closure().closure(),
            before.selected_closure().closure()
        );
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        assert_eq!(
            super::page(&reopened).pull_requests[0].event,
            *offered.event()
        );
        let final_head = after.basis().id();
        assert_eq!(
            apply(&reopened, &offered, b"reviewed-ff", Default::default()).unwrap(),
            terminal
        );
        assert_eq!(super::page(&reopened).source_head, final_head);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn source_tip_review_requires_native_ancestry_and_selected_complete_live_inspection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for divergent in [true, false] {
            let scratch = Scratch::new();
            let mut f = fixture_with_history(&scratch.0, format, divergent, true);
            let approval = command(&f, PolicyEpoch::FIRST);
            let bytes = bundle(&f);
            let original_refs = refs(&f.node);
            let request = f.node.request_context();
            let inspected = f
                .node
                .runtime()
                .block_on(f.node.inspect_pull_request_bundle_in(
                    &request,
                    &approval.review.subject,
                    approval.candidate,
                    &bytes,
                    &RefVisibility::new(),
                    &ReviewOptions::default(),
                ));
            if divergent {
                assert!(matches!(inspected,
                    Err(PullRequestInspectionRefusal::Candidate(error))
                    if matches!(*error, BundleInspectionRefusal::Validation(ProjectionFailure::Refuse(RefusalCode::NonFastForwardRefused)))
                ));
                denied(
                    vote(&f.node, &approval, Some(&bytes), b"divergent-vote")
                        .unwrap()
                        .1,
                    RefusalCode::NonFastForwardRefused,
                );
            } else {
                inspected.unwrap();
                let mut hidden = RefVisibility::new();
                hidden
                    .push_rule(topic_ref().as_bytes(), &Default::default())
                    .unwrap();
                assert!(
                    f.node
                        .runtime()
                        .block_on(f.node.inspect_pull_request_bundle_in(
                            &request,
                            &approval.review.subject,
                            approval.candidate,
                            &bytes,
                            &hidden,
                            &ReviewOptions::default(),
                        ))
                        .is_err()
                );
                let mut corrupt = bytes.clone();
                *corrupt.last_mut().unwrap() ^= 1;
                assert!(
                    f.node
                        .runtime()
                        .block_on(f.node.inspect_pull_request_bundle_in(
                            &request,
                            &approval.review.subject,
                            approval.candidate,
                            &corrupt,
                            &RefVisibility::new(),
                            &ReviewOptions::default(),
                        ))
                        .is_err()
                );
                let cancelled = f.node.request_context();
                cancelled.cancel();
                assert!(
                    f.node
                        .runtime()
                        .block_on(f.node.admit_candidate_review_durable_in(
                            &cancelled,
                            &session(3, b"cancelled-review"),
                            &approval,
                            Some(&bytes),
                            Default::default(),
                        ))
                        .is_err()
                );
                let mut low = ReviewOptions::default();
                low.limits.max_output_bytes = 1;
                assert!(
                    f.node
                        .runtime()
                        .block_on(f.node.inspect_pull_request_bundle_in(
                            &request,
                            &approval.review.subject,
                            approval.candidate,
                            &bytes,
                            &RefVisibility::new(),
                            &low,
                        ))
                        .is_err()
                );
                committed(
                    vote(&f.node, &approval, Some(&bytes), b"cancelled-review")
                        .unwrap()
                        .1,
                );
            }
            assert_eq!(refs(&f.node), original_refs);
            f.node.shutdown().unwrap();
        }
    }
}
