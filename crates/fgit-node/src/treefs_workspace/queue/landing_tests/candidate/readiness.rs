//! Readiness executes the real candidate admission preparation without sealing
//! an observation into a permanent refusal. All objects and canonical state are
//! produced by the file-backed native importer and existing publication paths.

use super::*;
use fgit_admission::merge::native::queue::CandidateLandingReadiness;
use fgit_authority::{OutcomeLookup, read_seal_async};
use fgit_forge::event::protection::RequiredCandidateWorkflowCheck;

fn inspect(
    node: &OneNode,
    offered: &QueueCandidateLandingCommand,
    key: &str,
) -> Result<CandidateLandingReadiness, NodeWorkspaceRefusal> {
    node.runtime()
        .block_on(node.inspect_queue_head_candidate_in(
            &node.request_context(),
            &session(key),
            offered,
        ))
}

fn assert_unsubmitted(node: &OneNode, tx_id: TxId) {
    let request = node.request_context();
    assert!(
        node.runtime()
            .block_on(read_seal_async(
                &node.authority,
                request.authority(),
                node.tenant_id,
                node.repository_id,
                tx_id,
            ))
            .unwrap()
            .is_none(),
        "a readiness observation must not reserve its landing key"
    );
    assert!(matches!(
        node.runtime()
            .block_on(node.resolve_outcome_checkpointed_in(&request, tx_id))
            .unwrap(),
        OutcomeLookup::Undecided
    ));
}

fn observe(
    node: &OneNode,
    offered: &QueueCandidateLandingCommand,
    key: &str,
    refusal: Option<RefusalCode>,
) -> CandidateLandingReadiness {
    let before = snapshot(node);
    let queued = read(node, 1, None);
    let result = inspect(node, offered, key).unwrap();
    assert_eq!(result.basis, before.basis().id());
    assert_eq!(result.policy_epoch, before.basis().body().policy_epoch);
    assert_eq!(result.refusal, refusal);
    assert_eq!(snapshot(node).basis(), before.basis());
    unchanged_publication(&before, &snapshot(node));
    assert_eq!(read(node, 1, None), queued);
    assert_unsubmitted(node, result.tx_id);
    result
}

fn publish_candidate_to_ci(node: &OneNode, prepared: &PreparedQueueHeadBundle) {
    let offered = offer(prepared);
    let bundle = prepared.bundle.as_deref().unwrap();
    let boundary = bundle.windows(2).position(|pair| pair == b"\n\n").unwrap() + 2;
    let header = std::str::from_utf8(&bundle[..boundary]).unwrap();
    let target = std::str::from_utf8(offered.merge.target_ref.as_bytes()).unwrap();
    let original = format!("{} {target}\n", offered.merge.merge_commit);
    let ci = RefName::try_new(b"refs/heads/ci-readiness").unwrap();
    assert_eq!(header.matches(original.as_str()).count(), 1);
    let mut bytes = header
        .replace(
            original.as_str(),
            &format!("{} refs/heads/ci-readiness\n", offered.merge.merge_commit),
        )
        .into_bytes();
    bytes.extend_from_slice(&bundle[boundary..]);
    let result = node
        .runtime()
        .block_on(node.import_incremental_git_bundle_durable_in(
            &node.request_context(),
            &session("readiness-ci-publication"),
            &bytes,
            &[(ci.clone(), None)],
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert_eq!(result.commands.len(), 1);
    for command in result.commands {
        committed((command.tx_id, command.terminal));
    }
    assert_eq!(
        snapshot(node).snapshot().refs[&ci],
        offered.merge.merge_commit
    );
}

#[test]
fn waiting_review_does_not_poison_the_landing_key_and_ready_uses_the_same_admission() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, pulls, _, _) = fixture(format, false);
        let reviewer = PrincipalId::from_bytes([0xa5; 16]);
        let mut rule = super::super::protection::queue_only(pulls[0].data.target_ref.clone());
        rule.required_approvals = 1;
        rule.reviewers = vec![reviewer];
        protect(&node, vec![rule], "readiness-review-policy");
        let prepared = prepare(
            &node,
            &subject(&node, &pulls[0]),
            1,
            MergeProfile::PathMergeV1,
        )
        .unwrap();
        let offered = offer(&prepared);
        let before = snapshot(&node);
        assert!(
            inspect(&node, &offered, "readiness-landing").is_err(),
            "missing candidate objects are unavailable, not a readiness observation"
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        assert!(node.read_git_object(offered.merge.merge_commit).is_err());
        publish_candidate_to_ci(&node, &prepared);

        let waiting = observe(
            &node,
            &offered,
            "readiness-landing",
            Some(RefusalCode::EvidenceMissing),
        );
        assert_eq!(
            observe(
                &node,
                &offered,
                "readiness-landing",
                Some(RefusalCode::EvidenceMissing),
            ),
            waiting
        );
        let approval = CandidateReviewCommand {
            review: ReviewCommand {
                expected_version: ExpectedVersion::NewStream,
                subject: prepared.subject.clone(),
                decision: ReviewDecision::Approve,
                reason: "Independent review of the exact stored queue candidate".into(),
            },
            candidate: CandidateBinding {
                merge_base: offered.merge.base_tip,
                commit: offered.merge.merge_commit,
            },
        };
        let reviewer_session = LoopbackReceiveSession::authenticated(
            reviewer,
            IdempotencyKey::new(b"readiness-approve".to_vec()).unwrap(),
        );
        accepted(
            node.runtime()
                .block_on(node.admit_candidate_review_durable_in(
                    &node.request_context(),
                    &reviewer_session,
                    &approval,
                    prepared.bundle.as_deref(),
                    AdmissionLimits::default(),
                )),
        );
        let ready = observe(&node, &offered, "readiness-landing", None);
        assert_eq!(ready.tx_id, waiting.tx_id);
        assert_ne!(ready.basis, waiting.basis);
        let landed = committed(
            publish(
                &node,
                &offered,
                prepared.bundle.as_deref().unwrap(),
                "readiness-landing",
            )
            .unwrap(),
        );
        assert_eq!(landed.0, ready.tx_id);
        assert_eq!(
            snapshot(&node).snapshot().refs[&offered.merge.target_ref],
            offered.merge.merge_commit
        );
        assert!(read(&node, 1, None).queue.unwrap().is_empty());
        assert_eq!(
            publish(&node, &offered, b"lost original bundle", "readiness-landing").unwrap(),
            landed
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn ready_observation_does_not_authorize_landing_after_queue_movement() {
    let (_scratch, node, pulls, _, _) = fixture(GitHashAlgorithm::Sha256, false);
    let prepared = prepare(
        &node,
        &subject(&node, &pulls[0]),
        1,
        MergeProfile::PathMergeV1,
    )
    .unwrap();
    let offered = offer(&prepared);
    publish_candidate_to_ci(&node, &prepared);
    let ready = observe(&node, &offered, "readiness-racing-landing", None);
    accepted(apply(
        &node,
        &enqueue(1, 1, &pulls[1], 0),
        "readiness-second-queued",
    ));
    let stale = observe(
        &node,
        &offered,
        "readiness-racing-landing",
        Some(RefusalCode::EvidenceStale),
    );
    assert_eq!(ready.tx_id, stale.tx_id);
    assert_ne!(ready.basis, stale.basis);
    let refused = refused(
        &node,
        &offered,
        prepared.bundle.as_deref().unwrap(),
        "readiness-racing-landing",
        RefusalCode::EvidenceStale,
    );
    assert_eq!(refused.0, ready.tx_id);
    assert_eq!(read(&node, 1, None).queue.unwrap().len(), 2);
    node.shutdown().unwrap();
}

#[test]
fn required_checks_anonymous_and_cancelled_observations_never_publish_a_decision() {
    let (_scratch, node, pulls, _, _) = fixture(GitHashAlgorithm::Sha1, false);
    let prepared = prepare(
        &node,
        &subject(&node, &pulls[0]),
        1,
        MergeProfile::PathMergeV1,
    )
    .unwrap();
    let mut offered = offer(&prepared);
    publish_candidate_to_ci(&node, &prepared);
    observe(&node, &offered, "readiness-required-check", None);
    let mut rule = super::super::protection::queue_only(offered.merge.target_ref.clone());
    rule.required_candidate_checks = vec![RequiredCandidateWorkflowCheck {
        publisher: actor(),
        graph_root: [0x84; 32],
        job: "test".into(),
    }];
    let epoch = protect(&node, vec![rule], "readiness-check-policy");
    observe(
        &node,
        &offered,
        "readiness-required-check",
        Some(RefusalCode::EvidenceStale),
    );
    offered.expected_policy_epoch = epoch;
    let waiting = observe(
        &node,
        &offered,
        "readiness-required-check",
        Some(RefusalCode::ProtectedRefTransitionDenied),
    );
    let before = snapshot(&node);
    assert!(
        node.runtime()
            .block_on(node.inspect_queue_head_candidate_in(
                &node.request_context(),
                &LoopbackReceiveSession::anonymous(),
                &offered,
            ))
            .is_err()
    );
    let cancelled = node.request_context();
    cancelled.authority().cancel();
    assert!(
        node.runtime()
            .block_on(node.inspect_queue_head_candidate_in(
                &cancelled,
                &session("readiness-required-check"),
                &offered,
            ))
            .is_err()
    );
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert_unsubmitted(&node, waiting.tx_id);
    let rejected = refused(
        &node,
        &offered,
        prepared.bundle.as_deref().unwrap(),
        "readiness-required-check",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    assert_eq!(rejected.0, waiting.tx_id);
    node.shutdown().unwrap();
}

#[test]
fn readiness_preserves_verified_authentication_and_only_observes_operator_refusal() {
    let (_scratch, node, pulls, _, _) = fixture(GitHashAlgorithm::Sha256, false);
    let prepared = prepare(
        &node,
        &subject(&node, &pulls[0]),
        1,
        MergeProfile::PathMergeV1,
    )
    .unwrap();
    let mut offered = offer(&prepared);
    publish_candidate_to_ci(&node, &prepared);
    offered.expected_policy_epoch = install_protection(
        &node,
        ReviewProtection {
            ref_policy: Some(compile_ref_policy(
                "policy queue_credential { rule verified { when actor.authentication >= single_factor then allow } default deny \"verified credential required\" }",
            ).unwrap()),
            administrators: vec![actor()],
            branches: vec![super::super::protection::queue_only(
                offered.merge.target_ref.clone(),
            )],
        },
        "readiness-authentication-policy",
    );
    let denied = observe(
        &node,
        &offered,
        "readiness-authenticated-landing",
        Some(RefusalCode::ProtectedRefTransitionDenied),
    );
    let verified = LoopbackReceiveSession::Authenticated(
        crate::AuthenticatedReceiveSession::new(
            actor(),
            IdempotencyKey::new(b"readiness-authenticated-landing".to_vec()).unwrap(),
        )
        .with_authentication(AdmissionAuthentication::HttpToken),
    );
    let before = snapshot(&node);
    let ready = node
        .runtime()
        .block_on(node.inspect_queue_head_candidate_in(
            &node.request_context(),
            &verified,
            &offered,
        ))
        .unwrap();
    assert_eq!(ready.refusal, None);
    assert_eq!(ready.basis, before.basis().id());
    assert_eq!(ready.tx_id, denied.tx_id);
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert_unsubmitted(&node, ready.tx_id);
    let landed = committed(
        node.runtime()
            .block_on(node.land_queue_head_bundle_durable_in(
                &node.request_context(),
                &verified,
                &offered,
                prepared.bundle.as_deref().unwrap(),
                AdmissionLimits::default(),
            ))
            .unwrap(),
    );
    assert_eq!(landed.0, ready.tx_id);
    assert_authenticated_landing_evidence(&node, landed.0);
    node.shutdown().unwrap();
}
