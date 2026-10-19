//! Actual imported native objects and file-backed authority quorum admission.
use super::*;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};

fn install(fixture: &mut Fixture, reviewers: &[u8], required_approvals: u16, key: &str) {
    let request = fixture.node.request_context();
    let current = fixture
        .node
        .runtime()
        .block_on(fixture.node.read_review_protection_in(&request))
        .unwrap();
    let command = ProtectionCommand {
        expected_version: current
            .version()
            .map(ExpectedVersion::Exactly)
            .unwrap_or(ExpectedVersion::NewStream),
        expected_epoch: current.policy_epoch,
        protection: ReviewProtection {
            administrators: vec![actor(1)],
            branches: vec![ProtectedBranch {
                name: target(),
                reviewers: reviewers.iter().copied().map(actor).collect(),
                required_approvals,
                required_checks: Vec::new(),
            }],
        },
    };
    committed(
        fixture
            .node
            .runtime()
            .block_on(fixture.node.admit_review_protection_durable_in(
                &request,
                &session(1, key),
                &command,
                AdmissionLimits::default(),
            ))
            .unwrap(),
    );
    fixture.command.review.subject.policy_epoch =
        snapshot(&fixture.node).basis().body().policy_epoch;
}

fn plain(fixture: &Fixture, key: &str, bundle: &[u8]) -> (TxId, TerminalOutcome) {
    let request = fixture.node.request_context();
    fixture
        .node
        .runtime()
        .block_on(
            fixture.node.apply_merge_bundle_durable_in(
                &request,
                actor(2),
                key.as_bytes(),
                fixture.command.review.subject.pull_request,
                ExpectedVersion::Exactly(fixture.command.review.subject.pull_request_version),
                &fixture
                    .command
                    .candidate
                    .merge(&fixture.command.review.subject),
                bundle,
            ),
        )
        .unwrap()
}

fn denied(value: &(TxId, TerminalOutcome)) {
    assert!(
        matches!(
            value.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ),
        "{value:?}"
    );
}

fn restart(fixture: Fixture, scratch: &Scratch, format: GitHashAlgorithm) -> Fixture {
    let Fixture {
        node,
        command,
        bundle,
        data,
    } = fixture;
    node.shutdown().unwrap();
    let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
    reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
    Fixture {
        node: reopened,
        command,
        bundle,
        data,
    }
}

#[test]
fn mandatory_two_of_three_publishes_an_actual_merge_and_recovers_exact_terminals() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut f = fixture(&scratch, format);
        let original = snapshot(&f.node);
        install(&mut f, &[3, 4, 5], 2, "quorum-policy");
        code_unchanged(&original, &snapshot(&f.node));
        committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "quorum-three").unwrap());
        let missing = plain(&f, "quorum-too-few", &f.bundle);
        denied(&missing);
        code_unchanged(&original, &snapshot(&f.node));
        committed(vote(&f.node, &f.command, Some(&f.bundle), 4, "quorum-four").unwrap());
        let mut request_changes = f.command.clone();
        request_changes.review.decision = ReviewDecision::RequestChanges;
        request_changes.review.reason = "This reviewer has not approved".into();
        committed(
            vote(
                &f.node,
                &request_changes,
                Some(&f.bundle),
                5,
                "quorum-five-changes",
            )
            .unwrap(),
        );
        // Explicit caller-selected requirements still demand every named vote.
        let additional = publish(
            &f.node,
            &f.command,
            &f.bundle,
            &[actor(5)],
            "quorum-additional-review",
        )
        .unwrap();
        denied(&additional);
        let reviewed = snapshot(&f.node);
        let published = committed(plain(&f, "quorum-merge", &f.bundle));
        let after = snapshot(&f.node);
        assert_eq!(after.snapshot().refs[&target()], f.command.candidate.commit);
        assert_eq!(
            after.snapshot().outbox.len(),
            reviewed.snapshot().outbox.len() + 1
        );
        assert_ne!(
            after.basis().body().forge_position_root,
            reviewed.basis().body().forge_position_root
        );
        assert!(f.node.read_git_object(f.command.candidate.commit).is_ok());
        let request = f.node.request_context();
        let prs = f
            .node
            .runtime()
            .block_on(
                f.node
                    .read_pull_requests_in(&request, &RefVisibility::new(), 0, 100, None),
            )
            .unwrap();
        assert!(matches!(
            prs.pull_requests[0].event.payload,
            ForgeEventPayload::MergeCommittedNative(_)
        ));
        f = restart(f, &scratch, format);
        let recovered_basis = snapshot(&f.node).basis().clone();
        assert_eq!(plain(&f, "quorum-merge", &[]), published);
        assert_eq!(plain(&f, "quorum-too-few", &[]), missing);
        assert_eq!(snapshot(&f.node).basis(), &recovered_basis);
        f.node.shutdown().unwrap();
    }
}

#[test]
fn latest_withdrawal_loses_quorum_across_restart_until_another_reviewer_approves() {
    let format = GitHashAlgorithm::Sha256;
    let scratch = Scratch::new();
    let mut f = fixture(&scratch, format);
    install(&mut f, &[3, 4, 5], 2, "withdraw-policy");
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "withdraw-three").unwrap());
    committed(vote(&f.node, &f.command, Some(&f.bundle), 4, "withdraw-four").unwrap());
    let mut withdrawn = f.command.clone();
    withdrawn.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    withdrawn.review.decision = ReviewDecision::Withdraw;
    withdrawn.review.reason = "Retract the previous approval".into();
    let withdrawal = committed(vote(&f.node, &withdrawn, None, 4, "withdraw-four-later").unwrap());
    let before = snapshot(&f.node);
    denied(&plain(&f, "withdraw-blocked", &f.bundle));
    code_unchanged(&before, &snapshot(&f.node));
    f = restart(f, &scratch, format);
    denied(&plain(&f, "withdraw-still-blocked", &f.bundle));
    assert_eq!(
        vote(&f.node, &withdrawn, None, 4, "withdraw-four-later").unwrap(),
        withdrawal
    );
    committed(vote(&f.node, &f.command, Some(&f.bundle), 5, "withdraw-five").unwrap());
    committed(plain(&f, "withdraw-restored-quorum", &f.bundle));
    assert_eq!(
        snapshot(&f.node).snapshot().refs[&target()],
        f.command.candidate.commit
    );
    f.node.shutdown().unwrap();
}

#[test]
fn author_and_submitter_votes_cannot_reduce_the_required_independent_approvals() {
    let scratch = Scratch::new();
    let mut f = fixture(&scratch, GitHashAlgorithm::Sha1);
    install(&mut f, &[1, 2, 3, 4], 2, "independent-policy");
    for (reviewer, key) in [
        (1, "opener-vote"),
        (2, "submitter-vote"),
        (3, "independent-three"),
    ] {
        committed(vote(&f.node, &f.command, Some(&f.bundle), reviewer, key).unwrap());
    }
    let before = snapshot(&f.node);
    denied(&plain(&f, "independent-too-few", &f.bundle));
    code_unchanged(&before, &snapshot(&f.node));
    committed(vote(&f.node, &f.command, Some(&f.bundle), 4, "independent-four").unwrap());
    committed(plain(&f, "independent-quorum", &f.bundle));
    f.node.shutdown().unwrap();
}

#[test]
fn administrator_lowering_a_threshold_still_requires_votes_for_the_new_policy_epoch() {
    let scratch = Scratch::new();
    let mut f = fixture(&scratch, GitHashAlgorithm::Sha256);
    install(&mut f, &[3, 4, 5], 2, "epoch-policy");
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "epoch-old-three").unwrap());
    committed(vote(&f.node, &f.command, Some(&f.bundle), 4, "epoch-old-four").unwrap());
    let old_epoch = f.command.review.subject.policy_epoch;
    install(&mut f, &[3, 4, 5], 1, "epoch-lower-threshold");
    assert_ne!(f.command.review.subject.policy_epoch, old_epoch);
    denied(&plain(&f, "epoch-stale-votes", &f.bundle));
    f.command.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "epoch-fresh-three").unwrap());
    committed(plain(&f, "epoch-fresh-quorum", &f.bundle));
    f.node.shutdown().unwrap();
}

#[test]
fn approvals_for_distinct_real_candidate_commits_cannot_be_combined_into_a_quorum() {
    let scratch = Scratch::new();
    let mut f = fixture(&scratch, GitHashAlgorithm::Sha1);
    install(&mut f, &[3, 4, 5], 2, "candidate-policy");
    committed(
        vote(
            &f.node,
            &f.command,
            Some(&f.bundle),
            3,
            "candidate-old-three",
        )
        .unwrap(),
    );
    let request = f.node.request_context();
    let prepared = f
        .node
        .runtime()
        .block_on(f.node.prepare_merge_bundle_in(
            &request,
            &target(),
            &incoming(),
            &RefVisibility::new(),
            &MergeMetadata {
                author: "Fixture <fixture@example.invalid>".into(),
                committer: "Fixture <fixture@example.invalid>".into(),
                timestamp: 1,
                message: b"Different exact reviewed candidate\n".to_vec(),
            },
            PreparationLimits::default(),
        ))
        .unwrap();
    let MergePreparation::Clean(plan) = prepared.outcome else {
        panic!("clean candidate")
    };
    assert_ne!(plan.commit, f.command.candidate.commit);
    f.command.candidate = CandidateBinding {
        merge_base: plan.base,
        commit: plan.commit,
    };
    f.bundle = prepared.bundle.unwrap();
    committed(
        vote(
            &f.node,
            &f.command,
            Some(&f.bundle),
            4,
            "candidate-new-four",
        )
        .unwrap(),
    );
    denied(&plain(&f, "candidate-mixed-votes", &f.bundle));
    committed(
        vote(
            &f.node,
            &f.command,
            Some(&f.bundle),
            5,
            "candidate-new-five",
        )
        .unwrap(),
    );
    committed(plain(&f, "candidate-exact-quorum", &f.bundle));
    assert_eq!(snapshot(&f.node).snapshot().refs[&target()], plan.commit);
    f.node.shutdown().unwrap();
}
