//! A retarget invalidates the old review even when both target branches name
//! the same commit and the resulting candidate bytes happen to be identical.
use super::*;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};

#[test]
fn retarget_never_reuses_old_approval_and_new_exact_review_permits_the_same_candidate() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch, format);
        let request = f.node.request_context();
        let release = RefName::try_new(b"refs/heads/release").unwrap();
        let created = f
            .node
            .runtime()
            .block_on(f.node.admit_branch_updates_durable_in(
                &request,
                &session(2, "create-release"),
                &[RefCommand {
                    name: release.clone(),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(f.data.target_tip),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            created.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        committed(&vote(&f.node, &f.command, Some(&f.bundle), 3, "old-approval").unwrap());
        assert_eq!(
            page(&f.node, None, 100, None).unwrap().reviews[0].freshness,
            ReviewFreshness::Current
        );
        let mut data = f.data.clone();
        data.target_ref = release.clone();
        let retarget = fgit_forge::event::pull_request::PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: fgit_forge::event::pull_request::PullRequestAction::Retarget,
            data,
        };
        let before = snapshot(&f.node);
        committed(
            &f.node
                .runtime()
                .block_on(f.node.admit_pull_request_durable_in(
                    &request,
                    &session(1, "retarget"),
                    &retarget,
                    Default::default(),
                ))
                .unwrap(),
        );
        code_unchanged(&before, &snapshot(&f.node));
        let rows = page(&f.node, None, 100, None).unwrap();
        assert_eq!(
            rows.reviews[0].freshness,
            ReviewFreshness::PullRequestChanged
        );
        assert_eq!(rows.reviews[0].event.subject.target_ref, target());
        let mut current = f.command.clone();
        current.review.subject.target_ref = release.clone();
        current.review.subject.pull_request_version = AggregateVersion::try_new(2).unwrap();
        let before = snapshot(&f.node);
        let refused = publish(
            &f.node,
            &current,
            &f.bundle,
            &[actor(3)],
            "old-review-refused",
        )
        .unwrap();
        assert!(
            matches!(
                refused.1.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::EvidenceStale,
                    ..
                }
            ),
            "{refused:?}"
        );
        code_unchanged(&before, &snapshot(&f.node));
        let mut withdrawal = f.command.clone();
        withdrawal.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        withdrawal.review.decision = ReviewDecision::Withdraw;
        withdrawal.review.reason = "Retract approval of the original target".into();
        committed(&vote(&f.node, &withdrawal, None, 3, "withdraw-old-target").unwrap());
        assert_eq!(
            page(&f.node, None, 100, None).unwrap().reviews[0].freshness,
            ReviewFreshness::Withdrawn
        );
        let inbox = f
            .node
            .runtime()
            .block_on(f.node.read_notification_target_in(
                &request,
                &session(1, "retarget-inbox"),
                fgit_forge::event::notification::NotificationTarget::PullRequest(
                    PullRequestNumber::FIRST,
                ),
                None,
            ))
            .unwrap();
        assert_eq!(inbox.threads.len(), 1);
        assert_eq!(inbox.threads[0].thread_version.get(), 4);
        assert_eq!(inbox.threads[0].title, retarget.data.title);
        current.review.expected_version =
            ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        committed(&vote(&f.node, &current, Some(&f.bundle), 3, "new-approval").unwrap());
        assert_eq!(
            page(&f.node, None, 100, None).unwrap().reviews[0].freshness,
            ReviewFreshness::Current
        );
        committed(
            &publish(
                &f.node,
                &current,
                &f.bundle,
                &[actor(3)],
                "new-review-merge",
            )
            .unwrap(),
        );
        let after = snapshot(&f.node);
        assert_eq!(after.snapshot().refs[&release], current.candidate.commit);
        assert_eq!(after.snapshot().refs[&target()], f.data.target_tip);
        f.node.shutdown().unwrap();
    }
}
