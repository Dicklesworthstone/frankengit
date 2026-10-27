//! Threshold admission against authenticated reference-store frontiers.
//! These are canonical-body fixtures, not durable-node or executed-review proof.
use super::*;

fn quorum(fixture: &Fixture, reviewers: &[u8], count: u16) -> Result<(), ProjectionFailure> {
    let intent = crate::merge::native::NativeMergeIntent::new(
        PullRequestNumber::FIRST,
        ExpectedVersion::Exactly(AggregateVersion::FIRST),
        fixture.candidate.merge(&fixture.subject),
    )
    .unwrap();
    let reviewers: Vec<_> = reviewers.iter().copied().map(principal).collect();
    run(gate::verify_quorum_at(
        &fixture.store,
        &(),
        &fixture.basis,
        &intent,
        principal(3),
        PolicyEpoch::FIRST,
        &reviewers,
        count,
        &|| fixture.store.cancelled.load(Ordering::Relaxed),
    ))
}
fn insufficient(result: Result<(), ProjectionFailure>) {
    assert!(
        matches!(
            result,
            Err(ProjectionFailure::Refuse(
                RefusalCode::ProtectedRefTransitionDenied
            ))
        ),
        "{result:?}"
    );
}

#[test]
fn two_of_three_counts_distinct_current_approvals_without_requiring_an_absent_third() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, 0, vec![vote(format, 9), vote(format, 12)]);
        quorum(&fixture, &[9, 12, 13], 2).unwrap();
        quorum(&fixture, &[13, 9, 12], 2).unwrap();
        assert!(matches!(
            quorum(&fixture, &[9, 12, 13], 3),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))
        ));
        assert!(matches!(
            fixture.gate(vec![principal(9), principal(12), principal(13)]),
            Err(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))
        ));
        let missing = Fixture::new(format, 0, vec![vote(format, 9)]);
        insufficient(quorum(&missing, &[9, 12, 13], 2));
    }
}

#[test]
fn only_each_latest_vote_counts_and_changes_requested_is_not_an_extra_veto() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for decision in [ReviewDecision::Withdraw, ReviewDecision::RequestChanges] {
            let first = vote(format, 9);
            let mut latest = first.clone();
            latest.version = AggregateVersion::try_new(2).unwrap();
            let ForgeEventPayload::PullRequestReviewedNative(review) = &mut latest.payload else {
                panic!()
            };
            review.decision = decision;
            review.reason = "Latest decision supersedes the earlier approval".into();
            let insufficient_votes = Fixture::new(
                format,
                0,
                vec![first.clone(), latest.clone(), vote(format, 12)],
            );
            insufficient(quorum(&insufficient_votes, &[9, 12, 13], 2));
            let enough = Fixture::new(
                format,
                0,
                vec![first, latest, vote(format, 12), vote(format, 13)],
            );
            quorum(&enough, &[9, 12, 13], 2).unwrap();
            assert!(matches!(
                enough.gate(vec![principal(9)]),
                Err(ProjectionFailure::Refuse(
                    RefusalCode::ProtectedRefTransitionDenied
                ))
            ));
        }
    }
}

#[test]
fn source_only_and_every_stale_candidate_coordinate_contribute_no_approval() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for changed_field in 0..9 {
            let mut stale = vote(format, 9);
            let ForgeEventPayload::PullRequestReviewedNative(review) = &mut stale.payload else {
                panic!()
            };
            match changed_field {
                0 => review.candidate = None,
                1 => review.candidate.as_mut().unwrap().commit = oid(format, "55"),
                2 => review.candidate.as_mut().unwrap().merge_base = oid(format, "55"),
                3 => review.subject.pull_request_version = AggregateVersion::try_new(2).unwrap(),
                4 => review.subject.policy_epoch = PolicyEpoch::try_new(2).unwrap(),
                5 => review.subject.source_tip = oid(format, "55"),
                6 => review.subject.target_tip = oid(format, "55"),
                7 => {
                    review.subject.source_ref =
                        RefName::try_new(b"refs/heads/other-source").unwrap();
                }
                _ => {
                    review.subject.target_ref =
                        RefName::try_new(b"refs/heads/other-target").unwrap();
                }
            }
            let missing = Fixture::new(format, 0, vec![stale.clone(), vote(format, 12)]);
            insufficient(quorum(&missing, &[9, 12, 13], 2));
            let enough = Fixture::new(format, 0, vec![stale, vote(format, 12), vote(format, 13)]);
            quorum(&enough, &[9, 12, 13], 2).unwrap();
        }
    }
}

#[test]
fn opener_and_submitter_are_excluded_without_reducing_the_numeric_threshold() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let only_one = Fixture::new(
            format,
            0,
            vec![vote(format, 3), vote(format, 7), vote(format, 9)],
        );
        insufficient(quorum(&only_one, &[3, 7, 9, 12], 2));
        insufficient(quorum(&only_one, &[3, 7, 9], 2));
        let enough = Fixture::new(
            format,
            0,
            vec![
                vote(format, 3),
                vote(format, 7),
                vote(format, 9),
                vote(format, 12),
            ],
        );
        quorum(&enough, &[3, 7, 9, 12], 2).unwrap();
        insufficient(quorum(&enough, &[3, 7, 9, 12], 3));
        insufficient(quorum(&enough, &[3, 7, 9, 12], 4));
    }
}

#[test]
fn every_eligible_frontier_remains_authenticated_after_the_threshold_is_reached() {
    let format = GitHashAlgorithm::Sha256;
    let fixture = Fixture::new(
        format,
        0,
        vec![vote(format, 9), vote(format, 12), vote(format, 13)],
    );
    fixture.pr_page();
    let baseline = fixture.store.reads_of(&fixture.key(13));
    fixture.store.reset_reads();
    quorum(&fixture, &[9, 12, 13], 2).unwrap();
    assert_eq!(fixture.store.reads_of(&fixture.key(13)), baseline + 1);
    for (fault, code) in [
        (ReadFault::Missing, RefusalCode::EvidenceMissing),
        (ReadFault::Tampered, RefusalCode::EvidenceInvalid),
    ] {
        *fixture.store.fault.lock().unwrap() = Some((fixture.key(13), fault));
        assert!(matches!(quorum(&fixture, &[9, 12, 13], 2),
            Err(ProjectionFailure::Unavailable(observed)) if observed == code));
        *fixture.store.fault.lock().unwrap() = None;
        quorum(&fixture, &[9, 12, 13], 2).unwrap();
    }
}

#[test]
fn cancellation_during_a_later_frontier_cannot_return_an_already_reached_quorum() {
    let format = GitHashAlgorithm::Sha1;
    let fixture = Fixture::new(
        format,
        0,
        vec![vote(format, 9), vote(format, 12), vote(format, 13)],
    );
    fixture.pr_page();
    let parent_reads = fixture.store.reads_of(&fixture.key(13));
    fixture.store.reset_reads();
    *fixture.store.cancel_on.lock().unwrap() = Some((fixture.key(13), parent_reads + 1));
    assert!(matches!(
        quorum(&fixture, &[9, 12, 13], 2),
        Err(ProjectionFailure::Unavailable(
            RefusalCode::CancellationInProgress
        ))
    ));
    fixture.store.reset_reads();
    quorum(&fixture, &[9, 12, 13], 2).unwrap();
}

#[test]
fn malformed_thresholds_and_duplicate_reviewers_never_create_an_empty_gate() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, 0, vec![]);
    for (reviewers, count) in [
        (vec![9, 12, 13], 0),
        (vec![9, 12, 13], 4),
        (vec![9, 9, 12], 2),
        (vec![], 0),
        (vec![], 1),
    ] {
        assert!(matches!(
            quorum(&fixture, &reviewers, count),
            Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))
        ));
    }
}
