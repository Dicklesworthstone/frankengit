//! Old display snapshots are not new merge authorization. The real candidate,
//! review driver and coupled merge below keep using current admission policy.
use super::*;

#[test]
fn review_walk_retains_votes_and_historical_branch_tips_after_coupled_merge() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch, format);
        committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "peer-three").unwrap());
        committed(vote(&f.node, &f.command, Some(&f.bundle), 4, "peer-four").unwrap());
        let reference = page(&f.node, None, 100, None).unwrap();
        let first = page(&f.node, None, 1, Some(reference.source_head)).unwrap();
        assert_eq!(first.next_after, Some(actor(3)));

        let mut withdrawn = f.command.clone();
        withdrawn.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        withdrawn.review.decision = ReviewDecision::Withdraw;
        withdrawn.review.reason = "Withdraw after the reader pinned its view".into();
        committed(vote(&f.node, &withdrawn, None, 4, "withdraw-four").unwrap());
        let second = page(&f.node, first.next_after, 1, Some(first.source_head)).unwrap();
        assert_eq!(second.reviews, reference.reviews[1..]);
        assert_eq!(second.reviews[0].freshness, ReviewFreshness::Current);
        assert_eq!(second.source_head, reference.source_head);
        assert!(second.next_after.is_none());
        let current = page(&f.node, Some(actor(3)), 1, Some(snapshot(&f.node).basis().id())).unwrap();
        assert_eq!(current.reviews[0].freshness, ReviewFreshness::Withdrawn);

        // The old display page cannot satisfy a now-withdrawn required vote.
        let denied = publish(&f.node, &f.command, &f.bundle, &[actor(3), actor(4)], "withdrawn-publication").unwrap();
        assert!(matches!(denied.1.outcome, DecisionOutcome::Refused {
            code: RefusalCode::ProtectedRefTransitionDenied, .. }));
        let mut renewed = f.command.clone();
        renewed.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        committed(vote(&f.node, &renewed, Some(&f.bundle), 4, "renew-four").unwrap());
        committed(publish(&f.node, &f.command, &f.bundle, &[actor(3), actor(4)], "merge-after-renewal").unwrap());
        let after = snapshot(&f.node);
        assert_eq!(after.snapshot().refs[&target()], f.command.candidate.commit);
        assert_ne!(after.snapshot().refs[&target()], f.data.target_tip);
        assert_eq!(page(&f.node, None, 100, Some(reference.source_head)).unwrap(), reference,
            "historical review freshness must use the historical ref root, not current branch tips");
        assert!(page(&f.node, None, 100, None).unwrap().reviews.iter()
            .all(|review| review.freshness == ReviewFreshness::PullRequestClosed));
        assert_eq!(snapshot(&f.node).basis(), after.basis());
        f.node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        let head = reopened.runtime().block_on(reopened.authenticate_authority_head()).unwrap();
        reopened.bring_into_service(head.receipt().generation()).unwrap();
        assert_eq!(page(&reopened, None, 100, Some(reference.source_head)).unwrap(), reference);
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn retained_review_reads_preserve_current_visibility_and_cancellation_gates() {
    let scratch = Scratch::new();
    let f = fixture(&scratch, GitHashAlgorithm::Sha256);
    committed(vote(&f.node, &f.command, Some(&f.bundle), 3, "peer-three").unwrap());
    let pinned = page(&f.node, None, 100, None).unwrap();
    committed(vote(&f.node, &f.command, Some(&f.bundle), 4, "later-peer").unwrap());
    let before = snapshot(&f.node);
    for reference in [target(), incoming()] {
        let mut visibility = RefVisibility::new();
        visibility.push_rule(reference.as_bytes(), &Default::default()).unwrap();
        let request = f.node.request_context();
        assert!(f.node.runtime().block_on(f.node.read_reviews_in(&request, &visibility,
            PullRequestNumber::FIRST, None, 100, Some(pinned.source_head))).unwrap().is_none());
    }
    let request = f.node.request_context();
    request.authority().cancel();
    assert!(f.node.runtime().block_on(f.node.read_reviews_in(&request, &RefVisibility::new(),
        PullRequestNumber::FIRST, None, 100, Some(pinned.source_head))).is_err());
    assert_eq!(page(&f.node, None, 100, Some(pinned.source_head)).unwrap(), pinned);
    assert_eq!(snapshot(&f.node).basis(), before.basis());
    f.node.shutdown().unwrap();
}
