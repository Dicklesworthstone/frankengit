#![forbid(unsafe_code)]
//! Path-specific policy through real native publication, current exact votes,
//! private bundle custody and canonical queue landing.

#[path = "path_review_publication/support.rs"]
mod support;
use support::*;

use fgit_admission::merge::native::NativeMergeMethod;
use fgit_admission::merge::native::queue::{QueueCandidateLandingCommand, QueueLandingCommand};
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand, TerminalOutcome};
use fgit_forge::event::protection::{PathReviewRule, PathReviewScope};
use fgit_forge::event::review::ReviewDecision;
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_types::{GitHashAlgorithm, RefusalCode};

fn rule(path: &[u8], scope: PathReviewScope, reviewer: u8) -> PathReviewRule {
    PathReviewRule {
        path: path.to_vec(),
        scope,
        reviewers: vec![actor(reviewer)],
        required_approvals: 1,
    }
}
fn methods() -> [NativeMergeMethod; 3] {
    [
        NativeMergeMethod::MergeCommit,
        NativeMergeMethod::Squash,
        NativeMergeMethod::FastForwardOnly,
    ]
}

#[test]
fn independent_path_quorums_follow_current_exact_votes_and_durable_retry_for_every_method() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for method in methods() {
            let root = Scratch::new();
            let mut f = Fixture::new(&root, format, method, Change::ProtectedLeaf);
            f.protect(
                vec![
                    rule(b"secure", PathReviewScope::Subtree, 3),
                    rule(b"secure/key", PathReviewScope::Exact, 4),
                ],
                Vec::new(),
                false,
            );
            let first = f.publish(b"no-votes", &f.bundle);
            refused(&first, RefusalCode::EvidenceMissing);
            assert_eq!(f.target(), f.merge.target_tip_before);
            if method != NativeMergeMethod::FastForwardOnly {
                assert!(
                    f.node.read_git_object(f.merge.merge_commit).is_err(),
                    "refused candidate stays in private custody"
                );
            }
            committed(&f.review(3, 0, ReviewDecision::Approve, b"subtree-review"));
            refused(
                &f.publish(b"only-subtree-vote", &f.bundle),
                RefusalCode::EvidenceMissing,
            );
            committed(&f.review(4, 0, ReviewDecision::Approve, b"exact-review"));
            committed(&f.review(3, 1, ReviewDecision::Withdraw, b"withdraw-subtree"));
            refused(
                &f.publish(b"withdrawn-subtree-vote", &f.bundle),
                RefusalCode::ProtectedRefTransitionDenied,
            );
            f = f.reopen(root.config(format));
            assert_eq!(f.target(), f.merge.target_tip_before);
            refused(
                &f.publish(b"withdrawn-after-restart", &f.bundle),
                RefusalCode::ProtectedRefTransitionDenied,
            );
            committed(&f.review(3, 2, ReviewDecision::Approve, b"renew-subtree"));
            assert_eq!(
                f.publish(b"no-votes", &[]),
                first,
                "historical refusal is not reinterpreted after new votes"
            );
            let accepted = f.publish(b"both-current-quorums", &f.bundle);
            committed(&accepted);
            assert_eq!(f.target(), f.merge.merge_commit);
            f = f.reopen(root.config(format));
            assert_eq!(
                f.publish(b"both-current-quorums", &[]),
                accepted,
                "exact committed retry needs no candidate upload"
            );
            f.node.shutdown().unwrap();
        }
    }
}

#[test]
fn two_of_three_path_quorum_requires_two_independent_principals_and_counts_latest_vote_once() {
    let root = Scratch::new();
    let mut f = Fixture::new(
        &root,
        GitHashAlgorithm::Sha256,
        NativeMergeMethod::MergeCommit,
        Change::ProtectedLeaf,
    );
    f.protect(
        vec![PathReviewRule {
            path: b"secure".to_vec(),
            scope: PathReviewScope::Subtree,
            reviewers: vec![actor(2), actor(3), actor(4)],
            required_approvals: 2,
        }],
        Vec::new(),
        false,
    );
    committed(&f.review(2, 0, ReviewDecision::Approve, b"submitter-approval"));
    committed(&f.review(3, 0, ReviewDecision::Approve, b"first-independent-approval"));
    let insufficient = f.publish(b"submitter-and-one-independent", &f.bundle);
    refused(&insufficient, RefusalCode::ProtectedRefTransitionDenied);
    assert_eq!(f.target(), f.merge.target_tip_before);

    // The same principal's newer approval replaces its prior vote. Two
    // canonical approval events from that principal still count as one person.
    committed(&f.review(3, 1, ReviewDecision::Approve, b"renew-first-independent"));
    refused(
        &f.publish(b"renewed-one-independent", &f.bundle),
        RefusalCode::ProtectedRefTransitionDenied,
    );
    assert_eq!(f.target(), f.merge.target_tip_before);
    assert!(f.node.read_git_object(f.merge.merge_commit).is_err());

    committed(&f.review(
        4,
        0,
        ReviewDecision::Approve,
        b"second-independent-approval",
    ));
    assert_eq!(
        f.publish(b"submitter-and-one-independent", &[]),
        insufficient,
        "a later quorum does not reinterpret the original terminal refusal"
    );
    committed(&f.publish(b"two-independent-principals", &f.bundle));
    assert_eq!(f.target(), f.merge.merge_commit);
    f.node.shutdown().unwrap();
}

#[test]
fn unrelated_paths_do_not_require_votes_and_exact_directory_is_distinct_from_subtree() {
    for method in methods() {
        for (change, selector) in [
            (Change::Unrelated, b"secure/key".as_slice()),
            (Change::ProtectedLeaf, b"secure".as_slice()),
        ] {
            let root = Scratch::new();
            let mut f = Fixture::new(&root, GitHashAlgorithm::Sha256, method, change);
            f.protect(
                vec![rule(selector, PathReviewScope::Exact, 3)],
                Vec::new(),
                false,
            );
            committed(&f.publish(b"unaffected-exact-rule", &f.bundle));
            assert_eq!(f.target(), f.merge.merge_commit);
            f.node.shutdown().unwrap();
        }
    }
}

#[test]
fn actual_candidate_changes_require_path_votes_even_when_the_source_diff_does_not() {
    for method in [NativeMergeMethod::MergeCommit, NativeMergeMethod::Squash] {
        let root = Scratch::new();
        let mut f = Fixture::new(
            &root,
            GitHashAlgorithm::Sha256,
            method,
            Change::CandidateOnly,
        );
        f.protect(
            vec![rule(b"secure/key", PathReviewScope::Exact, 3)],
            vec![actor(4)],
            false,
        );
        // The source changes only docs/readme. The supplied reviewed candidate
        // additionally changes secure/key. A source-side summary would omit it.
        committed(&f.review(4, 0, ReviewDecision::Approve, b"branch-review"));
        refused(
            &f.publish(b"branch-vote-without-path-vote", &f.bundle),
            RefusalCode::EvidenceMissing,
        );
        assert_eq!(f.target(), f.merge.target_tip_before);
        assert!(f.node.read_git_object(f.merge.merge_commit).is_err());
        committed(&f.review(
            3,
            0,
            ReviewDecision::Approve,
            b"actual-candidate-path-review",
        ));
        committed(&f.publish(b"branch-and-path-votes", &f.bundle));
        assert_eq!(f.target(), f.merge.merge_commit);
        f.node.shutdown().unwrap();
    }
}

#[test]
fn replacing_an_ancestor_directory_cannot_bypass_an_exact_descendant_rule() {
    for method in methods() {
        let root = Scratch::new();
        let mut f = Fixture::new(
            &root,
            GitHashAlgorithm::Sha1,
            method,
            Change::DirectoryReplacement,
        );
        f.protect(
            vec![rule(b"secure/key", PathReviewScope::Exact, 3)],
            Vec::new(),
            false,
        );
        // Replacing secure/ with a symlink deletes secure/key. No submitted
        // patch/path list supplies that fact; it must come from both trees.
        refused(
            &f.publish(b"deleted-descendant-without-review", &f.bundle),
            RefusalCode::EvidenceMissing,
        );
        assert_eq!(f.target(), f.merge.target_tip_before);
        committed(&f.review(3, 0, ReviewDecision::Approve, b"review-descendant-removal"));
        committed(&f.publish(b"reviewed-descendant-removal", &f.bundle));
        assert_eq!(f.target(), f.merge.merge_commit);
        f.node.shutdown().unwrap();
    }
}

#[test]
fn direct_ref_updates_cannot_bypass_path_only_protection_even_after_a_valid_vote() {
    let root = Scratch::new();
    let mut f = Fixture::new(
        &root,
        GitHashAlgorithm::Sha256,
        NativeMergeMethod::FastForwardOnly,
        Change::ProtectedLeaf,
    );
    f.protect(
        vec![rule(b"secure/key", PathReviewScope::Exact, 3)],
        Vec::new(),
        false,
    );
    let command = RefCommand {
        name: f.merge.target_ref.clone(),
        expected_old: ExpectedOld::Exactly(f.merge.target_tip_before),
        proposed_new: ProposedNew::Update(f.merge.source_tip),
        force: false,
    };
    for (index, key) in [b"direct-before-review".as_slice(), b"direct-after-review"]
        .into_iter()
        .enumerate()
    {
        if index == 1 {
            committed(&f.review(3, 0, ReviewDecision::Approve, b"review-native-path"));
        }
        let result = f
            .node
            .runtime()
            .block_on(f.node.admit_branch_updates_durable_in(
                &f.node.request_context(),
                &session(2, key),
                std::slice::from_ref(&command),
                Default::default(),
            ))
            .unwrap();
        assert_eq!(result.commands.len(), 1);
        refused(
            &result.commands[0].terminal,
            RefusalCode::ProtectedRefTransitionDenied,
        );
        assert_eq!(f.target(), f.merge.target_tip_before);
    }
    // The identical source and target coordinates can publish through the
    // native PR operation that authenticates the path witness and exact vote.
    committed(&f.publish(b"reviewed-native-path", &f.bundle));
    assert_eq!(f.target(), f.merge.merge_commit);
    f.node.shutdown().unwrap();
}

fn enqueue(f: &Fixture) {
    let command = QueueCommand {
        number: QueueNumber::FIRST,
        target_ref: f.merge.target_ref.clone(),
        expected_version: ExpectedVersion::NewStream,
        action: QueueCommandAction::Enqueue {
            pull_request: PullRequestNumber::FIRST,
            expected_pull_request_version: AggregateVersion::FIRST,
            source_ref: f.merge.source_ref.clone(),
            head_tip: f.merge.source_tip,
            expected_target_tip: f.merge.target_tip_before,
            priority: 0,
        },
    };
    let (_, terminal) = f
        .node
        .runtime()
        .block_on(f.node.admit_queue_durable_in(
            &f.node.request_context(),
            &session(1, b"enqueue"),
            &command,
            Default::default(),
        ))
        .unwrap();
    committed(&terminal);
}
fn land(f: &Fixture, key: &[u8], bytes: &[u8]) -> TerminalOutcome {
    if f.method == NativeMergeMethod::FastForwardOnly {
        let command = QueueLandingCommand {
            number: QueueNumber::FIRST,
            expected_version: AggregateVersion::FIRST,
            expected_policy_epoch: f.epoch,
            pull_request: PullRequestNumber::FIRST,
            expected_pull_request_version: AggregateVersion::FIRST,
            source_ref: f.merge.source_ref.clone(),
            head_tip: f.merge.source_tip,
            target_ref: f.merge.target_ref.clone(),
            expected_target_tip: f.merge.target_tip_before,
        };
        f.node
            .runtime()
            .block_on(f.node.land_queue_head_durable_in(
                &f.node.request_context(),
                &session(2, key),
                &command,
                Default::default(),
            ))
            .unwrap()
            .1
    } else {
        let command = QueueCandidateLandingCommand {
            number: QueueNumber::FIRST,
            expected_version: AggregateVersion::FIRST,
            expected_policy_epoch: f.epoch,
            pull_request: PullRequestNumber::FIRST,
            expected_pull_request_version: AggregateVersion::FIRST,
            merge: f.merge.clone(),
        };
        f.node
            .runtime()
            .block_on(f.node.land_queue_head_bundle_durable_in(
                &f.node.request_context(),
                &session(2, key),
                &command,
                bytes,
                Default::default(),
            ))
            .unwrap()
            .1
    }
}

#[test]
fn canonical_queue_landing_requires_path_reviews_for_fast_forward_and_private_candidates() {
    for method in [
        NativeMergeMethod::FastForwardOnly,
        NativeMergeMethod::MergeCommit,
    ] {
        let root = Scratch::new();
        let mut f = Fixture::new(
            &root,
            GitHashAlgorithm::Sha256,
            method,
            Change::ProtectedLeaf,
        );
        f.protect(
            vec![rule(b"secure/key", PathReviewScope::Exact, 3)],
            Vec::new(),
            true,
        );
        enqueue(&f);
        let denied = land(&f, b"queue-without-path-review", &f.bundle);
        refused(&denied, RefusalCode::EvidenceMissing);
        assert_eq!(f.target(), f.merge.target_tip_before);
        let queue = f
            .node
            .runtime()
            .block_on(f.node.read_queue_in(
                &f.node.request_context(),
                &Default::default(),
                QueueNumber::FIRST,
                None,
            ))
            .unwrap()
            .queue
            .unwrap();
        assert_eq!(queue.version, AggregateVersion::FIRST);
        assert_eq!(queue.deterministic_order(), vec![PullRequestNumber::FIRST]);
        committed(&f.review(3, 0, ReviewDecision::Approve, b"review-queued-path"));
        let accepted = land(&f, b"reviewed-queue-land", &f.bundle);
        committed(&accepted);
        assert_eq!(f.target(), f.merge.merge_commit);
        let queue = f
            .node
            .runtime()
            .block_on(f.node.read_queue_in(
                &f.node.request_context(),
                &Default::default(),
                QueueNumber::FIRST,
                None,
            ))
            .unwrap()
            .queue
            .unwrap();
        assert!(queue.deterministic_order().is_empty());
        assert_eq!(queue.version.get(), 3);
        f = f.reopen(root.config(GitHashAlgorithm::Sha256));
        assert_eq!(land(&f, b"reviewed-queue-land", &[]), accepted);
        assert_eq!(land(&f, b"queue-without-path-review", &[]), denied);
        f.node.shutdown().unwrap();
    }
}
