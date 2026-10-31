//! Pure identity/selection tests; actual canonical reads, execution and landing
//! are exercised by the separate trusted_queue_merge_watch integration fixture.
use super::super::pull_request::PullSelection;
use super::*;
use fgit_crypto::{DigestAlgorithm, DigestBytes};
use fgit_forge::PullRequestNumber;
use fgit_forge::merge_queue::QueueEntry;
use fgit_forge::preparation::{MergeMetadata, MergeProfile};
use fgit_types::{
    CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId,
    RepositoryDecisionBatchId,
};

fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}

fn head(byte: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithm::Sha256.id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).unwrap(),
    )
}

fn selected(format: GitHashAlgorithm) -> Selected {
    Selected {
        head: head(1),
        commit: oid(format, 2),
        previous_commit: None,
        batch: RepositoryDecisionBatchId::from_digest(
            DigestAlgorithm::Sha256.id(),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[3; 32]).unwrap(),
        ),
        event_head: head(4),
        pull: Some(PullSelection {
            number: 5,
            version: 6,
            target: RefName::try_new(b"refs/heads/main").unwrap(),
            target_commit: oid(format, 7),
            recorded_source: oid(format, 2),
            recorded_target: oid(format, 7),
            policy_epoch: PolicyEpoch::FIRST,
        }),
        queue: Some(QueueSelection {
            number: QueueNumber::try_new(8).unwrap(),
            version: AggregateVersion::try_new(9).unwrap(),
            source: RefName::try_new(b"refs/heads/topic/\xff").unwrap(),
        }),
    }
}

fn event(selected: &Selected) -> [u8; 32] {
    selected
        .queue
        .as_ref()
        .unwrap()
        .event_id(&[10; 32], selected)
        .unwrap()
}

#[test]
fn queue_event_invalidates_each_semantic_guard_but_not_unrelated_authority_progress() {
    let changes: &[fn(&mut Selected)] = &[
        |s| s.queue.as_mut().unwrap().number = QueueNumber::try_new(11).unwrap(),
        |s| s.queue.as_mut().unwrap().version = AggregateVersion::try_new(10).unwrap(),
        |s| s.queue.as_mut().unwrap().source = RefName::try_new(b"refs/heads/topic/\xfe").unwrap(),
        |s| s.pull.as_mut().unwrap().number += 1,
        |s| s.pull.as_mut().unwrap().version += 1,
        |s| s.pull.as_mut().unwrap().target = RefName::try_new(b"refs/heads/release").unwrap(),
        |s| s.pull.as_mut().unwrap().target_commit = oid(s.commit.algorithm(), 12),
        |s| s.pull.as_mut().unwrap().recorded_source = oid(s.commit.algorithm(), 13),
        |s| s.pull.as_mut().unwrap().recorded_target = oid(s.commit.algorithm(), 14),
        |s| s.pull.as_mut().unwrap().policy_epoch = PolicyEpoch::FIRST.next().unwrap(),
        |s| s.commit = oid(s.commit.algorithm(), 15),
        |s| {
            s.batch = RepositoryDecisionBatchId::from_digest(
                DigestAlgorithm::Sha256.id(),
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[16; 32]).unwrap(),
            )
        },
    ];
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = selected(format);
        let expected = event(&original);
        assert_eq!(event(&selected(format)), expected);
        for (index, change) in changes.iter().enumerate() {
            let mut altered = selected(format);
            change(&mut altered);
            assert_ne!(event(&altered), expected, "guard {index}");
        }
        let mut unrelated = selected(format);
        unrelated.head = head(17);
        assert_eq!(event(&unrelated), expected);
        assert_ne!(
            original
                .queue
                .as_ref()
                .unwrap()
                .event_id(&[18; 32], &original)
                .unwrap(),
            expected,
        );
        unrelated.pull = None;
        assert!(
            unrelated
                .queue
                .as_ref()
                .unwrap()
                .event_id(&[10; 32], &unrelated)
                .is_err()
        );
    }
    assert_ne!(
        event(&selected(GitHashAlgorithm::Sha1)),
        event(&selected(GitHashAlgorithm::Sha256))
    );
}

#[test]
fn current_queue_match_requires_exact_number_version_target_and_first_entry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let state = selected(format);
        let selected = state.queue.as_ref().unwrap();
        let pull = state.pull.as_ref().unwrap();
        let subject = ReviewSubject {
            pull_request: PullRequestNumber::try_new(pull.number).unwrap(),
            pull_request_version: AggregateVersion::try_new(pull.version).unwrap(),
            source_ref: selected.source.clone(),
            target_ref: pull.target.clone(),
            source_tip: state.commit,
            target_tip: pull.target_commit,
            policy_epoch: pull.policy_epoch,
        };
        let mut queue = MergeQueueSnapshot::new(selected.number, subject.target_ref.clone());
        queue.version = selected.version;
        queue.entries.push(QueueEntry {
            pull_request: subject.pull_request,
            source_ref: subject.source_ref.clone(),
            head_tip: subject.source_tip,
            enqueued_by: PrincipalId::from_bytes([1; 16]),
            priority: 0,
            enqueued_version: AggregateVersion::FIRST,
        });
        assert!(selected.matches(&queue, &subject));
        let mut stale = queue.clone();
        stale.version = AggregateVersion::FIRST;
        assert!(!selected.matches(&stale, &subject));
        let mut stale = queue.clone();
        stale.queue_number = QueueNumber::try_new(19).unwrap();
        assert!(!selected.matches(&stale, &subject));
        let mut stale = queue.clone();
        stale.target_ref = RefName::try_new(b"refs/heads/other").unwrap();
        assert!(!selected.matches(&stale, &subject));
        let mut stale = queue.clone();
        stale.entries[0].head_tip = oid(format, 20);
        assert!(!selected.matches(&stale, &subject));
        let mut stale = queue.clone();
        let mut earlier = stale.entries[0].clone();
        earlier.pull_request = PullRequestNumber::try_new(21).unwrap();
        stale.entries.insert(0, earlier);
        assert!(!selected.matches(&stale, &subject));
        queue.entries.clear();
        assert!(!selected.matches(&queue, &subject));
    }
}

#[test]
fn queue_selection_is_explicit_two_parent_and_exclusive() {
    let target = RefName::try_new(b"refs/heads/main").unwrap();
    let config = |reference: RefName, style| {
        pull_request_merge::PullRequestMergeWatchConfig::try_new(
            reference,
            PrincipalId::from_bytes([1; 16]),
            MergeMetadata {
                author: "CI <ci@example.test>".into(),
                committer: "CI <ci@example.test>".into(),
                timestamp: 1_700_000_000,
                message: b"Test queue head".to_vec(),
            },
            MergeProfile::PathMergeV1,
            style,
        )
        .unwrap()
    };
    let ci = RefName::try_new(b"refs/heads/ci/main").unwrap();
    let two_parent = config(ci.clone(), MergeCommitStyle::TwoParent);
    assert!(validate_selection(&target, None, Some(1), Some(&two_parent)).is_ok());
    assert!(validate_selection(&target, None, Some(0), Some(&two_parent)).is_err());
    assert!(validate_selection(&target, Some(1), Some(1), Some(&two_parent)).is_err());
    assert!(validate_selection(&target, None, Some(1), None).is_err());
    assert!(
        validate_selection(
            &target,
            None,
            Some(1),
            Some(&config(ci, MergeCommitStyle::Squash))
        )
        .is_err()
    );
    assert!(
        validate_selection(
            &target,
            None,
            Some(1),
            Some(&config(target.clone(), MergeCommitStyle::TwoParent))
        )
        .is_err()
    );
    // Existing direct-source and explicitly selected PR profiles are unchanged.
    assert!(validate_selection(&target, None, None, None).is_ok());
    assert!(validate_selection(&target, Some(1), None, Some(&two_parent)).is_ok());
}
