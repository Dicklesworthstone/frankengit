use super::*;
use fgit_types::{GitHashAlgorithm, PrincipalId};
use std::path::PathBuf;
use std::time::Duration;

fn config() -> WorkflowWatchConfig {
    WorkflowWatchConfig::try_new(
        GitHashAlgorithm::Sha256,
        RefName::try_new(b"refs/heads/main").unwrap(),
        b"ci".to_vec(),
        PathBuf::from("/private/pr-runs"),
        vec![b"ci".to_vec(), b"src".to_vec()],
        Duration::from_millis(20),
    )
    .unwrap()
}

#[test]
fn collection_bounds_and_fixed_selectors_are_mutually_exclusive_in_both_orders() {
    for bound in [0, 65, usize::MAX] {
        assert!(config().with_pull_requests(bound).is_err());
    }
    for bound in [1, 64] {
        assert_eq!(
            config().with_pull_requests(bound).unwrap().pull_requests(),
            Some(bound)
        );
    }
    assert!(
        config()
            .with_pull_request(1)
            .unwrap()
            .with_pull_requests(2)
            .is_err()
    );
    assert!(
        config()
            .with_pull_requests(2)
            .unwrap()
            .with_pull_request(1)
            .is_err()
    );
    assert!(
        config()
            .with_merge_queue(1)
            .unwrap()
            .with_pull_requests(2)
            .is_err()
    );
    assert!(
        config()
            .with_pull_requests(2)
            .unwrap()
            .with_merge_queue(1)
            .is_err()
    );
}

#[test]
fn capacity_and_poll_scheduling_do_not_reset_execution_or_reporting_binding() {
    let scope = [7; 32];
    let first = config().with_pull_requests(2).unwrap();
    let original = binding(&first, &scope);
    let mut changed = first
        .clone()
        .with_pull_requests(64)
        .unwrap()
        .with_attempt_timeout(Duration::from_secs(30))
        .unwrap();
    changed.interval = Duration::from_secs(2);
    assert_eq!(binding(&changed, &scope), original);
    assert_ne!(
        binding(
            &first
                .clone()
                .with_publisher(PrincipalId::from_bytes([1; 16])),
            &scope
        ),
        original
    );
    let mut changed = first.clone();
    changed.inputs.reverse();
    assert_ne!(binding(&changed, &scope), original);
    let mut changed = first.clone();
    changed.directory = b"src".to_vec();
    assert_ne!(binding(&changed, &scope), original);
    assert_ne!(binding(&first, &[8; 32]), original);
}

#[test]
fn child_selection_retains_exact_source_pr_and_all_execution_contracts() {
    let group = config()
        .with_pull_requests(64)
        .unwrap()
        .with_publisher(PrincipalId::from_bytes([9; 16]));
    let row = Entry {
        number: 31,
        reference: RefName::try_new(b"refs/heads/topic").unwrap(),
        initialized: true,
    };
    let child = member_config(&group, &row).unwrap();
    assert_eq!(child.pull_request(), Some(31));
    assert_eq!(child.pull_requests(), None);
    assert_eq!(child.reference(), &row.reference);
    assert_eq!(child.inputs(), group.inputs());
    assert_eq!(child.publisher(), group.publisher());
    assert_eq!(child.run_parent(), group.run_parent());
    assert_eq!(child.directory(), group.directory());
    assert_eq!(child.attempt_timeout(), group.attempt_timeout());
}

fn candidate(stem: &[u8]) -> PullRequestMergeWatchConfig {
    use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergeProfile};
    PullRequestMergeWatchConfig::try_new(
        RefName::try_new(stem).unwrap(),
        PrincipalId::from_bytes([3; 16]),
        MergeMetadata {
            author: "CI <ci@example.test>".into(),
            committer: "CI <ci@example.test>".into(),
            timestamp: 1_700_000_000,
            message: b"Test the actual combined tree".to_vec(),
        },
        MergeProfile::PathMergeV1,
        MergeCommitStyle::TwoParent,
    )
    .unwrap()
}

#[test]
fn collection_candidates_use_distinct_raw_byte_refs_and_ordinary_member_custody() {
    let source_only = config().with_pull_requests(4).unwrap();
    let template = candidate(b"refs/heads/ci/\xff");
    let group = source_only
        .clone()
        .with_pull_request_merge_candidates(template.clone())
        .unwrap();
    assert!(group.validate().is_ok());
    for number in [1, 23, u64::MAX] {
        let row = Entry {
            number,
            reference: RefName::try_new(b"refs/heads/topic").unwrap(),
            initialized: true,
        };
        let child = member_config(&group, &row).unwrap();
        let expected = [
            b"refs/heads/ci/\xff/pr-".as_slice(),
            number.to_string().as_bytes(),
        ]
        .concat();
        let merge = child.merge_candidate().unwrap();
        assert_eq!(merge.reference().as_bytes(), expected);
        assert_eq!(merge.principal(), template.principal());
        assert_eq!(merge.metadata(), template.metadata());
        assert_eq!(merge.profile(), template.profile());
        assert_eq!(merge.style(), template.style());
        assert_eq!(child.pull_request(), Some(number));
        assert_eq!(child.pull_requests(), None);
        assert_eq!(child.reference(), &row.reference);
        assert!(child.validate().is_ok());
    }
    let scope = [9; 32];
    assert_ne!(binding(&source_only, &scope), binding(&group, &scope));
    let raised = group.clone().with_pull_requests(64).unwrap();
    assert_eq!(binding(&raised, &scope), binding(&group, &scope));
    let changed = source_only
        .with_pull_request_merge_candidates(candidate(b"refs/heads/other-ci"))
        .unwrap();
    assert_ne!(binding(&changed, &scope), binding(&group, &scope));
}

#[test]
fn collection_candidate_namespace_is_explicit_disjoint_and_bounded_before_custody() {
    let template = candidate(b"refs/heads/ci");
    assert!(
        config()
            .with_pull_request_merge_candidates(template.clone())
            .is_err()
    );
    assert!(
        config()
            .with_pull_request(1)
            .unwrap()
            .with_pull_request_merge_candidates(template.clone())
            .is_err()
    );
    assert!(
        config()
            .with_pull_requests(4)
            .unwrap()
            .with_merge_candidate(template)
            .is_err()
    );
    for stem in [b"refs/heads/main".as_slice(), b"refs/heads/main/ci"] {
        assert!(
            config()
                .with_pull_requests(4)
                .unwrap()
                .with_pull_request_merge_candidates(candidate(stem))
                .is_err()
        );
    }
    let group = config()
        .with_pull_requests(4)
        .unwrap()
        .with_pull_request_merge_candidates(candidate(b"refs/heads/ci"))
        .unwrap();
    for source in [
        b"refs/heads/ci".as_slice(),
        b"refs/heads/ci/pr-2",
        b"refs/heads/ci/other",
    ] {
        let entry = Entry {
            number: 1,
            reference: RefName::try_new(source).unwrap(),
            initialized: false,
        };
        assert!(member_config(&group, &entry).is_err());
    }
    let nested = config()
        .with_pull_requests(4)
        .unwrap()
        .with_pull_request_merge_candidates(candidate(b"refs/heads/topic/ci"))
        .unwrap();
    let ancestor = Entry {
        number: 1,
        reference: RefName::try_new(b"refs/heads/topic").unwrap(),
        initialized: false,
    };
    assert!(member_config(&nested, &ancestor).is_err());
    for (length, valid) in [(1000, true), (1001, false)] {
        let mut stem = b"refs/heads/".to_vec();
        stem.resize(length, b'x');
        assert_eq!(
            config()
                .with_pull_requests(4)
                .unwrap()
                .with_pull_request_merge_candidates(candidate(&stem))
                .is_ok(),
            valid
        );
    }
}
