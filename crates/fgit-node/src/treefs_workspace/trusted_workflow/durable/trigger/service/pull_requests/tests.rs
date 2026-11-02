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
    let child = member_config(&group, &row);
    assert_eq!(child.pull_request(), Some(31));
    assert_eq!(child.pull_requests(), None);
    assert_eq!(child.reference(), &row.reference);
    assert_eq!(child.inputs(), group.inputs());
    assert_eq!(child.publisher(), group.publisher());
    assert_eq!(child.run_parent(), group.run_parent());
    assert_eq!(child.directory(), group.directory());
    assert_eq!(child.attempt_timeout(), group.attempt_timeout());
}
