use super::*;
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm};

#[test]
fn path_history_is_snapshot_pinned_read_only_and_excludes_other_ref_ancestry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, incoming) = super::super::tests::fixture(format, false);
        let request = node.request_context();
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let mut query = PathLogOptions { path: b"text".to_vec(), log: LogOptions {
            limit: 1, ..LogOptions::default() } };
        let (head, first) = node.runtime().block_on(node.read_path_history_in(&request,
            &reference, &RefVisibility::new(), None, &query)).unwrap();
        assert_eq!(head, before.basis().id()); assert_eq!(first.tip, target);
        assert_eq!(first.total_commits, 2); assert_eq!(first.commits[0].id, target);
        assert_eq!(first.next_after, Some(1));
        query.log.after = 1;
        let (last_head, last) = node.runtime().block_on(node.read_path_history_in(&request,
            &reference, &RefVisibility::new(), Some(head), &query)).unwrap();
        assert_eq!(last_head, head); assert_eq!(last.next_after, None);
        assert_eq!(last.commits.len(), 1); assert_ne!(last.commits[0].id, incoming);
        query.path = b"path-that-never-existed".to_vec(); query.log.after = 0;
        let (empty_head, empty) = node.runtime().block_on(node.read_path_history_in(&request,
            &reference, &RefVisibility::new(), Some(head), &query)).unwrap();
        assert_eq!(empty_head, head); assert_eq!(empty.tip, target);
        assert_eq!(empty.total_commits, 0); assert!(empty.commits.is_empty());
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn path_history_preserves_visibility_pinning_and_resource_refusals() {
    let (_scratch, node, _, _) = super::super::tests::fixture(GitHashAlgorithm::Sha1, false);
    let request = node.request_context();
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let mut query = PathLogOptions { path: b"text".to_vec(), log: LogOptions::default() };
    let mut hidden = RefVisibility::new();
    hidden.push_rule(b"refs/heads/main", &fgit_wire::WireLimits::default()).unwrap();
    assert!(matches!(node.runtime().block_on(node.read_path_history_in(&request,
        &reference, &hidden, None, &query)), Err(NodeHistoryRefusal::Unavailable)));
    let missing = RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(matches!(node.runtime().block_on(node.read_path_history_in(&request,
        &missing, &RefVisibility::new(), None, &query)), Err(NodeHistoryRefusal::Unavailable)));
    let wrong = RepositoryAuthorityHeadId::from_digest(DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION, DigestBytes::try_new(&[123; 32]).unwrap());
    assert!(matches!(node.runtime().block_on(node.read_path_history_in(&request,
        &reference, &RefVisibility::new(), Some(wrong), &query)), Err(NodeHistoryRefusal::SnapshotMoved)));
    query.log.after = 1;
    assert!(matches!(node.runtime().block_on(node.read_path_history_in(&request,
        &reference, &RefVisibility::new(), None, &query)), Err(NodeHistoryRefusal::UnpinnedContinuation)));
    query.log.after = 0; query.log.limits.max_commits = 1;
    assert!(matches!(node.runtime().block_on(node.read_path_history_in(&request,
        &reference, &RefVisibility::new(), None, &query)), Err(NodeHistoryRefusal::History(_))));
    query.log = LogOptions::default(); query.path = b"../text".to_vec();
    let refusal = node.runtime().block_on(node.read_path_history_in(&request,
        &reference, &RefVisibility::new(), None, &query)).unwrap_err();
    assert_eq!(refusal.history_error(), Some(&HistoryError::InvalidOptions));
    node.shutdown().unwrap();
}
