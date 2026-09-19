use super::*;
use crate::NodeWorkspaceRefusal;
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

#[test]
fn historical_browsing_opens_old_bytes_but_never_other_branch_commits() {
    use fgit_forge::source_browse::{SourceBrowseAction, SourceBrowseContent, SourceBrowseQuery};
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, target, incoming) = super::super::tests::fixture(format, false);
        let request = node.request_context();
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let (head, history) = node.runtime().block_on(node.read_commit_history_in(&request,
            &reference, &RefVisibility::new(), None, LogOptions::default())).unwrap();
        let base = history.commits.last().unwrap().id;
        assert_ne!(base, target);
        let mut query = SourceBrowseQuery { path: Some(b"text".to_vec()), expected_head: Some(head),
            expected_commit: Some(base), action: SourceBrowseAction::Read { offset: 0, limit: 1024 } };
        let report = node.runtime().block_on(node.browse_source_ancestor_local_in(&request,
            &reference, target, base, &query)).unwrap();
        assert_eq!(report.source_head, head);
        assert_eq!(report.source_commit, base);
        let SourceBrowseContent::Blob { bytes, next_offset, .. } = report.content else { panic!("blob"); };
        assert_eq!(bytes, b"a\nb\nc\nd\ne\n");
        assert_eq!(next_offset, None);
        query.action = SourceBrowseAction::Read { offset: 2, limit: 2 };
        let range = node.runtime().block_on(node.browse_source_ancestor_local_in(&request,
            &reference, target, base, &query)).unwrap();
        let SourceBrowseContent::Blob { bytes, next_offset, .. } = range.content else { panic!("blob"); };
        assert_eq!(bytes, b"b\n"); assert_eq!(next_offset, Some(4));
        query.path = None;
        query.action = SourceBrowseAction::List { after: None, limit: 10 };
        assert!(node.runtime().block_on(node.browse_source_ancestor_local_in(&request,
            &reference, target, base, &query)).is_ok());
        query.expected_commit = Some(incoming);
        assert!(matches!(node.runtime().block_on(node.browse_source_ancestor_local_in(&request,
            &reference, target, incoming, &query)), Err(NodeWorkspaceRefusal::RefUnavailable)));
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn historical_reads_refuse_unpinned_stale_missing_and_cancelled_selections() {
    use fgit_forge::source_browse::{SourceBrowseAction, SourceBrowseQuery};
    let (_scratch, node, target, incoming) = super::super::tests::fixture(GitHashAlgorithm::Sha1, false);
    let request = node.request_context();
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let head = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis().id();
    let mut query = SourceBrowseQuery { path: None, expected_head: None, expected_commit: Some(target),
        action: SourceBrowseAction::List { after: None, limit: 1 } };
    assert!(node.runtime().block_on(node.browse_source_ancestor_local_in(&request,
        &reference, target, target, &query)).is_err());
    query.expected_head = Some(head);
    assert!(node.runtime().block_on(node.browse_source_ancestor_local_in(&request,
        &reference, incoming, target, &query)).is_err());
    let missing = RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(matches!(node.runtime().block_on(node.browse_source_ancestor_local_in(&request,
        &missing, target, target, &query)), Err(NodeWorkspaceRefusal::RefUnavailable)));
    let wrong = RepositoryAuthorityHeadId::from_digest(DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION, DigestBytes::try_new(&[123; 32]).unwrap());
    query.expected_head = Some(wrong);
    assert!(node.runtime().block_on(node.browse_source_ancestor_local_in(&request,
        &reference, target, target, &query)).is_err());
    query.expected_head = Some(head);
    request.cancel();
    assert!(node.runtime().block_on(node.browse_source_ancestor_local_in(&request,
        &reference, target, target, &query)).is_err());
    node.shutdown().unwrap();
}
