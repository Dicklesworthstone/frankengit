#![forbid(unsafe_code)]
//! Scoped incremental refresh through native TreeFS, real source publication,
//! persistent authority and index codecs. No supplied document inventory.
#[path = "source_http/support.rs"]
mod support;
use fgit_forge::patch::PatchLimits;
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_search::SearchLimits;
use fgit_graph::lexical::scoped::{LexicalScope, ScopedLexicalReport};
use fgit_graph::lexical::{
    IndexError, LexicalChannel, LexicalQuery, LexicalReadLimits, LexicalRefreshStats, LexicalSource,
};
use fgit_graph::{GenerationActivation, GenerationRecovery, GraphGenerationId};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
use support::*;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn coverage(paths: &[&[u8]]) -> LexicalScope {
    LexicalScope::new(&paths.iter().map(|p| p.to_vec()).collect::<Vec<_>>()).unwrap()
}
fn build(node: &OneNode, scope: &LexicalScope, old: Option<GraphGenerationId>) -> GenerationActivation {
    node.runtime().block_on(node.build_scoped_source_index_local_in(
        &node.outbox_delivery_context(), &reference(), scope, None, None, old, Default::default(),
    )).unwrap().1
}
fn refresh(
    node: &OneNode,
    scope: &LexicalScope,
    old: &GenerationActivation,
    limits: SearchLimits,
) -> Result<(LexicalSource, GenerationActivation, LexicalRefreshStats), NodeWorkspaceRefusal> {
    node.runtime().block_on(node.refresh_scoped_source_index_local_in(
        &node.outbox_delivery_context(), &reference(), scope, None, None,
        old.generation_id, limits, Default::default(),
    ))
}
fn search(node: &OneNode, scope: &LexicalScope, term: &[u8]) -> ScopedLexicalReport {
    node.runtime().block_on(node.search_scoped_source_index_local_in(
        &node.request_context(), &reference(), scope, None, None, None, None,
        &LexicalQuery::new(LexicalChannel::Content, &[term.to_vec()], &[]).unwrap(),
        None, Default::default(), Default::default(),
    )).unwrap()
}
fn edit(node: &OneNode, base: GitOid, patch: &[u8]) -> GitOid {
    let request = node.outbox_delivery_context();
    let metadata = MergeMetadata {
        author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(),
        timestamp: 2,
        message: b"scoped refresh source\n".to_vec(),
    };
    let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(
        &request, &reference(), base, [0xe7; 16], patch, &metadata, PatchLimits::default(),
    )).unwrap();
    let terminal = node.runtime().block_on(node.apply_workspace_bundle_durable_in(
        &request, OWNER, b"scoped-refresh-edit", &reference(), base,
        candidate.candidate_commit, candidate.bundle_bytes(),
    )).unwrap();
    assert!(!terminal.commands.is_empty());
    assert!(terminal.commands.iter().all(|r| matches!(r.terminal.outcome, DecisionOutcome::Committed { .. })));
    candidate.candidate_commit
}

#[test]
fn unchanged_scoped_rows_reuse_postings_in_both_formats_and_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let scope = coverage(&[b"dir/nested.txt", b"dir", BINARY_PATH, b"alpha.txt"]);
        let before = generation(&node);
        let first = build(&node, &scope, None);
        let original = search(&node, &scope, b"needle");
        let (source, second, stats) = refresh(&node, &scope, &first, SearchLimits {
            max_files: 3, max_matches: 1, ..Default::default()
        }).unwrap();
        assert_eq!(source.commit, commit);
        assert_eq!(source, original.index.source);
        assert_eq!((stats.reused_documents, stats.rebuilt_documents, stats.prior_documents_not_reused), (3, 0, 0));
        assert_eq!(stats.reused_source_bytes, TEXT.len() + BINARY.len() + b"needle in nested\n".len());
        assert_eq!(stats.rebuilt_source_bytes, 0);
        assert!(stats.previous_payload_bytes_read > 0);
        assert!(stats.previous_generation_bytes_read > 0);
        assert_eq!(search(&node, &scope, b"needle").index.results, original.index.results);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
        let node = reopen(&config);
        let equivalent = coverage(&[b"alpha.txt", BINARY_PATH, b"dir"]);
        let (_, third, stats) = refresh(&node, &equivalent, &second, Default::default()).unwrap();
        assert_eq!((stats.reused_documents, stats.rebuilt_documents), (3, 0));
        assert_eq!(search(&node, &scope, b"needle").index.generation, third);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn actual_cross_scope_renames_edits_and_deletions_match_a_complete_scoped_rebuild() {
    let patch = b"diff --git a/empty b/empty\ndeleted file mode 100644\ndiff --git a/run b/run\n--- a/run\n+++ b/run\n@@ -1,2 +1,2 @@\n #!/bin/sh\n-needle\n+changed\ndiff --git a/dir/nested.txt b/moved.txt\nsimilarity index 100%\nrename from dir/nested.txt\nrename to moved.txt\ndiff --git a/alpha.txt b/dir/imported.txt\nsimilarity index 100%\nrename from alpha.txt\nrename to dir/imported.txt\ndiff --git a/dir/new.txt b/dir/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/dir/new.txt\n@@ -0,0 +1 @@\n+novel\n";
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, base) = fixture(&root, format);
        let scope = coverage(&[b"dir", b"run", b"empty", BINARY_PATH]);
        let first = build(&node, &scope, None);
        let commit = edit(&node, base, patch);
        let before = generation(&node);
        let (source, second, stats) = refresh(&node, &scope, &first, Default::default()).unwrap();
        assert_eq!(source.commit, commit);
        assert_eq!((stats.reused_documents, stats.rebuilt_documents, stats.prior_documents_not_reused), (1, 3, 3));
        assert_eq!(stats.reused_source_bytes, BINARY.len());
        assert_eq!(stats.rebuilt_source_bytes, TEXT.len() + b"novel\n".len() + b"#!/bin/sh\nchanged\n".len());
        let incremental = search(&node, &scope, b"needle");
        assert_eq!(incremental.index.results.hits.iter().map(|h| h.path.as_slice()).collect::<Vec<_>>(),
            vec![BINARY_PATH, b"dir/imported.txt".as_slice()]);
        assert_eq!(incremental.index.indexed_documents, 4);
        let novel = search(&node, &scope, b"novel").index.results;
        let changed = search(&node, &scope, b"changed").index.results;
        let rebuilt = build(&node, &scope, Some(second.generation_id));
        let full = search(&node, &scope, b"needle");
        assert_eq!(full.index.source, source);
        assert_eq!(full.index.generation, rebuilt);
        assert_eq!(full.index.results, incremental.index.results);
        assert_eq!(search(&node, &scope, b"novel").index.results, novel);
        assert_eq!(search(&node, &scope, b"changed").index.results, changed);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn exact_nested_scope_prunes_sibling_blobs_and_does_not_initialize_whole_tree_index() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, base) = fixture(&root, format);
        // Missing coverage is retained, and prefix order need not agree
        // between raw-byte keys and component-based path representations.
        let scope = coverage(&[b"dir.z", b"dir/nested.txt"]);
        let first = build(&node, &scope, None);
        edit(&node, base, b"diff --git a/dir/sibling.txt b/dir/sibling.txt\nnew file mode 100644\n--- /dev/null\n+++ b/dir/sibling.txt\n@@ -0,0 +1 @@\n+this sibling is outside the exact indexed path\n");
        let before = generation(&node);
        let (_, _, stats) = refresh(&node, &scope, &first, SearchLimits {
            max_files: 1, max_file_bytes: 17, max_total_bytes: 17, ..Default::default()
        }).unwrap();
        assert_eq!((stats.reused_documents, stats.rebuilt_documents), (1, 0));
        assert_eq!(stats.rebuilt_source_bytes, 0);
        assert_eq!(search(&node, &scope, b"needle").index.indexed_documents, 1);
        let unscoped = node.runtime().block_on(node.search_source_index_local_in(
            &node.request_context(), &reference(), None, None, None, None,
            &LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap(),
            None, Default::default(), Default::default(),
        ));
        assert!(matches!(unscoped, Err(NodeWorkspaceRefusal::SourceIndex(error)) if matches!(*error, IndexError::Uninitialized)));
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn reuse_obeys_source_and_previous_payload_budgets_before_any_candidate_barrier() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let scope = coverage(&[b"alpha.txt", b"dir"]);
    let first = build(&node, &scope, None);
    let original = search(&node, &scope, b"needle");
    let before = generation(&node);
    for limits in [
        SearchLimits { max_files: 1, ..Default::default() },
        SearchLimits { max_file_bytes: 1, ..Default::default() },
        SearchLimits { max_total_bytes: original.index.indexed_source_bytes - 1, ..Default::default() },
    ] {
        let mut called = false;
        let result = node.runtime().block_on(node.refresh_scoped_source_index_guarded_local_in(
            &node.outbox_delivery_context(), &reference(), &scope, None, None,
            first.generation_id, limits, Default::default(), &mut |_| { called = true; Ok(()) },
        ));
        assert!(result.is_err());
        assert!(!called);
        assert_eq!(search(&node, &scope, b"needle").index.generation, first);
    }
    let mut called = false;
    assert!(node.runtime().block_on(node.refresh_scoped_source_index_guarded_local_in(
        &node.outbox_delivery_context(), &reference(), &scope, None, None, first.generation_id,
        Default::default(), LexicalReadLimits { max_payload_bytes: 1, ..Default::default() },
        &mut |_| { called = true; Ok(()) },
    )).is_err());
    assert!(!called);
    let (_, _, stats) = refresh(&node, &scope, &first, SearchLimits {
        max_total_bytes: original.index.indexed_source_bytes, ..Default::default()
    }).unwrap();
    assert_eq!(stats.reused_source_bytes, original.index.indexed_source_bytes);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn stale_foreign_scope_source_pins_and_cancelled_requests_cannot_refresh() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let scope = coverage(&[b"dir"]);
    let foreign = coverage(&[b"run"]);
    let first = build(&node, &scope, None);
    let other = build(&node, &foreign, None);
    assert!(refresh(&node, &scope, &other, Default::default()).is_err());
    let second = refresh(&node, &scope, &first, Default::default()).unwrap().1;
    assert!(refresh(&node, &scope, &first, Default::default()).is_err());
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let wrong = GitOid::from_hex(format, &"a".repeat(2 * format.digest_len())).unwrap();
        assert!(node.runtime().block_on(node.refresh_scoped_source_index_local_in(
            &node.outbox_delivery_context(), &reference(), &scope, None, Some(wrong),
            second.generation_id, Default::default(), Default::default(),
        )).is_err());
    }
    assert!(matches!(node.runtime().block_on(node.refresh_scoped_source_index_local_in(
        &node.outbox_delivery_context(), &RefName::try_new(b"refs/heads/missing").unwrap(),
        &scope, None, None, second.generation_id, Default::default(), Default::default(),
    )), Err(NodeWorkspaceRefusal::RefUnavailable)));
    let request = node.outbox_delivery_context();
    request.cancel();
    assert!(node.runtime().block_on(node.refresh_scoped_source_index_local_in(
        &request, &reference(), &scope, None, None, second.generation_id,
        Default::default(), Default::default(),
    )).is_err());
    drop(node.refresh_scoped_source_index_local_in(
        &node.outbox_delivery_context(), &reference(), &scope, None, None,
        second.generation_id, Default::default(), Default::default(),
    ));
    assert_eq!(search(&node, &scope, b"needle").index.generation, second);
    assert_eq!(search(&node, &foreign, b"needle").index.generation, other);
    node.shutdown().unwrap();
}

#[test]
fn barrier_refusal_and_cancellation_retain_original_scoped_candidate_for_recovery() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha256);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let scope = coverage(&[b"dir"]);
    let first = build(&node, &scope, None);
    let before = generation(&node);
    let mut original = None;
    let result = node.runtime().block_on(node.refresh_scoped_source_index_guarded_local_in(
        &node.outbox_delivery_context(), &reference(), &scope, None, None, first.generation_id,
        Default::default(), Default::default(), &mut |id| {
            original = Some(id); Err(NodeWorkspaceRefusal::RefUnavailable)
        },
    ));
    assert!(matches!(result, Err(NodeWorkspaceRefusal::RefUnavailable)));
    assert_eq!(search(&node, &scope, b"needle").index.generation, first);
    let candidate = original.unwrap();
    let request = node.outbox_delivery_context();
    let result = node.runtime().block_on(node.refresh_scoped_source_index_guarded_local_in(
        &request, &reference(), &scope, None, None, first.generation_id,
        Default::default(), Default::default(), &mut |id| {
            assert_eq!(id, candidate); request.cancel(); Ok(())
        },
    ));
    assert!(matches!(result, Err(NodeWorkspaceRefusal::SourceIndexPublication { candidate: id, .. }) if id == candidate));
    let (_, second, _) = refresh(&node, &scope, &first, Default::default()).unwrap();
    assert_eq!(candidate, second.generation_id);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
    let node = reopen(&config);
    assert!(matches!(node.runtime().block_on(node.recover_scoped_source_index_local_in(
        &node.request_context(), &reference(), &scope, candidate, Some(&second), Default::default(),
    )).unwrap(), GenerationRecovery::Active { .. }));
    node.shutdown().unwrap();
}

#[test]
fn empty_and_non_regular_scopes_refresh_without_following_links_or_inventing_rows() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    for (paths, excluded) in [
        (&[b"absent".as_slice()][..], 0),
        (&[b"link".as_slice(), b"module"][..], 2),
    ] {
        let scope = coverage(paths);
        let first = build(&node, &scope, None);
        let (_, second, stats) = refresh(&node, &scope, &first, Default::default()).unwrap();
        assert_eq!((stats.reused_documents, stats.rebuilt_documents, stats.prior_documents_not_reused), (0, 0, 0));
        let report = search(&node, &scope, b"needle");
        assert_eq!(report.index.generation, second);
        assert_eq!(report.index.indexed_documents, 0);
        assert_eq!(report.index.non_regular_entries, excluded);
        assert!(report.index.results.complete && report.index.results.hits.is_empty());
    }
    node.shutdown().unwrap();
}

#[test]
fn forge_only_publication_refreshes_scoped_source_stamps_without_rebuilding_blobs() {
    let root = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let config = root.config(format);
    let (node, commit) = fixture(&root, format);
    let scope = coverage(&[b"dir"]);
    let first = build(&node, &scope, None);
    let original = search(&node, &scope, b"needle");
    let credentials_path = root.0.join("credentials");
    credentials(&node, &credentials_path);
    let server = Server::start(node, &credentials_path, 1, true, true);
    let body = b"expected_version=0&title=Scoped+refresh&body=";
    let response = exchange(&server.client, &request(
        &server.client, "/api/v1/issues/1/open", 'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: scoped-forge-only\r\n", body.len()), body,
    ), true);
    status(&response, 200);
    assert_eq!(server.finish().accepted_sessions(), 1);
    let node = reopen(&config);
    let before = generation(&node);
    // The old exact source token must not be silently relaxed during refresh.
    assert!(node.runtime().block_on(node.refresh_scoped_source_index_local_in(
        &node.outbox_delivery_context(), &reference(), &scope,
        Some(original.index.source.source_head), Some(commit), first.generation_id,
        Default::default(), Default::default(),
    )).is_err());
    let (source, second, stats) = refresh(&node, &scope, &first, Default::default()).unwrap();
    assert_eq!(source.commit, commit);
    assert_eq!(source.tree, original.index.source.tree);
    assert_ne!(source.source_head, original.index.source.source_head);
    assert_eq!((stats.reused_documents, stats.rebuilt_documents, stats.rebuilt_source_bytes), (1, 0, 0));
    let refreshed = search(&node, &scope, b"needle");
    assert_eq!(refreshed.index.generation, second);
    assert_eq!(refreshed.index.results, original.index.results);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
