#![forbid(unsafe_code)]
//! Native source edits and refresh through the actual node, TreeFS, index,
//! file-backed authority and existing HTTP listener. No replacement searcher.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use fgit_forge::patch::PatchLimits;
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_search::SearchLimits;
use fgit_graph::{GenerationActivation, GenerationRecovery, GraphGenerationId};
use fgit_graph::lexical::{IndexedLexicalReport, LexicalChannel, LexicalQuery,
    LexicalReadLimits, LexicalRefreshStats, LexicalSource};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};

fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn build(node: &OneNode, predecessor: Option<GraphGenerationId>) -> GenerationActivation {
    node.runtime().block_on(node.build_source_index_local_in(&node.request_context(), &reference(),
        None, None, predecessor, Default::default())).unwrap().1
}
fn refresh(node: &OneNode, predecessor: &GenerationActivation, limits: SearchLimits)
    -> Result<(LexicalSource, GenerationActivation, LexicalRefreshStats), NodeWorkspaceRefusal>
{
    node.runtime().block_on(node.refresh_source_index_local_in(&node.request_context(), &reference(),
        None, None, predecessor.generation_id, limits, Default::default()))
}
fn query(node: &OneNode, channel: LexicalChannel, word: &[u8]) -> IndexedLexicalReport {
    let query = LexicalQuery::new(channel, &[word.to_vec()], &[]).unwrap();
    node.runtime().block_on(node.search_source_index_local_in(&node.request_context(), &reference(),
        None, None, None, None, &query, None, Default::default(), Default::default())).unwrap()
}
fn edit(node: &OneNode, base: GitOid, patch: &[u8], key: &[u8]) -> GitOid {
    let context = node.request_context();
    let metadata = MergeMetadata { author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(), timestamp: 2, message: b"index refresh fixture\n".to_vec() };
    let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(&context, &reference(), base,
        [0xe4;16], patch, &metadata, PatchLimits::default())).unwrap();
    let terminal = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&context, OWNER, key,
        &reference(), base, candidate.candidate_commit, candidate.bundle_bytes())).unwrap();
    assert!(terminal.commands.iter().all(|r| matches!(r.terminal.outcome, DecisionOutcome::Committed { .. })));
    candidate.candidate_commit
}

#[test]
fn same_tree_reuses_every_blob_and_survives_reopen_without_repository_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, commit) = fixture(&root, format); let before = generation(&node);
        let first = build(&node, None); let old = query(&node, LexicalChannel::Content, b"needle");
        let (source, second, stats) = refresh(&node, &first, SearchLimits { max_matches: 1, ..Default::default() }).unwrap();
        assert_eq!(source, old.source); assert_eq!(source.commit, commit);
        assert_eq!((stats.reused_documents, stats.rebuilt_documents), (5, 0));
        assert_eq!(stats.reused_source_bytes, old.indexed_source_bytes);
        assert_eq!(stats.rebuilt_source_bytes, 0); assert_eq!(stats.prior_documents_not_reused, 0);
        assert!(stats.previous_payload_bytes_read > 0); assert!(stats.previous_generation_bytes_read > 0);
        let after = query(&node, LexicalChannel::Content, b"needle");
        assert_eq!(after.results, old.results); assert_eq!(after.generation, second);
        assert_eq!(after.non_regular_entries, 2); assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
        let node = reopen(&config);
        assert_eq!(query(&node, LexicalChannel::Content, b"needle").results, after.results);
        let third = refresh(&node, &second, Default::default()).unwrap();
        assert_eq!(third.2.reused_documents, 5); assert_eq!(third.2.rebuilt_documents, 0);
        assert_eq!(generation(&node), before); node.shutdown().unwrap();
    }
}

#[test]
fn actual_insert_delete_replace_rename_refresh_matches_full_rebuild_in_both_formats() {
    let patch = b"diff --git a/00-new.txt b/00-new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/00-new.txt\n@@ -0,0 +1 @@\n+novel\ndiff --git a/empty b/empty\ndeleted file mode 100644\ndiff --git a/run b/run\n--- a/run\n+++ b/run\n@@ -1,2 +1,2 @@\n #!/bin/sh\n-needle\n+changed\ndiff --git a/dir/nested.txt b/moved.txt\nsimilarity index 100%\nrename from dir/nested.txt\nrename to moved.txt\n";
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, base) = fixture(&root, format);
        let first = build(&node, None); let commit = edit(&node, base, patch, b"refresh-source-edit");
        let before = generation(&node);
        let (source, second, stats) = refresh(&node, &first, Default::default()).unwrap();
        assert_eq!(source.commit, commit);
        assert_eq!((stats.reused_documents, stats.rebuilt_documents, stats.prior_documents_not_reused), (2, 3, 3));
        assert_eq!(stats.reused_source_bytes, TEXT.len() + BINARY.len());
        assert_eq!(stats.rebuilt_source_bytes, b"novel\n".len() + b"needle in nested\n".len() + b"#!/bin/sh\nchanged\n".len());
        let indexed = query(&node, LexicalChannel::Content, b"needle");
        assert_eq!(indexed.results.hits.iter().map(|h| h.path.as_slice()).collect::<Vec<_>>(),
            vec![b"alpha.txt".as_slice(), BINARY_PATH, b"moved.txt"]);
        assert!(query(&node, LexicalChannel::Path, b"empty").results.hits.is_empty());
        assert!(query(&node, LexicalChannel::Path, b"dir").results.hits.is_empty());
        assert_eq!(query(&node, LexicalChannel::Content, b"novel").results.hits[0].document_id, 1);
        let full = build(&node, Some(second.generation_id));
        let rebuilt = query(&node, LexicalChannel::Content, b"needle");
        assert_eq!(rebuilt.generation, full); assert_eq!(rebuilt.source, source);
        assert_eq!(rebuilt.results, indexed.results); assert_eq!(rebuilt.indexed_documents, 5);
        assert_eq!(rebuilt.non_regular_entries, 2); assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn refresh_after_forge_only_write_restores_http_queries_without_reading_source_blobs() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node, commit) = fixture(&root, GitHashAlgorithm::Sha1); let first = build(&node, None);
    let original = query(&node, LexicalChannel::Content, b"needle");
    let path = root.0.join("credentials"); credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, true);
    let body = b"expected_version=0&title=Refresh+source&body=";
    let result = exchange(&server.client, &request(&server.client, "/api/v1/issues/1/open", 'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: refresh-forge-only\r\n", body.len()), body), true);
    status(&result, 200); assert_eq!(server.finish().accepted_sessions(), 1);
    let node = reopen(&config); let before = generation(&node);
    let (source, second, stats) = refresh(&node, &first, Default::default()).unwrap();
    assert_eq!(source.commit, commit); assert_eq!(source.tree, original.source.tree);
    assert_ne!(source.source_head, original.source.source_head);
    assert_eq!(stats.rebuilt_source_bytes, 0); assert_eq!(stats.reused_documents, 5);
    assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 1, true, false);
    let response = post(&server.client, "search-index", 'a',
        &(common(GitHashAlgorithm::Sha1) + "&term_hex=6e6565646c65"), true);
    status(&response, 200); assert_eq!(number(&response.body, "index_number"), second.authority_generation.get());
    assert_eq!(server.finish().accepted_sessions(), 1);
}

#[test]
fn source_and_index_resource_limits_apply_to_reused_rows_without_partial_publication() {
    let root = Scratch::new(); let (node, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let first = build(&node, None); let report = query(&node, LexicalChannel::Content, b"needle");
    let before = generation(&node);
    for limits in [SearchLimits { max_files: 4, ..Default::default() },
        SearchLimits { max_file_bytes: 1, ..Default::default() },
        SearchLimits { max_total_bytes: report.indexed_source_bytes - 1, ..Default::default() }] {
        assert!(refresh(&node, &first, limits).is_err());
        assert_eq!(query(&node, LexicalChannel::Content, b"needle").generation, first);
    }
    assert!(node.runtime().block_on(node.refresh_source_index_local_in(&node.request_context(), &reference(),
        None, None, first.generation_id, Default::default(),
        LexicalReadLimits { max_payload_bytes: 1, ..Default::default() })).is_err());
    assert_eq!(query(&node, LexicalChannel::Content, b"needle").generation, first);
    let exact = refresh(&node, &first, SearchLimits { max_total_bytes: report.indexed_source_bytes, ..Default::default() }).unwrap();
    assert_eq!(exact.2.reused_source_bytes, report.indexed_source_bytes);
    assert_eq!(generation(&node), before); node.shutdown().unwrap();
}

#[test]
fn bad_source_pins_missing_refs_stale_predecessors_and_cancelled_requests_do_not_refresh() {
    let root = Scratch::new(); let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let first = build(&node, None); let second = refresh(&node, &first, Default::default()).unwrap().1;
    assert!(refresh(&node, &first, Default::default()).is_err());
    let missing = RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(matches!(node.runtime().block_on(node.refresh_source_index_local_in(&node.request_context(), &missing,
        None, None, second.generation_id, Default::default(), Default::default())), Err(NodeWorkspaceRefusal::RefUnavailable)));
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let wrong = GitOid::from_hex(format, &"a".repeat(format.digest_len()*2)).unwrap();
        assert!(node.runtime().block_on(node.refresh_source_index_local_in(&node.request_context(), &reference(),
            None, Some(wrong), second.generation_id, Default::default(), Default::default())).is_err());
    }
    let context = node.request_context(); context.cancel();
    assert!(node.runtime().block_on(node.refresh_source_index_local_in(&context, &reference(),
        None, None, second.generation_id, Default::default(), Default::default())).is_err());
    let context = node.request_context();
    drop(node.refresh_source_index_local_in(&context, &reference(), None, None,
        second.generation_id, Default::default(), Default::default()));
    assert_eq!(query(&node, LexicalChannel::Content, b"needle").generation, second);
    node.shutdown().unwrap();
}

#[test]
fn refreshed_generation_continuation_and_original_candidate_recovery_remain_exact() {
    let root = Scratch::new(); let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let first = build(&node, None); let q = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
    let page = node.runtime().block_on(node.search_source_index_local_in(&node.request_context(), &reference(),
        None, None, Some(&first), None, &q, None,
        fgit_graph::lexical::LexicalQueryLimits { max_results: 2, ..Default::default() }, Default::default())).unwrap();
    let second = refresh(&node, &first, Default::default()).unwrap().1;
    let continued = node.runtime().block_on(node.search_source_index_local_in(&node.request_context(), &reference(),
        Some(page.source.source_head), Some(page.source.commit), Some(&first), Some(&second), &q,
        page.results.next_after, Default::default(), Default::default())).unwrap();
    assert_eq!(continued.generation, first); assert_eq!(continued.selected_generation_head, second);
    assert_eq!(continued.results.hits.iter().map(|h| h.document_id).collect::<Vec<_>>(), vec![3,5]);
    // The activation's receipt may be discarded; its identity still resolves
    // through persisted history. This is not an injected database crash.
    let observed = node.runtime().block_on(node.recover_source_index_local_in(&node.request_context(), &reference(),
        second.generation_id, None, Default::default())).unwrap();
    assert!(matches!(observed, GenerationRecovery::Active { .. }));
    let third = refresh(&node, &second, Default::default()).unwrap().1;
    let observed = node.runtime().block_on(node.recover_source_index_local_in(&node.request_context(), &reference(),
        second.generation_id, Some(&third), Default::default())).unwrap();
    assert!(matches!(observed, GenerationRecovery::Superseded { activation, .. } if activation == second));
    node.shutdown().unwrap();
}

#[test]
fn mode_only_changes_reuse_postings_but_rename_is_a_fresh_path() {
    let root = Scratch::new(); let (node, base) = fixture(&root, GitHashAlgorithm::Sha256);
    let first = build(&node, None);
    let commit = edit(&node, base, b"diff --git a/run b/run\nold mode 100755\nnew mode 100644\n", b"refresh-mode");
    let (_, second, stats) = refresh(&node, &first, Default::default()).unwrap();
    assert_eq!(stats.reused_documents, 5); assert_eq!(stats.rebuilt_documents, 0);
    edit(&node, commit, b"diff --git a/run b/renamed\nsimilarity index 100%\nrename from run\nrename to renamed\n", b"refresh-rename");
    let (_, _, stats) = refresh(&node, &second, Default::default()).unwrap();
    assert_eq!(stats.reused_documents, 4); assert_eq!(stats.rebuilt_documents, 1);
    assert!(query(&node, LexicalChannel::Path, b"run").results.hits.is_empty());
    assert_eq!(query(&node, LexicalChannel::Path, b"renamed").results.hits.len(), 1);
    node.shutdown().unwrap();
}

#[test]
fn unsupported_new_source_keeps_the_old_generation_and_does_not_omit_the_file() {
    let root = Scratch::new(); let (node, base) = fixture(&root, GitHashAlgorithm::Sha1);
    let first = build(&node, None);
    let patch = format!("diff --git a/bad b/bad\nnew file mode 100644\n--- /dev/null\n+++ b/bad\n@@ -0,0 +1 @@\n+{}\n", "x".repeat(129));
    edit(&node, base, patch.as_bytes(), b"refresh-unsupported");
    let before = generation(&node);
    assert!(refresh(&node, &first, Default::default()).is_err());
    let observed = node.runtime().block_on(node.recover_source_index_local_in(&node.request_context(), &reference(),
        first.generation_id, None, Default::default())).unwrap();
    assert!(matches!(observed, GenerationRecovery::Active { .. }));
    assert_eq!(generation(&node), before); node.shutdown().unwrap();
}
