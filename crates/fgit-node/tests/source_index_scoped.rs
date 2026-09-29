#![forbid(unsafe_code)]
//! Native TreeFS enumeration and the existing Fsqlite-backed node, including
//! reopen and actual authenticated TCP metadata publication. No fake index.
#[path = "source_http/support.rs"]
mod support;
use fgit_forge::source_search::SearchLimits;
use fgit_graph::lexical::scoped::{LexicalScope, ScopedLexicalReport};
use fgit_graph::lexical::{
    IndexError, LexicalChannel, LexicalQuery, LexicalQueryLimits, LexicalSource,
};
use fgit_graph::{GenerationActivation, GenerationRecovery, GraphGenerationId};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use support::*;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn scope(paths: &[&[u8]]) -> LexicalScope {
    LexicalScope::new(&paths.iter().map(|p| p.to_vec()).collect::<Vec<_>>()).unwrap()
}
fn query() -> LexicalQuery {
    LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap()
}
fn build(
    node: &OneNode,
    scope: &LexicalScope,
    predecessor: Option<GraphGenerationId>,
    limits: SearchLimits,
) -> Result<(LexicalSource, GenerationActivation), NodeWorkspaceRefusal> {
    node.runtime()
        .block_on(node.build_scoped_source_index_local_in(
            &node.outbox_delivery_context(),
            &reference(),
            scope,
            None,
            None,
            predecessor,
            limits,
        ))
}
fn search(
    node: &OneNode,
    scope: &LexicalScope,
) -> Result<ScopedLexicalReport, NodeWorkspaceRefusal> {
    node.runtime()
        .block_on(node.search_scoped_source_index_local_in(
            &node.request_context(),
            &reference(),
            scope,
            None,
            None,
            None,
            None,
            &query(),
            None,
            Default::default(),
            Default::default(),
        ))
}

#[test]
fn out_of_scope_files_do_not_consume_blob_limits_or_initialize_the_full_index() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, commit) = fixture(&root, format);
        let before = generation(&node);
        let limits = SearchLimits {
            max_file_bytes: 1,
            max_total_bytes: 1,
            ..Default::default()
        };
        assert!(
            node.runtime()
                .block_on(node.build_source_index_local_in(
                    &node.outbox_delivery_context(),
                    &reference(),
                    None,
                    Some(commit),
                    None,
                    limits,
                ))
                .is_err()
        );
        // Only the empty file is selected. Every other regular file exceeds
        // these same limits. No out-of-scope blob may be opened as a fallback.
        let coverage = scope(&[b"empty"]);
        let (source, activation) = build(&node, &coverage, None, limits).unwrap();
        assert_eq!(source.commit, commit);
        assert_eq!(activation.authority_generation.get(), 1);
        let report = node
            .runtime()
            .block_on(node.search_scoped_source_index_local_in(
                &node.request_context(),
                &reference(),
                &coverage,
                None,
                None,
                None,
                None,
                &LexicalQuery::new(LexicalChannel::Path, &[b"empty".to_vec()], &[]).unwrap(),
                None,
                Default::default(),
                Default::default(),
            ))
            .unwrap();
        assert_eq!(report.scope, coverage);
        assert_eq!(report.index.indexed_documents, 1);
        assert_eq!(report.index.indexed_source_bytes, 0);
        assert_eq!(report.index.results.hits.len(), 1);
        assert_eq!(report.index.results.hits[0].content_bytes, 0);
        match node.runtime().block_on(node.search_source_index_local_in(
            &node.request_context(),
            &reference(),
            None,
            None,
            None,
            None,
            &query(),
            None,
            Default::default(),
            Default::default(),
        )) {
            Err(NodeWorkspaceRefusal::SourceIndex(error)) => {
                assert!(matches!(*error, IndexError::Uninitialized))
            }
            other => panic!("scoped build must not initialize full coverage: {other:?}"),
        }
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
#[test]
fn canonical_union_has_native_raw_path_order_and_survives_persisted_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let coverage = scope(&[b"dir/nested.txt", b"dir", BINARY_PATH, b"alpha.txt"]);
        let (source, activation) = build(&node, &coverage, None, Default::default()).unwrap();
        let first = search(&node, &coverage).unwrap();
        assert_eq!(
            first
                .index
                .results
                .hits
                .iter()
                .map(|h| h.path.as_slice())
                .collect::<Vec<_>>(),
            vec![b"alpha.txt".as_slice(), BINARY_PATH, b"dir/nested.txt"]
        );
        assert_eq!(
            first.index.indexed_source_bytes,
            TEXT.len() + BINARY.len() + b"needle in nested\n".len()
        );
        assert_eq!(first.index.non_regular_entries, 0);
        assert_eq!(first.index.source.commit, commit);
        assert_eq!(first.index.generation, activation);
        assert_eq!(first.index.source, source);
        node.shutdown().unwrap();
        let node = reopen(&config);
        let equivalent = scope(&[b"alpha.txt", BINARY_PATH, b"dir"]);
        let again = search(&node, &equivalent).unwrap();
        assert_eq!(again.scope, coverage);
        assert_eq!(again.index.results, first.index.results);
        assert_eq!(again.index.source, source);
        assert_eq!(again.index.generation, activation);
        node.shutdown().unwrap();
    }
}
#[test]
fn empty_and_non_regular_coverage_is_explicit_and_never_follows_links() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    for (paths, excluded) in [
        (&[b"absent".as_slice()][..], 0),
        (&[b"link".as_slice(), b"module"][..], 2),
    ] {
        let coverage = scope(paths);
        build(&node, &coverage, None, Default::default()).unwrap();
        let report = search(&node, &coverage).unwrap();
        assert!(report.index.results.complete && report.index.results.hits.is_empty());
        assert_eq!(report.index.indexed_documents, 0);
        assert_eq!(report.index.non_regular_entries, excluded);
        assert_eq!(report.scope, coverage);
    }
    node.shutdown().unwrap();
}
#[test]
fn separate_scopes_cannot_exchange_floors_or_continuations() {
    let root = Scratch::new();
    let (node, commit) = fixture(&root, GitHashAlgorithm::Sha256);
    let a = scope(&[b"alpha.txt", b"dir"]);
    let b = scope(&[b"run"]);
    let (source, first) = build(&node, &a, None, Default::default()).unwrap();
    let (_, other) = build(&node, &b, None, Default::default()).unwrap();
    assert_ne!(first.generation_id, other.generation_id);
    assert!(
        node.runtime()
            .block_on(node.search_scoped_source_index_local_in(
                &node.request_context(),
                &reference(),
                &a,
                None,
                None,
                None,
                Some(&other),
                &query(),
                None,
                Default::default(),
                Default::default(),
            ))
            .is_err()
    );
    let q = query();
    let one = node
        .runtime()
        .block_on(node.search_scoped_source_index_local_in(
            &node.request_context(),
            &reference(),
            &a,
            Some(source.source_head),
            Some(commit),
            Some(&first),
            None,
            &q,
            None,
            LexicalQueryLimits {
                max_results: 1,
                ..Default::default()
            },
            Default::default(),
        ))
        .unwrap();
    assert_eq!(one.index.results.next_after, Some(1));
    assert!(
        node.runtime()
            .block_on(node.search_scoped_source_index_local_in(
                &node.request_context(),
                &reference(),
                &a,
                None,
                None,
                Some(&first),
                None,
                &q,
                Some(1),
                Default::default(),
                Default::default(),
            ))
            .is_err()
    );
    let two = node
        .runtime()
        .block_on(node.search_scoped_source_index_local_in(
            &node.request_context(),
            &reference(),
            &a,
            Some(source.source_head),
            Some(commit),
            Some(&first),
            Some(&first),
            &q,
            Some(1),
            Default::default(),
            Default::default(),
        ))
        .unwrap();
    assert_eq!(two.index.results.hits[0].path.as_slice(), b"dir/nested.txt");
    assert!(two.index.results.complete);
    assert!(
        node.runtime()
            .block_on(node.search_scoped_source_index_local_in(
                &node.request_context(),
                &reference(),
                &b,
                Some(source.source_head),
                Some(commit),
                Some(&first),
                None,
                &q,
                Some(1),
                Default::default(),
                Default::default(),
            ))
            .is_err()
    );
    node.shutdown().unwrap();
}
#[test]
fn selected_oversized_files_refuse_before_the_candidate_barrier_and_keep_the_old_index() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let coverage = scope(&[b"alpha.txt"]);
    let (_, first) = build(&node, &coverage, None, Default::default()).unwrap();
    let mut armed = false;
    assert!(
        node.runtime()
            .block_on(node.build_scoped_source_index_guarded_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                &coverage,
                None,
                None,
                Some(first.generation_id),
                SearchLimits {
                    max_file_bytes: 1,
                    ..Default::default()
                },
                &mut |_| {
                    armed = true;
                    Ok(())
                },
            ))
            .is_err()
    );
    assert!(!armed);
    assert_eq!(search(&node, &coverage).unwrap().index.generation, first);
    let (_, second) = build(
        &node,
        &coverage,
        Some(first.generation_id),
        Default::default(),
    )
    .unwrap();
    assert!(second.authority_generation > first.authority_generation);
    node.shutdown().unwrap();
}
#[test]
fn guarded_publication_records_original_candidates_and_cancellation_never_infers_commit() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha256);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let before = generation(&node);
    let coverage = scope(&[b"dir"]);
    let mut candidate = None;
    let failed = node
        .runtime()
        .block_on(node.build_scoped_source_index_guarded_local_in(
            &node.outbox_delivery_context(),
            &reference(),
            &coverage,
            None,
            None,
            None,
            Default::default(),
            &mut |id| {
                candidate = Some(id);
                Err(NodeWorkspaceRefusal::RefUnavailable)
            },
        ));
    assert!(matches!(failed, Err(NodeWorkspaceRefusal::RefUnavailable)));
    let candidate = candidate.unwrap();
    assert!(search(&node, &coverage).is_err());
    let request = node.outbox_delivery_context();
    let failed = node
        .runtime()
        .block_on(node.build_scoped_source_index_guarded_local_in(
            &request,
            &reference(),
            &coverage,
            None,
            None,
            None,
            Default::default(),
            &mut |id| {
                assert_eq!(id, candidate);
                request.cancel();
                Ok(())
            },
        ));
    assert!(
        matches!(failed, Err(NodeWorkspaceRefusal::SourceIndexPublication { candidate: id, .. }) if id == candidate)
    );
    let (_, confirmed) = build(&node, &coverage, None, Default::default()).unwrap();
    assert_eq!(confirmed.generation_id, candidate);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
    let node = reopen(&config);
    assert!(matches!(
        node.runtime()
            .block_on(node.recover_scoped_source_index_local_in(
                &node.request_context(),
                &reference(),
                &coverage,
                candidate,
                Some(&confirmed),
                Default::default(),
            ))
            .unwrap(),
        GenerationRecovery::Active { .. }
    ));
    node.shutdown().unwrap();
}
#[test]
fn current_source_visibility_and_commit_pins_precede_scoped_index_disclosure() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let coverage = scope(&[b"dir"]);
    build(&node, &coverage, None, Default::default()).unwrap();
    let missing = RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(matches!(
        node.runtime()
            .block_on(node.search_scoped_source_index_local_in(
                &node.request_context(),
                &missing,
                &coverage,
                None,
                None,
                None,
                None,
                &query(),
                None,
                Default::default(),
                Default::default(),
            )),
        Err(NodeWorkspaceRefusal::RefUnavailable)
    ));
    let foreign = GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap();
    assert!(matches!(
        node.runtime()
            .block_on(node.search_scoped_source_index_local_in(
                &node.request_context(),
                &reference(),
                &coverage,
                None,
                Some(foreign),
                None,
                None,
                &query(),
                None,
                Default::default(),
                Default::default(),
            )),
        Err(NodeWorkspaceRefusal::ObjectFormatMismatch)
    ));
    let cancelled = node.request_context();
    cancelled.cancel();
    assert!(
        node.runtime()
            .block_on(node.search_scoped_source_index_local_in(
                &cancelled,
                &reference(),
                &coverage,
                None,
                None,
                None,
                None,
                &query(),
                None,
                Default::default(),
                Default::default(),
            ))
            .is_err()
    );
    node.shutdown().unwrap();
}
#[test]
fn metadata_changes_keep_scoped_reads_strict_until_an_explicit_rebuild() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, commit) = fixture(&root, format);
    let coverage = scope(&[b"dir"]);
    let (_, first) = build(&node, &coverage, None, Default::default()).unwrap();
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, true);
    let body = b"expected_version=0&title=Scoped+index+staleness&body=";
    let reply = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/issues/1/open",
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: scoped-index-metadata\r\n",
                body.len()
            ),
            body,
        ),
        true,
    );
    status(&reply, 200);
    assert!(reply.body.contains("\"outcome\":\"committed\""));
    server.finish();
    let node = reopen(&config);
    assert!(matches!(
        search(&node, &coverage),
        Err(NodeWorkspaceRefusal::SourceIndexStale)
    ));
    let (source, second) = build(
        &node,
        &coverage,
        Some(first.generation_id),
        Default::default(),
    )
    .unwrap();
    assert_eq!(source.commit, commit);
    assert_eq!(search(&node, &coverage).unwrap().index.generation, second);
    node.shutdown().unwrap();
}
