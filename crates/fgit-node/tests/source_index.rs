#![forbid(unsafe_code)]
//! Native imported Git trees, the actual OneNode object fabric, and persisted
//! FrankenSQLite generations. No replacement index/store or external Git.
#[path = "source_http/support.rs"]
mod support;
use fgit_forge::source_search::SearchLimits;
use fgit_graph::lexical::{
    IndexError, IndexedLexicalReport, LexicalChannel, LexicalQuery, LexicalQueryLimits,
    LexicalReadLimits,
};
use fgit_graph::{GenerationActivation, GenerationRecovery};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{GitHashAlgorithm, RefName};
use support::*;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn query(channel: LexicalChannel, terms: &[&[u8]], prefixes: &[Vec<u8>]) -> LexicalQuery {
    LexicalQuery::new(
        channel,
        &terms.iter().map(|s| s.to_vec()).collect::<Vec<_>>(),
        prefixes,
    )
    .unwrap()
}
fn search(
    node: &OneNode,
    query: &LexicalQuery,
) -> Result<IndexedLexicalReport, NodeWorkspaceRefusal> {
    node.runtime().block_on(node.search_source_index_local_in(
        &node.request_context(),
        &reference(),
        None,
        None,
        None,
        None,
        query,
        None,
        LexicalQueryLimits::default(),
        LexicalReadLimits::default(),
    ))
}
fn build(node: &OneNode, predecessor: Option<&GenerationActivation>) -> GenerationActivation {
    node.runtime()
        .block_on(node.build_source_index_local_in(
            &node.request_context(),
            &reference(),
            None,
            None,
            predecessor.map(|p| p.generation_id),
            SearchLimits::default(),
        ))
        .unwrap()
        .1
}

#[test]
fn native_index_uses_complete_verified_tree_and_survives_real_node_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let before = generation(&node);
        let q = query(LexicalChannel::Content, &[b"NEEDLE"], &[]);
        assert!(
            matches!(search(&node, &q), Err(NodeWorkspaceRefusal::SourceIndex(e)) if matches!(*e, IndexError::Uninitialized))
        );
        let (source, activation) = node
            .runtime()
            .block_on(node.build_source_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                Some(commit),
                None,
                SearchLimits {
                    max_matches: 1,
                    ..SearchLimits::default()
                },
            ))
            .unwrap();
        let report = search(&node, &q).unwrap();
        assert_eq!(report.source, source);
        assert_eq!(report.generation, activation);
        assert_eq!(report.source.commit, commit);
        assert_eq!(report.indexed_documents, 5);
        assert_eq!(report.non_regular_entries, 2);
        assert_eq!(report.results.hits.len(), 4);
        assert!(report.results.complete);
        assert_eq!(report.results.next_after, None);
        assert_eq!(
            report.indexed_source_bytes,
            TEXT.len() + BINARY.len() + b"needle in nested\n".len() + b"#!/bin/sh\nneedle\n".len()
        );
        assert_eq!(
            report
                .results
                .hits
                .iter()
                .map(|h| h.path.as_slice())
                .collect::<Vec<_>>(),
            vec![
                b"alpha.txt".as_slice(),
                BINARY_PATH,
                b"dir/nested.txt",
                b"run"
            ]
        );
        assert_eq!(
            report
                .results
                .hits
                .iter()
                .map(|h| h.spans[0].byte_offset)
                .collect::<Vec<_>>(),
            vec![0, 2, 0, 10]
        );
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
        let node = reopen(&config);
        let reopened = search(&node, &q).unwrap();
        assert_eq!(reopened.source, source);
        assert_eq!(reopened.generation, activation);
        assert_eq!(reopened.results, report.results);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn native_index_keeps_path_channel_binary_names_and_component_scope_exact() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha256);
    build(&node, None);
    let nested = search(
        &node,
        &query(
            LexicalChannel::Content,
            &[b"needle", b"NESTED"],
            &[b"dir".to_vec()],
        ),
    )
    .unwrap();
    assert_eq!(nested.results.hits.len(), 1);
    assert_eq!(nested.results.hits[0].path, b"dir/nested.txt");
    assert!(
        search(
            &node,
            &query(LexicalChannel::Content, &[b"needle"], &[b"di".to_vec()])
        )
        .unwrap()
        .results
        .hits
        .is_empty()
    );
    let names = search(&node, &query(LexicalChannel::Path, &[b"dat"], &[])).unwrap();
    assert_eq!(names.results.hits.len(), 1);
    assert_eq!(names.results.hits[0].path, BINARY_PATH);
    assert!(
        search(
            &node,
            &query(LexicalChannel::Content, &[b"outside", b"secret"], &[])
        )
        .unwrap()
        .results
        .hits
        .is_empty()
    );
    // Empty regular files are indexed in the path channel; non-regular entries are not.
    assert_eq!(
        search(&node, &query(LexicalChannel::Path, &[b"empty"], &[]))
            .unwrap()
            .results
            .hits
            .len(),
        1
    );
    assert!(
        search(&node, &query(LexicalChannel::Path, &[b"module"], &[]))
            .unwrap()
            .results
            .hits
            .is_empty()
    );
    node.shutdown().unwrap();
}

#[test]
fn native_continuation_keeps_exact_generation_across_new_same_source_activation() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let first = build(&node, None);
    let q = query(LexicalChannel::Content, &[b"needle"], &[]);
    let page = node
        .runtime()
        .block_on(node.search_source_index_local_in(
            &node.request_context(),
            &reference(),
            None,
            None,
            Some(&first),
            None,
            &q,
            None,
            LexicalQueryLimits {
                max_results: 2,
                ..Default::default()
            },
            Default::default(),
        ))
        .unwrap();
    assert!(!page.results.complete);
    assert_eq!(page.results.next_after, Some(2));
    let second = build(&node, Some(&first));
    assert_ne!(first, second);
    let next = node
        .runtime()
        .block_on(node.search_source_index_local_in(
            &node.request_context(),
            &reference(),
            Some(page.source.source_head),
            Some(page.source.commit),
            Some(&first),
            Some(&second),
            &q,
            page.results.next_after,
            LexicalQueryLimits {
                max_results: 2,
                ..Default::default()
            },
            Default::default(),
        ))
        .unwrap();
    assert_eq!(next.generation, first);
    assert_eq!(next.selected_generation_head, second);
    assert!(next.results.complete);
    assert_eq!(next.results.next_after, None);
    let ids: Vec<_> = page
        .results
        .hits
        .iter()
        .chain(&next.results.hits)
        .map(|h| h.document_id)
        .collect();
    assert_eq!(ids, vec![1, 2, 3, 5]);
    assert!(
        node.runtime()
            .block_on(node.search_source_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                None,
                None,
                &q,
                Some(2),
                Default::default(),
                Default::default()
            ))
            .is_err()
    );
    node.shutdown().unwrap();
}

#[test]
fn failed_build_does_not_publish_a_partial_index_or_move_repository_authority() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let before = generation(&node);
    let q = query(LexicalChannel::Content, &[b"needle"], &[]);
    let failed = node.runtime().block_on(node.build_source_index_local_in(
        &node.request_context(),
        &reference(),
        None,
        None,
        None,
        SearchLimits {
            max_files: 1,
            ..Default::default()
        },
    ));
    assert!(matches!(failed, Err(NodeWorkspaceRefusal::SourceSearch(_))));
    assert!(
        matches!(search(&node, &q), Err(NodeWorkspaceRefusal::SourceIndex(e)) if matches!(*e, IndexError::Uninitialized))
    );
    let good = build(&node, None);
    assert!(
        node.runtime()
            .block_on(node.build_source_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                Some(good.generation_id),
                SearchLimits {
                    max_total_bytes: 1,
                    ..Default::default()
                }
            ))
            .is_err()
    );
    assert_eq!(search(&node, &q).unwrap().generation, good);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn original_candidate_recovery_distinguishes_active_and_superseded_without_republishing() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let before = generation(&node);
    let first = build(&node, None);
    // Same source/predecessor produces the original candidate, but cannot activate twice.
    let error = node
        .runtime()
        .block_on(node.build_source_index_local_in(
            &node.request_context(),
            &reference(),
            None,
            None,
            None,
            SearchLimits::default(),
        ))
        .unwrap_err();
    let NodeWorkspaceRefusal::SourceIndexPublication { candidate, .. } = error else {
        panic!("publication boundary required");
    };
    assert_eq!(candidate, first.generation_id);
    let recovered = node
        .runtime()
        .block_on(node.recover_source_index_local_in(
            &node.request_context(),
            &reference(),
            candidate,
            None,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(recovered, GenerationRecovery::Active { .. }));
    let second = build(&node, Some(&first));
    let recovered = node
        .runtime()
        .block_on(node.recover_source_index_local_in(
            &node.request_context(),
            &reference(),
            candidate,
            Some(&second),
            Default::default(),
        ))
        .unwrap();
    assert!(
        matches!(recovered, GenerationRecovery::Superseded { activation, .. } if activation == first)
    );
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn forge_write_invalidates_old_index_even_when_the_git_commit_has_not_changed() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, commit) = fixture(&root, GitHashAlgorithm::Sha1);
    let first = build(&node, None);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, true);
    let body = b"expected_version=0&title=Indexed+source+changed&body=";
    let written = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/issues/1/open",
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: index-intervening-issue\r\n",
                body.len()
            ),
            body,
        ),
        true,
    );
    status(&written, 200);
    assert_eq!(server.finish().accepted_sessions(), 1);
    let node = reopen(&config);
    let q = query(LexicalChannel::Content, &[b"needle"], &[]);
    assert!(matches!(
        search(&node, &q),
        Err(NodeWorkspaceRefusal::SourceIndexStale)
    ));
    let second = build(&node, Some(&first));
    let current = search(&node, &q).unwrap();
    assert_eq!(current.generation, second);
    assert_eq!(current.source.commit, commit);
    assert!(
        node.runtime()
            .block_on(node.search_source_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                Some(commit),
                Some(&first),
                None,
                &q,
                None,
                Default::default(),
                Default::default()
            ))
            .is_err()
    );
    node.shutdown().unwrap();
}

#[test]
fn invalid_source_pins_and_missing_refs_cannot_build_or_disclose_an_index() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let missing = RefName::try_new(b"refs/heads/unavailable").unwrap();
    assert!(matches!(
        node.runtime().block_on(node.build_source_index_local_in(
            &node.request_context(),
            &missing,
            None,
            None,
            None,
            Default::default()
        )),
        Err(NodeWorkspaceRefusal::RefUnavailable)
    ));
    let foreign = fgit_types::GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap();
    assert!(matches!(
        node.runtime().block_on(node.build_source_index_local_in(
            &node.request_context(),
            &reference(),
            None,
            Some(foreign),
            None,
            Default::default()
        )),
        Err(NodeWorkspaceRefusal::ObjectFormatMismatch)
    ));
    build(&node, None);
    assert!(
        node.runtime()
            .block_on(node.search_source_index_local_in(
                &node.request_context(),
                &missing,
                None,
                None,
                None,
                None,
                &query(LexicalChannel::Content, &[b"needle"], &[]),
                None,
                Default::default(),
                Default::default()
            ))
            .is_err()
    );
    node.shutdown().unwrap();
}
