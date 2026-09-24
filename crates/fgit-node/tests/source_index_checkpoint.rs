#![forbid(unsafe_code)]
//! Native publication barriers against imported objects and the file-backed
//! node. These tests do not substitute a matcher, index, or authority backend.
#[path = "source_http/support.rs"]
mod support;
use fgit_forge::source_search::SearchLimits;
use fgit_graph::lexical::{IndexError, LexicalChannel, LexicalQuery};
use fgit_graph::{GenerationActivation, GenerationRecovery, GraphGenerationId};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{GitHashAlgorithm, RefName};
use support::*;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
const fn refusal() -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::WorkspaceCapacity
}
fn selected(node: &OneNode) -> Result<GenerationActivation, NodeWorkspaceRefusal> {
    let q = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
    node.runtime()
        .block_on(node.search_source_index_local_in(
            &node.request_context(),
            &reference(),
            None,
            None,
            None,
            None,
            &q,
            None,
            Default::default(),
            Default::default(),
        ))
        .map(|r| r.generation)
}
fn record(path: &std::path::Path, id: GraphGenerationId) {
    use std::io::Write;
    let mut file = std::fs::File::create(path).unwrap();
    file.write_all(id.as_internal_object_id().digest().as_bytes())
        .unwrap();
    file.sync_all().unwrap();
}

#[test]
fn rejected_build_barrier_retains_original_identity_without_activating() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, _) = fixture(&root, format);
        let before = generation(&node);
        let mut saved = None;
        let failed = node
            .runtime()
            .block_on(node.build_source_index_guarded_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                None,
                Default::default(),
                &mut |id| {
                    assert!(saved.replace(id).is_none());
                    Err(refusal())
                },
            ));
        assert!(matches!(
            failed,
            Err(NodeWorkspaceRefusal::WorkspaceCapacity)
        ));
        let candidate = saved.unwrap();
        assert!(
            matches!(selected(&node), Err(NodeWorkspaceRefusal::SourceIndex(e))
            if matches!(*e, IndexError::Uninitialized))
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.recover_source_index_local_in(
                    &node.request_context(),
                    &reference(),
                    candidate,
                    None,
                    Default::default()
                ))
                .unwrap(),
            GenerationRecovery::Uninitialized
        ));
        // A fresh same-source attempt derives the exact candidate handed to the barrier.
        let activation = node
            .runtime()
            .block_on(node.build_source_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                None,
                Default::default(),
            ))
            .unwrap()
            .1;
        assert_eq!(activation.generation_id, candidate);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn confirmed_build_is_recoverable_from_only_the_prepublication_record_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, _) = fixture(&root, format);
        let path = root.0.join("candidate");
        let mut saved = None;
        let result = node
            .runtime()
            .block_on(node.build_source_index_guarded_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                None,
                Default::default(),
                &mut |id| {
                    record(&path, id);
                    saved = Some(id);
                    Ok(())
                },
            ));
        assert!(result.is_ok());
        drop(result); // Caller loses the returned activation.
        let candidate = saved.unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            candidate.as_internal_object_id().digest().as_bytes()
        );
        node.shutdown().unwrap();
        let node = reopen(&config);
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
        assert!(matches!(recovered, GenerationRecovery::Active { selected }
            if selected.activation().generation_id == candidate));
        node.shutdown().unwrap();
    }
}

#[test]
fn callback_cancellation_cannot_turn_a_recorded_candidate_into_an_unknown_identity() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let request = node.request_context();
    let mut saved = None;
    let error = node
        .runtime()
        .block_on(node.build_source_index_guarded_local_in(
            &request,
            &reference(),
            None,
            None,
            None,
            Default::default(),
            &mut |id| {
                saved = Some(id);
                request.cancel();
                Ok(())
            },
        ))
        .unwrap_err();
    assert!(
        matches!(error, NodeWorkspaceRefusal::SourceIndexPublication { candidate, .. }
        if Some(candidate) == saved)
    );
    assert!(
        matches!(selected(&node), Err(NodeWorkspaceRefusal::SourceIndex(e))
        if matches!(*e, IndexError::Uninitialized))
    );
    node.shutdown().unwrap();
}

#[test]
fn refresh_barrier_is_once_before_publication_and_noop_reconcile_does_not_call_it() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, _) = fixture(&root, format);
        let first = node
            .runtime()
            .block_on(node.build_source_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                None,
                Default::default(),
            ))
            .unwrap()
            .1;
        let mut saved = None;
        assert!(
            node.runtime()
                .block_on(node.refresh_source_index_guarded_local_in(
                    &node.request_context(),
                    &reference(),
                    None,
                    None,
                    first.generation_id,
                    Default::default(),
                    Default::default(),
                    &mut |id| {
                        saved = Some(id);
                        Err(refusal())
                    }
                ))
                .is_err()
        );
        assert_eq!(selected(&node).unwrap(), first);
        let mut calls = 0;
        let (_, second, stats) = node
            .runtime()
            .block_on(node.refresh_source_index_guarded_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                first.generation_id,
                Default::default(),
                Default::default(),
                &mut |id| {
                    calls += 1;
                    assert_eq!(Some(id), saved);
                    Ok(())
                },
            ))
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(stats.rebuilt_documents, 0);
        let current = node
            .runtime()
            .block_on(node.reconcile_source_index_guarded_local_in(
                &node.request_context(),
                &reference(),
                None,
                Some(&second),
                Default::default(),
                Default::default(),
                &mut |_| panic!("current metadata is a read-only no-op"),
            ))
            .unwrap();
        assert_eq!(current.1, second);
        node.shutdown().unwrap();
    }
}

#[test]
fn reconciliation_carries_the_barrier_through_genesis_and_stale_refresh() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let mut saved = None;
    let first = node
        .runtime()
        .block_on(node.reconcile_source_index_guarded_local_in(
            &node.request_context(),
            &reference(),
            None,
            None,
            Default::default(),
            Default::default(),
            &mut |id| {
                saved = Some(id);
                Ok(())
            },
        ))
        .unwrap()
        .1;
    assert_eq!(Some(first.generation_id), saved);
    let credentials_path = root.0.join("credentials");
    credentials(&node, &credentials_path);
    let server = Server::start(node, &credentials_path, 1, true, true);
    let body = b"expected_version=0&title=Guarded+refresh&body=";
    status(
        &exchange(
            &server.client,
            &request(
                &server.client,
                "/api/v1/issues/1/open",
                'b',
                &format!(
                    "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: barrier-issue\r\n",
                    body.len()
                ),
                body,
            ),
            true,
        ),
        200,
    );
    server.finish();
    let node = reopen(&config);
    saved = None;
    let result = node
        .runtime()
        .block_on(node.reconcile_source_index_guarded_local_in(
            &node.request_context(),
            &reference(),
            None,
            Some(&first),
            Default::default(),
            Default::default(),
            &mut |id| {
                saved = Some(id);
                Err(refusal())
            },
        ));
    assert!(matches!(
        result,
        Err(NodeWorkspaceRefusal::WorkspaceCapacity)
    ));
    assert!(saved.is_some());
    assert_ne!(saved, Some(first.generation_id));
    let (_, second) = node
        .runtime()
        .block_on(node.reconcile_source_index_guarded_local_in(
            &node.request_context(),
            &reference(),
            None,
            Some(&first),
            Default::default(),
            Default::default(),
            &mut |id| {
                assert_eq!(saved, Some(id));
                Ok(())
            },
        ))
        .unwrap();
    assert_eq!(Some(second.generation_id), saved);
    node.shutdown().unwrap();
}

#[test]
fn invalid_cancelled_unpolled_and_exhausted_preparations_do_not_enter_the_barrier() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let request = node.request_context();
    let reference = reference();
    let mut barrier =
        |_| -> Result<(), NodeWorkspaceRefusal> { panic!("preparation never completed") };
    let future = node.build_source_index_guarded_local_in(
        &request,
        &reference,
        None,
        None,
        None,
        Default::default(),
        &mut barrier,
    );
    drop(future);
    assert!(
        node.runtime()
            .block_on(node.build_source_index_guarded_local_in(
                &request,
                &reference,
                None,
                None,
                None,
                SearchLimits {
                    max_files: 1,
                    ..Default::default()
                },
                &mut barrier
            ))
            .is_err()
    );
    let missing = RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(
        node.runtime()
            .block_on(node.reconcile_source_index_guarded_local_in(
                &request,
                &missing,
                None,
                None,
                Default::default(),
                Default::default(),
                &mut barrier
            ))
            .is_err()
    );
    request.cancel();
    assert!(
        node.runtime()
            .block_on(node.build_source_index_guarded_local_in(
                &request,
                &reference,
                None,
                None,
                None,
                Default::default(),
                &mut barrier
            ))
            .is_err()
    );
    node.shutdown().unwrap();
}
