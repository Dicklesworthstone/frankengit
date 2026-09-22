#![forbid(unsafe_code)]
//! The actual node, native imported objects and file-backed index generations.
#[path = "source_http/support.rs"]
mod support;
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_search::SearchLimits;
use fgit_graph::lexical::{IndexError, LexicalChannel, LexicalQuery, LexicalSource};
use fgit_graph::{GenerationActivation, GenerationAuthorityError};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
use support::*;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn reconcile(
    node: &OneNode,
    minimum: Option<&GenerationActivation>,
) -> (LexicalSource, GenerationActivation) {
    node.runtime()
        .block_on(node.reconcile_source_index_local_in(
            &node.outbox_delivery_context(),
            &reference(),
            None,
            minimum,
            Default::default(),
            Default::default(),
        ))
        .unwrap()
}
fn search(
    node: &OneNode,
    term: &[u8],
) -> Result<fgit_graph::lexical::IndexedLexicalReport, NodeWorkspaceRefusal> {
    let query = LexicalQuery::new(LexicalChannel::Content, &[term.to_vec()], &[]).unwrap();
    node.runtime().block_on(node.search_source_index_local_in(
        &node.request_context(),
        &reference(),
        None,
        None,
        None,
        None,
        &query,
        None,
        Default::default(),
        Default::default(),
    ))
}
fn add_file(node: &OneNode, base: GitOid, word: &[u8]) -> GitOid {
    let patch = [b"diff --git a/added.txt b/added.txt\nnew file mode 100644\n--- /dev/null\n+++ b/added.txt\n@@ -0,0 +1 @@\n+".as_slice(), word, b"\n"].concat();
    let metadata = MergeMetadata {
        author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(),
        timestamp: 3,
        message: b"maintenance source change\n".to_vec(),
    };
    let request = node.request_context();
    let candidate = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            &reference(),
            base,
            [0x51; 16],
            &patch,
            &metadata,
            Default::default(),
        ))
        .unwrap();
    let terminal = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            OWNER,
            b"index-maintenance-source-change",
            &reference(),
            base,
            candidate.candidate_commit,
            candidate.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    candidate.candidate_commit
}

#[test]
fn reconcile_builds_genesis_then_remains_idempotent_across_reopen_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let canonical = generation(&node);
        let first = reconcile(&node, None);
        assert_eq!(first.0.commit, commit);
        assert_eq!(first.1.authority_generation.get(), 1);
        for _ in 0..4 {
            assert_eq!(reconcile(&node, Some(&first.1)), first);
        }
        assert_eq!(search(&node, b"needle").unwrap().results.hits.len(), 4);
        assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
        let node = reopen(&config);
        assert_eq!(reconcile(&node, Some(&first.1)), first);
        assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
    }
}

#[test]
fn reconcile_refreshes_actual_git_edits_without_a_caller_supplied_predecessor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, commit) = fixture(&root, format);
        let first = reconcile(&node, None);
        let new_commit = add_file(&node, commit, b"fresh_token");
        let canonical = generation(&node);
        assert!(matches!(
            search(&node, b"fresh_token"),
            Err(NodeWorkspaceRefusal::SourceIndexStale)
        ));
        let second = reconcile(&node, Some(&first.1));
        assert_eq!(second.0.commit, new_commit);
        assert!(
            first
                .1
                .authority_generation
                .is_immediate_predecessor_of(second.1.authority_generation)
        );
        let result = search(&node, b"fresh_token").unwrap();
        assert_eq!(result.results.hits.len(), 1);
        assert_eq!(result.results.hits[0].path, b"added.txt");
        assert_eq!(reconcile(&node, Some(&second.1)), second);
        assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
    }
}

#[test]
fn forge_only_write_is_reconciled_without_weakening_search_freshness() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, commit) = fixture(&root, GitHashAlgorithm::Sha1);
    let first = reconcile(&node, None);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, true);
    let body = b"expected_version=0&title=Maintenance&body=";
    let reply = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/issues/1/open",
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: maintenance-forge\r\n",
                body.len()
            ),
            body,
        ),
        true,
    );
    status(&reply, 200);
    assert_eq!(server.finish().accepted_sessions(), 1);
    let node = reopen(&config);
    let canonical = generation(&node);
    assert!(matches!(
        search(&node, b"needle"),
        Err(NodeWorkspaceRefusal::SourceIndexStale)
    ));
    let second = reconcile(&node, Some(&first.1));
    assert_eq!(second.0.commit, commit);
    assert_ne!(second.0.source_head, first.0.source_head);
    assert_eq!(search(&node, b"needle").unwrap().generation, second.1);
    assert_eq!(generation(&node), canonical);
    node.shutdown().unwrap();
}

#[test]
fn unresolved_checkpoint_never_turns_into_genesis_or_a_lower_current_selection() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let first = reconcile(&node, None);
    let mut higher = first.1.clone();
    higher.authority_generation = fgit_types::HeadGeneration::try_new(2).unwrap();
    let result = node
        .runtime()
        .block_on(node.reconcile_source_index_local_in(
            &node.request_context(),
            &reference(),
            None,
            Some(&higher),
            Default::default(),
            Default::default(),
        ));
    assert!(
        matches!(result, Err(NodeWorkspaceRefusal::SourceIndex(e)) if
        matches!(*e, IndexError::Generation(GenerationAuthorityError::CheckpointUnresolved)))
    );
    assert_eq!(reconcile(&node, Some(&first.1)), first);
    let fresh_root = Scratch::new();
    let (fresh_node, _) = fixture(&fresh_root, GitHashAlgorithm::Sha1);
    assert!(
        fresh_node
            .runtime()
            .block_on(fresh_node.reconcile_source_index_local_in(
                &fresh_node.request_context(),
                &reference(),
                None,
                Some(&first.1),
                Default::default(),
                Default::default()
            ))
            .is_err()
    );
    assert!(
        matches!(search(&fresh_node, b"needle"), Err(NodeWorkspaceRefusal::SourceIndex(e)) if matches!(*e, IndexError::Uninitialized))
    );
    fresh_node.shutdown().unwrap();
    let other = RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(matches!(
        node.runtime()
            .block_on(node.reconcile_source_index_local_in(
                &node.request_context(),
                &other,
                None,
                Some(&first.1),
                Default::default(),
                Default::default()
            )),
        Err(NodeWorkspaceRefusal::RefUnavailable)
    ));
    node.shutdown().unwrap();
}

#[test]
fn failed_build_and_failed_refresh_never_advance_the_index_or_canonical_history() {
    let root = Scratch::new();
    let (node, commit) = fixture(&root, GitHashAlgorithm::Sha256);
    let small = SearchLimits {
        max_files: 1,
        ..Default::default()
    };
    assert!(
        node.runtime()
            .block_on(node.reconcile_source_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                None,
                small,
                Default::default()
            ))
            .is_err()
    );
    assert!(
        matches!(search(&node, b"needle"), Err(NodeWorkspaceRefusal::SourceIndex(e)) if matches!(*e, IndexError::Uninitialized))
    );
    let first = reconcile(&node, None);
    add_file(&node, commit, b"fresh_token");
    let canonical = generation(&node);
    assert!(
        node.runtime()
            .block_on(node.reconcile_source_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                Some(&first.1),
                small,
                Default::default()
            ))
            .is_err()
    );
    let recovered = node
        .runtime()
        .block_on(node.recover_source_index_local_in(
            &node.request_context(),
            &reference(),
            first.1.generation_id,
            Some(&first.1),
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        recovered,
        fgit_graph::GenerationRecovery::Active { .. }
    ));
    assert_eq!(generation(&node), canonical);
    assert_eq!(
        reconcile(&node, Some(&first.1))
            .1
            .authority_generation
            .get(),
        2
    );
    node.shutdown().unwrap();
}

#[test]
fn stale_source_pin_cancellation_and_unpolled_work_never_publish() {
    let root = Scratch::new();
    let (node, commit) = fixture(&root, GitHashAlgorithm::Sha1);
    let context = node.request_context();
    let reference = reference();
    let future = node.reconcile_source_index_local_in(
        &context,
        &reference,
        None,
        None,
        Default::default(),
        Default::default(),
    );
    drop(future);
    assert!(
        matches!(search(&node, b"needle"), Err(NodeWorkspaceRefusal::SourceIndex(e)) if matches!(*e, IndexError::Uninitialized))
    );
    let first = reconcile(&node, None);
    add_file(&node, commit, b"fresh_token");
    let result = node
        .runtime()
        .block_on(node.reconcile_source_index_local_in(
            &context,
            &reference,
            Some(first.0.source_head),
            Some(&first.1),
            Default::default(),
            Default::default(),
        ));
    assert!(matches!(result, Err(NodeWorkspaceRefusal::SourceBrowse(_))));
    context.cancel();
    assert!(
        node.runtime()
            .block_on(node.reconcile_source_index_local_in(
                &context,
                &reference,
                None,
                Some(&first.1),
                Default::default(),
                Default::default()
            ))
            .is_err()
    );
    let canonical = generation(&node);
    let second = reconcile(&node, Some(&first.1));
    assert_eq!(second.1.authority_generation.get(), 2);
    assert_eq!(generation(&node), canonical);
    node.shutdown().unwrap();
}

#[test]
fn malformed_limits_are_rejected_even_when_the_index_is_already_current() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let first = reconcile(&node, None);
    let read = fgit_graph::lexical::LexicalReadLimits {
        max_payload_bytes: 0,
        ..Default::default()
    };
    assert!(
        node.runtime()
            .block_on(node.reconcile_source_index_local_in(
                &node.request_context(),
                &reference(),
                None,
                Some(&first.1),
                Default::default(),
                read
            ))
            .is_err()
    );
    assert_eq!(reconcile(&node, Some(&first.1)), first);
    node.shutdown().unwrap();
}
