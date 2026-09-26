#![forbid(unsafe_code)]
//! Actual OneNode, native Git objects, persisted FrankenSQLite generations and
//! authenticated HTTP issue writes. No substitute authority or lexical engine.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::source_browse::SourceBrowseError;
use fgit_forge::source_search::SearchLimits;
use fgit_graph::GenerationActivation;
use fgit_graph::lexical::{IndexError, LexicalChannel, LexicalError, LexicalQuery};
use fgit_node::source_retrieval::current_index::{
    RevalidatedIndexReport, RevalidatedIndexRequest,
};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
use std::fs;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn query() -> LexicalQuery {
    LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap()
}
fn build(node: &OneNode, predecessor: Option<&GenerationActivation>) -> GenerationActivation {
    node.runtime()
        .block_on(node.build_source_index_local_in(
            &node.request_context(), &reference(), None, None,
            predecessor.map(|p| p.generation_id), SearchLimits::default(),
        ))
        .unwrap()
        .1
}
fn search(node: &OneNode) -> Result<RevalidatedIndexReport, NodeWorkspaceRefusal> {
    node.runtime().block_on(node.search_source_index_revalidated_local_in(
        &node.request_context(), RevalidatedIndexRequest::new(&reference(), &query()),
    ))
}
fn issue_write(node: OneNode, root: &Scratch) -> OneNode {
    let format = search(&node).unwrap().current_source().namespace.object_format;
    let config = root.config(format);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, true);
    let body = b"expected_version=0&title=Metadata+only&body=";
    let response = exchange(
        &server.client,
        &request(
            &server.client, "/api/v1/issues/1/open", 'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: revalidated-index-issue\r\n",
                body.len(),
            ), body,
        ), true,
    );
    status(&response, 200);
    assert_eq!(server.finish().accepted_sessions(), 1);
    reopen(&config)
}

#[test]
fn metadata_write_keeps_search_usable_without_rebuilding_or_relabelling_evidence() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let activation = build(&node, None);
        let before = search(&node).unwrap();
        assert!(!before.has_distinct_provenance());
        assert_eq!(before.index().results.hits.len(), 4);
        let node = issue_write(node, &root);
        let authority_before_read = generation(&node);
        let after = search(&node).unwrap();
        assert!(after.has_distinct_provenance());
        assert_ne!(after.current_source().source_head, before.current_source().source_head);
        assert_ne!(after.current_source().forge_position_root, before.current_source().forge_position_root);
        assert_eq!(after.current_source().commit, commit);
        assert_eq!(after.current_source().tree, before.current_source().tree);
        assert_eq!(after.index().source, before.index().source);
        assert_eq!(after.index().generation, activation);
        assert_eq!(after.index().selected_generation_head, activation);
        assert_eq!(after.index().results, before.index().results);
        assert_eq!(generation(&node), authority_before_read);
        // Keep the original exact-snapshot contract; it must still refuse.
        assert!(matches!(
            node.runtime().block_on(node.search_source_index_local_in(
                &node.request_context(), &reference(), None, None, None, None,
                &query(), None, Default::default(), Default::default(),
            )),
            Err(NodeWorkspaceRefusal::SourceIndexStale)
        ));
        node.shutdown().unwrap();
        let node = reopen(&config);
        let reopened = search(&node).unwrap();
        assert_eq!(reopened.current_source(), after.current_source());
        assert_eq!(reopened.index().source, before.index().source);
        assert_eq!(reopened.index().generation, activation);
        assert_eq!(reopened.index().results, after.index().results);
        node.shutdown().unwrap();
    }
}

#[test]
fn pages_pin_current_source_and_original_generation_even_after_new_index_activation() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let first = build(&node, None);
    let node = issue_write(node, &root);
    let reference = reference();
    let query = query();
    let mut options = RevalidatedIndexRequest::new(&reference, &query);
    options.generation = Some(&first);
    options.query_limits.max_results = 2;
    let page = node.runtime().block_on(node.search_source_index_revalidated_local_in(
        &node.request_context(), options.clone(),
    )).unwrap();
    assert!(!page.index().results.complete);
    let second = build(&node, Some(&first));
    options.expected_head = Some(page.current_source().source_head);
    options.expected_commit = Some(page.current_source().commit);
    options.minimum = Some(&second);
    options.after = page.index().results.next_after;
    let next = node.runtime().block_on(node.search_source_index_revalidated_local_in(
        &node.request_context(), options,
    )).unwrap();
    assert_eq!(next.index().generation, first);
    assert_eq!(next.index().selected_generation_head, second);
    assert_eq!(next.current_source(), page.current_source());
    assert_eq!(next.index().source, page.index().source);
    assert!(next.index().results.complete);
    let ids: Vec<_> = page.index().results.hits.iter()
        .chain(&next.index().results.hits).map(|h| h.document_id).collect();
    assert_eq!(ids, vec![1, 2, 3, 5]);
    node.shutdown().unwrap();
}

#[test]
fn stale_continuation_head_is_not_silently_rebased_after_metadata_change() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let activation = build(&node, None);
    let before = search(&node).unwrap();
    let node = issue_write(node, &root);
    let reference = reference();
    let query = query();
    let mut options = RevalidatedIndexRequest::new(&reference, &query);
    options.expected_head = Some(before.current_source().source_head);
    options.expected_commit = Some(before.current_source().commit);
    options.generation = Some(&activation);
    options.after = Some(2);
    assert!(matches!(
        node.runtime().block_on(node.search_source_index_revalidated_local_in(
            &node.request_context(), options,
        )),
        Err(NodeWorkspaceRefusal::SourceBrowse(error))
            if matches!(*error, SourceBrowseError::SnapshotMoved)
    ));
    assert!(search(&node).unwrap().has_distinct_provenance());
    node.shutdown().unwrap();
}

// Test-only native loose-object writer. The imported child is a real Git
// object, not a mutable ref map or an external Git subprocess.
fn advance_commit(root: &Scratch, node: &OneNode, parent: GitOid, tree: GitOid) -> GitOid {
    let body = format!(
        "tree {tree}\nparent {parent}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nchild\n"
    );
    let format = parent.algorithm();
    let child = git_object_id(format, GitObjectKind::Commit, body.as_bytes());
    let raw = [format!("commit {}\0", body.len()).as_bytes(), body.as_bytes()].concat();
    let size = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(size.to_le_bytes());
    encoded.extend((!size).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let git = root.0.join("git-source");
    let text = child.to_string();
    let directory = git.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&text[2..]), encoded).unwrap();
    fs::write(git.join("refs/heads/main"), format!("{child}\n")).unwrap();
    let result = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &node.request_context(), &git, OWNER, b"revalidated-index-child",
    )).unwrap();
    assert!(result.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
    child
}

#[test]
fn different_commit_with_even_the_same_tree_refuses_until_a_real_index_refresh() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, commit) = fixture(&root, format);
        let first = build(&node, None);
        let before = search(&node).unwrap();
        let child = advance_commit(&root, &node, commit, before.current_source().tree);
        assert!(matches!(search(&node), Err(NodeWorkspaceRefusal::SourceIndexStale)));
        let second = build(&node, Some(&first));
        let after = search(&node).unwrap();
        assert_eq!(after.current_source().commit, child);
        assert_eq!(after.index().generation, second);
        assert!(!after.has_distinct_provenance());
        assert_eq!(after.index().results, before.index().results);
        node.shutdown().unwrap();
    }
}

#[test]
fn missing_index_ref_and_insufficient_budgets_are_not_complete_empty_results() {
    let root = Scratch::new();
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    assert!(matches!(search(&node), Err(NodeWorkspaceRefusal::SourceIndex(error))
        if matches!(*error, IndexError::Uninitialized)));
    build(&node, None);
    let query = query();
    let missing = RefName::try_new(b"refs/heads/missing").unwrap();
    assert!(matches!(
        node.runtime().block_on(node.search_source_index_revalidated_local_in(
            &node.request_context(), RevalidatedIndexRequest::new(&missing, &query),
        )), Err(NodeWorkspaceRefusal::RefUnavailable)
    ));
    let reference = reference();
    let mut options = RevalidatedIndexRequest::new(&reference, &query);
    options.query_limits.max_work = 1;
    assert!(matches!(
        node.runtime().block_on(node.search_source_index_revalidated_local_in(
            &node.request_context(), options.clone(),
        )), Err(NodeWorkspaceRefusal::SourceIndex(error))
            if matches!(*error, IndexError::Lexical(LexicalError::Limit("query work")))
    ));
    options.query_limits = Default::default();
    options.read_limits.max_payload_bytes = 1;
    assert!(node.runtime().block_on(node.search_source_index_revalidated_local_in(
        &node.request_context(), options,
    )).is_err());
    assert_eq!(search(&node).unwrap().index().results.hits.len(), 4);
    node.shutdown().unwrap();
}

#[test]
fn continuation_requires_all_pins_and_rejects_wrong_native_domain() {
    let root = Scratch::new();
    let (node, commit) = fixture(&root, GitHashAlgorithm::Sha1);
    let activation = build(&node, None);
    let first = search(&node).unwrap();
    let reference = reference();
    let query = query();
    let mut complete = RevalidatedIndexRequest::new(&reference, &query);
    complete.expected_head = Some(first.current_source().source_head);
    complete.expected_commit = Some(commit);
    complete.generation = Some(&activation);
    complete.after = Some(2);
    for absent in 0..3 {
        let mut options = complete.clone();
        match absent {
            0 => options.expected_head = None,
            1 => options.expected_commit = None,
            _ => options.generation = None,
        }
        assert!(matches!(
            node.runtime().block_on(node.search_source_index_revalidated_local_in(
                &node.request_context(), options,
            )), Err(NodeWorkspaceRefusal::SourceIndex(error))
                if matches!(*error, IndexError::Lexical(LexicalError::Invalid(_)))
        ));
    }
    assert!(node.runtime().block_on(node.search_source_index_revalidated_local_in(
        &node.request_context(), complete.clone(),
    )).is_ok());
    complete.expected_commit = Some(GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap());
    assert!(matches!(
        node.runtime().block_on(node.search_source_index_revalidated_local_in(
            &node.request_context(), complete,
        )), Err(NodeWorkspaceRefusal::ObjectFormatMismatch)
    ));
    node.shutdown().unwrap();
}
