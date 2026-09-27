#![forbid(unsafe_code)]
//! Native stored indexes, real metadata writes, reopen and TCP. Authored
//! regressions; executing these requires the full repository Rust toolchain.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use fgit_forge::patch::PatchLimits;
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_search::SearchLimits;
use fgit_forge::source_symbols::index::{self as data, AccessError};
use fgit_forge::source_symbols::{MAX_SYMBOL_WORK, SymbolMatchMode, SymbolQuery};
use fgit_graph::{GenerationActivation, GenerationAuthorityError};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, RefName};

type Failure = AccessError<NodeWorkspaceRefusal, GenerationAuthorityError>;
fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn query() -> SymbolQuery {
    SymbolQuery::new(b"Thing", SymbolMatchMode::Prefix, &[], &[], MAX_SYMBOL_WORK).unwrap()
}
fn add_file(node: &OneNode, base: GitOid, name: &str, key: &[u8]) -> GitOid {
    let patch = format!("diff --git a/{name} b/{name}\nnew file mode 100644\n--- /dev/null\n+++ b/{name}\n@@ -0,0 +1,2 @@\n+macro_rules! make {{ ($名:ident) => {{ fn Hidden() {{}} }}; }}\n+pub fn Thing() {{}}\n");
    let metadata = MergeMetadata {
        author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(),
        timestamp: 2,
        message: b"current symbol fixture\n".to_vec(),
    };
    let context = node.request_context();
    let prepared = node.runtime().block_on(node.prepare_trusted_patch_in(
        &context, &reference(), base, [0x77; 16], patch.as_bytes(), &metadata, PatchLimits::default(),
    )).unwrap();
    let result = node.runtime().block_on(node.apply_workspace_bundle_durable_in(
        &context, OWNER, key, &reference(), base, prepared.candidate_commit, prepared.bundle_bytes(),
    )).unwrap();
    assert!(!result.commands.is_empty());
    assert!(result.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
    prepared.candidate_commit
}
fn setup(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, data::Source, GenerationActivation) {
    let (node, base) = fixture(root, format);
    let tip = add_file(&node, base, "sample.rs", b"current-symbol-fixture");
    let (source, activation) = node.runtime().block_on(node.build_source_symbol_index_local_in(
        &node.outbox_delivery_context(), &reference(), None, Some(tip), None, Default::default(),
    )).unwrap();
    (node, source, activation)
}
fn current(node: &OneNode, floor: Option<&GenerationActivation>, bytes: usize) -> Result<(data::Source, data::Report), Failure> {
    node.runtime().block_on(node.search_source_symbols_index_revalidated_local_in(
        &node.request_context(), &reference(), None, None, floor, &query(), Default::default(), bytes,
    ))
}
fn issue(client: &Endpoint) -> Reply {
    let body = "expected_version=0&title=metadata&body=unchanged+Git+source";
    exchange(client, &request(client, "/api/v1/issues/1/open", 'b', &format!(
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: symbol-metadata\r\n", body.len(),
    ), body.as_bytes()), true)
}
fn metadata(node: OneNode, root: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let path = root.0.join("credentials"); credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, true);
    let written = issue(&server.client); status(&written, 200);
    assert!(written.body.contains("\"outcome\":\"committed\""));
    server.finish(); reopen(&root.config(format))
}

#[test]
fn metadata_only_writes_preserve_original_symbol_provenance_across_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, source, activation) = setup(&root, format);
        let (initial_current, initial) = current(&node, Some(&activation), data::MAX_INDEX_BYTES).unwrap();
        assert_eq!(initial_current, source); assert_eq!(initial.source, source);
        assert_eq!(initial.matches.len(), 1); assert_eq!(initial.matches[0].name, b"Thing");
        let before = generation(&node);
        let node = metadata(node, &root, format);
        assert_eq!(generation(&node), before + 1);
        assert!(matches!(node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(
            &node.request_context(), &reference(), None, None, Some(&activation), &query(), Default::default(), data::MAX_INDEX_BYTES,
        )), Err(AccessError::Stale)));
        let (selected, report) = current(&node, Some(&activation), data::MAX_INDEX_BYTES).unwrap();
        assert_ne!(selected.head, source.head); assert_ne!(selected.rcr, source.rcr);
        assert_eq!(selected.commit, source.commit); assert_eq!(selected.tree, source.tree);
        assert_eq!(report.source, source); assert_eq!(report.matches, initial.matches);
        assert_eq!(report.generation, initial.generation); assert_eq!(report.generation_number, initial.generation_number);
        assert_eq!(report.indexed_source_bytes, initial.indexed_source_bytes);
        assert_eq!(generation(&node), before + 1);
        node.shutdown().unwrap();
        let node = reopen(&root.config(format));
        let (again, report) = current(&node, Some(&activation), data::MAX_INDEX_BYTES).unwrap();
        assert_eq!(again, selected); assert_eq!(report.source, source);
        assert_eq!(generation(&node), before + 1); node.shutdown().unwrap();
    }
}

#[test]
fn changed_native_commit_refuses_reuse_without_rebuilding() {
    let root = Scratch::new(); let format = GitHashAlgorithm::Sha256;
    let (node, source, activation) = setup(&root, format);
    add_file(&node, source.commit, "extra.rs", b"current-symbol-changed");
    let before = generation(&node);
    assert!(matches!(current(&node, Some(&activation), data::MAX_INDEX_BYTES), Err(AccessError::Stale)));
    assert_eq!(generation(&node), before); node.shutdown().unwrap();
}

#[test]
fn current_pins_cancellation_and_generation_floors_are_not_replaced() {
    let root = Scratch::new(); let format = GitHashAlgorithm::Sha1;
    let (node, original, activation) = setup(&root, format);
    let node = metadata(node, &root, format);
    let before = generation(&node);
    let (selected, _) = current(&node, Some(&activation), data::MAX_INDEX_BYTES).unwrap();
    assert!(node.runtime().block_on(node.search_source_symbols_index_revalidated_local_in(
        &node.request_context(), &reference(), Some(original.head), Some(original.commit), Some(&activation), &query(), Default::default(), data::MAX_INDEX_BYTES,
    )).is_err());
    assert!(node.runtime().block_on(node.search_source_symbols_index_revalidated_local_in(
        &node.request_context(), &reference(), Some(selected.head), Some(selected.commit), Some(&activation), &query(), Default::default(), data::MAX_INDEX_BYTES,
    )).is_ok());
    let floor = GenerationActivation {
        generation_id: activation.generation_id,
        authority_generation: HeadGeneration::try_new(activation.authority_generation.get() + 1).unwrap(),
    };
    assert!(current(&node, Some(&floor), data::MAX_INDEX_BYTES).is_err());
    let cancelled = node.request_context(); cancelled.cancel();
    assert!(node.runtime().block_on(node.search_source_symbols_index_revalidated_local_in(
        &cancelled, &reference(), None, None, Some(&activation), &query(), Default::default(), data::MAX_INDEX_BYTES,
    )).is_err());
    assert_eq!(generation(&node), before); node.shutdown().unwrap();
}

#[test]
fn missing_indexes_and_existing_read_limits_never_trigger_fallback() {
    let root = Scratch::new(); let format = GitHashAlgorithm::Sha1;
    let (node, _) = fixture(&root, format);
    assert!(matches!(current(&node, None, data::MAX_INDEX_BYTES), Err(AccessError::Uninitialized)));
    node.shutdown().unwrap();
    let root = Scratch::new(); let (node, _, activation) = setup(&root, format);
    let (_, full) = current(&node, Some(&activation), data::MAX_INDEX_BYTES).unwrap();
    assert!(current(&node, Some(&activation), full.payload_bytes_read).is_ok());
    assert!(current(&node, Some(&activation), full.payload_bytes_read - 1).is_err());
    assert!(node.runtime().block_on(node.search_source_symbols_index_revalidated_local_in(
        &node.request_context(), &reference(), None, None, Some(&activation), &query(),
        SearchLimits { max_file_bytes: 1, ..Default::default() }, data::MAX_INDEX_BYTES,
    )).is_err());
    assert!(current(&node, Some(&activation), data::MAX_INDEX_BYTES).is_ok());
    node.shutdown().unwrap();
}

#[test]
fn authenticated_http_revalidation_is_explicit_and_keeps_both_source_identities() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, original, activation) = setup(&root, format);
        let path = root.0.join("credentials"); let header = credentials(&node, &path);
        let before = generation(&node);
        let server = Server::start(node, &path, 10, true, true);
        let body = format!("{}&name_hex={}&match=prefix", common(format), hex(b"Thing"));
        let strict = post(&server.client, "search-symbols-index", 'a', &body, false); status(&strict, 200);
        status(&issue(&server.client), 200);
        let stale = post(&server.client, "search-symbols-index", 'a', &body, false); status(&stale, 409);
        let revalidated = post(&server.client, "search-symbols-index", 'a', &(body.clone() + "&source_mode=revalidated"), true);
        status(&revalidated, 200);
        assert!(revalidated.body.contains("\"type\":\"source_search_symbols_index_revalidated\""));
        let (prefix, nested) = revalidated.body.split_once("\"result\":").unwrap();
        assert!(prefix.contains("\"current_source\":{") && prefix.contains("\"indexed_source\":{"));
        assert_eq!(nested.strip_suffix('}').unwrap(), strict.body);
        assert_ne!(text(prefix, "snapshot_token"), token(&strict));
        assert_eq!(text(prefix, "source_commit"), original.commit.to_string());
        assert_eq!(number(nested, "index_number"), activation.authority_generation.get());
        let denied = post(&server.client, "search-symbols-index", 'c', &(body.clone() + "&source_mode=revalidated"), false); status(&denied, 403);
        let stale_pin = post(&server.client, "search-symbols-index", 'a', &format!("{body}&source_mode=revalidated&expected_head={}", token(&strict)), false); status(&stale_pin, 409);
        let invalid = post(&server.client, "search-symbols-index", 'a', &(body.clone() + "&source_mode=force"), false); status(&invalid, 400);
        let selected_form = body + "&source_mode=revalidated";
        let mutation_key = request(
            &server.client, "/api/v1/source/search-symbols-index", 'a',
            &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: forbidden-read-key\r\n", selected_form.len()),
            selected_form.as_bytes(),
        );
        status(&exchange(&server.client, &mutation_key, true), 400);
        status(&post(&server.client, "search-symbols-index", 'a', &(selected_form.clone() + "&max_work=1"), false), 413);
        replace(&path, &(header + &row('c', OWNER, "outcomes-read")));
        status(&post(&server.client, "search-symbols-index", 'a', &selected_form, false), 401);
        assert_eq!(server.finish().accepted_sessions(), 10);
        let node = reopen(&root.config(format));
        assert_eq!(generation(&node), before + 1);
        let (_, report) = current(&node, Some(&activation), data::MAX_INDEX_BYTES).unwrap();
        assert_eq!(report.source, original); node.shutdown().unwrap();
    }
}

#[test]
fn missing_refs_and_cross_domain_pins_do_not_disclose_an_existing_index() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, _, activation) = setup(&root, format);
        let before = generation(&node);
        let missing = RefName::try_new(b"refs/heads/missing").unwrap();
        assert!(matches!(node.runtime().block_on(node.search_source_symbols_index_revalidated_local_in(
            &node.request_context(), &missing, None, None, Some(&activation), &query(), Default::default(), data::MAX_INDEX_BYTES,
        )), Err(AccessError::Source(NodeWorkspaceRefusal::RefUnavailable))));
        let other = match format { GitHashAlgorithm::Sha1 => GitHashAlgorithm::Sha256, GitHashAlgorithm::Sha256 => GitHashAlgorithm::Sha1 };
        let foreign = fgit_crypto::git_object_id(other, fgit_crypto::GitObjectKind::Commit, b"foreign");
        assert!(matches!(node.runtime().block_on(node.search_source_symbols_index_revalidated_local_in(
            &node.request_context(), &reference(), None, Some(foreign), Some(&activation), &query(), Default::default(), data::MAX_INDEX_BYTES,
        )), Err(AccessError::Source(NodeWorkspaceRefusal::ObjectFormatMismatch))));
        assert!(current(&node, Some(&activation), data::MAX_INDEX_BYTES).is_ok());
        assert_eq!(generation(&node), before); node.shutdown().unwrap();
    }
}

#[test]
fn revalidation_retains_path_scope_result_completeness_and_table_limits() {
    let root = Scratch::new(); let format = GitHashAlgorithm::Sha256;
    let (node, first_source, first) = setup(&root, format);
    let tip = add_file(&node, first_source.commit, "extra.rs", b"current-symbol-scope");
    let (source, activation) = node.runtime().block_on(node.build_source_symbol_index_local_in(
        &node.outbox_delivery_context(), &reference(), None, Some(tip), Some(first.generation_id), Default::default(),
    )).unwrap();
    let node = metadata(node, &root, format); let before = generation(&node);
    let read = |q: &SymbolQuery, limits| node.runtime().block_on(node.search_source_symbols_index_revalidated_local_in(
        &node.request_context(), &reference(), None, None, Some(&activation), q, limits, data::MAX_INDEX_BYTES,
    ));
    let (_, limited) = read(&query(), SearchLimits { max_matches: 1, ..Default::default() }).unwrap();
    assert_eq!(limited.matches.len(), 1); assert!(!limited.complete);
    let (_, full) = read(&query(), SearchLimits { max_matches: 2, ..Default::default() }).unwrap();
    assert_eq!(full.matches.len(), 2); assert!(full.complete); assert_eq!(full.source, source);
    assert!(read(&query(), SearchLimits { max_files: 1, ..Default::default() }).is_err());
    let scoped = SymbolQuery::new(b"Thing", SymbolMatchMode::Exact, &[], &[b"sample.rs".to_vec()], MAX_SYMBOL_WORK).unwrap();
    let (_, report) = read(&scoped, SearchLimits { max_files: 1, ..Default::default() }).unwrap();
    assert_eq!(report.matches.len(), 1); assert!(report.complete);
    assert_eq!(report.matches[0].location.path, b"sample.rs");
    assert_eq!(report.tables_read, 1); assert_eq!(report.source, source);
    assert_eq!(generation(&node), before); node.shutdown().unwrap();
}
