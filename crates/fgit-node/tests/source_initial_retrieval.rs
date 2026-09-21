#![forbid(unsafe_code)]
//! Compose the real persistent index owners, actual native edits and storage
//! reopen. These are not substitute searchers or metadata-only fixtures.
#[path = "source_http/support.rs"]
mod support;
use support::*;
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_symbols::{SymbolMatchMode, index as symbols};
use fgit_node::{OneNode, source_retrieval::{Checkpoints, InitialLimits, InitialQuery,
    InitialReport, RetrievalError, SymbolChannel, SymbolPolicy, SymbolUnavailable}};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};

fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn query(policy: SymbolPolicy, prefixes: &[Vec<u8>]) -> InitialQuery {
    InitialQuery::new(&[b"Thing".to_vec()], prefixes).unwrap()
        .with_symbols(b"Thing", SymbolMatchMode::Prefix, &[], policy).unwrap()
}
fn edit(node: &OneNode, base: GitOid, files: &[(&str, &str)], key: &[u8]) -> GitOid {
    let mut patch = String::new();
    for (path, body) in files {
        assert!(body.ends_with('\n'));
        patch.push_str(&format!("diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{} @@\n", body.lines().count()));
        for line in body.lines() { patch.push('+'); patch.push_str(line); patch.push('\n'); }
    }
    let metadata = MergeMetadata { author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(), timestamp: 5,
        message: b"initial retrieval source\n".to_vec() };
    let request = node.outbox_delivery_context();
    let prepared = node.runtime().block_on(node.prepare_trusted_patch_in(&request, &reference(), base,
        [0x69; 16], patch.as_bytes(), &metadata, Default::default())).unwrap();
    let result = node.runtime().block_on(node.apply_workspace_bundle_durable_in(&request, OWNER, key,
        &reference(), base, prepared.candidate_commit, prepared.bundle_bytes())).unwrap();
    assert!(result.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
    prepared.candidate_commit
}
fn corpus(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, GitOid) {
    let (node, base) = fixture(root, format);
    let commit = edit(&node, base, &[
        ("src/Thing.rs", "pub fn Thing() {}\n"),
        ("src/comment.rs", "// Thing\npub struct Other;\n"),
        ("src2/Thing.rs", "pub fn Thing() {}\n"),
        ("docs/Thing.txt", "path-only result\n"),
    ], b"initial-retrieval-corpus");
    (node, commit)
}
fn build(node: &OneNode, symbols: bool) -> Checkpoints {
    let lexical = node.runtime().block_on(node.build_source_index_local_in(&node.outbox_delivery_context(),
        &reference(), None, None, None, Default::default())).unwrap().1;
    let symbols = symbols.then(|| node.runtime().block_on(node.build_source_symbol_index_local_in(
        &node.outbox_delivery_context(), &reference(), None, None, None, Default::default())).unwrap().1);
    Checkpoints { lexical: Some(lexical), symbols }
}
fn initial(node: &OneNode, query: &InitialQuery, floors: &Checkpoints, limits: InitialLimits)
    -> Result<InitialReport, RetrievalError>
{
    node.runtime().block_on(node.search_source_initial_local_in(&node.outbox_delivery_context(),
        &reference(), None, None, floors, query, limits))
}

#[test]
fn channels_match_native_owners_share_source_and_keep_generation_vector_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, commit) = corpus(&root, format); let floors = build(&node, true);
        let canonical = generation(&node); let q = query(SymbolPolicy::Required, &[]);
        let report = initial(&node, &q, &floors, Default::default()).unwrap();
        assert!(report.complete()); assert_eq!(report.source().commit, commit);
        assert_eq!(report.content().results.hits.len(), 3);
        assert_eq!(report.path().results.hits.len(), 3);
        assert_eq!(report.content().generation, report.path().generation);
        for (channel, expected) in [(q.content(), report.content()), (q.path(), report.path())] {
            let direct = node.runtime().block_on(node.search_source_index_local_in(&node.outbox_delivery_context(),
                &reference(), Some(report.source().source_head), Some(commit), Some(&report.generations().lexical),
                floors.lexical.as_ref(), channel, None, Default::default(), Default::default())).unwrap();
            assert_eq!(direct.results.hits, expected.results.hits);
            assert_eq!(direct.source, *report.source());
        }
        let SymbolChannel::Available(found) = report.symbols() else { panic!("required symbols absent") };
        assert_eq!(found.matches.len(), 2);
        let direct = node.runtime().block_on(node.search_source_symbols_index_snapshot_local_in(&node.outbox_delivery_context(),
            &reference(), Some(report.source().source_head), Some(commit), floors.symbols.as_ref(),
            q.symbols().unwrap().0, Default::default(), symbols::MAX_INDEX_BYTES)).unwrap();
        assert_eq!(found.matches, direct.matches);
        let scoped = initial(&node, &query(SymbolPolicy::Required, &[b"src".to_vec()]), &floors, Default::default()).unwrap();
        assert_eq!(scoped.content().results.hits.len(), 2);
        assert_eq!(scoped.path().results.hits.len(), 1);
        let SymbolChannel::Available(found) = scoped.symbols() else { panic!("required symbols absent") };
        assert_eq!(found.matches.len(), 1); assert_eq!(found.matches[0].location.path, b"src/Thing.rs");
        assert_eq!(generation(&node), canonical); node.shutdown().unwrap();
        let node = reopen(&config);
        let again = initial(&node, &q, &floors, Default::default()).unwrap();
        assert_eq!(again.generations(), report.generations());
        assert_eq!(again.content().results.hits, report.content().results.hits);
        assert_eq!(again.path().results.hits, report.path().results.hits);
        assert_eq!(again.source(), report.source()); assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
    }
}

#[test]
fn optional_uninitialized_symbols_are_not_empty_success_or_permission_to_ignore_a_floor() {
    let root = Scratch::new(); let (node, _) = corpus(&root, GitHashAlgorithm::Sha1);
    let floors = build(&node, false); let q = query(SymbolPolicy::Optional, &[]);
    let report = initial(&node, &q, &floors, Default::default()).unwrap();
    assert!(!report.complete()); assert_eq!(report.content().results.hits.len(), 3);
    assert!(matches!(report.symbols(), SymbolChannel::Unavailable(SymbolUnavailable::Uninitialized)));
    assert!(report.generations().symbols.is_none());
    assert!(matches!(initial(&node, &query(SymbolPolicy::Required, &[]), &floors, Default::default()),
        Err(RetrievalError::Symbols(symbols::AccessError::Uninitialized))));
    let bad_floor = Checkpoints { symbols: floors.lexical.clone(), ..floors.clone() };
    assert!(initial(&node, &q, &bad_floor, Default::default()).is_err());
    let lexical_only = InitialQuery::new(&[b"Thing".to_vec()], &[]).unwrap();
    assert!(matches!(initial(&node, &lexical_only, &bad_floor, Default::default()),
        Err(RetrievalError::Invalid("symbol checkpoint without symbol query"))));
    let report = initial(&node, &lexical_only, &floors, Default::default()).unwrap();
    assert!(report.complete()); assert!(matches!(report.symbols(), SymbolChannel::NotRequested));
    node.shutdown().unwrap();
}

#[test]
fn authenticated_empty_symbol_inventory_is_available_not_missing() {
    let root = Scratch::new(); let (node, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let floors = build(&node, true);
    let report = initial(&node, &query(SymbolPolicy::Required, &[]), &floors, Default::default()).unwrap();
    let SymbolChannel::Available(found) = report.symbols() else { panic!("initialized empty corpus unavailable") };
    assert_eq!(found.indexed_files, 0); assert!(found.matches.is_empty());
    assert!(report.complete()); assert!(report.generations().symbols.is_some());
    node.shutdown().unwrap();
}

#[test]
fn stale_symbols_never_mix_old_source_with_refreshed_lexical_results() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, commit) = corpus(&root, format);
        let floors = build(&node, true);
        let old = initial(&node, &query(SymbolPolicy::Required, &[]), &floors, Default::default()).unwrap();
        let next = edit(&node, commit, &[("fresh.rs", "pub fn ThingFresh() {}\n")], b"initial-retrieval-next");
        node.runtime().block_on(node.reconcile_source_index_local_in(&node.outbox_delivery_context(),
            &reference(), None, floors.lexical.as_ref(), Default::default(), Default::default())).unwrap();
        let no_symbol_floor = Checkpoints { symbols: None, ..floors.clone() };
        let q = query(SymbolPolicy::Optional, &[]);
        let report = initial(&node, &q, &no_symbol_floor, Default::default()).unwrap();
        assert_eq!(report.source().commit, next); assert!(!report.complete());
        assert!(matches!(report.symbols(), SymbolChannel::Unavailable(SymbolUnavailable::Stale)));
        assert!(initial(&node, &q, &floors, Default::default()).is_err());
        assert!(initial(&node, &query(SymbolPolicy::Required, &[]), &no_symbol_floor, Default::default()).is_err());
        assert!(node.runtime().block_on(node.search_source_initial_local_in(&node.outbox_delivery_context(),
            &reference(), Some(old.source().source_head), Some(commit), &floors, &q, Default::default())).is_err());
        let canonical = generation(&node);
        node.runtime().block_on(node.refresh_source_symbol_index_local_in(&node.outbox_delivery_context(),
            &reference(), None, Some(next), floors.symbols.as_ref().unwrap().generation_id, Default::default())).unwrap();
        let current = initial(&node, &q, &floors, Default::default()).unwrap();
        let SymbolChannel::Available(found) = current.symbols() else { panic!("refreshed symbols absent") };
        assert_eq!(found.matches.len(), 3); assert!(current.complete());
        assert_eq!(found.source.commit, next); assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
    }
}

#[test]
fn shared_limits_truncation_and_cancellation_have_no_publication_side_effects() {
    let root = Scratch::new(); let (node, _) = corpus(&root, GitHashAlgorithm::Sha256);
    let floors = build(&node, true); let canonical = generation(&node);
    let q = query(SymbolPolicy::Required, &[]); let limits = InitialLimits::default();
    let full = initial(&node, &q, &floors, limits).unwrap();
    assert!(full.completed_payload_bytes_read() <= limits.max_payload_bytes);
    assert!(full.completed_work_units() <= limits.max_work);
    let bounded = initial(&node, &q, &floors, InitialLimits { max_results_per_channel: 1, ..limits }).unwrap();
    assert!(!bounded.complete()); assert_eq!(bounded.content().results.hits.len(), 1);
    assert_eq!(bounded.path().results.hits.len(), 1);
    assert!(initial(&node, &q, &floors, InitialLimits { max_result_bytes: full.result_bytes(), ..limits }).is_ok());
    assert!(matches!(initial(&node, &q, &floors, InitialLimits { max_result_bytes: full.result_bytes() - 1, ..limits }),
        Err(RetrievalError::Limit("retained result bytes"))));
    for narrowed in [InitialLimits { max_work: 3, ..limits }, InitialLimits { max_payload_bytes: 3, ..limits }] {
        assert!(initial(&node, &q, &floors, narrowed).is_err());
    }
    let request = node.outbox_delivery_context(); let reference = reference();
    drop(node.search_source_initial_local_in(&request, &reference, None, None, &floors, &q, limits));
    request.cancel();
    assert!(node.runtime().block_on(node.search_source_initial_local_in(&request, &reference,
        None, None, &floors, &q, limits)).is_err());
    let again = initial(&node, &q, &floors, limits).unwrap();
    assert_eq!(again.generations(), full.generations()); assert_eq!(generation(&node), canonical);
    node.shutdown().unwrap();
}

#[test]
fn missing_lexical_index_never_becomes_a_source_scan_or_implicit_build() {
    let root = Scratch::new(); let (node, _) = corpus(&root, GitHashAlgorithm::Sha1);
    let canonical = generation(&node);
    for _ in 0..2 {
        let result = initial(&node, &query(SymbolPolicy::Optional, &[]), &Checkpoints::default(), Default::default());
        assert!(matches!(result, Err(RetrievalError::Source(fgit_node::NodeWorkspaceRefusal::SourceIndex(error)))
            if matches!(*error, fgit_graph::lexical::IndexError::Uninitialized)));
        assert_eq!(generation(&node), canonical);
    }
    node.shutdown().unwrap();
}
