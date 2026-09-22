#![forbid(unsafe_code)]
//! Real native TreeFS, storage reopen, and authenticated TCP query routing.
#[path = "source_http/support.rs"]
mod support;
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::source_search::SearchLimits;
use fgit_forge::source_symbols::index::{self as data, AccessError};
use fgit_forge::source_symbols::{MAX_SYMBOL_WORK, SymbolKind, SymbolMatchMode, SymbolQuery};
use fgit_graph::{GenerationActivation, GenerationAuthorityError};
use fgit_node::{NodeWorkspaceRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
use support::*;
type Failure = AccessError<NodeWorkspaceRefusal, GenerationAuthorityError>;
const FILES: usize = 35;
fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn query(
    name: &[u8],
    mode: SymbolMatchMode,
    kinds: &[SymbolKind],
    scopes: &[Vec<u8>],
) -> SymbolQuery {
    SymbolQuery::new(name, mode, kinds, scopes, MAX_SYMBOL_WORK).unwrap()
}
fn corpus(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, GitOid, GenerationActivation) {
    let (node, base) = fixture(root, format);
    let mut files: Vec<_> = (0..32)
        .map(|i| {
            (
                format!("bulk/f{i:02}.rs"),
                format!("fn Noise{i:02}() {{}}\n"),
            )
        })
        .collect();
    files.extend([
        (
            "src/rare.rs".into(),
            "pub fn NeedleOne() {}\nstruct Shared;\n".into(),
        ),
        (
            "src2/twin.rs".into(),
            "pub fn NeedleTwo() {}\nfn Shared() {}\n".into(),
        ),
        ("types.rs".into(), "struct NeedleOne;\n".into()),
    ]);
    assert_eq!(files.len(), FILES);
    let mut patch = String::new();
    for (path, body) in &files {
        let lines = body.lines().count();
        patch.push_str(&format!("diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{lines} @@\n"));
        for line in body.lines() {
            patch.push('+');
            patch.push_str(line);
            patch.push('\n');
        }
    }
    let metadata = MergeMetadata {
        author: "Fixture <fixture@example.invalid>".into(),
        committer: "Fixture <fixture@example.invalid>".into(),
        timestamp: 4,
        message: b"directory routing corpus\n".to_vec(),
    };
    let request = node.outbox_delivery_context();
    let candidate = node
        .runtime()
        .block_on(node.prepare_trusted_patch_in(
            &request,
            &reference(),
            base,
            [0x79; 16],
            patch.as_bytes(),
            &metadata,
            Default::default(),
        ))
        .unwrap();
    let applied = node
        .runtime()
        .block_on(node.apply_workspace_bundle_durable_in(
            &request,
            OWNER,
            b"symbol-directory-corpus",
            &reference(),
            base,
            candidate.candidate_commit,
            candidate.bundle_bytes(),
        ))
        .unwrap();
    assert!(
        applied
            .commands
            .iter()
            .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    let (_, activation) = node
        .runtime()
        .block_on(node.build_source_symbol_index_local_in(
            &node.outbox_delivery_context(),
            &reference(),
            None,
            Some(candidate.candidate_commit),
            None,
            Default::default(),
        ))
        .unwrap();
    (node, candidate.candidate_commit, activation)
}
fn indexed(
    node: &OneNode,
    q: &SymbolQuery,
    limits: SearchLimits,
    bytes: usize,
) -> Result<data::Report, Failure> {
    node.runtime()
        .block_on(node.search_source_symbols_index_snapshot_local_in(
            &node.outbox_delivery_context(),
            &reference(),
            None,
            None,
            None,
            q,
            limits,
            bytes,
        ))
}

#[test]
fn routing_reads_only_matching_tables_and_retains_exact_native_results_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit, first) = corpus(&root, format);
        let canonical = generation(&node);
        let rare = query(
            b"NeedleOne",
            SymbolMatchMode::Exact,
            &[SymbolKind::Function],
            &[],
        );
        let cases = [
            (rare.clone(), 1usize),
            (query(b"Needle", SymbolMatchMode::Prefix, &[], &[]), 3),
            (
                query(
                    b"Needle",
                    SymbolMatchMode::Prefix,
                    &[SymbolKind::Struct],
                    &[],
                ),
                1,
            ),
            (
                query(b"Needle", SymbolMatchMode::Prefix, &[], &[b"src".to_vec()]),
                1,
            ),
            (query(b"Missing", SymbolMatchMode::Exact, &[], &[]), 0),
        ];
        for (q, count) in cases {
            let report = indexed(
                &node,
                &q,
                SearchLimits {
                    max_files: count.max(1),
                    ..Default::default()
                },
                data::MAX_INDEX_BYTES,
            )
            .unwrap();
            let (_, live) = node
                .runtime()
                .block_on(node.search_source_symbols_snapshot_local_in(
                    &node.outbox_delivery_context(),
                    &reference(),
                    Some(report.source.head),
                    Some(commit),
                    &q,
                    Default::default(),
                ))
                .unwrap();
            assert_eq!(report.matches, live.matches);
            assert!(report.complete);
            assert_eq!(report.indexed_files, FILES);
            assert_eq!(report.tables_read, count);
            assert_eq!(
                report.generation,
                *first.generation_id.as_internal_object_id()
            );
            assert!(report.payload_bytes_read > 0); // Manifest/directory still require real I/O.
        }
        let all = query(b"Needle", SymbolMatchMode::Prefix, &[], &[]);
        let limited = indexed(
            &node,
            &all,
            SearchLimits {
                max_matches: 2,
                ..Default::default()
            },
            data::MAX_INDEX_BYTES,
        )
        .unwrap();
        assert_eq!(limited.matches.len(), 2);
        assert!(!limited.complete);
        let exact = indexed(
            &node,
            &all,
            SearchLimits {
                max_matches: 3,
                ..Default::default()
            },
            data::MAX_INDEX_BYTES,
        )
        .unwrap();
        assert_eq!(exact.matches.len(), 3);
        assert!(exact.complete);
        assert!(
            indexed(
                &node,
                &all,
                SearchLimits {
                    max_files: 2,
                    ..Default::default()
                },
                data::MAX_INDEX_BYTES
            )
            .is_err()
        );
        let report = indexed(&node, &rare, Default::default(), data::MAX_INDEX_BYTES).unwrap();
        assert!(indexed(&node, &rare, Default::default(), report.payload_bytes_read).is_ok());
        assert!(
            indexed(
                &node,
                &rare,
                Default::default(),
                report.payload_bytes_read - 1
            )
            .is_err()
        );
        let tiny = SymbolQuery::new(b"Missing", SymbolMatchMode::Exact, &[], &[], 1).unwrap();
        assert!(indexed(&node, &tiny, Default::default(), data::MAX_INDEX_BYTES).is_err());
        assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
        let node = reopen(&config);
        let (source, next, stats) = node
            .runtime()
            .block_on(node.refresh_source_symbol_index_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                None,
                Some(commit),
                first.generation_id,
                Default::default(),
            ))
            .unwrap();
        assert_eq!(stats.source_blobs_read, 0);
        assert_eq!(stats.reused_files, FILES);
        let again = node
            .runtime()
            .block_on(node.search_source_symbols_index_snapshot_local_in(
                &node.outbox_delivery_context(),
                &reference(),
                Some(source.head),
                Some(commit),
                Some(&first),
                &rare,
                SearchLimits {
                    max_files: 1,
                    ..Default::default()
                },
                data::MAX_INDEX_BYTES,
            ))
            .unwrap();
        assert_eq!(again.matches, report.matches);
        assert_eq!(again.tables_read, 1);
        assert_eq!(
            again.generation,
            *next.generation_id.as_internal_object_id()
        );
        assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
    }
}

#[test]
fn authenticated_http_exposes_selective_work_without_weakening_scopes_or_limits() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let (node, _, _) = corpus(&root, format);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 8, true, false);
    let form =
        |name: &[u8], suffix: &str| format!("{}&name_hex={}&{suffix}", common(format), hex(name));
    for (name, suffix, matches, tables, complete, chunked) in [
        (
            b"NeedleOne".as_slice(),
            "match=exact&kind=function",
            1,
            1,
            true,
            false,
        ),
        (
            b"Needle",
            "match=prefix&path_prefix_hex=737263",
            1,
            1,
            true,
            true,
        ),
        (b"Needle", "match=prefix&kind=struct", 1, 1, true, false),
        (b"Missing", "match=exact", 0, 0, true, true),
        (b"Needle", "match=prefix&max_matches=2", 2, 3, false, false),
        (b"Needle", "match=prefix&max_matches=3", 3, 3, true, true),
    ] {
        let reply = post(
            &server.client,
            "search-symbols-index",
            'a',
            &form(name, suffix),
            chunked,
        );
        status(&reply, 200);
        assert_eq!(number(&reply.body, "indexed_files"), FILES as u64);
        assert_eq!(number(&reply.body, "returned_matches"), matches);
        assert_eq!(number(&reply.body, "tables_read"), tables);
        assert_eq!(number(&reply.body, "source_blobs_read"), 0);
        assert!(reply.body.contains(&format!("\"complete\":{complete}")));
    }
    status(
        &post(
            &server.client,
            "search-symbols-index",
            'b',
            &form(b"Needle", "match=prefix"),
            false,
        ),
        403,
    );
    status(
        &post(
            &server.client,
            "search-symbols-index",
            'a',
            &form(b"Missing", "match=exact&max_work=1"),
            false,
        ),
        413,
    );
    assert_eq!(server.finish().accepted_sessions(), 8);
}
