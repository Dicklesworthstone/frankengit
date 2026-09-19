#![forbid(unsafe_code)]
//! Same-snapshot batch retrieval through real imported trees, native node APIs
//! and the production authenticated HTTP listener. No substitute matcher/store.
#[path = "source_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_crypto::{GitHashAlgorithm as NativeFormat, Sha1, Sha256};
use fgit_forge::source_browse::SourceBrowseError;
use fgit_forge::source_search::{SearchCase, SearchCompletion, SearchLimits};
use fgit_forge::source_search::batch::{SourceQueryBatch, SourceSearchBatchReport};
use fgit_node::{LoopbackReceiveSession, NodeWorkspaceRefusal, OneNode};
use fgit_treefs::{TreeCapability, TreePath, WorkspaceId};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryId};
use fgit_wire::visibility::RefVisibility;

fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn queries(needles: &[&[u8]], prefixes: &[Vec<u8>]) -> SourceQueryBatch {
    SourceQueryBatch::new(&needles.iter().map(|needle| needle.to_vec()).collect::<Vec<_>>(),
        SearchCase::AsciiInsensitive, prefixes).unwrap()
}
fn local(node: &OneNode, query: &SourceQueryBatch, limits: SearchLimits) -> SourceSearchBatchReport {
    node.runtime().block_on(node.search_source_batch_snapshot_local_in(&node.request_context(),
        &reference(), None, None, query, limits)).unwrap().1
}

#[test]
fn batch_native_matches_individual_queries_with_one_shared_read_budget_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, commit) = fixture(&root, format);
        let before = generation(&node);
        let query = queries(&[b"needle", b"NEEDLE", b"aba", b"\0\xff", b"absent"], &[]);
        let (head, batch) = node.runtime().block_on(node.search_source_batch_snapshot_local_in(
            &node.request_context(), &reference(), None, Some(commit), &query, SearchLimits::default())).unwrap();
        assert_eq!(batch.results.len(), 5);
        assert_eq!(batch.source_commit, commit);
        assert_eq!(batch.files_read, 5);
        assert_eq!(batch.files_selected, 5);
        assert_eq!(batch.non_regular_entries, 2);
        assert_eq!(batch.bytes_searched, batch.bytes_read);
        for (needle, result) in query.queries().iter().zip(&batch.results) {
            let (single_head, single) = node.runtime().block_on(node.search_source_snapshot_local_in(
                &node.request_context(), &reference(), Some(head), Some(commit), needle, SearchLimits::default())).unwrap();
            assert_eq!(single_head, head);
            assert_eq!(single.source_rcr, batch.source_rcr);
            assert_eq!(single.source_tree, batch.source_tree);
            assert_eq!(single.matches, result.matches);
            assert_eq!(single.completion, result.completion);
            assert_eq!(single.files_read, batch.files_read);
            assert_eq!(single.bytes_read, batch.bytes_read);
        }
        let repeats = queries(&[b"needle".as_slice(); 32], &[]);
        let exact = SearchLimits { max_total_bytes: batch.bytes_read, ..SearchLimits::default() };
        let repeated = local(&node, &repeats, exact);
        assert_eq!(repeated.bytes_read, batch.bytes_read);
        assert!(repeated.results.iter().all(|result| result.matches == batch.results[0].matches));
        assert!(node.runtime().block_on(node.search_source_batch_snapshot_local_in(
            &node.request_context(), &reference(), Some(head), Some(commit), &repeats,
            SearchLimits { max_total_bytes: batch.bytes_read - 1, ..exact })).is_err());
        let repeated_batch = node.runtime().block_on(node.search_source_batch_snapshot_local_in(
            &node.request_context(), &reference(), Some(head), Some(commit), &query, SearchLimits::default())).unwrap();
        assert_eq!(repeated_batch, (head, batch));
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

fn scoped<A: NativeFormat>(node: &OneNode, capability: &mut TreeCapability,
    query: &SourceQueryBatch, visibility: &RefVisibility,
) -> Result<SourceSearchBatchReport, NodeWorkspaceRefusal> {
    node.runtime().block_on(node.search_source_batch_in::<A>(&node.request_context(),
        &reference(), visibility, capability, 0, query, SearchLimits::default()))
}
fn capability(repository: RepositoryId) -> TreeCapability {
    TreeCapability::new(WorkspaceId::from_bytes([0x95; 16]), repository,
        vec![TreePath::parse_default(b"dir").unwrap()], Vec::new())
}

#[test]
fn batch_native_capabilities_and_prefixes_never_widen_disclosure() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let (node, _) = fixture(&root, format);
        let repository = RepositoryId::from_bytes([0x32; 16]);
        let query = queries(&[b"needle", b"aba", b"\0\xff"], &[]);
        let run = |cap: &mut TreeCapability, visible: &RefVisibility| match format {
            GitHashAlgorithm::Sha1 => scoped::<Sha1>(&node, cap, &query, visible),
            GitHashAlgorithm::Sha256 => scoped::<Sha256>(&node, cap, &query, visible),
        };
        let report = run(&mut capability(repository), &RefVisibility::new()).unwrap();
        assert_eq!(report.files_selected, 1);
        assert_eq!(report.results[0].matches.len(), 1);
        assert_eq!(report.results[0].matches[0].path, b"dir/nested.txt");
        assert!(report.results[1..].iter().all(|result| result.matches.is_empty()
            && result.completion == SearchCompletion::Complete));
        assert!(run(&mut capability(RepositoryId::from_bytes([0x99; 16])), &RefVisibility::new()).is_err());
        let mut revoked = capability(repository); revoked.revoke();
        assert!(run(&mut revoked, &RefVisibility::new()).is_err());
        let mut hidden = RefVisibility::new(); hidden.push_rule(reference().as_bytes(), &fgit_wire::WireLimits::default()).unwrap();
        assert!(run(&mut capability(repository), &hidden).is_err());
        let narrowed = local(&node, &queries(&[b"needle", b"aba"], &[b"dir".to_vec()]), SearchLimits::default());
        assert_eq!(narrowed.files_selected, 1);
        assert_eq!(narrowed.results[0].matches, report.results[0].matches);
        let absent = local(&node, &queries(&[b"needle", b"absent"], &[b"di".to_vec()]), SearchLimits::default());
        assert_eq!(absent.files_selected, 0);
        assert_eq!(absent.bytes_read, 0);
        assert!(absent.results.iter().all(|result| result.matches.is_empty()
            && result.completion == SearchCompletion::Complete));
        node.shutdown().unwrap();
    }
}

#[test]
fn batch_native_lookahead_is_per_query_and_snapshot_checks_precede_answers() {
    let root = Scratch::new(); let (node, commit) = fixture(&root, GitHashAlgorithm::Sha1);
    let query = queries(&[b"needle", b"aba", b"absent"], &[]);
    let batch = local(&node, &query, SearchLimits { max_matches: 2, ..SearchLimits::default() });
    assert_eq!(batch.results[0].completion, SearchCompletion::MatchLimit);
    assert_eq!(batch.results[0].matches.len(), 2);
    assert_eq!(batch.results[1].completion, SearchCompletion::Complete);
    assert_eq!(batch.results[1].matches.len(), 2);
    assert_eq!(batch.results[2].completion, SearchCompletion::Complete);
    assert!(batch.results[2].matches.is_empty());
    assert_eq!(batch.files_read, batch.files_selected);
    let wrong = GitOid::from_hex(GitHashAlgorithm::Sha1, &"a".repeat(40)).unwrap();
    assert_ne!(wrong, commit);
    let result = node.runtime().block_on(node.search_source_batch_snapshot_local_in(&node.request_context(),
        &reference(), None, Some(wrong), &query, SearchLimits::default()));
    assert!(matches!(result, Err(NodeWorkspaceRefusal::SourceBrowse(error)) if matches!(*error, SourceBrowseError::CommitMoved)));
    let foreign = GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap();
    assert!(node.runtime().block_on(node.search_source_batch_snapshot_local_in(&node.request_context(),
        &reference(), None, Some(foreign), &query, SearchLimits::default())).is_err());
    node.shutdown().unwrap();
}

fn batch_form(format: GitHashAlgorithm) -> String {
    format!("{}&needle_hex={}&needle_hex={}&needle_hex={}&case=ascii-insensitive",
        common(format), hex(b"needle"), hex(b"aba"), hex(b"absent"))
}
fn result_segment(body: &str, index: usize) -> &str {
    body.split_once(&format!("{{\"query_index\":{index},")).unwrap().1
        .split("{\"query_index\":").next().unwrap()
}

#[test]
fn batch_http_uses_real_listener_lossless_results_shared_counters_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, commit) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); credentials(&node, &path);
        let server = Server::start(node, &path, 5, true, false);
        let form = batch_form(format);
        let first = post(&server.client, "search-batch", 'a', &form, false); // 1
        status(&first, 200);
        assert_eq!(text(&first.body, "type"), "source_search_batch");
        assert_eq!(text(&first.body, "profile"), "literal-bytes-batch-v1");
        assert_eq!(text(&first.body, "source_commit"), commit.to_string());
        assert_eq!(number(&first.body, "query_count"), 3);
        assert_eq!(number(&first.body, "files_selected"), 5);
        assert_eq!(number(&first.body, "files_read"), 5);
        assert!(first.body.contains("\"shared_scan\":true"));
        assert_eq!(number(result_segment(&first.body, 0), "returned_matches"), 5);
        assert_eq!(number(result_segment(&first.body, 1), "returned_matches"), 2);
        assert_eq!(number(result_segment(&first.body, 2), "returned_matches"), 0);
        assert!(result_segment(&first.body, 0).contains(&hex(BINARY_PATH)));
        assert!(result_segment(&first.body, 1).contains("\"byte_offset\":15,\"line\":2,\"byte_column\":1"));
        let pinned = format!("{form}&expected_head={}&expected_commit={commit}", token(&first));
        let chunked = post(&server.client, "search-batch", 'a', &pinned, true); // 2
        status(&chunked, 200); assert_eq!(chunked, first);
        let single = post(&server.client, "search", 'a', &format!("{}&needle_hex={}&case=ascii-insensitive",
            common(format), hex(b"needle")), false); // 3
        status(&single, 200);
        assert_eq!(number(&single.body, "bytes_read"), number(&first.body, "bytes_read"));
        let limited = post(&server.client, "search-batch", 'a', &(form.clone() + "&max_matches=2"), false); // 4
        status(&limited, 200);
        assert_eq!(text(result_segment(&limited.body, 0), "completion"), "match_limit");
        assert_eq!(text(result_segment(&limited.body, 1), "completion"), "complete");
        assert_eq!(text(result_segment(&limited.body, 2), "completion"), "complete");
        let refused = post(&server.client, "search-batch", 'a', &(form.clone() + "&max_bytes=1"), false); // 5
        status(&refused, 413); assert!(!refused.body.contains("\"results\""));
        assert_eq!(server.finish().accepted_sessions(), 5);
        let node = reopen(&config); assert_eq!(generation(&node), before);
        let session = LoopbackReceiveSession::authenticated(OWNER,
            IdempotencyKey::new(b"read-only-source-query".to_vec()).unwrap());
        assert!(matches!(node.runtime().block_on(node.recover_transaction_in(&node.request_context(), &session)).unwrap(),
            RequestRecovery::KeyNotObserved));
        let server = Server::start(node, &path, 1, true, false);
        assert_eq!(post(&server.client, "search-batch", 'a', &pinned, false), first);
        assert_eq!(server.finish().accepted_sessions(), 1);
    }
}

#[test]
fn batch_http_read_scope_and_no_transaction_boundary_are_enforced_before_disclosure() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1); let before = generation(&node);
    let path = root.0.join("credentials"); credentials(&node, &path);
    let server = Server::start(node, &path, 5, true, false);
    let form = batch_form(GitHashAlgorithm::Sha1);
    for (token, code) in [('b', 403), ('c', 403), ('f', 401)] {
        let response = post(&server.client, "search-batch", token, &form, false); // 1-3
        status(&response, code);
        assert!(!response.body.contains("\"source_commit\"") && !response.body.contains("\"results\""));
    }
    let headers = format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: not-a-write\r\n", form.len());
    let response = exchange(&server.client, &request(&server.client, "/api/v1/source/search-batch", 'a',
        &headers, form.as_bytes()), true); // 4
    status(&response, 400);
    let malformed = post(&server.client, "search-batch", 'a', &(form + "&needle_hex=0a"), false); // 5
    status(&malformed, 400);
    assert_eq!(server.finish().accepted_sessions(), 5);
    let node = reopen(&config); assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn batch_http_pinned_head_refuses_intervening_canonical_mutation() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node, commit) = fixture(&root, GitHashAlgorithm::Sha1);
    let path = root.0.join("credentials"); credentials(&node, &path);
    let server = Server::start(node, &path, 4, true, true);
    let form = batch_form(GitHashAlgorithm::Sha1);
    let first = post(&server.client, "search-batch", 'a', &form, false); // 1
    status(&first, 200);
    let body = b"expected_version=0&title=Intervening+write&body=";
    let issue = exchange(&server.client, &request(&server.client, "/api/v1/issues/1/open", 'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: batch-intervening-issue\r\n", body.len()), body), true); // 2
    status(&issue, 200);
    let stale = post(&server.client, "search-batch", 'a', &format!("{form}&expected_head={}", token(&first)), false); // 3
    status(&stale, 409);
    assert!(stale.body.contains("source_snapshot_moved") && !stale.body.contains("\"results\""));
    let current = post(&server.client, "search-batch", 'a', &format!("{form}&expected_commit={commit}"), false); // 4
    status(&current, 200); assert_ne!(token(&current), token(&first));
    assert_eq!(text(&current.body, "source_commit"), commit.to_string());
    assert_eq!(server.finish().accepted_sessions(), 4);
    let node = reopen(&config); node.shutdown().unwrap();
}
