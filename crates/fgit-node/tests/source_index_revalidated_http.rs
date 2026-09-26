#![forbid(unsafe_code)]
//! Real TCP requests, native imported trees and persisted index generations.
//! Explicit revalidation is not permission to bypass the source gateway.
#[path = "source_http/support.rs"]
mod support;
use fgit_graph::GenerationActivation;
use fgit_node::OneNode;
use fgit_node::source_retrieval::current_index::{LexicalChannel, LexicalQuery, RevalidatedIndexRequest};
use fgit_types::{GitHashAlgorithm, RefName};
use support::*;

fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn build(node: &OneNode, predecessor: Option<&GenerationActivation>) -> GenerationActivation {
    node.runtime().block_on(node.build_source_index_local_in(
        &node.request_context(), &reference(), None, None,
        predecessor.map(|value| value.generation_id), Default::default(),
    )).unwrap().1
}
fn index_token(activation: &GenerationActivation) -> String {
    let id = activation.generation_id.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn form(format: GitHashAlgorithm) -> String {
    format!("{}&term_hex=6e6565646c65&source_mode=revalidated", common(format))
}
fn issue(client: &Endpoint, number: u64) -> Reply {
    let body = b"expected_version=0&title=Metadata+only&body=does+not+change+Git";
    exchange(client, &request(
        client, &format!("/api/v1/issues/{number}/open"), 'b',
        &format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: revalidated-http-issue-{number}\r\n",
            body.len(),
        ), body,
    ), true)
}
fn nested<'a>(body: &'a str, field: &str) -> &'a str {
    body.split_once(&format!("\"{field}\":{{")).unwrap().1.split_once('}').unwrap().0
}

#[test]
fn authenticated_http_reuses_index_after_metadata_writes_without_rewriting_provenance() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let generation_before = generation(&node);
        let activation = build(&node, None);
        let credentials_path = root.0.join("credentials");
        credentials(&node, &credentials_path);
        let server = Server::start(node, &credentials_path, 6, true, true);
        let strict = format!("{}&term_hex=6e6565646c65", common(format));
        let before = post(&server.client, "search-index", 'a', &strict, false);
        status(&before, 200);
        let same = post(&server.client, "search-index", 'a', &form(format), true);
        status(&same, 200);
        assert!(same.body.contains("\"distinct_provenance\":false"));
        status(&issue(&server.client, 1), 200);
        let stale = post(&server.client, "search-index", 'a', &strict, false);
        status(&stale, 409);
        assert!(stale.body.contains("source_index_stale"));
        let reused = post(&server.client, "search-index", 'a', &form(format), true);
        status(&reused, 200);
        assert_eq!(text(&reused.body, "type"), "source_search_index_current");
        assert_eq!(text(&reused.body, "profile"), "source-lexical-revalidated-v1");
        assert_eq!(text(&reused.body, "index_token"), index_token(&activation));
        assert_eq!(text(&reused.body, "index_number"), activation.authority_generation.get().to_string());
        assert_eq!(text(&reused.body, "source_commit"), commit.to_string());
        assert_eq!(number(&reused.body, "returned_hits"), 4);
        assert!(reused.body.contains("\"distinct_provenance\":true"));
        assert!(reused.body.contains("\"document_id\":\"1\""));
        assert!(reused.body.contains(&hex(BINARY_PATH)));
        assert!(reused.body.contains("\"read_only\":true,\"transaction_created\":false,\"published\":false"));
        assert_eq!(text(nested(&reused.body, "indexed_source"), "snapshot_token"), token(&before));
        assert_eq!(text(nested(&reused.body, "current_source"), "snapshot_token"), token(&reused));
        assert_ne!(token(&before), token(&reused));
        let path = post(&server.client, "search-index", 'a', &format!(
            "{}&source_mode=revalidated&channel=path&term_hex=646174", common(format),
        ), false);
        status(&path, 200);
        assert_eq!(number(&path.body, "returned_hits"), 1);
        assert!(path.body.contains(&hex(BINARY_PATH)));
        assert_eq!(server.finish().accepted_sessions(), 6);
        let node = reopen(&config);
        assert_eq!(generation(&node), generation_before + 1);
        let reference = reference();
        let query = LexicalQuery::new(LexicalChannel::Content, &[b"needle".to_vec()], &[]).unwrap();
        let after = node.runtime().block_on(node.search_source_index_revalidated_local_in(
            &node.request_context(), RevalidatedIndexRequest::new(&reference, &query),
        )).unwrap();
        assert_eq!(after.index().generation, activation);
        assert_eq!(after.current_source().commit, commit);
        assert_eq!(generation(&node), generation_before + 1);
        node.shutdown().unwrap();
    }
}

#[test]
fn pagination_pins_current_head_and_original_generation_without_implicit_rebase() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let (node, commit) = fixture(&root, format);
    let first = build(&node, None);
    let second = build(&node, Some(&first));
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 7, true, true);
    let request_form = format!(
        "{}&limit=2&index_token={}&index_number={}&minimum_index_token={}&minimum_index_number={}",
        form(format), index_token(&first), first.authority_generation.get(),
        index_token(&second), second.authority_generation.get(),
    );
    let before = post(&server.client, "search-index", 'a', &request_form, false);
    status(&before, 200);
    assert_eq!(text(&before.body, "next_after"), "2");
    status(&issue(&server.client, 1), 200);
    let next = |snapshot: &str| format!(
        "{request_form}&expected_head={snapshot}&expected_commit={commit}&after=2",
    );
    let stale = post(&server.client, "search-index", 'a', &next(&token(&before)), true);
    status(&stale, 409);
    assert!(!stale.body.contains("\"hits\""));
    let restarted = post(&server.client, "search-index", 'a', &request_form, false);
    status(&restarted, 200);
    assert_eq!(text(&restarted.body, "index_token"), index_token(&first));
    assert_eq!(text(&restarted.body, "selected_index_token"), index_token(&second));
    let last = post(&server.client, "search-index", 'a', &next(&token(&restarted)), true);
    status(&last, 200);
    assert_eq!(text(&last.body, "index_token"), index_token(&first));
    assert_eq!(token(&last), token(&restarted));
    assert!(last.body.contains("\"document_id\":\"3\""));
    assert!(last.body.contains("\"document_id\":\"5\""));
    assert!(last.body.contains("\"complete\":true,\"next_after\":null"));
    for suffix in ["&max_work=1", "&max_payload_bytes=1"] {
        let denied = post(&server.client, "search-index", 'a', &(form(format) + suffix), false);
        status(&denied, 413);
        assert!(!denied.body.contains("\"hits\""));
    }
    assert_eq!(server.finish().accepted_sessions(), 7);
}

#[test]
fn revalidated_mode_does_not_supply_read_permission_or_accept_mutation_keys() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = fixture(&root, format);
    build(&node, None);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 6, true, true);
    let form = form(format);
    for (credential, expected) in [('b', 403), ('c', 403), ('d', 401)] {
        let refused = post(&server.client, "search-index", credential, &form, false);
        status(&refused, expected);
        assert!(!refused.body.contains("\"indexed_source\""));
        assert!(!refused.body.contains("\"hits\""));
    }
    let keyed = exchange(&server.client, &request(
        &server.client, "/api/v1/source/search-index", 'a',
        &format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: not-a-write\r\n",
            form.len(),
        ), form.as_bytes(),
    ), true);
    status(&keyed, 400);
    assert!(!keyed.body.contains("\"outcome\""));
    status(&post(&server.client, "search-index", 'a', &(form.clone() + "&build=true"), false), 400);
    status(&post(&server.client, "search-index", 'a', &form, false), 200);
    assert_eq!(server.finish().accepted_sessions(), 6);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn missing_index_and_disabled_source_api_never_fall_back_to_a_scan_or_build() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 2, true, false);
    for chunked in [false, true] {
        let missing = post(&server.client, "search-index", 'a', &form(format), chunked);
        status(&missing, 409);
        assert!(missing.body.contains("source_index_uninitialized"));
        assert!(!missing.body.contains("\"hits\""));
    }
    assert_eq!(server.finish().accepted_sessions(), 2);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    build(&node, None);
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, false, false);
    status(&post(&server.client, "search-index", 'a', &form(format), false), 403);
    assert_eq!(server.finish().accepted_sessions(), 1);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
