#![forbid(unsafe_code)]
//! Production TCP service over real native imports and node-owned persisted
//! indexes. No replacement HTTP server, query engine or authority store.
#[path = "source_http/support.rs"]
mod support;
use fgit_graph::GenerationActivation;
use fgit_node::OneNode;
use fgit_types::{GitHashAlgorithm, RefName};
use support::*;
fn build(node: &OneNode, predecessor: Option<&GenerationActivation>) -> GenerationActivation {
    node.runtime()
        .block_on(node.build_source_index_local_in(
            &node.request_context(),
            &RefName::try_new(b"refs/heads/main").unwrap(),
            None,
            None,
            predecessor.map(|p| p.generation_id),
            Default::default(),
        ))
        .unwrap()
        .1
}
fn form(format: GitHashAlgorithm) -> String {
    format!("{}&term_hex=6e6565646c65", common(format))
}
fn index_token(activation: &GenerationActivation) -> String {
    let id = activation.generation_id.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}

#[test]
fn authenticated_http_reports_omissions_across_pages_revalidation_and_initial_channels() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let before = generation(&node);
        let (source, activation) = node
            .runtime()
            .block_on(node.build_source_index_local_in(
                &node.outbox_delivery_context(),
                &RefName::try_new(b"refs/heads/main").unwrap(),
                None,
                Some(commit),
                None,
                fgit_forge::source_search::SearchLimits {
                    max_file_bytes: TEXT.len() - 1,
                    ..Default::default()
                },
            ))
            .unwrap();
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 6, true, false);
        let found = post(&server.client, "search-index", 'a', &form(format), false);
        status(&found, 200);
        assert_eq!(number(&found.body, "schema_version"), 2);
        assert_eq!(
            text(&found.body, "index_profile"),
            "ascii-word-postings-omissions-v1"
        );
        assert_eq!(number(&found.body, "returned_hits"), 3);
        assert_eq!(number(&found.body, "omitted_files"), 1);
        assert_eq!(
            number(&found.body, "omitted_source_bytes"),
            TEXT.len() as u64
        );
        assert!(found.body.contains("\"complete\":true,\"next_after\":null"));
        assert!(found.body.contains("\"coverage_complete\":false"));
        assert!(found.body.contains(&format!(
            "\"omissions\":[{{\"path_hex\":\"{}\"",
            hex(b"alpha.txt")
        )));
        let revalidated = post(
            &server.client,
            "search-index",
            'a',
            &(form(format) + "&source_mode=revalidated"),
            true,
        );
        status(&revalidated, 200);
        assert_eq!(
            text(&revalidated.body, "profile"),
            "source-lexical-revalidated-v1"
        );
        assert_eq!(number(&revalidated.body, "schema_version"), 2);
        assert!(revalidated.body.contains("\"coverage_complete\":false"));
        let first = post(
            &server.client,
            "search-index",
            'a',
            &(form(format) + "&limit=1"),
            false,
        );
        status(&first, 200);
        assert!(first.body.contains("\"complete\":false"));
        let next = number(&first.body, "next_after");
        let head = source.source_head.as_internal_object_id();
        let continuation = format!(
            "{}&after={next}&expected_head=alg:{}:{}&expected_commit={commit}&index_token={}&index_number={}",
            form(format),
            head.algorithm().code_point(),
            hex(head.digest().as_bytes()),
            index_token(&activation),
            activation.authority_generation.get()
        );
        let rest = post(&server.client, "search-index", 'a', &continuation, true);
        status(&rest, 200);
        assert_eq!(number(&rest.body, "returned_hits"), 2);
        assert!(rest.body.contains("\"complete\":true,\"next_after\":null"));
        assert_eq!(
            rest.body.split_once("\"omissions\":").unwrap().1,
            first.body.split_once("\"omissions\":").unwrap().1
        );
        let initial = post(&server.client, "search-initial", 'a', &form(format), false);
        status(&initial, 200);
        assert!(
            initial
                .body
                .split_once("\"complete\":")
                .unwrap()
                .1
                .starts_with("false")
        );
        assert_eq!(
            initial.body.matches("\"coverage_complete\":false").count(),
            2
        );
        assert_eq!(initial.body.matches("\"omitted_files\":1").count(), 2);
        let denied = post(&server.client, "search-index", 'b', &form(format), false);
        status(&denied, 403);
        assert!(!denied.body.contains("\"omissions\""));
        assert_eq!(server.finish().accepted_sessions(), 6);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
#[test]
fn indexed_http_serves_native_content_path_and_binary_results_for_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit) = fixture(&root, format);
        let before = generation(&node);
        let activation = build(&node, None);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 4, true, false);
        let found = post(&server.client, "search-index", 'a', &form(format), false);
        status(&found, 200);
        assert_eq!(text(&found.body, "type"), "source_search_index");
        assert_eq!(text(&found.body, "profile"), "ascii-word-postings-v1");
        assert_eq!(text(&found.body, "source_commit"), commit.to_string());
        assert_eq!(text(&found.body, "index_token"), index_token(&activation));
        assert_eq!(number(&found.body, "returned_hits"), 4);
        assert_eq!(number(&found.body, "indexed_documents"), 5);
        assert_eq!(number(&found.body, "non_regular_entries"), 2);
        assert!(found.body.contains("\"complete\":true,\"next_after\":null"));
        assert!(
            found
                .body
                .contains(&format!("\"path_hex\":\"{}\"", hex(BINARY_PATH)))
        );
        assert!(found.body.contains("\"byte_offset\":2,\"byte_length\":6"));
        assert!(
            found
                .body
                .contains("\"read_only\":true,\"transaction_created\":false,\"published\":false")
        );
        let nested = post(
            &server.client,
            "search-index",
            'a',
            &(form(format) + "&term_hex=4e4553544544&path_prefix_hex=646972"),
            true,
        );
        status(&nested, 200);
        assert_eq!(number(&nested.body, "returned_hits"), 1);
        assert!(nested.body.contains(&hex(b"dir/nested.txt")));
        let names = post(
            &server.client,
            "search-index",
            'a',
            &format!("{}&channel=path&term_hex=646174", common(format)),
            false,
        );
        status(&names, 200);
        assert_eq!(number(&names.body, "returned_hits"), 1);
        assert!(names.body.contains(&hex(BINARY_PATH)));
        let absent = post(
            &server.client,
            "search-index",
            'a',
            &format!("{}&term_hex=616273656e74", common(format)),
            false,
        );
        status(&absent, 200);
        assert!(absent.body.contains("\"hits\":[]"));
        assert!(absent.body.contains("\"complete\":true"));
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}
#[test]
fn index_continuation_uses_old_generation_and_shared_resource_limits() {
    let root = Scratch::new();
    let (node, commit) = fixture(&root, GitHashAlgorithm::Sha256);
    let first = build(&node, None);
    let second = build(&node, Some(&first));
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 5, true, false);
    let form = form(GitHashAlgorithm::Sha256);
    let first_page = format!(
        "{form}&limit=2&index_token={}&index_number={}&minimum_index_token={}&minimum_index_number={}",
        index_token(&first),
        first.authority_generation.get(),
        index_token(&second),
        second.authority_generation.get()
    );
    let page = post(&server.client, "search-index", 'a', &first_page, false);
    status(&page, 200);
    assert_eq!(text(&page.body, "index_token"), index_token(&first));
    assert_eq!(
        text(&page.body, "selected_index_token"),
        index_token(&second)
    );
    assert!(page.body.contains("\"complete\":false"));
    assert_eq!(number(&page.body, "next_after"), 2);
    let next = format!(
        "{first_page}&expected_head={}&expected_commit={commit}&after=2",
        token(&page)
    );
    let page = post(&server.client, "search-index", 'a', &next, true);
    status(&page, 200);
    assert!(page.body.contains("\"document_id\":3"));
    assert!(page.body.contains("\"document_id\":5"));
    assert!(page.body.contains("\"complete\":true,\"next_after\":null"));
    status(
        &post(
            &server.client,
            "search-index",
            'a',
            &(form.clone() + "&after=2"),
            false,
        ),
        400,
    );
    status(
        &post(
            &server.client,
            "search-index",
            'a',
            &(form.clone() + "&max_work=1"),
            false,
        ),
        413,
    );
    status(
        &post(
            &server.client,
            "search-index",
            'a',
            &(form + "&max_payload_bytes=1"),
            false,
        ),
        413,
    );
    assert_eq!(server.finish().accepted_sessions(), 5);
}
#[test]
fn indexed_reads_keep_independent_credentials_and_cannot_create_transactions() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    build(&node, None);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 6, true, false);
    let form = form(GitHashAlgorithm::Sha1);
    status(
        &post(&server.client, "search-index", 'b', &form, false),
        403,
    );
    status(
        &post(&server.client, "search-index", 'c', &form, false),
        403,
    );
    status(
        &post(&server.client, "search-index", 'd', &form, false),
        401,
    );
    let keyed = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/source/search-index",
            'a',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: no-index-write\r\n",
                form.len()
            ),
            form.as_bytes(),
        ),
        true,
    );
    status(&keyed, 400);
    assert!(!keyed.body.contains("\"outcome\""));
    status(
        &post(
            &server.client,
            "search-index",
            'a',
            &(form.clone() + "&build=true"),
            false,
        ),
        400,
    );
    status(
        &post(&server.client, "search-index", 'a', &form, false),
        200,
    );
    assert_eq!(server.finish().accepted_sessions(), 6);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
#[test]
fn index_missing_and_disabled_are_not_complete_empty_results() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, true, false);
    let missing = post(
        &server.client,
        "search-index",
        'a',
        &form(GitHashAlgorithm::Sha1),
        false,
    );
    status(&missing, 409);
    assert!(missing.body.contains("source_index_uninitialized"));
    assert!(!missing.body.contains("\"hits\""));
    assert_eq!(server.finish().accepted_sessions(), 1);
    let node = reopen(&config);
    build(&node, None);
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, false, false);
    status(
        &post(
            &server.client,
            "search-index",
            'a',
            &form(GitHashAlgorithm::Sha1),
            false,
        ),
        403,
    );
    assert_eq!(server.finish().accepted_sessions(), 1);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
#[test]
fn forge_only_publication_returns_stale_not_implicit_rebuild_over_http() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let activation = build(&node, None);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 2, true, true);
    let body = b"expected_version=0&title=Index+staleness&body=";
    let changed = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/issues/1/open",
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: indexed-http-staleness\r\n",
                body.len()
            ),
            body,
        ),
        true,
    );
    status(&changed, 200);
    let stale = post(
        &server.client,
        "search-index",
        'a',
        &form(GitHashAlgorithm::Sha1),
        false,
    );
    status(&stale, 409);
    assert!(stale.body.contains("source_index_stale"));
    assert!(!stale.body.contains("\"hits\""));
    assert_eq!(server.finish().accepted_sessions(), 2);
    let node = reopen(&config);
    let recovered = node
        .runtime()
        .block_on(node.recover_source_index_local_in(
            &node.request_context(),
            &RefName::try_new(b"refs/heads/main").unwrap(),
            activation.generation_id,
            None,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        recovered,
        fgit_graph::GenerationRecovery::Active { .. }
    ));
    node.shutdown().unwrap();
}
