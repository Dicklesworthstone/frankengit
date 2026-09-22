//! Exercise joined retrieval through the actual credentialed TCP server.
use super::*;
fn form(format: GitHashAlgorithm) -> String {
    format!(
        "object_format={}&ref=refs/heads/main&term_hex=5468696e67&symbol_name_hex=5468696e67&symbol_match=prefix",
        format.as_str()
    )
}
fn floor(pin: &fgit_graph::GenerationActivation, channel: &str, number: u64) -> String {
    let id = pin.generation_id.as_internal_object_id();
    format!(
        "&minimum_{channel}_token=alg:{}:{}&minimum_{channel}_number={number}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}

#[test]
fn authenticated_initial_http_returns_one_vector_with_native_channels_and_shared_limits() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, _) = corpus(&root, format);
        let pins = build(&node, true);
        let canonical = generation(&node);
        let credentials_path = root.0.join("credentials");
        credentials(&node, &credentials_path);
        let input = form(format) + "&symbol_policy=required";
        let server = Server::start(node, &credentials_path, 14, true, false);
        let first = post(&server.client, "search-initial", 'a', &input, false);
        status(&first, 200);
        assert!(first.body.contains("\"type\":\"source_search_initial\""));
        assert!(first.body.contains("\"phase\":\"Initial\""));
        assert!(first.body.contains("\"generation_vector\":{\"lexical\":{"));
        assert!(
            first
                .body
                .contains("\"symbols\":{\"state\":\"available\",\"result\":{")
        );
        assert!(
            first
                .body
                .split_once("\"complete\":")
                .unwrap()
                .1
                .starts_with("true")
        );
        assert_eq!(number(&first.body, "source_blobs_read"), 0);
        assert_eq!(number(&first.body, "returned_hits"), 3);
        assert_eq!(number(&first.body, "returned_matches"), 2);
        let chunked = post(&server.client, "search-initial", 'a', &input, true);
        status(&chunked, 200);
        assert_eq!(chunked.body, first.body);
        let scoped = post(
            &server.client,
            "search-initial",
            'a',
            &(input.clone() + "&path_prefix_hex=737263"),
            true,
        );
        status(&scoped, 200);
        assert_eq!(number(&scoped.body, "returned_hits"), 2);
        assert_eq!(number(&scoped.body, "returned_matches"), 1);
        assert!(!scoped.body.contains(&hex(b"src2/Thing.rs")));
        let limited = post(
            &server.client,
            "search-initial",
            'a',
            &(input.clone() + "&max_results_per_channel=1"),
            false,
        );
        status(&limited, 200);
        assert!(
            limited
                .body
                .split_once("\"complete\":")
                .unwrap()
                .1
                .starts_with("false")
        );
        assert_eq!(number(&limited.body, "returned_hits"), 1);
        let high = pins.lexical.as_ref().unwrap();
        let other_format = if format == GitHashAlgorithm::Sha1 {
            "sha256"
        } else {
            "sha1"
        };
        for (token, body, expected) in [
            ('b', input.clone(), 403),
            ('z', input.clone(), 401),
            (
                'a',
                input.replacen(
                    &format!("object_format={}", format.as_str()),
                    &format!("object_format={other_format}"),
                    1,
                ),
                400,
            ),
            ('a', input.clone() + "&force=true", 400),
            ('a', input.clone() + "&symbol_policy=optional", 400),
            ('a', input.clone() + "&minimum_lexical_number=1", 400),
            ('a', input.clone() + "&max_payload_bytes=3", 413),
            ('a', input.clone() + "&max_work=3", 413),
            (
                'a',
                input.clone() + &floor(high, "lexical", high.authority_generation.get() + 1),
                409,
            ),
        ] {
            let refused = post(&server.client, "search-initial", token, &body, false);
            status(&refused, expected);
            assert!(!refused.body.contains("\"content\":{"));
        }
        let headers = format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: no-read-transaction\r\n",
            input.len()
        );
        let bytes = request(
            &server.client,
            "/api/v1/source/search-initial",
            'a',
            &headers,
            input.as_bytes(),
        );
        status(&exchange(&server.client, &bytes, true), 400);
        assert_eq!(server.finish().accepted_sessions(), 14);
        let node = reopen(&config);
        let again = initial(
            &node,
            &query(SymbolPolicy::Required, &[]),
            &pins,
            Default::default(),
        )
        .unwrap();
        assert_eq!(Some(again.generations().lexical.clone()), pins.lexical);
        assert_eq!(again.generations().symbols, pins.symbols);
        assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
    }
}

#[test]
fn optional_missing_symbols_are_explicit_and_never_trigger_http_index_maintenance() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = corpus(&root, format);
    let pins = build(&node, false);
    let canonical = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 3, true, false);
    let input = form(format);
    let partial = post(&server.client, "search-initial", 'a', &input, false);
    status(&partial, 200);
    assert!(
        partial
            .body
            .split_once("\"complete\":")
            .unwrap()
            .1
            .starts_with("false")
    );
    assert!(
        partial
            .body
            .contains("\"state\":\"unavailable\",\"reason\":\"uninitialized\"")
    );
    assert!(partial.body.contains("\"result\":null"));
    assert_eq!(number(&partial.body, "returned_hits"), 3);
    let strict = post(
        &server.client,
        "search-initial",
        'a',
        &(input.clone() + "&symbol_policy=required"),
        false,
    );
    status(&strict, 409);
    assert!(!strict.body.contains("\"content\":{"));
    let pin = pins.lexical.as_ref().unwrap();
    let pinned = post(
        &server.client,
        "search-initial",
        'a',
        &(input + &floor(pin, "symbol", pin.authority_generation.get())),
        true,
    );
    status(&pinned, 409);
    assert!(!pinned.body.contains("\"content\":{"));
    assert_eq!(server.finish().accepted_sessions(), 3);
    let node = reopen(&config);
    let unchanged = initial(
        &node,
        &query(SymbolPolicy::Optional, &[]),
        &pins,
        Default::default(),
    )
    .unwrap();
    assert!(matches!(
        unchanged.symbols(),
        SymbolChannel::Unavailable(SymbolUnavailable::Uninitialized)
    ));
    assert_eq!(generation(&node), canonical);
    node.shutdown().unwrap();
}

#[test]
fn read_scope_revocation_and_disabled_source_service_apply_to_the_combined_endpoint() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = corpus(&root, format);
    build(&node, true);
    let path = root.0.join("credentials");
    let header = credentials(&node, &path);
    let server = Server::start(node, &path, 2, true, false);
    status(
        &post(&server.client, "search-initial", 'a', &form(format), false),
        200,
    );
    replace(&path, &(header + &row('c', OWNER, "outcomes-read")));
    status(
        &post(&server.client, "search-initial", 'a', &form(format), false),
        401,
    );
    server.finish();
    let node = reopen(&config);
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, false, false);
    status(
        &post(&server.client, "search-initial", 'a', &form(format), false),
        403,
    );
    server.finish();
}
