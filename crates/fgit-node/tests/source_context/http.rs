//! Production credentialed TCP route, native index owners and exact blobs.
use super::*;
fn form(format: GitHashAlgorithm) -> String {
    format!(
        "object_format={}&ref=refs/heads/main&term_hex=5468696e67&symbol_name_hex=5468696e67&symbol_match=prefix",
        format.as_str()
    )
}
fn floor(pin: &fgit_graph::GenerationActivation, number: u64) -> String {
    let id = pin.generation_id.as_internal_object_id();
    format!(
        "&minimum_lexical_token=alg:{}:{}&minimum_lexical_number={number}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}

#[test]
fn authenticated_context_returns_exact_native_bytes_once_per_file_and_keeps_index_only_reads_unchanged()
 {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, _) = corpus(&root, format, true);
        let canonical = generation(&node);
        let original = initial(&node, b"Thing", true, &[]);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 7, true, false);
        let input = form(format);
        let first = post(&server.client, "context-initial", 'a', &input, false);
        status(&first, 200);
        assert_eq!(text(&first.body, "type"), "source_context_initial");
        assert_eq!(text(&first.body, "profile"), "source-initial-context-v1");
        assert_eq!(number(&first.body, "source_blobs_read"), 4);
        assert_eq!(number(&first.body, "returned_files"), 4);
        assert_eq!(number(&first.body, "omitted_files"), 0);
        assert_eq!(
            number(&first.body, "source_bytes_read") as usize,
            INPUTS.iter().map(|(_, b)| b.len()).sum::<usize>()
        );
        assert_eq!(text(&first.body, "untrusted_bytes_hex"), hex(A));
        assert!(first.body.contains(&hex(INPUTS[3].0)));
        assert!(first.body.contains(&hex(C)));
        assert!(!first.body.contains("Ignore previous instructions"));
        assert!(first.body.contains("\"source_material_untrusted\":true"));
        assert!(first.body.contains("\"transaction_created\":false"));
        assert!(first.body.contains("\"generation_vector\":"));
        assert!(
            first
                .body
                .contains("\"host\":\"http-repository-read-credential\"")
        );
        assert_eq!(first.body.matches("\"authorization_labels\":[").count(), 4);
        // Four files and four excerpts each retain the same file-level profile.
        assert_eq!(first.body.matches("\"lineage_commitment\":").count(), 8);
        assert_eq!(text(&first.body, "lineage_commitment").len(), 64);
        assert!(
            first
                .body
                .contains("\"position_domain\":\"raw-path-bytes\"")
        );
        let chunked = post(&server.client, "context-initial", 'a', &input, true);
        status(&chunked, 200);
        assert_eq!(chunked.body, first.body);
        let scoped = post(
            &server.client,
            "context-initial",
            'a',
            &(input.clone() + "&path_prefix_hex=61"),
            false,
        );
        status(&scoped, 200);
        assert_eq!(number(&scoped.body, "returned_files"), 1);
        assert_eq!(number(&scoped.body, "candidate_files"), 1);
        assert_eq!(number(&scoped.body, "source_blobs_read"), 1);
        assert_eq!(text(&scoped.body, "untrusted_bytes_hex"), hex(A));
        let capped = post(
            &server.client,
            "context-initial",
            'a',
            &(input.clone() + "&context_max_files=1"),
            true,
        );
        status(&capped, 200);
        assert_eq!(number(&capped.body, "omitted_files"), 3);
        assert_eq!(number(&capped.body, "source_blobs_read"), 1);
        assert!(
            capped
                .body
                .split_once("\"complete\":")
                .unwrap()
                .1
                .starts_with("false")
        );
        let read = post(&server.client, "search-initial", 'a', &input, false);
        status(&read, 200);
        assert_eq!(number(&read.body, "source_blobs_read"), 0);
        assert!(!read.body.contains("untrusted_bytes_hex"));
        status(
            &post(
                &server.client,
                "search-initial",
                'a',
                &(input + "&context_max_files=1"),
                false,
            ),
            400,
        );
        let empty = format!(
            "object_format={}&ref=refs/heads/main&term_hex={}",
            format.as_str(),
            hex(b"NoSuchToken")
        );
        let reply = post(&server.client, "context-initial", 'a', &empty, true);
        status(&reply, 200);
        assert_eq!(number(&reply.body, "returned_files"), 0);
        assert_eq!(number(&reply.body, "source_blobs_read"), 0);
        assert!(reply.body.contains("\"files\":[]"));
        assert_eq!(server.finish().accepted_sessions(), 7);
        let node = reopen(&config);
        assert_eq!(
            initial(&node, b"Thing", true, &[]).generations(),
            original.generations()
        );
        assert_eq!(generation(&node), canonical);
        node.shutdown().unwrap();
    }
}

#[test]
fn authorization_limits_and_checkpoint_failures_never_disclose_a_partial_context() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = corpus(&root, format, true);
    let canonical = generation(&node);
    let report = initial(&node, b"Thing", true, &[]);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 11, true, false);
    let input = form(format);
    let pin = &report.generations().lexical;
    for (principal, suffix, expected) in [
        ('b', String::new(), 403),
        ('z', String::new(), 401),
        ('a', "&context_max_files=0".into(), 400),
        ('a', "&context_radius_bytes=4097".into(), 400),
        ('a', "&context_max_files=1&context_max_files=2".into(), 400),
        ('a', "&force=true".into(), 400),
        ('a', "&context_max_excerpt_bytes=1".into(), 413),
        ('a', "&max_work=3".into(), 413),
        ('a', floor(pin, pin.authority_generation.get() + 1), 409),
    ] {
        let reply = post(
            &server.client,
            "context-initial",
            principal,
            &(input.clone() + &suffix),
            false,
        );
        status(&reply, expected);
        assert!(!reply.body.contains("untrusted_bytes_hex"));
        assert!(!reply.body.contains("\"retrieval\":{"));
    }
    let headers = format!(
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: no-context-write\r\n",
        input.len()
    );
    let bytes = request(
        &server.client,
        "/api/v1/source/context-initial",
        'a',
        &headers,
        input.as_bytes(),
    );
    status(&exchange(&server.client, &bytes, true), 400);
    let refused = post(
        &server.client,
        "context-initial",
        'a',
        &(input
            + &format!(
                "&context_max_files=1&context_max_source_bytes={}",
                A.len() - 1
            )),
        false,
    );
    assert!(refused.status >= 400);
    assert!(!refused.body.contains("untrusted_bytes_hex"));
    assert_eq!(server.finish().accepted_sessions(), 11);
    let node = reopen(&config);
    assert_eq!(
        initial(&node, b"Thing", true, &[]).generations(),
        report.generations()
    );
    assert_eq!(generation(&node), canonical);
    node.shutdown().unwrap();
}

#[test]
fn optional_symbols_and_credential_revocation_keep_their_original_meaning() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = corpus(&root, format, false);
    let path = root.0.join("credentials");
    let header = credentials(&node, &path);
    let server = Server::start(node, &path, 3, true, false);
    let input = form(format);
    let partial = post(&server.client, "context-initial", 'a', &input, false);
    status(&partial, 200);
    assert_eq!(number(&partial.body, "source_blobs_read"), 3);
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
    let strict = post(
        &server.client,
        "context-initial",
        'a',
        &(input.clone() + "&symbol_policy=required"),
        true,
    );
    status(&strict, 409);
    assert!(!strict.body.contains("untrusted_bytes_hex"));
    replace(&path, &(header + &row('c', OWNER, "outcomes-read")));
    status(
        &post(&server.client, "context-initial", 'a', &input, false),
        401,
    );
    assert_eq!(server.finish().accepted_sessions(), 3);
    let node = reopen(&config);
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, false, false);
    status(
        &post(&server.client, "context-initial", 'a', &input, false),
        403,
    );
    assert_eq!(server.finish().accepted_sessions(), 1);
}
