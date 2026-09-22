#![forbid(unsafe_code)]
//! Production HTTP -> verified native line ancestry -> embedded authority.
//! The transport must not widen a selected line range or create a transaction.
#[path = "source_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_forge::history::{BlameOptions, HistoryLimits};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{GitHashAlgorithm, RefName};

#[test]
fn blame_returns_exact_requested_lines_and_origin_records_in_both_formats_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, main) = fixture(&root, format);
        let before = generation(&node);
        let options = BlameOptions {
            path: b"alpha.txt".to_vec(),
            first_line: 0,
            end_line: None,
            limits: HistoryLimits::default(),
        };
        let (_, direct) = node
            .runtime()
            .block_on(node.blame_source_in(
                &node.request_context(),
                &RefName::try_new(b"refs/heads/main").unwrap(),
                &Default::default(),
                None,
                &options,
            ))
            .unwrap();
        assert_eq!(direct.content, TEXT);
        assert_eq!(direct.total_lines, 2);
        assert_eq!(direct.origins.len(), 1);
        assert!(direct.lines.iter().all(|line| line.origin_commit == main));
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 12, true, false);
        let query = format!("{}&path_hex={}", common(format), hex(b"alpha.txt"));
        let full = post(&server.client, "blame", 'a', &query, false); // 1
        status(&full, 200);
        assert_eq!(text(&full.body, "type"), "source_blame");
        assert_eq!(text(&full.body, "profile"), "exact-lines-all-parents-v1");
        assert_eq!(text(&full.body, "source_commit"), main.to_string());
        assert_eq!(text(&full.body, "content_hex"), hex(TEXT));
        assert_eq!(text(&full.body, "body_hex"), hex(&direct.origins[0].body));
        assert_eq!(number(&full.body, "graph_commits"), 2);
        assert_eq!(number(&full.body, "total_lines"), 2);
        assert!(
            full.body
                .contains("\"transaction_created\":false,\"published\":false")
        );
        assert!(full.body.contains("\"author_identity_verified\":false"));
        let pin = token(&full);
        let range_query = format!("{query}&line_start=1&line_end=2&expected_head={pin}");
        let range = post(&server.client, "blame", 'a', &range_query, true); // 2
        status(&range, 200);
        assert_eq!(token(&range), pin);
        assert_eq!(text(&range.body, "content_hex"), hex(b"ababa\n"));
        assert_eq!(number(&range.body, "content_byte_start"), 15);
        assert_eq!(number(&range.body, "first_line"), 1);
        assert_eq!(number(&range.body, "end_line"), 2);
        assert_eq!(number(&range.body, "origin_line"), 1);
        assert_eq!(number(&range.body, "origin_byte_start"), 15);
        assert_eq!(number(&range.body, "origin_byte_end"), TEXT.len() as u64);
        assert!(!range.body.contains(&hex(b"Needle needle\r\n")));
        let end = post(
            &server.client,
            "blame",
            'a',
            &format!("{query}&line_start=2&line_end=2&expected_head={pin}"),
            false,
        ); // 3
        status(&end, 200);
        assert_eq!(text(&end.body, "content_hex"), "");
        assert!(end.body.contains("\"origins\":[],\"lines\":[]"));
        let binary = post(
            &server.client,
            "blame",
            'a',
            &format!("{}&path_hex={}", common(format), hex(BINARY_PATH)),
            false,
        ); // 4
        status(&binary, 409);
        assert!(binary.body.contains("binary_blame_unsupported"));
        assert!(!binary.body.contains("content_hex"));
        let link = post(
            &server.client,
            "blame",
            'a',
            &format!("{}&path_hex={}", common(format), hex(b"link/secret")),
            false,
        ); // 5
        status(&link, 404);
        assert!(!link.body.contains("outside-secret"));
        let invalid = post(
            &server.client,
            "blame",
            'a',
            &format!("{}&path_hex={}", common(format), hex(b"../secret")),
            false,
        ); // 6
        status(&invalid, 400);
        for extra in ["&max_commits=1", "&max_lines=1"] {
            // 7, 8
            let exhausted = post(
                &server.client,
                "blame",
                'a',
                &(query.clone() + extra),
                false,
            );
            status(&exhausted, 413);
            assert!(!exhausted.body.contains("\"lines\":[]"));
        }
        let other_format = if format == GitHashAlgorithm::Sha1 {
            "sha256"
        } else {
            "sha1"
        };
        status(
            &post(
                &server.client,
                "blame",
                'a',
                &query.replacen(format.as_str(), other_format, 1),
                false,
            ),
            400,
        ); // 9
        status(
            &post(
                &server.client,
                "blame",
                'a',
                &format!("{}&path_hex=616273656e74ff", common(format)),
                false,
            ),
            404,
        ); // 10
        let moved = post(
            &server.client,
            "blame",
            'a',
            &format!(
                "{query}&expected_commit={}",
                "e".repeat(format.digest_len() * 2)
            ),
            false,
        ); // 11
        status(&moved, 409);
        assert!(moved.body.contains("source_commit_moved"));
        let empty = post(
            &server.client,
            "blame",
            'a',
            &format!("{}&path_hex=656d707479", common(format)),
            false,
        ); // 12
        status(&empty, 200);
        assert_eq!(number(&empty.body, "total_lines"), 0);
        assert_eq!(text(&empty.body, "content_hex"), "");
        assert_eq!(server.finish().accepted_sessions(), 12);

        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        let sentinel = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"read-only-source-query".to_vec()).unwrap(),
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.recover_transaction_in(&node.request_context(), &sentinel))
                .unwrap(),
            RequestRecovery::KeyNotObserved
        ));
        let server = Server::start(node, &path, 2, true, false);
        assert_eq!(post(&server.client, "blame", 'a', &query, true), full);
        assert_eq!(
            post(&server.client, "blame", 'a', &range_query, false),
            range
        );
        assert_eq!(server.finish().accepted_sessions(), 2);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn blame_is_read_scoped_before_ingress_and_disabled_without_source_service() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    let header = credentials(&node, &path);
    let server = Server::start(node, &path, 8, true, false);
    let query = format!("{}&path_hex={}", common(format), hex(b"alpha.txt"));
    let permitted = post(&server.client, "blame", 'a', &query, false); // 1
    status(&permitted, 200);
    let denied = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/source/blame",
            'b',
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\n",
            &[],
        ),
        true,
    ); // 2
    status(&denied, 403);
    assert!(!denied.body.contains("content_hex") && !denied.raw.contains("100 Continue"));
    status(&post(&server.client, "blame", 'c', &query, false), 403); // 3
    status(&post(&server.client, "blame", 'd', &query, false), 401); // 4
    let key = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/source/blame",
            'a',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: blame-must-not-seal\r\n",
                query.len()
            ),
            query.as_bytes(),
        ),
        true,
    ); // 5
    status(&key, 400);
    let mut foreign = server.client.clone();
    foreign.route = "/another.git".into();
    status(&post(&foreign, "blame", 'a', &query, false), 404); // 6
    replace(&path, &(header + &row('9', OWNER, "read")));
    status(&post(&server.client, "blame", 'a', &query, false), 401); // 7
    assert_eq!(post(&server.client, "blame", '9', &query, true), permitted); // 8
    assert_eq!(server.finish().accepted_sessions(), 8);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 1, false, false);
    status(&post(&server.client, "blame", '9', &query, false), 403);
    assert_eq!(server.finish().accepted_sessions(), 1);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn blame_ranges_cannot_mix_snapshots_across_an_intervening_authority_write() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, main) = fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 5, true, true);
    let query = format!("{}&path_hex={}", common(format), hex(b"alpha.txt"));
    let first = post(
        &server.client,
        "blame",
        'a',
        &(query.clone() + "&line_end=1"),
        false,
    ); // 1
    status(&first, 200);
    let pin = token(&first);
    let body = b"expected_version=0&title=Intervening+write&body=";
    let write = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/issues/1/open",
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: blame-pin-race\r\n",
                body.len()
            ),
            body,
        ),
        true,
    ); // 2
    status(&write, 200);
    let stale = post(
        &server.client,
        "blame",
        'a',
        &format!("{query}&line_start=1&expected_head={pin}"),
        false,
    ); // 3
    status(&stale, 409);
    assert!(stale.body.contains("source_snapshot_moved"));
    assert!(!stale.body.contains("content_hex"));
    let current = post(
        &server.client,
        "blame",
        'a',
        &format!("{query}&expected_commit={main}"),
        true,
    ); // 4
    status(&current, 200);
    assert_ne!(token(&current), pin);
    assert_eq!(text(&current.body, "content_hex"), hex(TEXT));
    let range = post(
        &server.client,
        "blame",
        'a',
        &format!("{query}&line_start=1&expected_head={}", token(&current)),
        false,
    ); // 5
    status(&range, 200);
    assert_eq!(text(&range.body, "content_hex"), hex(b"ababa\n"));
    assert_eq!(server.finish().accepted_sessions(), 5);
    let node = reopen(&config);
    assert_eq!(generation(&node), before + 1);
    node.shutdown().unwrap();
}
