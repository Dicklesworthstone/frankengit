#![forbid(unsafe_code)]
//! Production listener -> authenticated history reader -> embedded authority.
//! The shared source fixture contains an actual two-commit native Git graph.
#[path = "source_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_forge::history::LogOptions;
use fgit_node::LoopbackReceiveSession;
use fgit_types::{GitHashAlgorithm, RefName};

#[test]
fn native_log_pages_pin_complete_history_and_survive_reopen_without_a_transaction() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, main) = fixture(&root, format);
        let before = generation(&node);
        let (_, oracle) = node
            .runtime()
            .block_on(node.read_commit_history_in(
                &node.request_context(),
                &RefName::try_new(b"refs/heads/main").unwrap(),
                &Default::default(),
                None,
                LogOptions::default(),
            ))
            .unwrap();
        assert_eq!(oracle.total_commits, 2);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 8, true, false);
        let query = common(format);
        let first = post(
            &server.client,
            "log",
            'a',
            &(query.clone() + "&limit=1"),
            false,
        );
        status(&first, 200);
        assert_eq!(text(&first.body, "type"), "source_log");
        assert_eq!(text(&first.body, "source_commit"), main.to_string());
        assert_eq!(number(&first.body, "total_commits"), 2);
        assert_eq!(number(&first.body, "next_after"), 1);
        assert_eq!(text(&first.body, "body_hex"), hex(&oracle.commits[0].body));
        assert!(
            first
                .body
                .contains("\"transaction_created\":false,\"published\":false")
        );
        assert!(first.body.contains("\"author_identity_verified\":false"));
        let pin = token(&first);
        let tail_query = format!("{query}&after=1&limit=1&expected_head={pin}");
        let tail = post(&server.client, "log", 'a', &tail_query, true);
        status(&tail, 200);
        assert_eq!(token(&tail), pin);
        assert_eq!(
            text(&tail.body, "object_id"),
            oracle.commits[1].id.to_string()
        );
        assert_eq!(text(&tail.body, "body_hex"), hex(&oracle.commits[1].body));
        assert!(tail.body.contains("\"next_after\":null"));
        let end = post(
            &server.client,
            "log",
            'a',
            &format!("{query}&after=2&expected_head={pin}"),
            false,
        );
        status(&end, 200);
        assert!(end.body.contains("\"commits\":[]"));
        status(
            &post(
                &server.client,
                "log",
                'a',
                &(query.clone() + "&after=1"),
                false,
            ),
            400,
        );
        status(
            &post(
                &server.client,
                "log",
                'a',
                &format!("{query}&after=3&expected_head={pin}"),
                false,
            ),
            400,
        );
        let exhausted = post(
            &server.client,
            "log",
            'a',
            &(query.clone() + "&max_commits=1"),
            false,
        );
        status(&exhausted, 413);
        assert!(!exhausted.body.contains("\"commits\":[]"));
        status(
            &post(
                &server.client,
                "log",
                'a',
                &format!(
                    "{query}&expected_commit={}",
                    "e".repeat(format.digest_len() * 2)
                ),
                false,
            ),
            409,
        );
        let tree = post(&server.client, "tree", 'a', &query, false);
        status(&tree, 200);
        assert_eq!(token(&tree), pin);
        assert_eq!(server.finish().accepted_sessions(), 8);

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
        assert_eq!(
            post(&server.client, "log", 'a', &(query + "&limit=1"), true),
            first
        );
        assert_eq!(post(&server.client, "log", 'a', &tail_query, false), tail);
        assert_eq!(server.finish().accepted_sessions(), 2);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn history_requires_read_scope_before_ingress_and_honors_rotation_and_disable() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, _) = fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    let header = credentials(&node, &path);
    let server = Server::start(node, &path, 8, true, false);
    let query = common(format);
    let valid = post(&server.client, "log", 'a', &query, false);
    status(&valid, 200);
    // No body is supplied. The write-only credential must be refused before
    // ingress, rather than waiting for input or treating write scope as read.
    let denied = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/source/log",
            'b',
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\n",
            &[],
        ),
        true,
    );
    status(&denied, 403);
    status(&post(&server.client, "log", 'c', &query, false), 403);
    status(&post(&server.client, "log", 'd', &query, false), 401);
    let key = exchange(
        &server.client,
        &request(
            &server.client,
            "/api/v1/source/log",
            'a',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: forbidden-read-key\r\n",
                query.len()
            ),
            query.as_bytes(),
        ),
        true,
    );
    status(&key, 400);
    let mut foreign = server.client.clone();
    foreign.route = "/another.git".into();
    status(&post(&foreign, "log", 'a', &query, false), 404);
    replace(&path, &(header + &row('9', OWNER, "read")));
    status(&post(&server.client, "log", 'a', &query, false), 401);
    assert_eq!(post(&server.client, "log", '9', &query, true), valid);
    assert_eq!(server.finish().accepted_sessions(), 8);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 1, false, false);
    let disabled = post(&server.client, "log", '9', &query, false);
    status(&disabled, 403);
    assert!(!disabled.body.contains("body_hex"));
    assert_eq!(server.finish().accepted_sessions(), 1);
}

#[test]
fn even_an_unrelated_authority_write_invalidates_history_continuations() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new();
    let config = root.config(format);
    let (node, main) = fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 5, true, true);
    let query = common(format);
    let first = post(
        &server.client,
        "log",
        'a',
        &(query.clone() + "&limit=1"),
        false,
    );
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
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: history-pin-race\r\n",
                body.len()
            ),
            body,
        ),
        true,
    );
    status(&write, 200);
    let stale = post(
        &server.client,
        "log",
        'a',
        &format!("{query}&after=1&expected_head={pin}"),
        false,
    );
    status(&stale, 409);
    assert!(stale.body.contains("source_snapshot_moved"));
    assert!(!stale.body.contains("body_hex"));
    let current = post(
        &server.client,
        "log",
        'a',
        &format!("{query}&limit=1&expected_commit={main}"),
        true,
    );
    status(&current, 200);
    assert_ne!(token(&current), pin);
    assert_eq!(text(&current.body, "source_commit"), main.to_string());
    let tail = post(
        &server.client,
        "log",
        'a',
        &format!("{query}&after=1&expected_head={}", token(&current)),
        false,
    );
    status(&tail, 200);
    assert_eq!(server.finish().accepted_sessions(), 5);
    let node = reopen(&config);
    assert_eq!(generation(&node), before + 1);
    node.shutdown().unwrap();
}
