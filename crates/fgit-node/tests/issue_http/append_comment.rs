use super::*;

#[test]
fn append_comments_survive_intervening_changes_without_weakening_strict_commands_or_auth() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = start_node(configuration.clone());
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .basis()
            .generation();
        let path = root.0.join("credentials");
        grants(&node, &path);
        let server = Server::start(node, path, 16, true);
        committed(&post(
            &server,
            "/api/v1/issues/1/open",
            'b',
            "open",
            "expected_version=0&title=Original&body=Immutable",
            false,
        )); // 1
        for token in ['a', 'd'] {
            status(
                &post(
                    &server,
                    "/api/v1/issues/1/append-comment",
                    token,
                    "denied",
                    "body=Denied",
                    false,
                ),
                403,
            );
        } // 2, 3
        status(
            &post(
                &server,
                "/api/v1/issues/1/append-comment",
                'b',
                "invalid-version",
                "expected_version=1&body=Do+not+discard+this+version",
                false,
            ),
            400,
        ); // 4
        let body = "body=First+%F0%9F%A6%80%0A%252f";
        let first = post(
            &server,
            "/api/v1/issues/1/append-comment",
            'b',
            "append-first",
            body,
            true,
        ); // 5
        committed(&first);
        assert!(first.body.contains("\"action\":\"append-comment\""));
        assert!(first.body.contains("\"expected_version\":null"));
        assert!(
            first
                .body
                .contains(&format!("\"principal_id\":\"{}\"", principal(0xb1)))
        );
        let stale = post(
            &server,
            "/api/v1/issues/1/comment",
            'b',
            "strict-stale",
            "expected_version=1&body=Stale+strict+comment",
            false,
        ); // 6
        status(&stale, 409);
        assert!(stale.body.contains("\"outcome\":\"refused\""));
        assert!(stale.body.contains("\"action\":\"comment\""));
        assert!(stale.body.contains("\"expected_version\":1"));
        committed(&post(
            &server,
            "/api/v1/issues/1/comment",
            'b',
            "strict-comment",
            "expected_version=2&body=Strict",
            false,
        )); // 7
        committed(&post(
            &server,
            "/api/v1/issues/1/edit",
            'c',
            "edit",
            "expected_version=3&title=Renamed",
            false,
        )); // 8
        committed(&post(
            &server,
            "/api/v1/issues/1/append-comment",
            'b',
            "append-second",
            "body=Second",
            false,
        )); // 9
        let retry = post(
            &server,
            "/api/v1/issues/1/append-comment",
            'b',
            "append-first",
            body,
            false,
        ); // 10
        assert_eq!(
            retry.body, first.body,
            "retries retain the first canonical outcome"
        );
        for (action, body) in [
            ("append-comment", "body=Changed"),
            (
                "comment",
                "expected_version=4&body=First+%F0%9F%A6%80%0A%252f",
            ),
        ] {
            let reuse = post(
                &server,
                &format!("/api/v1/issues/1/{action}"),
                'b',
                "append-first",
                body,
                false,
            );
            status(&reuse, 409);
            assert!(reuse.body.contains("\"code\":\"idempotency_key_reuse\""));
        } // 11, 12
        let current = get(&server, "/api/v1/issues/1", 'a'); // 13
        status(&current, 200);
        assert!(current.body.contains("\"version\":5"));
        assert!(current.body.contains("\"comments\":3"));
        assert!(
            current
                .body
                .contains("\"name\":\"comment\",\"body\":\"First 🦀\\u000a%2f\"")
        );
        assert!(!current.body.contains("\"name\":\"append-comment\""));
        let missing = post(
            &server,
            "/api/v1/issues/2/append-comment",
            'b',
            "missing-issue",
            "body=Missing",
            false,
        ); // 14
        status(&missing, 409);
        assert!(missing.body.contains("\"outcome\":\"refused\""));
        let missing_retry = post(
            &server,
            "/api/v1/issues/2/append-comment",
            'b',
            "missing-issue",
            "body=Missing",
            true,
        ); // 15
        assert_eq!(missing_retry.body, missing.body);
        status(
            &post(
                &server,
                "/api/v1/issues/1/append-comment",
                'b',
                "forged-principal",
                "body=Forged&principal=admin",
                false,
            ),
            400,
        ); // 16
        assert_eq!(server.finish().accepted_sessions(), 16);

        let node = reopened(configuration);
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            selected.basis().generation().get(),
            before.get() + 7,
            "five commits and two refusals; denied, malformed and retried requests publish nothing"
        );
        assert!(selected.snapshot().refs.is_empty());
        let history = node
            .runtime()
            .block_on(node.read_issue_history_in(
                &node.request_context(),
                IssueNumber::FIRST,
                0,
                10,
                None,
            ))
            .unwrap();
        let issue = history.issue.unwrap();
        assert_eq!(issue.title, "Renamed");
        assert_eq!(issue.body, "Immutable");
        assert_eq!(issue.version.get(), 5);
        assert_eq!(issue.comments, 3);
        assert_eq!(issue.last_actor, principal(0xb1));
        assert_eq!(history.events.len(), 5);
        node.shutdown().unwrap();
    }
}
