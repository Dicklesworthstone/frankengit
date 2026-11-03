//! Authenticated label additions through TCP, canonical admission and reopen.
use super::*;

#[test]
fn additive_labels_preserve_auth_replacement_history_and_original_outcomes_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = start_node(configuration.clone());
        let path = root.0.join("credentials");
        grants(&node, &path);
        let server = Server::start(node, path.clone(), 19, true);
        committed(&post(
            &server,
            "/api/v1/issues/1/open",
            'b',
            "open",
            "expected_version=0&title=Original&body=Immutable&label=baseline",
            false,
        )); // 1
        let form = "label=gamma&label=beta";
        for token in ['a', 'd'] {
            status(
                &post(
                    &server,
                    "/api/v1/issues/1/add-labels",
                    token,
                    "denied",
                    form,
                    false,
                ),
                403,
            );
        } // 2, 3
        status(
            &post(
                &server,
                "/api/v1/issues/1/add-labels",
                'b',
                "invalid-version",
                &format!("{form}&expected_version=1"),
                false,
            ),
            400,
        ); // 4
        status(
            &post(
                &server,
                "/api/v1/issues/1/add-labels",
                'b',
                "duplicate-label",
                &format!("{form}&label=beta"),
                false,
            ),
            400,
        ); // 5
        let original = post(
            &server,
            "/api/v1/issues/1/add-labels",
            'b',
            "add-first",
            form,
            true,
        ); // 6
        committed(&original);
        assert!(original.body.contains("\"action\":\"add-labels\""));
        assert!(
            original
                .body
                .contains("\"command_profile\":\"issue.add-labels.v1\"")
        );
        assert!(original.body.contains("\"expected_version\":null"));
        assert!(
            original
                .body
                .contains(&format!("\"principal_id\":\"{}\"", principal(0xb1)))
        );
        let stale = post(
            &server,
            "/api/v1/issues/1/edit",
            'b',
            "strict-stale",
            "expected_version=1&label=replacement",
            false,
        ); // 7
        status(&stale, 409);
        assert!(stale.body.contains("\"refusal_code\":\"EvidenceStale\""));
        assert!(stale.body.contains("\"expected_version\":1"));
        committed(&post(
            &server,
            "/api/v1/issues/1/edit",
            'c',
            "edit",
            "expected_version=2&title=Renamed",
            false,
        )); // 8
        committed(&post(
            &server,
            "/api/v1/issues/1/add-labels",
            'b',
            "add-second",
            "label=gamma&label=alpha",
            false,
        )); // 9
        let retry = post(
            &server,
            "/api/v1/issues/1/add-labels",
            'b',
            "add-first",
            "label=beta&label=gamma",
            false,
        ); // 10
        assert_eq!(retry.body, original.body);
        for (action, body) in [
            ("add-labels", "label=beta"),
            ("edit", "expected_version=1&label=beta&label=gamma"),
        ] {
            let reuse = post(
                &server,
                &format!("/api/v1/issues/1/{action}"),
                'b',
                "add-first",
                body,
                false,
            );
            status(&reuse, 409);
            assert!(reuse.body.contains("\"code\":\"idempotency_key_reuse\""));
        } // 11, 12
        let current = get(&server, "/api/v1/issues/1", 'a'); // 13
        status(&current, 200);
        assert!(current.body.contains("\"version\":4"));
        assert!(current.body.contains("\"title\":\"Renamed\""));
        assert!(
            current
                .body
                .contains("\"labels\":[\"alpha\",\"baseline\",\"beta\",\"gamma\"]")
        );
        assert!(
            current
                .body
                .contains("\"name\":\"add-labels\",\"labels\":[\"beta\",\"gamma\"]")
        );
        let missing = post(
            &server,
            "/api/v1/issues/2/add-labels",
            'b',
            "missing",
            form,
            false,
        ); // 14
        status(&missing, 409);
        assert!(missing.body.contains("\"refusal_code\":\"EvidenceStale\""));
        let missing_retry = post(
            &server,
            "/api/v1/issues/2/add-labels",
            'b',
            "missing",
            form,
            true,
        ); // 15
        assert_eq!(missing_retry.body, missing.body);
        status(
            &post(
                &server,
                "/api/v1/issues/1/add-labels",
                'b',
                "forged-actor",
                &format!("{form}&principal={}", principal(0xa1)),
                false,
            ),
            400,
        ); // 16
        committed(&post(
            &server,
            "/api/v1/issues/1/edit",
            'b',
            "replace-later",
            "expected_version=4&label=kept",
            false,
        )); // 17
        let replay = post(
            &server,
            "/api/v1/issues/1/add-labels",
            'b',
            "add-first",
            form,
            false,
        ); // 18
        assert_eq!(
            replay.body, original.body,
            "original recovery must not restore removed labels"
        );
        let replaced = get(&server, "/api/v1/issues/1", 'a'); // 19
        status(&replaced, 200);
        assert!(replaced.body.contains("\"version\":5"));
        assert!(replaced.body.contains("\"labels\":[\"kept\"]"));
        assert_eq!(server.finish().accepted_sessions(), 19);

        let node = reopened(configuration.clone());
        let before_retry = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let server = Server::start(node, path, 2, true);
        let replay = post(
            &server,
            "/api/v1/issues/1/add-labels",
            'b',
            "add-first",
            form,
            false,
        );
        assert_eq!(replay.body, original.body);
        let historical = get(
            &server,
            &format!("/api/v1/issues/1?expected_head={}", token(&current)),
            'a',
        );
        assert_eq!(historical.body, current.body);
        assert_eq!(server.finish().accepted_sessions(), 2);

        let node = reopened(configuration);
        let request = node.request_context();
        let history = node
            .runtime()
            .block_on(node.read_issue_history_in(&request, IssueNumber::FIRST, 0, 10, None))
            .unwrap();
        let issue = history.issue.unwrap();
        assert_eq!(issue.labels, ["kept"]);
        assert_eq!(issue.version.get(), 5);
        assert_eq!(issue.title, "Renamed");
        assert_eq!(issue.body, "Immutable");
        assert_eq!(issue.comments, 0);
        assert_eq!(history.events.len(), 5);
        let settled = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(settled.basis(), before_retry.basis());
        assert!(settled.snapshot().refs.is_empty());
        node.shutdown().unwrap();
    }
}
