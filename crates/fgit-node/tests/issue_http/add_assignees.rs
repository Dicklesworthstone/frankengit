//! Authenticated additive assignment through the real HTTP and durable node.
use super::*;

#[test]
fn additive_assignment_preserves_auth_strict_versions_and_retries_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = start_node(configuration.clone());
        let path = root.0.join("credentials");
        grants(&node, &path);
        let server = Server::start(node, path.clone(), 17, true);
        committed(&post(
            &server,
            "/api/v1/issues/1/open",
            'b',
            "open",
            "expected_version=0&title=Original&body=Immutable",
            false,
        )); // 1
        let a = principal(0xa1).to_string();
        let b = principal(0xb1).to_string();
        let c = principal(0xc1).to_string();
        let form = format!("assignee={c}&assignee={b}");
        for token in ['a', 'd'] {
            status(
                &post(
                    &server,
                    "/api/v1/issues/1/add-assignees",
                    token,
                    "denied",
                    &form,
                    false,
                ),
                403,
            );
        } // 2, 3
        status(
            &post(
                &server,
                "/api/v1/issues/1/add-assignees",
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
                "/api/v1/issues/1/add-assignees",
                'b',
                "duplicate-member",
                &format!("{form}&assignee={b}"),
                false,
            ),
            400,
        ); // 5
        let original = post(
            &server,
            "/api/v1/issues/1/add-assignees",
            'b',
            "add-first",
            &form,
            true,
        ); // 6
        committed(&original);
        assert!(original.body.contains("\"action\":\"add-assignees\""));
        assert!(
            original
                .body
                .contains("\"command_profile\":\"issue.add-assignees.v1\"")
        );
        assert!(original.body.contains("\"expected_version\":null"));
        assert!(original.body.contains(&format!("\"principal_id\":\"{b}\"")));
        let stale = post(
            &server,
            "/api/v1/issues/1/assign",
            'b',
            "strict-stale",
            &format!("expected_version=1&assignee={a}"),
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
            "/api/v1/issues/1/add-assignees",
            'b',
            "add-second",
            &format!("assignee={a}"),
            false,
        )); // 9
        // The principal set is canonicalized once at the HTTP boundary.
        let retry = post(
            &server,
            "/api/v1/issues/1/add-assignees",
            'b',
            "add-first",
            &format!("assignee={b}&assignee={c}"),
            false,
        ); // 10
        assert_eq!(retry.body, original.body);
        for (action, body) in [
            ("add-assignees", format!("assignee={b}")),
            (
                "assign",
                format!("expected_version=1&assignee={b}&assignee={c}"),
            ),
        ] {
            let reuse = post(
                &server,
                &format!("/api/v1/issues/1/{action}"),
                'b',
                "add-first",
                &body,
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
                .contains(&format!("\"assignees\":[\"{a}\",\"{b}\",\"{c}\"]"))
        );
        assert!(current.body.contains("\"name\":\"assign\""));
        assert!(!current.body.contains("\"name\":\"add-assignees\""));
        let missing = post(
            &server,
            "/api/v1/issues/2/add-assignees",
            'b',
            "missing",
            &form,
            false,
        ); // 14
        status(&missing, 409);
        assert!(missing.body.contains("\"refusal_code\":\"EvidenceStale\""));
        let missing_retry = post(
            &server,
            "/api/v1/issues/2/add-assignees",
            'b',
            "missing",
            &form,
            true,
        ); // 15
        assert_eq!(missing_retry.body, missing.body);
        status(
            &post(
                &server,
                "/api/v1/issues/1/add-assignees",
                'b',
                "forged-actor",
                &format!("{form}&principal={a}"),
                false,
            ),
            400,
        ); // 16
        // Adding the read-only principal to the issue does not grant writes.
        status(
            &post(
                &server,
                "/api/v1/issues/1/add-assignees",
                'a',
                "assigned-reader",
                &form,
                false,
            ),
            403,
        ); // 17
        assert_eq!(server.finish().accepted_sessions(), 17);

        let node = reopened(configuration.clone());
        let before_retry = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let server = Server::start(node, path, 2, true);
        let replay = post(
            &server,
            "/api/v1/issues/1/add-assignees",
            'b',
            "add-first",
            &form,
            false,
        ); // 1
        assert_eq!(replay.body, original.body);
        // The later missing-issue refusal advanced authority without changing
        // this issue. Its retained historical snapshot must still round-trip.
        let after_reopen = get(
            &server,
            &format!("/api/v1/issues/1?expected_head={}", token(&current)),
            'a',
        ); // 2
        assert_eq!(after_reopen.body, current.body);
        assert_eq!(server.finish().accepted_sessions(), 2);

        let node = reopened(configuration);
        let request = node.request_context();
        let history = node
            .runtime()
            .block_on(node.read_issue_history_in(&request, IssueNumber::FIRST, 0, 10, None))
            .unwrap();
        let issue = history.issue.unwrap();
        assert_eq!(
            issue.assignees,
            vec![principal(0xa1), principal(0xb1), principal(0xc1)]
        );
        assert_eq!(issue.version.get(), 4);
        assert_eq!(issue.body, "Immutable");
        assert_eq!(issue.comments, 0);
        assert_eq!(history.events.len(), 4);
        let settled = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(settled.basis(), before_retry.basis());
        assert!(settled.snapshot().refs.is_empty());
        node.shutdown().unwrap();
    }
}
