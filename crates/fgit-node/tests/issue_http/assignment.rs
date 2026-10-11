use super::*;

#[test]
fn assignments_round_trip_over_authenticated_http_without_granting_access() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = start_node(configuration.clone());
        let path = root.0.join("credentials");
        grants(&node, &path);
        let server = Server::start(node, path, 13, true);
        committed(&post(
            &server,
            "/api/v1/issues/1/open",
            'b',
            "open",
            "expected_version=0&title=Assign&body=Original",
            false,
        )); // 1
        let a = principal(0xa1).to_string();
        let b = principal(0xe1).to_string();
        let form = format!("expected_version=1&assignee={b}&assignee={a}");
        status(
            &post(
                &server,
                "/api/v1/issues/1/assign",
                'd',
                "git-only",
                &form,
                false,
            ),
            403,
        ); // 2
        let original = post(
            &server,
            "/api/v1/issues/1/assign",
            'b',
            "assign",
            &form,
            true,
        ); // 3
        committed(&original);
        let first = get(&server, "/api/v1/issues/1", 'a'); // 4
        status(&first, 200);
        assert!(
            first
                .body
                .contains(&format!("\"assignees\":[\"{a}\",\"{b}\"]"))
        );
        assert!(
            first
                .body
                .contains(&format!("\"last_actor\":\"{}\"", principal(0xb1)))
        );
        let pin = token(&first);
        // Being assigned leaves this existing read-only credential read-only.
        status(
            &post(
                &server,
                "/api/v1/issues/1/unassign",
                'a',
                "assigned-reader",
                &format!("expected_version=2&assignee={a}"),
                false,
            ),
            403,
        ); // 5
        status(&get(&server, "/api/v1/issues/1", 'b'), 403); // 6
        status(
            &post(
                &server,
                "/api/v1/issues/1/assign",
                'b',
                "forged-actor",
                &format!("expected_version=2&assignee={b}&principal={a}"),
                false,
            ),
            400,
        ); // 7
        committed(&post(
            &server,
            "/api/v1/issues/1/unassign",
            'b',
            "unassign",
            &format!("expected_version=2&assignee={a}"),
            false,
        )); // 8
        let current = get(&server, "/api/v1/issues/1", 'a'); // 9
        status(&current, 200);
        assert!(current.body.contains(&format!("\"assignees\":[\"{b}\"]")));
        assert!(
            current
                .body
                .contains(&format!("\"name\":\"unassign\",\"assignees\":[\"{a}\"]"))
        );
        let retry = post(
            &server,
            "/api/v1/issues/1/assign",
            'b',
            "assign",
            &format!("expected_version=1&assignee={a}&assignee={b}"),
            false,
        ); // 10
        assert_eq!(retry.body, original.body);
        let stale = post(
            &server,
            "/api/v1/issues/1/assign",
            'b',
            "stale",
            &format!("expected_version=2&assignee={a}"),
            false,
        ); // 11
        status(&stale, 409);
        assert!(stale.body.contains("\"refusal_code\":\"EvidenceStale\""));
        let pinned = get(
            &server,
            &format!("/api/v1/issues/1?expected_head={pin}"),
            'a',
        ); // 12
        assert_eq!(pinned.body, first.body);
        let conflict = post(
            &server,
            "/api/v1/issues/1/assign",
            'b',
            "assign",
            &format!("expected_version=1&assignee={a}"),
            false,
        ); // 13
        status(&conflict, 409);
        assert!(conflict.body.contains("\"code\":\"idempotency_key_reuse\""));
        assert_eq!(server.finish().accepted_sessions(), 13);

        let node = reopened(configuration);
        let request = node.request_context();
        let history = node
            .runtime()
            .block_on(node.read_issue_history_in(&request, IssueNumber::FIRST, 0, 10, None))
            .unwrap();
        let issue = history.issue.unwrap();
        assert_eq!(issue.assignees, vec![principal(0xe1)]);
        assert_eq!(issue.version.get(), 3);
        assert_eq!(issue.last_actor, principal(0xb1));
        assert_eq!(issue.body, "Original");
        let selected = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert!(selected.snapshot().refs.is_empty());
        node.shutdown().unwrap();
    }
}
