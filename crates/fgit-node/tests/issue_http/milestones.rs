//! The real authenticated HTTP gateway, native authority and cold node restart.
use super::*;

fn milestone_committed(reply: &Reply) {
    status(reply, 200);
    assert!(reply.body.contains("\"type\":\"milestone_publication\""));
    assert!(reply.body.contains("\"outcome\":\"committed\""));
}
fn counts(reply: &Reply, open: u64, closed: u64) {
    status(reply, 200);
    assert!(
        reply.body.contains(&format!(
            "\"open_issues\":{open},\"closed_issues\":{closed}"
        )),
        "{}",
        reply.body
    );
}

#[test]
fn milestone_lifecycle_membership_scopes_and_historical_retries_survive_http_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = start_node(configuration.clone());
        let path = root.0.join("credentials");
        let header = grants(&node, &path);
        let server = Server::start(node, path.clone(), 24, true);
        let opening = "expected_version=0&title=Release&body=Literal%20%3Cscript%3E&due_at=0";
        status(
            &post(
                &server,
                "/api/v1/milestones/7/open",
                'a',
                "read-only",
                opening,
                false,
            ),
            403,
        ); // 1
        status(&get(&server, "/api/v1/milestones", 'd'), 403); // 2
        let original = post(
            &server,
            "/api/v1/milestones/7/open",
            'b',
            "milestone-original",
            opening,
            true,
        ); // 3
        milestone_committed(&original);
        committed(&post(
            &server,
            "/api/v1/issues/1/open",
            'b',
            "issue-open",
            "expected_version=0&title=Work&body=Original",
            false,
        )); // 4
        let set = "expected_version=1&milestone=7&expected_milestone_version=1";
        committed(&post(
            &server,
            "/api/v1/issues/1/set-milestone",
            'b',
            "assign-original",
            set,
            false,
        )); // 5
        let before = get(&server, "/api/v1/milestones", 'a'); // 6
        counts(&before, 1, 0);
        assert!(before.body.contains("\"due_at\":0"));
        let pin = token(&before);
        let first_history = get(&server, "/api/v1/milestones/7", 'a'); // 7
        counts(&first_history, 1, 0);
        assert!(
            first_history
                .body
                .contains(&format!("\"opened_by\":\"{}\"", principal(0xb1)))
        );
        assert!(first_history.body.contains("\"name\":\"open\""));
        milestone_committed(&post(
            &server,
            "/api/v1/milestones/7/edit",
            'b',
            "clear-date",
            "expected_version=1&clear_due_at=true",
            false,
        )); // 8
        status(
            &post(
                &server,
                "/api/v1/issues/1/set-milestone",
                'b',
                "stale-milestone",
                "expected_version=2&milestone=7&expected_milestone_version=1",
                false,
            ),
            409,
        ); // 9
        committed(&post(
            &server,
            "/api/v1/issues/1/set-milestone",
            'b',
            "repeat-membership",
            "expected_version=2&milestone=7&expected_milestone_version=2",
            false,
        )); // 10
        milestone_committed(&post(
            &server,
            "/api/v1/milestones/7/close",
            'b',
            "close-milestone",
            "expected_version=2",
            false,
        )); // 11
        status(
            &post(
                &server,
                "/api/v1/issues/1/set-milestone",
                'b',
                "closed-milestone",
                "expected_version=3&milestone=7&expected_milestone_version=3",
                false,
            ),
            409,
        ); // 12
        committed(&post(
            &server,
            "/api/v1/issues/1/close",
            'b',
            "close-issue",
            "expected_version=3",
            false,
        )); // 13
        let closed = get(&server, "/api/v1/milestones", 'a'); // 14
        counts(&closed, 0, 1);
        assert!(closed.body.contains("\"state\":\"closed\""));
        assert!(closed.body.contains("\"due_at\":null"));
        committed(&post(
            &server,
            "/api/v1/issues/1/clear-milestone",
            'b',
            "clear-membership",
            "expected_version=4",
            false,
        )); // 15
        let retry = post(
            &server,
            "/api/v1/milestones/7/open",
            'b',
            "milestone-original",
            opening,
            false,
        ); // 16
        assert_eq!(retry.body, original.body);
        status(
            &post(
                &server,
                "/api/v1/milestones/7/open",
                'b',
                "milestone-original",
                "expected_version=0&title=Changed&body=Original",
                false,
            ),
            409,
        ); // 17
        status(
            &post(
                &server,
                "/api/v1/milestones/7/reopen",
                'b',
                "forged-actor",
                "expected_version=3&principal=admin",
                false,
            ),
            400,
        ); // 18
        status(&get(&server, "/api/v1/milestones", 'b'), 403); // 19
        let historical = get(
            &server,
            &format!("/api/v1/milestones?expected_head={pin}"),
            'a',
        ); // 20
        assert_eq!(historical.body, before.body);
        let issue = get(&server, "/api/v1/issues/1", 'a'); // 21
        status(&issue, 200);
        assert!(issue.body.contains("\"version\":5"));
        assert!(issue.body.contains("\"milestone\":null"));
        assert!(issue.body.contains(
            "\"name\":\"set-milestone\",\"milestone\":7,\"expected_milestone_version\":2"
        ));
        assert!(issue.body.contains("\"name\":\"clear-milestone\""));
        let milestone = get(&server, "/api/v1/milestones/7", 'a'); // 22
        counts(&milestone, 0, 0);
        assert!(milestone.body.contains("\"name\":\"edit\",\"due_at\":null"));
        let form = b"milestone=none";
        let search = exchange(
            server.address,
            &request(
                &server,
                "POST",
                "/api/v1/issues/search",
                'a',
                &format!(
                    "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
                    form.len()
                ),
                form,
            ),
            false,
        ); // 23
        status(&search, 200);
        assert!(search.body.contains("\"milestone\":\"none\""));
        assert!(search.body.contains("\"number\":1"));
        replace(&path, &(header + &row('b', 0xb1, "issues-write")));
        let revoked = get(&server, "/api/v1/milestones", 'a'); // 24
        status(&revoked, 401);
        assert!(revoked.body.contains("\"type\":\"milestone_error\""));
        assert!(revoked.body.contains("\"code\":\"unauthorized\""));
        server.finish();

        let node = reopened(configuration);
        let materialized = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert!(materialized.snapshot().refs.is_empty());
        drop(materialized);
        grants(&node, &path);
        let server = Server::start(node, path, 6, true);
        assert_eq!(get(&server, "/api/v1/issues/1", 'a').body, issue.body); // 1
        assert_eq!(
            get(&server, "/api/v1/milestones/7", 'a').body,
            milestone.body
        ); // 2
        milestone_committed(&post(
            &server,
            "/api/v1/milestones/7/reopen",
            'b',
            "reopen-milestone",
            "expected_version=3",
            false,
        )); // 3
        committed(&post(
            &server,
            "/api/v1/issues/1/set-milestone",
            'b',
            "assign-closed-issue",
            "expected_version=5&milestone=7&expected_milestone_version=4",
            false,
        )); // 4
        counts(&get(&server, "/api/v1/milestones", 'a'), 0, 1); // 5
        let final_history = get(&server, "/api/v1/milestones/7", 'a'); // 6
        assert!(final_history.body.contains("\"version\":4"));
        assert!(final_history.body.contains("\"name\":\"reopen\""));
        server.finish();
    }
}
