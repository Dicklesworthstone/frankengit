//! Actual HTTP append forms retain strict-command, lock, credential and retry boundaries.
use super::*;
use fgit_forge::DiscussionNumber;
use fgit_forge::event::discussion::DiscussionState;

fn appended(reply: &Reply) {
    discussion_committed(reply);
    assert!(reply.body.contains("\"action\":\"append-comment\""));
    assert!(reply.body.contains("\"expected_version\":null"));
    assert!(reply.body.contains("\"delivery_acknowledged\":null"));
}

#[test]
fn append_http_preserves_exact_recovery_locks_and_independent_grants_across_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format).with_http_discussions();
        let node = start_node(configuration.clone());
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let path = root.0.join("credentials");
        let complete = credentials(&node, &path);
        let server = Server::start(node, path.clone(), 25, false);
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/1/open",
            'c',
            "open",
            "expected_version=0&title=Original&body=Immutable",
            false,
        )); // 1
        for token in ['a', 'd', 'e'] {
            status(
                &post(
                    &server,
                    "/api/v1/discussions/1/append-comment",
                    token,
                    "denied",
                    "body=Denied",
                    false,
                ),
                403,
            );
        } // 2, 3, 4
        for body in [
            "expected_version=1&body=Do+not+discard",
            "body=Forged&principal=admin",
        ] {
            status(
                &post(
                    &server,
                    "/api/v1/discussions/1/append-comment",
                    'b',
                    "invalid",
                    body,
                    false,
                ),
                400,
            );
        } // 5, 6
        let body = "body=First+%F0%9F%A6%80%0D%0A%252f";
        let original = post(
            &server,
            "/api/v1/discussions/1/append-comment",
            'b',
            "append-first",
            body,
            true,
        ); // 7
        appended(&original);
        assert!(
            original
                .body
                .contains(&format!("\"principal_id\":\"{}\"", principal(0xb1)))
        );
        let stale = post(
            &server,
            "/api/v1/discussions/1/comment",
            'c',
            "strict-stale",
            "expected_version=1&body=Stale+strict+comment",
            false,
        ); // 8
        status(&stale, 409);
        assert!(stale.body.contains("EvidenceStale"));
        assert!(stale.body.contains("\"action\":\"comment\""));
        assert!(stale.body.contains("\"expected_version\":1"));
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/1/edit",
            'c',
            "edit",
            "expected_version=2&title=Revised",
            false,
        )); // 9
        appended(&post(
            &server,
            "/api/v1/discussions/1/append-comment",
            'b',
            "append-second",
            "body=Second",
            false,
        )); // 10
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/1/close",
            'c',
            "close",
            "expected_version=4",
            false,
        )); // 11
        appended(&post(
            &server,
            "/api/v1/discussions/1/append-comment",
            'b',
            "append-closed",
            "body=Closed+discussion",
            true,
        )); // 12
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/1/lock",
            'c',
            "lock",
            "expected_version=6",
            false,
        )); // 13
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/1/append-comment",
                'b',
                "append-first",
                body,
                false,
            )
            .body,
            original.body
        ); // 14
        let denied = post(
            &server,
            "/api/v1/discussions/1/append-comment",
            'b',
            "locked-comment",
            "body=Blocked",
            false,
        ); // 15
        status(&denied, 409);
        assert!(denied.body.contains("ProtectedRefTransitionDenied"));
        assert!(denied.body.contains("\"expected_version\":null"));
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/1/unlock",
            'c',
            "unlock",
            "expected_version=7",
            false,
        )); // 16
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/1/append-comment",
                'b',
                "locked-comment",
                "body=Blocked",
                true,
            )
            .body,
            denied.body
        ); // 17
        appended(&post(
            &server,
            "/api/v1/discussions/1/append-comment",
            'b',
            "after-unlock",
            "body=Blocked",
            false,
        )); // 18
        for (action, body) in [
            ("append-comment", "body=Changed"),
            (
                "comment",
                "expected_version=9&body=First+%F0%9F%A6%80%0D%0A%252f",
            ),
        ] {
            let reused = post(
                &server,
                &format!("/api/v1/discussions/1/{action}"),
                'b',
                "append-first",
                body,
                false,
            );
            status(&reused, 409);
            assert!(reused.body.contains("idempotency_key_reuse"));
        } // 19, 20
        let current = get(&server, "/api/v1/discussions/1", 'a'); // 21
        status(&current, 200);
        assert!(current.body.contains("\"version\":9,\"title\":\"Revised\""));
        assert!(current.body.contains("\"comments\":4,\"locked\":false"));
        assert!(
            current
                .body
                .contains("\"name\":\"comment\",\"body\":\"First 🦀\\u000d\\u000a%2f\"")
        );
        assert!(!current.body.contains("\"name\":\"append-comment\""));
        let missing = post(
            &server,
            "/api/v1/discussions/2/append-comment",
            'b',
            "missing",
            "body=Missing",
            false,
        ); // 22
        status(&missing, 409);
        assert!(missing.body.contains("EvidenceStale"));
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/2/open",
            'c',
            "open-later",
            "expected_version=0&title=Later&body=",
            false,
        )); // 23
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/2/append-comment",
                'b',
                "missing",
                "body=Missing",
                false,
            )
            .body,
            missing.body
        ); // 24
        let revoked = complete
            .lines()
            .filter(|line| !line.contains(&principal(0xb1).to_string()))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        replace(&path, &revoked);
        status(
            &post(
                &server,
                "/api/v1/discussions/1/append-comment",
                'b',
                "append-first",
                body,
                false,
            ),
            401,
        ); // 25: even an existing outcome requires current HTTP authentication.
        assert_eq!(server.finish().accepted_sessions(), 25);

        replace(&path, &complete);
        let server = Server::start(reopened(configuration.clone()), path, 4, false);
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/1/append-comment",
                'b',
                "append-first",
                body,
                true,
            )
            .body,
            original.body
        ); // 1
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/1/append-comment",
                'b',
                "locked-comment",
                "body=Blocked",
                false,
            )
            .body,
            denied.body
        ); // 2
        status(&get(&server, "/api/v1/discussions/1", 'a'), 200); // 3
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/2/append-comment",
                'b',
                "missing",
                "body=Missing",
                false,
            )
            .body,
            missing.body
        ); // 4
        assert_eq!(server.finish().accepted_sessions(), 4);

        let node = reopened(configuration);
        let after = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(
            after.basis().generation().get(),
            before.basis().generation().get() + 13
        );
        assert_eq!(after.snapshot().refs, before.snapshot().refs);
        assert_eq!(
            after.basis().body().policy_epoch,
            before.basis().body().policy_epoch
        );
        assert_eq!(
            after.selected_closure().closure(),
            before.selected_closure().closure()
        );
        let page = node
            .runtime()
            .block_on(node.read_discussion_history_in(
                &node.request_context(),
                DiscussionNumber::FIRST,
                0,
                100,
                None,
            ))
            .unwrap();
        let discussion = page.discussion.unwrap();
        assert_eq!(discussion.version.get(), 9);
        assert_eq!(discussion.comments, 4);
        assert_eq!(discussion.title, "Revised");
        assert_eq!(discussion.body, "Immutable");
        assert_eq!(discussion.state, DiscussionState::Closed);
        assert!(!discussion.locked);
        assert_eq!(page.events.len(), 9);
        node.shutdown().unwrap();
    }
}
