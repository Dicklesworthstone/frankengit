//! Real TCP discussion routes with independent grants, native decisions and restart.
#[path = "discussions/append.rs"]
mod append;

use super::*;

fn credentials(node: &OneNode, path: &Path) -> String {
    let header = format!(
        "frankengit-http-credentials-v1 {} {} {}\n",
        TenantId::from_bytes([0x91; 16]),
        RepositoryId::from_bytes([0x92; 16]),
        node.repository_incarnation_id()
    );
    let complete = header.clone()
        + &row('a', 0xa1, "discussions-read")
        + &row('b', 0xb1, "discussions-write")
        + &row('c', 0xc1, "discussions-read,discussions-write")
        + &row('d', 0xd1, "issues-read,issues-write")
        + &row('e', 0xe1, "read,receive");
    replace(path, &complete);
    complete
}
fn discussion_committed(reply: &Reply) {
    status(reply, 200);
    assert!(
        reply.body.contains("\"type\":\"discussion_publication\""),
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains("\"outcome\":\"committed\""),
        "{}",
        reply.body
    );
}

#[test]
fn discussion_lifecycle_scope_isolation_pagination_and_original_retry_over_http() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format).with_http_discussions();
        let node = start_node(configuration.clone());
        let path = root.0.join("credentials");
        let complete = credentials(&node, &path);
        let server = Server::start(node, path.clone(), 29, true);
        let opening = "expected_version=0&title=Design&body=%3Cscript%3Euntrusted%3C%2Fscript%3E";
        let empty = get(&server, "/api/v1/discussions", 'a'); // 1
        status(&empty, 200);
        assert!(empty.body.contains("\"discussions\":[]"));
        status(
            &post(
                &server,
                "/api/v1/discussions/7/open",
                'a',
                "read-only",
                opening,
                false,
            ),
            403,
        ); // 2
        let original = post(
            &server,
            "/api/v1/discussions/7/open",
            'b',
            "original-open",
            opening,
            true,
        ); // 3
        discussion_committed(&original);
        status(&get(&server, "/api/v1/discussions/7", 'b'), 403); // 4
        let first = get(&server, "/api/v1/discussions/7?render=html_safe", 'a'); // 5
        status(&first, 200);
        let pin = token(&first);
        assert!(first.body.contains("&lt;script&gt;"));
        assert!(
            first
                .body
                .contains(&format!("\"opened_by\":\"{}\"", principal(0xb1)))
        );
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/7/edit",
            'c',
            "edit",
            "expected_version=1&title=Revised",
            false,
        )); // 6
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/7/comment",
            'c',
            "comment",
            "expected_version=2&body=first+comment",
            true,
        )); // 7
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/7/lock",
            'c',
            "lock",
            "expected_version=3",
            false,
        )); // 8
        let denied = post(
            &server,
            "/api/v1/discussions/7/comment",
            'c',
            "locked-comment",
            "expected_version=4&body=blocked",
            false,
        ); // 9
        status(&denied, 409);
        assert!(denied.body.contains("ProtectedRefTransitionDenied"));
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/7/unlock",
            'c',
            "unlock",
            "expected_version=4",
            false,
        )); // 10
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/7/close",
            'c',
            "close",
            "expected_version=5",
            false,
        )); // 11
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/7/comment",
            'c',
            "closed-comment",
            "expected_version=6&body=closed+comment",
            false,
        )); // 12
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/7/reopen",
            'c',
            "reopen",
            "expected_version=7",
            false,
        )); // 13
        let stale = post(
            &server,
            "/api/v1/discussions/7/close",
            'c',
            "stale",
            "expected_version=1",
            false,
        ); // 14
        status(&stale, 409);
        assert!(stale.body.contains("EvidenceStale"));
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/7/open",
                'b',
                "original-open",
                opening,
                false
            )
            .body,
            original.body
        ); // 15
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/7/comment",
                'c',
                "locked-comment",
                "expected_version=4&body=blocked",
                false
            )
            .body,
            denied.body
        ); // 16
        let changed = post(
            &server,
            "/api/v1/discussions/7/open",
            'b',
            "original-open",
            "expected_version=0&title=Different&body=",
            false,
        ); // 17
        status(&changed, 409);
        assert!(changed.body.contains("idempotency_key_reuse"));
        let historical = get(
            &server,
            &format!("/api/v1/discussions/7?render=html_safe&expected_head={pin}"),
            'a',
        ); // 18
        status(&historical, 200);
        assert_eq!(historical.body, first.body);
        let current = get(&server, "/api/v1/discussions/7", 'a'); // 19
        status(&current, 200);
        assert!(current.body.contains("\"version\":8,\"title\":\"Revised\""));
        assert!(current.body.contains("\"comments\":2,\"locked\":false"));
        status(&get(&server, "/api/v1/discussions", 'd'), 403); // 20
        status(&get(&server, "/api/v1/issues", 'c'), 403); // 21
        status(&get(&server, "/api/v1/discussions", 'e'), 403); // 22
        let unpinned = get(&server, "/api/v1/discussions/7?after_version=1", 'a'); // 23
        status(&unpinned, 400);
        assert!(unpinned.body.contains("\"type\":\"discussion_error\""));
        status(&get(&server, "/api/v1/discussions/99", 'a'), 404); // 24
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/9/open",
            'c',
            "open-nine",
            "expected_version=0&title=Nine&body=",
            false,
        )); // 25
        let page = get(&server, "/api/v1/discussions?limit=1", 'a'); // 26
        status(&page, 200);
        assert!(page.body.contains("\"next_after\":7"));
        let page_pin = token(&page);
        discussion_committed(&post(
            &server,
            "/api/v1/discussions/8/open",
            'c',
            "open-eight",
            "expected_version=0&title=Eight&body=",
            false,
        )); // 27
        let second = get(
            &server,
            &format!("/api/v1/discussions?after=7&limit=1&expected_head={page_pin}"),
            'a',
        ); // 28
        status(&second, 200);
        assert!(second.body.contains("\"number\":9"));
        assert!(!second.body.contains("\"number\":8"));
        let revoked = complete
            .lines()
            .filter(|line| !line.contains(&principal(0xc1).to_string()))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        replace(&path, &revoked);
        status(&get(&server, "/api/v1/discussions", 'c'), 401); // 29
        assert_eq!(server.finish().accepted_sessions(), 29);

        replace(&path, &complete);
        // Discussion enablement is independent even when the issue service is off.
        let server = Server::start(reopened(configuration), path, 3, false);
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/7/open",
                'b',
                "original-open",
                opening,
                false
            )
            .body,
            original.body
        ); // 1
        let after = get(&server, "/api/v1/discussions/7", 'a'); // 2
        status(&after, 200);
        assert!(after.body.contains("\"version\":8,\"title\":\"Revised\""));
        assert_eq!(
            post(
                &server,
                "/api/v1/discussions/7/comment",
                'c',
                "locked-comment",
                "expected_version=4&body=blocked",
                false
            )
            .body,
            denied.body
        ); // 3
        assert_eq!(server.finish().accepted_sessions(), 3);
    }
}

#[test]
fn valid_discussion_credentials_do_not_enable_the_disabled_service() {
    let root = Scratch::new();
    let configuration = config(&root, GitHashAlgorithm::Sha1);
    assert!(!configuration.http_discussions_enabled());
    let node = start_node(configuration.clone());
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, path, 3, true);
    status(&get(&server, "/api/v1/discussions", 'a'), 403);
    status(
        &post(
            &server,
            "/api/v1/discussions/1/open",
            'b',
            "disabled",
            "expected_version=0&title=Disabled&body=",
            false,
        ),
        403,
    );
    status(
        &post(
            &server,
            "/api/v1/discussions/1/append-comment",
            'b',
            "disabled-append",
            "body=Disabled",
            false,
        ),
        403,
    );
    assert_eq!(server.finish().accepted_sessions(), 3);
    let node = reopened(configuration);
    let page = node
        .runtime()
        .block_on(node.read_discussions_in(&node.request_context(), 0, 10, None))
        .unwrap();
    assert!(page.discussions.is_empty());
    node.shutdown().unwrap();
}
