//! Writes interleave between requests on the real listener. Every continuation
//! retains the first page, rather than restarting or mixing current rows.
use super::*;

#[test]
fn issue_list_walk_survives_insert_edit_close_and_listener_restart() {
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
        let server = Server::start(node, path.clone(), 13, true);
        for number in [1, 3, 5] {
            // 1..3
            committed(&post(
                &server,
                &format!("/api/v1/issues/{number}/open"),
                'b',
                &format!("open-{number}"),
                &format!("expected_version=0&title=Original-{number}&body="),
                false,
            ));
        }
        let first = get(&server, "/api/v1/issues?limit=1", 'a'); // 4
        status(&first, 200);
        assert!(first.body.contains("\"number\":1"));
        let pin = token(&first);
        committed(&post(
            &server,
            "/api/v1/issues/2/open",
            'b',
            "later-insertion",
            "expected_version=0&title=Inserted-after-pin&body=",
            true,
        )); // 5
        committed(&post(
            &server,
            "/api/v1/issues/3/edit",
            'b',
            "later-edit",
            "expected_version=1&title=Edited-after-pin",
            false,
        )); // 6
        let second_path = format!("/api/v1/issues?limit=1&after=1&expected_head={pin}");
        let second = get(&server, &second_path, 'a'); // 7
        status(&second, 200);
        assert_eq!(token(&second), pin);
        assert!(second.body.contains("\"number\":3"));
        assert!(second.body.contains("Original-3"));
        assert!(!second.body.contains("Edited-after-pin"));
        assert!(second.body.contains("\"next_after\":3"));
        committed(&post(
            &server,
            "/api/v1/issues/5/close",
            'b',
            "later-close",
            "expected_version=1",
            false,
        )); // 8
        let last_path = format!("/api/v1/issues?limit=1&after=3&expected_head={pin}");
        let last = get(&server, &last_path, 'a'); // 9
        status(&last, 200);
        assert_eq!(token(&last), pin);
        assert!(last.body.contains("\"number\":5"));
        assert!(last.body.contains("\"state\":\"open\""));
        assert!(last.body.contains("\"next_after\":null"));
        let fresh = get(&server, "/api/v1/issues?limit=100", 'a'); // 10
        status(&fresh, 200);
        assert_ne!(token(&fresh), pin);
        // `issue_page` has no count field; the fresh page lists all four rows.
        assert_eq!(fresh.body.matches("\"number\":").count(), 4);
        for number in [1, 2, 3, 5] {
            assert!(fresh.body.contains(&format!("\"number\":{number},")));
        }
        assert!(
            fresh.body.contains("Inserted-after-pin") && fresh.body.contains("Edited-after-pin")
        );
        assert!(fresh.body.contains("\"state\":\"closed\""));
        let absent = get(
            &server,
            &format!("/api/v1/issues/2?expected_head={pin}"),
            'a',
        ); // 11
        status(&absent, 404);
        assert_eq!(token(&absent), pin);
        assert!(absent.body.contains("\"found\":false"));
        let mut unknown = pin.clone();
        unknown.pop();
        unknown.push(if pin.ends_with('f') { 'e' } else { 'f' });
        let unavailable = get(
            &server,
            &format!("/api/v1/issues?after=1&expected_head={unknown}"),
            'a',
        ); // 12
        status(&unavailable, 409);
        assert!(unavailable.body.contains("\"code\":\"snapshot_moved\""));
        status(&get(&server, "/api/v1/issues?after=1", 'a'), 400); // 13
        assert_eq!(server.finish().accepted_sessions(), 13);

        let node = reopened(configuration.clone());
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .generation()
                .get(),
            before.get() + 6,
            "only the six mutations publish"
        );
        let server = Server::start(node, path, 2, true);
        assert_eq!(get(&server, &second_path, 'a').body, second.body);
        assert_eq!(get(&server, &last_path, 'a').body, last.body);
        assert_eq!(server.finish().accepted_sessions(), 2);
        let node = reopened(configuration);
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .generation()
                .get(),
            before.get() + 6
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn pinned_comment_history_is_stable_but_the_token_never_grants_access() {
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
        let header = grants(&node, &path);
        let server = Server::start(node, path.clone(), 12, true);
        committed(&post(
            &server,
            "/api/v1/issues/7/open",
            'c',
            "open-seven",
            "expected_version=0&title=History&body=",
            false,
        )); // 1
        committed(&post(
            &server,
            "/api/v1/issues/7/comment",
            'c',
            "comment-one",
            "expected_version=1&body=First-comment",
            true,
        )); // 2
        committed(&post(
            &server,
            "/api/v1/issues/7/comment",
            'c',
            "comment-two",
            "expected_version=2&body=Second-comment",
            false,
        )); // 3
        let first = get(&server, "/api/v1/issues/7?limit=1", 'a'); // 4
        status(&first, 200);
        let pin = token(&first);
        committed(&post(
            &server,
            "/api/v1/issues/7/comment",
            'c',
            "later-comment",
            "expected_version=3&body=Not-in-the-pinned-history",
            false,
        )); // 5
        committed(&post(
            &server,
            "/api/v1/issues/7/close",
            'c',
            "later-close",
            "expected_version=4",
            true,
        )); // 6
        let second_path = format!("/api/v1/issues/7?limit=1&after_version=1&expected_head={pin}");
        let second = get(&server, &second_path, 'a'); // 7
        status(&second, 200);
        assert_eq!(token(&second), pin);
        assert!(second.body.contains("First-comment"));
        assert!(second.body.contains("\"version\":3") && second.body.contains("\"comments\":2"));
        assert!(second.body.contains("\"state\":\"open\""));
        assert!(!second.body.contains("Not-in-the-pinned-history"));
        let last = get(
            &server,
            &format!("/api/v1/issues/7?limit=1&after_version=2&expected_head={pin}"),
            'a',
        ); // 8
        status(&last, 200);
        assert_eq!(token(&last), pin);
        assert!(last.body.contains("Second-comment"));
        assert!(last.body.contains("\"next_after_version\":null"));
        let fresh = get(&server, "/api/v1/issues/7?limit=100", 'a'); // 9
        status(&fresh, 200);
        assert!(fresh.body.contains("\"version\":5") && fresh.body.contains("\"comments\":3"));
        assert!(fresh.body.contains("Not-in-the-pinned-history"));
        assert!(fresh.body.contains("\"state\":\"closed\""));
        replace(
            &path,
            &(header + &row('e', 0xa1, "issues-read") + &row('d', 0xd1, "read,receive")),
        );
        status(&get(&server, &second_path, 'a'), 401); // 10: revoked bearer, valid old token.
        assert_eq!(get(&server, &second_path, 'e').body, second.body); // 11: rotated reader.
        status(&get(&server, &second_path, 'd'), 403); // 12: Git-only grant, valid old token.
        assert_eq!(server.finish().accepted_sessions(), 12);
        let node = reopened(configuration);
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .generation()
                .get(),
            before.get() + 5
        );
        node.shutdown().unwrap();
    }
}
