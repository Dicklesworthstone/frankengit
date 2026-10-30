//! Real HTTP append requests retain their exact identity across intervening
//! comments and restart. Native admission owns sequencing and authorization.

use super::*;

fn append_form(body: &str) -> String {
    format!("body={}", encode(body.as_bytes()))
}

fn appended(reply: &Reply) {
    status(reply, 200);
    for field in [
        "\"type\":\"pull_request_comment_publication\"",
        "\"action\":\"append-comment\"",
        "\"outcome\":\"committed\"",
        "\"expected_version\":null",
        "\"comment_version\":null",
        "\"refs_changed\":false",
        "\"delivery_acknowledged\":null",
    ] {
        assert!(reply.body.contains(field), "{field}: {}", reply.body);
    }
}

#[test]
fn append_comments_preserve_grants_legacy_preconditions_and_original_retry_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        native_open(&node, &data);
        let credentials = root.0.join("credentials");
        grants(&node, &credentials);
        let server = Server::start(node, &credentials, 14, true, true);
        let client = &server.client;
        let body = append_form("Concurrent 🦀 <script>literal</script>\n%2f");
        status(
            &post(client, 1, "comments/append", 'a', "reader", &body, false),
            403,
        ); // 1
        status(
            &post(
                client,
                1,
                "comments/append",
                'd',
                "wrong-grant",
                &body,
                false,
            ),
            403,
        ); // 2
        status(
            &post(
                client,
                1,
                "comments/append",
                'b',
                "invalid-form",
                &format!("{body}&expected_version=0"),
                false,
            ),
            400,
        ); // 3
        let first = post(
            client,
            1,
            "comments/append",
            'b',
            "append-one",
            &body,
            false,
        ); // 4
        appended(&first);
        appended(&post(
            client,
            1,
            "comments/append",
            'b',
            "append-two",
            &body,
            true,
        )); // 5
        comment_committed(&post(
            client,
            1,
            "comments",
            'b',
            "strict",
            &comment_form(2, "Strict third comment"),
            false,
        )); // 6
        assert_eq!(
            post(
                client,
                1,
                "comments/append",
                'b',
                "append-one",
                &body,
                false
            )
            .body,
            first.body
        ); // 7
        status(
            &post(
                client,
                1,
                "comments/append",
                'b',
                "append-one",
                &append_form("Changed bytes"),
                false,
            ),
            409,
        ); // 8
        status(
            &post(
                client,
                1,
                "comments",
                'b',
                "append-one",
                &comment_form(0, "Concurrent 🦀 <script>literal</script>\n%2f"),
                false,
            ),
            409,
        ); // 9
        let current = get(client, COMMENTS, 'a'); // 10
        status(&current, 200);
        assert!(current.body.contains("\"discussion_version\":3"));
        assert_eq!(current.body.matches("\"actor\":").count(), 3);
        assert_eq!(
            current.body.matches("Concurrent 🦀").count(),
            2,
            "distinct keys retain duplicate text"
        );
        status(&get(client, &format!("{COMMENTS}/append"), 'a'), 405); // 11
        status(
            &post(
                client,
                7,
                "comments/append",
                'b',
                "missing-pr",
                &body,
                false,
            ),
            409,
        ); // 12
        appended(&post(
            client,
            1,
            "comments/append",
            'b',
            "invalid-form",
            &append_form("Valid after corrected form"),
            false,
        )); // 13
        let latest = get(client, COMMENTS, 'a'); // 14
        status(&latest, 200);
        assert!(latest.body.contains("\"discussion_version\":4"));
        assert_eq!(latest.body.matches("\"actor\":").count(), 4);
        assert_eq!(server.finish().accepted_sessions(), 14);
        let node = reopen(&config);
        let before = generation(&node);
        let server = Server::start(node, &credentials, 2, true, true);
        assert_eq!(
            post(
                &server.client,
                1,
                "comments/append",
                'b',
                "append-one",
                &body,
                false
            )
            .body,
            first.body
        );
        assert_eq!(get(&server.client, COMMENTS, 'a').body, latest.body);
        assert_eq!(server.finish().accepted_sessions(), 2);
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before,
            "recovery and reads never republish"
        );
        node.shutdown().unwrap();
    }
}
