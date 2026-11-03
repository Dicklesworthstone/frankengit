//! Native discussion inboxes: actual TCP grants, canonical decisions and restart.
use super::*;

fn credentials(node: &OneNode, path: &Path) -> String {
    let header = grants(node, path);
    let complete = header
        + &row('a', 0xa1, "discussions-read")
        + &row('b', 0xb1, "discussions-write")
        + &row('c', 0xc1, "discussions-read,discussions-write")
        + &row('d', 0xd1, "issues-read,issues-write,notifications-write")
        + &row('e', 0xe1, "notifications-write")
        + &row(
            'f',
            0xf1,
            "issues-read,notifications-write,discussions-read,discussions-write",
        );
    replace(path, &complete);
    complete
}

fn committed_as(reply: &Reply, kind: &str) {
    status(reply, 200);
    assert!(
        reply
            .body
            .contains(&format!("\"type\":\"{kind}_publication\"")),
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
fn discussion_preferences_survive_restart_and_do_not_acknowledge_later_or_issue_activity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format).with_http_discussions();
        let node = start_node(configuration.clone());
        let incarnation = node.repository_incarnation_id().to_string();
        let form = |fields: &str| {
            format!(
                "{fields}&expected_principal={}&expected_incarnation={incarnation}",
                principal(0xf1)
            )
        };
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, path.clone(), 29, true);
        committed_as(
            &post(
                &server,
                "/api/v1/discussions/7/open",
                'b',
                "discussion-open",
                "expected_version=0&title=Discussion+seven&body=Text",
                false,
            ),
            "discussion",
        ); // 1
        committed_as(
            &post(
                &server,
                "/api/v1/issues/7/open",
                'd',
                "issue-open",
                "expected_version=0&title=Issue+seven&body=Text",
                false,
            ),
            "issue",
        ); // 2
        let empty = get(&server, "/api/v1/notifications/discussions", 'f'); // 3
        status(&empty, 200);
        assert!(empty.body.contains("\"threads\":[]"));
        let original = post(
            &server,
            "/api/v1/notifications/discussions/7/subscribe",
            'f',
            "discussion-subscribe",
            &form("expected_version=0"),
            true,
        ); // 4
        committed_as(&original, "discussion_notification");
        assert!(original.body.contains("\"target_kind\":\"discussion\""));
        let issue = get(&server, "/api/v1/notifications/7", 'f'); // 5
        status(&issue, 200);
        assert!(issue.body.contains("\"preference_version\":null"));
        assert!(!issue.body.contains("discussion_version"));
        let observed = get(&server, "/api/v1/notifications/discussions/7", 'f'); // 6
        status(&observed, 200);
        assert!(observed.body.contains("\"discussion_version\":1"));
        assert!(
            observed
                .body
                .contains("\"preference_version\":1,\"mode\":\"subscribed\"")
        );
        let pin = token(&observed);
        committed_as(
            &post(
                &server,
                "/api/v1/notifications/discussions/7/read",
                'f',
                "read-one",
                &form("expected_version=1&read_through=1"),
                false,
            ),
            "discussion_notification",
        ); // 7
        committed_as(
            &post(
                &server,
                "/api/v1/discussions/7/comment",
                'c',
                "other-reply",
                "expected_version=1&body=Later+reply",
                false,
            ),
            "discussion",
        ); // 8
        let unread = get(&server, "/api/v1/notifications/discussions/7", 'f'); // 9
        status(&unread, 200);
        assert!(
            unread
                .body
                .contains("\"read_through\":1,\"latest_other_version\":2,\"unread\":true")
        );
        let stale = post(
            &server,
            "/api/v1/notifications/discussions/7/read",
            'f',
            "stale-preference",
            &form("expected_version=1&read_through=2"),
            false,
        ); // 10
        status(&stale, 409);
        assert!(stale.body.contains("EvidenceStale"));
        let future = post(
            &server,
            "/api/v1/notifications/discussions/7/read",
            'f',
            "future-prefix",
            &form("expected_version=2&read_through=99"),
            false,
        ); // 11
        status(&future, 409);
        assert!(future.body.contains("EvidenceStale"));
        committed_as(
            &post(
                &server,
                "/api/v1/notifications/discussions/7/read",
                'f',
                "read-two",
                &form("expected_version=2&read_through=2"),
                false,
            ),
            "discussion_notification",
        ); // 12
        let read = get(&server, "/api/v1/notifications/discussions/7", 'f'); // 13
        status(&read, 200);
        assert!(read.body.contains("\"unread\":false"));
        committed_as(
            &post(
                &server,
                "/api/v1/notifications/discussions/7/mute",
                'f',
                "mute",
                &form("expected_version=3"),
                false,
            ),
            "discussion_notification",
        ); // 14
        let muted = get(&server, "/api/v1/notifications/discussions", 'f'); // 15
        status(&muted, 200);
        assert!(muted.body.contains("\"threads\":[]"));
        let included = get(
            &server,
            "/api/v1/notifications/discussions?include_muted=true",
            'f',
        ); // 16
        status(&included, 200);
        assert!(
            included
                .body
                .contains("\"mode\":\"muted\",\"read_through\":2")
        );
        committed_as(
            &post(
                &server,
                "/api/v1/notifications/discussions/7/automatic",
                'f',
                "automatic",
                &form("expected_version=4"),
                false,
            ),
            "discussion_notification",
        ); // 17
        let automatic = get(&server, "/api/v1/notifications/discussions", 'f'); // 18
        status(&automatic, 200);
        assert!(automatic.body.contains("\"threads\":[]"));
        committed_as(
            &post(
                &server,
                "/api/v1/discussions/7/comment",
                'f',
                "own-reply",
                "expected_version=2&body=My+reply",
                false,
            ),
            "discussion",
        ); // 19
        let participant = get(&server, "/api/v1/notifications/discussions", 'f'); // 20
        status(&participant, 200);
        assert!(participant.body.contains("\"reasons\":[\"participant\"]"));
        assert!(participant.body.contains("\"unread\":false"));
        committed_as(
            &post(
                &server,
                "/api/v1/discussions/7/comment",
                'b',
                "later-reply",
                "expected_version=3&body=Another+reply",
                false,
            ),
            "discussion",
        ); // 21
        let later = get(
            &server,
            "/api/v1/notifications/discussions?unread_only=true",
            'f',
        ); // 22
        status(&later, 200);
        assert!(later.body.contains("\"discussion_version\":4"));
        assert!(later.body.contains("\"unread\":true"));
        let issue = get(&server, "/api/v1/notifications/7", 'f'); // 23
        status(&issue, 200);
        assert!(issue.body.contains("\"preference_version\":null"));
        committed_as(
            &post(
                &server,
                "/api/v1/notifications/7/subscribe",
                'f',
                "issue-subscribe",
                &form("expected_version=0"),
                false,
            ),
            "notification",
        ); // 24
        let distinct = get(&server, "/api/v1/notifications/discussions/7", 'f'); // 25
        status(&distinct, 200);
        assert!(
            distinct
                .body
                .contains("\"preference_version\":5,\"mode\":\"automatic\",\"read_through\":2")
        );
        let retry = post(
            &server,
            "/api/v1/notifications/discussions/7/subscribe",
            'f',
            "discussion-subscribe",
            &form("expected_version=0"),
            false,
        ); // 26
        assert_eq!(retry.body, original.body);
        let rebound = post(
            &server,
            "/api/v1/notifications/7/subscribe",
            'f',
            "discussion-subscribe",
            &form("expected_version=0"),
            false,
        ); // 27
        status(&rebound, 409);
        assert!(rebound.body.contains("idempotency_key_reuse"));
        let retained = get(
            &server,
            &format!("/api/v1/notifications/discussions/7?expected_head={pin}"),
            'f',
        ); // 28
        assert_eq!(retained.body, observed.body);
        let owner = get(&server, "/api/v1/notifications/discussions/7", 'a'); // 29
        status(&owner, 200);
        assert!(owner.body.contains("\"preference_version\":null"));
        assert_eq!(server.finish().accepted_sessions(), 29);

        // Discussion inbox works with the issue service disabled after a cold reopen.
        let server = Server::start(reopened(configuration), path, 3, false);
        let replay = post(
            &server,
            "/api/v1/notifications/discussions/7/subscribe",
            'f',
            "discussion-subscribe",
            &form("expected_version=0"),
            false,
        );
        assert_eq!(replay.body, original.body);
        let restored = get(&server, "/api/v1/notifications/discussions/7", 'f');
        assert_eq!(restored.body, distinct.body);
        status(&get(&server, "/api/v1/notifications", 'f'), 403);
        assert_eq!(server.finish().accepted_sessions(), 3);
    }
}

#[test]
fn discussion_inbox_requires_discussion_disclosure_and_preference_grants() {
    let root = Scratch::new();
    let node = start_node(config(&root, GitHashAlgorithm::Sha256).with_http_discussions());
    let incarnation = node.repository_incarnation_id().to_string();
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, path, 9, true);
    for credential in ['b', 'd', 'e'] {
        status(
            &get(&server, "/api/v1/notifications/discussions", credential),
            403,
        );
    }
    for (credential, actor) in [
        ('a', 0xa1),
        ('b', 0xb1),
        ('c', 0xc1),
        ('d', 0xd1),
        ('e', 0xe1),
    ] {
        let form = format!(
            "expected_version=0&expected_principal={}&expected_incarnation={incarnation}",
            principal(actor)
        );
        status(
            &post(
                &server,
                "/api/v1/notifications/discussions/7/subscribe",
                credential,
                "forbidden-preference",
                &form,
                false,
            ),
            403,
        );
    }
    status(&get(&server, "/api/v1/notifications", 'a'), 403);
    assert_eq!(server.finish().accepted_sessions(), 9);
}
