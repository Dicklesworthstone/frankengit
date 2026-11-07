#![forbid(unsafe_code)]
//! Actual TCP, canonical PR/review/comment publication, exact read prefixes and
//! reopened embedded storage. The inbox never substitutes for PR authorization.

#[path = "review_merge_http/support.rs"]
mod support;
use support::*;

use fgit_types::GitHashAlgorithm;

fn preference(client: &Endpoint, actor: char, action: &str, key: &str, fields: &str) -> Reply {
    let headers = format!(
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: {key}\r\n",
        fields.len()
    );
    exchange(
        client,
        &request(
            client,
            "POST",
            &format!("/api/v1/notifications/pulls/1/{action}"),
            actor,
            &headers,
            fields.as_bytes(),
        ),
        true,
    )
}

fn accepted_preference(reply: &Reply) {
    status(reply, 200);
    for required in [
        "\"type\":\"pull_request_notification_publication\"",
        "\"target_kind\":\"pull_request\"",
        "\"outcome\":\"committed\"",
    ] {
        assert!(reply.body.contains(required), "{}", reply.body);
    }
}

fn activity(reply: &Reply, version: u64, read: Option<u64>, other: Option<u64>, unread: bool) {
    status(reply, 200);
    let optional = |value: Option<u64>| value.map_or_else(|| "null".into(), |v| v.to_string());
    for required in [
        "\"target_kind\":\"pull_request\"".to_owned(),
        format!("\"activity_version\":{version},"),
        format!("\"read_through\":{},", optional(read)),
        format!("\"latest_other_version\":{},", optional(other)),
        format!("\"unread\":{unread},"),
    ] {
        assert!(
            reply.body.contains(&required),
            "missing {required}: {}",
            reply.body
        );
    }
    assert!(!reply.body.contains("issue_version"));
    assert!(!reply.body.contains("discussion_version"));
}

#[test]
fn canonical_pr_activity_prefix_covers_reviews_comments_merge_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = root.config(format);
        let (node, candidate) = prepared(&root, format);
        let incarnation = node.repository_incarnation_id();
        let form_for = |principal, fields: &str| {
            format!("{fields}&expected_principal={principal}&expected_incarnation={incarnation}")
        };
        let credentials = root.0.join("credentials");
        replace(
            &credentials,
            &(header(&node)
                + &row(
                    'a',
                    OWNER,
                    "pulls-read,pulls-write,reviews-read,merges-write,notifications-write",
                )
                + &row(
                    'b',
                    REVIEWER,
                    "pulls-read,pulls-write,reviews-read,reviews-write,notifications-write",
                )
                + &row('c', FOREIGN, "pulls-read,reviews-read,notifications-write")),
        );
        let server = Server::start(node, &credentials, 24, true, false);
        let client = &server.client;
        open(client, &candidate); // 1
        let initial = get(client, "/api/v1/notifications/pulls/1", 'a'); // 2
        activity(&initial, 1, None, None, false);
        assert!(
            initial
                .body
                .contains("\"reasons\":[\"author\",\"participant\"]")
        );
        let empty = get(client, "/api/v1/notifications/pulls", 'c'); // 3
        status(&empty, 200);
        assert!(empty.body.contains("\"threads\":[]"));
        let subscribe_form = form_for(FOREIGN, "expected_version=0");
        let subscribed = preference(client, 'c', "subscribe", "watch-pr", &subscribe_form); // 4
        accepted_preference(&subscribed);
        status(
            &post(
                client,
                1,
                "comments",
                'b',
                "reviewer-comment",
                "expected_version=0&body=Please+check+this",
                false,
            ),
            200,
        ); // 5
        accepted(&send(
            client,
            "reviews/approve",
            'b',
            "reviewer-vote",
            &review_form(&candidate, 0),
            Some(&candidate.bundle),
            false,
        )); // 6
        let observed = get(client, "/api/v1/notifications/pulls/1", 'a'); // 7
        activity(&observed, 3, None, Some(3), true);
        let pin = token(&observed);
        accepted_preference(&preference(
            client,
            'a',
            "read",
            "read-comment-prefix",
            &form_for(OWNER, "expected_version=0&read_through=2"),
        )); // 8
        activity(
            &get(client, "/api/v1/notifications/pulls/1", 'a'),
            3,
            Some(2),
            Some(3),
            true,
        ); // 9
        accepted_preference(&preference(
            client,
            'a',
            "read",
            "read-review-prefix",
            &form_for(OWNER, "expected_version=1&read_through=3"),
        )); // 10
        activity(
            &get(client, "/api/v1/notifications/pulls/1", 'a'),
            3,
            Some(3),
            Some(3),
            false,
        ); // 11
        status(
            &post(
                client,
                1,
                "comments",
                'a',
                "own-comment",
                "expected_version=1&body=Addressed",
                false,
            ),
            200,
        ); // 12
        activity(
            &get(client, "/api/v1/notifications/pulls/1", 'a'),
            4,
            Some(3),
            Some(3),
            false,
        ); // 13
        accepted(&send(
            client,
            "reviews/withdraw",
            'b',
            "withdraw-vote",
            &review_form(&candidate, 1),
            None,
            false,
        )); // 14
        activity(
            &get(client, "/api/v1/notifications/pulls/1", 'a'),
            5,
            Some(3),
            Some(5),
            true,
        ); // 15
        let retained = get(
            client,
            &format!("/api/v1/notifications/pulls/1?expected_head={pin}"),
            'a',
        ); // 16
        assert_eq!(
            retained, observed,
            "later events cannot replace a retained PR activity prefix"
        );
        assert_eq!(
            preference(client, 'c', "subscribe", "watch-pr", &subscribe_form),
            subscribed
        ); // 17
        let stale = preference(
            client,
            'a',
            "read",
            "stale-read",
            &form_for(OWNER, "expected_version=0&read_through=5"),
        ); // 18
        status(&stale, 409);
        assert!(stale.body.contains("EvidenceStale"));
        let future = preference(
            client,
            'a',
            "read",
            "future-read",
            &form_for(OWNER, "expected_version=2&read_through=99"),
        ); // 19
        status(&future, 409);
        assert!(future.body.contains("EvidenceStale"));
        accepted_preference(&preference(
            client,
            'c',
            "mute",
            "mute-pr",
            &form_for(FOREIGN, "expected_version=1"),
        )); // 20
        let muted = get(client, "/api/v1/notifications/pulls", 'c'); // 21
        status(&muted, 200);
        assert!(muted.body.contains("\"threads\":[]"));
        let included = get(
            client,
            "/api/v1/notifications/pulls?include_muted=true",
            'c',
        ); // 22
        activity(&included, 5, None, Some(5), true);
        assert!(included.body.contains("\"mode\":\"muted\""));
        accepted(&send(
            client,
            "merge",
            'a',
            "merge-pr",
            &merge_form(&candidate, &[]),
            Some(&candidate.bundle),
            false,
        )); // 23
        let merged = get(client, "/api/v1/notifications/pulls/1", 'a'); // 24
        activity(&merged, 6, Some(3), Some(5), true);
        assert!(merged.body.contains("\"state\":\"merged\""));
        assert_eq!(server.finish().accepted_sessions(), 24);

        let node = reopen(&configuration);
        let before = generation(&node);
        let server = Server::start(node, &credentials, 4, true, false);
        activity(
            &get(&server.client, "/api/v1/notifications/pulls/1", 'a'),
            6,
            Some(3),
            Some(5),
            true,
        ); // 1
        let muted = get(&server.client, "/api/v1/notifications/pulls/1", 'c'); // 2
        assert!(muted.body.contains("\"mode\":\"muted\""));
        assert_eq!(
            preference(
                &server.client,
                'c',
                "subscribe",
                "watch-pr",
                &subscribe_form
            ),
            subscribed
        ); // 3
        activity(
            &get(&server.client, "/api/v1/notifications/pulls/1", 'b'),
            6,
            None,
            Some(6),
            true,
        ); // 4
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&configuration);
        assert_eq!(
            generation(&node),
            before,
            "reads and exact retries cannot republish preferences"
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn pull_notifications_require_pull_and_review_disclosure_and_an_independent_preference_grant() {
    let root = Scratch::new();
    let configuration = root.config(GitHashAlgorithm::Sha1);
    let (node, data) = fixture(&root, GitHashAlgorithm::Sha1);
    let incarnation = node.repository_incarnation_id();
    let credentials = root.0.join("credentials");
    replace(
        &credentials,
        &(header(&node)
            + &row('a', OWNER, "pulls-read,reviews-read")
            + &row('b', OWNER, "notifications-write")
            + &row('c', FOREIGN, "issues-read,notifications-write")
            + &row('d', OWNER, "pulls-write,notifications-write")
            + &row('e', FOREIGN, "pulls-read,reviews-read,notifications-write")
            + &row('f', OWNER, "reviews-read,notifications-write")
            + &row('0', OWNER, "pulls-read,notifications-write")),
    );
    let server = Server::start(node, &credentials, 15, true, false);
    let client = &server.client;
    committed(&post(
        client,
        1,
        "open",
        'd',
        "open-grants",
        &form(&data, 0),
        false,
    )); // 1
    for token in ['b', 'c', 'd', 'f', '0'] {
        status(&get(client, "/api/v1/notifications/pulls", token), 403); // 2..6
    }
    status(&get(client, "/api/v1/notifications/pulls", 'a'), 200); // 7
    let guarded = |principal| {
        format!(
            "expected_version=0&expected_principal={principal}&expected_incarnation={incarnation}"
        )
    };
    for token in ['a', 'b', 'c', 'd', 'f', '0'] {
        status(
            &preference(client, token, "subscribe", "denied-watch", &guarded(OWNER)),
            403,
        ); // 8..13
    }
    let changed_identity = preference(client, 'e', "subscribe", "wrong-recipient", &guarded(OWNER)); // 14
    status(&changed_identity, 409);
    assert!(
        changed_identity
            .body
            .contains("notification_identity_changed")
    );
    accepted_preference(&preference(
        client,
        'e',
        "subscribe",
        "permitted-watch",
        &guarded(FOREIGN),
    )); // 15
    assert_eq!(server.finish().accepted_sessions(), 15);
    let node = reopen(&configuration);
    let before = generation(&node);
    let server = Server::start(node, &credentials, 2, false, false);
    status(
        &get(&server.client, "/api/v1/notifications/pulls", 'e'),
        403,
    );
    status(&get(&server.client, "/ui/pull-notifications/", 'e'), 404);
    server.finish();
    let node = reopen(&configuration);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}
