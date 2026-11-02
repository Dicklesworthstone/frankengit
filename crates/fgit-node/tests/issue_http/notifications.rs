//! Real HTTP authentication, native preference publication and reconstructed
//! inboxes. Recipient identity always comes from the authenticated credential.

use super::*;

struct PreferenceGuards {
    incarnation: String,
}

impl PreferenceGuards {
    fn new(node: &OneNode) -> Self {
        Self {
            incarnation: node.repository_incarnation_id().to_string(),
        }
    }

    fn form(&self, actor: u8, fields: &str) -> String {
        format!(
            "{fields}&expected_principal={}&expected_incarnation={}",
            principal(actor),
            self.incarnation
        )
    }
}

fn notification_grants(node: &OneNode, path: &Path) -> String {
    let header = grants(node, path);
    replace(
        path,
        &(header.clone()
            + &row('a', 0xa1, "issues-read")
            + &row('b', 0xb1, "issues-write")
            + &row('c', 0xc1, "issues-read,issues-write")
            + &row('d', 0xd1, "read,receive")
            + &row('e', 0xe1, "notifications-write")
            + &row('f', 0xf1, "issues-read,notifications-write")
            + &row('1', 0xb1, "issues-read,issues-write,notifications-write")
            + &row('2', 0xa1, "issues-read,notifications-write")
            + &row('3', 0xc1, "issues-read,notifications-write")
            + &row('4', 0xe1, "issues-write,notifications-write")),
    );
    header
}

fn notification_committed(reply: &Reply, actor: u8) {
    status(reply, 200);
    for field in [
        "\"type\":\"notification_publication\"".to_owned(),
        "\"outcome\":\"committed\"".to_owned(),
        format!("\"principal_id\":\"{}\"", principal(actor)),
        "\"delivery_acknowledged\":null".to_owned(),
    ] {
        assert!(reply.body.contains(&field), "{}", reply.body);
    }
}

fn source_is_self(reply: &Reply, actor: u8) {
    status(reply, 200);
    assert!(
        reply
            .body
            .contains(&format!("\"principal_id\":\"{}\"", principal(actor))),
        "{}",
        reply.body
    );
    for field in [
        "\"source_positions\":{",
        "\"forge_position_root\":",
        "\"outbox_root\":",
        "\"complete\":true",
    ] {
        assert!(reply.body.contains(field), "{}", reply.body);
    }
}

fn has_thread(reply: &Reply, number: u64) -> bool {
    reply
        .body
        .contains(&format!("\"number\":{number},\"issue_version\":"))
}

fn preference(reply: &Reply, version: Option<u64>, mode: &str, read_through: Option<u64>) {
    status(reply, 200);
    let version = version.map_or_else(|| "null".to_owned(), |value| value.to_string());
    let read = read_through.map_or_else(|| "null".to_owned(), |value| value.to_string());
    assert!(
        reply.body.contains(&format!(
            "\"preference_version\":{version},\"mode\":\"{mode}\",\"read_through\":{read}"
        )),
        "{}",
        reply.body
    );
}

#[test]
fn inbox_reasons_are_self_owned_and_notification_writes_require_both_explicit_grants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let node = start_node(config(&root, format));
        let guards = PreferenceGuards::new(&node);
        let path = root.0.join("credentials");
        let header = notification_grants(&node, &path);
        let server = Server::start(node, path.clone(), 32, true);
        committed(&post(
            &server,
            "/api/v1/issues/1/open",
            'b',
            "reason-open",
            "expected_version=0&title=Reasons&body=Original",
            false,
        )); // 1
        committed(&post(
            &server,
            "/api/v1/issues/1/comment",
            'c',
            "reason-comment",
            "expected_version=1&body=Participant",
            true,
        )); // 2
        committed(&post(
            &server,
            "/api/v1/issues/1/assign",
            'b',
            "reason-assign",
            &format!("expected_version=2&assignee={}", principal(0xa1)),
            false,
        )); // 3

        for (credential, actor, reasons) in [
            ('1', 0xb1, "[\"author\",\"participant\"]"),
            ('3', 0xc1, "[\"participant\"]"),
            ('2', 0xa1, "[\"assignee\"]"),
        ] {
            let inbox = get(&server, "/api/v1/notifications", credential); // 4..6
            source_is_self(&inbox, actor);
            assert!(has_thread(&inbox, 1));
            assert!(
                inbox.body.contains(&format!("\"reasons\":{reasons}")),
                "{}",
                inbox.body
            );
            preference(&inbox, None, "automatic", None);
        }
        let unrelated = get(&server, "/api/v1/notifications", 'f'); // 7
        source_is_self(&unrelated, 0xf1);
        assert!(unrelated.body.contains("\"threads\":[]"));
        let exact = get(&server, "/api/v1/notifications/1", 'f'); // 8
        source_is_self(&exact, 0xf1);
        assert!(exact.body.contains("\"found\":true"));
        assert!(exact.body.contains("\"reasons\":[]"));
        preference(&exact, None, "automatic", None);
        notification_committed(
            &post(
                &server,
                "/api/v1/notifications/1/subscribe",
                'f',
                "reason-subscribe",
                &guards.form(0xf1, "expected_version=0"),
                true,
            ),
            0xf1,
        ); // 9
        let subscribed = get(&server, "/api/v1/notifications", 'f'); // 10
        source_is_self(&subscribed, 0xf1);
        preference(&subscribed, Some(1), "subscribed", None);
        assert!(subscribed.body.contains("\"reasons\":[\"subscribed\"]"));
        let author = get(&server, "/api/v1/notifications/1", '1'); // 11
        source_is_self(&author, 0xb1);
        preference(&author, None, "automatic", None);

        // Neither issue-write nor notification-write implies issue disclosure.
        for credential in ['b', 'e', '4', 'd'] {
            status(&get(&server, "/api/v1/notifications", credential), 403); // 12..15
        }
        // Issue disclosure by itself does not permit preference mutation.
        // Even issue-read + issue-write needs the separate notification grant.
        for credential in ['a', 'b', 'c', 'e', '4', 'd'] {
            status(
                &post(
                    &server,
                    "/api/v1/notifications/1/mute",
                    credential,
                    &format!("denied-{credential}"),
                    "expected_version=0",
                    false,
                ),
                403,
            ); // 16..21
        }
        status(
            &post(
                &server,
                "/api/v1/notifications/1/mute",
                'f',
                "forged-recipient",
                &guards.form(
                    0xf1,
                    &format!("expected_version=1&principal={}", principal(0xb1)),
                ),
                false,
            ),
            400,
        ); // 22
        status(
            &get(
                &server,
                &format!("/api/v1/notifications?principal={}", principal(0xb1)),
                'f',
            ),
            400,
        ); // 23
        let missing = get(&server, "/api/v1/notifications/999", 'f'); // 24
        status(&missing, 404);
        assert!(missing.body.contains("\"found\":false,\"thread\":null"));
        let read_only = get(&server, "/api/v1/notifications/1", 'a'); // 25
        source_is_self(&read_only, 0xa1);
        preference(&read_only, None, "automatic", None);
        status(
            &post(
                &server,
                "/api/v1/notifications/1/mute",
                'f',
                "missing-guards",
                "expected_version=1",
                false,
            ),
            400,
        ); // 26
        let wrong_actor = post(
            &server,
            "/api/v1/notifications/1/mute",
            'f',
            "wrong-principal",
            &guards.form(0xb1, "expected_version=1"),
            false,
        ); // 27
        status(&wrong_actor, 409);
        assert!(
            wrong_actor
                .body
                .contains("\"code\":\"notification_identity_changed\"")
        );
        let mut wrong_incarnation = guards.incarnation.clone();
        wrong_incarnation.pop();
        wrong_incarnation.push(if guards.incarnation.ends_with('f') {
            'e'
        } else {
            'f'
        });
        let wrong_repository = post(
            &server,
            "/api/v1/notifications/1/mute",
            'f',
            "wrong-incarnation",
            &PreferenceGuards {
                incarnation: wrong_incarnation,
            }
            .form(0xf1, "expected_version=1"),
            false,
        ); // 28
        status(&wrong_repository, 409);
        assert!(
            wrong_repository
                .body
                .contains("\"code\":\"notification_identity_changed\"")
        );
        let unchanged = get(&server, "/api/v1/notifications/1", 'f'); // 29
        preference(&unchanged, Some(1), "subscribed", None);
        assert_eq!(
            token(&unchanged),
            token(&subscribed),
            "guard refusals never enter admission"
        );

        // A saved request cannot follow the same bearer into another account.
        replace(
            &path,
            &(header.clone() + &row('f', 0xb1, "issues-read,notifications-write")),
        );
        let rebound = post(
            &server,
            "/api/v1/notifications/1/subscribe",
            'f',
            "reason-subscribe",
            &guards.form(0xf1, "expected_version=0"),
            false,
        ); // 30
        status(&rebound, 409);
        assert!(
            rebound
                .body
                .contains("\"code\":\"notification_identity_changed\"")
        );
        let rebound_thread = get(&server, "/api/v1/notifications/1", 'f'); // 31
        source_is_self(&rebound_thread, 0xb1);
        preference(&rebound_thread, None, "automatic", None);
        replace(
            &path,
            &(header + &row('f', 0xf1, "issues-read,notifications-write")),
        );
        assert_eq!(
            get(&server, "/api/v1/notifications/1", 'f').body,
            unchanged.body
        ); // 32
        assert_eq!(server.finish().accepted_sessions(), 32);
    }
}

#[test]
fn read_prefixes_preference_versions_muting_and_retries_survive_later_comments_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = start_node(configuration.clone());
        let guards = PreferenceGuards::new(&node);
        let path = root.0.join("credentials");
        notification_grants(&node, &path);
        let server = Server::start(node, path.clone(), 27, true);
        committed(&post(
            &server,
            "/api/v1/issues/1/open",
            'b',
            "prefix-open",
            "expected_version=0&title=Read-prefix&body=Original",
            false,
        )); // 1
        let subscribed = post(
            &server,
            "/api/v1/notifications/1/subscribe",
            'f',
            "subscribe-original",
            &guards.form(0xf1, "expected_version=0"),
            true,
        ); // 2
        notification_committed(&subscribed, 0xf1);
        let observed = get(&server, "/api/v1/notifications/1", 'f'); // 3
        preference(&observed, Some(1), "subscribed", None);
        assert!(observed.body.contains("\"issue_version\":1"));

        committed(&post(
            &server,
            "/api/v1/issues/1/comment",
            'c',
            "later-comment",
            "expected_version=1&body=Arrives-after-the-observed-prefix",
            false,
        )); // 4
        let first_read = post(
            &server,
            "/api/v1/notifications/1/read",
            'f',
            "read-observed",
            &guards.form(0xf1, "expected_version=1&read_through=1"),
            false,
        ); // 5
        notification_committed(&first_read, 0xf1);
        let raced = get(&server, "/api/v1/notifications/1", 'f'); // 6
        preference(&raced, Some(2), "subscribed", Some(1));
        assert!(raced.body.contains("\"issue_version\":2"));
        assert!(
            raced
                .body
                .contains("\"latest_other_version\":2,\"unread\":true")
        );
        let stale = post(
            &server,
            "/api/v1/notifications/1/mute",
            'f',
            "stale-preference",
            &guards.form(0xf1, "expected_version=1"),
            false,
        ); // 7
        status(&stale, 409);
        assert!(stale.body.contains("\"refusal_code\":\"EvidenceStale\""));
        let retried = post(
            &server,
            "/api/v1/notifications/1/read",
            'f',
            "read-observed",
            &guards.form(0xf1, "expected_version=1&read_through=1"),
            true,
        ); // 8
        notification_committed(&retried, 0xf1);
        assert_eq!(retried.body, first_read.body);
        let future = post(
            &server,
            "/api/v1/notifications/1/read",
            'f',
            "future-prefix",
            &guards.form(0xf1, "expected_version=2&read_through=999"),
            false,
        ); // 9
        status(&future, 409);
        assert!(future.body.contains("\"refusal_code\":\"EvidenceStale\""));
        notification_committed(
            &post(
                &server,
                "/api/v1/notifications/1/read",
                'f',
                "read-current",
                &guards.form(0xf1, "expected_version=2&read_through=2"),
                false,
            ),
            0xf1,
        ); // 10
        let read_page = get(&server, "/api/v1/notifications?unread_only=true", 'f'); // 11
        status(&read_page, 200);
        assert!(read_page.body.contains("\"threads\":[]"));
        let read_thread = get(&server, "/api/v1/notifications/1", 'f'); // 12
        preference(&read_thread, Some(3), "subscribed", Some(2));
        assert!(read_thread.body.contains("\"unread\":false"));
        notification_committed(
            &post(
                &server,
                "/api/v1/notifications/1/unread",
                'f',
                "mark-unread",
                &guards.form(0xf1, "expected_version=3"),
                true,
            ),
            0xf1,
        ); // 13
        let unread = get(&server, "/api/v1/notifications?unread_only=true", 'f'); // 14
        preference(&unread, Some(4), "subscribed", None);
        assert!(has_thread(&unread, 1));
        notification_committed(
            &post(
                &server,
                "/api/v1/notifications/1/mute",
                'f',
                "mute-current",
                &guards.form(0xf1, "expected_version=4"),
                false,
            ),
            0xf1,
        ); // 15
        let muted_default = get(&server, "/api/v1/notifications", 'f'); // 16
        status(&muted_default, 200);
        assert!(muted_default.body.contains("\"threads\":[]"));
        let muted_included = get(&server, "/api/v1/notifications?include_muted=true", 'f'); // 17
        preference(&muted_included, Some(5), "muted", None);
        assert!(has_thread(&muted_included, 1));
        let muted_thread = get(&server, "/api/v1/notifications/1", 'f'); // 18
        preference(&muted_thread, Some(5), "muted", None);
        notification_committed(
            &post(
                &server,
                "/api/v1/notifications/1/automatic",
                'f',
                "automatic-current",
                &guards.form(0xf1, "expected_version=5"),
                false,
            ),
            0xf1,
        ); // 19
        let automatic = get(&server, "/api/v1/notifications", 'f'); // 20
        status(&automatic, 200);
        assert!(automatic.body.contains("\"threads\":[]"));
        let automatic_thread = get(&server, "/api/v1/notifications/1", 'f'); // 21
        preference(&automatic_thread, Some(6), "automatic", None);
        assert!(automatic_thread.body.contains("\"reasons\":[]"));
        notification_committed(
            &post(
                &server,
                "/api/v1/notifications/1/subscribe",
                'f',
                "resubscribe",
                &guards.form(0xf1, "expected_version=6"),
                false,
            ),
            0xf1,
        ); // 22
        let final_thread = get(&server, "/api/v1/notifications/1", 'f'); // 23
        preference(&final_thread, Some(7), "subscribed", None);
        assert!(
            final_thread
                .body
                .contains("\"latest_other_version\":2,\"unread\":true")
        );
        let original_retry = post(
            &server,
            "/api/v1/notifications/1/subscribe",
            'f',
            "subscribe-original",
            &guards.form(0xf1, "expected_version=0"),
            false,
        ); // 24
        assert_eq!(original_retry.body, subscribed.body);
        let conflicting_retry = post(
            &server,
            "/api/v1/notifications/1/subscribe",
            'f',
            "subscribe-original",
            &guards.form(0xf1, "expected_version=6"),
            false,
        ); // 25
        status(&conflicting_retry, 409);
        assert!(
            conflicting_retry
                .body
                .contains("\"code\":\"idempotency_key_reuse\"")
        );
        let author = get(&server, "/api/v1/notifications/1", '1'); // 26
        preference(&author, None, "automatic", None);
        let stable = get(&server, "/api/v1/notifications/1", 'f'); // 27
        preference(&stable, Some(7), "subscribed", None);
        assert_eq!(server.finish().accepted_sessions(), 27);

        let node = reopened(configuration.clone());
        let server = Server::start(node, path, 3, true);
        let recovered = get(&server, "/api/v1/notifications/1", 'f');
        source_is_self(&recovered, 0xf1);
        assert_eq!(recovered.body, stable.body);
        assert_eq!(
            post(
                &server,
                "/api/v1/notifications/1/subscribe",
                'f',
                "subscribe-original",
                &guards.form(0xf1, "expected_version=0"),
                true
            )
            .body,
            subscribed.body
        );
        let inbox = get(&server, "/api/v1/notifications?unread_only=true", 'f');
        preference(&inbox, Some(7), "subscribed", None);
        assert!(has_thread(&inbox, 1));
        assert_eq!(server.finish().accepted_sessions(), 3);
        let node = reopened(configuration);
        let issue = node
            .runtime()
            .block_on(node.read_issue_history_in(
                &node.request_context(),
                IssueNumber::FIRST,
                0,
                10,
                None,
            ))
            .unwrap()
            .issue
            .unwrap();
        assert_eq!(
            issue.version.get(),
            2,
            "preference events never edit the issue aggregate"
        );
        assert_eq!(issue.comments, 1);
        assert_eq!(issue.body, "Original");
        assert!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs
                .is_empty()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn inbox_pages_pin_both_issue_and_preference_sources_across_writes_rotation_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let configuration = config(&root, format);
        let node = start_node(configuration.clone());
        let guards = PreferenceGuards::new(&node);
        let path = root.0.join("credentials");
        let header = notification_grants(&node, &path);
        let server = Server::start(node, path.clone(), 18, true);
        for number in [1, 3, 5] {
            committed(&post(
                &server,
                &format!("/api/v1/issues/{number}/open"),
                'b',
                &format!("pin-open-{number}"),
                &format!("expected_version=0&title=Original-{number}&body="),
                false,
            )); // 1..3
        }
        let first = get(&server, "/api/v1/notifications?limit=1", '1'); // 4
        source_is_self(&first, 0xb1);
        assert!(has_thread(&first, 1));
        assert!(first.body.contains("\"next_after\":1"));
        let pin = token(&first);
        committed(&post(
            &server,
            "/api/v1/issues/2/open",
            'b',
            "pin-insertion",
            "expected_version=0&title=Inserted-after-pin&body=",
            true,
        )); // 5
        notification_committed(
            &post(
                &server,
                "/api/v1/notifications/3/mute",
                '1',
                "pin-mute",
                &guards.form(0xb1, "expected_version=0"),
                false,
            ),
            0xb1,
        ); // 6
        committed(&post(
            &server,
            "/api/v1/issues/5/close",
            'b',
            "pin-close",
            "expected_version=1",
            false,
        )); // 7
        let second_path = format!("/api/v1/notifications?limit=1&after=1&expected_head={pin}");
        let second = get(&server, &second_path, '1'); // 8
        source_is_self(&second, 0xb1);
        assert_eq!(token(&second), pin);
        assert!(has_thread(&second, 3));
        preference(&second, None, "automatic", None);
        assert!(second.body.contains("\"next_after\":3"));
        let last_path = format!("/api/v1/notifications?limit=1&after=3&expected_head={pin}");
        let last = get(&server, &last_path, '1'); // 9
        assert_eq!(token(&last), pin);
        assert!(has_thread(&last, 5));
        assert!(last.body.contains("\"state\":\"open\""));
        assert!(last.body.contains("\"next_after\":null"));
        let fresh = get(&server, "/api/v1/notifications?limit=100", '1'); // 10
        source_is_self(&fresh, 0xb1);
        assert_ne!(token(&fresh), pin);
        for number in [1, 2, 5] {
            assert!(has_thread(&fresh, number));
        }
        assert!(!has_thread(&fresh, 3));
        assert!(fresh.body.contains("\"state\":\"closed\""));
        let pinned_thread = get(
            &server,
            &format!("/api/v1/notifications/3?expected_head={pin}"),
            '1',
        ); // 11
        preference(&pinned_thread, None, "automatic", None);
        let current_thread = get(&server, "/api/v1/notifications/3", '1'); // 12
        preference(&current_thread, Some(1), "muted", None);
        status(&get(&server, "/api/v1/notifications?after=1", '1'), 400); // 13
        let mut unknown = pin.clone();
        unknown.pop();
        unknown.push(if pin.ends_with('f') { 'e' } else { 'f' });
        let unavailable = get(
            &server,
            &format!("/api/v1/notifications?after=1&expected_head={unknown}"),
            '1',
        ); // 14
        status(&unavailable, 409);
        assert!(unavailable.body.contains("\"code\":\"snapshot_moved\""));
        let other_principal = get(&server, &second_path, 'f'); // 15
        source_is_self(&other_principal, 0xf1);
        assert!(other_principal.body.contains("\"threads\":[]"));

        replace(
            &path,
            &(header
                + &row('5', 0xb1, "issues-read,notifications-write")
                + &row('d', 0xd1, "read,receive")),
        );
        status(&get(&server, &second_path, '1'), 401); // 16
        assert_eq!(get(&server, &second_path, '5').body, second.body); // 17
        status(&get(&server, &second_path, 'd'), 403); // 18
        assert_eq!(server.finish().accepted_sessions(), 18);

        let node = reopened(configuration);
        let server = Server::start(node, path, 3, true);
        assert_eq!(get(&server, &second_path, '5').body, second.body);
        assert_eq!(get(&server, &last_path, '5').body, last.body);
        let recovered = get(&server, "/api/v1/notifications/3", '5');
        source_is_self(&recovered, 0xb1);
        preference(&recovered, Some(1), "muted", None);
        assert_eq!(server.finish().accepted_sessions(), 3);
    }
}

#[test]
fn legacy_git_http_entry_point_does_not_enable_notification_routes() {
    let root = Scratch::new();
    let node = start_node(config(&root, GitHashAlgorithm::Sha1));
    let path = root.0.join("credentials");
    notification_grants(&node, &path);
    let server = Server::start(node, path, 2, false);
    status(&get(&server, "/api/v1/notifications", 'f'), 403);
    status(
        &post(
            &server,
            "/api/v1/notifications/1/subscribe",
            'f',
            "disabled-notifications",
            "expected_version=0",
            false,
        ),
        403,
    );
    assert_eq!(server.finish().refused_sessions(), 2);
}
