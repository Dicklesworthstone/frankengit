#![forbid(unsafe_code)]
//! Real native label publication, authority snapshots and durable original-key
//! retries through the production TCP service in both Git object formats.

#[path = "pull_request_labels_http/addition.rs"]
mod addition;
#[path = "pull_request_http/support.rs"]
mod support;

use fgit_types::GitHashAlgorithm;
use support::*;

const LABELS: &str = "/api/v1/pulls/1/labels";

fn label_committed(reply: &Reply, version: u64) {
    status(reply, 200);
    for field in [
        "\"type\":\"pull_request_labels_publication\"",
        "\"action\":\"set-labels\"",
        "\"outcome\":\"committed\"",
        "\"refs_changed\":false",
        "\"pull_request_version_changed\":false",
        "\"delivery_acknowledged\":null",
    ] {
        assert!(reply.body.contains(field), "{}", reply.body);
    }
    assert!(
        reply
            .body
            .contains(&format!("\"labels_version\":{version}"))
    );
}

#[test]
fn labels_preserve_content_versions_and_original_receipts_across_close_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        let credentials = root.0.join("credentials");
        grants(&node, &credentials);
        let server = Server::start(node, &credentials, 22, true, true);
        let client = &server.client;
        let original = "expected_version=0&label=triage&label=bug";
        status(
            &post(client, 7, "labels", 'b', "missing", original, false),
            409,
        ); // 1
        committed(&post(
            client,
            1,
            "open",
            'b',
            "open",
            &form(&data, 0),
            false,
        )); // 2
        let empty = get(client, LABELS, 'a'); // 3
        status(&empty, 200);
        assert!(
            empty
                .body
                .contains("\"labels\":[],\"labels_version\":0,\"labels_actor\":null")
        );
        assert!(empty.body.contains("\"pull_request_version\":1"));
        assert!(empty.body.contains("\"transaction_created\":false"));
        status(
            &post(client, 1, "labels", 'a', "reader", original, false),
            403,
        ); // 4
        status(&get(client, LABELS, 'b'), 403); // 5
        status(
            &post(client, 1, "labels", 'd', "wrong-grant", original, false),
            403,
        ); // 6
        let first = post(client, 1, "labels", 'b', "first-labels", original, false); // 7
        label_committed(&first, 1);
        assert!(first.body.contains("\"labels\":[\"bug\",\"triage\"]"));
        let selected = get(client, LABELS, 'a'); // 8
        status(&selected, 200);
        let pin = token(&selected);
        assert!(selected.body.contains("\"pull_request_version\":1"));
        assert!(
            selected
                .body
                .contains(&format!("\"labels_actor\":\"{OWNER}\""))
        );
        let filtered = get(client, "/api/v1/pulls?label=bug&limit=1", 'a'); // 9
        status(&filtered, 200);
        assert!(
            filtered
                .body
                .contains("\"labels\":[\"bug\"],\"pull_requests\":[")
        );
        assert!(filtered.body.contains("\"number\":1,\"version\":1"));
        assert_eq!(
            post(client, 1, "labels", 'b', "first-labels", original, true).body,
            first.body
        ); // 10
        status(
            &post(
                client,
                1,
                "labels",
                'b',
                "first-labels",
                "expected_version=0&label=changed",
                false,
            ),
            409,
        ); // 11
        status(
            &post(client, 1, "labels", 'b', "stale", original, false),
            409,
        ); // 12
        label_committed(
            &post(
                client,
                1,
                "labels",
                'b',
                "clear",
                "expected_version=1&clear_labels=true",
                true,
            ),
            2,
        ); // 13
        let retained = get(client, &format!("{LABELS}?expected_head={pin}"), 'a'); // 14
        status(&retained, 200);
        assert!(
            retained
                .body
                .contains("\"labels\":[\"bug\",\"triage\"],\"labels_version\":1")
        );
        let cleared = get(client, LABELS, 'a'); // 15
        status(&cleared, 200);
        assert!(cleared.body.contains("\"labels\":[],\"labels_version\":2"));
        assert_eq!(
            post(client, 1, "labels", 'b', "first-labels", original, false).body,
            first.body
        ); // 16
        committed(&post(
            client,
            1,
            "close",
            'b',
            "close",
            &form(&data, 1),
            false,
        )); // 17
        label_committed(
            &post(
                client,
                1,
                "labels",
                'b',
                "closed-labels",
                "expected_version=2&label=archived",
                false,
            ),
            3,
        ); // 18
        let closed = get(client, "/api/v1/pulls/1", 'a'); // 19
        status(&closed, 200);
        assert!(closed.body.contains("\"version\":2,\"state\":\"closed\""));
        assert!(
            closed
                .body
                .contains("\"labels\":[\"archived\"],\"labels_version\":3")
        );
        let missing = get(client, "/api/v1/pulls/99/labels", 'a'); // 20
        status(&missing, 404);
        assert!(missing.body.contains("\"found\":false"));
        assert!(
            missing
                .body
                .contains("\"labels\":null,\"labels_version\":null")
        );
        status(
            &post(
                client,
                1,
                "labels",
                'b',
                "missing-set",
                "expected_version=3",
                false,
            ),
            400,
        ); // 21
        status(
            &post(
                client,
                1,
                "labels",
                'b',
                "caller-actor",
                "expected_version=3&label=bug&actor=administrator",
                false,
            ),
            400,
        ); // 22
        server.finish();

        let node = reopen(&config);
        let server = Server::start(node, &credentials, 4, true, true);
        let client = &server.client;
        let persisted = get(client, LABELS, 'a'); // 1
        status(&persisted, 200);
        assert!(persisted.body.contains("\"pull_request_version\":2"));
        assert!(
            persisted
                .body
                .contains("\"labels\":[\"archived\"],\"labels_version\":3")
        );
        label_committed(
            &post(
                client,
                1,
                "labels",
                'b',
                "clear-after-restart",
                "expected_version=3&clear_labels=true",
                false,
            ),
            4,
        ); // 2
        let unchanged = get(client, "/api/v1/pulls/1", 'a'); // 3
        status(&unchanged, 200);
        assert!(
            unchanged
                .body
                .contains("\"version\":2,\"state\":\"closed\"")
        );
        assert_eq!(
            post(client, 1, "labels", 'b', "first-labels", original, false).body,
            first.body
        ); // 4
        server.finish();
    }
}

#[test]
fn label_filters_run_before_page_limits_and_preserve_pinned_numeric_order() {
    let root = Scratch::new();
    let (node, data) = fixture(&root, GitHashAlgorithm::Sha256);
    let credentials = root.0.join("credentials");
    grants(&node, &credentials);
    let server = Server::start(node, &credentials, 11, true, false);
    let client = &server.client;
    for number in 1..=3 {
        committed(&post(
            client,
            number,
            "open",
            'b',
            &format!("open-{number}"),
            &form(&data, 0),
            false,
        ));
    } // 1..3
    label_committed(
        &post(
            client,
            1,
            "labels",
            'b',
            "labels-1",
            "expected_version=0&label=bug",
            false,
        ),
        1,
    ); // 4
    label_committed(
        &post(
            client,
            3,
            "labels",
            'b',
            "labels-3",
            "expected_version=0&label=triage&label=bug",
            false,
        ),
        1,
    ); // 5
    let triage = get(client, "/api/v1/pulls?label=triage&limit=1", 'a'); // 6
    status(&triage, 200);
    assert!(triage.body.contains("\"number\":3,\"version\":1"));
    assert!(!triage.body.contains("\"number\":1,"));
    let first = get(client, "/api/v1/pulls?label=bug&limit=1", 'a'); // 7
    status(&first, 200);
    assert!(first.body.contains("\"next_after\":1"));
    assert!(first.body.contains("\"number\":1,\"version\":1"));
    let second = get(
        client,
        &format!(
            "/api/v1/pulls?label=bug&limit=1&after=1&expected_head={}",
            token(&first)
        ),
        'a',
    ); // 8
    status(&second, 200);
    assert!(second.body.contains("\"next_after\":null"));
    assert!(second.body.contains("\"number\":3,\"version\":1"));
    let both = get(client, "/api/v1/pulls?label=triage&label=bug", 'a'); // 9
    status(&both, 200);
    assert!(
        both.body
            .contains("\"labels\":[\"bug\",\"triage\"],\"pull_requests\":[")
    );
    assert!(both.body.contains("\"number\":3,\"version\":1"));
    assert!(!both.body.contains("\"number\":1,"));
    let none = get(client, "/api/v1/pulls?label=missing", 'a'); // 10
    status(&none, 200);
    assert!(none.body.contains("\"pull_requests\":[]"));
    status(&get(client, "/api/v1/pulls?label=bug&label=bug", 'a'), 400); // 11
    server.finish();
}
