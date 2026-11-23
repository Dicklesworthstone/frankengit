//! Additive labels over real TCP, durable authority and imported native objects.
use super::*;

const ADD: &str = "labels/add";

fn added(reply: &Reply, additions: &str) {
    status(reply, 200);
    for field in [
        "\"type\":\"pull_request_labels_publication\"",
        "\"action\":\"add-labels\"",
        "\"command_profile\":\"pull-request.add-labels.v1\"",
        "\"expected_version\":null",
        "\"labels_version\":null",
        "\"outcome\":\"committed\"",
        "\"refs_changed\":false",
        "\"pull_request_version_changed\":false",
        "\"delivery_acknowledged\":null",
    ] {
        assert!(reply.body.contains(field), "{}", reply.body);
    }
    assert!(
        reply.body.contains(&format!("\"labels\":{additions}")),
        "{}",
        reply.body
    );
}

fn content(reply: &Reply) -> &str {
    reply
        .body
        .split_once("\"number\":1,")
        .unwrap()
        .1
        .split_once(",\"labels\":")
        .unwrap()
        .0
}

#[test]
fn additions_union_and_keep_original_receipts_after_exact_clear_close_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        let credentials = root.0.join("credentials");
        grants(&node, &credentials);
        let server = Server::start(node, &credentials, 18, true, true);
        let client = &server.client;
        let original = "label=triage&label=urgent";
        let missing = post(client, 99, ADD, 'b', "add-missing", original, false); // 1
        status(&missing, 409);
        assert!(
            missing
                .body
                .contains("\"refusal_code\":\"EvidenceMissing\"")
        );
        committed(&post(
            client,
            1,
            "open",
            'b',
            "add-open",
            &form(&data, 0),
            false,
        )); // 2
        label_committed(
            &post(
                client,
                1,
                "labels",
                'b',
                "add-base",
                "expected_version=0&label=bug",
                false,
            ),
            1,
        ); // 3
        let before = get(client, "/api/v1/pulls/1", 'a'); // 4
        status(&before, 200);
        let first = post(client, 1, ADD, 'b', "add-original", original, true); // 5
        added(&first, "[\"triage\",\"urgent\"]");
        let selected = get(client, LABELS, 'a'); // 6
        status(&selected, 200);
        let pin = token(&selected);
        assert!(
            selected
                .body
                .contains("\"labels\":[\"bug\",\"triage\",\"urgent\"],\"labels_version\":2")
        );
        assert!(selected.body.contains("\"pull_request_version\":1"));
        assert!(
            selected
                .body
                .contains(&format!("\"labels_actor\":\"{OWNER}\""))
        );
        let after = get(client, "/api/v1/pulls/1", 'a'); // 7
        status(&after, 200);
        assert_eq!(content(&before), content(&after));
        let filtered = get(client, "/api/v1/pulls?label=bug&label=urgent", 'a'); // 8
        status(&filtered, 200);
        assert!(filtered.body.contains("\"number\":1,\"version\":1"));
        added(
            &post(client, 1, ADD, 'b', "add-overlap", "label=bug", false),
            "[\"bug\"]",
        ); // 9
        label_committed(
            &post(
                client,
                1,
                "labels",
                'b',
                "add-clear",
                "expected_version=3&clear_labels=true",
                true,
            ),
            4,
        ); // 10
        assert_eq!(
            post(
                client,
                1,
                ADD,
                'b',
                "add-original",
                "label=urgent&label=triage",
                false
            )
            .body,
            first.body
        ); // 11
        let cleared = get(client, LABELS, 'a'); // 12
        status(&cleared, 200);
        assert!(cleared.body.contains("\"labels\":[],\"labels_version\":4"));
        let retained = get(client, &format!("{LABELS}?expected_head={pin}"), 'a'); // 13
        status(&retained, 200);
        assert!(
            retained
                .body
                .contains("\"labels\":[\"bug\",\"triage\",\"urgent\"],\"labels_version\":2")
        );
        status(
            &post(client, 1, ADD, 'b', "add-original", "label=changed", false),
            409,
        ); // 14
        status(
            &post(
                client,
                1,
                "labels",
                'b',
                "add-original",
                "expected_version=0&label=triage&label=urgent",
                false,
            ),
            409,
        ); // 15
        committed(&post(
            client,
            1,
            "close",
            'b',
            "add-close",
            &form(&data, 1),
            false,
        )); // 16
        added(
            &post(client, 1, ADD, 'b', "add-closed", "label=archived", false),
            "[\"archived\"]",
        ); // 17
        let closed = get(client, "/api/v1/pulls/1", 'a'); // 18
        status(&closed, 200);
        assert!(closed.body.contains("\"version\":2,\"state\":\"closed\""));
        assert!(
            closed
                .body
                .contains("\"labels\":[\"archived\"],\"labels_version\":5")
        );
        server.finish();

        let server = Server::start(reopen(&config), &credentials, 4, true, true);
        let client = &server.client;
        assert_eq!(
            post(client, 1, ADD, 'b', "add-original", original, true).body,
            first.body
        ); // 1
        let persisted = get(client, LABELS, 'a'); // 2
        status(&persisted, 200);
        assert!(
            persisted
                .body
                .contains("\"labels\":[\"archived\"],\"labels_version\":5")
        );
        assert!(persisted.body.contains("\"pull_request_version\":2"));
        let retained = get(client, &format!("{LABELS}?expected_head={pin}"), 'a'); // 3
        status(&retained, 200);
        assert!(
            retained
                .body
                .contains("\"labels\":[\"bug\",\"triage\",\"urgent\"],\"labels_version\":2")
        );
        let unchanged = get(client, "/api/v1/pulls/1", 'a'); // 4
        status(&unchanged, 200);
        assert_eq!(content(&unchanged), content(&closed));
        server.finish();
    }
}

#[test]
fn malformed_additions_and_missing_write_permissions_never_publish() {
    let invalid = [
        "",
        "label=",
        "label=+",
        "label=bug&label=bug",
        "label=bug&label=%62ug",
        "label=bug&expected_version=0",
        "label=bug&expected_version=1",
        "clear_labels=true",
        "label=bug&clear_labels=true",
        "label=bug&actor=administrator",
        "label=bug&expected_head=ignored",
        "label=%FF",
        "label=x%00y",
        "label=x%0Ay",
        "label=%",
    ];
    let root = Scratch::new();
    let (node, data) = fixture(&root, GitHashAlgorithm::Sha256);
    let credentials = root.0.join("credentials");
    grants(&node, &credentials);
    let server = Server::start(node, &credentials, invalid.len() + 10, true, false);
    let client = &server.client;
    committed(&post(
        client,
        1,
        "open",
        'b',
        "grammar-open",
        &form(&data, 0),
        false,
    )); // 1
    let before = get(client, LABELS, 'a'); // 2
    status(&before, 200);
    for (index, body) in invalid.iter().enumerate() {
        status(
            &post(
                client,
                1,
                ADD,
                'b',
                &format!("bad-addition-{index}"),
                body,
                index % 2 == 1,
            ),
            400,
        );
    }
    for (token, expected) in [('a', 403), ('d', 403), ('x', 401)] {
        // +3
        status(
            &post(
                client,
                1,
                ADD,
                token,
                "wrong-addition-grant",
                "label=bug",
                false,
            ),
            expected,
        );
    }
    let no_key = request(
        client,
        "POST",
        "/api/v1/pulls/1/labels/add",
        'b',
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n",
        b"label=bug",
    );
    status(&exchange(client, &no_key, true), 400); // +1
    status(&get(client, "/api/v1/pulls/1/labels/add", 'a'), 405); // +1
    let unchanged = get(client, LABELS, 'a'); // +1
    status(&unchanged, 200);
    assert_eq!(token(&before), token(&unchanged));
    added(
        &post(
            client,
            1,
            ADD,
            'b',
            "valid-addition-after-errors",
            "label=bug",
            true,
        ),
        "[\"bug\"]",
    ); // +1
    let selected = get(client, LABELS, 'a'); // +1
    status(&selected, 200);
    assert!(
        selected
            .body
            .contains("\"labels\":[\"bug\"],\"labels_version\":1")
    );
    server.finish();
}

#[test]
fn additive_http_bounds_preserve_full_sets_and_report_capacity_refusals() {
    let root = Scratch::new();
    let (node, data) = fixture(&root, GitHashAlgorithm::Sha256);
    let credentials = root.0.join("credentials");
    grants(&node, &credentials);
    let server = Server::start(node, &credentials, 9, true, false);
    let client = &server.client;
    committed(&post(
        client,
        1,
        "open",
        'b',
        "bounds-open",
        &form(&data, 0),
        false,
    )); // 1
    let longest = "é".repeat(32);
    added(
        &post(
            client,
            1,
            ADD,
            'b',
            "maximum-label-bytes",
            &format!("label={}", encode(longest.as_bytes())),
            false,
        ),
        &format!("[\"{longest}\"]"),
    ); // 2
    status(
        &post(
            client,
            1,
            ADD,
            'b',
            "excess-label-bytes",
            &format!("label={}", encode("é".repeat(33).as_bytes())),
            true,
        ),
        413,
    ); // 3
    let excessive = (0..33)
        .map(|index| format!("label=label-{index:02}"))
        .collect::<Vec<_>>()
        .join("&");
    status(
        &post(client, 1, ADD, 'b', "excess-label-count", &excessive, false),
        413,
    ); // 4
    let thirty_one = (0..31)
        .map(|index| format!("label=label-{index:02}"))
        .collect::<Vec<_>>()
        .join("&");
    let receipt = post(
        client,
        1,
        ADD,
        'b',
        "fill-label-capacity",
        &thirty_one,
        true,
    ); // 5
    status(&receipt, 200);
    let refused = post(client, 1, ADD, 'b', "excess-union", "label=overflow", false); // 6
    status(&refused, 409);
    assert!(
        refused
            .body
            .contains("\"refusal_code\":\"ResourceBudgetExceeded\"")
    );
    assert!(
        refused
            .body
            .contains("\"labels\":[\"overflow\"],\"labels_version\":null")
    );
    let full = get(client, LABELS, 'a'); // 7
    status(&full, 200);
    assert!(full.body.contains("\"labels_version\":2"));
    assert!(full.body.contains(&longest));
    assert!(full.body.contains("label-30"));
    assert!(!full.body.contains("overflow"));
    added(
        &post(
            client,
            1,
            ADD,
            'b',
            "overlap-at-capacity",
            "label=label-00",
            false,
        ),
        "[\"label-00\"]",
    ); // 8
    let overlapped = get(client, LABELS, 'a'); // 9
    status(&overlapped, 200);
    assert!(overlapped.body.contains("\"labels_version\":3"));
    assert!(overlapped.body.contains(&longest));
    assert!(overlapped.body.contains("label-30"));
    server.finish();
}

fn hide(root: &Scratch, head_key: &fgit_authority::HeadKey, reference: &fgit_types::RefName) {
    use fgit_authority::{AuthorityLimits, StoreInstanceId};
    use fgit_authority_fsqlite::FsqliteAuthorityStore;
    use fgit_runtime::{BudgetClass, RuntimeProfile};
    use fsqlite_types::cx::Cx;
    use std::time::Duration;
    let runtime = RuntimeProfile::production(1).build().unwrap();
    {
        let cx = Cx::new();
        cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
        let path = root
            .0
            .join("node/authority.fsqlite")
            .to_str()
            .unwrap()
            .to_owned();
        let mut store = runtime
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                path,
                StoreInstanceId::from_raw(1),
                AuthorityLimits::default(),
            ))
            .unwrap();
        runtime
            .block_on(
                fgit_admission::merge::native::protection::publish_hidden_ref_policy_async(
                    &store,
                    &cx,
                    head_key,
                    fgit_types::TenantId::from_bytes([0x31; 16]),
                    Some(&fgit_codec::HiddenRefPolicyBody {
                        rules: vec![reference.as_bytes().to_vec()],
                    }),
                    fgit_codec::harness::tx_id(),
                ),
            )
            .unwrap();
        runtime.block_on(store.close(&cx)).unwrap();
    }
    assert!(runtime.join_root(Duration::from_secs(5)));
}

#[test]
fn current_hidden_source_or_target_refuses_new_additions_but_preserves_original_receipts() {
    for source in [true, false] {
        let root = Scratch::new();
        let config = root.config(GitHashAlgorithm::Sha256);
        let (node, data) = fixture(&root, GitHashAlgorithm::Sha256);
        let head_key = node.authority_head_key().clone();
        let credentials = root.0.join("credentials");
        grants(&node, &credentials);
        let server = Server::start(node, &credentials, 2, true, true);
        committed(&post(
            &server.client,
            1,
            "open",
            'b',
            "hidden-open",
            &form(&data, 0),
            false,
        )); // 1
        let original = post(
            &server.client,
            1,
            ADD,
            'b',
            "hidden-original",
            "label=triage",
            false,
        ); // 2
        added(&original, "[\"triage\"]");
        server.finish();
        hide(
            &root,
            &head_key,
            if source {
                &data.source_ref
            } else {
                &data.target_ref
            },
        );
        let server = Server::start(reopen(&config), &credentials, 3, true, true);
        let hidden = get(&server.client, LABELS, 'a'); // 1
        status(&hidden, 404);
        assert!(hidden.body.contains("\"found\":false"));
        assert!(!hidden.body.contains("triage"));
        let refused = post(
            &server.client,
            1,
            ADD,
            'b',
            "hidden-new",
            "label=urgent",
            false,
        ); // 2
        status(&refused, 409);
        assert!(
            refused
                .body
                .contains("\"refusal_code\":\"HiddenRefUnauthorized\"")
        );
        assert_eq!(
            post(
                &server.client,
                1,
                ADD,
                'b',
                "hidden-original",
                "label=triage",
                true
            )
            .body,
            original.body
        ); // 3
        server.finish();
    }
}
