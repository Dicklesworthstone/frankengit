//! Real MCP calls through reopened authority-backed node operations.
use super::*;
fn options(fixture: &Fixture, principal: u8, writes: bool) -> Options {
    let mut options = fixture.options(false, false, true, principal);
    options.principal = Some(PrincipalId::from_bytes([principal; 16]));
    options.writes.notifications = writes;
    options
}
fn call(
    server: &mut Server,
    backend: &mut NodeTools,
    next: &mut u64,
    name: &str,
    args: Value,
) -> Value {
    let id = *next;
    *next += 1;
    invoke(server, backend, id, name, args)
}
fn inbox(server: &mut Server, backend: &mut NodeTools, next: &mut u64, args: Value) -> Value {
    let reply = call(server, backend, next, "frankengit_inbox_list", args);
    assert!(!failed(&reply), "{reply:?}");
    reply
}
fn show(server: &mut Server, backend: &mut NodeTools, next: &mut u64) -> Value {
    let reply = call(
        server,
        backend,
        next,
        "frankengit_inbox_show",
        object([("number", text("7"))]),
    );
    assert!(!failed(&reply), "{reply:?}");
    assert_eq!(structured(&reply)["found"], Value::Bool(true));
    reply
}
fn rows(reply: &Value) -> &[Value] {
    let Value::Array(rows) = &structured(reply)["threads"] else {
        panic!("missing inbox rows")
    };
    rows
}
fn committed(reply: &Value) {
    assert!(!failed(reply), "{reply:?}");
    assert_eq!(structured(reply)["outcome"], text("committed"));
    assert_eq!(structured(reply)["refs_changed"], Value::Bool(false));
}

#[test]
fn durable_self_inbox_pinned_pages_and_other_actor_activity_survive_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut author = NodeTools::open(fixture.options(true, false, false, 0xa4)).unwrap();
        let mut server = initialized(&mut author);
        let mut next = 2;
        committed(&call(
            &mut server,
            &mut author,
            &mut next,
            "frankengit_issue_open",
            opening(),
        ));
        committed(&call(
            &mut server,
            &mut author,
            &mut next,
            "frankengit_issue_open",
            command(
                "8",
                "0",
                "second-issue",
                &[
                    ("title", text("Second issue")),
                    ("body", text("literal body")),
                ],
            ),
        ));
        author.close().unwrap();
        let mut backend = NodeTools::open(options(&fixture, 0xa3, true)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        assert!(rows(&inbox(&mut server, &mut backend, &mut next, object([]))).is_empty());
        let initial = show(&mut server, &mut backend, &mut next);
        assert_eq!(
            rows(&initial)[0].object().unwrap()["preference_version"],
            Value::Null
        );
        assert_eq!(
            rows(&initial)[0].object().unwrap()["reasons"],
            Value::Array(vec![])
        );
        let subscribe = command("7", "0", "subscribe-original", &[]);
        let original = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_subscribe",
            subscribe.clone(),
        );
        committed(&original);
        assert_eq!(
            structured(&original)["principal_id"],
            text(PrincipalId::from_bytes([0xa3; 16]).to_string())
        );
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_subscribe",
            command("8", "0", "second-subscription", &[]),
        ));
        let first = inbox(
            &mut server,
            &mut backend,
            &mut next,
            object([("limit", json::number(1))]),
        );
        assert_eq!(rows(&first)[0].object().unwrap()["number"], text("7"));
        assert_eq!(structured(&first)["next_after"], text("7"));
        let pin = structured(&first)["snapshot_token"].clone();
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_read",
            command(
                "7",
                "1",
                "read-observed-prefix",
                &[("read_through", text("1"))],
            ),
        ));
        let future = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_read",
            command(
                "7",
                "2",
                "future-prefix-refused",
                &[("read_through", text("2"))],
            ),
        );
        assert!(failed(&future));
        assert_eq!(structured(&future)["outcome"], text("refused"));
        let stale = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_mute",
            command("7", "0", "stale-pref-refused", &[]),
        );
        assert!(failed(&stale));
        assert_eq!(structured(&stale)["outcome"], text("refused"));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_mute",
            command("8", "1", "mute-second", &[]),
        ));
        let second = inbox(
            &mut server,
            &mut backend,
            &mut next,
            object([
                ("after", text("7")),
                ("limit", json::number(1)),
                ("expected_head", pin.clone()),
            ]),
        );
        assert_eq!(structured(&second)["snapshot_token"], pin);
        assert_eq!(rows(&second)[0].object().unwrap()["number"], text("8"));
        assert_eq!(
            rows(&second)[0].object().unwrap()["mode"],
            text("subscribed")
        );
        assert_eq!(
            rows(&inbox(&mut server, &mut backend, &mut next, object([]))).len(),
            1
        );
        let read = show(&mut server, &mut backend, &mut next);
        assert_eq!(
            rows(&read)[0].object().unwrap()["preference_version"],
            text("2")
        );
        assert_eq!(
            rows(&read)[0].object().unwrap()["unread"],
            Value::Bool(false)
        );
        backend.close().unwrap();
        let mut author = NodeTools::open(fixture.options(true, false, false, 0xa4)).unwrap();
        let mut server = initialized(&mut author);
        let mut next = 2;
        committed(&call(
            &mut server,
            &mut author,
            &mut next,
            "frankengit_issue_comment",
            command(
                "7",
                "1",
                "new-other-activity",
                &[("body", text("Comment after acknowledged prefix"))],
            ),
        ));
        author.close().unwrap();
        let mut backend = NodeTools::open(options(&fixture, 0xa3, true)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        let retry = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_subscribe",
            subscribe,
        );
        committed(&retry);
        assert_eq!(structured(&retry), structured(&original));
        let changed = show(&mut server, &mut backend, &mut next);
        let row = rows(&changed)[0].object().unwrap();
        assert_eq!(row["preference_version"], text("2"));
        assert_eq!(row["read_through"], text("1"));
        assert_eq!(row["latest_other_version"], text("2"));
        assert_eq!(row["unread"], Value::Bool(true));
        assert_eq!(row["reasons"], Value::Array(vec![text("subscribed")]));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_unread",
            command("7", "2", "clear-prefix", &[]),
        ));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_mute",
            command("7", "3", "mute-self", &[]),
        ));
        assert!(rows(&inbox(&mut server, &mut backend, &mut next, object([]))).is_empty());
        let muted = inbox(
            &mut server,
            &mut backend,
            &mut next,
            object([("include_muted", Value::Bool(true))]),
        );
        assert_eq!(rows(&muted).len(), 2);
        assert_eq!(
            rows(&muted)[0].object().unwrap()["read_through"],
            Value::Null
        );
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_automatic",
            command("7", "4", "restore-participation", &[]),
        ));
        assert!(rows(&inbox(&mut server, &mut backend, &mut next, object([]))).is_empty());
        let automatic = show(&mut server, &mut backend, &mut next);
        assert_eq!(
            rows(&automatic)[0].object().unwrap()["mode"],
            text("participating")
        );
        assert_eq!(
            rows(&automatic)[0].object().unwrap()["preference_version"],
            text("5")
        );
        backend.close().unwrap();
        let mut other = NodeTools::open(options(&fixture, 0xa5, false)).unwrap();
        let mut server = initialized(&mut other);
        let mut next = 2;
        assert!(
            rows(&inbox(
                &mut server,
                &mut other,
                &mut next,
                object([("include_muted", Value::Bool(true))])
            ))
            .is_empty()
        );
        let independent = show(&mut server, &mut other, &mut next);
        assert_eq!(
            rows(&independent)[0].object().unwrap()["preference_version"],
            Value::Null
        );
        assert_eq!(
            rows(&independent)[0].object().unwrap()["read_through"],
            Value::Null
        );
        other.close().unwrap();
        let mut author = NodeTools::open(options(&fixture, 0xa4, false)).unwrap();
        let mut server = initialized(&mut author);
        let mut next = 2;
        let authored = inbox(&mut server, &mut author, &mut next, object([]));
        assert_eq!(rows(&authored).len(), 2);
        for row in rows(&authored) {
            let row = row.object().unwrap();
            assert_eq!(row["unread"], Value::Bool(false));
            assert_eq!(row["latest_other_version"], Value::Null);
            assert!(
                matches!(&row["reasons"], Value::Array(reasons) if reasons.contains(&text("author")))
            );
        }
        author.close().unwrap();
    }
}
#[test]
fn issue_and_notification_write_grants_never_authorize_each_other() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let mut issue_writer = NodeTools::open(fixture.options(true, false, true, 0xa3)).unwrap();
    let before = current_head(&issue_writer);
    for name in [
        "frankengit_inbox_subscribe",
        "frankengit_inbox_mute",
        "frankengit_inbox_automatic",
        "frankengit_inbox_read",
        "frankengit_inbox_unread",
    ] {
        assert!(!issue_writer.is_mutation(name));
        assert!(
            issue_writer
                .call(
                    name,
                    command("7", "0", "not-granted", &[]).object().unwrap()
                )
                .is_err()
        );
    }
    assert_eq!(current_head(&issue_writer), before);
    issue_writer.close().unwrap();
    let mut personal = NodeTools::open(options(&fixture, 0xa3, true)).unwrap();
    let before = current_head(&personal);
    assert!(!personal.is_mutation("frankengit_issue_open"));
    assert!(
        personal
            .call("frankengit_issue_open", opening().object().unwrap())
            .is_err()
    );
    for field in ["principal", "recipient", "actor"] {
        let mut spoofed = command("7", "0", "not-owned", &[])
            .object()
            .unwrap()
            .clone();
        spoofed.insert(
            field.into(),
            text(PrincipalId::from_bytes([0xa4; 16]).to_string()),
        );
        assert!(
            personal
                .call("frankengit_inbox_subscribe", &spoofed)
                .is_err()
        );
    }
    assert_eq!(current_head(&personal), before);
    personal.close().unwrap();
}
