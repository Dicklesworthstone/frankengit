//! Native MCP dispatch binds the selected thread domain to grants and receipts.
use super::*;

fn personal(fixture: &Fixture, issue: bool, discussion: bool, writes: bool) -> Options {
    let mut options = super::options(fixture, 0xa3, writes);
    options.issues = issue;
    options.discussions = discussion;
    options
}
fn selected(number: &str, before: &str, key: &str, fields: &[(&str, Value)]) -> Value {
    let mut fields = fields.to_vec();
    fields.push(("kind", text("discussion")));
    command(number, before, key, &fields)
}
fn discussion_show(server: &mut Server, backend: &mut NodeTools, next: &mut u64) -> Value {
    let reply = call(
        server,
        backend,
        next,
        "frankengit_inbox_show",
        object([("kind", text("discussion")), ("number", text("7"))]),
    );
    assert!(!failed(&reply), "{reply:?}");
    assert_eq!(
        structured(&reply)["type"],
        text("discussion_notification_thread")
    );
    assert_eq!(structured(&reply)["target_kind"], text("discussion"));
    assert_eq!(structured(&reply)["found"], Value::Bool(true));
    reply
}

#[test]
fn actual_dispatch_checks_each_selected_kind_before_reads_writes_or_retry_recovery() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    for (issues, discussions, denied) in [(true, false, "discussion"), (false, true, "issue")] {
        let mut backend = NodeTools::open(personal(&fixture, issues, discussions, true)).unwrap();
        let before = current_head(&backend);
        for name in [
            "frankengit_inbox_list",
            "frankengit_inbox_show",
            "frankengit_inbox_subscribe",
            "frankengit_inbox_mute",
            "frankengit_inbox_automatic",
            "frankengit_inbox_read",
            "frankengit_inbox_unread",
        ] {
            assert!(backend.tools().iter().any(|tool| tool.name == name));
            let args = match name {
                "frankengit_inbox_list" => object([("kind", text(denied))]),
                "frankengit_inbox_show" => object([("kind", text(denied)), ("number", text("7"))]),
                "frankengit_inbox_read" => command(
                    "7",
                    "0",
                    "no-cross-grant",
                    &[("kind", text(denied)), ("read_through", text("1"))],
                ),
                _ => command("7", "0", "no-cross-grant", &[("kind", text(denied))]),
            };
            let refusal = backend.call(name, args.object().unwrap()).unwrap_err();
            assert_eq!(refusal.code, "tool_not_granted", "{name}");
            if !issues {
                let mut default_issue = args.object().unwrap().clone();
                default_issue.remove("kind");
                assert_eq!(
                    backend.call(name, &default_issue).unwrap_err().code,
                    "tool_not_granted"
                );
            }
        }
        assert_eq!(current_head(&backend), before);
        backend.close().unwrap();
    }
    let mut content_writer = personal(&fixture, false, true, false);
    content_writer.writes.discussions = true;
    let mut backend = NodeTools::open(content_writer).unwrap();
    let before = current_head(&backend);
    for name in [
        "frankengit_inbox_subscribe",
        "frankengit_inbox_mute",
        "frankengit_inbox_automatic",
        "frankengit_inbox_read",
        "frankengit_inbox_unread",
    ] {
        assert!(!backend.is_mutation(name));
        assert_eq!(
            backend
                .call(
                    name,
                    selected("7", "0", "not-authorized", &[]).object().unwrap()
                )
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
    }
    assert_eq!(current_head(&backend), before);
    backend.close().unwrap();
}

#[test]
fn discussion_inbox_pagination_activity_and_exact_recovery_stay_separate_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut author_options = fixture.options(true, false, false, 0xa4);
        author_options.writes.discussions = true;
        let mut author = NodeTools::open(author_options.clone()).unwrap();
        let mut server = initialized(&mut author);
        let mut next = 2;
        committed(&call(
            &mut server,
            &mut author,
            &mut next,
            "frankengit_issue_open",
            opening(),
        ));
        for (number, key) in [("7", "discussion-seven"), ("8", "discussion-eight")] {
            committed(&call(
                &mut server,
                &mut author,
                &mut next,
                "frankengit_discussion_open",
                command(
                    number,
                    "0",
                    key,
                    &[
                        ("title", text(format!("Discussion {number} é"))),
                        ("body", text("Literal discussion body")),
                    ],
                ),
            ));
        }
        author.close().unwrap();

        let options = personal(&fixture, true, true, true);
        let mut backend = NodeTools::open(options.clone()).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        let original_command = selected("7", "0", "discussion-original-subscribe", &[]);
        let original = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_subscribe",
            original_command.clone(),
        );
        committed(&original);
        assert_eq!(
            structured(&original)["type"],
            text("discussion_notification_publication")
        );
        assert_eq!(structured(&original)["target_kind"], text("discussion"));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_subscribe",
            selected("8", "0", "discussion-second-subscribe", &[]),
        ));
        let issue_receipt = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_subscribe",
            command("7", "0", "issue-original-subscribe", &[]),
        );
        committed(&issue_receipt);
        assert_eq!(
            structured(&issue_receipt)["type"],
            text("notification_publication")
        );
        assert!(!structured(&issue_receipt).contains_key("target_kind"));

        let first = inbox(
            &mut server,
            &mut backend,
            &mut next,
            object([("kind", text("discussion")), ("limit", json::number(1))]),
        );
        assert_eq!(
            structured(&first)["type"],
            text("discussion_notification_inbox")
        );
        assert_eq!(structured(&first)["target_kind"], text("discussion"));
        assert_eq!(structured(&first)["next_after"], text("7"));
        assert_eq!(
            rows(&first)[0].object().unwrap()["discussion_version"],
            text("1")
        );
        assert!(
            !rows(&first)[0]
                .object()
                .unwrap()
                .contains_key("issue_version")
        );
        let pin = structured(&first)["snapshot_token"].clone();
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_read",
            selected(
                "7",
                "1",
                "discussion-read-first",
                &[("read_through", text("1"))],
            ),
        ));
        let second = inbox(
            &mut server,
            &mut backend,
            &mut next,
            object([
                ("kind", text("discussion")),
                ("after", text("7")),
                ("limit", json::number(1)),
                ("expected_head", pin),
            ]),
        );
        assert_eq!(rows(&second).len(), 1);
        assert_eq!(rows(&second)[0].object().unwrap()["number"], text("8"));
        assert_eq!(structured(&second)["next_after"], Value::Null);
        let discussion = discussion_show(&mut server, &mut backend, &mut next);
        assert_eq!(
            rows(&discussion)[0].object().unwrap()["unread"],
            Value::Bool(false)
        );
        let issue = show(&mut server, &mut backend, &mut next);
        let issue_row = rows(&issue)[0].object().unwrap();
        assert_eq!(issue_row["issue_version"], text("1"));
        assert!(!issue_row.contains_key("discussion_version"));
        assert_eq!(issue_row["preference_version"], text("1"));
        assert_eq!(issue_row["read_through"], Value::Null);
        assert_eq!(issue_row["unread"], Value::Bool(true));
        backend.close().unwrap();

        let mut author = NodeTools::open(author_options).unwrap();
        let mut server = initialized(&mut author);
        let mut next = 2;
        committed(&call(
            &mut server,
            &mut author,
            &mut next,
            "frankengit_discussion_comment",
            command(
                "7",
                "1",
                "later-discussion-comment",
                &[("body", text("Later activity stays unread"))],
            ),
        ));
        author.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        let later = discussion_show(&mut server, &mut backend, &mut next);
        let row = rows(&later)[0].object().unwrap();
        assert_eq!(row["discussion_version"], text("2"));
        assert_eq!(row["read_through"], text("1"));
        assert_eq!(row["latest_other_version"], text("2"));
        assert_eq!(row["unread"], Value::Bool(true));
        let replay = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_subscribe",
            original_command.clone(),
        );
        assert_eq!(structured(&replay), structured(&original));
        let unchanged = discussion_show(&mut server, &mut backend, &mut next);
        assert_eq!(
            rows(&unchanged)[0].object().unwrap()["preference_version"],
            text("2")
        );
        let future = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_read",
            selected(
                "7",
                "2",
                "future-discussion-read",
                &[("read_through", text("3"))],
            ),
        );
        assert!(failed(&future));
        assert_eq!(structured(&future)["outcome"], text("refused"));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_mute",
            selected("7", "2", "discussion-mute", &[]),
        ));
        let selected_threads = inbox(
            &mut server,
            &mut backend,
            &mut next,
            object([("kind", text("discussion"))]),
        );
        assert_eq!(rows(&selected_threads).len(), 1);
        assert_eq!(
            rows(&selected_threads)[0].object().unwrap()["number"],
            text("8")
        );
        let all = inbox(
            &mut server,
            &mut backend,
            &mut next,
            object([
                ("kind", text("discussion")),
                ("include_muted", Value::Bool(true)),
            ]),
        );
        assert_eq!(rows(&all).len(), 2);
        assert_eq!(rows(&all)[0].object().unwrap()["mode"], text("muted"));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_automatic",
            selected("7", "3", "discussion-automatic", &[]),
        ));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_inbox_unread",
            selected("7", "4", "discussion-unread", &[]),
        ));
        let reset = discussion_show(&mut server, &mut backend, &mut next);
        assert_eq!(
            rows(&reset)[0].object().unwrap()["preference_version"],
            text("5")
        );
        assert_eq!(
            rows(&reset)[0].object().unwrap()["read_through"],
            Value::Null
        );
        assert_eq!(
            rows(&reset)[0].object().unwrap()["mode"],
            text("participating")
        );
        let issue = show(&mut server, &mut backend, &mut next);
        assert_eq!(
            rows(&issue)[0].object().unwrap()["preference_version"],
            text("1")
        );
        backend.close().unwrap();

        // A valid historical discussion key does not bypass a later issue-only grant.
        let mut issue_only = NodeTools::open(personal(&fixture, true, false, true)).unwrap();
        let before = current_head(&issue_only);
        assert_eq!(
            issue_only
                .call(
                    "frankengit_inbox_subscribe",
                    original_command.object().unwrap()
                )
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
        assert_eq!(current_head(&issue_only), before);
        issue_only.close().unwrap();
    }
}
