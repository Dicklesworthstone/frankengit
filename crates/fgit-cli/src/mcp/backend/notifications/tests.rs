use super::*;
fn args() -> Object {
    object([
        ("number", text("7")),
        ("expected_version", text("0")),
        ("idempotency_key", text("same-command")),
    ])
    .object()
    .unwrap()
    .clone()
}
#[test]
fn commands_keep_exact_versions_and_never_accept_another_recipient() {
    for (name, action) in [
        (
            "frankengit_inbox_subscribe",
            NotificationAction::SetMode(NotificationMode::Subscribed),
        ),
        (
            "frankengit_inbox_mute",
            NotificationAction::SetMode(NotificationMode::Muted),
        ),
        (
            "frankengit_inbox_automatic",
            NotificationAction::SetMode(NotificationMode::Participating),
        ),
        (
            "frankengit_inbox_unread",
            NotificationAction::SetReadThrough(None),
        ),
    ] {
        let command = parse_command(name, &args()).unwrap();
        assert_eq!(command.expected_version, ExpectedVersion::NewStream);
        assert_eq!(command.action, action);
        for field in [
            "principal",
            "principal_id",
            "recipient",
            "actor",
            "read_through",
            "repository",
        ] {
            let mut spoofed = args();
            spoofed.insert(field.into(), text("1"));
            assert!(
                parse_command(name, &spoofed).is_err(),
                "{name} accepted {field}"
            );
        }
        for invalid in [
            Value::Number("0".into()),
            text("01"),
            text("-1"),
            text("1.0"),
            text(u64::MAX.to_string()),
        ] {
            let mut malformed = args();
            malformed.insert("expected_version".into(), invalid);
            assert!(parse_command(name, &malformed).is_err());
        }
    }
    let mut exact = args();
    exact.insert("expected_version".into(), text("9007199254740993"));
    assert_eq!(
        parse_command("frankengit_inbox_mute", &exact)
            .unwrap()
            .expected_version,
        ExpectedVersion::Exactly(AggregateVersion::try_new(9_007_199_254_740_993).unwrap())
    );
}
#[test]
fn explicit_positive_read_prefix_and_strict_filter_booleans_cannot_be_coerced() {
    assert!(parse_command("frankengit_inbox_read", &args()).is_err());
    for prefix in [
        text("0"),
        text("01"),
        text("-1"),
        text("1.0"),
        Value::Null,
        json::number(1),
    ] {
        let mut invalid = args();
        invalid.insert("read_through".into(), prefix);
        assert!(parse_command("frankengit_inbox_read", &invalid).is_err());
    }
    let mut valid = args();
    valid.insert("read_through".into(), text("2"));
    assert_eq!(
        parse_command("frankengit_inbox_read", &valid)
            .unwrap()
            .action,
        NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(2).unwrap()))
    );
    assert!(!boolean(&Object::new(), "unread_only").unwrap());
    for value in [text("true"), text("false"), json::number(1), Value::Null] {
        let mut bad = Object::new();
        bad.insert("unread_only".into(), value);
        assert!(boolean(&bad, "unread_only").is_err());
    }
    assert_eq!(read_tools().len(), 2);
    assert_eq!(write_tools().len(), 5);
    for tool in read_tools().into_iter().chain(write_tools()) {
        let schema = tool.schema.object().unwrap();
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        let properties = schema["properties"].object().unwrap();
        let contract = fgit_schema::mcp::find_tool(tool.name).unwrap();
        let served: std::collections::BTreeSet<_> = properties.keys().map(String::as_str).collect();
        let declared: std::collections::BTreeSet<_> = contract
            .input_fields
            .iter()
            .map(|field| field.name)
            .collect();
        assert_eq!(served, declared);
        for forbidden in ["principal", "principal_id", "recipient", "actor"] {
            assert!(!properties.contains_key(forbidden));
        }
    }
}
fn launch(flags: &[&str]) -> Vec<String> {
    let mut args = vec![
        "unopened-node".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--trusted-local".into(),
    ];
    args.extend(flags.iter().map(|flag| (*flag).to_owned()));
    args
}
fn bound(mut args: Vec<String>) -> Vec<String> {
    args.extend([
        "--principal".into(),
        "33".repeat(16),
        "--expected-incarnation".into(),
        "44".repeat(16),
    ]);
    args
}
#[test]
fn personal_grants_require_issue_disclosure_and_launch_identity() {
    let ordinary = crate::mcp::parse_options(&launch(&["--allow-issues"])).unwrap();
    assert!(!read_permitted(&ordinary) && !write_permitted(&ordinary));
    let personal = crate::mcp::parse_options(&bound(launch(&["--allow-issues"]))).unwrap();
    assert!(read_permitted(&personal) && !write_permitted(&personal));
    assert!(!personal.writes.any());
    let names: Vec<_> = tools_for_options(&personal)
        .into_iter()
        .map(|tool| tool.name)
        .collect();
    assert!(read_tools().iter().all(|tool| names.contains(&tool.name)));
    assert!(write_tools().iter().all(|tool| !names.contains(&tool.name)));
    let issue_writer =
        crate::mcp::parse_options(&bound(launch(&["--allow-issues", "--allow-issue-writes"])))
            .unwrap();
    assert!(!write_permitted(&issue_writer));
    let notification_writer = crate::mcp::parse_options(&bound(launch(&[
        "--allow-issues",
        "--allow-notification-writes",
    ])))
    .unwrap();
    assert!(write_permitted(&notification_writer));
    assert!(!notification_writer.writes.issues && !notification_writer.outcomes);
    assert!(
        crate::mcp::parse_options(&launch(&["--allow-issues", "--allow-notification-writes"]))
            .is_err()
    );
    assert!(crate::mcp::parse_options(&bound(launch(&["--allow-notification-writes"]))).is_err());
    let mut no_pin = bound(launch(&["--allow-issues"]));
    no_pin.truncate(no_pin.len() - 2);
    assert!(crate::mcp::parse_options(&no_pin).is_err());
    for remove_principal in [true, false] {
        let mut inconsistent = notification_writer.clone();
        if remove_principal {
            inconsistent.principal = None;
        } else {
            inconsistent.incarnation = None;
        }
        assert!(!read_permitted(&inconsistent) && !write_permitted(&inconsistent));
    }
}
