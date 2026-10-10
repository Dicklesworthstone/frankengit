use super::*;

fn input(version: &str, body: &str) -> Object {
    object([
        ("number", text("7")),
        ("expected_version", text(version)),
        ("idempotency_key", text("original-key")),
        ("body", text(body)),
    ])
    .object()
    .unwrap()
    .clone()
}

#[test]
fn comment_command_uses_exact_independent_versions_and_literal_bodies() {
    let body = " é\r\n<script>literal body</script> \n";
    for version in ["0", "1", "9007199254740993"] {
        let parsed = command(&input(version, body)).unwrap();
        assert_eq!(parsed.number.get(), 7);
        assert_eq!(parsed.body, body);
        let observed = match parsed.expected_version {
            ExpectedVersion::NewStream => 0,
            ExpectedVersion::Exactly(version) => version.get(),
        };
        assert_eq!(observed.to_string(), version);
    }
    assert!(command(&input("1", &"x".repeat(common::MAX_TEXT_BYTES))).is_ok());
    for version in ["01", "-1", "1.0", "18446744073709551615"] {
        assert!(command(&input(version, body)).is_err());
    }
    for body in [
        "".into(),
        " \r\n\t".into(),
        "a\0b".into(),
        "é".repeat(common::MAX_TEXT_BYTES / 2 + 1),
    ] {
        assert!(command(&input("0", &body)).is_err());
    }
}

#[test]
fn remote_text_cannot_choose_identity_change_metadata_or_invent_anchors() {
    for name in [
        "principal",
        "repository_id",
        "source_tip",
        "pull_request_version",
        "force",
        "approved",
        "line",
        "path",
        "reply_to",
        "delete",
    ] {
        let mut args = input("0", "body");
        args.insert(name.into(), text("injected"));
        assert!(command(&args).is_err(), "{name}");
    }
    for name in ["number", "expected_version", "body"] {
        let mut args = input("0", "body");
        args.remove(name);
        assert!(command(&args).is_err(), "missing {name}");
    }
    let mut args = input("0", "body");
    args.insert("number".into(), json::number(7));
    assert!(command(&args).is_err());
}

#[test]
fn comment_read_continuations_are_exact_and_read_only() {
    for input in [
        r#"{}"#,
        r#"{"number":7}"#,
        r#"{"number":"0"}"#,
        r#"{"number":"7","after":"1"}"#,
        r#"{"number":"7","limit":21}"#,
        r#"{"number":"7","body":"mutate"}"#,
        r#"{"number":"7","expected_version":"1"}"#,
    ] {
        assert!(
            query(json::parse(input.as_bytes()).unwrap().object().unwrap()).is_err(),
            "{input}"
        );
    }
    let args = object([("number", text("7")), ("after", text("0"))]);
    let parsed = query(args.object().unwrap()).unwrap();
    assert_eq!(parsed.after, 0);
    assert_eq!(parsed.limit, 5);
}

#[test]
fn discovery_distinguishes_read_only_comment_pages_and_append_inputs() {
    let read = read_tool();
    assert_eq!(read.name, READ);
    let properties = read.schema.object().unwrap()["properties"]
        .object()
        .unwrap();
    assert!(!properties.contains_key("idempotency_key"));
    assert!(!properties.contains_key("body"));
    let write = write_tool();
    let properties = write.schema.object().unwrap()["properties"]
        .object()
        .unwrap();
    assert_eq!(properties.len(), 4);
    assert!(properties.contains_key("expected_version"));
    assert!(properties.contains_key("idempotency_key"));
    assert_eq!(
        write.schema.object().unwrap()["additionalProperties"],
        Value::Bool(false)
    );
}
