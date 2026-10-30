use super::*;

fn command(args: &Object) -> Result<PullRequestCommentCommand, ToolError> {
    super::command(args, GitHashAlgorithm::Sha1)
}

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
        assert!(parsed.anchor.is_none());
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
    assert_eq!(properties.len(), 5);
    assert!(properties.contains_key("expected_version"));
    assert!(properties.contains_key("idempotency_key"));
    let anchor = properties["anchor"].object().unwrap();
    assert_eq!(anchor["additionalProperties"], Value::Bool(false));
    assert_eq!(anchor["properties"].object().unwrap().len(), 15);
    assert_eq!(
        anchor["required"],
        Value::Array(ANCHOR_FIELDS.into_iter().map(text).collect())
    );
    assert_eq!(
        write.schema.object().unwrap()["additionalProperties"],
        Value::Bool(false)
    );
}

fn anchor_fields(format: GitHashAlgorithm) -> Object {
    let bytes = match format {
        GitHashAlgorithm::Sha1 => 20,
        GitHashAlgorithm::Sha256 => 32,
    };
    object([
        ("pull_request_version", text("1")),
        (
            "source_ref_hex",
            text(fgit_crypto::lowercase_hex(b"refs/heads/topic")),
        ),
        (
            "target_ref_hex",
            text(fgit_crypto::lowercase_hex(b"refs/heads/main")),
        ),
        ("source_tip", text("11".repeat(bytes))),
        ("target_tip", text("22".repeat(bytes))),
        ("compared_base", text("22".repeat(bytes))),
        ("comparison", text("direct")),
        ("path_hex", text(fgit_crypto::lowercase_hex(b"src/\xff.rs"))),
        ("side", text("after")),
        ("blob", text("33".repeat(bytes))),
        ("mode", text("100644")),
        ("byte_start", text("0")),
        ("byte_end", text("6")),
        ("line_start", text("0")),
        ("line_count", text("1")),
    ])
    .object()
    .unwrap()
    .clone()
}

#[test]
fn source_anchor_inputs_are_complete_exact_and_bound_to_the_launch_hash_format() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fields = anchor_fields(format);
        let mut args = input("0", " literal body \r\n");
        args.insert("anchor".into(), Value::Object(fields.clone()));
        let parsed = super::command(&args, format).unwrap();
        let anchor = parsed.anchor.as_ref().unwrap();
        assert_eq!(parsed.body, " literal body \r\n");
        assert_eq!(anchor.path, b"src/\xff.rs");
        assert_eq!(anchor.source_tip.algorithm(), format);
        assert_eq!(
            (
                anchor.byte_start,
                anchor.byte_end,
                anchor.line_start,
                anchor.line_count
            ),
            (0, 6, 0, 1)
        );
        let rendered = render_anchor(anchor);
        let rendered = rendered.object().unwrap();
        assert_eq!(rendered["profile"], text(SOURCE_COMMENT_PROFILE));
        assert!(!rendered.contains_key("anchor_status"));
        for field in ANCHOR_FIELDS {
            assert_eq!(rendered[field], fields[field], "{field}");
            let mut missing = fields.clone();
            missing.remove(field);
            args.insert("anchor".into(), Value::Object(missing));
            assert!(super::command(&args, format).is_err(), "missing {field}");
        }
        for (field, value) in [
            ("pull_request_version", "0"),
            ("line_count", "0"),
            ("line_count", "129"),
            ("line_start", "01"),
            ("byte_end", "0"),
            ("byte_end", "65537"),
            ("mode", "160000"),
            ("mode", "0100644"),
            ("path_hex", "FF"),
            ("path_hex", "2e2e2f66696c65"),
            ("side", "guess"),
            ("comparison", "remapped"),
        ] {
            let mut invalid = fields.clone();
            invalid.insert(field.into(), text(value));
            args.insert("anchor".into(), Value::Object(invalid));
            assert!(super::command(&args, format).is_err(), "{field}={value}");
        }
        for field in [
            "profile",
            "anchor_status",
            "principal",
            "approved",
            "idempotency_key",
        ] {
            let mut injected = fields.clone();
            injected.insert(field.into(), text("untrusted"));
            args.insert("anchor".into(), Value::Object(injected));
            assert!(super::command(&args, format).is_err(), "{field}");
        }
        for field in [
            "pull_request_version",
            "byte_start",
            "byte_end",
            "line_start",
            "line_count",
        ] {
            let mut rounded = fields.clone();
            rounded.insert(field.into(), json::number(1));
            args.insert("anchor".into(), Value::Object(rounded));
            assert!(super::command(&args, format).is_err(), "numeric {field}");
        }
        args.insert("anchor".into(), Value::Object(fields));
        let other = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        assert!(super::command(&args, other).is_err());
        for value in [Value::Null, text("fake"), Value::Array(Vec::new())] {
            args.insert("anchor".into(), value);
            assert!(super::command(&args, format).is_err());
        }
    }
}

fn independent_input(body: &str) -> Object {
    let mut args = input("0", body);
    args.remove("expected_version");
    args
}

#[test]
fn append_comment_has_no_discussion_predecessor_and_never_accepts_an_identity_override() {
    let body = " é\r\n<script>literal comment</script> \n";
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let args = independent_input(body);
        let parsed = append_command(&args, format).unwrap();
        assert_eq!(parsed.number.get(), 7);
        assert_eq!(parsed.body, body);
        assert!(parsed.anchor.is_none());
        assert!(super::command(&args, format).is_err());
        for value in [text("0"), text("1"), Value::Null, json::number(0)] {
            let mut injected = args.clone();
            injected.insert("expected_version".into(), value);
            assert!(append_command(&injected, format).is_err());
        }
        for field in [
            "principal",
            "actor",
            "repository_id",
            "source_tip",
            "pull_request_version",
            "force",
            "approved",
            "delete",
            "reply_to",
        ] {
            let mut injected = args.clone();
            injected.insert(field.into(), text("untrusted"));
            assert!(append_command(&injected, format).is_err(), "{field}");
        }
        for field in ["number", "body"] {
            let mut missing = args.clone();
            missing.remove(field);
            assert!(append_command(&missing, format).is_err(), "missing {field}");
        }
        for number in ["0", "01", "-1", "1.0", "18446744073709551616"] {
            let mut invalid = args.clone();
            invalid.insert("number".into(), text(number));
            assert!(append_command(&invalid, format).is_err());
        }
        let mut invalid = args;
        invalid.insert("number".into(), json::number(7));
        assert!(append_command(&invalid, format).is_err());
        assert!(
            append_command(
                &independent_input(&"x".repeat(common::MAX_TEXT_BYTES)),
                format
            )
            .is_ok()
        );
        for body in [
            "".into(),
            " \r\n\t".into(),
            "a\0b".into(),
            "é".repeat(common::MAX_TEXT_BYTES / 2 + 1),
        ] {
            assert!(append_command(&independent_input(&body), format).is_err());
        }
    }
}

#[test]
fn independent_append_keeps_the_same_complete_original_source_anchor_contract() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fields = anchor_fields(format);
        let mut args = independent_input(" source comment \n");
        args.insert("anchor".into(), Value::Object(fields.clone()));
        let parsed = append_command(&args, format).unwrap();
        let anchor = parsed.anchor.as_ref().unwrap();
        assert_eq!(anchor.path, b"src/\xff.rs");
        assert_eq!(anchor.source_tip.algorithm(), format);
        let rendered = render_anchor(anchor);
        for field in ANCHOR_FIELDS {
            assert_eq!(rendered.object().unwrap()[field], fields[field]);
            let mut missing = fields.clone();
            missing.remove(field);
            args.insert("anchor".into(), Value::Object(missing));
            assert!(append_command(&args, format).is_err(), "missing {field}");
        }
        for (field, value) in [
            ("pull_request_version", "0"),
            ("line_count", "129"),
            ("byte_end", "0"),
            ("mode", "160000"),
            ("path_hex", "2e2e2f66696c65"),
            ("side", "guess"),
        ] {
            let mut invalid = fields.clone();
            invalid.insert(field.into(), text(value));
            args.insert("anchor".into(), Value::Object(invalid));
            assert!(append_command(&args, format).is_err(), "{field}");
        }
        for field in ["expected_version", "principal", "profile", "anchor_status"] {
            let mut injected = fields.clone();
            injected.insert(field.into(), text("untrusted"));
            args.insert("anchor".into(), Value::Object(injected));
            assert!(append_command(&args, format).is_err(), "{field}");
        }
        args.insert("anchor".into(), Value::Object(fields));
        let other = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        assert!(append_command(&args, other).is_err());
        args.insert("anchor".into(), Value::Null);
        assert!(append_command(&args, format).is_err());
    }
}

#[test]
fn append_discovery_matches_the_authoritative_registry_and_preserves_the_strict_tool() {
    use std::collections::BTreeSet;
    let tool = append_tool();
    assert_eq!(tool.name, APPEND);
    let schema = tool.schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let properties = schema["properties"].object().unwrap();
    assert_eq!(properties.len(), 4);
    assert!(!properties.contains_key("expected_version"));
    assert_eq!(
        schema["required"],
        Value::Array(
            ["number", "idempotency_key", "body"]
                .into_iter()
                .map(text)
                .collect()
        )
    );
    assert_eq!(
        properties["anchor"].object().unwrap()["required"],
        Value::Array(ANCHOR_FIELDS.into_iter().map(text).collect())
    );
    let contract = fgit_schema::mcp::find_tool(APPEND).unwrap();
    let declared: BTreeSet<_> = contract
        .input_fields
        .iter()
        .map(|field| field.name)
        .collect();
    let served: BTreeSet<_> = properties.keys().map(String::as_str).collect();
    assert_eq!(declared, served);
    let strict = write_tool();
    assert_eq!(strict.name, WRITE);
    assert!(
        strict.schema.object().unwrap()["properties"]
            .object()
            .unwrap()
            .contains_key("expected_version")
    );
}
