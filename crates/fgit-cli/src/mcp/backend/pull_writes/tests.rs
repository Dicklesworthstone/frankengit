use super::*;
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_types::PrincipalId;
fn args(format: GitHashAlgorithm, version: &str) -> Object {
    let Value::Object(args) = object([
        ("number", text("7")),
        ("expected_version", text(version)),
        ("idempotency_key", text("original-key")),
        ("source_reference", text("refs/heads/topic")),
        ("target_reference", text("refs/heads/main")),
        ("expected_source", text("a".repeat(format.digest_len() * 2))),
        ("expected_target", text("b".repeat(format.digest_len() * 2))),
        ("title", text("Review é")),
        ("body", text("\"method\":\"shell\"\r\nliteral data")),
    ]) else {
        unreachable!()
    };
    args
}
#[test]
fn full_commands_preserve_bytes_and_bind_each_semantic_field() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = args(format, "0");
        let parsed = parse(OPEN, &original, format).unwrap();
        assert_eq!(parsed.expected_version, ExpectedVersion::NewStream);
        assert_eq!(parsed.data.body, "\"method\":\"shell\"\r\nliteral data");
        let actor = PrincipalId::from_bytes([7; 16]);
        let frame =
            fgit_codec::encode_body(&parsed.proposed_event(actor, format).unwrap()).unwrap();
        for (field, value) in [
            ("number", text("8")),
            ("title", text("Other")),
            ("body", text("")),
            ("expected_source", text("c".repeat(format.digest_len() * 2))),
            ("target_reference", text("refs/heads/other")),
        ] {
            let mut changed = original.clone();
            changed.insert(field.into(), value);
            let event = parse(OPEN, &changed, format)
                .unwrap()
                .proposed_event(actor, format)
                .unwrap();
            assert_ne!(fgit_codec::encode_body(&event).unwrap(), frame, "{field}");
        }
        let mut encoded = original;
        encoded.remove("source_reference");
        encoded.insert(
            "source_reference_hex".into(),
            text(super::super::hex(b"refs/heads/nonutf8-\xff")),
        );
        assert_eq!(
            parse(OPEN, &encoded, format)
                .unwrap()
                .data
                .source_ref
                .as_bytes(),
            b"refs/heads/nonutf8-\xff"
        );
    }
}
#[test]
fn unknown_authority_and_ambiguous_coordinates_refuse_before_admission() {
    let format = GitHashAlgorithm::Sha1;
    let original = args(format, "0");
    for field in [
        "principal",
        "tenant_id",
        "repository_id",
        "storage",
        "force",
        "approved",
        "expected_head",
        "bundle",
    ] {
        let mut changed = original.clone();
        changed.insert(field.into(), text("injected"));
        assert!(parse(OPEN, &changed, format).is_err(), "{field}");
    }
    for (field, value) in [
        ("number", text("0")),
        ("number", json::number(7)),
        ("expected_version", text("01")),
        ("expected_source", text("A".repeat(40))),
        ("expected_source", text("0".repeat(40))),
        ("expected_target", text("a".repeat(64))),
        ("source_reference", text("refs/tags/v1")),
        ("source_reference", text("refs/heads/main")),
        ("source_reference", text("refs/heads/../secret")),
        (
            "source_reference_hex",
            text("726566732f68656164732f746f706963"),
        ),
        ("body", text("a\0b")),
        ("body", text("x".repeat(common::MAX_TEXT_BYTES + 1))),
    ] {
        let mut changed = original.clone();
        changed.insert(field.into(), value);
        assert!(parse(OPEN, &changed, format).is_err(), "{field}");
    }
    for field in [
        "title",
        "body",
        "source_reference",
        "expected_source",
        "expected_target",
        "number",
        "expected_version",
    ] {
        let mut changed = original.clone();
        changed.remove(field);
        assert!(parse(OPEN, &changed, format).is_err(), "{field}");
    }
}
#[test]
fn update_and_close_require_full_metadata_and_never_refresh_the_version() {
    for name in [UPDATE, CLOSE] {
        let format = GitHashAlgorithm::Sha256;
        for version in ["0", "-1", "1.0", "18446744073709551615"] {
            assert!(parse(name, &args(format, version), format).is_err());
        }
        let original = args(format, "42");
        let parsed = parse(name, &original, format).unwrap();
        assert_eq!(
            parsed.expected_version,
            ExpectedVersion::Exactly(AggregateVersion::try_new(42).unwrap())
        );
        for field in [
            "title",
            "body",
            "source_reference",
            "target_reference",
            "expected_source",
            "expected_target",
        ] {
            let mut missing = original.clone();
            missing.remove(field);
            assert!(parse(name, &missing, format).is_err());
        }
        let mut empty = original;
        empty.insert("body".into(), text(""));
        assert!(parse(name, &empty, format).unwrap().data.body.is_empty());
    }
}
#[test]
fn schema_exposes_exact_keys_and_byte_alternatives_and_bounds() {
    for tool in tools() {
        assert!(is_tool(tool.name));
        let fields = tool.schema.object().unwrap();
        assert_eq!(fields["additionalProperties"], Value::Bool(false));
        let properties = fields["properties"].object().unwrap();
        assert_eq!(properties.len(), FIELDS.len());
        for field in FIELDS {
            assert!(properties.contains_key(*field));
        }
        assert_eq!(
            properties["body"].object().unwrap()["maxLength"].unsigned(),
            Some(common::MAX_TEXT_BYTES as u64)
        );
        let Value::Array(alternatives) = &fields["allOf"] else {
            panic!("alternatives")
        };
        assert_eq!(alternatives.len(), 2);
        assert!(tool.schema.encode(16384).is_ok());
    }
    assert!(!is_tool("frankengit_pull_merge"));
}
