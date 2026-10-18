use super::*;
use fgit_forge::{ExpectedVersion, event::protection::MAX_POLICY_ADMINISTRATORS};

fn branch(reference: &[u8], reviewers: &[u8]) -> Value {
    object([
        ("reference_hex", text(hex(reference))),
        ("required_reviewers", people(reviewers)),
    ])
}
fn people(ids: &[u8]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| text(PrincipalId::from_bytes([*id; 16]).to_string()))
            .collect(),
    )
}
fn arguments() -> Object {
    let Value::Object(args) = object([
        ("idempotency_key", text("policy-request-1")),
        ("expected_version", text("0")),
        ("expected_epoch", text("1")),
        ("administrators", people(&[0x11, 0x22])),
        (
            "branches",
            Value::Array(vec![
                branch(b"refs/heads/main", &[0x33, 0x44]),
                branch(b"refs/heads/topic-\xff", &[0x55]),
            ]),
        ),
    ]) else {
        unreachable!()
    };
    args
}
fn fields(args: &mut Object) -> &mut Object {
    let Value::Array(branches) = args.get_mut("branches").unwrap() else {
        panic!("branches")
    };
    let Value::Object(fields) = &mut branches[0] else {
        panic!("branch")
    };
    fields
}

#[test]
fn complete_policy_preserves_non_utf8_branches_and_explicit_disabled_state() {
    let args = arguments();
    let command = write::parse(&args).unwrap();
    assert_eq!(command.expected_version, ExpectedVersion::NewStream);
    assert_eq!(command.expected_epoch.get(), 1);
    assert_eq!(
        command.protection.branches[1].name.as_bytes(),
        b"refs/heads/topic-\xff"
    );
    assert_eq!(command.protection.branches[0].reviewers.len(), 2);
    let mut disabled = args;
    disabled.insert("branches".into(), Value::Array(Vec::new()));
    let command = write::parse(&disabled).unwrap();
    assert!(command.protection.branches.is_empty());
    assert_eq!(command.protection.administrators.len(), 2);
    disabled.remove("branches");
    assert_eq!(
        write::parse(&disabled).unwrap_err().code,
        "policy_array_required"
    );
}

#[test]
fn expected_version_and_epoch_are_exact_nonexhausted_decimal_strings() {
    for name in ["expected_version", "expected_epoch"] {
        for value in [
            text("01"),
            text("-1"),
            text("+1"),
            text("1.0"),
            text("1e0"),
            text(""),
            json::number(1),
            Value::Null,
            text(u64::MAX.to_string()),
        ] {
            let mut args = arguments();
            args.insert(name.into(), value);
            assert!(write::parse(&args).is_err(), "{name}");
        }
        let mut args = arguments();
        args.remove(name);
        assert!(write::parse(&args).is_err(), "{name}");
        args.insert(name.into(), text((u64::MAX - 1).to_string()));
        assert!(write::parse(&args).is_ok(), "{name}");
    }
    let mut args = arguments();
    args.insert("expected_epoch".into(), text("0"));
    assert_eq!(
        write::parse(&args).unwrap_err().code,
        "invalid_policy_epoch"
    );
    args.insert("expected_epoch".into(), text("2"));
    args.insert("expected_version".into(), text("1"));
    assert_eq!(
        write::parse(&args).unwrap().expected_version,
        ExpectedVersion::Exactly(fgit_forge::AggregateVersion::FIRST),
    );
}

#[test]
fn authority_selectors_unknown_and_inapplicable_fields_refuse_before_admission() {
    for name in [
        "principal",
        "principal_id",
        "allow_write",
        "force",
        "expected_head",
        "storage",
        "repository",
        "policy_file",
        "request_id",
        "clear",
    ] {
        let mut args = arguments();
        args.insert(name.into(), text("injected"));
        assert_eq!(
            write::parse(&args).unwrap_err().code,
            "unknown_argument",
            "{name}"
        );
    }
    for name in ["reference_utf8", "principal", "checks", "quorum", "force"] {
        let mut args = arguments();
        fields(&mut args).insert(name.into(), text("injected"));
        assert_eq!(
            write::parse(&args).unwrap_err().code,
            "unknown_argument",
            "{name}"
        );
    }
}

#[test]
fn canonical_principal_sets_are_required_without_normalization_or_deduplication() {
    for ids in [&[][..], &[0x11, 0x11], &[0x22, 0x11]] {
        let mut args = arguments();
        args.insert("administrators".into(), people(ids));
        assert!(write::parse(&args).is_err());
        let mut args = arguments();
        fields(&mut args).insert("required_reviewers".into(), people(ids));
        assert!(write::parse(&args).is_err());
    }
    for value in [
        text("AA".repeat(16)),
        text("a".repeat(31)),
        json::number(1),
        Value::Null,
    ] {
        let mut args = arguments();
        args.insert("administrators".into(), Value::Array(vec![value.clone()]));
        assert_eq!(
            write::parse(&args).unwrap_err().code,
            "invalid_principal_id"
        );
        let mut args = arguments();
        fields(&mut args).insert("required_reviewers".into(), Value::Array(vec![value]));
        assert_eq!(
            write::parse(&args).unwrap_err().code,
            "invalid_principal_id"
        );
    }
    let mut args = arguments();
    args.insert("administrators".into(), text("[]"));
    assert_eq!(
        write::parse(&args).unwrap_err().code,
        "policy_array_required"
    );
}

#[test]
fn branch_set_is_exact_sorted_unique_and_limited_to_native_heads() {
    for branches in [
        vec![branch(b"refs/heads/a", &[1]), branch(b"refs/heads/a", &[2])],
        vec![branch(b"refs/heads/z", &[1]), branch(b"refs/heads/a", &[2])],
    ] {
        let mut args = arguments();
        args.insert("branches".into(), Value::Array(branches));
        assert_eq!(
            write::parse(&args).unwrap_err().code,
            "policy_branches_not_canonical"
        );
    }
    for reference in [
        b"refs/tags/tag".as_slice(),
        b"main",
        b"refs/heads/../main",
        b"refs/heads/a\n",
    ] {
        let mut args = arguments();
        args.insert(
            "branches".into(),
            Value::Array(vec![branch(reference, &[1])]),
        );
        assert!(write::parse(&args).is_err());
    }
    for raw in [text("0"), text("FF"), text("zz"), json::number(12)] {
        let mut args = arguments();
        fields(&mut args).insert("reference_hex".into(), raw);
        assert!(write::parse(&args).is_err());
    }
    let mut args = arguments();
    args.insert(
        "branches".into(),
        Value::Array(vec![text("refs/heads/main")]),
    );
    assert_eq!(
        write::parse(&args).unwrap_err().code,
        "policy_branch_object_required"
    );
}

#[test]
fn policy_cardinality_and_reference_byte_limits_have_permitted_twins() {
    let mut args = arguments();
    let ids: Vec<_> = (0..MAX_POLICY_ADMINISTRATORS as u8).collect();
    args.insert("administrators".into(), people(&ids));
    assert!(write::parse(&args).is_ok());
    let ids: Vec<_> = (0..=MAX_POLICY_ADMINISTRATORS as u8).collect();
    args.insert("administrators".into(), people(&ids));
    assert_eq!(write::parse(&args).unwrap_err().code, "policy_array_limit");

    let mut args = arguments();
    let reviewers: Vec<_> = (0..32).collect();
    fields(&mut args).insert("required_reviewers".into(), people(&reviewers));
    assert!(write::parse(&args).is_ok());
    let reviewers: Vec<_> = (0..33).collect();
    fields(&mut args).insert("required_reviewers".into(), people(&reviewers));
    assert_eq!(write::parse(&args).unwrap_err().code, "policy_array_limit");

    let mut args = arguments();
    for count in [64, 65] {
        args.insert(
            "branches".into(),
            Value::Array(
                (0..count)
                    .map(|n| branch(format!("refs/heads/b{n:02}").as_bytes(), &[1]))
                    .collect(),
            ),
        );
        assert_eq!(write::parse(&args).is_ok(), count == 64);
    }
    let mut args = arguments();
    for size in [1024, 1025] {
        let name = format!("refs/heads/{}", "a".repeat(size - 11));
        args.insert(
            "branches".into(),
            Value::Array(vec![branch(name.as_bytes(), &[1])]),
        );
        assert_eq!(write::parse(&args).is_ok(), size == 1024);
    }
}

#[test]
fn discovered_write_schema_requires_the_complete_canonical_command() {
    let tool = write::tool();
    assert_eq!(tool.name, "frankengit_protection_set");
    let schema = tool.schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    assert_eq!(
        schema["required"],
        Value::Array(
            [
                "idempotency_key",
                "expected_version",
                "expected_epoch",
                "administrators",
                "branches"
            ]
            .into_iter()
            .map(text)
            .collect()
        ),
    );
    let properties = schema["properties"].object().unwrap();
    assert_eq!(properties.len(), 5);
    assert!(
        properties["branches"].object().unwrap()["description"]
            .text()
            .unwrap()
            .contains("empty array")
    );
}
