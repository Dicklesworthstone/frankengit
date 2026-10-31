use super::super::super::json::{self, object, text};
use super::*;
use fgit_forge::ExpectedVersion;
use fgit_forge::merge_queue::QueueCommandAction;
use fgit_types::{GitHashAlgorithm, RepositoryIncarnationId};

fn incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([0xab; 16])
}
fn args(name: &str, format: GitHashAlgorithm) -> Object {
    let Value::Object(mut fields) = object([
        ("number", text("1")),
        (
            "expected_version",
            text(if name == ENQUEUE { "0" } else { "2" }),
        ),
        ("idempotency_key", text("original-key")),
        ("expected_incarnation", text(incarnation().to_string())),
        ("object_format", text(format.as_str())),
        ("target_reference", text("refs/heads/main")),
    ]) else {
        unreachable!()
    };
    if matches!(name, ENQUEUE | LAND) {
        fields.extend([
            ("pull_request".into(), text("7")),
            ("expected_pull_request_version".into(), text("3")),
            ("source_reference".into(), text("refs/heads/topic")),
            (
                "expected_source".into(),
                text("aa".repeat(format.digest_len())),
            ),
            (
                "expected_target".into(),
                text("bb".repeat(format.digest_len())),
            ),
        ]);
        if name == LAND {
            fields.insert("expected_policy_epoch".into(), text("4"));
        }
    } else if name == DEQUEUE {
        fields.insert("pull_request".into(), text("7"));
        fields.insert("reason".into(), text("withdrawn"));
    } else {
        fields.insert("order".into(), Value::Array(vec![text("9"), text("7")]));
    }
    fields
}

#[test]
fn exact_guards_and_native_hash_domains_survive_typed_parsing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for name in [ENQUEUE, DEQUEUE, REORDER, LAND] {
            let fields = args(name, format);
            let (_, command) = input::parse(name, &fields, format, incarnation()).unwrap();
            match command {
                Command::Landing(command) => {
                    assert_eq!(command.expected_version.get(), 2);
                    assert_eq!(command.expected_pull_request_version.get(), 3);
                    assert_eq!(command.expected_policy_epoch.get(), 4);
                    assert_eq!(command.head_tip.algorithm(), format);
                    assert_eq!(command.expected_target_tip.algorithm(), format);
                }
                Command::Management(command) => {
                    if name == ENQUEUE {
                        assert_eq!(command.expected_version, ExpectedVersion::NewStream);
                    }
                    if let QueueCommandAction::Reorder { order } = command.action {
                        assert_eq!(order.iter().map(|n| n.get()).collect::<Vec<_>>(), [9, 7]);
                    }
                }
            }
            for field in [
                "number",
                "expected_version",
                "idempotency_key",
                "expected_incarnation",
                "object_format",
                "target_reference",
            ] {
                let mut missing = fields.clone();
                missing.remove(field);
                assert!(
                    input::parse(name, &missing, format, incarnation()).is_err(),
                    "{name} missing {field}"
                );
            }
            for field in [
                "principal",
                "trusted_local",
                "force",
                "bundle",
                "method",
                "head",
                "tenant_id",
            ] {
                let mut injected = fields.clone();
                injected.insert(field.into(), text("override"));
                assert_eq!(
                    input::parse(name, &injected, format, incarnation())
                        .unwrap_err()
                        .code,
                    "unknown_argument"
                );
            }
        }
    }
}

#[test]
fn incarnation_format_positive_versions_and_capacity_are_exact() {
    let original = args(LAND, GitHashAlgorithm::Sha1);
    for (field, value) in [
        ("expected_incarnation", text("ab".repeat(15))),
        ("expected_incarnation", text("AB".repeat(16))),
        ("expected_incarnation", text("ac".repeat(16))),
        ("object_format", text("sha256")),
        ("number", text("0")),
        ("expected_version", text("0")),
        ("expected_version", text((u64::MAX - 1).to_string())),
        ("expected_pull_request_version", text("0")),
        ("expected_pull_request_version", text(u64::MAX.to_string())),
        ("expected_policy_epoch", text("0")),
        ("expected_policy_epoch", json::number(1)),
        ("expected_source", text("00".repeat(20))),
        ("expected_source", text("aa".repeat(32))),
        ("expected_target", text("BB".repeat(20))),
        ("expected_target", text("aa".repeat(20))),
        ("source_reference", text("refs/heads/main")),
        ("source_reference", text("refs/tags/topic")),
        ("idempotency_key", text("key with spaces")),
    ] {
        let mut invalid = original.clone();
        invalid.insert(field.into(), value);
        assert!(
            input::parse(LAND, &invalid, GitHashAlgorithm::Sha1, incarnation()).is_err(),
            "{field}"
        );
    }
    let mut last = original;
    last.insert("expected_version".into(), text((u64::MAX - 2).to_string()));
    assert!(input::parse(LAND, &last, GitHashAlgorithm::Sha1, incarnation()).is_ok());
    for name in [ENQUEUE, DEQUEUE, REORDER, LAND] {
        for value in [
            text("01"),
            text("-1"),
            json::number(1),
            text(u64::MAX.to_string()),
        ] {
            let mut invalid = args(name, GitHashAlgorithm::Sha1);
            invalid.insert("expected_version".into(), value);
            assert!(input::parse(name, &invalid, GitHashAlgorithm::Sha1, incarnation()).is_err());
        }
    }
}

#[test]
fn byte_references_and_complete_order_have_closed_bounded_encodings() {
    let mut raw = args(ENQUEUE, GitHashAlgorithm::Sha1);
    raw.remove("source_reference");
    raw.insert(
        "source_reference_hex".into(),
        text("726566732f68656164732fff"),
    );
    let (_, Command::Management(command)) =
        input::parse(ENQUEUE, &raw, GitHashAlgorithm::Sha1, incarnation()).unwrap()
    else {
        panic!()
    };
    let QueueCommandAction::Enqueue { source_ref, .. } = command.action else {
        panic!()
    };
    assert_eq!(source_ref.as_bytes(), b"refs/heads/\xff");
    for value in ["726566732F68656164732fff", "726", "zz"] {
        let mut invalid = raw.clone();
        invalid.insert("source_reference_hex".into(), text(value));
        assert!(input::parse(ENQUEUE, &invalid, GitHashAlgorithm::Sha1, incarnation()).is_err());
    }
    raw.insert("source_reference".into(), text("refs/heads/topic"));
    assert!(input::parse(ENQUEUE, &raw, GitHashAlgorithm::Sha1, incarnation()).is_err());
    let mut reorder = args(REORDER, GitHashAlgorithm::Sha1);
    for order in [
        vec![],
        vec![text("7"), text("7")],
        vec![json::number(7)],
        (1..=257).map(|n| text(n.to_string())).collect(),
    ] {
        reorder.insert("order".into(), Value::Array(order));
        assert!(input::parse(REORDER, &reorder, GitHashAlgorithm::Sha1, incarnation()).is_err());
    }
    reorder.insert(
        "order".into(),
        Value::Array((1..=256).map(|n| text(n.to_string())).collect()),
    );
    assert!(input::parse(REORDER, &reorder, GitHashAlgorithm::Sha1, incarnation()).is_ok());
    let mut enqueue = args(ENQUEUE, GitHashAlgorithm::Sha1);
    enqueue.insert("priority".into(), text(u32::MAX.to_string()));
    assert!(input::parse(ENQUEUE, &enqueue, GitHashAlgorithm::Sha1, incarnation()).is_ok());
    enqueue.insert(
        "priority".into(),
        text((u64::from(u32::MAX) + 1).to_string()),
    );
    assert!(input::parse(ENQUEUE, &enqueue, GitHashAlgorithm::Sha1, incarnation()).is_err());
}

#[test]
fn discovery_contract_matches_registered_fields_and_independent_effects() {
    let all = QueueGrants {
        read: true,
        write: true,
        land: true,
    };
    for tool in tools(all) {
        let entry = fgit_schema::mcp::find_tool(tool.name).unwrap();
        let properties = tool.schema.object().unwrap()["properties"]
            .object()
            .unwrap();
        let declared: std::collections::BTreeSet<_> =
            entry.input_fields.iter().map(|f| f.name).collect();
        let advertised: std::collections::BTreeSet<_> =
            properties.keys().map(String::as_str).collect();
        assert_eq!(declared, advertised, "{} fields", tool.name);
        let Value::Array(required) = &tool.schema.object().unwrap()["required"] else {
            panic!()
        };
        let required: std::collections::BTreeSet<_> =
            required.iter().map(|field| field.text().unwrap()).collect();
        assert_eq!(
            required,
            entry
                .input_fields
                .iter()
                .filter(|field| field.required)
                .map(|field| field.name)
                .collect()
        );
        assert_eq!(
            is_mutation(all, tool.name),
            !matches!(tool.name, LIST | SHOW)
        );
        assert_eq!(
            tool.schema.object().unwrap()["additionalProperties"],
            Value::Bool(false)
        );
    }
    assert!(!permitted(
        QueueGrants {
            read: false,
            write: true,
            land: false
        },
        LAND
    ));
    assert!(!permitted(
        QueueGrants {
            read: false,
            write: false,
            land: true
        },
        ENQUEUE
    ));
}
