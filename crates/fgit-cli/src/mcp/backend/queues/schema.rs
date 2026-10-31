//! Closed discovery schemas mirror the typed queue input parser.
use super::super::super::json::{self, object, text};
use super::super::decimal_schema;
use super::*;

pub(super) fn for_tool(name: &str) -> Value {
    let mut properties = Object::new();
    if matches!(name, LIST | SHOW) {
        properties.insert("expected_head".into(), object([
            ("type", text("string")), ("maxLength", json::number(140)),
            ("description", text("Original snapshot_token; required for any nonzero after cursor. Current disclosure rules remain enforced.")),
        ]));
        if name == SHOW {
            properties.insert("number".into(), positive());
            return common::input_schema(properties, &["number"]);
        }
        properties.insert("after".into(), decimal_schema());
        properties.insert(
            "limit".into(),
            object([
                ("type", text("integer")),
                ("minimum", json::number(1)),
                ("maximum", json::number(20)),
                ("default", json::number(5)),
            ]),
        );
        return common::input_schema(properties, &[]);
    }
    properties.insert("number".into(), positive());
    properties.insert(
        "expected_version".into(),
        if name == ENQUEUE {
            decimal_schema()
        } else {
            positive()
        },
    );
    properties.insert("idempotency_key".into(), common::key_schema());
    properties.insert(
        "expected_incarnation".into(),
        object([
            ("type", text("string")),
            ("pattern", text("^[0-9a-f]{32}$")),
            ("maxLength", json::number(32)),
            (
                "description",
                text("Exact launch-pinned incarnation, never a repository selector."),
            ),
        ]),
    );
    properties.insert(
        "object_format".into(),
        object([
            ("type", text("string")),
            ("enum", Value::Array(vec![text("sha1"), text("sha256")])),
        ]),
    );
    let mut required = vec![
        "number",
        "expected_version",
        "idempotency_key",
        "expected_incarnation",
        "object_format",
    ];
    let mut references = vec![("target_reference", "target_reference_hex")];
    if matches!(name, ENQUEUE | LAND) {
        for field in ["pull_request", "expected_pull_request_version"] {
            properties.insert(field.into(), positive());
            required.push(field);
        }
        for field in ["expected_source", "expected_target"] {
            properties.insert(field.into(), object([
                ("type", text("string")), ("maxLength", json::number(64)),
                ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
                ("description", text("Explicit nonzero native OID in the launch-pinned repository hash format.")),
            ]));
            required.push(field);
        }
        references.push(("source_reference", "source_reference_hex"));
        if name == LAND {
            properties.insert("expected_policy_epoch".into(), positive());
            required.push("expected_policy_epoch");
        } else {
            properties.insert("priority".into(), object([
                ("type", text("string")), ("maxLength", json::number(10)),
                ("pattern", text("^(0|[1-9][0-9]*)$")), ("default", text("0")),
                ("description", text("Canonical unsigned decimal u32, at most 4294967295; higher enters first.")),
            ]));
        }
    } else if name == DEQUEUE {
        properties.insert("pull_request".into(), positive());
        properties.insert(
            "reason".into(),
            object([
                ("type", text("string")),
                (
                    "enum",
                    Value::Array(
                        [
                            "withdrawn",
                            "conflict",
                            "check-failed",
                            "base-moved",
                            "evicted",
                            "admin-override",
                        ]
                        .into_iter()
                        .map(text)
                        .collect(),
                    ),
                ),
            ]),
        );
        required.extend(["pull_request", "reason"]);
    } else {
        properties.insert("order".into(), object([
            ("type", text("array")), ("minItems", json::number(1)),
            ("maxItems", json::number(MAX_ORDER as u64)), ("uniqueItems", Value::Bool(true)), ("items", positive()),
            ("description", text("Complete desired order of every current queued PR; no omission or addition is admitted.")),
        ]));
        required.push("order");
    }
    for (plain, encoded) in &references {
        properties.insert((*plain).into(), object([
            ("type", text("string")), ("maxLength", json::number(MAX_BRANCH as u64)),
            ("description", text("Full refs/heads/ branch, at most 1024 UTF-8 bytes; supply this OR its hex alternative.")),
        ]));
        properties.insert((*encoded).into(), object([
            ("type", text("string")), ("maxLength", json::number((MAX_BRANCH * 2) as u64)),
            ("pattern", text("^(?:[0-9a-f]{2})+$")),
            ("description", text("Lossless full branch bytes in lowercase hex; alternative to the UTF-8 field.")),
        ]));
    }
    let mut schema = common::input_schema(properties, &required);
    if let Value::Object(fields) = &mut schema {
        fields.insert(
            "allOf".into(),
            Value::Array(
                references
                    .into_iter()
                    .map(|(plain, encoded)| {
                        object([(
                            "oneOf",
                            Value::Array(vec![
                                object([("required", Value::Array(vec![text(plain)]))]),
                                object([("required", Value::Array(vec![text(encoded)]))]),
                            ]),
                        )])
                    })
                    .collect(),
            ),
        );
    }
    schema
}
fn positive() -> Value {
    object([
        ("type", text("string")),
        ("maxLength", json::number(20)),
        ("pattern", text("^[1-9][0-9]*$")),
    ])
}
