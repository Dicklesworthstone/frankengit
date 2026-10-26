#![forbid(unsafe_code)]
//! One capability-narrow batch; no per-command key, principal or force override.
use super::*;
use std::collections::BTreeSet;
const MAX_COMMANDS: usize = fgit_node::OneNode::MAX_BRANCH_TRANSACTION_COMMANDS;

pub(super) fn schema() -> Value {
    let variants = [(CREATE, "create"), (UPDATE, "update"), (DELETE, "delete")]
        .into_iter()
        .map(|(name, action)| {
            let mut item = super::schema(name);
            if let Value::Object(fields) = &mut item {
                if let Some(Value::Object(properties)) = fields.get_mut("properties") {
                    properties.remove("idempotency_key");
                    properties.insert(
                        "action".into(),
                        object([
                            ("type", text("string")),
                            ("enum", Value::Array(vec![text(action)])),
                        ]),
                    );
                }
                if let Some(Value::Array(required)) = fields.get_mut("required") {
                    required.retain(|field| field.text() != Some("idempotency_key"));
                    required.push(text("action"));
                }
            }
            item
        })
        .collect();
    let mut fields = Object::new();
    fields.insert("idempotency_key".into(), common::key_schema());
    fields.insert(
        "commands".into(),
        object([
            ("type", text("array")),
            ("minItems", json::number(1)),
            ("maxItems", json::number(MAX_COMMANDS as u64)),
            ("items", object([("oneOf", Value::Array(variants))])),
        ]),
    );
    common::input_schema(fields, &["idempotency_key", "commands"])
}
pub(super) fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    require_fields(args, &["idempotency_key", "commands"])?;
    let Some(Value::Array(items)) = args.get("commands") else {
        return Err(ToolError::invalid("commands_required"));
    };
    if items.is_empty() || items.len() > MAX_COMMANDS {
        return Err(ToolError::invalid("branch_transaction_limit"));
    }
    let mut names = BTreeSet::new();
    let mut commands = Vec::with_capacity(items.len());
    for item in items {
        let Value::Object(fields) = item else {
            return Err(ToolError::invalid("command_must_be_object"));
        };
        require_fields(
            fields,
            &[
                "action",
                "reference",
                "reference_hex",
                "expected_old",
                "target",
            ],
        )?;
        let name = match common::required(fields, "action")? {
            "create" => CREATE,
            "update" => UPDATE,
            "delete" => DELETE,
            _ => return Err(ToolError::invalid("invalid_branch_action")),
        };
        let mut fields = fields.clone();
        fields.remove("action");
        let input = super::parse(name, &fields, format)?;
        let mut parsed = input.commands.into_iter();
        let command = parsed
            .next()
            .ok_or(ToolError::invalid("command_required"))?;
        if parsed.next().is_some() || !names.insert(command.name.clone()) {
            return Err(ToolError::invalid("duplicate_branch_target"));
        }
        commands.push(command);
    }
    Ok(Input {
        commands,
        bundle: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(items: Vec<Value>) -> Object {
        match object([
            ("idempotency_key", text("exact-key")),
            ("commands", Value::Array(items)),
        ]) {
            Value::Object(o) => o,
            _ => unreachable!(),
        }
    }
    fn create(name: &str, tip: &str) -> Value {
        object([
            ("action", text("create")),
            ("reference", text(name)),
            ("target", text(tip)),
        ])
    }
    #[test]
    fn mixed_commands_preserve_exact_native_expectations_and_raw_names() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let old = "a".repeat(format.digest_len() * 2);
            let new = "b".repeat(format.digest_len() * 2);
            let parsed = parse(
                &args(vec![
                    create("refs/heads/a", &new),
                    object([
                        ("action", text("update")),
                        ("reference_hex", text(hex(b"refs/heads/raw-\xff"))),
                        ("expected_old", text(&old)),
                        ("target", text(&new)),
                    ]),
                    object([
                        ("action", text("delete")),
                        ("reference", text("refs/heads/c")),
                        ("expected_old", text(&old)),
                    ]),
                ]),
                format,
            )
            .unwrap();
            assert_eq!(parsed.commands.len(), 3);
            assert!(parsed.bundle.is_none());
            assert_eq!(parsed.commands[0].expected_old, ExpectedOld::Absent);
            assert_eq!(parsed.commands[1].name.as_bytes(), b"refs/heads/raw-\xff");
            assert_eq!(parsed.commands[2].proposed_new, ProposedNew::Delete);
        }
    }
    #[test]
    fn bounds_duplicates_and_per_command_authority_are_closed() {
        let format = GitHashAlgorithm::Sha1;
        let tip = "a".repeat(40);
        let maximum = (0..MAX_COMMANDS)
            .map(|i| create(&format!("refs/heads/{i}"), &tip))
            .collect::<Vec<_>>();
        assert_eq!(
            parse(&args(maximum.clone()), format)
                .unwrap()
                .commands
                .len(),
            MAX_COMMANDS
        );
        let mut excess = maximum;
        excess.push(create("refs/heads/overflow", &tip));
        assert!(parse(&args(excess), format).is_err());
        assert!(parse(&args(vec![]), format).is_err());
        let good = create("refs/heads/a", &tip);
        assert!(parse(&args(vec![good.clone(), good.clone()]), format).is_err());
        for field in [
            "force",
            "principal",
            "idempotency_key",
            "bundle_hex_chunks",
            "atomic",
        ] {
            let Value::Object(mut entry) = good.clone() else {
                unreachable!()
            };
            entry.insert(field.into(), text("override"));
            assert!(parse(&args(vec![Value::Object(entry)]), format).is_err());
        }
        assert!(parse(&args(vec![Value::Null]), format).is_err());
    }
    #[test]
    fn transaction_schema_has_bounded_action_variants_without_nested_keys() {
        let encoded = schema().encode(json::MAX_INPUT).unwrap();
        assert!(encoded.contains("maxItems"));
        assert_eq!(encoded.matches("idempotency_key").count(), 2);
        assert!(
            encoded.contains("create") && encoded.contains("update") && encoded.contains("delete")
        );
    }
}
