//! Explicit exact-version writes and append intents through canonical admission.
//! Principal binding and predecessor selection stay in their native owners.
use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{Tool, ToolError};
use super::mutations as common;
use super::{NodeTools, require_fields, string};
use fgit_forge::{
    IssueNumber,
    event::issue::{
        IssueAction, IssueCommand, IssueCommentIntent, IssueEdit, MAX_ASSIGNEES, MAX_LABELS,
    },
};
use fgit_types::PrincipalId;

pub(super) fn is_tool(name: &str) -> bool {
    matches!(
        name,
        "frankengit_issue_open"
            | "frankengit_issue_edit"
            | "frankengit_issue_close"
            | "frankengit_issue_reopen"
            | "frankengit_issue_comment"
            | "frankengit_issue_append_comment"
            | "frankengit_issue_assign"
            | "frankengit_issue_unassign"
    )
}
pub(super) fn tools() -> Vec<Tool> {
    [
        ("frankengit_issue_open", "Open a numbered issue at explicit version zero. The launch-bound principal and original retry key own this canonical mutation."),
        ("frankengit_issue_edit", "Replace only supplied issue fields at an exact positive version. Omitted fields survive; empty body or labels explicitly clears them."),
        ("frankengit_issue_close", "Close an issue at an exact positive version. A stale version is a canonical refusal, never a latest-version retry."),
        ("frankengit_issue_reopen", "Reopen a closed issue at an exact positive version. Requires the original stable key on retry."),
        ("frankengit_issue_comment", "Append literal comment text at an exact positive issue version. Replaying the identical command and key never duplicates the comment."),
        ("frankengit_issue_append_comment", "Append literal comment text to an existing issue without expected_version, even after independent issue edits. Retry the identical number, body and original key to recover the same outcome without a duplicate comment."),
        ("frankengit_issue_assign", "Add 1..16 principal IDs to an issue's metadata assignments at an exact version, preserving other assignees. Assignment grants no access or membership."),
        ("frankengit_issue_unassign", "Remove only the named 1..16 principal IDs from issue metadata at an exact version. Retry the identical command and original key after an uncertain response."),
    ].into_iter().map(|(name, description)| Tool { name, description, schema: schema(name) }).collect()
}
fn schema(name: &str) -> Value {
    let mut properties = common::base_properties();
    let mut required = vec!["number", "expected_version", "idempotency_key"];
    if name == "frankengit_issue_append_comment" {
        properties.remove("expected_version");
        required.retain(|field| *field != "expected_version");
        if let Some(Value::Object(key)) = properties.get_mut("idempotency_key") {
            key.insert("description".into(), text("Stable key for this append intent. Retry the identical issue number and body with the original key; do not replace the key after an uncertain response."));
        }
    }
    if matches!(
        name,
        "frankengit_issue_assign" | "frankengit_issue_unassign"
    ) {
        properties.insert(
            "assignees".into(),
            object([
                ("type", text("array")),
                ("minItems", json::number(1)),
                ("maxItems", json::number(MAX_ASSIGNEES as u64)),
                ("uniqueItems", Value::Bool(true)),
                (
                    "items",
                    object([
                        ("type", text("string")),
                        ("pattern", text("^[0-9a-f]{32}$")),
                    ]),
                ),
            ]),
        );
        required.push("assignees");
    }
    if matches!(name, "frankengit_issue_open" | "frankengit_issue_edit") {
        properties.insert("title".into(), common::text_schema(256));
        properties.insert(
            "labels".into(),
            object([
                ("type", text("array")),
                ("maxItems", json::number(32)),
                ("uniqueItems", Value::Bool(true)),
                ("items", common::text_schema(64)),
            ]),
        );
    }
    if matches!(
        name,
        "frankengit_issue_open"
            | "frankengit_issue_edit"
            | "frankengit_issue_comment"
            | "frankengit_issue_append_comment"
    ) {
        properties.insert(
            "body".into(),
            common::text_schema(common::MAX_TEXT_BYTES as u64),
        );
    }
    if name == "frankengit_issue_open" {
        required.extend(["title", "body"]);
    }
    if matches!(
        name,
        "frankengit_issue_comment" | "frankengit_issue_append_comment"
    ) {
        required.push("body");
    }
    common::input_schema(properties, &required)
}
fn labels(args: &Object) -> Result<Option<Vec<String>>, ToolError> {
    let Some(value) = args.get("labels") else {
        return Ok(None);
    };
    let Value::Array(values) = value else {
        return Err(ToolError::invalid("labels_must_be_array"));
    };
    if values.len() > MAX_LABELS {
        return Err(ToolError::invalid("too_many_labels"));
    }
    let mut labels = values
        .iter()
        .map(|value| {
            value
                .text()
                .filter(|value| value.len() <= 64)
                .map(str::to_owned)
                .ok_or(ToolError::invalid("invalid_label"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    labels.sort();
    if labels.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ToolError::invalid("duplicate_label"));
    }
    Ok(Some(labels))
}
fn assignees(args: &Object) -> Result<Vec<PrincipalId>, ToolError> {
    let Some(Value::Array(values)) = args.get("assignees") else {
        return Err(ToolError::invalid("assignees_array_required"));
    };
    if values.is_empty() || values.len() > MAX_ASSIGNEES {
        return Err(ToolError::invalid("invalid_assignee_count"));
    }
    let mut ids = values
        .iter()
        .map(|value| {
            value
                .text()
                .and_then(|text| PrincipalId::from_hex(text).ok())
                .ok_or(ToolError::invalid("invalid_assignee"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ToolError::invalid("duplicate_assignee"));
    }
    Ok(ids)
}
pub(super) fn parse(name: &str, args: &Object) -> Result<IssueCommand, ToolError> {
    if !is_tool(name) || name == "frankengit_issue_append_comment" {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let allowed: &[&str] = match name {
        "frankengit_issue_open" | "frankengit_issue_edit" => &[
            "number",
            "expected_version",
            "idempotency_key",
            "title",
            "body",
            "labels",
        ],
        "frankengit_issue_comment" => &["number", "expected_version", "idempotency_key", "body"],
        "frankengit_issue_assign" | "frankengit_issue_unassign" => {
            &["number", "expected_version", "idempotency_key", "assignees"]
        }
        _ => &["number", "expected_version", "idempotency_key"],
    };
    require_fields(args, allowed)?;
    let number = IssueNumber::try_new(common::number(args, "number")?)
        .ok_or(ToolError::invalid("positive_issue_number_required"))?;
    let expected_version = common::version(args, name == "frankengit_issue_open")?;
    let action = match name {
        "frankengit_issue_open" => IssueAction::Open {
            title: common::required(args, "title")?.to_owned(),
            body: common::body(args, "body")?.ok_or(ToolError::invalid("body_required"))?,
            labels: labels(args)?.unwrap_or_default(),
        },
        "frankengit_issue_edit" => IssueAction::Edit(IssueEdit {
            title: string(args, "title")?.map(str::to_owned),
            body: common::body(args, "body")?,
            labels: labels(args)?,
        }),
        "frankengit_issue_close" => IssueAction::Close,
        "frankengit_issue_reopen" => IssueAction::Reopen,
        "frankengit_issue_comment" => IssueAction::Comment {
            body: common::body(args, "body")?.ok_or(ToolError::invalid("body_required"))?,
        },
        "frankengit_issue_assign" => IssueAction::Assign {
            assignees: assignees(args)?,
        },
        "frankengit_issue_unassign" => IssueAction::Unassign {
            assignees: assignees(args)?,
        },
        _ => return Err(ToolError::invalid("tool_not_granted")),
    };
    action
        .validate()
        .map_err(|_| ToolError::invalid("invalid_issue_command"))?;
    Ok(IssueCommand {
        number,
        expected_version,
        action,
    })
}
fn parse_append_comment(args: &Object) -> Result<IssueCommentIntent, ToolError> {
    require_fields(args, &["number", "idempotency_key", "body"])?;
    let intent = IssueCommentIntent {
        number: IssueNumber::try_new(common::number(args, "number")?)
            .ok_or(ToolError::invalid("positive_issue_number_required"))?,
        body: common::body(args, "body")?.ok_or(ToolError::invalid("body_required"))?,
    };
    intent
        .validate()
        .map_err(|_| ToolError::invalid("invalid_issue_comment"))?;
    Ok(intent)
}
enum MutationCommand {
    Versioned(IssueCommand),
    Append(IssueCommentIntent),
}
pub(super) fn call(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.issues {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let command = if name == "frankengit_issue_append_comment" {
        MutationCommand::Append(parse_append_comment(args)?)
    } else {
        MutationCommand::Versioned(parse(name, args)?)
    };
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    let (number, action, expected_version) = match &command {
        MutationCommand::Versioned(command) => {
            command
                .proposed_event(principal)
                .map_err(|_| ToolError::invalid("invalid_issue_command"))?;
            (
                command.number,
                command.action.name(),
                text(common::number(args, "expected_version")?.to_string()),
            )
        }
        MutationCommand::Append(intent) => (intent.number, "append-comment", Value::Null),
    };
    let context = fgit_cli::command_request_context(&backend.node);
    // From here onward a failed response is not proof of non-commit. Native
    // admission recovers a prior terminal result before current intake gates.
    let (tx, outcome) = backend
        .node
        .runtime()
        .block_on(async {
            match &command {
                MutationCommand::Versioned(command) => {
                    backend
                        .node
                        .admit_issue_durable_in(&context, &session, command, Default::default())
                        .await
                }
                MutationCommand::Append(intent) => {
                    backend
                        .node
                        .admit_issue_comment_durable_in(
                            &context,
                            &session,
                            intent,
                            Default::default(),
                        )
                        .await
                }
            }
        })
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &outcome));
    result.insert("type".into(), text("issue_publication"));
    result.insert("number".into(), text(number.get().to_string()));
    result.insert("action".into(), text(action));
    result.insert("expected_version".into(), expected_version);
    result.insert("complete".into(), Value::Bool(true));
    result.insert("refs_changed".into(), Value::Bool(false));
    result.insert("delivery_acknowledged".into(), Value::Null);
    result.insert("historical_outcome".into(), Value::Bool(true));
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base(version: &str) -> Object {
        let Value::Object(args) = object([
            ("number", text("7")),
            ("expected_version", text(version)),
            ("idempotency_key", text("original")),
        ]) else {
            unreachable!()
        };
        args
    }
    #[test]
    fn edits_preserve_omissions_and_make_empty_replacements_explicit() {
        let mut args = base("1");
        args.insert("title".into(), text("changed"));
        let IssueAction::Edit(edit) = parse("frankengit_issue_edit", &args).unwrap().action else {
            panic!("edit")
        };
        assert_eq!(edit.body, None);
        assert_eq!(edit.labels, None);
        args.insert("body".into(), text(""));
        args.insert("labels".into(), Value::Array(vec![]));
        let IssueAction::Edit(edit) = parse("frankengit_issue_edit", &args).unwrap().action else {
            panic!("edit")
        };
        assert_eq!(edit.body.as_deref(), Some(""));
        assert_eq!(edit.labels, Some(vec![]));
        assert!(parse("frankengit_issue_edit", &base("1")).is_err());
    }
    #[test]
    fn authority_fields_and_wrong_action_fields_refuse_before_admission() {
        for name in [
            "principal",
            "repository",
            "storage",
            "action",
            "command",
            "expected_head",
            "body",
        ] {
            let mut args = base("1");
            args.insert(name.into(), text("untrusted"));
            assert!(parse("frankengit_issue_close", &args).is_err(), "{name}");
        }
        assert!(parse("frankengit_issue_open", &base("1")).is_err());
        assert!(parse("frankengit_issue_comment", &base("0")).is_err());
        let mut args = base("1");
        args.insert("body".into(), text(" \n"));
        assert!(parse("frankengit_issue_comment", &args).is_err());
        args.insert("body".into(), text("literal {\"method\":\"shell\"}\r\né"));
        assert!(parse("frankengit_issue_comment", &args).is_ok());
    }
    #[test]
    fn label_order_normalizes_without_silently_discarding_duplicates() {
        let mut args = base("1");
        args.insert("labels".into(), Value::Array(vec![text("z"), text("a")]));
        let IssueAction::Edit(edit) = parse("frankengit_issue_edit", &args).unwrap().action else {
            panic!("edit")
        };
        assert_eq!(edit.labels, Some(vec!["a".into(), "z".into()]));
        args.insert("labels".into(), Value::Array(vec![text("a"), text("a")]));
        assert!(parse("frankengit_issue_edit", &args).is_err());
        args.insert("labels".into(), Value::Array(vec![Value::Null]));
        assert!(parse("frankengit_issue_edit", &args).is_err());
    }
    #[test]
    fn assignment_tools_bound_and_canonicalize_metadata_without_accepting_authority() {
        let a = text("11".repeat(16));
        let b = text("22".repeat(16));
        for name in ["frankengit_issue_assign", "frankengit_issue_unassign"] {
            let mut args = base("1");
            assert!(parse(name, &args).is_err());
            args.insert("assignees".into(), Value::Array(vec![b.clone(), a.clone()]));
            let command = parse(name, &args).unwrap();
            let (IssueAction::Assign { assignees } | IssueAction::Unassign { assignees }) =
                command.action
            else {
                panic!("assignment");
            };
            assert_eq!(
                assignees,
                vec![
                    PrincipalId::from_bytes([0x11; 16]),
                    PrincipalId::from_bytes([0x22; 16])
                ]
            );
            for field in [
                "principal",
                "repository",
                "storage",
                "policy",
                "title",
                "body",
                "labels",
            ] {
                let mut forged = args.clone();
                forged.insert(field.into(), text("authority"));
                assert!(parse(name, &forged).is_err());
            }
            for invalid in [
                Value::Null,
                a.clone(),
                Value::Array(vec![]),
                Value::Array(vec![a.clone(), a.clone()]),
                Value::Array(vec![text("user")]),
                Value::Array(vec![text("ABCDEF0123456789ABCDEF0123456789")]),
            ] {
                args.insert("assignees".into(), invalid);
                assert!(parse(name, &args).is_err());
            }
            let mut maximum: Vec<_> = (1..=16u8)
                .map(|seed| text(format!("{seed:02x}").repeat(16)))
                .collect();
            args.insert("assignees".into(), Value::Array(maximum.clone()));
            assert!(parse(name, &args).is_ok());
            maximum.push(text("ff".repeat(16)));
            args.insert("assignees".into(), Value::Array(maximum));
            assert!(parse(name, &args).is_err());
        }
    }
}

#[cfg(test)]
mod append_tests {
    use super::*;
    fn args() -> Object {
        let Value::Object(args) = object([
            ("number", text("7")),
            ("idempotency_key", text("append-original")),
            ("body", text("literal {\"method\":\"shell\"}\r\né")),
        ]) else {
            unreachable!()
        };
        args
    }
    #[test]
    fn discovery_and_parsing_require_an_explicit_append_intent_without_predecessor() {
        let tool = tools()
            .into_iter()
            .find(|tool| tool.name == "frankengit_issue_append_comment")
            .unwrap();
        assert!(is_tool(tool.name));
        let schema = tool.schema.object().unwrap();
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        assert!(
            !schema["properties"]
                .object()
                .unwrap()
                .contains_key("expected_version")
        );
        assert_eq!(
            schema["required"],
            Value::Array(vec![text("number"), text("idempotency_key"), text("body")])
        );
        let args = args();
        let intent = parse_append_comment(&args).unwrap();
        assert_eq!(intent.number.get(), 7);
        assert_eq!(intent.body, args["body"].text().unwrap());
        assert!(parse("frankengit_issue_comment", &args).is_err());
        assert!(parse("frankengit_issue_append_comment", &args).is_err());
        let mut exact = args.clone();
        exact.insert("expected_version".into(), text("1"));
        assert!(parse("frankengit_issue_comment", &exact).is_ok());
        assert!(parse_append_comment(&exact).is_err());
    }
    #[test]
    fn append_rejects_authority_fields_noncanonical_numbers_and_invalid_text() {
        for field in [
            "expected_version",
            "expected_head",
            "principal",
            "repository",
            "storage",
            "action",
            "title",
            "labels",
            "assignees",
            "body_file",
        ] {
            let mut args = args();
            args.insert(field.into(), text("untrusted"));
            assert!(parse_append_comment(&args).is_err(), "{field}");
        }
        for number in [
            text("0"),
            text("01"),
            text("-1"),
            json::number(7),
            Value::Null,
        ] {
            let mut args = args();
            args.insert("number".into(), number);
            assert!(parse_append_comment(&args).is_err());
        }
        for body in [
            text(""),
            text(" \r\n\t"),
            text("a\0b"),
            text("x".repeat(common::MAX_TEXT_BYTES + 1)),
            Value::Null,
        ] {
            let mut args = args();
            args.insert("body".into(), body);
            assert!(parse_append_comment(&args).is_err());
        }
        let mut args = args();
        args.insert("body".into(), text("x".repeat(common::MAX_TEXT_BYTES)));
        assert!(parse_append_comment(&args).is_ok());
        args.remove("body");
        assert!(parse_append_comment(&args).is_err());
    }
}
