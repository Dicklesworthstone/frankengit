//! Narrow issue writes through real sealed canonical admission. No lookup of
//! the latest version, caller principal, source checkout or local issue DB.
use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{Tool, ToolError};
use super::mutations as common;
use super::{NodeTools, require_fields, string};
use fgit_forge::{
    IssueNumber,
    event::issue::{IssueAction, IssueCommand, IssueEdit, MAX_LABELS},
};

pub(super) fn is_tool(name: &str) -> bool {
    matches!(
        name,
        "frankengit_issue_open"
            | "frankengit_issue_edit"
            | "frankengit_issue_close"
            | "frankengit_issue_reopen"
            | "frankengit_issue_comment"
    )
}
pub(super) fn tools() -> Vec<Tool> {
    [
        ("frankengit_issue_open", "Open a numbered issue at explicit version zero. The launch-bound principal and original retry key own this canonical mutation."),
        ("frankengit_issue_edit", "Replace only supplied issue fields at an exact positive version. Omitted fields survive; empty body or labels explicitly clears them."),
        ("frankengit_issue_close", "Close an issue at an exact positive version. A stale version is a canonical refusal, never a latest-version retry."),
        ("frankengit_issue_reopen", "Reopen a closed issue at an exact positive version. Requires the original stable key on retry."),
        ("frankengit_issue_comment", "Append literal comment text at an exact positive issue version. Replaying the identical command and key never duplicates the comment."),
    ].into_iter().map(|(name, description)| Tool { name, description, schema: schema(name) }).collect()
}
fn schema(name: &str) -> Value {
    let mut properties = common::base_properties();
    let mut required = vec!["number", "expected_version", "idempotency_key"];
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
        "frankengit_issue_open" | "frankengit_issue_edit" | "frankengit_issue_comment"
    ) {
        properties.insert(
            "body".into(),
            common::text_schema(common::MAX_TEXT_BYTES as u64),
        );
    }
    if name == "frankengit_issue_open" {
        required.extend(["title", "body"]);
    }
    if name == "frankengit_issue_comment" {
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
pub(super) fn parse(name: &str, args: &Object) -> Result<IssueCommand, ToolError> {
    if !is_tool(name) {
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
pub(super) fn call(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.issues {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let command = parse(name, args)?;
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    command
        .proposed_event(principal)
        .map_err(|_| ToolError::invalid("invalid_issue_command"))?;
    let context = backend.node.request_context();
    // From here onward a failed response is not proof of non-commit. Native
    // admission recovers a prior terminal result before current intake gates.
    let (tx, outcome) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_issue_durable_in(
            &context,
            &session,
            &command,
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &outcome));
    result.insert("type".into(), text("issue_publication"));
    result.insert("number".into(), text(command.number.get().to_string()));
    result.insert("action".into(), text(command.action.name()));
    result.insert(
        "expected_version".into(),
        text(common::number(args, "expected_version")?.to_string()),
    );
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
}
