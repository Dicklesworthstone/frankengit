//! Native discussions under independent launch-time read and write grants.
//! Authorship comes only from the launch principal; repository text is untrusted.
use super::issues::rendered;
use super::mutations as common;
use super::*;
use fgit_forge::event::discussion::{
    DiscussionAction, DiscussionCommand, DiscussionCommentIntent, DiscussionEdit,
    DiscussionSnapshot, DiscussionState,
};
use fgit_forge::{AggregateId, DiscussionNumber, ForgeEventPayload};

pub(super) fn is_read(name: &str) -> bool {
    matches!(
        name,
        "frankengit_discussion_list" | "frankengit_discussion_show"
    )
}
pub(super) fn is_write(name: &str) -> bool {
    matches!(
        name,
        "frankengit_discussion_open"
            | "frankengit_discussion_edit"
            | "frankengit_discussion_comment"
            | "frankengit_discussion_append_comment"
            | "frankengit_discussion_lock"
            | "frankengit_discussion_unlock"
            | "frankengit_discussion_close"
            | "frankengit_discussion_reopen"
    )
}
pub(super) fn read_tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "frankengit_discussion_list",
            description: "List standalone discussions at one authenticated head under the independent discussion-read grant. Continue with the original snapshot token. Metadata never selects identity or grants access.",
            schema: rendered::schema(schema(false)),
        },
        Tool {
            name: "frankengit_discussion_show",
            description: "Read a discussion and its exact authored lifecycle and comment history under the independent discussion-read grant. Number, versions and cursors are exact decimal strings. Optional rendering preserves raw text.",
            schema: rendered::schema(schema(true)),
        },
    ]
}
pub(super) fn write_tools() -> Vec<Tool> {
    [
        ("frankengit_discussion_open", "Open a standalone discussion at explicit version zero under the independent discussion-write grant and launch-bound principal. Retry only the identical command and original durable key."),
        ("frankengit_discussion_edit", "Edit supplied discussion title/body at the exact positive version. Omitted metadata, comments, lock and state survive. Uses only the explicit discussion-write grant."),
        ("frankengit_discussion_comment", "Append an immutable authored comment at the exact positive discussion version. Locked discussions refuse; closed unlocked discussions accept replies. Retain the original key and payload."),
        ("frankengit_discussion_append_comment", "Append an immutable authored comment across concurrent discussion changes without an expected version. Current locks, permissions and budgets still apply. Retry only the same body, number and original durable key; never use a new key to recover an uncertain result."),
        ("frankengit_discussion_close", "Close an open discussion at the exact positive version under the independent discussion-write grant. Comments, metadata and lock are preserved."),
        ("frankengit_discussion_reopen", "Reopen a closed discussion at the exact positive version under the independent discussion-write grant. Text cannot select another actor or expand access."),
        ("frankengit_discussion_lock", "Lock discussion replies at the exact positive version under the independent discussion-write grant. Metadata edits and lifecycle remain independent; retry the original durable key."),
        ("frankengit_discussion_unlock", "Unlock discussion replies at the exact positive version under the independent discussion-write grant. Prior refused comment keys stay refused; submit new intent with a new key."),
    ].into_iter().map(|(name, description)| Tool { name, description, schema: write_schema(name) }).collect()
}
fn write_schema(name: &str) -> Value {
    let mut fields = common::base_properties();
    let mut required = vec!["number", "expected_version", "idempotency_key"];
    if name == "frankengit_discussion_append_comment" {
        fields.remove("expected_version");
        required = vec!["number", "idempotency_key"];
    }
    if matches!(
        name,
        "frankengit_discussion_open" | "frankengit_discussion_edit"
    ) {
        fields.insert("title".into(), common::text_schema(256));
    }
    if matches!(
        name,
        "frankengit_discussion_open"
            | "frankengit_discussion_edit"
            | "frankengit_discussion_comment"
            | "frankengit_discussion_append_comment"
    ) {
        fields.insert(
            "body".into(),
            common::text_schema(common::MAX_TEXT_BYTES as u64),
        );
    }
    if name == "frankengit_discussion_open" {
        required.extend(["title", "body"]);
    }
    if matches!(
        name,
        "frankengit_discussion_comment" | "frankengit_discussion_append_comment"
    ) {
        required.push("body");
    }
    common::input_schema(fields, &required)
}
fn parse(name: &str, args: &Object) -> Result<DiscussionCommand, ToolError> {
    if !is_write(name) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    require_fields(
        args,
        if matches!(
            name,
            "frankengit_discussion_open" | "frankengit_discussion_edit"
        ) {
            &[
                "number",
                "expected_version",
                "idempotency_key",
                "title",
                "body",
            ]
        } else if name == "frankengit_discussion_comment" {
            &["number", "expected_version", "idempotency_key", "body"]
        } else {
            &["number", "expected_version", "idempotency_key"]
        },
    )?;
    let number = DiscussionNumber::try_new(common::number(args, "number")?)
        .ok_or(ToolError::invalid("positive_discussion_number_required"))?;
    let expected_version = common::version(args, name == "frankengit_discussion_open")?;
    let action = match name {
        "frankengit_discussion_open" => DiscussionAction::Open {
            title: common::required(args, "title")?.to_owned(),
            body: common::body(args, "body")?.ok_or(ToolError::invalid("body_required"))?,
        },
        "frankengit_discussion_edit" => DiscussionAction::Edit(DiscussionEdit {
            title: string(args, "title")?.map(str::to_owned),
            body: common::body(args, "body")?,
        }),
        "frankengit_discussion_comment" => DiscussionAction::Comment {
            body: common::body(args, "body")?.ok_or(ToolError::invalid("body_required"))?,
        },
        "frankengit_discussion_lock" => DiscussionAction::Lock,
        "frankengit_discussion_unlock" => DiscussionAction::Unlock,
        "frankengit_discussion_close" => DiscussionAction::Close,
        "frankengit_discussion_reopen" => DiscussionAction::Reopen,
        _ => return Err(ToolError::invalid("tool_not_granted")),
    };
    action
        .validate()
        .map_err(|_| ToolError::invalid("invalid_discussion_command"))?;
    Ok(DiscussionCommand {
        number,
        expected_version,
        action,
    })
}
pub(super) fn write(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.discussions {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    if name == "frankengit_discussion_append_comment" {
        return write_append(backend, args);
    }
    let command = parse(name, args)?;
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    command
        .proposed_event(principal)
        .map_err(|_| ToolError::invalid("invalid_discussion_command"))?;
    let request = backend.command_context();
    let (tx, outcome) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_discussion_durable_in(
            &request,
            &session,
            &command,
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &outcome));
    result.insert("type".into(), text("discussion_publication"));
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

fn parse_append(args: &Object) -> Result<DiscussionCommentIntent, ToolError> {
    require_fields(args, &["number", "idempotency_key", "body"])?;
    let intent = DiscussionCommentIntent {
        number: DiscussionNumber::try_new(common::number(args, "number")?)
            .ok_or(ToolError::invalid("positive_discussion_number_required"))?,
        body: common::body(args, "body")?.ok_or(ToolError::invalid("body_required"))?,
    };
    intent
        .validate()
        .map_err(|_| ToolError::invalid("invalid_discussion_comment"))?;
    Ok(intent)
}

fn write_append(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    let intent = parse_append(args)?;
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    let request = backend.command_context();
    let (tx, outcome) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_discussion_comment_durable_in(
            &request,
            &session,
            &intent,
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &outcome));
    result.insert("type".into(), text("discussion_publication"));
    result.insert("number".into(), text(intent.number.get().to_string()));
    result.insert("action".into(), text("append-comment"));
    result.insert("expected_version".into(), Value::Null);
    result.insert("complete".into(), Value::Bool(true));
    result.insert("refs_changed".into(), Value::Bool(false));
    result.insert("delivery_acknowledged".into(), Value::Null);
    result.insert("historical_outcome".into(), Value::Bool(true));
    Ok(Value::Object(result))
}
fn optional(value: Option<u64>) -> Value {
    value.map_or(Value::Null, |n| text(n.to_string()))
}
fn summary(value: &DiscussionSnapshot) -> Result<Value, ToolError> {
    DiscussionAction::Open {
        title: value.title.clone(),
        body: value.body.clone(),
    }
    .validate()
    .map_err(|_| ToolError::failed("invalid_discussion_snapshot"))?;
    if value.comments >= value.version.get() {
        return Err(ToolError::failed("invalid_discussion_snapshot"));
    }
    Ok(object([
        ("number", text(value.number.get().to_string())),
        ("version", text(value.version.get().to_string())),
        ("title", text(value.title.clone())),
        ("body", text(value.body.clone())),
        (
            "state",
            text(match value.state {
                DiscussionState::Open => "open",
                DiscussionState::Closed => "closed",
            }),
        ),
        ("opened_by", text(value.opened_by.to_string())),
        ("last_actor", text(value.last_actor.to_string())),
        ("comments", text(value.comments.to_string())),
        ("locked", Value::Bool(value.locked)),
    ]))
}
fn action(value: &DiscussionAction) -> Value {
    match value {
        DiscussionAction::Open { title, body } => object([
            ("name", text("open")),
            ("title", text(title.clone())),
            ("body", text(body.clone())),
        ]),
        DiscussionAction::Edit(edit) => {
            let mut fields = Object::new();
            fields.insert("name".into(), text("edit"));
            if let Some(title) = &edit.title {
                fields.insert("title".into(), text(title.clone()));
            }
            if let Some(body) = &edit.body {
                fields.insert("body".into(), text(body.clone()));
            }
            Value::Object(fields)
        }
        DiscussionAction::Comment { body } => {
            object([("name", text("comment")), ("body", text(body.clone()))])
        }
        DiscussionAction::Close
        | DiscussionAction::Reopen
        | DiscussionAction::Lock
        | DiscussionAction::Unlock => object([("name", text(value.name()))]),
    }
}
fn read_error(error: fgit_node::DiscussionReadRefusal) -> ToolError {
    match error {
        fgit_node::DiscussionReadRefusal::SnapshotMoved => ToolError::failed("snapshot_moved"),
        fgit_node::DiscussionReadRefusal::SnapshotRequired => {
            ToolError::invalid("snapshot_required")
        }
        fgit_node::DiscussionReadRefusal::InvalidLimit => ToolError::invalid("invalid_limit"),
        _ => ToolError::failed("discussion_read_unavailable"),
    }
}
pub(super) fn read(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.discussions || !is_read(name) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let show = name == "frankengit_discussion_show";
    require_fields(
        args,
        if show {
            &[
                "number",
                "after_version",
                "limit",
                "expected_head",
                "render",
            ]
        } else {
            &["after", "limit", "expected_head", "render"]
        },
    )?;
    let mut rendering = rendered::RenderBudget::from_args(args)?;
    let after = decimal(args, if show { "after_version" } else { "after" }, 0)?;
    let limit = limit(args)?;
    let expected = head(args, after)?;
    let request = backend.command_context();
    if show {
        let number = DiscussionNumber::try_new(decimal(args, "number", 0)?)
            .ok_or(ToolError::invalid("positive_discussion_number_required"))?;
        let page = backend
            .node
            .runtime()
            .block_on(
                backend
                    .node
                    .read_discussion_history_in(&request, number, after, limit, expected),
            )
            .map_err(read_error)?;
        if expected.is_some_and(|head| head != page.source_head)
            || page.events.len() > usize::from(limit)
            || page
                .discussion
                .as_ref()
                .is_some_and(|row| row.number != number)
            || (page.discussion.is_none() && (!page.events.is_empty() || page.next_after.is_some()))
        {
            return Err(ToolError::failed("invalid_discussion_history"));
        }
        if let Some(row) = &page.discussion {
            let remaining = row.version.get().saturating_sub(after);
            let count = remaining.min(u64::from(limit));
            let next = if remaining > count {
                after.checked_add(count)
            } else {
                None
            };
            if page.events.len() as u64 != count || page.next_after != next {
                return Err(ToolError::failed("invalid_discussion_history"));
            }
        }
        let mut row = page
            .discussion
            .as_ref()
            .map(summary)
            .transpose()?
            .unwrap_or(Value::Null);
        rendering.annotate(&mut row)?;
        let mut events = Vec::new();
        for (index, event) in page.events.iter().enumerate() {
            if event.aggregate != AggregateId::Discussion(number)
                || after
                    .checked_add(index as u64)
                    .and_then(|n| n.checked_add(1))
                    != Some(event.version.get())
            {
                return Err(ToolError::failed("invalid_discussion_history"));
            }
            let ForgeEventPayload::DiscussionChangedNative(change) = &event.payload else {
                return Err(ToolError::failed("invalid_discussion_history"));
            };
            change
                .action
                .validate()
                .map_err(|_| ToolError::failed("invalid_discussion_history"))?;
            let mut change_value = action(&change.action);
            rendering.annotate(&mut change_value)?;
            events.push(object([
                ("version", text(event.version.get().to_string())),
                ("actor", text(change.actor.to_string())),
                ("action", change_value),
            ]));
        }
        let mut result = backend.header(page.source_head);
        result.insert("schema_version".into(), json::number(1));
        result.insert("type".into(), text("discussion_history"));
        result.insert("scope".into(), text("repository_discussions"));
        result.insert("found".into(), Value::Bool(page.discussion.is_some()));
        result.insert("discussion".into(), row);
        result.insert("events".into(), Value::Array(events));
        result.insert("next_after_version".into(), optional(page.next_after));
        result.insert("complete".into(), Value::Bool(page.next_after.is_none()));
        Ok(Value::Object(result))
    } else {
        let page = backend
            .node
            .runtime()
            .block_on(
                backend
                    .node
                    .read_discussions_in(&request, after, limit, expected),
            )
            .map_err(read_error)?;
        if expected.is_some_and(|head| head != page.source_head)
            || page.discussions.len() > usize::from(limit)
            || page.discussions.iter().any(|row| row.number.get() <= after)
            || page
                .discussions
                .windows(2)
                .any(|p| p[0].number >= p[1].number)
            || page.next_after.is_some_and(|next| {
                page.discussions.len() != usize::from(limit)
                    || page.discussions.last().map(|row| row.number.get()) != Some(next)
            })
        {
            return Err(ToolError::failed("invalid_discussion_page"));
        }
        let rows = page
            .discussions
            .iter()
            .map(|row| {
                let mut row = summary(row)?;
                rendering.annotate(&mut row)?;
                Ok(row)
            })
            .collect::<Result<Vec<_>, ToolError>>()?;
        let mut result = backend.header(page.source_head);
        result.insert("schema_version".into(), json::number(1));
        result.insert("type".into(), text("discussion_page"));
        result.insert("scope".into(), text("repository_discussions"));
        result.insert("discussions".into(), Value::Array(rows));
        result.insert("next_after".into(), optional(page.next_after));
        result.insert("complete".into(), Value::Bool(page.next_after.is_none()));
        Ok(Value::Object(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base(version: &str) -> Object {
        object([
            ("number", text("9007199254740993")),
            ("expected_version", text(version)),
            ("idempotency_key", text("original")),
        ])
        .object()
        .unwrap()
        .clone()
    }
    #[test]
    fn exact_decimal_versions_literal_text_and_closed_grammar_are_enforced() {
        let mut args = base("1");
        args.insert("body".into(), text("exact é\r\n<script>literal</script>"));
        let comment = parse("frankengit_discussion_comment", &args).unwrap();
        assert_eq!(comment.number.get(), 9007199254740993);
        assert_eq!(
            comment.action,
            DiscussionAction::Comment {
                body: "exact é\r\n<script>literal</script>".into()
            }
        );
        args.insert("body".into(), text(""));
        assert!(parse("frankengit_discussion_comment", &args).is_err());
        assert_eq!(
            parse("frankengit_discussion_edit", &args).unwrap().action,
            DiscussionAction::Edit(DiscussionEdit {
                title: None,
                body: Some(String::new())
            })
        );
        for field in [
            "principal",
            "repository",
            "storage",
            "source_head",
            "assignees",
            "labels",
            "due_at",
        ] {
            let mut args = base("1");
            args.insert(field.into(), text("injected"));
            assert!(parse("frankengit_discussion_close", &args).is_err());
        }
        for version in ["0", "01", "18446744073709551615"] {
            assert!(parse("frankengit_discussion_lock", &base(version)).is_err());
        }
        let mut args = base("1");
        args.insert("number".into(), json::number(7));
        assert!(parse("frankengit_discussion_unlock", &args).is_err());
        assert!(parse("frankengit_discussion_edit", &base("1")).is_err());
        assert!(parse("frankengit_discussion_open", &base("0")).is_err());
        for tool in write_tools() {
            assert_eq!(
                tool.schema.object().unwrap()["additionalProperties"],
                Value::Bool(false)
            );
        }
    }

    #[test]
    fn append_grammar_has_no_predecessor_or_caller_selected_actor() {
        let mut args = base("1");
        args.remove("expected_version");
        args.insert("body".into(), text("Exact é\r\n<script>data</script>"));
        let intent = parse_append(&args).unwrap();
        assert_eq!(intent.number.get(), 9007199254740993);
        assert_eq!(intent.body, "Exact é\r\n<script>data</script>");
        for field in [
            "expected_version",
            "principal",
            "repository",
            "source_head",
            "title",
        ] {
            let mut changed = args.clone();
            changed.insert(field.into(), text("1"));
            assert!(parse_append(&changed).is_err(), "{field}");
        }
        for body in [
            "".to_owned(),
            " \r\n".into(),
            "x".repeat(common::MAX_TEXT_BYTES + 1),
        ] {
            let mut changed = args.clone();
            changed.insert("body".into(), text(body));
            assert!(parse_append(&changed).is_err());
        }
        let schema = write_schema("frankengit_discussion_append_comment");
        let schema = schema.object().unwrap();
        assert!(
            !schema["properties"]
                .object()
                .unwrap()
                .contains_key("expected_version")
        );
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
    }
}
