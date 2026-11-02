//! Self inbox reads and preferences, with independent notification write grants.
use super::mutations as common;
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::issue::IssueState;
use fgit_forge::event::notification::{NotificationAction, NotificationCommand, NotificationMode};
use fgit_forge::{AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_node::{NotificationInboxPage, NotificationReadRefusal, NotificationThreadView};

pub(super) fn read_permitted(options: &Options) -> bool {
    options.issues && options.principal.is_some() && options.incarnation.is_some()
}
pub(super) fn write_permitted(options: &Options) -> bool {
    read_permitted(options) && options.writes.notifications
}
pub(super) fn is_read(name: &str) -> bool {
    matches!(name, "frankengit_inbox_list" | "frankengit_inbox_show")
}
pub(super) fn is_write(name: &str) -> bool {
    matches!(
        name,
        "frankengit_inbox_subscribe"
            | "frankengit_inbox_mute"
            | "frankengit_inbox_automatic"
            | "frankengit_inbox_read"
            | "frankengit_inbox_unread"
    )
}
pub(super) fn read_tools() -> Vec<Tool> {
    [("frankengit_inbox_list", "Read your repository issue inbox under issue-read permission. Reasons, read state and preferences derive from one exact canonical source. Continue with the original snapshot token and unchanged filters. Launch identity owns the recipient.", false),
     ("frankengit_inbox_show", "Read your preferences and activity for one issue, including an issue not yet followed. Requires issue-read plus launch-bound principal/incarnation. Reading does not acknowledge activity.", true)]
        .into_iter().map(|(name, description, show)| Tool { name, description, schema: read_schema(show) }).collect()
}
pub(super) fn write_tools() -> Vec<Tool> {
    [("frankengit_inbox_subscribe", "Subscribe yourself to an issue with notification-write plus issue-read. Preference version zero creates your stream; preserve the original predecessor and durable key on retry."),
     ("frankengit_inbox_mute", "Mute your issue notifications at the exact preference version, preserving read state. Requires notification-write plus issue-read; no issue content or other recipient changes."),
     ("frankengit_inbox_automatic", "Restore author/participant/assignee selection at the exact preference version, preserving read state. Requires notification-write plus issue-read."),
     ("frankengit_inbox_read", "Mark your explicit observed issue prefix read, using positive read_through and exact preference version. Later activity stays unread. Requires notification-write plus issue-read and the original durable key."),
     ("frankengit_inbox_unread", "Clear your read prefix at the exact preference version, preserving delivery mode. Requires notification-write plus issue-read; retry the identical command and original key.")]
        .into_iter().map(|(name, description)| {
            let mut properties = common::base_properties();
            let mut required = vec!["number", "expected_version", "idempotency_key"];
            if name == "frankengit_inbox_read" { properties.insert("read_through".into(), decimal_schema()); required.push("read_through"); }
            Tool { name, description, schema: common::input_schema(properties, &required) }
        }).collect()
}
fn read_schema(show: bool) -> Value {
    let mut properties = Object::new();
    properties.insert(
        "expected_head".into(),
        object([
            ("type", text("string")),
            ("maxLength", json::number(140)),
            (
                "description",
                text("Exact snapshot token, required with a nonzero after cursor."),
            ),
        ]),
    );
    if show {
        properties.insert("number".into(), decimal_schema());
    } else {
        properties.insert("after".into(), decimal_schema());
        properties.insert(
            "limit".into(),
            object([
                ("type", text("integer")),
                ("minimum", json::number(1)),
                ("maximum", json::number(100)),
                ("default", json::number(20)),
            ]),
        );
        for name in ["unread_only", "include_muted"] {
            properties.insert(
                name.into(),
                object([("type", text("boolean")), ("default", Value::Bool(false))]),
            );
        }
    }
    common::input_schema(properties, if show { &["number"] } else { &[] })
}
fn parse_command(name: &str, args: &Object) -> Result<NotificationCommand, ToolError> {
    if !is_write(name) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    require_fields(
        args,
        if name == "frankengit_inbox_read" {
            &[
                "number",
                "expected_version",
                "idempotency_key",
                "read_through",
            ]
        } else {
            &["number", "expected_version", "idempotency_key"]
        },
    )?;
    let number = IssueNumber::try_new(common::number(args, "number")?)
        .ok_or(ToolError::invalid("positive_issue_number_required"))?;
    let before = common::number(args, "expected_version")?;
    let expected_version = if before == 0 {
        ExpectedVersion::NewStream
    } else {
        let before = AggregateVersion::try_new(before)
            .ok_or(ToolError::invalid("invalid_preference_version"))?;
        before
            .next()
            .map_err(|_| ToolError::invalid("version_exhausted"))?;
        ExpectedVersion::Exactly(before)
    };
    let action = match name {
        "frankengit_inbox_subscribe" => NotificationAction::SetMode(NotificationMode::Subscribed),
        "frankengit_inbox_mute" => NotificationAction::SetMode(NotificationMode::Muted),
        "frankengit_inbox_automatic" => {
            NotificationAction::SetMode(NotificationMode::Participating)
        }
        "frankengit_inbox_read" => NotificationAction::SetReadThrough(Some(
            AggregateVersion::try_new(common::number(args, "read_through")?)
                .ok_or(ToolError::invalid("positive_read_through_required"))?,
        )),
        "frankengit_inbox_unread" => NotificationAction::SetReadThrough(None),
        _ => return Err(ToolError::invalid("tool_not_granted")),
    };
    Ok(NotificationCommand {
        number,
        expected_version,
        action,
    })
}
fn action_name(action: NotificationAction) -> &'static str {
    match action {
        NotificationAction::SetMode(NotificationMode::Subscribed) => "subscribe",
        NotificationAction::SetMode(NotificationMode::Muted) => "mute",
        NotificationAction::SetMode(NotificationMode::Participating) => "automatic",
        NotificationAction::SetReadThrough(Some(_)) => "read",
        NotificationAction::SetReadThrough(None) => "unread",
    }
}
pub(super) fn write(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !write_permitted(&backend.options) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let command = parse_command(name, args)?;
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    command
        .proposed_event(principal)
        .map_err(|_| ToolError::invalid("invalid_notification_command"))?;
    let request = fgit_cli::command_request_context(&backend.node);
    let (tx, terminal) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_notification_durable_in(
            &request,
            &session,
            &command,
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &terminal));
    result.insert("type".into(), text("notification_publication"));
    result.insert("number".into(), text(command.number.get().to_string()));
    result.insert("action".into(), text(action_name(command.action)));
    result.insert(
        "expected_version".into(),
        text(common::number(args, "expected_version")?.to_string()),
    );
    let (mode, through) = match command.action {
        NotificationAction::SetMode(mode) => (text(mode.name()), Value::Null),
        NotificationAction::SetReadThrough(through) => {
            (Value::Null, optional(through.map(AggregateVersion::get)))
        }
    };
    result.insert("requested_mode".into(), mode);
    result.insert("requested_read_through".into(), through);
    result.insert("complete".into(), Value::Bool(true));
    result.insert("refs_changed".into(), Value::Bool(false));
    result.insert("delivery_acknowledged".into(), Value::Null);
    result.insert("historical_outcome".into(), Value::Bool(true));
    Ok(Value::Object(result))
}
fn optional(value: Option<u64>) -> Value {
    value.map_or(Value::Null, |v| text(v.to_string()))
}
fn thread(row: &NotificationThreadView) -> Value {
    object([
        ("number", text(row.number.get().to_string())),
        ("issue_version", text(row.issue_version.get().to_string())),
        ("title", text(row.title.clone())),
        (
            "state",
            text(match row.state {
                IssueState::Open => "open",
                IssueState::Closed => "closed",
            }),
        ),
        (
            "preference_version",
            optional(row.preference_version.map(AggregateVersion::get)),
        ),
        ("mode", text(row.mode.name())),
        (
            "read_through",
            optional(row.read_through.map(AggregateVersion::get)),
        ),
        (
            "latest_other_version",
            optional(row.latest_other_version.map(AggregateVersion::get)),
        ),
        (
            "reasons",
            Value::Array(
                row.reasons
                    .iter()
                    .map(|reason| text(reason.as_str()))
                    .collect(),
            ),
        ),
        ("unread", Value::Bool(row.unread)),
    ])
}
fn boolean(args: &Object, name: &str) -> Result<bool, ToolError> {
    match args.get(name) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(ToolError::invalid("expected_boolean")),
    }
}
fn read_error(error: NotificationReadRefusal) -> ToolError {
    match error {
        NotificationReadRefusal::Unauthenticated => ToolError::invalid("principal_not_bound"),
        NotificationReadRefusal::InvalidLimit => ToolError::invalid("invalid_limit"),
        NotificationReadRefusal::SnapshotRequired => ToolError::invalid("snapshot_required"),
        NotificationReadRefusal::SnapshotMoved => ToolError::failed("snapshot_moved"),
        _ => ToolError::failed("notification_read_unavailable"),
    }
}
pub(super) fn read(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !read_permitted(&backend.options) || !is_read(name) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let show = name == "frankengit_inbox_show";
    require_fields(
        args,
        if show {
            &["number", "expected_head"]
        } else {
            &[
                "after",
                "limit",
                "expected_head",
                "unread_only",
                "include_muted",
            ]
        },
    )?;
    let after = decimal(args, "after", 0)?;
    let count = args
        .get("limit")
        .map(|v| v.unsigned().ok_or(ToolError::invalid("invalid_limit")))
        .transpose()?
        .unwrap_or(20);
    if !(1..=100).contains(&count) {
        return Err(ToolError::invalid("invalid_limit"));
    }
    let expected = head(args, after)?;
    let number = if show {
        Some(
            IssueNumber::try_new(common::number(args, "number")?)
                .ok_or(ToolError::invalid("positive_issue_number_required"))?,
        )
    } else {
        None
    };
    let unread = boolean(args, "unread_only")?;
    let muted = boolean(args, "include_muted")?;
    let session = common::session(
        backend,
        IdempotencyKey::new(b"inbox-read-no-publication".to_vec())
            .map_err(|_| ToolError::failed("notification_read_unavailable"))?,
    )?;
    let request = fgit_cli::command_request_context(&backend.node);
    let page = if let Some(number) = number {
        backend.node.runtime().block_on(
            backend
                .node
                .read_notification_thread_in(&request, &session, number, expected),
        )
    } else {
        backend
            .node
            .runtime()
            .block_on(backend.node.read_notification_inbox_in(
                &request,
                &session,
                after,
                count as u16,
                expected,
                unread,
                muted,
            ))
    }
    .map_err(read_error)?;
    validate_page(
        backend,
        &page,
        number,
        after,
        count as u16,
        expected,
        unread,
        muted,
    )?;
    let mut result = backend.header(page.binding.authority_head);
    result.extend([
        (
            "type".into(),
            text(if show {
                "notification_thread"
            } else {
                "notification_inbox"
            }),
        ),
        ("schema_version".into(), json::number(1)),
        (
            "principal_id".into(),
            text(page.binding.principal.to_string()),
        ),
        (
            "source_head".into(),
            text(page.binding.authority_head.to_string()),
        ),
        (
            "source_generation".into(),
            text(page.binding.authority_head_generation.to_string()),
        ),
        (
            "forge_position_root".into(),
            text(page.binding.forge_position_root.to_string()),
        ),
        (
            "outbox_root".into(),
            text(page.binding.outbox_root.to_string()),
        ),
        (
            "threads".into(),
            Value::Array(page.threads.iter().map(thread).collect()),
        ),
        ("next_after".into(), optional(page.next_after)),
        ("complete".into(), Value::Bool(page.next_after.is_none())),
    ]);
    if let Some(number) = number {
        result.insert("number".into(), text(number.get().to_string()));
        result.insert("found".into(), Value::Bool(!page.threads.is_empty()));
    } else {
        result.insert("after".into(), text(after.to_string()));
        result.insert("limit".into(), json::number(count));
        result.insert("unread_only".into(), Value::Bool(unread));
        result.insert("include_muted".into(), Value::Bool(muted));
    }
    Ok(Value::Object(result))
}
fn validate_page(
    backend: &NodeTools,
    page: &NotificationInboxPage,
    number: Option<IssueNumber>,
    after: u64,
    limit: u16,
    expected: Option<RepositoryAuthorityHeadId>,
    unread: bool,
    muted: bool,
) -> Result<(), ToolError> {
    let binding = &page.binding;
    if binding.tenant != backend.options.tenant
        || binding.repository != backend.options.repository
        || Some(binding.incarnation) != backend.options.incarnation
        || Some(binding.principal) != backend.options.principal
        || expected.is_some_and(|head| head != binding.authority_head)
        || page.threads.windows(2).any(|p| p[0].number >= p[1].number)
    {
        return Err(ToolError::failed("invalid_notification_page"));
    }
    if let Some(number) = number {
        if page.threads.len() > 1
            || page.threads.iter().any(|t| t.number != number)
            || page.next_after.is_some()
        {
            return Err(ToolError::failed("invalid_notification_page"));
        }
    } else if page.threads.len() > usize::from(limit)
        || page.threads.iter().any(|t| {
            t.number.get() <= after
                || (unread && !t.unread)
                || (!muted && t.mode == NotificationMode::Muted)
        })
        || page.next_after.is_some_and(|next| {
            page.threads.len() != usize::from(limit)
                || page.threads.last().map(|t| t.number.get()) != Some(next)
        })
    {
        return Err(ToolError::failed("invalid_notification_page"));
    }
    Ok(())
}
#[cfg(test)]
mod tests;
