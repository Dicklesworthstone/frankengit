//! Self inbox reads and preferences, with independent notification write grants.
use super::mutations as common;
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::event::notification::{
    NotificationAction, NotificationCommand, NotificationMode, NotificationTarget,
    NotificationTargetKind,
};
use fgit_forge::{AggregateVersion, DiscussionNumber, ExpectedVersion, IssueNumber};
use fgit_node::{
    NotificationInboxPage, NotificationReadRefusal, NotificationThreadState, NotificationThreadView,
};

pub(super) fn read_permitted(options: &Options) -> bool {
    (options.issues || options.discussions)
        && options.principal.is_some()
        && options.incarnation.is_some()
}
fn read_kind_permitted(options: &Options, kind: NotificationTargetKind) -> bool {
    read_permitted(options)
        && match kind {
            NotificationTargetKind::Issue => options.issues,
            NotificationTargetKind::Discussion => options.discussions,
        }
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
    [("frankengit_inbox_list", "Read your issue or discussion inbox. Optional kind defaults to issue and requires that kind's independent read grant. Reasons, read state and preferences derive from one exact canonical source. Continue with the original snapshot token and unchanged kind/filters. Launch identity owns the recipient.", false),
     ("frankengit_inbox_show", "Read your preferences and activity for one issue or discussion, including an unfollowed thread. Optional kind defaults to issue and requires that kind's read grant plus launch-bound principal/incarnation. Reading does not acknowledge activity.", true)]
        .into_iter().map(|(name, description, show)| Tool { name, description, schema: read_schema(show) }).collect()
}
pub(super) fn write_tools() -> Vec<Tool> {
    [("frankengit_inbox_subscribe", "Subscribe yourself to an issue or discussion with notification-write plus the selected kind's read grant. Kind defaults to issue. Preference version zero creates your separate stream; preserve kind, number, predecessor and durable key on retry."),
     ("frankengit_inbox_mute", "Mute your issue or discussion notifications at the exact preference version, preserving read state. Requires notification-write plus the selected kind's read grant; kind defaults to issue. No content or other recipient changes."),
     ("frankengit_inbox_automatic", "Restore author/participant selection, and assignee selection for issues, at the exact preference version while preserving read state. Requires notification-write plus the selected kind's read grant; kind defaults to issue."),
     ("frankengit_inbox_read", "Mark your explicit observed issue or discussion prefix read, using positive read_through and exact preference version. Later activity stays unread. Requires notification-write plus the selected kind's read grant; kind defaults to issue. Preserve the original durable key."),
     ("frankengit_inbox_unread", "Clear your read prefix at the exact preference version, preserving delivery mode. Requires notification-write plus the selected kind's read grant; kind defaults to issue. Retry the identical command and original key.")]
        .into_iter().map(|(name, description)| {
            let mut properties = common::base_properties();
            properties.insert("kind".into(), kind_schema());
            let mut required = vec!["number", "expected_version", "idempotency_key"];
            if name == "frankengit_inbox_read" { properties.insert("read_through".into(), decimal_schema()); required.push("read_through"); }
            Tool { name, description, schema: common::input_schema(properties, &required) }
        }).collect()
}
fn kind_schema() -> Value {
    object([
        ("type", text("string")),
        (
            "enum",
            Value::Array(vec![text("issue"), text("discussion")]),
        ),
        ("default", text("issue")),
        ("maxLength", json::number(10)),
        (
            "description",
            text("Thread domain; requires its own issue or discussion read grant."),
        ),
    ])
}
fn kind(args: &Object) -> Result<NotificationTargetKind, ToolError> {
    match string(args, "kind")?.unwrap_or("issue") {
        "issue" => Ok(NotificationTargetKind::Issue),
        "discussion" => Ok(NotificationTargetKind::Discussion),
        _ => Err(ToolError::invalid("invalid_notification_kind")),
    }
}
fn target(args: &Object, kind: NotificationTargetKind) -> Result<NotificationTarget, ToolError> {
    let number = common::number(args, "number")?;
    match kind {
        NotificationTargetKind::Issue => IssueNumber::try_new(number)
            .map(NotificationTarget::Issue)
            .ok_or(ToolError::invalid("positive_issue_number_required")),
        NotificationTargetKind::Discussion => DiscussionNumber::try_new(number)
            .map(NotificationTarget::Discussion)
            .ok_or(ToolError::invalid("positive_discussion_number_required")),
    }
}
fn read_schema(show: bool) -> Value {
    let mut properties = Object::new();
    properties.insert("kind".into(), kind_schema());
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
                "kind",
            ]
        } else {
            &["number", "expected_version", "idempotency_key", "kind"]
        },
    )?;
    let target = target(args, kind(args)?)?;
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
        target,
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
    if !read_kind_permitted(&backend.options, command.target.kind()) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
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
    result.insert(
        "type".into(),
        text(match command.target.kind() {
            NotificationTargetKind::Issue => "notification_publication",
            NotificationTargetKind::Discussion => "discussion_notification_publication",
        }),
    );
    if command.target.kind() == NotificationTargetKind::Discussion {
        result.insert("target_kind".into(), text("discussion"));
    }
    result.insert("number".into(), text(command.target.number().to_string()));
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
        ("number", text(row.target.number().to_string())),
        (
            match row.target.kind() {
                NotificationTargetKind::Issue => "issue_version",
                NotificationTargetKind::Discussion => "discussion_version",
            },
            text(row.thread_version.get().to_string()),
        ),
        ("title", text(row.title.clone())),
        (
            "state",
            text(match row.state {
                NotificationThreadState::Open => "open",
                NotificationThreadState::Closed => "closed",
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
            &["number", "expected_head", "kind"]
        } else {
            &[
                "after",
                "limit",
                "expected_head",
                "unread_only",
                "include_muted",
                "kind",
            ]
        },
    )?;
    let kind = kind(args)?;
    if !read_kind_permitted(&backend.options, kind) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
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
    let target = if show {
        Some(target(args, kind)?)
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
    let page = if let Some(target) = target {
        backend.node.runtime().block_on(
            backend
                .node
                .read_notification_target_in(&request, &session, target, expected),
        )
    } else {
        backend
            .node
            .runtime()
            .block_on(backend.node.read_notification_inbox_for_kind_in(
                &request,
                &session,
                kind,
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
        kind,
        target,
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
            text(match (kind, show) {
                (NotificationTargetKind::Issue, true) => "notification_thread",
                (NotificationTargetKind::Issue, false) => "notification_inbox",
                (NotificationTargetKind::Discussion, true) => "discussion_notification_thread",
                (NotificationTargetKind::Discussion, false) => "discussion_notification_inbox",
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
    if kind == NotificationTargetKind::Discussion {
        result.insert("target_kind".into(), text("discussion"));
    }
    if let Some(target) = target {
        result.insert("number".into(), text(target.number().to_string()));
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
    kind: NotificationTargetKind,
    target: Option<NotificationTarget>,
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
        || binding.kind.name() != kind.name()
        || expected.is_some_and(|head| head != binding.authority_head)
        || page.kind != kind
        || page
            .threads
            .iter()
            .any(|thread| thread.target.kind() != kind)
        || page
            .threads
            .windows(2)
            .any(|p| p[0].target.number() >= p[1].target.number())
    {
        return Err(ToolError::failed("invalid_notification_page"));
    }
    if let Some(target) = target {
        if page.threads.len() > 1
            || page.threads.iter().any(|t| t.target != target)
            || page.next_after.is_some()
        {
            return Err(ToolError::failed("invalid_notification_page"));
        }
    } else if page.threads.len() > usize::from(limit)
        || page.threads.iter().any(|t| {
            t.target.number() <= after
                || (unread && !t.unread)
                || (!muted && t.mode == NotificationMode::Muted)
        })
        || page.next_after.is_some_and(|next| {
            page.threads.len() != usize::from(limit)
                || page.threads.last().map(|t| t.target.number()) != Some(next)
        })
    {
        return Err(ToolError::failed("invalid_notification_page"));
    }
    Ok(())
}
#[cfg(test)]
mod tests;
