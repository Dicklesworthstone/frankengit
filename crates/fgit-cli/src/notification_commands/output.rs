//! Bounded JSON preserves every u64 position as a decimal string.
use super::options::{Mutation, Options, ReadOptions, action_name};
use crate::issues::options::head_token;
use fgit_authority::TerminalOutcome;
use fgit_forge::event::{issue::IssueState, notification::NotificationAction};
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_node::{NotificationInboxPage, NotificationThreadView};
use fgit_schema::json::{self, Object, Value, object, text};
use fgit_types::{DecisionOutcome, RepositoryIncarnationId, TxId};
const MAX_REPLY_BYTES: usize = 1024 * 1024;
fn optional(value: Option<u64>) -> Value {
    value.map_or(Value::Null, |v| text(v.to_string()))
}
fn fields(value: Value) -> Object {
    match value {
        Value::Object(v) => v,
        _ => unreachable!(),
    }
}
fn thread(value: &NotificationThreadView) -> Value {
    object([
        ("number", text(value.number.get().to_string())),
        ("issue_version", text(value.issue_version.get().to_string())),
        ("title", text(value.title.clone())),
        (
            "state",
            text(match value.state {
                IssueState::Open => "open",
                IssueState::Closed => "closed",
            }),
        ),
        (
            "preference_version",
            optional(value.preference_version.map(AggregateVersion::get)),
        ),
        ("mode", text(value.mode.name())),
        (
            "read_through",
            optional(value.read_through.map(AggregateVersion::get)),
        ),
        (
            "latest_other_version",
            optional(value.latest_other_version.map(AggregateVersion::get)),
        ),
        (
            "reasons",
            Value::Array(
                value
                    .reasons
                    .iter()
                    .map(|reason| text(reason.as_str()))
                    .collect(),
            ),
        ),
        ("unread", Value::Bool(value.unread)),
    ])
}
pub(super) fn page(
    options: &Options,
    read: &ReadOptions,
    page: &NotificationInboxPage,
) -> Result<(String, u8), String> {
    let binding = &page.binding;
    if binding.tenant != options.tenant
        || binding.repository != options.repository
        || binding.principal != options.principal
        || options
            .incarnation
            .is_some_and(|id| id != binding.incarnation)
        || read
            .expected_head
            .is_some_and(|head| head != binding.authority_head)
        || page.threads.windows(2).any(|p| p[0].number >= p[1].number)
    {
        return Err("inbox response does not match its identity or snapshot binding".into());
    }
    if let Some(number) = read.number {
        if page.threads.len() > 1
            || page.threads.iter().any(|t| t.number != number)
            || page.next_after.is_some()
        {
            return Err("inbox thread lookup returned another issue or a continuation".into());
        }
    } else if page.threads.len() > usize::from(read.limit)
        || page.threads.iter().any(|t| {
            t.number.get() <= read.after
                || (read.unread_only && !t.unread)
                || (!read.include_muted
                    && t.mode == fgit_forge::event::notification::NotificationMode::Muted)
        })
        || page.next_after.is_some_and(|next| {
            page.threads.len() != usize::from(read.limit)
                || page.threads.last().map(|t| t.number.get()) != Some(next)
        })
    {
        return Err("inbox response violates its requested page or filters".into());
    }
    let mut out = fields(object([
        (
            "type",
            text(if read.number.is_some() {
                "notification_thread"
            } else {
                "notification_inbox"
            }),
        ),
        ("schema_version", json::number(1)),
        ("tenant_id", text(binding.tenant.to_string())),
        ("repository_id", text(binding.repository.to_string())),
        (
            "repository_incarnation",
            text(binding.incarnation.to_string()),
        ),
        ("principal_id", text(binding.principal.to_string())),
        ("object_format", text(options.format.as_str())),
        ("source_head", text(binding.authority_head.to_string())),
        ("snapshot_token", text(head_token(binding.authority_head))),
        (
            "source_generation",
            text(binding.authority_head_generation.to_string()),
        ),
        (
            "forge_position_root",
            text(binding.forge_position_root.to_string()),
        ),
        ("outbox_root", text(binding.outbox_root.to_string())),
        (
            "threads",
            Value::Array(page.threads.iter().map(thread).collect()),
        ),
        ("next_after", optional(page.next_after)),
        ("complete", Value::Bool(page.next_after.is_none())),
        ("read_only", Value::Bool(true)),
        ("node_closed", Value::Bool(true)),
    ]));
    if let Some(number) = read.number {
        out.insert("number".into(), text(number.get().to_string()));
        out.insert("found".into(), Value::Bool(!page.threads.is_empty()));
    } else {
        out.insert("after".into(), text(read.after.to_string()));
        out.insert("limit".into(), json::number(u64::from(read.limit)));
        out.insert("unread_only".into(), Value::Bool(read.unread_only));
        out.insert("include_muted".into(), Value::Bool(read.include_muted));
    }
    Ok((
        Value::Object(out)
            .encode(MAX_REPLY_BYTES)
            .map_err(str::to_owned)?,
        if read.number.is_some() && page.threads.is_empty() {
            4
        } else {
            0
        },
    ))
}
pub(super) fn mutation(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    mutation: &Mutation,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> Result<String, String> {
    let (outcome, committed, rcr, refusal, code) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            true,
            text(repository_commit_id.to_string()),
            Value::Null,
            Value::Null,
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            false,
            Value::Null,
            text(refusal_record_id.to_string()),
            text(format!("{code:?}")),
        ),
    };
    let before = match mutation.command.expected_version {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(v) => v.get(),
    };
    let mut out = fields(object([
        ("type", text("notification_publication")),
        ("schema_version", json::number(1)),
        ("tenant_id", text(options.tenant.to_string())),
        ("repository_id", text(options.repository.to_string())),
        ("repository_incarnation", text(incarnation.to_string())),
        ("principal_id", text(options.principal.to_string())),
        ("object_format", text(options.format.as_str())),
        ("number", text(mutation.command.number.get().to_string())),
        ("expected_version", text(before.to_string())),
        ("action", text(action_name(mutation.command.action))),
        ("tx_id", text(tx.to_string())),
        (
            "decision_sequence",
            text(terminal.decision_sequence.get().to_string()),
        ),
        ("outcome", text(outcome)),
        ("command_committed", Value::Bool(committed)),
        ("repository_commit_id", rcr),
        ("refusal_record_id", refusal),
        ("refusal_code", code),
        ("terminal", Value::Bool(true)),
        ("outcome_unknown", Value::Bool(false)),
        ("historical_outcome", Value::Bool(true)),
        ("refs_changed", Value::Bool(false)),
        ("read_only", Value::Bool(false)),
        ("delivery_acknowledged", Value::Null),
        ("node_closed", Value::Bool(cleanup.is_none())),
        ("cleanup_error", cleanup.map_or(Value::Null, text)),
    ]));
    match mutation.command.action {
        NotificationAction::SetMode(mode) => {
            out.insert("requested_mode".into(), text(mode.name()));
        }
        NotificationAction::SetReadThrough(through) => {
            out.insert(
                "requested_read_through".into(),
                optional(through.map(AggregateVersion::get)),
            );
        }
    }
    Value::Object(out).encode(MAX_REPLY_BYTES).map_err(|error| {
        format!(
            "{}; committed/refused inbox receipt could not be encoded: {error}",
            crate::publication_support::describe(tx, terminal)
        )
    })
}
