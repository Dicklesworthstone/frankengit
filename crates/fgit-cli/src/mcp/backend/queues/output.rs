//! Complete bounded snapshots and original terminal receipts, never inferred state.
use std::collections::BTreeSet;

use fgit_admission::merge::native::queue::QueuePage;
use fgit_authority::TerminalOutcome;
use fgit_forge::ExpectedVersion;
use fgit_forge::event::queue::MAX_QUEUE_ENTRIES;
use fgit_forge::merge_queue::{DequeueReason, MergeQueueSnapshot, QueueCommandAction};
use fgit_node::QueueRead;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, PrincipalId, RefName, RepositoryAuthorityHeadId, TxId,
};

use super::super::super::json::{self, text};
use super::super::hex;
use super::*;

fn reference(fields: &mut Object, name: &str, value: &RefName) {
    fields.insert(
        name.into(),
        std::str::from_utf8(value.as_bytes()).map_or(Value::Null, text),
    );
    fields.insert(format!("{name}_hex"), text(hex(value.as_bytes())));
}
fn bounded(value: Value) -> Result<Value, ToolError> {
    value
        .encode(MAX_RESPONSE)
        .map_err(|_| ToolError::failed("queue_response_limit"))?;
    Ok(value)
}
fn header(
    backend: &NodeTools,
    head: RepositoryAuthorityHeadId,
    expected: Option<RepositoryAuthorityHeadId>,
) -> Result<Object, ToolError> {
    if expected.is_some_and(|expected| expected != head) {
        return Err(ToolError::failed("snapshot_unavailable"));
    }
    let mut fields = backend.header(head);
    fields.insert("schema_version".into(), json::number(1));
    fields.insert("source_head".into(), text(head.to_string()));
    Ok(fields)
}
fn queue(value: &MergeQueueSnapshot, format: GitHashAlgorithm) -> Result<Value, ToolError> {
    if value.entries.len() > MAX_QUEUE_ENTRIES
        || !value.target_ref.as_bytes().starts_with(b"refs/heads/")
    {
        return Err(ToolError::failed("invalid_queue_state"));
    }
    let mut fields = Object::new();
    fields.insert("number".into(), text(value.queue_number.get().to_string()));
    fields.insert("version".into(), text(value.version.get().to_string()));
    reference(&mut fields, "target_reference", &value.target_ref);
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut available = MAX_RESPONSE;
    for entry in &value.entries {
        if !seen.insert(entry.pull_request)
            || entry.source_ref == value.target_ref
            || !entry.source_ref.as_bytes().starts_with(b"refs/heads/")
            || entry.head_tip.is_zero()
            || entry.head_tip.algorithm() != format
            || entry.enqueued_version > value.version
        {
            return Err(ToolError::failed("invalid_queue_state"));
        }
        let mut row = Object::new();
        row.insert(
            "pull_request".into(),
            text(entry.pull_request.get().to_string()),
        );
        reference(&mut row, "source_reference", &entry.source_ref);
        row.insert("head_tip".into(), text(entry.head_tip.to_string()));
        row.insert("enqueued_by".into(), text(entry.enqueued_by.to_string()));
        row.insert("priority".into(), text(entry.priority.to_string()));
        row.insert(
            "enqueued_version".into(),
            text(entry.enqueued_version.get().to_string()),
        );
        let row = Value::Object(row);
        let encoded = row
            .encode(available)
            .map_err(|_| ToolError::failed("queue_response_limit"))?;
        available = available
            .checked_sub(encoded.len())
            .ok_or(ToolError::failed("queue_response_limit"))?;
        entries.push(row);
    }
    fields.insert("entries".into(), Value::Array(entries));
    fields.insert(
        "order".into(),
        Value::Array(
            value
                .deterministic_order()
                .iter()
                .map(|n| text(n.get().to_string()))
                .collect(),
        ),
    );
    fields.insert(
        "active_batch".into(),
        value
            .active_batch
            .as_ref()
            .map_or(Value::Null, |id| text(id.to_hex())),
    );
    bounded(Value::Object(fields))
}

pub(super) fn show(
    backend: &NodeTools,
    number: QueueNumber,
    expected: Option<RepositoryAuthorityHeadId>,
    selected: &QueueRead,
) -> Result<Value, ToolError> {
    if selected
        .queue
        .as_ref()
        .is_some_and(|queue| queue.queue_number != number)
    {
        return Err(ToolError::failed("invalid_queue_state"));
    }
    let mut fields = header(backend, selected.source_head, expected)?;
    fields.insert("type".into(), text("merge_queue"));
    fields.insert("number".into(), text(number.get().to_string()));
    fields.insert(
        "version".into(),
        text(
            selected
                .queue
                .as_ref()
                .map_or(0, |queue| queue.version.get())
                .to_string(),
        ),
    );
    fields.insert("found".into(), Value::Bool(selected.queue.is_some()));
    fields.insert(
        "queue".into(),
        selected
            .queue
            .as_ref()
            .map(|value| queue(value, backend.options.format))
            .transpose()?
            .unwrap_or(Value::Null),
    );
    fields.insert("complete".into(), Value::Bool(true));
    bounded(Value::Object(fields))
}

pub(super) fn list(
    backend: &NodeTools,
    after: u64,
    limit: u16,
    expected: Option<RepositoryAuthorityHeadId>,
    selected: &QueuePage,
) -> Result<Value, ToolError> {
    if selected.queues.len() > usize::from(limit)
        || selected
            .queues
            .iter()
            .any(|queue| queue.queue_number.get() <= after)
        || selected
            .queues
            .windows(2)
            .any(|pair| pair[0].queue_number >= pair[1].queue_number)
        || selected.next_after.is_some_and(|next| {
            selected.queues.len() != usize::from(limit)
                || selected.queues.last().map(|queue| queue.queue_number.get()) != Some(next)
        })
    {
        return Err(ToolError::failed("invalid_queue_page"));
    }
    let mut fields = header(backend, selected.source_head, expected)?;
    let mut queues = Vec::new();
    let mut available = MAX_RESPONSE;
    for value in &selected.queues {
        let value = queue(value, backend.options.format)?;
        let encoded = value
            .encode(available)
            .map_err(|_| ToolError::failed("queue_response_limit"))?;
        available = available
            .checked_sub(encoded.len())
            .ok_or(ToolError::failed("queue_response_limit"))?;
        queues.push(value);
    }
    fields.insert("type".into(), text("merge_queue_page"));
    fields.insert("after".into(), text(after.to_string()));
    fields.insert("limit".into(), json::number(u64::from(limit)));
    fields.insert("queues".into(), Value::Array(queues));
    fields.insert(
        "next_after".into(),
        selected
            .next_after
            .map_or(Value::Null, |next| text(next.to_string())),
    );
    fields.insert(
        "complete".into(),
        Value::Bool(selected.next_after.is_none()),
    );
    bounded(Value::Object(fields))
}

fn reason(value: DequeueReason) -> &'static str {
    match value {
        DequeueReason::Withdrawn => "withdrawn",
        DequeueReason::Conflict => "conflict",
        DequeueReason::CheckFailed => "check-failed",
        DequeueReason::BaseMoved => "base-moved",
        DequeueReason::Evicted => "evicted",
        DequeueReason::AdminOverride => "admin-override",
    }
}
fn action(command: &Command) -> (Object, &'static str) {
    let mut fields = Object::new();
    let name = match command {
        Command::Management(command) => match &command.action {
            QueueCommandAction::Enqueue {
                pull_request,
                expected_pull_request_version,
                source_ref,
                head_tip,
                expected_target_tip,
                priority,
            } => {
                fields.insert("pull_request".into(), text(pull_request.get().to_string()));
                fields.insert(
                    "expected_pull_request_version".into(),
                    text(expected_pull_request_version.get().to_string()),
                );
                reference(&mut fields, "source_reference", source_ref);
                fields.insert("expected_source".into(), text(head_tip.to_string()));
                fields.insert(
                    "expected_target".into(),
                    text(expected_target_tip.to_string()),
                );
                fields.insert("priority".into(), text(priority.to_string()));
                "enqueue"
            }
            QueueCommandAction::Dequeue {
                pull_request,
                reason: cause,
            } => {
                fields.insert("pull_request".into(), text(pull_request.get().to_string()));
                fields.insert("reason".into(), text(reason(*cause)));
                "dequeue"
            }
            QueueCommandAction::Reorder { order } => {
                fields.insert(
                    "order".into(),
                    Value::Array(order.iter().map(|n| text(n.get().to_string())).collect()),
                );
                "reorder"
            }
        },
        Command::Landing(command) => {
            fields.insert("method".into(), text("fast-forward-only"));
            fields.insert(
                "pull_request".into(),
                text(command.pull_request.get().to_string()),
            );
            fields.insert(
                "expected_pull_request_version".into(),
                text(command.expected_pull_request_version.get().to_string()),
            );
            fields.insert(
                "expected_policy_epoch".into(),
                text(command.expected_policy_epoch.get().to_string()),
            );
            reference(&mut fields, "source_reference", &command.source_ref);
            fields.insert("expected_source".into(), text(command.head_tip.to_string()));
            fields.insert(
                "expected_target".into(),
                text(command.expected_target_tip.to_string()),
            );
            "land"
        }
    };
    fields.insert("name".into(), text(name));
    (fields, name)
}
pub(super) fn publication(
    backend: &NodeTools,
    principal: PrincipalId,
    command: &Command,
    tx: TxId,
    terminal: &TerminalOutcome,
) -> Value {
    let (number, version, target, moves_ref) = match command {
        Command::Management(command) => (
            command.number,
            match command.expected_version {
                ExpectedVersion::NewStream => 0,
                ExpectedVersion::Exactly(version) => version.get(),
            },
            &command.target_ref,
            false,
        ),
        Command::Landing(command) => (
            command.number,
            command.expected_version.get(),
            &command.target_ref,
            command.head_tip != command.expected_target_tip,
        ),
    };
    let (proposed, name) = action(command);
    let mut fields = common::binding(backend, principal, false);
    fields.extend(common::terminal(tx, terminal));
    fields.insert("type".into(), text("merge_queue_publication"));
    fields.insert("number".into(), text(number.get().to_string()));
    fields.insert("expected_version".into(), text(version.to_string()));
    reference(&mut fields, "target_reference", target);
    fields.insert("action".into(), text(name));
    fields.insert("proposed_action".into(), Value::Object(proposed));
    fields.insert("complete".into(), Value::Bool(true));
    fields.insert(
        "refs_changed".into(),
        Value::Bool(moves_ref && matches!(terminal.outcome, DecisionOutcome::Committed { .. })),
    );
    fields.insert("delivery_acknowledged".into(), Value::Null);
    fields.insert("historical_outcome".into(), Value::Bool(true));
    Value::Object(fields)
}
