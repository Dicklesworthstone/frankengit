//! Complete bounded JSON snapshots and historical terminal decisions.
use super::options::{Operation, Options, head_token, hex, version};
use crate::publication_support::quote;
use fgit_admission::merge::native::queue::QueueLandingCommand;
use fgit_authority::TerminalOutcome;
use fgit_forge::QueueNumber;
use fgit_forge::event::queue::MAX_QUEUE_ENTRIES;
use fgit_forge::merge_queue::{DequeueReason, MergeQueueSnapshot, QueueCommandAction};
use fgit_types::{
    DecisionOutcome, RefName, RepositoryAuthorityHeadId, RepositoryIncarnationId, TxId,
};
use std::collections::BTreeSet;

const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;

fn scope(options: &Options, incarnation: RepositoryIncarnationId) -> String {
    format!(
        "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{}",
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(&incarnation.to_string()),
        quote(options.format.as_str()),
    )
}

fn reference(name: &RefName) -> String {
    std::str::from_utf8(name.as_bytes())
        .map(quote)
        .unwrap_or_else(|_| "null".into())
}

fn bounded(report: String) -> Result<String, String> {
    if report.len() > MAX_REPORT_BYTES {
        Err("queue response exceeds the 8 MiB complete-document limit".into())
    } else {
        Ok(report)
    }
}

fn snapshot(options: &Options, queue: &MergeQueueSnapshot) -> Result<String, String> {
    if queue.entries.len() > MAX_QUEUE_ENTRIES
        || !queue.target_ref.as_bytes().starts_with(b"refs/heads/")
    {
        return Err("invalid queue snapshot bounds or target".into());
    }
    let mut seen = BTreeSet::new();
    let mut entries = String::new();
    for entry in &queue.entries {
        if !seen.insert(entry.pull_request)
            || !entry.source_ref.as_bytes().starts_with(b"refs/heads/")
            || entry.source_ref == queue.target_ref
            || entry.head_tip.is_zero()
            || entry.head_tip.algorithm() != options.format
            || entry.enqueued_version > queue.version
        {
            return Err("invalid queue entry identity, format or version".into());
        }
        if !entries.is_empty() {
            entries.push(',');
        }
        entries.push_str(&format!(
            concat!(
                "{{\"pull_request\":{},\"source_ref\":{},\"source_ref_hex\":{},\"head_tip\":{},",
                "\"enqueued_by\":{},\"priority\":{},\"enqueued_version\":{}}}"
            ),
            entry.pull_request.get(),
            reference(&entry.source_ref),
            quote(&hex(entry.source_ref.as_bytes())),
            quote(&entry.head_tip.to_string()),
            quote(&entry.enqueued_by.to_string()),
            entry.priority,
            entry.enqueued_version.get(),
        ));
        if entries.len() > MAX_REPORT_BYTES {
            return Err("queue entries exceed the complete-document limit".into());
        }
    }
    let order = queue
        .deterministic_order()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    bounded(format!(
        concat!(
            "{{\"number\":{},\"target_ref\":{},\"target_ref_hex\":{},\"version\":{},",
            "\"entries\":[{}],\"order\":[{}],\"active_batch\":{}}}"
        ),
        queue.queue_number.get(),
        reference(&queue.target_ref),
        quote(&hex(queue.target_ref.as_bytes())),
        queue.version.get(),
        entries,
        order,
        queue
            .active_batch
            .as_ref()
            .map_or_else(|| "null".into(), |batch| quote(&batch.to_hex())),
    ))
}

pub(super) fn show(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    number: QueueNumber,
    head: RepositoryAuthorityHeadId,
    queue: Option<&MergeQueueSnapshot>,
) -> Result<String, String> {
    if queue.is_some_and(|queue| queue.queue_number != number) {
        return Err("queue response changed the requested queue number".into());
    }
    let rendered = queue
        .map(|queue| snapshot(options, queue))
        .transpose()?
        .unwrap_or_else(|| "null".into());
    bounded(format!(
        concat!(
            "{{\"type\":\"merge_queue\",{},\"number\":{},\"source_head\":{},\"snapshot_token\":{},",
            "\"found\":{},\"version\":{},\"queue\":{},\"complete\":true,\"node_closed\":true}}"
        ),
        scope(options, incarnation),
        number.get(),
        quote(&head.to_string()),
        quote(&head_token(head)),
        queue.is_some(),
        queue.map_or(0, |queue| queue.version.get()),
        rendered,
    ))
}

pub(super) fn list(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    head: RepositoryAuthorityHeadId,
    queues: &[MergeQueueSnapshot],
    next_after: Option<u64>,
) -> Result<String, String> {
    let Operation::List { after, limit, .. } = options.operation else {
        return Err("queue list result does not match its request".into());
    };
    if queues.len() > usize::from(limit)
        || queues
            .first()
            .is_some_and(|queue| queue.queue_number.get() <= after)
        || queues
            .windows(2)
            .any(|pair| pair[0].queue_number >= pair[1].queue_number)
        || next_after.is_some_and(|next| {
            queues
                .last()
                .is_none_or(|queue| queue.queue_number.get() != next)
        })
    {
        return Err("invalid queue page order, bounds or continuation".into());
    }
    let mut rendered = String::new();
    for queue in queues {
        let row = snapshot(options, queue)?;
        if rendered.len().saturating_add(row.len()).saturating_add(1) > MAX_REPORT_BYTES {
            return Err("queue page exceeds the complete-document limit; reduce --limit".into());
        }
        if !rendered.is_empty() {
            rendered.push(',');
        }
        rendered.push_str(&row);
    }
    bounded(format!(
        concat!(
            "{{\"type\":\"merge_queues\",{},\"source_head\":{},\"snapshot_token\":{},",
            "\"after\":{},\"limit\":{},\"queues\":[{}],\"next_after\":{},",
            "\"complete\":true,\"node_closed\":true}}"
        ),
        scope(options, incarnation),
        quote(&head.to_string()),
        quote(&head_token(head)),
        after,
        limit,
        rendered,
        next_after.map_or_else(|| "null".into(), |next| next.to_string()),
    ))
}

pub(super) const fn reason(value: DequeueReason) -> &'static str {
    match value {
        DequeueReason::Withdrawn => "withdrawn",
        DequeueReason::Conflict => "conflict",
        DequeueReason::CheckFailed => "check-failed",
        DequeueReason::BaseMoved => "base-moved",
        DequeueReason::Evicted => "evicted",
        DequeueReason::AdminOverride => "admin-override",
    }
}

fn action(value: &QueueCommandAction) -> String {
    match value {
        QueueCommandAction::Enqueue {
            pull_request,
            source_ref,
            head_tip,
            priority,
            expected_pull_request_version,
            expected_target_tip,
        } => format!(
            concat!(
                "{{\"name\":\"enqueue\",\"pull_request\":{},\"source_ref\":{},\"source_ref_hex\":{},",
                "\"head_tip\":{},\"priority\":{},\"expected_pull_request_version\":{},\"expected_target_tip\":{}}}"
            ),
            pull_request.get(),
            reference(source_ref),
            quote(&hex(source_ref.as_bytes())),
            quote(&head_tip.to_string()),
            priority,
            expected_pull_request_version.get(),
            quote(&expected_target_tip.to_string()),
        ),
        QueueCommandAction::Dequeue {
            pull_request,
            reason: cause,
        } => format!(
            "{{\"name\":\"dequeue\",\"pull_request\":{},\"reason\":{}}}",
            pull_request.get(),
            quote(reason(*cause)),
        ),
        QueueCommandAction::Reorder { order } => format!(
            "{{\"name\":\"reorder\",\"order\":[{}]}}",
            order
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
    }
}

fn landing_action(command: &QueueLandingCommand) -> String {
    format!(
        concat!(
            "{{\"name\":\"land\",\"method\":\"fast-forward-only\",\"pull_request\":{},",
            "\"expected_pull_request_version\":{},\"expected_policy_epoch\":{},",
            "\"source_ref\":{},\"source_ref_hex\":{},\"head_tip\":{},\"expected_target_tip\":{}}}"
        ),
        command.pull_request.get(),
        command.expected_pull_request_version.get(),
        command.expected_policy_epoch.get(),
        reference(&command.source_ref),
        quote(&hex(command.source_ref.as_bytes())),
        quote(&command.head_tip.to_string()),
        quote(&command.expected_target_tip.to_string()),
    )
}

pub(super) fn publication(
    options: &Options,
    incarnation: RepositoryIncarnationId,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> Result<String, String> {
    let (principal, number, target_ref, expected_version, proposed_action, moves_ref) =
        match &options.operation {
            Operation::Mutate {
                principal, command, ..
            } => (
                principal,
                command.number,
                &command.target_ref,
                version(command.expected_version),
                action(&command.action),
                false,
            ),
            Operation::Land {
                principal, command, ..
            } => (
                principal,
                command.number,
                &command.target_ref,
                command.expected_version.get(),
                landing_action(command),
                command.head_tip != command.expected_target_tip,
            ),
            _ => return Err("queue terminal result does not match its request".into()),
        };
    let (outcome, committed, record, refusal, code) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            true,
            quote(&repository_commit_id.to_string()),
            "null".into(),
            "null".into(),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            false,
            "null".into(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
        ),
    };
    bounded(format!(
        concat!(
            "{{\"type\":\"merge_queue_publication\",{},\"number\":{},\"principal_id\":{},",
            "\"target_ref\":{},\"target_ref_hex\":{},\"expected_version\":{},\"proposed_action\":{},",
            "\"tx_id\":{},\"decision_sequence\":{},\"outcome\":{},\"committed\":{},",
            "\"repository_commit_id\":{},\"refusal_record_id\":{},\"refusal_code\":{},",
            "\"refs_changed\":{},\"node_closed\":{},\"cleanup_error\":{}}}"
        ),
        scope(options, incarnation),
        number.get(),
        quote(&principal.to_string()),
        reference(target_ref),
        quote(&hex(target_ref.as_bytes())),
        expected_version,
        proposed_action,
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        quote(outcome),
        committed,
        record,
        refusal,
        code,
        committed && moves_ref,
        cleanup.is_none(),
        cleanup.map_or_else(|| "null".into(), quote),
    ))
}
