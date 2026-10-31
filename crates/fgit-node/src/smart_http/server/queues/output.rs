//! Complete bounded queue JSON and immutable terminal receipts.
use std::collections::BTreeSet;

use fgit_admission::merge::native::queue::{
    QueueCandidateLandingCommand, QueueLandingCommand, QueuePage,
};
use fgit_authority::TerminalOutcome;
use fgit_forge::event::queue::MAX_QUEUE_ENTRIES;
use fgit_forge::merge_queue::{
    DequeueReason, MergeQueueSnapshot, QueueCommand, QueueCommandAction,
};
use fgit_forge::{ExpectedVersion, QueueNumber};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, RepositoryAuthorityHeadId, TxId};

use super::super::issues::{ApiError, Page, quote, ref_fields};
use crate::OneNode;
use crate::treefs_workspace::QueueRead;

fn append(out: &mut String, text: &str, maximum: usize) -> Result<(), ApiError> {
    if out
        .len()
        .checked_add(text.len())
        .is_none_or(|size| size > maximum)
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(text.len())
        .map_err(|_| ApiError::unavailable())?;
    out.push_str(text);
    Ok(())
}

fn scope(node: &OneNode) -> String {
    format!(
        "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{}",
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str())
    )
}

fn header(
    node: &OneNode,
    head: RepositoryAuthorityHeadId,
    expected: Option<RepositoryAuthorityHeadId>,
) -> Result<String, ApiError> {
    if expected.is_some_and(|expected| expected != head) {
        return Err(ApiError::snapshot_moved());
    }
    let id = head.as_internal_object_id();
    let digest: String = id
        .digest()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!(
        "{},\"source_head\":{},\"snapshot_token\":{}",
        scope(node),
        quote(&head.to_string()),
        quote(&format!("alg:{}:{digest}", id.algorithm().code_point()))
    ))
}

fn snapshot(
    queue: &MergeQueueSnapshot,
    format: GitHashAlgorithm,
    maximum: usize,
) -> Result<String, ApiError> {
    if queue.entries.len() > MAX_QUEUE_ENTRIES
        || !queue.target_ref.as_bytes().starts_with(b"refs/heads/")
    {
        return Err(ApiError::unavailable());
    }
    let mut result = String::new();
    append(
        &mut result,
        &format!(
            "{{\"number\":{},{},\"version\":{},\"entries\":[",
            queue.queue_number.get(),
            ref_fields("target_ref", &queue.target_ref),
            queue.version.get()
        ),
        maximum,
    )?;
    let mut seen = BTreeSet::new();
    for (index, entry) in queue.entries.iter().enumerate() {
        if !seen.insert(entry.pull_request)
            || !entry.source_ref.as_bytes().starts_with(b"refs/heads/")
            || entry.source_ref == queue.target_ref
            || entry.head_tip.is_zero()
            || entry.head_tip.algorithm() != format
            || entry.enqueued_version > queue.version
        {
            return Err(ApiError::unavailable());
        }
        if index != 0 {
            append(&mut result, ",", maximum)?;
        }
        append(
            &mut result,
            &format!(
                "{{\"pull_request\":{},{},\"head_tip\":{},\"enqueued_by\":{},\"priority\":{},\"enqueued_version\":{}}}",
                entry.pull_request.get(),
                ref_fields("source_ref", &entry.source_ref),
                quote(&entry.head_tip.to_string()),
                quote(&entry.enqueued_by.to_string()),
                entry.priority,
                entry.enqueued_version.get()
            ),
            maximum,
        )?;
    }
    let order = queue
        .deterministic_order()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    append(
        &mut result,
        &format!(
            "],\"order\":[{order}],\"active_batch\":{}}}",
            queue
                .active_batch
                .as_ref()
                .map_or_else(|| "null".into(), |batch| quote(&batch.to_hex()))
        ),
        maximum,
    )?;
    Ok(result)
}

pub(super) fn list(
    node: &OneNode,
    page: Page,
    result: &QueuePage,
    maximum: usize,
) -> Result<String, ApiError> {
    if result.queues.len() > usize::from(page.limit)
        || result
            .queues
            .iter()
            .any(|queue| queue.queue_number.get() <= page.after)
        || result
            .queues
            .windows(2)
            .any(|rows| rows[0].queue_number >= rows[1].queue_number)
        || result.next_after.is_some_and(|next| {
            result.queues.len() != usize::from(page.limit)
                || result.queues.last().map(|queue| queue.queue_number.get()) != Some(next)
        })
    {
        return Err(ApiError::unavailable());
    }
    let mut body = String::new();
    append(
        &mut body,
        &format!(
            "{{\"type\":\"merge_queue_page\",{},\"after\":{},\"limit\":{},\"next_after\":{},\"queues\":[",
            header(node, result.source_head, page.expected_head)?,
            page.after,
            page.limit,
            result
                .next_after
                .map_or_else(|| "null".into(), |next| next.to_string())
        ),
        maximum,
    )?;
    for (index, queue) in result.queues.iter().enumerate() {
        if index != 0 {
            append(&mut body, ",", maximum)?;
        }
        append(
            &mut body,
            &snapshot(queue, node.object_format, maximum)?,
            maximum,
        )?;
    }
    append(&mut body, "],\"complete\":true}", maximum)?;
    Ok(body)
}

pub(super) fn show(
    node: &OneNode,
    number: QueueNumber,
    expected: Option<RepositoryAuthorityHeadId>,
    result: &QueueRead,
    maximum: usize,
) -> Result<String, ApiError> {
    if result
        .queue
        .as_ref()
        .is_some_and(|queue| queue.queue_number != number)
    {
        return Err(ApiError::unavailable());
    }
    let queue = result
        .queue
        .as_ref()
        .map(|queue| snapshot(queue, node.object_format, maximum))
        .transpose()?
        .unwrap_or_else(|| "null".into());
    let mut body = String::new();
    append(
        &mut body,
        &format!(
            "{{\"type\":\"merge_queue\",{},\"number\":{},\"found\":{},\"version\":{},\"queue\":{},\"complete\":true}}",
            header(node, result.source_head, expected)?,
            number.get(),
            result.queue.is_some(),
            result.queue.as_ref().map_or(0, |queue| queue.version.get()),
            queue
        ),
        maximum,
    )?;
    Ok(body)
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

fn action(command: &QueueCommandAction) -> String {
    match command {
        QueueCommandAction::Enqueue {
            pull_request,
            expected_pull_request_version,
            source_ref,
            head_tip,
            expected_target_tip,
            priority,
        } => format!(
            "{{\"name\":\"enqueue\",\"pull_request\":{},\"expected_pull_request_version\":{},{},\"expected_source_tip\":{},\"expected_target_tip\":{},\"priority\":{}}}",
            pull_request.get(),
            expected_pull_request_version.get(),
            ref_fields("source_ref", source_ref),
            quote(&head_tip.to_string()),
            quote(&expected_target_tip.to_string()),
            priority
        ),
        QueueCommandAction::Dequeue {
            pull_request,
            reason: cause,
        } => format!(
            "{{\"name\":\"dequeue\",\"pull_request\":{},\"reason\":{}}}",
            pull_request.get(),
            quote(reason(*cause))
        ),
        QueueCommandAction::Reorder { order } => format!(
            "{{\"name\":\"reorder\",\"order\":[{}]}}",
            order
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

pub(super) fn mutation(
    node: &OneNode,
    principal: PrincipalId,
    command: &QueueCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> String {
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
    let version = match command.expected_version {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(v) => v.get(),
    };
    format!(
        concat!(
            "{{\"type\":\"merge_queue_publication\",{},\"principal_id\":{},\"number\":{},{},\"expected_version\":{},",
            "\"proposed_action\":{},\"tx_id\":{},\"decision_sequence\":{},\"outcome\":{},\"committed\":{},",
            "\"repository_commit_id\":{},\"refusal_record_id\":{},\"refusal_code\":{},",
            "\"refs_changed\":false,\"delivery_acknowledged\":null,\"historical_outcome\":true,\"complete\":true}}"
        ),
        scope(node),
        quote(&principal.to_string()),
        command.number.get(),
        ref_fields("target_ref", &command.target_ref),
        version,
        action(&command.action),
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        quote(outcome),
        committed,
        record,
        refusal,
        code
    )
}

pub(super) fn landing(
    node: &OneNode,
    principal: PrincipalId,
    command: &QueueLandingCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> String {
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
    format!(
        concat!(
            "{{\"type\":\"merge_queue_publication\",{},\"principal_id\":{},\"number\":{},{},\"expected_version\":{},",
            "\"proposed_action\":{{\"name\":\"land\",\"method\":\"fast-forward-only\",\"pull_request\":{},",
            "\"expected_pull_request_version\":{},\"expected_policy_epoch\":{},{},",
            "\"expected_source_tip\":{},\"expected_target_tip\":{}}},",
            "\"tx_id\":{},\"decision_sequence\":{},\"outcome\":{},\"committed\":{},",
            "\"repository_commit_id\":{},\"refusal_record_id\":{},\"refusal_code\":{},",
            "\"refs_changed\":{},\"delivery_acknowledged\":null,\"historical_outcome\":true,\"complete\":true}}"
        ),
        scope(node),
        quote(&principal.to_string()),
        command.number.get(),
        ref_fields("target_ref", &command.target_ref),
        command.expected_version.get(),
        command.pull_request.get(),
        command.expected_pull_request_version.get(),
        command.expected_policy_epoch.get(),
        ref_fields("source_ref", &command.source_ref),
        quote(&command.head_tip.to_string()),
        quote(&command.expected_target_tip.to_string()),
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        quote(outcome),
        committed,
        record,
        refusal,
        code,
        committed
    )
}

pub(super) fn candidate_landing(
    node: &OneNode,
    principal: PrincipalId,
    command: &QueueCandidateLandingCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> String {
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
    let merge = &command.merge;
    format!(
        concat!(
            "{{\"type\":\"merge_queue_publication\",{},\"principal_id\":{},\"number\":{},{},\"expected_version\":{},",
            "\"proposed_action\":{{\"name\":\"land-candidate\",\"method\":\"merge-commit\",\"pull_request\":{},",
            "\"expected_pull_request_version\":{},\"expected_policy_epoch\":{},{},",
            "\"expected_source_tip\":{},\"expected_target_tip\":{},\"merge_base\":{},\"expected_commit\":{}}},",
            "\"tx_id\":{},\"decision_sequence\":{},\"outcome\":{},\"committed\":{},",
            "\"repository_commit_id\":{},\"refusal_record_id\":{},\"refusal_code\":{},",
            "\"refs_changed\":{},\"delivery_acknowledged\":null,\"historical_outcome\":true,\"complete\":true}}"
        ),
        scope(node),
        quote(&principal.to_string()),
        command.number.get(),
        ref_fields("target_ref", &merge.target_ref),
        command.expected_version.get(),
        command.pull_request.get(),
        command.expected_pull_request_version.get(),
        command.expected_policy_epoch.get(),
        ref_fields("source_ref", &merge.source_ref),
        quote(&merge.source_tip.to_string()),
        quote(&merge.target_tip_before.to_string()),
        quote(&merge.base_tip.to_string()),
        quote(&merge.merge_commit.to_string()),
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        quote(outcome),
        committed,
        record,
        refusal,
        code,
        committed
    )
}
