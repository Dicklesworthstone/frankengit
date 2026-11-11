//! Queue tools retain the launch-bound operator and the node's canonical keys.
//! Observation, membership management and landing are independent.
#[cfg(test)]
mod candidate_tests;
mod input;
#[cfg(test)]
mod integration_tests;
mod output;
#[cfg(test)]
mod refresh_tests;
mod schema;
#[cfg(test)]
mod tests;

use super::super::QueueGrants;
use super::super::json::{Object, Value};
use super::super::protocol::{Tool, ToolError};
use super::{NodeTools, decimal, head, limit, mutations as common, require_fields};
use fgit_admission::merge::native::queue::QueueCandidateLandingCommand;
use fgit_forge::QueueNumber;
use fgit_types::{GitHashAlgorithm, RepositoryIncarnationId};
use input::Command;

pub(super) const LIST: &str = "frankengit_queue_list";
pub(super) const SHOW: &str = "frankengit_queue_show";
pub(super) const ENQUEUE: &str = "frankengit_queue_enqueue";
pub(super) const DEQUEUE: &str = "frankengit_queue_dequeue";
pub(super) const REORDER: &str = "frankengit_queue_reorder";
pub(super) const REFRESH: &str = "frankengit_queue_refresh";
pub(super) const LAND: &str = "frankengit_queue_land";
pub(super) const LAND_CANDIDATE: &str = "frankengit_queue_land_candidate";
const MAX_RESPONSE: usize = 1024 * 1024;
// The ordinary MCP parser bounds every array at 256 items. Native queues can
// be larger; their complete reorder is available in the CLI/HTTP profiles.
const MAX_ORDER: usize = 256;
const MAX_BRANCH: usize = 1024;

pub(super) fn permitted(grants: QueueGrants, pull_write: bool, name: &str) -> bool {
    match name {
        LIST | SHOW => grants.read,
        ENQUEUE | DEQUEUE | REORDER => grants.write,
        REFRESH => grants.write && pull_write,
        LAND | LAND_CANDIDATE => grants.land,
        _ => false,
    }
}
pub(super) fn is_mutation(grants: QueueGrants, pull_write: bool, name: &str) -> bool {
    permitted(grants, pull_write, name) && !matches!(name, LIST | SHOW)
}
pub(super) fn tools(grants: QueueGrants, pull_write: bool) -> Vec<Tool> {
    [
        (LIST, "List complete visible merge queues in numeric order at one authority head. A continuation requires the original snapshot token; current hidden-ref policy still applies."),
        (SHOW, "Read one complete canonical merge queue at an optional retained snapshot. A hidden target or source hides the entire queue; absence grants no merge permission."),
        (ENQUEUE, "Enqueue or replace one open PR using its exact version and observed source/target tips. Requires the independent queue-write grant; changes queue intent only, never Git refs or approvals."),
        (DEQUEUE, "Remove one PR from an exact queue version with an explicit reason. Requires the independent queue-write grant; no Git ref or PR state changes."),
        (REORDER, "Replace the complete order of an exact queue with 1..256 distinct PR numbers. No member may be added or omitted. Requires the independent queue-write grant."),
        (REFRESH, "Refresh only the exact idle queue-head PR's recorded target tip after target advancement. Requires BOTH independent queue-write and PR-write grants, original complete PR title/body/source metadata, queue/PR versions, policy epoch, recorded old target and explicit new live target. Native admission verifies every guard and changes no refs, queue membership/order, reviews or checks. Retry identical coordinates and the same durable key after uncertainty; no implicit latest-state lookup."),
        (LAND, "Atomically fast-forward the exact queue-head PR and publish its PR merge plus queue completion. Requires the independent queue-landing grant and exact queue/PR versions, policy epoch and native tips. Current review/check/protected-ref rules remain mandatory; no new commit, force, implicit refresh or merge-method fallback."),
        (LAND_CANDIDATE, "Atomically land one exact two-parent queue-head candidate, its PR merge and queue completion. Requires the independent queue-landing grant, exact queue/PR versions, policy epoch, source/target/base/candidate commits and an inline native bundle of at most 24 KiB. Current protected-ref, review and check requirements remain mandatory. Retry the original coordinates and key; absent or empty chunks can recover an already terminal outcome without another upload."),
    ]
    .into_iter()
    .filter(|(name, _)| permitted(grants, pull_write, name))
    .map(|(name, description)| Tool { name, description, schema: schema::for_tool(name) })
    .collect()
}

/// Validate a prepared landing template with the same closed parser used by
/// publication. This performs no canonical read, intake or admission.
pub(super) fn parse_candidate_landing(
    args: &Object,
    format: GitHashAlgorithm,
    incarnation: RepositoryIncarnationId,
) -> Result<QueueCandidateLandingCommand, ToolError> {
    let (_, Command::CandidateLanding { command, .. }) =
        input::parse(LAND_CANDIDATE, args, format, incarnation)?
    else {
        unreachable!()
    };
    Ok(command)
}

pub(super) fn call(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    if !permitted(backend.options.queues, backend.options.writes.pulls, name) {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    if matches!(name, LIST | SHOW) {
        return read(backend, name, args);
    }
    let incarnation = backend
        .options
        .incarnation
        .ok_or(ToolError::invalid("incarnation_not_bound"))?;
    if incarnation != backend.node.repository_incarnation_id() {
        return Err(ToolError::invalid("repository_incarnation_mismatch"));
    }
    let (key, command) = input::parse(name, args, backend.options.format, incarnation)?;
    let session = common::session(backend, key)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    if let Command::Management(command) = &command {
        command
            .proposed_event(principal, backend.options.format)
            .map_err(|_| ToolError::invalid("invalid_queue_command"))?;
    }
    if let Command::Refresh(command) = &command {
        command
            .proposed_event(principal, backend.options.format)
            .map_err(|_| ToolError::invalid("invalid_queue_refresh_command"))?;
    }
    let request = fgit_cli::command_request_context(&backend.node);
    let result = match &command {
        Command::Management(command) => backend
            .node
            .runtime()
            .block_on(backend.node.admit_queue_durable_in(
                &request,
                &session,
                command,
                Default::default(),
            ))
            .map_err(|_| ToolError::uncertain("queue_mutation_outcome_unknown")),
        Command::Refresh(command) => backend
            .node
            .runtime()
            .block_on(backend.node.refresh_queue_head_durable_in(
                &request,
                &session,
                command,
                Default::default(),
            ))
            .map_err(|_| ToolError::uncertain("queue_mutation_outcome_unknown")),
        Command::Landing(command) => backend
            .node
            .runtime()
            .block_on(backend.node.land_queue_head_durable_in(
                &request,
                &session,
                command,
                Default::default(),
            ))
            .map_err(|_| ToolError::uncertain("queue_mutation_outcome_unknown")),
        Command::CandidateLanding { command, bundle } => backend
            .node
            .runtime()
            .block_on(backend.node.land_queue_head_bundle_durable_in(
                &request,
                &session,
                command,
                bundle,
                Default::default(),
            ))
            .map_err(|_| ToolError::uncertain("queue_mutation_outcome_unknown")),
    };
    let (tx, terminal) = result?;
    // The original terminal is authoritative even after later queue, PR or
    // policy changes. Never replace it with a latest-state read.
    let result = output::publication(backend, principal, &command, tx, &terminal);
    result
        .encode(MAX_RESPONSE)
        .map_err(|_| ToolError::uncertain("queue_mutation_outcome_unknown"))?;
    Ok(result)
}

fn read(backend: &NodeTools, name: &str, args: &Object) -> Result<Value, ToolError> {
    let request = fgit_cli::command_request_context(&backend.node);
    let read_error = |error: fgit_node::QueueReadRefusal| {
        ToolError::failed(if error.is_snapshot_unavailable() {
            "snapshot_unavailable"
        } else {
            "queue_read_failed"
        })
    };
    if name == SHOW {
        require_fields(args, &["number", "expected_head"])?;
        let number = QueueNumber::try_new(common::number(args, "number")?)
            .ok_or(ToolError::invalid("positive_queue_number_required"))?;
        let expected = head(args, 0)?;
        let selected = backend
            .node
            .runtime()
            .block_on(
                backend
                    .node
                    .read_queue_in(&request, &Default::default(), number, expected),
            )
            .map_err(read_error)?;
        output::show(backend, number, expected, &selected)
    } else {
        require_fields(args, &["after", "limit", "expected_head"])?;
        let after = decimal(args, "after", 0)?;
        let limit = limit(args)?;
        let expected = head(args, after)?;
        let selected = backend
            .node
            .runtime()
            .block_on(backend.node.read_queues_in(
                &request,
                &Default::default(),
                after,
                limit,
                expected,
            ))
            .map_err(read_error)?;
        output::list(backend, after, limit, expected, &selected)
    }
}
