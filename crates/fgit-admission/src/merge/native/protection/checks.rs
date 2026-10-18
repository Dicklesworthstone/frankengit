//! Exact-candidate trusted-workflow protection. Only canonical policy chooses
//! publishers; execution reports and observation IDs never grant themselves
//! authority. Publication order, not hash order or any older green result,
//! resolves repeated runs of the same configured workflow job.

use std::collections::BTreeMap;

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{HistoryStep, PublicationBasis, read_history_step_async};
use fgit_forge::ForgeEventPayload;
use fgit_forge::event::protection::RequiredWorkflowCheck;
use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
use fgit_types::{GitOid, RefName, RefusalCode};

use super::{infrastructure, live, storage};
use crate::ProjectionFailure;

const MAX_HISTORY_STEPS: usize = 4096;
const MAX_SCAN_BATCHES: usize = 65_536;
const MAX_SCAN_EVENTS: usize = 65_536;
const MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;

fn denied() -> ProjectionFailure {
    ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied)
}

/// The refs map must be materialized from this exact authenticated basis. Every
/// publication retry reruns this gate, so a new failure, moved source, or policy
/// replacement cannot be hidden behind an earlier successful preflight.
pub(super) async fn verify_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    refs: &BTreeMap<RefName, GitOid>,
    candidate: GitOid,
    required: &[RequiredWorkflowCheck],
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    live(cancelled).map_err(infrastructure)?;
    if required.is_empty() {
        return Ok(());
    }
    if required.iter().any(|check| refs.get(&check.source_ref) != Some(&candidate)) {
        return Err(denied());
    }
    let mut unresolved: Vec<_> = required.iter().collect();
    let mut successor = basis.body().clone();
    let mut walked = 0;
    let mut batches_seen = 0usize;
    let mut events_seen = 0usize;
    let mut bytes_seen = 0usize;
    loop {
        live(cancelled).map_err(infrastructure)?;
        let (predecessor, batch) = match read_history_step_async(
            store, cx, &successor, &mut walked, MAX_HISTORY_STEPS, cancelled,
        ).await.map_err(storage::history_step_refusal).map_err(infrastructure)? {
            HistoryStep::Genesis => return Err(denied()),
            HistoryStep::Checkpoint { predecessor } => {
                successor = predecessor.body().clone();
                continue;
            }
            HistoryStep::Decision { predecessor, batch } => (predecessor, batch),
        };
        for record in batch.committed_rcrs.iter().rev() {
            live(cancelled).map_err(infrastructure)?;
            batches_seen = batches_seen.checked_add(1).filter(|n| *n <= MAX_SCAN_BATCHES)
                .ok_or(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded))?;
            let (events, bytes) = storage::read_events_with_size(
                store, cx, basis.body().repository_id, record.forge_event_batch_root,
            ).await.map_err(infrastructure)?;
            live(cancelled).map_err(infrastructure)?;
            bytes_seen = bytes_seen.checked_add(bytes).filter(|n| *n <= MAX_SCAN_BYTES)
                .ok_or(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded))?;
            events_seen = events_seen.checked_add(events.events.len()).filter(|n| *n <= MAX_SCAN_EVENTS)
                .ok_or(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded))?;
            for event in events.events.iter().rev() {
                live(cancelled).map_err(infrastructure)?;
                let ForgeEventPayload::WorkflowCheckObservedNative(observation) = &event.payload else {
                    continue;
                };
                let check = &observation.record;
                if check.source_commit != candidate {
                    continue;
                }
                if let Some(index) = unresolved.iter().position(|requirement| {
                    requirement.source_ref == check.source_ref
                        && requirement.publisher == observation.actor
                        && requirement.graph_root == check.graph_root
                        && requirement.job == check.job
                }) {
                    // This is the LAST committed observation for the exact
                    // selector. A failure never falls back to an older success.
                    if check.conclusion != WorkflowCheckConclusion::Success {
                        return Err(denied());
                    }
                    unresolved.remove(index);
                    if unresolved.is_empty() {
                        live(cancelled).map_err(infrastructure)?;
                        return Ok(());
                    }
                }
            }
        }
        successor = predecessor.body().clone();
    }
}
