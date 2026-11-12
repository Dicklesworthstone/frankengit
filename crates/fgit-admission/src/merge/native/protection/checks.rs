//! Exact-candidate trusted-workflow protection. Only canonical policy chooses
//! publishers; execution reports and observation IDs never grant themselves
//! authority. Publication order, not hash order or any older green result,
//! resolves repeated runs of the same configured workflow job.

use std::collections::BTreeMap;

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{HistoryStep, HistoryStepRefusal, PublicationBasis, read_history_step_async};
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

mod frontier;

#[derive(Default)]
struct ScanBudget {
    batches: usize,
    events: usize,
    bytes: usize,
}

impl ScanBudget {
    fn charge_bytes(&mut self, bytes: usize) -> Result<(), ProjectionFailure> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|count| *count <= MAX_SCAN_BYTES)
            .ok_or_else(exhausted)?;
        Ok(())
    }

    fn reserve_batch(&mut self) -> Result<(), ProjectionFailure> {
        self.batches = self
            .batches
            .checked_add(1)
            .filter(|count| *count <= MAX_SCAN_BATCHES)
            .ok_or_else(exhausted)?;
        Ok(())
    }

    fn charge_batch(&mut self, bytes: usize, events: usize) -> Result<(), ProjectionFailure> {
        self.charge_bytes(bytes)?;
        self.events = self
            .events
            .checked_add(events)
            .filter(|count| *count <= MAX_SCAN_EVENTS)
            .ok_or_else(exhausted)?;
        Ok(())
    }
}

const fn exhausted() -> ProjectionFailure {
    ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
}

const fn denied() -> ProjectionFailure {
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
    if required
        .iter()
        .any(|check| refs.get(&check.source_ref) != Some(&candidate))
    {
        return Err(denied());
    }
    let mut unresolved: Vec<_> = required.iter().collect();
    verify_observations_at(
        store,
        cx,
        basis,
        move |payload| {
            let ForgeEventPayload::WorkflowCheckObservedNative(observation) = payload else {
                return Ok(false);
            };
            let check = &observation.record;
            if check.source_commit != candidate {
                return Ok(false);
            }
            if let Some(index) = unresolved.iter().position(|requirement| {
                requirement.source_ref == check.source_ref
                    && requirement.publisher == observation.actor
                    && requirement.graph_root == check.graph_root
                    && requirement.job == check.job
            }) {
                // The latest exact observation decides; never seek an older green.
                if check.conclusion != WorkflowCheckConclusion::Success {
                    return Err(denied());
                }
                unresolved.remove(index);
            }
            Ok(unresolved.is_empty())
        },
        cancelled,
    )
    .await
}

/// Walk one authenticated history with the existing cumulative resource limits.
/// A predicate can resolve several independently mandatory observation profiles
/// without performing a second history scan or accepting an older failed check.
/// When the predecessor-edge bound is reached, an exact canonical frontier may
/// establish that every remaining matching observation succeeded. Mixed results
/// retain the bound refusal because the frontier does not encode their order.
pub(super) async fn verify_observations_at<S, C, F>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    mut observe: F,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
    F: FnMut(&ForgeEventPayload) -> Result<bool, ProjectionFailure> + Clone + Send,
{
    let mut successor = basis.body().clone();
    let mut walked = 0;
    let mut scan = ScanBudget::default();
    loop {
        live(cancelled).map_err(infrastructure)?;
        let (predecessor, batch) = match read_history_step_async(
            store,
            cx,
            &successor,
            &mut walked,
            MAX_HISTORY_STEPS,
            cancelled,
        )
        .await
        {
            Err(HistoryStepRefusal::BoundExceeded { .. }) => {
                return if frontier::verify_unanimous_at(
                    store, cx, basis, observe, &mut scan, cancelled,
                )
                .await?
                {
                    Ok(())
                } else {
                    Err(exhausted())
                };
            }
            Err(error) => return Err(infrastructure(storage::history_step_refusal(error))),
            Ok(HistoryStep::Genesis) => return Err(denied()),
            Ok(HistoryStep::Checkpoint { predecessor, .. }) => {
                successor = predecessor.body().clone();
                continue;
            }
            Ok(HistoryStep::Decision { predecessor, batch }) => (predecessor, batch),
        };
        for record in batch.committed_rcrs.iter().rev() {
            live(cancelled).map_err(infrastructure)?;
            scan.reserve_batch()?;
            let (events, bytes) = storage::read_events_with_size(
                store,
                cx,
                basis.body().repository_id,
                record.forge_event_batch_root,
            )
            .await
            .map_err(infrastructure)?;
            live(cancelled).map_err(infrastructure)?;
            scan.charge_batch(bytes, events.events.len())?;
            for event in events.events.iter().rev() {
                live(cancelled).map_err(infrastructure)?;
                if observe(&event.payload)? {
                    live(cancelled).map_err(infrastructure)?;
                    return Ok(());
                }
            }
        }
        successor = predecessor.body().clone();
    }
}
