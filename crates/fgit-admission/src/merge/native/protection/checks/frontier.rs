//! Success-only proof from the exact canonical check frontier after bounded
//! ordered history is exhausted. The frontier has no cross-stream publication
//! order. It can settle a selector only if ALL of its observations succeeded;
//! it never treats check identity, job time or map order as publication order.

use std::collections::BTreeMap;

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_codec::{
    CanonicalForgePositionState, DecodeLimits, ForgePositionStateEntry,
    MAX_FORGE_POSITION_STATE_ENTRIES, decode_body,
};
use fgit_forge::event::workflow_check::WorkflowCheckId;
use fgit_forge::{AggregateId, AggregateVersion, ForgeEventPayload};
use fgit_types::{AsciiSlug, Digest, RefusalCode};

use super::super::super::delivery;
use super::{ScanBudget, infrastructure, live, storage};
use crate::ProjectionFailure;

const fn invalid() -> ProjectionFailure {
    ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid)
}

/// The matcher is the unresolved state LEFT by the ordered suffix. Clone it
/// before unordered accumulation so any older non-success for a still-pending
/// selector prevents this proof, even after another entry satisfies that selector.
/// Selectors already settled by the ordered suffix retain their newer result.
pub(super) async fn verify_unanimous_at<S, C, F>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    mut observe: F,
    scan: &mut ScanBudget,
    cancelled: &C,
) -> Result<bool, ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
    F: FnMut(&ForgeEventPayload) -> Result<bool, ProjectionFailure> + Clone + Send,
{
    live(cancelled).map_err(infrastructure)?;
    let repository = basis.body().repository_id;
    // Do not restart the legacy history bootstrap with another step allowance.
    // This independent proof requires the actual selected canonical map.
    let frame = storage::read_frame(
        store,
        cx,
        repository,
        storage::POSITION_NAMESPACE,
        basis.body().forge_position_root,
    )
    .await
    .map_err(infrastructure)?
    .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
    live(cancelled).map_err(infrastructure)?;
    scan.charge_bytes(frame.len())?;
    let positions: CanonicalForgePositionState = decode_body(
        &frame,
        DecodeLimits {
            elements: MAX_FORGE_POSITION_STATE_ENTRIES as u64,
            ..DecodeLimits::DEFAULT
        },
    )
    .map_err(|_| invalid())?;
    if positions.repository_id() != repository
        || storage::root(&positions).map_err(infrastructure)? != basis.body().forge_position_root
    {
        return Err(invalid());
    }
    drop(frame);

    // Coalesce shared event batches without retaining their decoded bodies.
    // The finite canonical frontier bounds this map; each event frame is read
    // and charged once, and the shared validator checks all selected ranges in
    // one pass rather than rescanning a bulk batch once per observation.
    let mut batches =
        BTreeMap::<Digest, BTreeMap<AsciiSlug, (&ForgePositionStateEntry, u32)>>::new();
    for position in positions.entries() {
        live(cancelled).map_err(infrastructure)?;
        let stream = position.stream();
        if !stream.as_str().starts_with("check/") {
            continue;
        }
        if WorkflowCheckId::from_label(stream.as_str()).is_none()
            || position.predecessor_position() != 0
            || position.event_count() != 1
        {
            return Err(invalid());
        }
        batches
            .entry(position.event_batch_root())
            .or_default()
            .insert(stream, (position, 0));
    }

    let unresolved = observe.clone();
    let mut complete = false;
    for (root, mut ranges) in batches {
        live(cancelled).map_err(infrastructure)?;
        scan.reserve_batch()?;
        let (batch, bytes) = storage::read_events_with_size(store, cx, repository, root)
            .await
            .map_err(infrastructure)?;
        live(cancelled).map_err(infrastructure)?;
        scan.charge_batch(bytes, batch.events.len())?;
        if !delivery::validate_position_ranges(&mut ranges, &batch, cancelled)
            .map_err(infrastructure)?
            .is_empty()
        {
            return Err(invalid());
        }
        for event in &batch.events {
            live(cancelled).map_err(infrastructure)?;
            let stream = storage::aggregate_label(event.aggregate).map_err(infrastructure)?;
            if !ranges.contains_key(&stream) {
                continue;
            }
            let AggregateId::WorkflowCheck(id) = event.aggregate else {
                return Err(invalid());
            };
            if event.version != AggregateVersion::FIRST {
                return Err(invalid());
            }
            match &event.payload {
                ForgeEventPayload::WorkflowCheckObservedNative(change) if change.id() == id => {}
                ForgeEventPayload::CandidateWorkflowCheckObservedNative(change)
                    if change.id() == id => {}
                _ => return Err(invalid()),
            }

            // A fresh clone for EVERY observation is essential. Reusing the
            // accumulator here would let a success hide a later-visited failure.
            let mut single = unresolved.clone();
            match single(&event.payload) {
                Err(ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied)) => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
                Ok(_) => {}
            }
            complete |= observe(&event.payload)?;
        }
    }
    live(cancelled).map_err(infrastructure)?;
    // Never return true inside the loop: later entries can invalidate unanimity.
    Ok(complete)
}

#[cfg(test)]
mod tests;
