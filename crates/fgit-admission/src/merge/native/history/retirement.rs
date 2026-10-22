//! Recover terminal receipts after their active outbox slots are released.
//! Only authenticated decision history establishes retirement. A staged effect
//! or receipt, or mere absence from the current map, never proves completion.

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{HistoryStep, PublicationBasis, read_history_step_async};
use fgit_codec::{CanonicalOutboxEffectState, CanonicalOutboxState};
use fgit_resource::ObligationState;
use fgit_types::{AsciiSlug, RefusalCode};

use super::super::{delivery, storage, unavailable};
use super::{
    MAX_HISTORY_BATCHES, MAX_HISTORY_RECORDS, OutboxRecordEvidence, checkpoint,
    latest_progress_for_entry, read_body, read_effect_receipt, read_selected_entry,
    validate_terminal_progress, verify_record_evidence,
};
use crate::AdmissionError;

/// Resolve a retired delivery without contacting its destination. Both the
/// terminal lifecycle and the exact map removal must be selected by the same
/// authenticated head transition. The immutable receipt remains in the RCR
/// history; no process-local tombstone or second authority is consulted.
///
/// History budgets are deliberate applicability limits. Missing, corrupt, or
/// over-budget history refuses; it cannot turn a forgotten key into a new send.
pub async fn retired_effect<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    key: AsciiSlug,
    destination: AsciiSlug,
    cancelled: &C,
) -> Result<Option<CanonicalOutboxEffectState>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    // Own the history scan once instead of embedding its state in every
    // receipt/driver future and synchronous runtime bridge. Debug poll frames
    // and runtime bridges otherwise reserve repeated copies of the full scan
    // on the caller stack. The same scan is awaited to completion with its
    // original cancellation checkpoints and provenance checks.
    Box::pin(retired_effect_in_class(
        store,
        cx,
        basis,
        key,
        destination,
        None,
        cancelled,
    ))
    .await
}

pub(in crate::merge::native) async fn retired_effect_in_class<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    key: AsciiSlug,
    destination: AsciiSlug,
    required_class: Option<AsciiSlug>,
    cancelled: &C,
) -> Result<Option<CanonicalOutboxEffectState>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    if fgit_authority::authority_head_identity(basis.body())
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
        != basis.id()
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let current = delivery::read_in(store, cx, basis, cancelled).await?;
    if current.outbox.entry(key).is_some() {
        return Err(unavailable(RefusalCode::EvidenceStale));
    }
    let repository = basis.body().repository_id;
    let mut successor = basis.body().clone();
    let mut batches = 0;
    let mut records = 0_usize;
    loop {
        let (predecessor, batch) = match read_history_step_async(
            store,
            cx,
            &successor,
            &mut batches,
            MAX_HISTORY_BATCHES,
            cancelled,
        )
        .await
        .map_err(storage::history_step_refusal)?
        {
            HistoryStep::Genesis => return Ok(None),
            HistoryStep::Checkpoint { predecessor } => {
                successor = predecessor.body().clone();
                continue;
            }
            HistoryStep::Decision { predecessor, batch } => (predecessor, batch),
        };
        records = records
            .checked_add(batch.committed_rcrs.len())
            .filter(|count| *count <= MAX_HISTORY_RECORDS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for record in batch.committed_rcrs.iter().rev() {
            let evidence = verify_record_evidence(store, cx, repository, record, cancelled).await?;
            let (effect, dispatch) = match evidence {
                OutboxRecordEvidence::Effect(effect) => (effect, None),
                OutboxRecordEvidence::Dispatch(progress) if progress.delivery_key() == key => {
                    if progress.finished_effect_root().is_none() {
                        return Err(unavailable(RefusalCode::EvidenceInvalid));
                    }
                    let origin = read_body(
                        store,
                        cx,
                        repository,
                        delivery::EFFECT_NAMESPACE,
                        progress.origin_effect_root(),
                        cancelled,
                    )
                    .await?;
                    let (effect, _) = progress
                        .terminal_objects(&origin)
                        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
                    (effect, Some(progress))
                }
                _ => continue,
            };
            if effect.delivery_key() != key {
                continue;
            }
            // An unresolved escalation remains an active responsibility. Never
            // reinterpret it as terminal delivery or prune it to gain capacity.
            if !matches!(
                effect.state(),
                ObligationState::Acknowledged | ObligationState::TerminallyFailed
            ) {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            let prior = read_selected_entry(store, cx, predecessor.body(), key, cancelled).await?;
            let selected: CanonicalOutboxState = read_body(
                store,
                cx,
                repository,
                delivery::OUTBOX_NAMESPACE,
                successor.outbox_root,
                cancelled,
            )
            .await?;
            if selected.repository_id() != repository
                || selected.entry(key).is_some()
                || (prior.effect_class() != AsciiSlug::from_static("forge-event")
                    && prior.effect_class() != super::super::dispatch::replay::REPLAY_CLASS)
                || required_class.is_some_and(|class| prior.effect_class() != class)
                || prior.destination() != destination
                || prior.tx_id() != effect.tx_id()
                || prior.payload_root() != effect.payload_root()
                || !(effect.predecessor_root() == Some(prior.effect_state_root())
                    || storage::root(&effect)? == prior.effect_state_root())
            {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            // Validate the predecessor's stable delivery identity and lifecycle
            // chain. Also validate the canonical progress through its creation
            // boundary, not merely the existence of a receipt-shaped object.
            delivery::read_effect_in(store, cx, repository, &prior, cancelled).await?;
            let receipt = read_effect_receipt(store, cx, &effect, cancelled)
                .await?
                .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
            if receipt.destination() != prior.destination() {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            if let Some(dispatch) = dispatch {
                let previous = super::super::dispatch::read_progress(
                    store,
                    cx,
                    &predecessor,
                    &prior,
                    cancelled,
                )
                .await?
                .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
                dispatch
                    .verify_successor_of(&previous)
                    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
                if dispatch.origin_effect_root() != prior.effect_state_root()
                    || dispatch.destination() != prior.destination()
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
            } else {
                let progress =
                    latest_progress_for_entry(store, cx, &predecessor, &prior, cancelled)
                        .await?
                        .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
                validate_terminal_progress(&progress, &effect, &receipt)?;
            }
            checkpoint(cancelled)?;
            return Ok(Some(effect));
        }
        successor = predecessor.body().clone();
    }
}
