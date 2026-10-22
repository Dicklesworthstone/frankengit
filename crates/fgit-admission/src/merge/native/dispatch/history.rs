//! Verify the complete selected execution, not just staged predecessor bodies.
use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{HistoryStep, PublicationBasis, read_history_step_async};
use fgit_codec::{CanonicalOutboxEffectState, CanonicalOutboxState, CanonicalOutboxStateEntry};
use fgit_resource::{LifecycleEvent, ObligationState};
use fgit_types::RefusalCode;

use super::super::{delivery, history, storage, unavailable};
use super::CanonicalDispatchProgress;
use crate::AdmissionError;

pub(in crate::merge::native) async fn latest<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    entry: &CanonicalOutboxStateEntry,
    cancelled: &C,
) -> Result<Option<CanonicalDispatchProgress>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    history::checkpoint(cancelled)?;
    if fgit_authority::authority_head_identity(basis.body()).map_err(|_| bad())? != basis.id() {
        return Err(bad());
    }
    let selected =
        history::read_selected_entry(store, cx, basis.body(), entry.delivery_key(), cancelled)
            .await?;
    if selected != *entry {
        return Err(unavailable(RefusalCode::EvidenceStale));
    }
    delivery::read_effect_in(store, cx, basis.body().repository_id, entry, cancelled).await?;
    let mut successor = basis.body().clone();
    let mut batches = 0;
    let mut records = 0_usize;
    let mut newest = None;
    let mut oldest: Option<CanonicalDispatchProgress> = None;
    loop {
        let (predecessor, batch) =
            match read_history_step_async(store, cx, &successor, &mut batches, 4096, cancelled)
                .await
                .map_err(storage::history_step_refusal)?
            {
                HistoryStep::Genesis => {
                    return if newest.is_none() {
                        Ok(None)
                    } else {
                        Err(unavailable(RefusalCode::EvidenceMissing))
                    };
                }
                HistoryStep::Checkpoint { predecessor } => {
                    successor = predecessor.body().clone();
                    continue;
                }
                HistoryStep::Decision { predecessor, batch } => (predecessor, batch),
            };
        records = records
            .checked_add(batch.committed_rcrs.len())
            .filter(|n| *n <= 65_536)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for record in batch.committed_rcrs.iter().rev() {
            let evidence = history::verify_record_evidence(
                store,
                cx,
                basis.body().repository_id,
                record,
                cancelled,
            )
            .await?;
            match evidence {
                history::OutboxRecordEvidence::Dispatch(progress)
                    if progress.delivery_key() == entry.delivery_key() =>
                {
                    if batch.committed_rcrs.len() != 1
                        || progress.destination() != entry.destination()
                        || progress.payload_root() != entry.payload_root()
                    {
                        return Err(bad());
                    }
                    let map: CanonicalOutboxState = history::read_body(
                        store,
                        cx,
                        progress.repository_id(),
                        delivery::OUTBOX_NAMESPACE,
                        successor.outbox_root,
                        cancelled,
                    )
                    .await?;
                    let selected = map.entry(entry.delivery_key()).ok_or_else(bad)?;
                    if selected.tx_id() != entry.tx_id()
                        || selected.payload_root() != entry.payload_root()
                        || selected.destination() != entry.destination()
                        || selected.effect_state_root()
                            != progress
                                .finished_effect_root()
                                .unwrap_or(progress.origin_effect_root())
                    {
                        return Err(bad());
                    }
                    if let Some(next) = &oldest {
                        next.verify_successor_of(&progress).map_err(|_| bad())?;
                    } else {
                        if entry.effect_state_root()
                            != progress
                                .finished_effect_root()
                                .unwrap_or(progress.origin_effect_root())
                        {
                            return Err(bad());
                        }
                        newest = Some(progress.clone());
                    }
                    if progress.predecessor_progress_root().is_none() {
                        let prior = history::read_selected_entry(
                            store,
                            cx,
                            predecessor.body(),
                            entry.delivery_key(),
                            cancelled,
                        )
                        .await?;
                        let original = delivery::read_effect_in(
                            store,
                            cx,
                            progress.repository_id(),
                            &prior,
                            cancelled,
                        )
                        .await?;
                        if original.state() != ObligationState::Committed
                            || progress.ordinal() != 0
                            || original
                                .transition(LifecycleEvent::Defer, None)
                                .map_err(|_| bad())?
                                .root()
                                .map_err(|_| bad())?
                                != progress.origin_effect_root()
                            || prior.destination() != entry.destination()
                            || prior.payload_root() != entry.payload_root()
                            || prior.tx_id() != entry.tx_id()
                        {
                            return Err(bad());
                        }
                        history::checkpoint(cancelled)?;
                        return Ok(newest);
                    }
                    oldest = Some(progress);
                }
                history::OutboxRecordEvidence::Progress(progress)
                    if progress.delivery_key() == entry.delivery_key() =>
                {
                    return if newest.is_none() {
                        Ok(None)
                    } else {
                        Err(bad())
                    };
                }
                _ => {}
            }
            if record.tx_id == entry.tx_id() && newest.is_none() {
                return Ok(None);
            }
        }
        successor = predecessor.body().clone();
    }
}

pub(in crate::merge::native) async fn verify<S, C>(
    store: &S,
    cx: &S::Context,
    progress: &CanonicalDispatchProgress,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let origin: CanonicalOutboxEffectState = history::read_body(
        store,
        cx,
        progress.repository_id(),
        delivery::EFFECT_NAMESPACE,
        progress.origin_effect_root(),
        cancelled,
    )
    .await?;
    if origin.state() != ObligationState::DeferredExternally
        || origin.delivery_key() != progress.delivery_key()
        || origin.payload_root() != progress.payload_root()
    {
        return Err(bad());
    }
    if let Some(root) = progress.predecessor_progress_root() {
        let previous: CanonicalDispatchProgress = history::read_body(
            store,
            cx,
            progress.repository_id(),
            history::OUTBOX_EFFECT_NAMESPACE,
            root,
            cancelled,
        )
        .await?;
        progress.verify_successor_of(&previous).map_err(|_| bad())?;
    }
    if progress.finished_effect_root().is_some() {
        let (effect, receipt) = progress.terminal_objects(&origin).map_err(|_| bad())?;
        let stored: CanonicalOutboxEffectState = history::read_body(
            store,
            cx,
            progress.repository_id(),
            delivery::EFFECT_NAMESPACE,
            effect.root().map_err(|_| bad())?,
            cancelled,
        )
        .await?;
        let stored_receipt: fgit_codec::CanonicalOutboxDeliveryReceipt = history::read_body(
            store,
            cx,
            progress.repository_id(),
            delivery::RECEIPT_NAMESPACE,
            receipt.root().map_err(|_| bad())?,
            cancelled,
        )
        .await?;
        if stored != effect || stored_receipt != receipt {
            return Err(bad());
        }
    }
    history::checkpoint(cancelled)
}

fn bad() -> AdmissionError {
    unavailable(RefusalCode::EvidenceInvalid)
}

pub(super) async fn retired<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    key: fgit_types::AsciiSlug,
    destination: fgit_types::AsciiSlug,
    cancelled: &C,
) -> Result<Option<CanonicalDispatchProgress>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    // The shared reader proves actual canonical removal and its full original
    // progress/receipt closure before any finished body is returned here.
    let Some(effect) =
        history::retired_effect(store, cx, basis, key, destination, cancelled).await?
    else {
        return Ok(None);
    };
    let mut successor = basis.body().clone();
    let mut walked = 0;
    let mut records = 0_usize;
    loop {
        let (predecessor, batch) =
            match read_history_step_async(store, cx, &successor, &mut walked, 4096, cancelled)
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
            .filter(|n| *n <= 65_536)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for record in batch.committed_rcrs.iter().rev() {
            if let history::OutboxRecordEvidence::Dispatch(progress) =
                history::verify_record_evidence(
                    store,
                    cx,
                    basis.body().repository_id,
                    record,
                    cancelled,
                )
                .await?
                && progress.delivery_key() == key
            {
                if progress.finished_effect_root() != Some(effect.root().map_err(|_| bad())?) {
                    return Err(bad());
                }
                return Ok(Some(progress));
            }
        }
        successor = predecessor.body().clone();
    }
}
