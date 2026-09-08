//! Canonical reconciliation history selected by an authenticated authority head.
//!
//! Progress comes from committed RCRs in repository sequence order. Immutable
//! object presence, a lexical root ordering, and process-local pending rows do
//! not establish which attempt is current.

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::{
    CanonicalBody, CanonicalOutboxDeliveryReceipt, CanonicalOutboxEffectState, CryptoBodyIdentity,
    DecodeLimits, OutboxDeliveryDisposition, RepositoryCommitRecord, decode_body,
};
use fgit_resource::{ObligationState, ReconcileState};
use fgit_types::{AsciiSlug, Digest, RefusalCode, RepositoryId};

use super::progress::{CanonicalOutboxProgress, MAX_OUTBOX_PROGRESS_TRANSITIONS};
use super::{delivery, storage, unavailable};
use crate::AdmissionError;

/// Existing admission evidence namespace. Progress and lifecycle records use
/// typed bodies here and under the invariant namespace with the same root.
pub const OUTBOX_EFFECT_NAMESPACE: &[u8] = b"frankengit/admission/outbox-effect-batch/v1/";
const MAX_HISTORY_BATCHES: usize = 4096;
const MAX_HISTORY_RECORDS: usize = 65_536;

/// The positively identified evidence schema of one committed outbox partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboxRecordEvidence {
    /// The existing transaction-fold outbox evidence schema. Its own consumer
    /// remains responsible for checking the complete transaction fold.
    Ordinary,
    /// A legal reconciliation observation or dispatch-responsibility marker.
    Progress(CanonicalOutboxProgress),
    /// A transition of the shared resource obligation lifecycle.
    Effect(CanonicalOutboxEffectState),
}

/// Find the latest progress for `key` through the exact authenticated decision
/// chain. Every earlier progress predecessor must occur canonically in order,
/// ending at the canonical deferred lifecycle record that authorized it.
/// Missing or corrupt history is refused instead of interpreted as no attempt.
pub async fn latest_progress<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    key: AsciiSlug,
    cancelled: &C,
) -> Result<Option<CanonicalOutboxProgress>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let repository = basis.body().repository_id;
    let mut successor = basis.body().clone();
    let mut chain = ReverseProgress::new(key);
    let mut batches = 0_usize;
    let mut records = 0_usize;
    while let Some(batch_id) = successor.decision_tail_id {
        checkpoint(cancelled)?;
        if batches >= MAX_HISTORY_BATCHES {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        batches += 1;
        let predecessor_id = successor
            .predecessor_head_id
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let predecessor =
            fgit_authority::read_authority_head_body_async(store, cx, predecessor_id).await?;
        checkpoint(cancelled)?;
        let batch = fgit_authority::read_decision_batch_body_async(store, cx, batch_id).await?;
        checkpoint(cancelled)?;
        verify_pair(
            &CryptoBodyIdentity,
            &PublicationBasis::new(predecessor_id, predecessor.clone()),
            &batch,
            &successor,
        )
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        records = records
            .checked_add(batch.committed_rcrs.len())
            .filter(|count| *count <= MAX_HISTORY_RECORDS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        // verify_pair proves that this is repository sequence order, including
        // batches containing several commits interleaved with refusals.
        for record in batch.committed_rcrs.iter().rev() {
            match verify_record_evidence(store, cx, repository, record, cancelled).await? {
                OutboxRecordEvidence::Ordinary => {}
                OutboxRecordEvidence::Progress(progress) => chain.progress(progress)?,
                OutboxRecordEvidence::Effect(effect) => {
                    if effect.delivery_key() == key {
                        if let Some(receipt) =
                            read_effect_receipt(store, cx, &effect, cancelled).await?
                        {
                            chain.terminal(&effect, receipt)?;
                        }
                    }
                    chain.effect(&effect)?;
                }
            }
        }
        successor = predecessor;
    }
    if successor.repository_id != repository
        || successor.generation != fgit_types::HeadGeneration::FIRST
        || successor.predecessor_head_id.is_some()
        || successor.latest_committed_rcr_id.is_some()
        || successor.latest_decision_sequence.is_some()
        || successor.latest_repository_sequence.is_some()
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    checkpoint(cancelled)?;
    chain.finish()
}

/// Verify the evidence body selected by an already authenticated RCR. Typed
/// progress/lifecycle witnesses must exist under both RCR evidence aliases;
/// lifecycle witnesses must also exist in the canonical effect namespace.
/// This validates persisted commitments, not a transport's trustworthiness or
/// the effect's membership in a particular outbox map.
pub async fn verify_record_evidence<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    record: &RepositoryCommitRecord,
    cancelled: &C,
) -> Result<OutboxRecordEvidence, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let frame = required_frame(
        store,
        cx,
        repository,
        OUTBOX_EFFECT_NAMESPACE,
        record.outbox_effect_root,
        cancelled,
    )
    .await?;
    let evidence = decode_record_effect(repository, record, &frame)?;
    if evidence == OutboxRecordEvidence::Ordinary {
        return Ok(evidence);
    }
    let invariant_frame = required_frame(
        store,
        cx,
        repository,
        storage::INVARIANT_NAMESPACE,
        record.invariant_evidence_root,
        cancelled,
    )
    .await?;
    if frame != invariant_frame {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    match &evidence {
        OutboxRecordEvidence::Ordinary => {}
        OutboxRecordEvidence::Progress(progress) => {
            let origin: CanonicalOutboxEffectState = read_body(
                store,
                cx,
                repository,
                delivery::EFFECT_NAMESPACE,
                progress.origin_effect_root(),
                cancelled,
            )
            .await?;
            validate_progress_origin(progress, &origin)?;
            if let Some(root) = progress.predecessor_progress_root() {
                let previous: CanonicalOutboxProgress = read_body(
                    store,
                    cx,
                    repository,
                    OUTBOX_EFFECT_NAMESPACE,
                    root,
                    cancelled,
                )
                .await?;
                progress
                    .verify_successor_of(&previous)
                    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
            }
        }
        OutboxRecordEvidence::Effect(effect) => {
            let effect_frame = required_frame(
                store,
                cx,
                repository,
                delivery::EFFECT_NAMESPACE,
                record.outbox_effect_root,
                cancelled,
            )
            .await?;
            if effect_frame != frame {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            verify_effect_predecessor(store, cx, effect, cancelled).await?;
            read_effect_receipt(store, cx, effect, cancelled).await?;
        }
    }
    checkpoint(cancelled)?;
    Ok(evidence)
}

fn decode_record_effect(
    repository: RepositoryId,
    record: &RepositoryCommitRecord,
    frame: &[u8],
) -> Result<OutboxRecordEvidence, AdmissionError> {
    if record.repository_id != repository {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    if let Ok(progress) = decode_body::<CanonicalOutboxProgress>(frame, DecodeLimits::DEFAULT) {
        if progress.repository_id() != repository
            || storage::root(&progress)? != record.outbox_effect_root
            || record.invariant_evidence_root != record.outbox_effect_root
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        return Ok(OutboxRecordEvidence::Progress(progress));
    }
    if let Ok(effect) = decode_body::<CanonicalOutboxEffectState>(frame, DecodeLimits::DEFAULT) {
        if effect.repository_id() != repository
            || storage::root(&effect)? != record.outbox_effect_root
            || record.invariant_evidence_root != record.outbox_effect_root
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        return Ok(OutboxRecordEvidence::Effect(effect));
    }
    let ordinary = decode_body::<crate::evidence::OutboxEffectBatch>(frame, DecodeLimits::DEFAULT)
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    if storage::root(&ordinary)? != record.outbox_effect_root {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(OutboxRecordEvidence::Ordinary)
}

async fn verify_effect_predecessor<S, C>(
    store: &S,
    cx: &S::Context,
    effect: &CanonicalOutboxEffectState,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let Some(root) = effect.predecessor_root() else {
        return Ok(());
    };
    let previous: CanonicalOutboxEffectState = read_body(
        store,
        cx,
        effect.repository_id(),
        delivery::EFFECT_NAMESPACE,
        root,
        cancelled,
    )
    .await?;
    let event = effect
        .event()
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    if previous
        .transition(event, effect.evidence_root())
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
        != *effect
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(())
}

async fn read_effect_receipt<S, C>(
    store: &S,
    cx: &S::Context,
    effect: &CanonicalOutboxEffectState,
    cancelled: &C,
) -> Result<Option<CanonicalOutboxDeliveryReceipt>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let disposition = match effect.state() {
        ObligationState::Acknowledged => Some(OutboxDeliveryDisposition::Acknowledged),
        ObligationState::TerminallyFailed => Some(OutboxDeliveryDisposition::TerminallyRefused),
        ObligationState::Escalated => Some(OutboxDeliveryDisposition::Indeterminate),
        ObligationState::Committed
        | ObligationState::DeferredExternally
        | ObligationState::Leaked => None,
        ObligationState::Reserved | ObligationState::Aborted => {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    };
    let Some(disposition) = disposition else {
        return if effect.evidence_root().is_none() {
            Ok(None)
        } else {
            Err(unavailable(RefusalCode::EvidenceInvalid))
        };
    };
    let receipt: CanonicalOutboxDeliveryReceipt = read_body(
        store,
        cx,
        effect.repository_id(),
        delivery::RECEIPT_NAMESPACE,
        effect
            .evidence_root()
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?,
        cancelled,
    )
    .await?;
    if receipt.repository_id() != effect.repository_id()
        || receipt.delivery_key() != effect.delivery_key()
        || receipt.payload_root() != effect.payload_root()
        || Some(receipt.predecessor_effect_state_root()) != effect.predecessor_root()
        || receipt.disposition() != disposition
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(Some(receipt))
}

fn validate_progress_origin(
    progress: &CanonicalOutboxProgress,
    effect: &CanonicalOutboxEffectState,
) -> Result<(), AdmissionError> {
    if progress.repository_id() != effect.repository_id()
        || progress.delivery_key() != effect.delivery_key()
        || progress.payload_root() != effect.payload_root()
        || progress.origin_effect_root() != storage::root(effect)?
        || effect.state() != ObligationState::DeferredExternally
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(())
}

/// Constant-space verifier fed by canonical repository order, newest first.
struct ReverseProgress {
    key: AsciiSlug,
    latest: Option<CanonicalOutboxProgress>,
    oldest: Option<CanonicalOutboxProgress>,
    count: u32,
    passed_origin: bool,
    terminal: Option<(CanonicalOutboxEffectState, CanonicalOutboxDeliveryReceipt)>,
}

impl ReverseProgress {
    fn new(key: AsciiSlug) -> Self {
        Self {
            key,
            latest: None,
            oldest: None,
            count: 0,
            passed_origin: false,
            terminal: None,
        }
    }

    fn progress(&mut self, progress: CanonicalOutboxProgress) -> Result<(), AdmissionError> {
        if progress.delivery_key() != self.key {
            return Ok(());
        }
        if self.passed_origin {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        // The initial body has ordinal zero and does not consume a transition.
        if self.count > MAX_OUTBOX_PROGRESS_TRANSITIONS {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        if let Some(successor) = &self.oldest {
            successor
                .verify_successor_of(&progress)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        } else {
            if let Some((effect, receipt)) = &self.terminal {
                validate_terminal_progress(&progress, effect, receipt)?;
            }
            self.latest = Some(progress.clone());
        }
        self.count += 1;
        self.oldest = Some(progress);
        Ok(())
    }

    fn terminal(
        &mut self,
        effect: &CanonicalOutboxEffectState,
        receipt: CanonicalOutboxDeliveryReceipt,
    ) -> Result<(), AdmissionError> {
        if effect.delivery_key() != self.key {
            return Ok(());
        }
        // Progress after a terminal lifecycle result cannot reopen its budget.
        if self.latest.is_some() || self.passed_origin {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        if self.terminal.is_none() {
            self.terminal = Some((effect.clone(), receipt));
        }
        Ok(())
    }

    fn effect(&mut self, effect: &CanonicalOutboxEffectState) -> Result<(), AdmissionError> {
        if effect.delivery_key() != self.key
            || effect.state() != ObligationState::DeferredExternally
        {
            return Ok(());
        }
        if self.passed_origin {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        if let Some(oldest) = &self.oldest {
            if oldest.predecessor_progress_root().is_some() || oldest.ordinal() != 0 {
                return Err(unavailable(RefusalCode::EvidenceMissing));
            }
            validate_progress_origin(oldest, effect)?;
        }
        self.passed_origin = true;
        Ok(())
    }

    fn finish(self) -> Result<Option<CanonicalOutboxProgress>, AdmissionError> {
        if self.latest.is_some() && !self.passed_origin {
            return Err(unavailable(RefusalCode::EvidenceMissing));
        }
        Ok(self.latest)
    }
}

fn validate_terminal_progress(
    progress: &CanonicalOutboxProgress,
    effect: &CanonicalOutboxEffectState,
    receipt: &CanonicalOutboxDeliveryReceipt,
) -> Result<(), AdmissionError> {
    let expected = match progress.state() {
        ReconcileState::Delivered { .. } => OutboxDeliveryDisposition::Acknowledged,
        ReconcileState::Undeliverable { .. } => OutboxDeliveryDisposition::TerminallyRefused,
        ReconcileState::Indeterminate { .. } => OutboxDeliveryDisposition::Indeterminate,
        ReconcileState::Pending { .. } | ReconcileState::Probing { .. } => {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    };
    if progress.repository_id() != effect.repository_id()
        || progress.delivery_key() != effect.delivery_key()
        || progress.payload_root() != effect.payload_root()
        || Some(progress.origin_effect_root()) != effect.predecessor_root()
        || progress.destination() != receipt.destination()
        || progress.evidence() != receipt.evidence()
        || receipt.disposition() != expected
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(())
}

async fn required_frame<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    namespace: &[u8],
    root: Digest,
    cancelled: &C,
) -> Result<Vec<u8>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let frame = storage::read_frame(store, cx, repository, namespace, root)
        .await?
        .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
    checkpoint(cancelled)?;
    Ok(frame)
}

async fn read_body<S, B, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    namespace: &[u8],
    root: Digest,
    cancelled: &C,
) -> Result<B, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    B: CanonicalBody,
    C: Fn() -> bool + Sync,
{
    let frame = required_frame(store, cx, repository, namespace, root, cancelled).await?;
    let body = decode_body::<B>(&frame, DecodeLimits::DEFAULT)
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    if storage::root(&body)? != root {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(body)
}

fn checkpoint(cancelled: &(impl Fn() -> bool + Sync)) -> Result<(), AdmissionError> {
    if cancelled() {
        Err(unavailable(RefusalCode::CancellationInProgress))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
