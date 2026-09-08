//! Canonical delivery bodies in the admission authority's immutable store.
//!
//! The node and native admission share this reader. A body can be staged long
//! before it is canonical; only an authenticated publication basis selects its
//! forge/outbox roots. Settlement never creates a second pending table.

use std::collections::BTreeMap;

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::{
    CanonicalBody, CanonicalForgePositionState, CanonicalOutboxDeliveryReceipt,
    CanonicalOutboxEffectState, CanonicalOutboxState, CanonicalOutboxStateEntry,
    CryptoBodyIdentity, DecodeLimits, ForgePositionStateEntry, OutboxDeliveryDisposition,
    OutboxDeliveryIdentityInput, decode_body, derive_outbox_delivery_key,
};
use fgit_forge::ForgeEventBatch;
use fgit_reference::intent::{ForgeStreamId, ForgeStreamPosition, OutboxDeliveryKey};
use fgit_resource::ObligationState;
use fgit_types::{Digest, RefusalCode, RepositoryId};

use super::{storage, unavailable};
use crate::AdmissionError;

pub const OUTBOX_NAMESPACE: &[u8] = b"frankengit/admission/outbox-state/v1/";
pub const EFFECT_NAMESPACE: &[u8] = b"frankengit/admission/outbox-effect-state/v1/";
pub const RECEIPT_NAMESPACE: &[u8] = b"frankengit/admission/outbox-delivery-receipt/v1/";
const MAX_LEGACY_BATCHES: usize = 4096;

/// Complete canonical maps selected by one repository authority basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryState {
    pub forge: CanonicalForgePositionState,
    pub outbox: CanonicalOutboxState,
}

impl DeliveryState {
    /// Reference evaluator's forge positions at the same immutable basis.
    #[must_use]
    pub fn forge_positions(&self) -> BTreeMap<ForgeStreamId, ForgeStreamPosition> {
        self.forge
            .entries()
            .iter()
            .map(|entry| {
                (
                    ForgeStreamId::new(entry.stream()),
                    ForgeStreamPosition::new(entry.successor_position()),
                )
            })
            .collect()
    }

    /// Reference evaluator's stable delivery parameter bindings.
    #[must_use]
    pub fn outbox_bindings(&self) -> BTreeMap<OutboxDeliveryKey, Digest> {
        self.outbox
            .entries()
            .iter()
            .map(|entry| {
                (
                    OutboxDeliveryKey::new(entry.delivery_key()),
                    entry.payload_root(),
                )
            })
            .collect()
    }
}

/// Resolve authority-selected state and all retained event/effect dependencies.
/// Legacy forge frontiers use the existing authenticated-history bootstrap;
/// missing outbox bodies are empty only for an unchanged exact legacy root.
pub async fn read_in<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    cancelled: &C,
) -> Result<DeliveryState, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let repository = basis.body().repository_id;
    let forge = storage::load_forge_positions(store, cx, basis).await?;
    checkpoint(cancelled)?;
    let outbox = match storage::read_frame(
        store,
        cx,
        repository,
        OUTBOX_NAMESPACE,
        basis.body().outbox_root,
    )
    .await?
    {
        Some(frame) => {
            let outbox: CanonicalOutboxState = decode_body(&frame, DecodeLimits::DEFAULT)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
            if outbox.repository_id() != repository
                || storage::root(&outbox)? != basis.body().outbox_root
            {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            outbox
        }
        None => {
            verify_legacy_empty_outbox(store, cx, basis, cancelled).await?;
            CanonicalOutboxState::try_new(repository, Vec::new())
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
        }
    };
    let state = DeliveryState { forge, outbox };
    for position in state.forge.entries() {
        checkpoint(cancelled)?;
        let events =
            storage::read_events(store, cx, repository, position.event_batch_root()).await?;
        validate_position_batch(position, &events)?;
    }
    for entry in state.outbox.entries() {
        read_effect_in(store, cx, repository, entry, cancelled).await?;
        checkpoint(cancelled)?;
        let payload = storage::read_events(store, cx, repository, entry.payload_root()).await?;
        validate_payload_positions(&state.forge, &payload)?;
    }
    checkpoint(cancelled)?;
    Ok(state)
}

async fn verify_legacy_empty_outbox<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let repository = basis.body().repository_id;
    let selected_root = basis.body().outbox_root;
    if selected_root != storage::legacy_genesis_root(repository, b"outbox") {
        return Err(unavailable(RefusalCode::EvidenceMissing));
    }
    let mut successor = basis.body().clone();
    let mut walked = 0;
    while let Some(batch_id) = successor.decision_tail_id {
        checkpoint(cancelled)?;
        if walked >= MAX_LEGACY_BATCHES {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        walked += 1;
        let predecessor_id = successor
            .predecessor_head_id
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let predecessor =
            fgit_authority::read_authority_head_body_async(store, cx, predecessor_id).await?;
        checkpoint(cancelled)?;
        let batch = fgit_authority::read_decision_batch_body_async(store, cx, batch_id).await?;
        verify_pair(
            &CryptoBodyIdentity,
            &PublicationBasis::new(predecessor_id, predecessor.clone()),
            &batch,
            &successor,
        )
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        if predecessor.outbox_root != selected_root || successor.outbox_root != selected_root {
            return Err(unavailable(RefusalCode::EvidenceMissing));
        }
        successor = predecessor;
    }
    if successor.repository_id != repository
        || successor.predecessor_head_id.is_some()
        || successor.latest_committed_rcr_id.is_some()
        || successor.latest_decision_sequence.is_some()
        || successor.latest_repository_sequence.is_some()
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    checkpoint(cancelled)
}

/// Resolve the immutable effect chain and prove every local predecessor claim.
/// A codec-valid body alone cannot prove that its predecessor actually exists.
pub async fn read_effect_in<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    entry: &CanonicalOutboxStateEntry,
    cancelled: &C,
) -> Result<CanonicalOutboxEffectState, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    validate_delivery_key(repository, entry)?;
    let latest: CanonicalOutboxEffectState = read_body(
        store,
        cx,
        repository,
        EFFECT_NAMESPACE,
        entry.effect_state_root(),
        cancelled,
    )
    .await?;
    validate_effect_binding(repository, entry, &latest)?;
    if latest.predecessor_root() != entry.predecessor_effect_state_root() {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let mut current = latest.clone();
    loop {
        verify_effect_receipt(store, cx, entry, &current, cancelled).await?;
        let Some(root) = current.predecessor_root() else {
            break;
        };
        // The codec caps the ordinal at three. Exact descent prevents cycles.
        let previous: CanonicalOutboxEffectState =
            read_body(store, cx, repository, EFFECT_NAMESPACE, root, cancelled).await?;
        validate_effect_binding(repository, entry, &previous)?;
        if previous.transition_ordinal().checked_add(1) != Some(current.transition_ordinal())
            || Some(previous.state()) != current.predecessor_state()
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        let event = current
            .event()
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if previous
            .transition(event, current.evidence_root())
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
            != current
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        current = previous;
    }
    if current.transition_ordinal() != 0 {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    checkpoint(cancelled)?;
    Ok(latest)
}

async fn verify_effect_receipt<S, C>(
    store: &S,
    cx: &S::Context,
    entry: &CanonicalOutboxStateEntry,
    effect: &CanonicalOutboxEffectState,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let expected = match effect.state() {
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
    let Some(disposition) = expected else {
        return if effect.evidence_root().is_none() {
            Ok(())
        } else {
            Err(unavailable(RefusalCode::EvidenceInvalid))
        };
    };
    let root = effect
        .evidence_root()
        .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
    let receipt: CanonicalOutboxDeliveryReceipt = read_body(
        store,
        cx,
        effect.repository_id(),
        RECEIPT_NAMESPACE,
        root,
        cancelled,
    )
    .await?;
    if receipt.repository_id() != effect.repository_id()
        || receipt.delivery_key() != effect.delivery_key()
        || receipt.destination() != entry.destination()
        || receipt.payload_root() != effect.payload_root()
        || Some(receipt.predecessor_effect_state_root()) != effect.predecessor_root()
        || receipt.disposition() != disposition
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(())
}

/// Stage a merge's event, initial effect and complete successor maps. The caller
/// owns the subsequent authority publication; this operation changes no head.
pub async fn stage_in<S, C>(
    store: &S,
    cx: &S::Context,
    state: &DeliveryState,
    events: &ForgeEventBatch,
    effect: &CanonicalOutboxEffectState,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let repository = state.forge.repository_id();
    if state.outbox.repository_id() != repository {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let entry = state
        .outbox
        .entry(effect.delivery_key())
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    validate_delivery_key(repository, entry)?;
    validate_effect_binding(repository, entry, effect)?;
    if effect.transition_ordinal() != 0
        || entry.predecessor_effect_state_root().is_some()
        || entry.effect_state_root() != storage::root(effect)?
        || entry.payload_root() != storage::root(events)?
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    validate_payload_positions(&state.forge, events)?;
    for event in &events.events {
        let position = state
            .forge
            .entry(storage::aggregate_label(event.aggregate)?)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if position.event_batch_root() != entry.payload_root() {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        validate_position_batch(position, events)?;
    }
    stage_body(
        store,
        cx,
        repository,
        storage::EVENT_NAMESPACE,
        events,
        cancelled,
    )
    .await?;
    stage_body(store, cx, repository, EFFECT_NAMESPACE, effect, cancelled).await?;
    stage_body(
        store,
        cx,
        repository,
        storage::POSITION_NAMESPACE,
        &state.forge,
        cancelled,
    )
    .await?;
    stage_body(
        store,
        cx,
        repository,
        OUTBOX_NAMESPACE,
        &state.outbox,
        cancelled,
    )
    .await
}

/// Stage a legal effect successor and its index after resolving the predecessor.
/// The destination's evidence body must be staged by its owning consumer first.
pub async fn stage_effect_and_outbox_in<S, C>(
    store: &S,
    cx: &S::Context,
    outbox: &CanonicalOutboxState,
    effect: &CanonicalOutboxEffectState,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let repository = outbox.repository_id();
    let entry = outbox
        .entry(effect.delivery_key())
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    validate_delivery_key(repository, entry)?;
    validate_effect_binding(repository, entry, effect)?;
    if effect.transition_ordinal() == 0
        || entry.predecessor_effect_state_root() != effect.predecessor_root()
        || entry.effect_state_root() != storage::root(effect)?
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let previous_root = effect
        .predecessor_root()
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    let previous: CanonicalOutboxEffectState = read_body(
        store,
        cx,
        repository,
        EFFECT_NAMESPACE,
        previous_root,
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
    verify_effect_receipt(store, cx, entry, effect, cancelled).await?;
    stage_body(store, cx, repository, EFFECT_NAMESPACE, effect, cancelled).await?;
    stage_body(store, cx, repository, OUTBOX_NAMESPACE, outbox, cancelled).await
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
    checkpoint(cancelled)?;
    let frame = storage::read_frame(store, cx, repository, namespace, root)
        .await?
        .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
    let body = decode_body::<B>(&frame, DecodeLimits::DEFAULT)
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    if storage::root(&body)? != root {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    checkpoint(cancelled)?;
    Ok(body)
}

async fn stage_body<S, B, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    namespace: &[u8],
    body: &B,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    B: CanonicalBody + Sync,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    storage::stage_body(store, cx, repository, namespace, body).await?;
    checkpoint(cancelled)
}

fn validate_payload_positions(
    forge: &CanonicalForgePositionState,
    payload: &ForgeEventBatch,
) -> Result<(), AdmissionError> {
    if payload.events.is_empty() {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    for event in &payload.events {
        let position = forge
            .entry(storage::aggregate_label(event.aggregate)?)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if position.successor_position() < event.version.get() {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    Ok(())
}

fn validate_position_batch(
    position: &ForgePositionStateEntry,
    batch: &ForgeEventBatch,
) -> Result<(), AdmissionError> {
    // A legacy event batch may contain several aggregates. The frontier's
    // count is for this stream, preserving each stream's original wire order.
    let mut count = 0_u32;
    for event in &batch.events {
        if storage::aggregate_label(event.aggregate)? != position.stream() {
            continue;
        }
        count = count
            .checked_add(1)
            .filter(|count| *count <= position.event_count())
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let expected = position
            .predecessor_position()
            .checked_add(u64::from(count))
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if event.version.get() != expected {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    if count != position.event_count() {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(())
}

fn validate_delivery_key(
    repository: RepositoryId,
    entry: &CanonicalOutboxStateEntry,
) -> Result<(), AdmissionError> {
    let expected = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        repository,
        entry.effect_class(),
        entry.destination(),
        entry.payload_root(),
        entry.tx_id(),
        entry.predecessor_rcr_id(),
    ))
    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    if expected != entry.delivery_key() {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(())
}

fn validate_effect_binding(
    repository: RepositoryId,
    entry: &CanonicalOutboxStateEntry,
    effect: &CanonicalOutboxEffectState,
) -> Result<(), AdmissionError> {
    if effect.repository_id() != repository
        || effect.delivery_key() != entry.delivery_key()
        || effect.tx_id() != entry.tx_id()
        || effect.payload_root() != entry.payload_root()
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(())
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
