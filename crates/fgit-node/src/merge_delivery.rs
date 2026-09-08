//! Canonical forge/outbox state in the node's existing immutable body store.
//!
//! Every read starts from authority-selected roots and verifies its immutable
//! dependencies. These helpers stage bodies; only the enclosing admission or
//! settlement publication may make their roots visible through head CAS.

use std::collections::BTreeMap;

use fgit_authority::AsyncAuthorityStore;
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxEffectState, CanonicalOutboxState,
    CanonicalOutboxStateEntry, ForgePositionStateEntry, OutboxDeliveryIdentityInput, RepositoryAuthorityHeadBody,
    derive_outbox_delivery_key,
};
use fgit_forge::{ForgeEvent, ForgeEventBatch};
use fgit_reference::intent::{ForgeStreamId, ForgeStreamPosition, OutboxDeliveryKey};
use fgit_types::{AsciiSlug, Digest, RefusalCode, RepositoryId};

use super::{
    ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX, AdmissionMaterializationRefusal,
    ensure_materializer_catch_up_live, evidence_root, genesis_root, read_evidence_body_in,
    stage_evidence_body_in,
};

pub(crate) const FORGE_POSITION_KEY_PREFIX: &[u8] =
    b"frankengit/admission/forge-position-state/v1/";
pub(crate) const OUTBOX_KEY_PREFIX: &[u8] = b"frankengit/admission/outbox-state/v1/";
pub(crate) const EFFECT_STATE_KEY_PREFIX: &[u8] =
    b"frankengit/admission/outbox-effect-state/v1/";

/// One immutable authority-selected pair, never an independent pending table.
#[derive(Clone, Debug)]
pub(crate) struct DeliveryState {
    pub(crate) forge: CanonicalForgePositionState,
    pub(crate) outbox: CanonicalOutboxState,
}

impl DeliveryState {
    pub(crate) fn forge_positions(&self) -> BTreeMap<ForgeStreamId, ForgeStreamPosition> {
        self.forge.entries().iter().map(|entry| {
            (ForgeStreamId::new(entry.stream()), ForgeStreamPosition::new(entry.successor_position()))
        }).collect()
    }

    pub(crate) fn outbox_bindings(&self) -> BTreeMap<OutboxDeliveryKey, Digest> {
        self.outbox.entries().iter().map(|entry| {
            (OutboxDeliveryKey::new(entry.delivery_key()), entry.payload_root())
        }).collect()
    }
}

/// Aggregate spelling is owned by the canonical forge aggregate type.
pub(crate) fn event_stream(event: &ForgeEvent) -> Result<AsciiSlug, AdmissionMaterializationRefusal> {
    AsciiSlug::try_new("forge_stream", event.aggregate.to_string().as_bytes())
        .map_err(|error| AdmissionMaterializationRefusal::CanonicalFrame(error.into()))
}

/// Resolve both roots and every retained payload/effect dependency. The two
/// exact legacy empty-genesis sentinels are the only bodies omitted by old
/// repository initialization; arbitrary absence never means an empty map.
pub(crate) async fn read_in<Authority, IsCancelled>(
    authority: &Authority,
    cx: &Authority::Context,
    repository_id: RepositoryId,
    head: &RepositoryAuthorityHeadBody,
    is_cancelled: &IsCancelled,
) -> Result<DeliveryState, AdmissionMaterializationRefusal>
where
    Authority: AsyncAuthorityStore + ?Sized,
    IsCancelled: Fn() -> bool + Sync,
{
    ensure_materializer_catch_up_live(is_cancelled)?;
    require_repository(repository_id, head.repository_id)?;
    let forge = if head.forge_position_root == genesis_root(repository_id, b"forge-position") {
        CanonicalForgePositionState::try_new(repository_id, Vec::new())
            .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?
    } else {
        read_evidence_body_in(authority, cx, repository_id, FORGE_POSITION_KEY_PREFIX,
            head.forge_position_root, is_cancelled).await?
    };
    let outbox = if head.outbox_root == genesis_root(repository_id, b"outbox") {
        CanonicalOutboxState::try_new(repository_id, Vec::new())
            .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?
    } else {
        read_evidence_body_in(authority, cx, repository_id, OUTBOX_KEY_PREFIX,
            head.outbox_root, is_cancelled).await?
    };
    require_repository(repository_id, forge.repository_id())?;
    require_repository(repository_id, outbox.repository_id())?;
    let state = DeliveryState { forge, outbox };

    // A stream root may not authenticate a position whose last event body is
    // absent, belongs to a different aggregate, or has a different sequence.
    for entry in state.forge.entries() {
        let batch: ForgeEventBatch = read_evidence_body_in(authority, cx, repository_id,
            ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX, entry.event_batch_root(), is_cancelled).await?;
        validate_position_batch(entry, &batch)?;
    }
    for entry in state.outbox.entries() {
        read_effect_in(authority, cx, repository_id, entry, is_cancelled).await?;
        let payload: ForgeEventBatch = read_evidence_body_in(authority, cx, repository_id,
            ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX, entry.payload_root(), is_cancelled).await?;
        validate_payload_position(&state, &payload)?;
    }
    ensure_materializer_catch_up_live(is_cancelled)?;
    Ok(state)
}

/// Verify a current effect and its complete, bounded immutable predecessor
/// chain. The codec checks local transition legality; this reader establishes
/// that the recorded predecessor really is the committed predecessor body.
pub(crate) async fn read_effect_in<Authority, IsCancelled>(
    authority: &Authority,
    cx: &Authority::Context,
    repository_id: RepositoryId,
    entry: &CanonicalOutboxStateEntry,
    is_cancelled: &IsCancelled,
) -> Result<CanonicalOutboxEffectState, AdmissionMaterializationRefusal>
where
    Authority: AsyncAuthorityStore + ?Sized,
    IsCancelled: Fn() -> bool + Sync,
{
    validate_delivery_key(repository_id, entry)?;
    let latest: CanonicalOutboxEffectState = read_evidence_body_in(authority, cx, repository_id,
        EFFECT_STATE_KEY_PREFIX, entry.effect_state_root(), is_cancelled).await?;
    validate_effect_binding(repository_id, entry, &latest)?;
    if latest.predecessor_root() != entry.predecessor_effect_state_root() {
        return Err(invalid());
    }
    let mut current = latest.clone();
    while let Some(root) = current.predecessor_root() {
        // Decode bounds the ordinal to three; checking it descends exactly
        // prevents a cycle from making this loop unbounded.
        let previous: CanonicalOutboxEffectState = read_evidence_body_in(authority, cx,
            repository_id, EFFECT_STATE_KEY_PREFIX, root, is_cancelled).await?;
        validate_effect_binding(repository_id, entry, &previous)?;
        if previous.transition_ordinal().checked_add(1) != Some(current.transition_ordinal())
            || Some(previous.state()) != current.predecessor_state()
        {
            return Err(invalid());
        }
        let Some(event) = current.event() else { return Err(invalid()); };
        let reproduced = previous.transition(event, current.evidence_root())
            .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
        if reproduced != current {
            return Err(invalid());
        }
        current = previous;
    }
    if current.transition_ordinal() != 0 {
        return Err(invalid());
    }
    Ok(latest)
}

/// Stage a merge's complete delivery successor before the authority CAS. Every
/// immutable put is awaited through the production store's transaction path.
pub(crate) async fn stage_in<Authority, IsCancelled>(
    authority: &Authority,
    cx: &Authority::Context,
    state: &DeliveryState,
    event: &ForgeEventBatch,
    effect: &CanonicalOutboxEffectState,
    is_cancelled: &IsCancelled,
) -> Result<(), AdmissionMaterializationRefusal>
where
    Authority: AsyncAuthorityStore + ?Sized,
    IsCancelled: Fn() -> bool + Sync,
{
    let repository_id = state.forge.repository_id();
    require_repository(repository_id, state.outbox.repository_id())?;
    let Some(entry) = state.outbox.entry(effect.delivery_key()) else { return Err(invalid()); };
    validate_delivery_key(repository_id, entry)?;
    validate_effect_binding(repository_id, entry, effect)?;
    if effect.transition_ordinal() != 0
        || entry.predecessor_effect_state_root().is_some()
        || entry.effect_state_root() != effect.root().map_err(AdmissionMaterializationRefusal::CanonicalFrame)?
        || entry.payload_root() != evidence_root(event).map_err(AdmissionMaterializationRefusal::CanonicalRoot)?
    {
        return Err(invalid());
    }
    validate_payload_position(state, event)?;
    for item in &event.events {
        let stream = event_stream(item)?;
        let Some(position) = state.forge.entry(stream) else { return Err(invalid()); };
        if position.event_batch_root() != entry.payload_root()
        {
            return Err(invalid());
        }
        validate_position_batch(position, event)?;
    }
    stage_evidence_body_in(authority, cx, repository_id, ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
        event, is_cancelled).await?;
    stage_evidence_body_in(authority, cx, repository_id, EFFECT_STATE_KEY_PREFIX,
        effect, is_cancelled).await?;
    stage_evidence_body_in(authority, cx, repository_id, FORGE_POSITION_KEY_PREFIX,
        &state.forge, is_cancelled).await?;
    stage_evidence_body_in(authority, cx, repository_id, OUTBOX_KEY_PREFIX,
        &state.outbox, is_cancelled).await
}

/// Stage one settlement successor and its outbox index. The caller publishes
/// the corresponding normal authority decision after these bodies are staged.
pub(crate) async fn stage_effect_and_outbox_in<Authority, IsCancelled>(
    authority: &Authority,
    cx: &Authority::Context,
    outbox: &CanonicalOutboxState,
    effect: &CanonicalOutboxEffectState,
    is_cancelled: &IsCancelled,
) -> Result<(), AdmissionMaterializationRefusal>
where
    Authority: AsyncAuthorityStore + ?Sized,
    IsCancelled: Fn() -> bool + Sync,
{
    let repository_id = outbox.repository_id();
    let Some(entry) = outbox.entry(effect.delivery_key()) else { return Err(invalid()); };
    validate_delivery_key(repository_id, entry)?;
    validate_effect_binding(repository_id, entry, effect)?;
    if effect.transition_ordinal() == 0
        || entry.predecessor_effect_state_root() != effect.predecessor_root()
        || entry.effect_state_root() != effect.root().map_err(AdmissionMaterializationRefusal::CanonicalFrame)?
    {
        return Err(invalid());
    }
    let Some(previous_root) = effect.predecessor_root() else { return Err(invalid()); };
    let previous: CanonicalOutboxEffectState = read_evidence_body_in(authority, cx, repository_id,
        EFFECT_STATE_KEY_PREFIX, previous_root, is_cancelled).await?;
    let Some(event) = effect.event() else { return Err(invalid()); };
    if previous.transition(event, effect.evidence_root())
        .map_err(AdmissionMaterializationRefusal::CanonicalFrame)? != *effect
    {
        return Err(invalid());
    }
    stage_evidence_body_in(authority, cx, repository_id, EFFECT_STATE_KEY_PREFIX,
        effect, is_cancelled).await?;
    stage_evidence_body_in(authority, cx, repository_id, OUTBOX_KEY_PREFIX,
        outbox, is_cancelled).await
}

fn validate_payload_position(state: &DeliveryState, payload: &ForgeEventBatch)
    -> Result<(), AdmissionMaterializationRefusal>
{
    if payload.events.is_empty() { return Err(invalid()); }
    for event in &payload.events {
        let Some(position) = state.forge.entry(event_stream(event)?) else { return Err(invalid()); };
        if position.successor_position() < event.version.get() { return Err(invalid()); }
    }
    Ok(())
}

fn validate_position_batch(position: &ForgePositionStateEntry, batch: &ForgeEventBatch)
    -> Result<(), AdmissionMaterializationRefusal>
{
    if batch.events.len() != position.event_count() as usize {
        return Err(invalid());
    }
    for (index, event) in batch.events.iter().enumerate() {
        // Position construction already established the complete range cannot
        // overflow, and the length comparison above bounds this index.
        if event_stream(event)? != position.stream()
            || event.version.get() != position.predecessor_position() + index as u64 + 1
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_delivery_key(repository_id: RepositoryId, entry: &CanonicalOutboxStateEntry)
    -> Result<(), AdmissionMaterializationRefusal>
{
    let expected = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        repository_id, entry.effect_class(), entry.destination(), entry.payload_root(),
        entry.tx_id(), entry.predecessor_rcr_id(),
    )).map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
    if expected != entry.delivery_key() { return Err(invalid()); }
    Ok(())
}

fn validate_effect_binding(repository_id: RepositoryId, entry: &CanonicalOutboxStateEntry,
    effect: &CanonicalOutboxEffectState) -> Result<(), AdmissionMaterializationRefusal>
{
    require_repository(repository_id, effect.repository_id())?;
    if effect.delivery_key() != entry.delivery_key()
        || effect.tx_id() != entry.tx_id()
        || effect.payload_root() != entry.payload_root()
    { return Err(invalid()); }
    Ok(())
}

fn require_repository(expected: RepositoryId, observed: RepositoryId)
    -> Result<(), AdmissionMaterializationRefusal>
{
    if expected != observed {
        return Err(AdmissionMaterializationRefusal::RepositoryMismatch { expected, observed });
    }
    Ok(())
}

fn invalid() -> AdmissionMaterializationRefusal {
    AdmissionMaterializationRefusal::CanonicalRoot(RefusalCode::EvidenceInvalid)
}
