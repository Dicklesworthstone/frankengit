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

#[cfg(test)]
mod tests {
    //! These tests drive the production Fsqlite immutable-body path. Supplied
    //! successor roots test body resolution, not authority publication; only
    //! the admission integration tests can establish the latter.

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use fgit_authority::ImmutableRead;
    use fgit_codec::harness::{digest_of, tx_id};
    use fgit_forge::{AggregateId, AggregateVersion, ForgeEventPayload, PullRequestNumber};
    use fgit_resource::{LifecycleEvent, ObligationState};
    use fgit_types::{GitOid, GitOidSha1, RefName, TenantId};

    use super::*;
    use crate::{NodeConfig, OneNode, admission_immutable_key};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("frankengit-merge-body-{}-{}",
                std::process::id(), NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed))))
        }

        fn config(&self) -> NodeConfig {
            NodeConfig::new(self.0.clone(), TenantId::from_bytes([0x51; 16]), RepositoryId::from_bytes([0x52; 16]))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn fixture(repository_id: RepositoryId) -> (DeliveryState, ForgeEventBatch, CanonicalOutboxEffectState) {
        let oid = |byte| GitOid::from(GitOidSha1::from_bytes([byte; 20]));
        let event = ForgeEventBatch::of_one(ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
            version: AggregateVersion::FIRST,
            payload: ForgeEventPayload::MergeCommittedNative(fgit_forge::event::NativeMerge {
                source_ref: RefName::try_new(b"refs/heads/topic").expect("source ref"),
                source_tip: oid(1), base_tip: oid(2),
                target_ref: RefName::try_new(b"refs/heads/main").expect("target ref"),
                target_tip_before: oid(3), merge_commit: oid(4),
            }),
        });
        let payload_root = evidence_root(&event).expect("event identity");
        let effect_class = AsciiSlug::from_static("forge-event");
        let destination = AsciiSlug::from_static("forge-projection");
        let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
            repository_id, effect_class, destination, payload_root, tx_id(), None,
        )).expect("stable identity");
        let effect = CanonicalOutboxEffectState::committed(repository_id, key, tx_id(), payload_root);
        let forge = CanonicalForgePositionState::try_new(repository_id, vec![
            ForgePositionStateEntry::try_new(event_stream(&event.events[0]).expect("stream"), 0, 1, payload_root).expect("position"),
        ]).expect("forge map");
        let outbox = CanonicalOutboxState::try_new(repository_id, vec![CanonicalOutboxStateEntry::new(
            key, effect_class, destination, payload_root, tx_id(), None, effect.root().expect("effect root"), None,
        )]).expect("outbox map");
        (DeliveryState { forge, outbox }, event, effect)
    }

    fn selected_head(node: &OneNode, state: &DeliveryState) -> RepositoryAuthorityHeadBody {
        let request = node.request_context();
        let mut head = node.runtime().block_on(node.authenticate_authority_head_in(&request))
            .expect("real head authenticates").body().expect("head decodes");
        head.forge_position_root = state.forge.root().expect("forge root");
        head.outbox_root = state.outbox.root().expect("outbox root");
        head
    }

    #[test]
    fn staged_delivery_bodies_round_trip_after_reopen_without_publishing_their_roots() {
        let scratch = Scratch::new();
        let config = scratch.config();
        let (node, _) = OneNode::init(config.clone()).expect("real Fsqlite node");
        let request = node.request_context();
        let original = node.runtime().block_on(node.read_authority_head_in(&request)).expect("head");
        let (state, event, effect) = fixture(node.repository_id());
        let head = selected_head(&node, &state);
        for _ in 0..2 {
            node.runtime().block_on(stage_in(&node.authority, request.authority(), &state, &event, &effect, &|| false)).expect("immutable staging is retryable");
        }
        let reread = node.runtime().block_on(read_in(&node.authority, request.authority(), node.repository_id(), &head, &|| false)).expect("all staged bodies resolve");
        assert_eq!(reread.forge, state.forge);
        assert_eq!(reread.outbox, state.outbox);
        assert_eq!(reread.forge_positions().values().next(), Some(&ForgeStreamPosition::new(1)));
        assert_eq!(reread.outbox_bindings().values().next(), Some(&effect.payload_root()));
        assert_eq!(node.runtime().block_on(node.read_authority_head_in(&request)).expect("head"), original);
        node.shutdown().expect("first node drains");

        let (reopened, _) = OneNode::init(config).expect("reopen real database");
        let request = reopened.request_context();
        let recovered = reopened.runtime().block_on(read_in(&reopened.authority, request.authority(), reopened.repository_id(), &head, &|| false)).expect("staged bodies survive a clean reopen");
        assert_eq!(recovered.forge, state.forge);
        assert_eq!(recovered.outbox, state.outbox);
        assert_eq!(reopened.runtime().block_on(reopened.read_authority_head_in(&request)).expect("head"), original);
        reopened.shutdown().expect("reopened node drains");
    }

    #[test]
    fn only_exact_legacy_genesis_roots_resolve_without_stored_bodies() {
        let scratch = Scratch::new();
        let (node, _) = OneNode::init(scratch.config()).expect("real Fsqlite node");
        let request = node.request_context();
        let genesis = node.runtime().block_on(node.authenticate_authority_head_in(&request)).expect("head").body().expect("body");
        let empty = node.runtime().block_on(read_in(&node.authority, request.authority(), node.repository_id(), &genesis, &|| false)).expect("exact genesis sentinels");
        assert!(empty.forge.entries().is_empty());
        assert!(empty.outbox.entries().is_empty());
        for forge_missing in [true, false] {
            let mut missing = genesis.clone();
            if forge_missing { missing.forge_position_root = digest_of(0x72); }
            else { missing.outbox_root = digest_of(0x73); }
            assert!(matches!(node.runtime().block_on(read_in(&node.authority, request.authority(), node.repository_id(), &missing, &|| false)),
                Err(AdmissionMaterializationRefusal::ImmutableAbsent(_))));
        }
        assert!(matches!(node.runtime().block_on(read_in(&node.authority, request.authority(), RepositoryId::from_bytes([9; 16]), &genesis, &|| false)),
            Err(AdmissionMaterializationRefusal::RepositoryMismatch { .. })));
        node.shutdown().expect("node drains");
    }

    #[test]
    fn an_event_or_effect_missing_at_a_staging_boundary_refuses_without_empty_fallback() {
        for omit_event in [true, false] {
            let scratch = Scratch::new();
            let (node, _) = OneNode::init(scratch.config()).expect("real Fsqlite node");
            let request = node.request_context();
            let (state, event, effect) = fixture(node.repository_id());
            let head = selected_head(&node, &state);
            node.runtime().block_on(async {
                if omit_event {
                    stage_evidence_body_in(&node.authority, request.authority(), node.repository_id(), EFFECT_STATE_KEY_PREFIX, &effect, &|| false).await.expect("effect only");
                } else {
                    stage_evidence_body_in(&node.authority, request.authority(), node.repository_id(), ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX, &event, &|| false).await.expect("event only");
                }
                stage_evidence_body_in(&node.authority, request.authority(), node.repository_id(), FORGE_POSITION_KEY_PREFIX, &state.forge, &|| false).await.expect("forge map");
                stage_evidence_body_in(&node.authority, request.authority(), node.repository_id(), OUTBOX_KEY_PREFIX, &state.outbox, &|| false).await.expect("outbox map");
            });
            let expected = if omit_event { effect.payload_root() } else { effect.root().expect("root") };
            assert!(matches!(node.runtime().block_on(read_in(&node.authority, request.authority(), node.repository_id(), &head, &|| false)),
                Err(AdmissionMaterializationRefusal::ImmutableAbsent(root)) if root == expected));
            node.runtime().block_on(stage_in(&node.authority, request.authority(), &state, &event, &effect, &|| false)).expect("resume exact staging");
            assert!(node.runtime().block_on(read_in(&node.authority, request.authority(), node.repository_id(), &head, &|| false)).is_ok());
            node.shutdown().expect("node drains");
        }
    }

    #[test]
    fn settlement_rereads_exact_predecessor_and_preserves_original_merge_payload() {
        let scratch = Scratch::new();
        let (node, _) = OneNode::init(scratch.config()).expect("real Fsqlite node");
        let request = node.request_context();
        let (mut state, event, effect) = fixture(node.repository_id());
        let ack = effect.transition(LifecycleEvent::Acknowledge, Some(digest_of(0x41))).expect("observation");
        let old_entry = *state.outbox.entry(effect.delivery_key()).expect("binding");
        state.outbox = CanonicalOutboxState::try_new(node.repository_id(), vec![CanonicalOutboxStateEntry::new(
            old_entry.delivery_key(), old_entry.effect_class(), old_entry.destination(), old_entry.payload_root(), old_entry.tx_id(),
            old_entry.predecessor_rcr_id(), ack.root().expect("ack root"), ack.predecessor_root(),
        )]).expect("successor outbox");
        assert!(matches!(node.runtime().block_on(stage_effect_and_outbox_in(&node.authority, request.authority(), &state.outbox, &ack, &|| false)),
            Err(AdmissionMaterializationRefusal::ImmutableAbsent(root)) if root == effect.root().expect("initial root")));
        let (original, _, _) = fixture(node.repository_id());
        node.runtime().block_on(stage_in(&node.authority, request.authority(), &original, &event, &effect, &|| false)).expect("initial bodies");
        node.runtime().block_on(stage_effect_and_outbox_in(&node.authority, request.authority(), &state.outbox, &ack, &|| false)).expect("verified settlement stages");
        let head = selected_head(&node, &state);
        let loaded = node.runtime().block_on(read_in(&node.authority, request.authority(), node.repository_id(), &head, &|| false)).expect("entire successor resolves");
        let entry = loaded.outbox.entry(effect.delivery_key()).expect("entry retained");
        let verified = node.runtime().block_on(read_effect_in(&node.authority, request.authority(), node.repository_id(), entry, &|| false)).expect("bounded chain");
        assert_eq!(verified.state(), ObligationState::Acknowledged);
        assert_eq!(verified.payload_root(), effect.payload_root());
        assert_eq!(verified.tx_id(), effect.tx_id());
        assert_eq!(verified.predecessor_root(), Some(effect.root().expect("original root")));
        assert_eq!(loaded.forge, original.forge);
        node.shutdown().expect("node drains");
    }

    #[test]
    fn cancellation_and_wrong_stream_ranges_refuse_before_any_body_is_staged() {
        let scratch = Scratch::new();
        let (node, _) = OneNode::init(scratch.config()).expect("real Fsqlite node");
        let request = node.request_context();
        let (state, event, effect) = fixture(node.repository_id());
        assert!(matches!(node.runtime().block_on(stage_in(&node.authority, request.authority(), &state, &event, &effect, &|| true)),
            Err(AdmissionMaterializationRefusal::Cancelled)));
        let wrong = DeliveryState {
            forge: CanonicalForgePositionState::try_new(node.repository_id(), vec![ForgePositionStateEntry::try_new(
                event_stream(&event.events[0]).expect("stream"), 1, 1, effect.payload_root(),
            ).expect("well-formed but wrong range")]).expect("forge map"),
            outbox: state.outbox.clone(),
        };
        assert!(matches!(node.runtime().block_on(stage_in(&node.authority, request.authority(), &wrong, &event, &effect, &|| false)),
            Err(AdmissionMaterializationRefusal::CanonicalRoot(RefusalCode::EvidenceInvalid))));
        let key = admission_immutable_key(ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX, node.repository_id(), effect.payload_root()).expect("event key");
        assert!(matches!(node.runtime().block_on(node.authority.read_immutable(request.authority(), &key)).expect("real immutable read"), ImmutableRead::Absent));
        node.shutdown().expect("node drains");
    }
}
