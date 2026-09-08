//! Awaited placement of a complete native merge in the existing authority
//! namespaces. There is no synchronous staging adapter and no publication here.

use fgit_authority::{AsyncAuthorityStore, ImmutableKey, PutOutcome};
use fgit_codec::{CanonicalBody, CanonicalOutboxEffectState, encode_body};
use fgit_types::{Digest, RefusalCode, RepositoryId};

use super::PreparedNativeMerge;
use crate::AdmissionError;
use crate::evidence::{evidence_root, principal_snapshot_id};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const REF_STATE: &[u8] = b"frankengit/admission/ref-state/v1/";
const CLOSURE: &[u8] = b"frankengit/admission/object-closure/v1/";
const PRINCIPAL: &[u8] = b"frankengit/admission/principal-snapshot/v1/";
const POLICY: &[u8] = b"frankengit/admission/policy-decision/v1/";
const INVARIANT: &[u8] = b"frankengit/admission/invariant-evidence/v1/";
const EVENT: &[u8] = b"frankengit/admission/forge-event-batch/v1/";
const FORGE: &[u8] = b"frankengit/admission/forge-position-state/v1/";
const OUTBOX: &[u8] = b"frankengit/admission/outbox-state/v1/";
const EFFECT: &[u8] = b"frankengit/admission/outbox-effect-state/v1/";
const OUTBOX_EVIDENCE: &[u8] = b"frankengit/admission/outbox-effect-batch/v1/";
const RETENTION: &[u8] = b"frankengit/admission/retention-delta/v1/";

/// Check all body/record links before the first write. The preparation itself
/// was derived against an authenticated predecessor, not supplied by a client.
pub(crate) fn validate_prepared(prepared: &PreparedNativeMerge) -> Result<(), AdmissionError> {
    let record = &prepared.materialization.record;
    let roots = &prepared.materialization.roots;
    let repository = record.repository_id;
    let event_root = root(&prepared.event)?;
    let effect_root = prepared.effect.root().map_err(|_| invalid())?;
    let entry = prepared.outbox.entry(prepared.effect.delivery_key()).ok_or_else(invalid)?;
    if prepared.event.events.len() != 1
        || prepared.request.tx_id != record.tx_id
        || prepared.request.repository != repository
        || prepared.request.canonical_request_digest != record.canonical_request_digest
        || prepared.forge.repository_id() != repository
        || prepared.outbox.repository_id() != repository
        || prepared.effect != CanonicalOutboxEffectState::committed(repository,
            prepared.effect.delivery_key(), record.tx_id, event_root)
        || entry.effect_state_root() != effect_root
        || entry.predecessor_effect_state_root().is_some()
        || entry.tx_id() != record.tx_id || entry.payload_root() != event_root
        || record.resulting_ref_root != roots.ref_root
        || crate::ref_state_root(prepared.root_layout, &prepared.refs).map_err(unavailable)? != roots.ref_root
        || crate::permitted_object_closure_root(&prepared.closure).map_err(unavailable)? != record.object_closure_root
        || event_root != record.forge_event_batch_root
        || root(&prepared.forge)? != roots.forge_position_root
        || record.resulting_forge_position_root != roots.forge_position_root
        || root(&prepared.outbox)? != roots.outbox_root
        || record.policy_epoch != roots.policy_epoch
        || roots.compaction_generation_link.is_some()
        || principal_snapshot_id(prepared.evidence.principal_snapshot()).map_err(unavailable)? != record.principal_snapshot_id
        || root(prepared.evidence.policy_decision())? != record.policy_decision_root
        || root(prepared.evidence.invariant_evidence())? != record.invariant_evidence_root
        || root(prepared.evidence.outbox_effect_batch())? != record.outbox_effect_root
        || root(prepared.evidence.retention_delta())? != record.retention_delta_root
    {
        return Err(invalid());
    }
    fgit_txn::IntentEvaluator::new().validate_report(&prepared.request, &prepared.fold)
        .map_err(unavailable)?;
    let event = &prepared.event.events[0];
    let stream = fgit_types::AsciiSlug::try_new("forge_stream", event.aggregate.to_string().as_bytes())
        .map_err(|_| invalid())?;
    let position = prepared.forge.entry(stream).ok_or_else(invalid)?;
    if position.event_count() != 1 || position.event_batch_root() != event_root
        || position.successor_position() != event.version.get()
    {
        return Err(invalid());
    }
    let key = fgit_codec::derive_outbox_delivery_key(fgit_codec::OutboxDeliveryIdentityInput::new(
        repository, entry.effect_class(), entry.destination(), entry.payload_root(),
        entry.tx_id(), entry.predecessor_rcr_id(),
    )).map_err(|_| invalid())?;
    if key != entry.delivery_key() { return Err(invalid()); }
    Ok(())
}

/// Persist every dependency through the same request-owned async authority
/// store used for the head CAS. Errors preserve undecided status. Identical
/// orphaned bodies from an interrupted or losing attempt are safe to reuse.
pub(crate) async fn stage_prepared<S: AsyncAuthorityStore + ?Sized>(
    store: &S, cx: &S::Context, prepared: &PreparedNativeMerge,
) -> Result<(), AdmissionError> {
    validate_prepared(prepared)?;
    let record = &prepared.materialization.record;
    let repository = record.repository_id;
    // Ref roots are configuration-selected (whole-body or Merkle). The stored
    // frame is still the full canonical state; do not key a Merkle repository
    // by the frame's unrelated whole-body digest.
    stage_at(store, cx, repository, REF_STATE, record.resulting_ref_root, &prepared.refs).await?;
    stage(store, cx, repository, CLOSURE, &prepared.closure).await?;
    stage(store, cx, repository, PRINCIPAL, prepared.evidence.principal_snapshot()).await?;
    stage(store, cx, repository, POLICY, prepared.evidence.policy_decision()).await?;
    stage(store, cx, repository, INVARIANT, prepared.evidence.invariant_evidence()).await?;
    stage(store, cx, repository, EVENT, prepared.evidence.forge_event_batch()).await?;
    stage(store, cx, repository, OUTBOX_EVIDENCE, prepared.evidence.outbox_effect_batch()).await?;
    stage(store, cx, repository, RETENTION, prepared.evidence.retention_delta()).await?;
    stage(store, cx, repository, EVENT, &prepared.event).await?;
    stage(store, cx, repository, EFFECT, &prepared.effect).await?;
    stage(store, cx, repository, FORGE, &prepared.forge).await?;
    stage(store, cx, repository, OUTBOX, &prepared.outbox).await
}

async fn stage<S: AsyncAuthorityStore + ?Sized, B: CanonicalBody + Sync>(
    store: &S, cx: &S::Context, repository: RepositoryId, namespace: &[u8], body: &B,
) -> Result<(), AdmissionError> {
    stage_at(store, cx, repository, namespace, root(body)?, body).await
}

async fn stage_at<S: AsyncAuthorityStore + ?Sized, B: CanonicalBody + Sync>(
    store: &S, cx: &S::Context, repository: RepositoryId,
    namespace: &[u8], digest: Digest, body: &B,
) -> Result<(), AdmissionError> {
    let frame = encode_body(body).map_err(|_| unavailable(RefusalCode::CanonicalFramingInvalid))?;
    if frame.len() > MAX_FRAME_BYTES {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    let mut bytes = Vec::with_capacity(namespace.len() + 18 + digest.bytes().len());
    bytes.extend_from_slice(namespace);
    bytes.extend_from_slice(repository.as_bytes());
    bytes.extend_from_slice(&digest.algorithm().code_point().to_be_bytes());
    bytes.extend_from_slice(digest.bytes().as_bytes());
    let key = ImmutableKey::new(bytes).map_err(|_| invalid())?;
    match store.put_if_absent(cx, &key, &frame).await? {
        PutOutcome::Created | PutOutcome::IdenticalRetry => Ok(()),
        PutOutcome::Conflict => Err(invalid()),
    }
}

fn root<B: CanonicalBody>(body: &B) -> Result<Digest, AdmissionError> {
    evidence_root(body).map_err(unavailable)
}
fn unavailable(code: RefusalCode) -> AdmissionError { AdmissionError::AsyncProjectionUnavailable(code) }
fn invalid() -> AdmissionError { unavailable(RefusalCode::EvidenceInvalid) }
