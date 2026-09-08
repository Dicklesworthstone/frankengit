//! Native publication for the original sealed-package API. Legacy Digest
//! events retain their existing path; a native merge is checked against the
//! complete Ref + Forge + Outbox preparation, never a ref-only validator.

use std::collections::BTreeMap;

use fgit_authority::{AsyncAuthorityStore, ImmutableKey, ImmutableRead, OutcomeLookup, SealAttempt, TerminalOutcome};
use fgit_chronicle::{PublicationBasis, PublicationPlan, verify_pair};
use fgit_codec::{CanonicalBody, CanonicalOutboxState, CryptoBodyIdentity, DecodeLimits, decode_body};
use fgit_forge::{ForgeEventBatch, ForgeEventPayload};
use fgit_reference::intent::OutboxDeliveryKey;
use fgit_types::{Digest, RefusalCode, RepositoryId, TxId};

use super::{AsyncMergeMaterializer, NativeMergeBasis, SealedMerge, legacy, prepare_native_merge, staging};
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, AsyncAdmissionProjection,
    CanonicalRefState, ProjectionFailure};
use crate::evidence::{DecisionEvidenceBodies, evidence_root};

const OUTBOX_NAMESPACE: &[u8] = b"frankengit/admission/outbox-state/v1/";
const EVENT_NAMESPACE: &[u8] = b"frankengit/admission/forge-event-batch/v1/";
const MAX_HISTORY: usize = 4096;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Admit an existing sealed package without changing its transaction identity.
/// Native packages use the same complete preparation as NativeMergeIntent.
/// The supplied materializer must await canonical-source staging before it
/// returns; its record is compared with independently prepared expected bytes.
/// Old Digest-valued packages are not reinterpreted as native Git identities.
///
/// Missing dependencies remain unavailable, not canonical refusals. Every CAS
/// replan reloads its basis and checks both refs, policy and aggregate state.
/// Recovery of an earlier terminal outcome precedes those staleness checks.
pub async fn admit_merge_async<S, P, M>(
    store: &S, cx: &S::Context, context: &AdmissionContext,
    sealed: &SealedMerge<'_>, limits: AdmissionLimits, projection: &P, materializer: &M,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: AsyncAdmissionProjection<S> + ?Sized,
    M: AsyncMergeMaterializer<S> + ?Sized,
{
    limits.validate()?;
    if !matches!(sealed.package.event.payload, ForgeEventPayload::MergeCommittedNative(_)) {
        return legacy::admit_merge_async(store, cx, context, sealed, limits, projection, materializer).await;
    }
    let attempt = legacy::seal_attempt_for(context, sealed)?;
    let admission = fgit_authority::seal_request_async(store, cx, &attempt).await?;
    let tx_id = admission.tx_id();
    for _ in 0..limits.max_cas_replans {
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            store, cx, &context.head_key, context.tenant_id, context.repository_id, tx_id,
        ).await? { return Ok(terminal); }
        let (basis, receipt, authenticated) = crate::read_basis_async(store, cx, &context.head_key).await?;
        let cumulative = fgit_authority::collect_cumulative_outcomes_async(store, cx, &context.head_key).await?;
        if cumulative.observed() != receipt.token() { continue; }
        let prepared: Result<_, PreparationFailure> = async {
            let snapshot = projection.snapshot_async(store, cx, &basis, &authenticated).await?;
            for name in [&sealed.attempt.source_ref, &sealed.attempt.target_ref] {
                if snapshot.hidden_refs.hides(name) {
                    return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
                }
            }
            legacy::check_against_snapshot(sealed, &snapshot)
                .map_err(|stale| ProjectionFailure::Refuse(stale.refusal_code()))?;
            let resolved = resolve_basis(store, cx, context, sealed, tx_id, &attempt, &basis, &snapshot).await?;
            check_open_aggregate(store, cx, sealed, &resolved).await?;
            let expected = prepare_native_merge(context, sealed, tx_id, &attempt, &basis, &resolved)
                .map_err(ProjectionFailure::Refuse)?;
            staging::validate_prepared(&expected)?;
            let produced = materializer.materialize_merge_async(store, cx, context, sealed, tx_id,
                &attempt, &basis, &expected.refs).await?;
            // A callback cannot substitute an empty outbox, omit forge advance,
            // clear HEAD or replace full-fold evidence with a subset witness.
            if produced != expected.materialization {
                return Err(AdmissionError::MaterializationMismatch("complete native merge materialization").into());
            }
            Ok(produced)
        }.await;
        let materialization = match prepared {
            Ok(materialization) => materialization,
            Err(PreparationFailure::Admission(error)) => return Err(*error),
            Err(PreparationFailure::Projection(ProjectionFailure::Unavailable(code))) => return Err(unavailable(code)),
            Err(PreparationFailure::Projection(ProjectionFailure::Refuse(code))) => {
                if let Some(terminal) = crate::publish_refusal_async(store, cx, context, &basis,
                    receipt.token(), admission.seal_id(), tx_id, code, projection, &cumulative).await?
                { return Ok(terminal); }
                continue;
            }
        };
        // The exact expected merge, not a general callback's unchecked roots,
        // reaches the existing authority publication machinery. Source-only
        // receive validation is deliberately left unchanged.
        let mut plan = PublicationPlan::open(basis.clone())?;
        plan.commit(materialization.record);
        let publication = plan.seal(&CryptoBodyIdentity, materialization.roots, &cumulative, receipt.token())?;
        if let Some(terminal) = crate::outcome_after_publish_async(store, cx, context, receipt.token(), &publication).await? {
            return Ok(terminal);
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded { limit: limits.max_cas_replans })
}

async fn resolve_basis<S: AsyncAuthorityStore + ?Sized>(
    store: &S, cx: &S::Context, context: &AdmissionContext, sealed: &SealedMerge<'_>,
    tx_id: TxId, attempt: &SealAttempt, basis: &PublicationBasis, snapshot: &AdmissionSnapshot,
) -> Result<NativeMergeBasis, AdmissionError> {
    let refs = match snapshot.head_target.as_ref() {
        Some(target) => CanonicalRefState::new_with_head_target(snapshot.refs.clone(), target.clone()).map_err(unavailable)?,
        None => CanonicalRefState::new(snapshot.refs.clone()),
    };
    let layout = match fgit_authority::read_repository_configuration_async(
        store, cx, &basis.body().configuration_root,
    ).await {
        Ok(configuration) => configuration.root_layout,
        Err(fgit_authority::OutcomeFailure::Codec(_)) =>
            fgit_authority::read_repository_incarnation_configuration_async(
                store, cx, &basis.body().configuration_root,
            ).await?.root_layout,
        Err(error) => return Err(error.into()),
    };
    if crate::ref_state_root(layout, &refs).map_err(unavailable)? != basis.body().ref_root {
        return Err(unavailable(RefusalCode::AuthorityReceiptStale));
    }
    let forge = super::native::load_forge_positions(store, cx, basis).await?;
    let outbox = match read_frame(store, cx, context.repository_id, OUTBOX_NAMESPACE, basis.body().outbox_root).await? {
        Some(frame) => {
            let state = decode_body::<CanonicalOutboxState>(&frame, DecodeLimits::DEFAULT)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
            if state.repository_id() != context.repository_id || root(&state)? != basis.body().outbox_root {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            state
        }
        None => {
            // Older genesis heads carry a sentinel instead of a state body.
            // A missing advanced root is NOT an empty outbox: prove the entire
            // authenticated prefix carried this root and owed no outbox effects.
            if !snapshot.outbox.is_empty() { return Err(unavailable(RefusalCode::EvidenceMissing)); }
            let request = crate::model_request(context, &attempt.request, tx_id, sealed.closure)?;
            let fold = fgit_txn::IntentEvaluator::new().evaluate(snapshot.as_fold_basis(), &request);
            let evidence = DecisionEvidenceBodies::derive(context, basis, &request, &fold).map_err(unavailable)?;
            let empty_effects = root(evidence.outbox_effect_batch())?;
            prove_empty_outbox_history(store, cx, basis, empty_effects).await?;
            CanonicalOutboxState::try_new(context.repository_id, Vec::new())
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
        }
    };
    let bindings: BTreeMap<_, _> = outbox.entries().iter().map(|entry|
        (OutboxDeliveryKey::new(entry.delivery_key()), entry.payload_root())).collect();
    if bindings != snapshot.outbox { return Err(unavailable(RefusalCode::AuthorityReceiptStale)); }
    Ok(NativeMergeBasis { refs, root_layout: layout, forge, outbox })
}

async fn prove_empty_outbox_history<S: AsyncAuthorityStore + ?Sized>(
    store: &S, cx: &S::Context, basis: &PublicationBasis, empty_effects: Digest,
) -> Result<(), AdmissionError> {
    let expected_root = basis.body().outbox_root;
    let mut successor = basis.body().clone();
    let mut walked = 0;
    while let Some(batch_id) = successor.decision_tail_id {
        if walked == MAX_HISTORY { return Err(unavailable(RefusalCode::ResourceBudgetExceeded)); }
        walked += 1;
        let predecessor_id = successor.predecessor_head_id.ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let predecessor = fgit_authority::read_authority_head_body_async(store, cx, predecessor_id).await?;
        let batch = fgit_authority::read_decision_batch_body_async(store, cx, batch_id).await?;
        verify_pair(&CryptoBodyIdentity, &PublicationBasis::new(predecessor_id, predecessor.clone()), &batch, &successor)
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        if predecessor.outbox_root != expected_root || successor.outbox_root != expected_root
            || batch.committed_rcrs.iter().any(|record| record.outbox_effect_root != empty_effects)
        { return Err(unavailable(RefusalCode::EvidenceMissing)); }
        successor = predecessor;
    }
    if successor.repository_id != basis.body().repository_id || successor.predecessor_head_id.is_some()
        || successor.latest_committed_rcr_id.is_some() || successor.latest_decision_sequence.is_some()
        || successor.outbox_root != expected_root
    { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
    Ok(())
}

async fn check_open_aggregate<S: AsyncAuthorityStore + ?Sized>(
    store: &S, cx: &S::Context, sealed: &SealedMerge<'_>, resolved: &NativeMergeBasis,
) -> Result<(), PreparationFailure> {
    let event = &sealed.package.event;
    let label = fgit_types::AsciiSlug::try_new("forge_stream", event.aggregate.to_string().as_bytes())
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    let previous = resolved.forge.entry(label);
    if previous.map_or(0, |entry| entry.successor_position()) != event.version.get() - 1 {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
    }
    if let Some(entry) = previous {
        let frame = read_frame(store, cx, resolved.forge.repository_id(), EVENT_NAMESPACE, entry.event_batch_root()).await?
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
        let batch = decode_body::<ForgeEventBatch>(&frame, DecodeLimits::DEFAULT)
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        if root(&batch)? != entry.event_batch_root() { return Err(unavailable(RefusalCode::EvidenceInvalid).into()); }
        let last = batch.events.iter().rev().find(|item| item.aggregate == event.aggregate)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if last.version.get() != entry.successor_position() { return Err(unavailable(RefusalCode::EvidenceInvalid).into()); }
        if matches!(last.payload, ForgeEventPayload::MergeCommitted { .. }
            | ForgeEventPayload::MergeCommittedNative(_) | ForgeEventPayload::PullRequestClosed { .. })
        { return Err(ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into()); }
    }
    Ok(())
}

async fn read_frame<S: AsyncAuthorityStore + ?Sized>(
    store: &S, cx: &S::Context, repository: RepositoryId, namespace: &[u8], digest: Digest,
) -> Result<Option<Vec<u8>>, AdmissionError> {
    let mut key = Vec::with_capacity(namespace.len() + 18 + digest.bytes().len());
    key.extend_from_slice(namespace);
    key.extend_from_slice(repository.as_bytes());
    key.extend_from_slice(&digest.algorithm().code_point().to_be_bytes());
    key.extend_from_slice(digest.bytes().as_bytes());
    let key = ImmutableKey::new(key).map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    match store.read_immutable(cx, &key).await? {
        ImmutableRead::Absent => Ok(None),
        ImmutableRead::Present(frame) => {
            if frame.len() > MAX_FRAME_BYTES { return Err(unavailable(RefusalCode::ResourceBudgetExceeded)); }
            Ok(Some(frame))
        }
    }
}

fn root<B: CanonicalBody>(body: &B) -> Result<Digest, AdmissionError> { evidence_root(body).map_err(unavailable) }
fn unavailable(code: RefusalCode) -> AdmissionError { AdmissionError::AsyncProjectionUnavailable(code) }
enum PreparationFailure { Admission(Box<AdmissionError>), Projection(ProjectionFailure) }
impl From<AdmissionError> for PreparationFailure { fn from(value: AdmissionError) -> Self { Self::Admission(Box::new(value)) } }
impl From<ProjectionFailure> for PreparationFailure { fn from(value: ProjectionFailure) -> Self { Self::Projection(value) } }
