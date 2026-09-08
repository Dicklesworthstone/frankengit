//! Bounded delivery from the canonical outbox, with root-last settlement.
//!
//! Deferred ownership is published before contacting a destination. Initial
//! recovery and persisted in-flight calls are probed; authenticated pending
//! progress resumes its next dispatch. Automatic dispatch requires durable
//! downstream idempotency; weaker destinations need a separate fenced owner.

use std::future::Future;

use fgit_authority::{
    AsyncAuthorityStore, OutcomeLookup, ScopedEntry, SealAttempt, SemanticRequest,
};
use fgit_chronicle::PublicationPlan;
use fgit_codec::{
    CanonicalOutboxDeliveryReceipt, CanonicalOutboxEffectState, CanonicalOutboxState,
    CanonicalOutboxStateEntry, CryptoBodyIdentity, OutboxDeliveryDisposition,
};
use fgit_forge::ForgeEventBatch;
use fgit_resource::settlement::{DeliveryVerdict, Observation, ProbeVerdict};
use fgit_resource::{
    DownstreamIdempotency, LifecycleEvent, ObligationState, ReconcilePolicy, ReconcileState,
};
use fgit_types::{AsciiSlug, Digest, DigestBytes, RefusalCode};

use super::progress::CanonicalOutboxProgress;
use super::{delivery, history, storage, unavailable};
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AsyncAdmissionProjection, LoweredRequest,
    PermittedObjectClosure, ProjectionFailure, PublicationPreparation, ValidatedClosure,
};

/// Immutable receipt namespace used by the canonical effect-chain reader.
pub const RECEIPT_NAMESPACE: &[u8] = b"frankengit/admission/outbox-delivery-receipt/v1/";

/// Authorized, immutable parameters supplied to a configured destination.
pub struct DeliveryRequest<'a> {
    /// Stable key; every retry and probe uses these same bytes.
    pub key: AsciiSlug,
    /// Destination from the canonical outbox entry.
    pub destination: AsciiSlug,
    /// Exact committed payload root.
    pub payload_root: Digest,
    /// Payload independently loaded and verified from authority storage.
    pub events: &'a ForgeEventBatch,
}

/// A configured transport capability, not a URL or callback from repository text.
/// Adapters honor `cx`, drain any acquired responsibility before returning, and
/// return the destination's actual bounded evidence with terminal observations.
pub trait OutboxDestination<Context: Sync + ?Sized>: Send {
    /// Configured audience this capability can contact.
    fn destination(&self) -> AsciiSlug;
    /// Required durable idempotency contract of that destination.
    fn idempotency(&self) -> DownstreamIdempotency;
    /// Reconcile an unknown prior call before any resend.
    fn probe<'a>(
        &'a mut self,
        cx: &'a Context,
        request: &'a DeliveryRequest<'_>,
    ) -> impl Future<Output = Result<(ProbeVerdict, Vec<u8>), RefusalCode>> + Send + 'a;
    /// Submit under the same durable idempotency key.
    fn deliver<'a>(
        &'a mut self,
        cx: &'a Context,
        request: &'a DeliveryRequest<'_>,
        attempt: u32,
    ) -> impl Future<Output = Result<(DeliveryVerdict, Vec<u8>), RefusalCode>> + Send + 'a;
}

/// Deliver one authority-selected obligation and publish its resulting lifecycle.
/// No destination call is made until a DeferredExternally transition is durable.
/// Cancellation or unavailable storage leaves the canonical obligation intact.
pub async fn deliver_outbox_async<S, P, D, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    key: AsciiSlug,
    projection: &P,
    destination: &mut D,
    policy: ReconcilePolicy,
    limits: AdmissionLimits,
    checkpoint: &C,
) -> Result<CanonicalOutboxEffectState, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: AsyncAdmissionProjection<S> + ?Sized,
    D: OutboxDestination<S::Context>,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    limits.validate()?;
    if !(2..=16).contains(&policy.max_attempts()) {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    // The canonical progress ceiling bounds useful transitions. Contention is
    // additionally bounded per invocation; retries never reset persisted policy.
    for _ in 0..128 {
        checkpoint().map_err(unavailable)?;
        let (basis, _, _) = crate::read_basis_async(store, cx, &context.head_key).await?;
        let state = delivery::read_in(store, cx, &basis, &|| checkpoint().is_err()).await?;
        let entry = state
            .outbox
            .entry(key)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
        if destination.destination() != entry.destination()
            || entry.effect_class() != AsciiSlug::from_static("forge-event")
            || destination.idempotency() != DownstreamIdempotency::Strong
        {
            return Err(unavailable(RefusalCode::PublicationPolicyRefused));
        }
        let effect = delivery::read_effect_in(store, cx, context.repository_id, entry, &|| {
            checkpoint().is_err()
        })
        .await?;
        if matches!(
            effect.state(),
            ObligationState::Acknowledged
                | ObligationState::TerminallyFailed
                | ObligationState::Escalated
        ) {
            return Ok(effect);
        }
        if effect.state() == ObligationState::Committed {
            let next = effect
                .transition(LifecycleEvent::Defer, None)
                .map_err(codec_error)?;
            publish_mutation(
                store,
                cx,
                context,
                projection,
                entry,
                RuntimeMutation::Lifecycle {
                    next: &next,
                    receipt: None,
                    progress: None,
                },
                limits,
                checkpoint,
            )
            .await?;
            continue;
        }
        if effect.state() != ObligationState::DeferredExternally {
            return Err(unavailable(RefusalCode::PublicationPolicyRefused));
        }
        let latest =
            history::latest_progress(store, cx, &basis, key, &|| checkpoint().is_err()).await?;
        let Some(mut progress) = latest else {
            let initial = CanonicalOutboxProgress::start(
                context.repository_id,
                key,
                entry.destination(),
                entry.payload_root(),
                storage::root(&effect)?,
                policy,
            )
            .map_err(codec_error)?;
            publish_mutation(
                store,
                cx,
                context,
                projection,
                entry,
                RuntimeMutation::Progress(&initial),
                limits,
                checkpoint,
            )
            .await?;
            continue;
        };
        if progress.max_attempts() != policy.max_attempts()
            || progress.origin_effect_root() != storage::root(&effect)?
            || progress.destination() != entry.destination()
            || progress.payload_root() != entry.payload_root()
        {
            return Err(unavailable(RefusalCode::PublicationPolicyRefused));
        }
        if let Some((event, disposition)) = terminal_transition(progress.state()) {
            let receipt = CanonicalOutboxDeliveryReceipt::try_new(
                context.repository_id,
                key,
                entry.destination(),
                entry.payload_root(),
                storage::root(&effect)?,
                disposition,
                progress.evidence().to_vec(),
            )
            .map_err(codec_error)?;
            let next = effect
                .transition(event, Some(storage::root(&receipt)?))
                .map_err(codec_error)?;
            publish_mutation(
                store,
                cx,
                context,
                projection,
                entry,
                RuntimeMutation::Lifecycle {
                    next: &next,
                    receipt: Some(&receipt),
                    progress: Some(&progress),
                },
                limits,
                checkpoint,
            )
            .await?;
            continue;
        }
        let mut dispatch = false;
        if matches!(progress.state(), ReconcileState::Pending { .. })
            && !progress.dispatch_in_flight()
        {
            let marked = progress.mark_dispatch().map_err(codec_error)?;
            if !publish_mutation(
                store,
                cx,
                context,
                projection,
                entry,
                RuntimeMutation::Progress(&marked),
                limits,
                checkpoint,
            )
            .await?
            {
                continue;
            }
            progress = marked;
            dispatch = true;
        }
        let events =
            storage::read_events(store, cx, context.repository_id, entry.payload_root()).await?;
        let request = DeliveryRequest {
            key,
            destination: entry.destination(),
            payload_root: entry.payload_root(),
            events: &events,
        };
        checkpoint().map_err(unavailable)?;
        let (observation, bytes) = if dispatch {
            let (verdict, bytes) = destination
                .deliver(cx, &request, progress.attempt())
                .await
                .map_err(unavailable)?;
            (Observation::Delivery(verdict), bytes)
        } else {
            // Includes a persisted in-flight dispatch from another invocation.
            // Probe under its SAME attempt; never assume cancellation proved absence.
            let (verdict, bytes) = destination.probe(cx, &request).await.map_err(unavailable)?;
            (Observation::Probe(verdict), bytes)
        };
        checkpoint().map_err(unavailable)?;
        if bytes.len() > fgit_codec::MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        let observed = progress.observe(observation, bytes).map_err(codec_error)?;
        publish_mutation(
            store,
            cx,
            context,
            projection,
            entry,
            RuntimeMutation::Progress(&observed),
            limits,
            checkpoint,
        )
        .await?;
    }
    Err(unavailable(RefusalCode::ResourceBudgetExceeded))
}

fn terminal_transition(
    state: ReconcileState,
) -> Option<(LifecycleEvent, OutboxDeliveryDisposition)> {
    match state {
        ReconcileState::Delivered { .. } => Some((
            LifecycleEvent::Acknowledge,
            OutboxDeliveryDisposition::Acknowledged,
        )),
        ReconcileState::Undeliverable { .. } => Some((
            LifecycleEvent::FailTerminally,
            OutboxDeliveryDisposition::TerminallyRefused,
        )),
        ReconcileState::Indeterminate { .. } => Some((
            LifecycleEvent::Escalate,
            OutboxDeliveryDisposition::Indeterminate,
        )),
        _ => None,
    }
}

// Both mutation kinds use the ordinary seal, reference materializer and sole
// authority CAS. Progress is in committed decision history; it is not a second
// database or an uncommitted object interpreted as permission to dispatch.
enum RuntimeMutation<'a> {
    Lifecycle {
        next: &'a CanonicalOutboxEffectState,
        receipt: Option<&'a CanonicalOutboxDeliveryReceipt>,
        progress: Option<&'a CanonicalOutboxProgress>,
    },
    Progress(&'a CanonicalOutboxProgress),
}

impl RuntimeMutation<'_> {
    fn root(&self) -> Result<Digest, AdmissionError> {
        match self {
            Self::Lifecycle { next, .. } => storage::root(*next),
            Self::Progress(body) => storage::root(*body),
        }
    }
    fn predecessor_progress_root(&self) -> Result<Option<Digest>, AdmissionError> {
        match self {
            Self::Lifecycle { progress, .. } => progress.map(storage::root).transpose(),
            Self::Progress(body) => Ok(body.predecessor_progress_root()),
        }
    }
}

// true means this exact mutation is canonically committed; false means the
// selected lifecycle/progress changed and the caller must reload. A refused
// terminal decision NEVER authorizes a call or returns a fabricated successor.
async fn publish_mutation<S, P, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    projection: &P,
    original: &CanonicalOutboxStateEntry,
    mutation: RuntimeMutation<'_>,
    limits: AdmissionLimits,
    checkpoint: &C,
) -> Result<bool, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: AsyncAdmissionProjection<S> + ?Sized,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    let next_root = mutation.root()?;
    let semantic = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![ScopedEntry::new(
            AsciiSlug::from_static("outbox"),
            AsciiSlug::from_static("runtime-successor"),
            next_root.bytes().as_bytes(),
        )?],
    )?;
    let mut settlement_context = context.clone();
    settlement_context.idempotency_key = fgit_authority::IdempotencyKey::new(
        format!(
            "outbox/{}",
            fgit_crypto::lowercase_hex(next_root.bytes().as_bytes())
        )
        .into_bytes(),
    )?;
    let attempt = SealAttempt {
        tenant_id: context.tenant_id,
        repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: settlement_context.idempotency_key.clone(),
        request: semantic.clone(),
    };
    let admission = fgit_authority::seal_request_async(store, cx, &attempt).await?;
    let lowered = LoweredRequest {
        semantic,
        idempotency_key: settlement_context.idempotency_key.clone(),
    };
    let empty = PermittedObjectClosure::default();
    let closure = ValidatedClosure {
        objects: empty.objects().clone(),
        object_closure_root: crate::permitted_object_closure_root(&empty).map_err(unavailable)?,
    };
    for _ in 0..limits.max_cas_replans {
        checkpoint().map_err(unavailable)?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            store,
            cx,
            &context.head_key,
            context.tenant_id,
            context.repository_id,
            admission.tx_id(),
        )
        .await?
        {
            return committed(terminal);
        }
        let (basis, head_receipt, authenticated) =
            crate::read_basis_async(store, cx, &context.head_key).await?;
        let cumulative =
            fgit_authority::collect_cumulative_outcomes_async(store, cx, &context.head_key).await?;
        if cumulative.observed() != head_receipt.token() {
            continue;
        }
        let state = delivery::read_in(store, cx, &basis, &|| checkpoint().is_err()).await?;
        let entry = state
            .outbox
            .entry(original.delivery_key())
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
        if entry != original {
            return Ok(false);
        }
        let previous =
            history::latest_progress(store, cx, &basis, original.delivery_key(), &|| {
                checkpoint().is_err()
            })
            .await?;
        if previous.as_ref().map(storage::root).transpose()?
            != mutation.predecessor_progress_root()?
        {
            return Ok(false);
        }
        if let RuntimeMutation::Progress(next) = &mutation {
            if next.origin_effect_root() != entry.effect_state_root() {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            if let Some(previous) = previous.as_ref() {
                next.verify_successor_of(previous).map_err(codec_error)?;
            }
        }
        let snapshot = projection
            .snapshot_async(store, cx, &basis, &authenticated)
            .await
            .map_err(projection_error)?;
        let prepared = match crate::prepare_publication_from_snapshot(
            &settlement_context,
            &lowered,
            &closure,
            admission.tx_id(),
            snapshot,
        )? {
            PublicationPreparation::Commit(prepared) => prepared,
            PublicationPreparation::Refuse(code) => return Err(unavailable(code)),
        };
        let mut materialization = projection
            .materialize_commit_async(
                store,
                cx,
                &basis,
                &prepared.request,
                &prepared.fold,
                &closure,
            )
            .await
            .map_err(projection_error)?;
        crate::validate_commit_materialization(
            &settlement_context,
            &basis,
            admission.tx_id(),
            &attempt.request,
            &closure,
            &materialization,
        )?;
        if materialization.roots.ref_root != basis.body().ref_root
            || materialization.roots.forge_position_root != basis.body().forge_position_root
            || materialization.roots.retention_root != basis.body().retention_root
            || materialization.roots.outbox_root != basis.body().outbox_root
            || materialization.roots.policy_epoch != basis.body().policy_epoch
            || materialization.roots.compaction_generation_link.is_some()
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        match &mutation {
            RuntimeMutation::Lifecycle { next, receipt, .. } => {
                let mut entries = state.outbox.entries().to_vec();
                let slot = entries
                    .iter_mut()
                    .find(|entry| entry.delivery_key() == original.delivery_key())
                    .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
                *slot = CanonicalOutboxStateEntry::new(
                    entry.delivery_key(),
                    entry.effect_class(),
                    entry.destination(),
                    entry.payload_root(),
                    entry.tx_id(),
                    entry.predecessor_rcr_id(),
                    next_root,
                    Some(entry.effect_state_root()),
                );
                let outbox = CanonicalOutboxState::try_new(context.repository_id, entries)
                    .map_err(codec_error)?;
                if let Some(receipt) = receipt {
                    checkpoint().map_err(unavailable)?;
                    storage::stage_body(
                        store,
                        cx,
                        context.repository_id,
                        RECEIPT_NAMESPACE,
                        *receipt,
                    )
                    .await?;
                }
                delivery::stage_effect_and_outbox_in(store, cx, &outbox, next, &|| {
                    checkpoint().is_err()
                })
                .await?;
                stage_runtime_evidence(store, cx, context, *next, checkpoint).await?;
                materialization.roots.outbox_root = storage::root(&outbox)?;
            }
            RuntimeMutation::Progress(body) => {
                stage_runtime_evidence(store, cx, context, *body, checkpoint).await?;
            }
        }
        materialization.record.invariant_evidence_root = next_root;
        materialization.record.outbox_effect_root = next_root;
        let mut plan = PublicationPlan::open(basis)?;
        plan.commit(materialization.record);
        let publication = plan.seal(
            &CryptoBodyIdentity,
            materialization.roots,
            &cumulative,
            head_receipt.token(),
        )?;
        checkpoint().map_err(unavailable)?;
        if let Some(terminal) = crate::outcome_after_publish_async(
            store,
            cx,
            &settlement_context,
            head_receipt.token(),
            &publication,
        )
        .await?
        {
            return committed(terminal);
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded {
        limit: limits.max_cas_replans,
    })
}

async fn stage_runtime_evidence<S, B, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    body: &B,
    checkpoint: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    B: fgit_codec::CanonicalBody + Sync,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    checkpoint().map_err(unavailable)?;
    storage::stage_body(
        store,
        cx,
        context.repository_id,
        history::OUTBOX_EFFECT_NAMESPACE,
        body,
    )
    .await?;
    checkpoint().map_err(unavailable)?;
    storage::stage_body(
        store,
        cx,
        context.repository_id,
        storage::INVARIANT_NAMESPACE,
        body,
    )
    .await?;
    checkpoint().map_err(unavailable)
}

fn committed(terminal: fgit_authority::TerminalOutcome) -> Result<bool, AdmissionError> {
    match terminal.outcome {
        fgit_types::DecisionOutcome::Committed { .. } => Ok(true),
        fgit_types::DecisionOutcome::Refused { code, .. } => Err(unavailable(code)),
    }
}

fn codec_error(_: fgit_codec::CodecRefusal) -> AdmissionError {
    unavailable(RefusalCode::EvidenceInvalid)
}

fn projection_error(error: ProjectionFailure) -> AdmissionError {
    match error {
        ProjectionFailure::Unavailable(code) | ProjectionFailure::Refuse(code) => unavailable(code),
    }
}

pub(super) fn resource_key(
    key: AsciiSlug,
) -> Result<fgit_resource::IdempotencyKey, AdmissionError> {
    if key.as_bytes().len() != 64 {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let mut bytes = [0_u8; 32];
    for (target, pair) in bytes.iter_mut().zip(key.as_bytes().chunks_exact(2)) {
        let text =
            std::str::from_utf8(pair).map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        *target =
            u8::from_str_radix(text, 16).map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    }
    Ok(fgit_resource::IdempotencyKey::new(Digest::new(
        fgit_crypto::IdentityDomain::Generation.algorithm().id(),
        DigestBytes::try_new(&bytes).map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?,
    )))
}

#[cfg(test)]
mod tests;
