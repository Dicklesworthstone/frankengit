//! Bounded delivery from the canonical outbox, with root-last settlement.
//!
//! Deferred ownership is published before contacting a destination. Initial
//! recovery and persisted in-flight calls are probed; authenticated pending
//! progress resumes its next dispatch. Automatic dispatch requires durable
//! downstream idempotency; weaker destinations need a separate fenced owner.

pub(super) mod publication;

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
        if destination.idempotency() != DownstreamIdempotency::Strong {
            return Err(unavailable(RefusalCode::PublicationPolicyRefused));
        }
        let Some(entry) = state.outbox.entry(key) else {
            return history::retired_effect(
                store,
                cx,
                &basis,
                key,
                destination.destination(),
                &|| checkpoint().is_err(),
            )
            .await?
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing));
        };
        if destination.destination() != entry.destination()
            || entry.effect_class() != AsciiSlug::from_static("forge-event")
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
            if retired_state(effect.state()) {
                let progress =
                    history::latest_progress_for_entry(store, cx, &basis, entry, &|| {
                        checkpoint().is_err()
                    })
                    .await?;
                publish_mutation(
                    store,
                    cx,
                    context,
                    projection,
                    entry,
                    RuntimeMutation::Retirement {
                        effect: &effect,
                        progress: progress.as_ref(),
                    },
                    limits,
                    checkpoint,
                )
                .await?;
                continue;
            }
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
            history::latest_progress_for_entry(store, cx, &basis, entry, &|| checkpoint().is_err())
                .await?;
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
        let dispatch = if matches!(progress.state(), ReconcileState::Pending { .. })
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
            true
        } else {
            false
        };
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

const fn terminal_transition(
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

// All mutation kinds use the ordinary seal, reference materializer and sole
// authority CAS. Progress is in committed decision history; it is not a second
// database or an uncommitted object interpreted as permission to dispatch.
pub(super) enum RuntimeMutation<'a> {
    Dispatch {
        next: &'a super::dispatch::CanonicalDispatchProgress,
        effect: Option<&'a CanonicalOutboxEffectState>,
        receipt: Option<&'a CanonicalOutboxDeliveryReceipt>,
    },
    Lifecycle {
        next: &'a CanonicalOutboxEffectState,
        receipt: Option<&'a CanonicalOutboxDeliveryReceipt>,
        progress: Option<&'a CanonicalOutboxProgress>,
    },
    Progress(&'a CanonicalOutboxProgress),
    Retirement {
        effect: &'a CanonicalOutboxEffectState,
        progress: Option<&'a CanonicalOutboxProgress>,
    },
}

impl RuntimeMutation<'_> {
    fn root(&self) -> Result<Digest, AdmissionError> {
        match self {
            Self::Dispatch { next, .. } => storage::root(*next),
            Self::Lifecycle { next, .. } => storage::root(*next),
            Self::Progress(body) => storage::root(*body),
            Self::Retirement { effect, .. } => storage::root(*effect),
        }
    }
    fn predecessor_progress_root(&self) -> Result<Option<Digest>, AdmissionError> {
        match self {
            Self::Dispatch { next, .. } => Ok(next.predecessor_progress_root()),
            Self::Lifecycle { progress, .. } => progress.map(storage::root).transpose(),
            Self::Progress(body) => Ok(body.predecessor_progress_root()),
            Self::Retirement { progress, .. } => progress.map(storage::root).transpose(),
        }
    }
}

// true means this invocation won the exact publication CAS and authenticated
// its commit. false means recovery or changed state: reload and probe rather
// than sending under another invocation's marker. A refusal never authorizes I/O.
pub(super) async fn publish_mutation<S, P, C>(
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
    // Retiring a legacy retained terminal entry is a distinct sealed intent
    // from its earlier lifecycle publication, even though both name the same
    // immutable terminal effect. Never reuse a decided seal with new semantics.
    let retiring = matches!(&mutation, RuntimeMutation::Retirement { .. });
    let semantic = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![ScopedEntry::new(
            AsciiSlug::from_static("outbox"),
            if matches!(&mutation, RuntimeMutation::Dispatch { .. }) {
                AsciiSlug::from_static("fenced-dispatch")
            } else if retiring {
                AsciiSlug::from_static("retire-settled")
            } else {
                AsciiSlug::from_static("runtime-successor")
            },
            next_root.bytes().as_bytes(),
        )?],
    )?;
    let mut settlement_context = context.clone();
    settlement_context.idempotency_key = fgit_authority::IdempotencyKey::new(
        format!(
            "outbox/{}{}",
            if retiring { "retire/" } else { "" },
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
        let (basis, head_receipt, authenticated) =
            crate::read_basis_async(store, cx, &context.head_key).await?;
        let cumulative = match projection
            .collect_cumulative_outcomes_async(store, cx, &context.head_key, &authenticated)
            .await
        {
            Ok(cumulative) => cumulative,
            Err(error) => {
                // A recent terminal can remain recoverable even when an older
                // prefix cannot supply a complete publication witness.
                if crate::collect_terminal_retryable(&error)
                    && let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
                        store,
                        cx,
                        &context.head_key,
                        context.tenant_id,
                        context.repository_id,
                        admission.tx_id(),
                    )
                    .await?
                {
                    return publication::recovered(terminal);
                }
                return Err(error.into());
            }
        };
        if cumulative.observed() != head_receipt.token() {
            continue;
        }
        match fgit_authority::resolve_outcome_with_cumulative_async(
            store,
            cx,
            &context.head_key,
            head_receipt.token(),
            context.tenant_id,
            context.repository_id,
            admission.tx_id(),
            &cumulative,
        )
        .await?
        {
            Some(OutcomeLookup::Decided(terminal)) => return publication::recovered(terminal),
            Some(OutcomeLookup::Undecided) => {}
            None => continue,
        }
        let state = delivery::read_in(store, cx, &basis, &|| checkpoint().is_err()).await?;
        let Some(entry) = state.outbox.entry(original.delivery_key()) else {
            // A concurrent terminal publication may have retired this slot.
            // Reload authority; absence never grants dispatch ownership.
            return Ok(false);
        };
        if entry != original {
            return Ok(false);
        }
        let previous = if let RuntimeMutation::Dispatch { next, effect, .. } = &mutation {
            let routes = next
                .routes()
                .iter()
                .map(|m| m.route.clone())
                .collect::<Vec<_>>();
            super::dispatch::replay::validate_plan(
                store,
                cx,
                context,
                &basis,
                entry,
                &routes,
                next.admits_new_send(),
                &|| checkpoint().is_err(),
            )
            .await?;
            let previous =
                super::dispatch::read_progress(store, cx, &basis, entry, &|| checkpoint().is_err())
                    .await?;
            if previous.as_ref().map(storage::root).transpose()? != next.predecessor_progress_root()
            {
                return Ok(false);
            }
            if next.owner() != context.principal_id
                || next.destination() != entry.destination()
                || next.payload_root() != entry.payload_root()
            {
                return Err(unavailable(RefusalCode::PublicationPolicyRefused));
            }
            if let Some(previous) = &previous {
                next.verify_successor_of(previous).map_err(codec_error)?;
            } else {
                let current =
                    delivery::read_effect_in(store, cx, context.repository_id, entry, &|| {
                        checkpoint().is_err()
                    })
                    .await?;
                if current.state() != ObligationState::Committed
                    || next.ordinal() != 0
                    || effect.map(storage::root).transpose()? != Some(next.origin_effect_root())
                    || current
                        .transition(LifecycleEvent::Defer, None)
                        .map_err(codec_error)?
                        .root()
                        .map_err(codec_error)?
                        != next.origin_effect_root()
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                // A Weak route set cannot take over a Strong or otherwise
                // already claimed execution merely because no Weak row exists.
                if history::latest_progress_for_entry(store, cx, &basis, entry, &|| {
                    checkpoint().is_err()
                })
                .await?
                .is_some()
                {
                    return Err(unavailable(RefusalCode::PublicationPolicyRefused));
                }
            }
            None
        } else {
            let previous = history::latest_progress_for_entry(store, cx, &basis, entry, &|| {
                checkpoint().is_err()
            })
            .await?;
            if previous.as_ref().map(storage::root).transpose()?
                != mutation.predecessor_progress_root()?
            {
                return Ok(false);
            }
            previous
        };
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
            &snapshot,
        )? {
            PublicationPreparation::Commit(prepared) => prepared,
            PublicationPreparation::Refuse(code) => return Err(unavailable(code)),
        };
        // The fold owns its result; release the snapshot before staging awaits.
        drop(snapshot);
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
            RuntimeMutation::Dispatch {
                next,
                effect,
                receipt,
            } => {
                if let Some(effect) = effect {
                    let current =
                        delivery::read_effect_in(store, cx, context.repository_id, entry, &|| {
                            checkpoint().is_err()
                        })
                        .await?;
                    if next.finished_effect_root().is_some() {
                        let (expected_effect, expected_receipt) =
                            next.terminal_objects(&current).map_err(codec_error)?;
                        if *effect != &expected_effect || *receipt != Some(&expected_receipt) {
                            return Err(unavailable(RefusalCode::EvidenceInvalid));
                        }
                    } else if next.ordinal() != 0
                        || effect.state() != ObligationState::DeferredExternally
                        || receipt.is_some()
                    {
                        return Err(unavailable(RefusalCode::EvidenceInvalid));
                    }
                    if let Some(receipt) = receipt {
                        storage::stage_body(
                            store,
                            cx,
                            context.repository_id,
                            RECEIPT_NAMESPACE,
                            *receipt,
                        )
                        .await?;
                    }
                    let root = storage::root(*effect)?;
                    let entries = state
                        .outbox
                        .entries()
                        .iter()
                        .map(|e| {
                            if e.delivery_key() == entry.delivery_key() {
                                CanonicalOutboxStateEntry::new(
                                    e.delivery_key(),
                                    e.effect_class(),
                                    e.destination(),
                                    e.payload_root(),
                                    e.tx_id(),
                                    e.predecessor_rcr_id(),
                                    root,
                                    Some(e.effect_state_root()),
                                )
                            } else {
                                *e
                            }
                        })
                        .collect();
                    let outbox = CanonicalOutboxState::try_new(context.repository_id, entries)
                        .map_err(codec_error)?;
                    delivery::stage_effect_and_outbox_in(store, cx, &outbox, effect, &|| {
                        checkpoint().is_err()
                    })
                    .await?;
                    materialization.roots.outbox_root = if retired_state(effect.state()) {
                        stage_retired_map(store, cx, &outbox, entry.delivery_key(), checkpoint)
                            .await?
                    } else {
                        storage::root(&outbox)?
                    };
                } else if next.ordinal() == 0
                    || next.finished_effect_root().is_some()
                    || receipt.is_some()
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                stage_runtime_evidence(store, cx, context, *next, checkpoint).await?;
            }
            RuntimeMutation::Lifecycle {
                next,
                receipt,
                progress,
            } => {
                if retired_state(next.state()) {
                    history::validate_terminal_progress(
                        progress.ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?,
                        next,
                        receipt.ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?,
                    )?;
                }
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
                materialization.roots.outbox_root = if retired_state(next.state()) {
                    stage_retired_map(store, cx, &outbox, original.delivery_key(), checkpoint)
                        .await?
                } else {
                    storage::root(&outbox)?
                };
            }
            RuntimeMutation::Progress(body) => {
                stage_runtime_evidence(store, cx, context, *body, checkpoint).await?;
            }
            RuntimeMutation::Retirement { effect, progress } => {
                if !retired_state(effect.state())
                    || storage::root(*effect)? != entry.effect_state_root()
                    || progress.is_none()
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                delivery::stage_effect_and_outbox_in(store, cx, &state.outbox, effect, &|| {
                    checkpoint().is_err()
                })
                .await?;
                stage_runtime_evidence(store, cx, context, *effect, checkpoint).await?;
                materialization.roots.outbox_root = stage_retired_map(
                    store,
                    cx,
                    &state.outbox,
                    original.delivery_key(),
                    checkpoint,
                )
                .await?;
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
        if let Some(owned) = publication::publish_owned(
            store,
            cx,
            &settlement_context,
            head_receipt.token(),
            &publication,
            admission.tx_id(),
            &cumulative,
        )
        .await?
        {
            return Ok(owned);
        }
    }
    // Unrelated writers can invalidate every retained witness without
    // invalidating a standing terminal. Recovery never acquires a new send.
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
        return publication::recovered(terminal);
    }
    Err(AdmissionError::CasReplanLimitExceeded {
        limit: limits.max_cas_replans,
    })
}

const fn retired_state(state: ObligationState) -> bool {
    matches!(
        state,
        ObligationState::Acknowledged | ObligationState::TerminallyFailed
    )
}

// The ordinary lifecycle stager MUST first verify the terminal entry and its
// predecessor/receipt closure in a map that actually contains it. Its staged
// retained map grants no authority. Only the pruned map below is selected by
// the final CAS; do not relax the lifecycle stager's membership check.
async fn stage_retired_map<S, C>(
    store: &S,
    cx: &S::Context,
    validated: &CanonicalOutboxState,
    key: AsciiSlug,
    checkpoint: &C,
) -> Result<Digest, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    checkpoint().map_err(unavailable)?;
    let entries = validated
        .entries()
        .iter()
        .copied()
        .filter(|entry| entry.delivery_key() != key)
        .collect();
    let active =
        CanonicalOutboxState::try_new(validated.repository_id(), entries).map_err(codec_error)?;
    let root = storage::stage_body(
        store,
        cx,
        validated.repository_id(),
        delivery::OUTBOX_NAMESPACE,
        &active,
    )
    .await?;
    checkpoint().map_err(unavailable)?;
    Ok(root)
}

pub(super) async fn stage_runtime_evidence<S, B, C>(
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

fn codec_error(_: fgit_codec::CodecRefusal) -> AdmissionError {
    unavailable(RefusalCode::EvidenceInvalid)
}

pub(super) const fn projection_error(error: ProjectionFailure) -> AdmissionError {
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
    for (target, pair) in bytes.iter_mut().zip(key.as_bytes().as_chunks::<2>().0) {
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
