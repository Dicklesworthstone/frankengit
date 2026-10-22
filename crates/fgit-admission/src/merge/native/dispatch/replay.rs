//! A new sealed one-send replay intent. The original terminal responsibility
//! and canonical forge events never reopen or advance as a side effect.
use super::super::{delivery, history, settlement, storage, unavailable};
use super::{DispatchRoute, read_progress};
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AsyncAdmissionProjection, LoweredRequest,
    PermittedObjectClosure, PublicationPreparation, ValidatedClosure,
};
use fgit_authority::{
    AsyncAuthorityStore, OutcomeLookup, ScopedEntry, SealAttempt, SemanticRequest,
};
use fgit_chronicle::{HistoryStep, PublicationBasis, PublicationPlan, read_history_step_async};
use fgit_codec::{
    CanonicalOutboxEffectState, CanonicalOutboxState, CanonicalOutboxStateEntry,
    CryptoBodyIdentity, OutboxDeliveryIdentityInput, derive_outbox_delivery_key,
};
use fgit_resource::ObligationState;
use fgit_types::{AsciiSlug, Digest, DigestAlgorithmId, DigestBytes, RefusalCode, TxId};

pub const REPLAY_REQUEST_NAMESPACE: &[u8] = b"frankengit/admission/outbox-replay-request/v1/";
pub const REPLAY_CLASS: AsciiSlug = AsciiSlug::from_static("forge-replay");

/// Expected source coordinates and one configured route, not caller-computed
/// successor state. The authenticated session's idempotency key names this
/// new replay; repeating it cannot create another delivery or raise its budget.
#[derive(Clone, Debug)]
pub struct ReplayIntent {
    pub source: AsciiSlug,
    pub destination: AsciiSlug,
    pub payload: Digest,
    pub expected_source_effect: Digest,
    pub route_id: u64,
    pub route_binding: Digest,
}
impl ReplayIntent {
    fn request(
        &self,
        format: fgit_types::GitHashAlgorithm,
    ) -> Result<SemanticRequest, AdmissionError> {
        settlement::resource_key(self.source)?;
        let entry = |key, value: Vec<u8>| {
            ScopedEntry::new(AsciiSlug::from_static("outbox-replay"), key, value)
                .map_err(AdmissionError::from)
        };
        Ok(SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            format,
            true,
            vec![],
            vec![],
            vec![
                entry(
                    AsciiSlug::from_static("source-key"),
                    self.source.as_bytes().to_vec(),
                )?,
                entry(
                    AsciiSlug::from_static("source-effect"),
                    digest_value(self.expected_source_effect),
                )?,
                entry(
                    AsciiSlug::from_static("payload"),
                    digest_value(self.payload),
                )?,
                entry(
                    AsciiSlug::from_static("destination"),
                    self.destination.as_bytes().to_vec(),
                )?,
                entry(
                    AsciiSlug::from_static("route-id"),
                    self.route_id.to_be_bytes().to_vec(),
                )?,
                entry(
                    AsciiSlug::from_static("route-binding"),
                    digest_value(self.route_binding),
                )?,
            ],
        )?)
    }
}

/// Validate the distinct replay-creation record, without treating it as a
/// new canonical forge event. The RCR directly commits the retained request.
/// Source eligibility is authenticated before creation and again before send;
/// historical lookup also authenticates the original source at the creation
/// predecessor, rather than trusting merely staged source bodies.
pub(in crate::merge::native) async fn validate_creation<S, C>(
    store: &S,
    cx: &S::Context,
    predecessor: &PublicationBasis,
    record: &fgit_codec::RepositoryCommitRecord,
    entry: &CanonicalOutboxStateEntry,
    evidence: &history::OutboxRecordEvidence,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let history::OutboxRecordEvidence::Effect(effect) = evidence else {
        return Err(bad());
    };
    if effect.state() != ObligationState::Committed
        || effect.tx_id() != entry.tx_id()
        || effect.delivery_key() != entry.delivery_key()
        || effect.payload_root() != entry.payload_root()
        || record.resulting_ref_root != predecessor.body().ref_root
        || record.resulting_forge_position_root != predecessor.body().forge_position_root
    {
        return Err(bad());
    }
    let request: SemanticRequest = history::read_body(
        store,
        cx,
        record.repository_id,
        REPLAY_REQUEST_NAMESPACE,
        record.canonical_request_digest,
        cancelled,
    )
    .await?;
    let intent = from_request(&request)?;
    if intent.source == entry.delivery_key()
        || intent.destination != entry.destination()
        || intent.payload != entry.payload_root()
    {
        return Err(bad());
    }
    // Only original forge-event parents are admitted, so this proof has one
    // source level. Replays form a star around the original event, never a
    // recursive chain with a fresh scan budget at each nested replay.
    let source = Box::pin(source_for_route(store, cx, predecessor, &intent, cancelled)).await?;
    if storage::root(&source)? != intent.expected_source_effect
        || source.payload_root() != intent.payload
    {
        return Err(bad());
    }
    let receipt = history::read_effect_receipt(store, cx, &source, cancelled)
        .await?
        .ok_or_else(bad)?;
    if receipt.destination() != intent.destination {
        return Err(bad());
    }
    if !storage::read_events(
        store,
        cx,
        record.repository_id,
        record.forge_event_batch_root,
    )
    .await?
    .events
    .is_empty()
    {
        return Err(bad());
    }
    Ok(())
}
fn from_request(request: &SemanticRequest) -> Result<ReplayIntent, AdmissionError> {
    let value = |key| {
        request
            .scoped_entries()
            .iter()
            .find(|e| {
                e.namespace == AsciiSlug::from_static("outbox-replay") && e.key.as_str() == key
            })
            .map(|e| e.value.as_slice())
            .ok_or_else(bad)
    };
    let id: [u8; 8] = value("route-id")?.try_into().map_err(|_| bad())?;
    let intent = ReplayIntent {
        source: AsciiSlug::try_new("replay source", value("source-key")?).map_err(|_| bad())?,
        destination: AsciiSlug::try_new("replay destination", value("destination")?)
            .map_err(|_| bad())?,
        payload: digest_from_value(value("payload")?)?,
        expected_source_effect: digest_from_value(value("source-effect")?)?,
        route_id: u64::from_be_bytes(id),
        route_binding: digest_from_value(value("route-binding")?)?,
    };
    if intent.request(request.object_format())? != *request {
        return Err(bad());
    }
    Ok(intent)
}

/// Authenticate the actual published source outcome. A diagnostic, active-map
/// absence, accepted source, or merely staged terminal body cannot authorize it.
pub async fn read_source<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    key: AsciiSlug,
    destination: AsciiSlug,
    cancelled: &C,
) -> Result<CanonicalOutboxEffectState, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let state = delivery::read_in(store, cx, basis, cancelled).await?;
    let effect = if let Some(entry) = state.outbox.entry(key) {
        if entry.destination() != destination
            || entry.effect_class() != AsciiSlug::from_static("forge-event")
        {
            return Err(bad());
        }
        let effect =
            delivery::read_effect_in(store, cx, basis.body().repository_id, entry, cancelled)
                .await?;
        if effect.state() != ObligationState::Escalated {
            return Err(unavailable(RefusalCode::PublicationPolicyRefused));
        }
        if let Some(progress) = read_progress(store, cx, basis, entry, cancelled).await? {
            if progress.finished_effect_root() != Some(storage::root(&effect)?) {
                return Err(bad());
            }
        } else {
            let progress = history::latest_progress_for_entry(store, cx, basis, entry, cancelled)
                .await?
                .ok_or_else(bad)?;
            if !progress.state().is_terminal() {
                return Err(bad());
            }
        }
        effect
    } else {
        history::retired_effect_in_class(
            store,
            cx,
            basis,
            key,
            destination,
            Some(AsciiSlug::from_static("forge-event")),
            cancelled,
        )
        .await?
        .ok_or_else(bad)?
    };
    if !matches!(
        effect.state(),
        ObligationState::TerminallyFailed | ObligationState::Escalated
    ) {
        return Err(unavailable(RefusalCode::PublicationPolicyRefused));
    }
    Ok(effect)
}

// An explicit replay can only retry the selected original route's terminal
// failure/uncertainty. A sibling's failure never grants replay of a delivered
// member, and local diagnostics cannot widen this canonical authorization.
async fn source_for_route<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    intent: &ReplayIntent,
    cancelled: &C,
) -> Result<CanonicalOutboxEffectState, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let source = read_source(
        store,
        cx,
        basis,
        intent.source,
        intent.destination,
        cancelled,
    )
    .await?;
    let plan = super::read_dispatch_plan(
        store,
        cx,
        basis,
        intent.source,
        intent.destination,
        cancelled,
    )
    .await?
    .ok_or_else(|| unavailable(RefusalCode::PublicationPolicyRefused))?;
    let member = plan
        .routes()
        .iter()
        .find(|m| m.route.id == intent.route_id && m.route.binding == intent.route_binding)
        .ok_or_else(|| unavailable(RefusalCode::PublicationPolicyRefused))?;
    if !matches!(
        member.state,
        fgit_resource::ReconcileState::Undeliverable { .. }
            | fgit_resource::ReconcileState::Indeterminate { .. }
    ) {
        return Err(unavailable(RefusalCode::PublicationPolicyRefused));
    }
    Ok(source)
}

/// Publish a fresh replay obligation with unchanged refs, forge positions and
/// retention. No transport runs here. Its request body is retained under the
/// seal's canonical request digest so every replay's provenance is inspectable.
pub async fn enqueue_replay_async<S, P, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    intent: &ReplayIntent,
    projection: &P,
    limits: AdmissionLimits,
    checkpoint: &C,
) -> Result<AsciiSlug, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: AsyncAdmissionProjection<S> + ?Sized,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    limits.validate()?;
    checkpoint().map_err(unavailable)?;
    let semantic = intent.request(context.object_format)?;
    let attempt = SealAttempt {
        tenant_id: context.tenant_id,
        repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: context.idempotency_key.clone(),
        request: semantic.clone(),
    };
    let admission = fgit_authority::seal_request_async(store, cx, &attempt).await?;
    let tx = admission.tx_id();
    let lowered = LoweredRequest {
        semantic: semantic.clone(),
        idempotency_key: context.idempotency_key.clone(),
    };
    let empty = PermittedObjectClosure::default();
    let closure = ValidatedClosure {
        objects: empty.objects().clone(),
        object_closure_root: crate::permitted_object_closure_root(&empty).map_err(unavailable)?,
    };
    for _ in 0..limits.max_cas_replans {
        checkpoint().map_err(unavailable)?;
        let (basis, receipt, authenticated) =
            crate::read_basis_async(store, cx, &context.head_key).await?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            store,
            cx,
            &context.head_key,
            context.tenant_id,
            context.repository_id,
            tx,
        )
        .await?
        {
            if let fgit_types::DecisionOutcome::Refused { code, .. } = terminal.outcome {
                return Err(unavailable(code));
            }
            let (decided_basis, _, _) =
                crate::read_basis_async(store, cx, &context.head_key).await?;
            return created_key(store, cx, &decided_basis, tx, &|| checkpoint().is_err()).await;
        }
        let source = source_for_route(store, cx, &basis, intent, &|| checkpoint().is_err()).await?;
        if source.payload_root() != intent.payload
            || storage::root(&source)? != intent.expected_source_effect
        {
            return Err(unavailable(RefusalCode::EvidenceStale));
        }
        let state = delivery::read_in(store, cx, &basis, &|| checkpoint().is_err()).await?;
        if state.outbox.entries().len() >= fgit_codec::MAX_OUTBOX_STATE_ENTRIES {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        let events = storage::read_events(store, cx, context.repository_id, intent.payload).await?;
        delivery::validate_payload_positions(&state.forge, &events)?;
        let cumulative =
            fgit_authority::collect_cumulative_outcomes_async(store, cx, &context.head_key).await?;
        if cumulative.observed() != receipt.token() {
            continue;
        }
        let snapshot = projection
            .snapshot_async(store, cx, &basis, &authenticated)
            .await
            .map_err(settlement::projection_error)?;
        let prepared = match crate::prepare_publication_from_snapshot(
            context, &lowered, &closure, tx, snapshot,
        )? {
            PublicationPreparation::Commit(p) => p,
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
            .map_err(settlement::projection_error)?;
        crate::validate_commit_materialization(
            context,
            &basis,
            tx,
            &attempt.request,
            &closure,
            &materialization,
        )?;
        if materialization.roots.ref_root != basis.body().ref_root
            || materialization.roots.forge_position_root != basis.body().forge_position_root
            || materialization.roots.outbox_root != basis.body().outbox_root
            || materialization.roots.retention_root != basis.body().retention_root
            || materialization.roots.policy_epoch != basis.body().policy_epoch
            || materialization.roots.compaction_generation_link.is_some()
        {
            return Err(bad());
        }
        let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
            context.repository_id,
            REPLAY_CLASS,
            intent.destination,
            intent.payload,
            tx,
            basis.body().latest_committed_rcr_id,
        ))
        .map_err(|_| bad())?;
        if key == intent.source || state.outbox.entry(key).is_some() {
            return Err(bad());
        }
        let effect =
            CanonicalOutboxEffectState::committed(context.repository_id, key, tx, intent.payload);
        let root = storage::root(&effect)?;
        let mut entries = state.outbox.entries().to_vec();
        entries.push(CanonicalOutboxStateEntry::new(
            key,
            REPLAY_CLASS,
            intent.destination,
            intent.payload,
            tx,
            basis.body().latest_committed_rcr_id,
            root,
            None,
        ));
        entries.sort_by_key(|e| e.delivery_key());
        let outbox =
            CanonicalOutboxState::try_new(context.repository_id, entries).map_err(|_| bad())?;
        // This is deliberately not the new-forge-event stager: replay references
        // an authenticated historical payload without moving its aggregate.
        checkpoint().map_err(unavailable)?;
        storage::stage_body(
            store,
            cx,
            context.repository_id,
            delivery::EFFECT_NAMESPACE,
            &effect,
        )
        .await?;
        storage::stage_body(
            store,
            cx,
            context.repository_id,
            delivery::OUTBOX_NAMESPACE,
            &outbox,
        )
        .await?;
        let request_root = storage::stage_body(
            store,
            cx,
            context.repository_id,
            REPLAY_REQUEST_NAMESPACE,
            &semantic,
        )
        .await?;
        if request_root != fgit_authority::canonical_request_digest(&semantic)? {
            return Err(bad());
        }
        settlement::stage_runtime_evidence(store, cx, context, &effect, checkpoint).await?;
        materialization.roots.outbox_root = storage::root(&outbox)?;
        materialization.record.invariant_evidence_root = root;
        materialization.record.outbox_effect_root = root;
        let mut plan = PublicationPlan::open(basis)?;
        plan.commit(materialization.record);
        let publication = plan.seal(
            &CryptoBodyIdentity,
            materialization.roots,
            &cumulative,
            receipt.token(),
        )?;
        checkpoint().map_err(unavailable)?;
        if let Some(_) = settlement::publication::publish_owned(
            store,
            cx,
            context,
            receipt.token(),
            &publication,
            tx,
        )
        .await?
        {
            // Reload selected history even on recovery; object existence grants
            // neither a new identity nor an extra send.
            let (basis, _, _) = crate::read_basis_async(store, cx, &context.head_key).await?;
            return created_key(store, cx, &basis, tx, &|| checkpoint().is_err()).await;
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded {
        limit: limits.max_cas_replans,
    })
}

/// A replay's class requires its retained sealed route intent. A different
/// principal/endpoint/route cannot claim it as an ordinary forge event.
pub(in crate::merge::native) async fn validate_plan<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    entry: &CanonicalOutboxStateEntry,
    routes: &[DispatchRoute],
    eligible: bool,
    cancelled: &C,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    if entry.effect_class() != REPLAY_CLASS {
        return Ok(());
    }
    if routes.len() != 1
        || routes[0].max_attempts != 1
        || routes[0].initial_delay_millis != 0
        || routes[0].max_delay_millis != 0
    {
        return Err(bad());
    }
    let seal = fgit_authority::read_seal_async(
        store,
        cx,
        context.tenant_id,
        context.repository_id,
        entry.tx_id(),
    )
    .await?
    .ok_or_else(bad)?;
    if seal.authenticated_principal_id != context.principal_id {
        return Err(unavailable(RefusalCode::PublicationPolicyRefused));
    }
    let request: SemanticRequest = history::read_body(
        store,
        cx,
        context.repository_id,
        REPLAY_REQUEST_NAMESPACE,
        seal.canonical_request_digest,
        cancelled,
    )
    .await?;
    let intent = from_request(&request)?;
    if request.object_format() != context.object_format
        || request.scoped_entries().len() != 6
        || !request.ref_commands().is_empty()
    {
        return Err(bad());
    }
    if intent.destination != entry.destination()
        || intent.payload != entry.payload_root()
        || intent.route_id != routes[0].id
        || intent.route_binding != routes[0].binding
    {
        return Err(bad());
    }
    let source = intent.source;
    let expected = intent.expected_source_effect;
    if !eligible {
        return Ok(());
    }
    let original = source_for_route(store, cx, basis, &intent, cancelled).await?;
    if source == entry.delivery_key()
        || storage::root(&original)? != expected
        || original.payload_root() != entry.payload_root()
    {
        return Err(bad());
    }
    Ok(())
}
async fn created_key<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    tx: TxId,
    cancelled: &C,
) -> Result<AsciiSlug, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let mut successor = basis.body().clone();
    let mut batches = 0;
    let mut records = 0usize;
    loop {
        let (predecessor, batch) =
            match read_history_step_async(store, cx, &successor, &mut batches, 4096, cancelled)
                .await
                .map_err(storage::history_step_refusal)?
            {
                HistoryStep::Genesis => return Err(bad()),
                HistoryStep::Checkpoint { predecessor } => {
                    successor = predecessor.body().clone();
                    continue;
                }
                HistoryStep::Decision { predecessor, batch } => (predecessor, batch),
            };
        records = records
            .checked_add(batch.committed_rcrs.len())
            .filter(|n| *n <= 65536)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for record in &batch.committed_rcrs {
            if record.tx_id != tx {
                continue;
            }
            let history::OutboxRecordEvidence::Effect(effect) = history::verify_record_evidence(
                store,
                cx,
                basis.body().repository_id,
                record,
                cancelled,
            )
            .await?
            else {
                return Err(bad());
            };
            let entry = history::read_selected_entry(
                store,
                cx,
                &successor,
                effect.delivery_key(),
                cancelled,
            )
            .await?;
            if effect.tx_id() != tx
                || effect.state() != ObligationState::Committed
                || entry.effect_class() != REPLAY_CLASS
                || entry.effect_state_root() != storage::root(&effect)?
                || entry.predecessor_rcr_id() != predecessor.body().latest_committed_rcr_id
            {
                return Err(bad());
            }
            delivery::read_effect_in(store, cx, basis.body().repository_id, &entry, cancelled)
                .await?;
            validate_creation(
                store,
                cx,
                &predecessor,
                record,
                &entry,
                &history::OutboxRecordEvidence::Effect(effect.clone()),
                cancelled,
            )
            .await?;
            return Ok(effect.delivery_key());
        }
        successor = predecessor.body().clone();
    }
}
fn digest_value(d: Digest) -> Vec<u8> {
    let mut v = d.algorithm().code_point().to_be_bytes().to_vec();
    v.push(d.bytes().len() as u8);
    v.extend_from_slice(d.bytes().as_bytes());
    v
}
fn digest_from_value(v: &[u8]) -> Result<Digest, AdmissionError> {
    if v.len() < 3 || usize::from(v[2]) + 3 != v.len() {
        return Err(bad());
    }
    Ok(Digest::new(
        DigestAlgorithmId::try_new(u16::from_be_bytes([v[0], v[1]])).map_err(|_| bad())?,
        DigestBytes::try_new(&v[3..]).map_err(|_| bad())?,
    ))
}
fn bad() -> AdmissionError {
    unavailable(RefusalCode::EvidenceInvalid)
}
