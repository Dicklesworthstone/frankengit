//! Durable admission of reviewed native branch merges.
//!
//! A typed intent, not caller-minted evidence, drives native-object validation
//! and the existing transaction evaluator's coupled ref/forge intents. The
//! asynchronous ref materializer handles its own partition; its ref effects
//! must exactly equal the complete fold. The final RCR carries the COMPLETE
//! fold's invariant evidence and the actual native event/frontier, published
//! together by the same authority-head CAS. Ordinary receive gates stay strict.

use std::collections::BTreeMap;
use std::future::Future;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ExpectedOld, OutcomeLookup, ProposedNew, RefCommand,
    ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan};
use fgit_codec::CryptoBodyIdentity;
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload, NativeMerge};
use fgit_reference::effect::FoldOutcome;
use fgit_reference::intent::{ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId, ForgeStreamPosition, Intent};
use fgit_txn::IntentEvaluator;
use fgit_types::{AsciiSlug, RefusalCode};

use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AsyncAdmissionProjection, LoweredRequest,
    ProjectionFailure, PublicationPreparation, ValidatedClosure,
};
use crate::evidence::{DecisionEvidenceBodies, principal_snapshot_id};
use storage::{aggregate_label, root};

pub mod objects;
mod storage;
pub use storage::load_forge_positions;

/// A reviewed two-parent merge. `NewStream` records the first merge receipt
/// for this PR number; it does not invent an earlier opening or approvals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMergeIntent {
    expected_version: ExpectedVersion,
    event: ForgeEvent,
}

impl NativeMergeIntent {
    pub fn new(
        pull_request: PullRequestNumber,
        expected_version: ExpectedVersion,
        merge: NativeMerge,
    ) -> Result<Self, AdmissionError> {
        merge.validate().map_err(|_| incoherent("native merge coordinates"))?;
        let version = match expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(version) => version.next()
                .map_err(|_| incoherent("exhausted aggregate version"))?,
        };
        Ok(Self {
            expected_version,
            event: ForgeEvent {
                aggregate: fgit_forge::aggregate::AggregateId::PullRequest(pull_request),
                version,
                payload: ForgeEventPayload::MergeCommittedNative(merge),
            },
        })
    }

    #[must_use]
    pub const fn expected_version(&self) -> ExpectedVersion { self.expected_version }

    #[must_use]
    pub const fn event(&self) -> &ForgeEvent { &self.event }

    pub fn merge(&self) -> Result<&NativeMerge, AdmissionError> {
        match &self.event.payload {
            ForgeEventPayload::MergeCommittedNative(merge) => Ok(merge),
            _ => Err(incoherent("native event kind")),
        }
    }

    /// The event root binds the aggregate, version, both branches, every input
    /// tip and result. The canonical request excludes derived closure/placement.
    pub fn seal_attempt(&self, context: &AdmissionContext) -> Result<SealAttempt, AdmissionError> {
        let merge = self.merge()?;
        if merge.merge_commit.algorithm() != context.object_format {
            return Err(AdmissionError::ObjectFormatMismatch);
        }
        let event_root = root(&ForgeEventBatch::of_one(self.event.clone()))?;
        let request = SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            vec![RefCommand {
                name: merge.target_ref.clone(),
                expected_old: ExpectedOld::Exactly(merge.target_tip_before),
                proposed_new: ProposedNew::Update(merge.merge_commit),
                force: false,
            }],
            Vec::new(),
            vec![ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("merge.event-batch-root"),
                event_root.bytes().as_bytes(),
            )?],
        )?;
        Ok(SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(),
            request,
        })
    }
}

/// Native validation is a required additional capability, not a synchronous
/// staging callback. It validates the exact reviewed commit, its parents/base
/// and complete object closure at this authenticated basis on EVERY CAS plan.
/// Unavailable dependencies leave the sealed request undecided and retryable.
pub trait NativeMergeProjection<S>: AsyncAdmissionProjection<S>
where S: AsyncAuthorityStore + ?Sized,
{
    fn validate_merge_async<'a>(
        &'a self,
        authority: &'a S,
        cx: &'a S::Context,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a;
}

/// Publish the ref movement and forge transition as one authority decision.
/// A retry probes the authenticated terminal outcome before rechecking refs
/// that its own earlier commit may already have moved. No outbox delivery or
/// PR-approval policy is inferred from this native merge receipt.
pub async fn admit_native_merge_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    intent: &NativeMergeIntent,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    limits.validate()?;
    let attempt = intent.seal_attempt(context)?;
    let admission = fgit_authority::seal_request_async(store, cx, &attempt).await?;
    let tx_id = admission.tx_id();
    let merge = intent.merge()?;
    let lowered = LoweredRequest {
        semantic: attempt.request.clone(),
        idempotency_key: context.idempotency_key.clone(),
    };
    for _ in 0..limits.max_cas_replans {
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            store, cx, &context.head_key, context.tenant_id, context.repository_id, tx_id,
        ).await? { return Ok(terminal); }
        let (basis, receipt, authenticated) = crate::read_basis_async(store, cx, &context.head_key).await?;
        let cumulative = fgit_authority::collect_cumulative_outcomes_async(store, cx, &context.head_key).await?;
        if cumulative.observed() != receipt.token() { continue; }

        let prepared: Result<_, PreparationFailure> = async {
            let snapshot = projection.snapshot_async(store, cx, &basis, &authenticated).await?;
            if snapshot.hidden_refs.hides(merge.source_ref.as_bytes())
                || snapshot.hidden_refs.hides(merge.target_ref.as_bytes())
            { return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into()); }
            if snapshot.refs.get(&merge.source_ref) != Some(&merge.source_tip)
                || snapshot.refs.get(&merge.target_ref) != Some(&merge.target_tip_before)
            { return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into()); }
            let positions = load_forge_positions(store, cx, &basis).await?;
            if let Some(code) = storage::aggregate_refusal(store, cx, &positions, intent).await? {
                return Err(ProjectionFailure::Refuse(code).into());
            }
            let closure = projection.validate_merge_async(store, cx, &basis, &authenticated, intent).await?;
            let recomputed = crate::permitted_object_closure_root(&crate::PermittedObjectClosure::new(closure.objects.clone()))
                .map_err(ProjectionFailure::Unavailable)?;
            if recomputed != closure.object_closure_root || !closure.objects.contains(&merge.merge_commit) {
                return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid).into());
            }

            let mut complete_snapshot = snapshot.clone();
            complete_snapshot.forge_positions = positions.entries().iter().map(|entry| (
                ForgeStreamId::new(entry.stream()), ForgeStreamPosition::new(entry.successor_position()),
            )).collect();
            let ref_partition = match crate::prepare_publication_from_snapshot(context, &lowered, &closure, tx_id, snapshot)? {
                PublicationPreparation::Commit(prepared) => prepared,
                PublicationPreparation::Refuse(code) => return Err(ProjectionFailure::Refuse(code).into()),
            };
            let mut complete_request = ref_partition.request.clone();
            let label = aggregate_label(intent.event.aggregate)?;
            let stream = ForgeStreamId::new(label);
            let event_kind = ForgeEventKind::PullRequestMerged {
                pull_request: ForgeEntityId::new(label), target: merge.target_ref.clone(),
            };
            let statement = complete_request.statements.first_mut()
                .ok_or_else(|| incoherent("missing ref statement"))?;
            statement.intents.push(Intent::Forge(ForgeIntent {
                stream,
                expected_position: ForgeStreamPosition::new(intent.event.version.get() - 1),
                event: event_kind.clone(),
            }));
            let complete_fold = IntentEvaluator::new().evaluate(complete_snapshot.as_fold_basis(), &complete_request);
            let complete_effects = match &complete_fold.outcome {
                FoldOutcome::Folded(effects) => effects,
                FoldOutcome::Aborted { code, .. } => return Err(ProjectionFailure::Refuse(*code).into()),
            };
            let ref_effects = ref_partition.fold.effects().ok_or_else(|| incoherent("ref fold"))?;
            if complete_effects.refs != ref_effects.refs
                || complete_effects.forge != BTreeMap::from([(stream, vec![event_kind])])
                || !complete_effects.retention.is_empty() || !complete_effects.outbox.is_empty()
            { return Err(incoherent("coupled merge normal form").into()); }
            let evidence = DecisionEvidenceBodies::derive(context, &basis, &complete_request, &complete_fold)
                .map_err(ProjectionFailure::Unavailable)?;

            // This materializer owns only ref/closure placement. Equality of the
            // ref partition above is mandatory; its subset invariant is NOT the
            // invariant that the completed merge RCR will publish below.
            let materialization = projection.materialize_commit_async(
                store, cx, &basis, &ref_partition.request, &ref_partition.fold, &closure,
            ).await?;
            crate::validate_commit_materialization(context, &basis, tx_id, &attempt.request, &closure, &materialization)?;
            storage::verify_head_target(store, cx, context.repository_id, materialization.roots.ref_root,
                complete_snapshot.head_target.as_ref()).await?;
            if materialization.record.principal_snapshot_id != principal_snapshot_id(evidence.principal_snapshot())
                    .map_err(ProjectionFailure::Unavailable)?
                || materialization.record.policy_decision_root != root(evidence.policy_decision())?
                || materialization.record.outbox_effect_root != root(evidence.outbox_effect_batch())?
                || materialization.record.retention_delta_root != root(evidence.retention_delta())?
            { return Err(incoherent("native and ref partition evidence bindings").into()); }
            Ok((materialization, positions, evidence))
        }.await;

        let (mut materialization, positions, evidence) = match prepared {
            Ok(prepared) => prepared,
            Err(PreparationFailure::Admission(error)) => return Err(*error),
            Err(PreparationFailure::Projection(ProjectionFailure::Unavailable(code))) => return Err(unavailable(code)),
            Err(PreparationFailure::Projection(ProjectionFailure::Refuse(code))) => {
                if let Some(terminal) = crate::publish_refusal_async(
                    store, cx, context, &basis, receipt.token(), admission.seal_id(), tx_id,
                    code, projection, &cumulative,
                ).await? { return Ok(terminal); }
                continue;
            }
        };
        let events = ForgeEventBatch::of_one(intent.event.clone());
        let event_root = storage::stage_body(store, cx, context.repository_id, storage::EVENT_NAMESPACE, &events).await?;
        let next = storage::advance_positions(&positions, &events, event_root)?;
        let position_root = storage::stage_body(store, cx, context.repository_id, storage::POSITION_NAMESPACE, &next).await?;
        let invariant_root = storage::stage_body(store, cx, context.repository_id, storage::INVARIANT_NAMESPACE,
            evidence.invariant_evidence()).await?;
        materialization.record.forge_event_batch_root = event_root;
        materialization.record.resulting_forge_position_root = position_root;
        materialization.record.invariant_evidence_root = invariant_root;
        materialization.roots.forge_position_root = position_root;
        let mut plan = PublicationPlan::open(basis.clone())?;
        plan.commit(materialization.record);
        let publication = plan.seal(&CryptoBodyIdentity, materialization.roots, &cumulative, receipt.token())?;
        if let Some(terminal) = crate::outcome_after_publish_async(store, cx, context, receipt.token(), &publication).await? {
            return Ok(terminal);
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded { limit: limits.max_cas_replans })
}

// Preserve storage/authority errors instead of flattening them into a terminal
// refusal or losing the original failure behind a generic availability code.
enum PreparationFailure {
    Projection(ProjectionFailure),
    Admission(Box<AdmissionError>),
}
impl From<ProjectionFailure> for PreparationFailure {
    fn from(value: ProjectionFailure) -> Self { Self::Projection(value) }
}
impl From<AdmissionError> for PreparationFailure {
    fn from(value: AdmissionError) -> Self { Self::Admission(Box::new(value)) }
}
fn unavailable(code: RefusalCode) -> AdmissionError { AdmissionError::AsyncProjectionUnavailable(code) }
fn incoherent(field: &'static str) -> AdmissionError { AdmissionError::MergeIncoherent { field } }
