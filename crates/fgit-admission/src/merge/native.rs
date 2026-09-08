//! Durable admission of reviewed native branch merges.
//!
//! A typed intent, not caller-minted evidence, drives native-object validation
//! and the existing transaction evaluator's coupled ref/forge intents. The
//! asynchronous ref materializer handles its own partition; its ref effects
//! must exactly equal the complete fold. The final RCR carries the COMPLETE
//! fold's invariant evidence and the actual native event/frontier, published
//! together by the same authority-head CAS. Ordinary receive gates stay strict.

use std::future::Future;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ExpectedOld, OutcomeLookup, ProposedNew, RefCommand,
    ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome,
};
use fgit_chronicle::{PublicationBasis, PublicationPlan};
use fgit_codec::CryptoBodyIdentity;
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload, NativeMerge};
use fgit_types::{AsciiSlug, RefusalCode};

use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AsyncAdmissionProjection, ProjectionFailure,
    ValidatedClosure,
};
use prepare::{PreparationFailure, prepare_native_merge};
use storage::root;

pub mod delivery;
pub mod history;
pub mod objects;
pub(crate) mod prepare;
pub mod progress;
pub mod settlement;
mod storage;
pub use storage::{legacy_genesis_root, load_forge_positions};

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
        merge
            .validate()
            .map_err(|_| incoherent("native merge coordinates"))?;
        let version = match expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(version) => version
                .next()
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
    pub const fn expected_version(&self) -> ExpectedVersion {
        self.expected_version
    }

    #[must_use]
    pub const fn event(&self) -> &ForgeEvent {
        &self.event
    }

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
where
    S: AsyncAuthorityStore + ?Sized,
{
    /// Checks the caller's cancellation and work budget between storage steps.
    fn merge_checkpoint(&self, cx: &S::Context) -> Result<(), RefusalCode>;
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
    for _ in 0..limits.max_cas_replans {
        projection.merge_checkpoint(cx).map_err(unavailable)?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            store,
            cx,
            &context.head_key,
            context.tenant_id,
            context.repository_id,
            tx_id,
        )
        .await?
        {
            return Ok(terminal);
        }
        let (basis, receipt, authenticated) =
            crate::read_basis_async(store, cx, &context.head_key).await?;
        let cumulative =
            fgit_authority::collect_cumulative_outcomes_async(store, cx, &context.head_key).await?;
        if cumulative.observed() != receipt.token() {
            continue;
        }

        let prepared: Result<_, PreparationFailure> = async {
            let snapshot = projection
                .snapshot_async(store, cx, &basis, &authenticated)
                .await?;
            if snapshot.hidden_refs.hides(merge.source_ref.as_bytes())
                || snapshot.hidden_refs.hides(merge.target_ref.as_bytes())
            {
                return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
            }
            if snapshot.refs.get(&merge.source_ref) != Some(&merge.source_tip)
                || snapshot.refs.get(&merge.target_ref) != Some(&merge.target_tip_before)
            {
                return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into());
            }
            let delivery_basis = delivery::read_in(store, cx, &basis, &|| {
                projection.merge_checkpoint(cx).is_err()
            })
            .await?;
            let positions = &delivery_basis.forge;
            if let Some(code) = storage::aggregate_refusal(store, cx, positions, intent).await? {
                return Err(ProjectionFailure::Refuse(code).into());
            }
            let closure = projection
                .validate_merge_async(store, cx, &basis, &authenticated, intent)
                .await?;
            let prepared = prepare_native_merge(
                context,
                &basis,
                tx_id,
                &attempt,
                intent.event(),
                snapshot,
                &closure,
                &delivery_basis,
            )?;

            // This materializer owns only ref/closure placement. Equality of the
            // ref partition above is mandatory; its subset invariant is NOT the
            // invariant that the completed merge RCR will publish below.
            let materialization = projection
                .materialize_commit_async(
                    store,
                    cx,
                    &basis,
                    &prepared.ref_request,
                    &prepared.ref_fold,
                    &closure,
                )
                .await?;
            crate::validate_commit_materialization(
                context,
                &basis,
                tx_id,
                &attempt.request,
                &closure,
                &materialization,
            )?;
            storage::verify_head_target(
                store,
                cx,
                context.repository_id,
                materialization.roots.ref_root,
                prepared.head_target.as_ref(),
            )
            .await?;
            prepared.validate_ref_evidence(&materialization)?;
            Ok((materialization, prepared))
        }
        .await;

        let (materialization, prepared) = match prepared {
            Ok(prepared) => prepared,
            Err(PreparationFailure::Admission(error)) => return Err(*error),
            Err(PreparationFailure::Projection(ProjectionFailure::Unavailable(code))) => {
                return Err(unavailable(code));
            }
            Err(PreparationFailure::Projection(ProjectionFailure::Refuse(code))) => {
                if let Some(terminal) = crate::publish_refusal_async(
                    store,
                    cx,
                    context,
                    &basis,
                    receipt.token(),
                    admission.seal_id(),
                    tx_id,
                    code,
                    projection,
                    &cumulative,
                )
                .await?
                {
                    return Ok(terminal);
                }
                continue;
            }
        };
        storage::stage_body(
            store,
            cx,
            context.repository_id,
            storage::EVENT_NAMESPACE,
            &prepared.events,
        )
        .await?;
        projection.merge_checkpoint(cx).map_err(unavailable)?;
        storage::stage_body(
            store,
            cx,
            context.repository_id,
            storage::POSITION_NAMESPACE,
            prepared.transition.forge_positions(),
        )
        .await?;
        storage::stage_body(
            store,
            cx,
            context.repository_id,
            delivery::OUTBOX_NAMESPACE,
            prepared.transition.outbox(),
        )
        .await?;
        storage::stage_body(
            store,
            cx,
            context.repository_id,
            delivery::EFFECT_NAMESPACE,
            &prepared.effect,
        )
        .await?;
        storage::stage_body(
            store,
            cx,
            context.repository_id,
            b"frankengit/admission/outbox-effect-batch/v1/",
            prepared.evidence.outbox_effect_batch(),
        )
        .await?;
        storage::stage_body(
            store,
            cx,
            context.repository_id,
            storage::INVARIANT_NAMESPACE,
            prepared.evidence.invariant_evidence(),
        )
        .await?;
        let materialization = prepared.finish_materialization(materialization)?;
        projection.merge_checkpoint(cx).map_err(unavailable)?;
        let mut plan = PublicationPlan::open(basis.clone())?;
        plan.commit(materialization.record);
        let publication = plan.seal(
            &CryptoBodyIdentity,
            materialization.roots,
            &cumulative,
            receipt.token(),
        )?;
        if let Some(terminal) =
            crate::outcome_after_publish_async(store, cx, context, receipt.token(), &publication)
                .await?
        {
            return Ok(terminal);
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded {
        limit: limits.max_cas_replans,
    })
}

fn unavailable(code: RefusalCode) -> AdmissionError {
    AdmissionError::AsyncProjectionUnavailable(code)
}
fn incoherent(field: &'static str) -> AdmissionError {
    AdmissionError::MergeIncoherent { field }
}
