//! Immutable workflow observations for exact unpublished native PR candidates.
//! The metadata driver owns sealing, original-outcome recovery and publication;
//! the trusted projection validates the real execution and native bundle.

use std::future::Future;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_forge::event::workflow_check::WorkflowCheckId;
use fgit_forge::event::workflow_check::candidate::{
    CandidateWorkflowCheckRecord, NativeCandidateWorkflowCheck,
};
use fgit_forge::{AggregateId, ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_types::{AsciiSlug, RefusalCode};

use super::super::{
    NativeMergeProjection, PreparationFailure, delivery, metadata, storage, unavailable,
};
use crate::merge::NativeMergeBasis;
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, ProjectionFailure,
    ValidatedClosure,
};

/// The owner authenticates the exact selected original dependencies, execution
/// evidence and candidate bundle. A journal or decoded frame cannot own trust.
pub trait CandidateWorkflowCheckProjection<S: AsyncAuthorityStore + ?Sized>:
    NativeMergeProjection<S>
{
    fn validate_candidate_workflow_check_async<'a>(
        &'a self,
        store: &'a S,
        cx: &'a S::Context,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        record: &'a CandidateWorkflowCheckRecord,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a;
}

/// The full immutable subject, candidate, bundle pin and inline execution
/// evidence enter one seal. Current authority-head identity is not a lease.
pub fn proposal(
    context: &AdmissionContext,
    record: &CandidateWorkflowCheckRecord,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = record
        .proposed_event(context.principal_id, context.object_format)
        .map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static("candidate-workflow-check.event-batch-root.v1"),
            root.bytes().as_bytes(),
        )?],
    )?;
    Ok((
        event,
        SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(),
            request,
        },
    ))
}

/// Admit one canonical observation and its existing delivery obligation. The
/// shared driver resolves the original terminal before current-subject checks.
pub async fn admit_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    record: &CandidateWorkflowCheckRecord,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: CandidateWorkflowCheckProjection<S> + ?Sized,
{
    limits.validate()?;
    let (event, attempt) = proposal(context, record)?;
    metadata::admit_metadata_async(
        store,
        cx,
        context,
        event,
        attempt,
        limits,
        projection,
        &Validation(record),
    )
    .await
}

struct Validation<'a>(&'a CandidateWorkflowCheckRecord);
impl<S, P> metadata::MetadataValidation<S, P> for Validation<'_>
where
    S: AsyncAuthorityStore + ?Sized,
    P: CandidateWorkflowCheckProjection<S> + ?Sized,
{
    fn precheck(&self, snapshot: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        let subject = &self.0.subject;
        if snapshot.hidden_refs.hides(subject.source_ref.as_bytes())
            || snapshot.hidden_refs.hides(subject.target_ref.as_bytes())
        {
            return Err(ProjectionFailure::Refuse(
                RefusalCode::HiddenRefUnauthorized,
            ));
        }
        Ok(())
    }

    async fn validate<'a>(
        &'a self,
        store: &'a S,
        cx: &'a S::Context,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        snapshot: &'a AdmissionSnapshot,
        resolved: &'a NativeMergeBasis,
        event: &'a ForgeEvent,
        projection: &'a P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        let subject = &self.0.subject;
        if subject.policy_epoch != basis.body().policy_epoch {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        if snapshot.refs.get(&subject.source_ref) != Some(&subject.source_tip)
            || snapshot.refs.get(&subject.target_ref) != Some(&subject.target_tip)
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into());
        }
        // Both profiles share one immutable publisher/run/attempt/job stream.
        // A new key cannot relabel an already admitted execution.
        let check_label = storage::aggregate_label(event.aggregate)?;
        if resolved.forge.entry(check_label).is_some() {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let aggregate = AggregateId::PullRequest(subject.pull_request);
        let label = storage::aggregate_label(aggregate)?;
        let Some(position) = resolved.forge.entry(label) else {
            return Err(ProjectionFailure::Refuse(RefusalCode::ForgeTransitionInvalid).into());
        };
        if position.successor_position() != subject.pull_request_version.get() {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        let batch = storage::read_events(
            store,
            cx,
            basis.body().repository_id,
            position.event_batch_root(),
        )
        .await?;
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        delivery::validate_position_batch(position, &batch)?;
        let previous = batch
            .events
            .into_iter()
            .rev()
            .find(|held| held.aggregate == aggregate)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if previous.version.get() != position.successor_position() {
            return Err(unavailable(RefusalCode::EvidenceInvalid).into());
        }
        let ForgeEventPayload::PullRequestChangedNative(change) = previous.payload else {
            return Err(
                ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into(),
            );
        };
        if change.action == PullRequestAction::Close {
            return Err(
                ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into(),
            );
        }
        if change.data.source_ref != subject.source_ref
            || change.data.target_ref != subject.target_ref
            || change.data.source_tip != subject.source_tip
            || change.data.target_tip != subject.target_tip
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        Ok(projection
            .validate_candidate_workflow_check_async(store, cx, basis, authenticated, self.0)
            .await?)
    }
}

/// Read only this explicit profile through the shared authenticated immutable
/// check frontier. An ordinary branch observation is a valid different profile.
pub async fn read_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    id: WorkflowCheckId,
    cancelled: &C,
) -> Result<Option<NativeCandidateWorkflowCheck>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    Ok(
        match super::read_observation_at(store, cx, basis, id, cancelled).await? {
            Some(super::Observation::Candidate(change)) => Some(change),
            Some(super::Observation::Branch(_)) | None => None,
        },
    )
}
