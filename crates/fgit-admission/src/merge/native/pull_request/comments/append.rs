//! Stable additive comment intents obtain their position from current authority.

use super::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, AggregateId,
    AggregateVersion, AsciiSlug, AsyncAuthorityStore, AuthenticatedHead,
    CanonicalForgePositionState, ForgeEvent, ForgeEventBatch, ForgeEventPayload, NativeMergeBasis,
    NativeMergeProjection, PreparationFailure, ProjectionFailure, PublicationBasis, RefusalCode,
    ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome, ValidatedClosure, Validation,
    metadata, storage, unavailable,
};
use fgit_forge::event::admission::ForgeCommandProfile;
use fgit_forge::event::pull_request_comment::PullRequestAppendCommentCommand;

/// Commit the authenticated actor, PR number, exact text and optional immutable
/// source anchor without a mutable conversation predecessor. The version-one
/// event is a commitment template; the distinct scope preserves strict seals.
pub fn append_proposal(
    context: &AdmissionContext,
    command: &PullRequestAppendCommentCommand,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = command
        .commitment_event(context.principal_id)
        .map_err(unavailable)?;
    if command
        .anchor
        .as_ref()
        .is_some_and(|anchor| anchor.source_tip.algorithm() != context.object_format)
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static("pull-request.append-comment.v1"),
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

pub async fn admit_append_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &PullRequestAppendCommentCommand,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let (event, attempt) = append_proposal(context, command)?;
    metadata::admit_metadata_async(
        store,
        cx,
        context,
        event,
        attempt,
        limits,
        projection,
        &AppendValidation,
    )
    .await
}

struct AppendValidation;
impl<S, P> metadata::MetadataValidation<S, P> for AppendValidation
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    fn command_profile(&self) -> ForgeCommandProfile {
        ForgeCommandProfile::AppendPullRequestCommentV1
    }

    fn precheck(&self, _: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        Ok(())
    }

    fn plan_event(
        &self,
        context: &AdmissionContext,
        submitted: &ForgeEvent,
        resolved: &NativeMergeBasis,
    ) -> Result<ForgeEvent, ProjectionFailure> {
        plan_append_event(context, submitted, &resolved.forge)
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
        // Replanning shares the exact path's current PR, hidden-ref, canonical
        // conversation and independent immutable-source validation.
        <Validation as metadata::MetadataValidation<S, P>>::validate(
            &Validation,
            store,
            cx,
            basis,
            authenticated,
            snapshot,
            resolved,
            event,
            projection,
        )
        .await
    }
}

fn plan_append_event(
    context: &AdmissionContext,
    submitted: &ForgeEvent,
    positions: &CanonicalForgePositionState,
) -> Result<ForgeEvent, ProjectionFailure> {
    let (
        AggregateId::PullRequestConversation(number),
        ForgeEventPayload::PullRequestCommentedNative(comment),
    ) = (submitted.aggregate, &submitted.payload)
    else {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
    };
    let template = PullRequestAppendCommentCommand {
        number,
        body: comment.body.clone(),
        anchor: comment.anchor.clone(),
    }
    .commitment_event(context.principal_id)
    .map_err(ProjectionFailure::Refuse)?;
    if template != *submitted {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
    }
    if positions.repository_id() != context.repository_id {
        return Err(ProjectionFailure::Unavailable(
            RefusalCode::AuthorityReceiptStale,
        ));
    }
    let stream = AsciiSlug::try_new("forge_stream", submitted.aggregate.to_string().as_bytes())
        .map_err(|_| ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
    let version = match positions.entry(stream) {
        None => AggregateVersion::FIRST,
        Some(previous) => AggregateVersion::try_new(previous.successor_position())
            .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?
            .next()
            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ResourceBudgetExceeded))?,
    };
    Ok(ForgeEvent {
        version,
        ..template
    })
}

#[cfg(test)]
mod tests;
