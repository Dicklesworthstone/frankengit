//! Append-comment intent seals stay fixed while publication positions replan.
use super::{IssueValidation, NativeMergeBasis, metadata, storage, unavailable};
use crate::merge::native::{NativeMergeProjection, PreparationFailure};
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, ProjectionFailure,
    ValidatedClosure,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::CanonicalForgePositionState;
use fgit_forge::event::admission::ForgeCommandProfile;
use fgit_forge::event::issue::{IssueAction, IssueCommentIntent};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_types::{AsciiSlug, RefusalCode};

/// Seal the actor, issue and exact comment bytes without a mutable predecessor.
/// The version-2 event is only the canonical commitment template. The distinct
/// scoped key keeps every legacy exact-version comment's identity unchanged.
pub fn append_proposal(
    context: &AdmissionContext,
    intent: &IssueCommentIntent,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = intent
        .commitment_event(context.principal_id)
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
            AsciiSlug::from_static("issue.append-comment.v1"),
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

pub async fn admit_issue_comment_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    intent: &IssueCommentIntent,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let (event, attempt) = append_proposal(context, intent)?;
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
        ForgeCommandProfile::AppendIssueCommentV1
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

    async fn validate(
        &self,
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
        snapshot: &AdmissionSnapshot,
        resolved: &NativeMergeBasis,
        event: &ForgeEvent,
        projection: &P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        // Replay the same authenticated canonical history as a strict issue
        // mutation. Replanning neither skips permissions nor creates an issue.
        <IssueValidation as metadata::MetadataValidation<S, P>>::validate(
            &IssueValidation,
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
    let (AggregateId::Issue(number), ForgeEventPayload::IssueChangedNative(change)) =
        (submitted.aggregate, &submitted.payload)
    else {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
    };
    let IssueAction::Comment { body } = &change.action else {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
    };
    let template = IssueCommentIntent {
        number,
        body: body.clone(),
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
    let previous = positions
        .entry(stream)
        .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceStale))?;
    let version = AggregateVersion::try_new(previous.successor_position())
        .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid))?
        .next()
        .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ResourceBudgetExceeded))?;
    Ok(ForgeEvent {
        version,
        ..template
    })
}

#[cfg(test)]
mod tests;
