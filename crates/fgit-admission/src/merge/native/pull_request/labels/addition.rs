//! Version-independent label additions with a sealed original set.

use super::*;
use fgit_forge::event::admission::ForgeCommandProfile;
use fgit_forge::event::pull_request_labels::{
    NativePullRequestLabelsAddedEvent, PullRequestLabelsIntent,
};

/// Seal only the actor, PR and exact additions, using a version-one commitment
/// template. Its scope cannot be confused with an exact replacement request.
pub fn addition_proposal(
    context: &AdmissionContext,
    intent: &PullRequestLabelsIntent,
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
            AsciiSlug::from_static("pull-request.add-labels.v1"),
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

pub(super) fn verify_event_seal(
    context: &AdmissionContext,
    event: &ForgeEvent,
    attempt: &SealAttempt,
) -> Result<(), RefusalCode> {
    let (
        AggregateId::PullRequestLabels(number),
        ForgeEventPayload::PullRequestLabelsAddedNative(change),
    ) = (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    change
        .validate()
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let (_, expected) = addition_proposal(
        context,
        &PullRequestLabelsIntent {
            number,
            labels: change.additions.clone(),
        },
    )
    .map_err(|_| RefusalCode::EvidenceInvalid)?;
    if change.actor != context.principal_id || expected != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(())
}

pub async fn admit_addition_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    intent: &PullRequestLabelsIntent,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let (event, attempt) = addition_proposal(context, intent)?;
    metadata::admit_metadata_async(
        store,
        cx,
        context,
        event,
        attempt,
        limits,
        projection,
        &AdditionValidation,
    )
    .await
}

struct AdditionValidation;
impl<S, P> metadata::MetadataValidation<S, P> for AdditionValidation
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    fn command_profile(&self) -> ForgeCommandProfile {
        ForgeCommandProfile::AddPullRequestLabelsV1
    }

    fn precheck(&self, _: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        Ok(())
    }

    async fn plan_event_async<'a>(
        &'a self,
        store: &'a S,
        cx: &'a S::Context,
        context: &'a AdmissionContext,
        submitted: &'a ForgeEvent,
        resolved: &'a NativeMergeBasis,
    ) -> Result<ForgeEvent, PreparationFailure> {
        let (
            AggregateId::PullRequestLabels(number),
            ForgeEventPayload::PullRequestLabelsAddedNative(change),
        ) = (submitted.aggregate, &submitted.payload)
        else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        let template = PullRequestLabelsIntent {
            number,
            labels: change.additions.clone(),
        }
        .commitment_event(context.principal_id)
        .map_err(ProjectionFailure::Refuse)?;
        if template != *submitted {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        }
        if resolved.forge.repository_id() != context.repository_id {
            return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale).into());
        }
        let previous = frontier(store, cx, &resolved.forge, number).await?;
        // Exhaustion is a business refusal, so it must wait for current
        // capability and subject-disclosure checks. FIRST is only a planning
        // placeholder here: Validation independently checks the real successor
        // and refuses overflow before this event can reach preparation.
        let version = next_version(previous.as_ref().map(|(event, _)| event))
            .unwrap_or(AggregateVersion::FIRST);
        let before = previous
            .as_ref()
            .and_then(|(event, _)| selected_labels(&event.payload))
            .map_or(&[][..], |(_, labels)| labels);
        // At most two bounded sets are merged here. Capacity is checked by the
        // validator after current subject visibility and capability checks.
        Ok(ForgeEvent {
            aggregate: submitted.aggregate,
            version,
            payload: ForgeEventPayload::PullRequestLabelsAddedNative(
                NativePullRequestLabelsAddedEvent {
                    actor: change.actor,
                    additions: change.additions.clone(),
                    labels: union(before, &change.additions),
                },
            ),
        })
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

pub(super) fn next_version(previous: Option<&ForgeEvent>) -> Result<AggregateVersion, RefusalCode> {
    previous.map_or(Ok(AggregateVersion::FIRST), |event| {
        event
            .version
            .next()
            .map_err(|_| RefusalCode::ResourceBudgetExceeded)
    })
}

#[cfg(test)]
mod tests;
