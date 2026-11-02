//! Canonical self-owned preferences over the existing sealed metadata owner.
use super::super::NativeMergeBasis;
use super::{NativeMergeProjection, PreparationFailure, metadata, storage, unavailable};
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, PermittedObjectClosure,
    ProjectionFailure, ValidatedClosure,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_forge::event::notification::{NotificationAction, NotificationCommand, apply_event};
use fgit_forge::{
    AggregateId, AggregateVersion, ExpectedVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload,
};
use fgit_types::{AsciiSlug, RefusalCode};
use std::collections::BTreeSet;

mod source;
pub use source::{NotificationSourceSnapshot, NotificationThread, read_source_at};

pub fn proposal(
    context: &AdmissionContext,
    command: &NotificationCommand,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = command
        .proposed_event(context.principal_id)
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
            AsciiSlug::from_static("notification.event-batch-root.v1"),
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

pub(in crate::merge) fn verify_event_seal(
    context: &AdmissionContext,
    event: &ForgeEvent,
    attempt: &SealAttempt,
) -> Result<(), RefusalCode> {
    let (
        AggregateId::NotificationPreference { principal, issue },
        ForgeEventPayload::NotificationPreferenceChangedNative(change),
    ) = (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    if principal != context.principal_id || change.actor != principal {
        return Err(RefusalCode::EvidenceInvalid);
    }
    let expected_version = if event.version == AggregateVersion::FIRST {
        ExpectedVersion::NewStream
    } else {
        ExpectedVersion::Exactly(
            AggregateVersion::try_new(event.version.get() - 1)
                .ok_or(RefusalCode::EvidenceInvalid)?,
        )
    };
    let command = NotificationCommand {
        number: issue,
        expected_version,
        action: change.action,
    };
    let (expected_event, expected_attempt) =
        proposal(context, &command).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected_event != *event || expected_attempt != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(())
}

pub async fn admit_notification_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &NotificationCommand,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let (event, attempt) = proposal(context, command)?;
    metadata::admit_metadata_async(
        store,
        cx,
        context,
        event,
        attempt,
        limits,
        projection,
        &NotificationValidation,
    )
    .await
}

fn validate_current_thread(
    thread: Option<&NotificationThread>,
    event: &ForgeEvent,
) -> Result<(), RefusalCode> {
    let Some(thread) = thread else {
        return Err(RefusalCode::EvidenceMissing);
    };
    let (
        AggregateId::NotificationPreference { issue, .. },
        ForgeEventPayload::NotificationPreferenceChangedNative(change),
    ) = (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    if issue != thread.issue.number {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if let NotificationAction::SetReadThrough(Some(through)) = change.action {
        if through > thread.issue.version {
            return Err(RefusalCode::EvidenceStale);
        }
    }
    apply_event(thread.preference.as_ref(), event)?;
    Ok(())
}

struct NotificationValidation;
impl<S, P> metadata::MetadataValidation<S, P> for NotificationValidation
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    fn precheck(&self, _: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        Ok(())
    }
    async fn validate(
        &self,
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        _: &AuthenticatedHead,
        _: &AdmissionSnapshot,
        _: &NativeMergeBasis,
        event: &ForgeEvent,
        projection: &P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        let AggregateId::NotificationPreference { principal, issue } = event.aggregate else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        let source = read_source_at(store, cx, basis, principal, &|| {
            projection.merge_checkpoint(cx).is_err()
        })
        .await?;
        validate_current_thread(
            source
                .threads
                .iter()
                .find(|thread| thread.issue.number == issue),
            event,
        )
        .map_err(ProjectionFailure::Refuse)?;
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let closure = PermittedObjectClosure::default();
        Ok(ValidatedClosure {
            object_closure_root: crate::permitted_object_closure_root(&closure)
                .map_err(ProjectionFailure::Unavailable)?,
            objects: BTreeSet::new(),
        })
    }
}

#[cfg(test)]
mod seal_tests;
