//! Independent PR labels through the shared metadata publisher.
//! Current PR visibility is checked on every CAS basis; content and review
//! versions, branch tips and policy are never advanced by label replacement.

use std::collections::BTreeSet;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::CanonicalForgePositionState;
use fgit_forge::event::pull_request_labels::{
    MAX_LABELS, PullRequestLabelsCommand, selected_labels,
};
use fgit_forge::{
    AggregateId, AggregateVersion, ExpectedVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload,
    PullRequestNumber,
};
use fgit_types::{AsciiSlug, RefusalCode};

use super::super::{
    NativeMergeProjection, PreparationFailure, delivery, metadata, storage, unavailable,
};
use crate::merge::NativeMergeBasis;
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, PermittedObjectClosure,
    ProjectionFailure, ValidatedClosure,
};

mod addition;
pub use addition::{addition_proposal, admit_addition_async};

/// The sealed event binds the complete set, exact label predecessor, PR and
/// authenticated actor. A CAS loser never refreshes any submitted field.
pub fn proposal(
    context: &AdmissionContext,
    command: &PullRequestLabelsCommand,
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
            AsciiSlug::from_static("pull-request-labels.event-batch-root.v1"),
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

/// Pure preparation independently binds the actual label event to its seal.
pub(crate) fn verify_event_seal(
    context: &AdmissionContext,
    event: &ForgeEvent,
    attempt: &SealAttempt,
) -> Result<(), RefusalCode> {
    if matches!(
        event.payload,
        ForgeEventPayload::PullRequestLabelsAddedNative(_)
    ) {
        return addition::verify_event_seal(context, event, attempt);
    }
    let (
        AggregateId::PullRequestLabels(number),
        ForgeEventPayload::PullRequestLabelsChangedNative(change),
    ) = (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let expected_version = if event.version == AggregateVersion::FIRST {
        ExpectedVersion::NewStream
    } else {
        ExpectedVersion::Exactly(
            AggregateVersion::try_new(event.version.get() - 1)
                .ok_or(RefusalCode::EvidenceInvalid)?,
        )
    };
    let (expected, sealed) = proposal(
        context,
        &PullRequestLabelsCommand {
            number,
            expected_version,
            labels: change.labels.clone(),
        },
    )
    .map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected != *event || sealed != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(())
}

pub async fn admit_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &PullRequestLabelsCommand,
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
        &Validation,
    )
    .await
}

struct Validation;
impl<S, P> metadata::MetadataValidation<S, P> for Validation
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    fn precheck(&self, _: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        Ok(())
    }

    async fn validate<'a>(
        &'a self,
        store: &'a S,
        cx: &'a S::Context,
        basis: &'a PublicationBasis,
        _: &'a AuthenticatedHead,
        snapshot: &'a AdmissionSnapshot,
        resolved: &'a NativeMergeBasis,
        event: &'a ForgeEvent,
        projection: &'a P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        let AggregateId::PullRequestLabels(number) = event.aggregate else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        let cancelled = || projection.merge_checkpoint(cx).is_err();
        // A retained native open/closed/merged PR is a valid label subject.
        // Legacy and merge-only receipts have no invented native metadata.
        let page = super::read_page_at(
            store,
            cx,
            basis,
            number.get() - 1,
            1,
            &|_, _| true,
            &cancelled,
        )
        .await?;
        let subject = page
            .pull_requests
            .into_iter()
            .find(|row| row.number == number)
            .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))?;
        let data = subject
            .data
            .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
        if snapshot.hidden_refs.hides(data.source_ref.as_bytes())
            || snapshot.hidden_refs.hides(data.target_ref.as_bytes())
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
        }
        let previous = frontier(store, cx, &resolved.forge, number).await?;
        if matches!(
            event.payload,
            ForgeEventPayload::PullRequestLabelsAddedNative(_)
        ) {
            // Version exhaustion, like set capacity, is evaluated only after
            // current capability and native-subject disclosure have passed.
            addition::next_version(previous.as_ref().map(|(event, _)| event))
                .map_err(ProjectionFailure::Refuse)?;
        }
        if previous
            .as_ref()
            .map_or(0, |(previous, _)| previous.version.get())
            != event.version.get() - 1
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        if let ForgeEventPayload::PullRequestLabelsAddedNative(change) = &event.payload {
            let before = previous
                .as_ref()
                .and_then(|(event, _)| selected_labels(&event.payload))
                .map_or(&[][..], |(_, labels)| labels);
            let expected = union(before, &change.additions);
            if expected.len() > MAX_LABELS {
                return Err(ProjectionFailure::Refuse(RefusalCode::ResourceBudgetExceeded).into());
            }
            if change.validate().is_err() || change.labels != expected {
                return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
            }
        }
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

fn union(previous: &[String], additions: &[String]) -> Vec<String> {
    previous
        .iter()
        .chain(additions)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// One bounded full-state event selected by the exact authenticated forge root.
/// Return encoded batch work as well as the event so filtered scans charge all
/// loaded data, including other events in the selected immutable batch.
pub(super) async fn frontier<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    positions: &CanonicalForgePositionState,
    number: PullRequestNumber,
) -> Result<Option<(ForgeEvent, usize)>, AdmissionError> {
    let aggregate = AggregateId::PullRequestLabels(number);
    let Some(entry) = positions.entry(storage::aggregate_label(aggregate)?) else {
        return Ok(None);
    };
    let events = storage::read_events(
        store,
        cx,
        positions.repository_id(),
        entry.event_batch_root(),
    )
    .await?;
    delivery::validate_position_batch(entry, &events)?;
    let bytes = fgit_codec::encode_body(&events)
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
        .len();
    let event = events
        .events
        .into_iter()
        .rev()
        .find(|event| event.aggregate == aggregate)
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    if event.version.get() != entry.successor_position()
        || !matches!(
            event.payload,
            ForgeEventPayload::PullRequestLabelsChangedNative(_)
                | ForgeEventPayload::PullRequestLabelsAddedNative(_)
        )
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(Some((event, bytes)))
}
