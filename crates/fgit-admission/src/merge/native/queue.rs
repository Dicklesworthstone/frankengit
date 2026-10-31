//! Queue management through the ordinary sealed metadata admission protocol.
//! Management commands record candidate intent. The separate immediate landing
//! profiles execute one exact queue head as an existing fast-forward tip or an
//! explicitly reviewed two-parent candidate. Native merge validation publishes
//! its ref, PR and queue changes in one transaction.
use super::{NativeMergeProjection, PreparationFailure, delivery, metadata, storage, unavailable};
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, PermittedObjectClosure,
    ProjectionFailure, ValidatedClosure,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_forge::aggregate::{AggregateId, AggregateVersion, ExpectedVersion};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestData};
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_types::{AsciiSlug, GitOid, RefusalCode};
use std::collections::BTreeSet;

mod read;
pub use read::{QueuePage, read_page_at, read_queue_at};
mod landing;
pub(super) use landing::validate_landing_at;
pub use landing::{
    QueueLandingCommand, ValidatedQueueLanding, admit_landing_async, landing_proposal,
};
mod candidate;
pub use candidate::{
    QueueCandidateLandingCommand, admit_candidate_landing_async, candidate_landing_proposal,
};
mod execution;
pub(in crate::merge) use execution::{Landing, validate_publication_shape};

/// Bind actor, queue identity, expected predecessor, action and candidate guards
/// without placing a selected head or retry counter into transaction identity.
pub fn proposal(
    context: &AdmissionContext,
    command: &QueueCommand,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = command
        .proposed_event(context.principal_id, context.object_format)
        .map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let mut guards = vec![ScopedEntry::new(
        AsciiSlug::from_static("forge"),
        AsciiSlug::from_static("queue.event-batch-root"),
        root.bytes().as_bytes(),
    )?];
    if let QueueCommandAction::Enqueue {
        expected_pull_request_version,
        expected_target_tip,
        ..
    } = &command.action
    {
        guards.push(ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static("queue.expected-pull-request-version"),
            expected_pull_request_version.get().to_be_bytes(),
        )?);
        guards.push(ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static("queue.expected-target-tip"),
            expected_target_tip.to_string().as_bytes(),
        )?);
    }
    let request = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        guards,
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

/// Independently reconstruct the complete request at the shared fold boundary.
/// Extra/missing guards, actor substitution and batch-event injection refuse.
pub(in crate::merge) fn verify_event_seal(
    context: &AdmissionContext,
    event: &ForgeEvent,
    attempt: &SealAttempt,
) -> Result<QueueCommand, RefusalCode> {
    use fgit_forge::event::queue::QueueAction;
    let ForgeEventPayload::MergeQueueChangedNative(change) = &event.payload else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let guard = |name: &str| {
        attempt
            .request
            .scoped_entries()
            .iter()
            .find(|entry| entry.namespace.as_str() == "forge" && entry.key.as_str() == name)
            .map(|entry| entry.value.as_slice())
            .ok_or(RefusalCode::EvidenceInvalid)
    };
    let action = match &change.action {
        QueueAction::Enqueue {
            pull_request,
            source_ref,
            head_tip,
            enqueued_by,
            priority,
        } if *enqueued_by == context.principal_id => {
            let version: [u8; 8] = guard("queue.expected-pull-request-version")?
                .try_into()
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
            let expected_pull_request_version =
                AggregateVersion::try_new(u64::from_be_bytes(version))
                    .ok_or(RefusalCode::EvidenceInvalid)?;
            let tip = std::str::from_utf8(guard("queue.expected-target-tip")?)
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
            let expected_target_tip = GitOid::from_hex(context.object_format, tip)
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
            QueueCommandAction::Enqueue {
                pull_request: *pull_request,
                expected_pull_request_version,
                source_ref: source_ref.clone(),
                head_tip: *head_tip,
                expected_target_tip,
                priority: *priority,
            }
        }
        QueueAction::Dequeue {
            pull_request,
            dequeued_by,
            reason,
        } if *dequeued_by == context.principal_id => QueueCommandAction::Dequeue {
            pull_request: *pull_request,
            reason: *reason,
        },
        QueueAction::Reorder {
            order,
            reordered_by,
        } if *reordered_by == context.principal_id => QueueCommandAction::Reorder {
            order: order.clone(),
        },
        _ => return Err(RefusalCode::EvidenceInvalid),
    };
    let command = QueueCommand {
        number: change.queue_number,
        target_ref: change.target_ref.clone(),
        expected_version: if event.version == AggregateVersion::FIRST {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(
                AggregateVersion::try_new(event.version.get() - 1)
                    .ok_or(RefusalCode::EvidenceInvalid)?,
            )
        },
        action,
    };
    let (expected_event, expected_attempt) =
        proposal(context, &command).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected_event != *event || expected_attempt != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(command)
}

pub async fn admit_queue_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &QueueCommand,
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
        &QueueValidation(command),
    )
    .await
}

fn candidate_data<'a>(
    selected: &'a ForgeEvent,
    expected_version: AggregateVersion,
    hidden: &impl Fn(&fgit_types::RefName) -> bool,
) -> Result<&'a PullRequestData, RefusalCode> {
    let (source, target) = match &selected.payload {
        ForgeEventPayload::PullRequestChangedNative(change) => {
            (&change.data.source_ref, &change.data.target_ref)
        }
        ForgeEventPayload::MergeCommittedNative(change) => (&change.source_ref, &change.target_ref),
        // Native readers expose no legacy candidate. Refuse it exactly like
        // an absent native PR before evaluating attacker-chosen version probes.
        _ => return Err(RefusalCode::ProtectedRefTransitionDenied),
    };
    if hidden(source) || hidden(target) {
        return Err(RefusalCode::HiddenRefUnauthorized);
    }
    let ForgeEventPayload::PullRequestChangedNative(change) = &selected.payload else {
        return Err(RefusalCode::ProtectedRefTransitionDenied);
    };
    if change.action == PullRequestAction::Close {
        return Err(RefusalCode::ProtectedRefTransitionDenied);
    }
    if selected.version != expected_version {
        return Err(RefusalCode::EvidenceStale);
    }
    Ok(&change.data)
}

struct QueueValidation<'a>(&'a QueueCommand);
impl<S, P> metadata::MetadataValidation<S, P> for QueueValidation<'_>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    fn precheck(&self, snapshot: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        if snapshot.hidden_refs.hides(self.0.target_ref.as_bytes())
            || matches!(&self.0.action, QueueCommandAction::Enqueue { source_ref, .. } if snapshot.hidden_refs.hides(source_ref.as_bytes()))
        {
            Err(ProjectionFailure::Refuse(
                RefusalCode::HiddenRefUnauthorized,
            ))
        } else {
            Ok(())
        }
    }
    async fn validate(
        &self,
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        _: &AuthenticatedHead,
        snapshot: &AdmissionSnapshot,
        resolved: &super::super::NativeMergeBasis,
        event: &ForgeEvent,
        projection: &P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        let command = self.0;
        let cancelled = || projection.merge_checkpoint(cx).is_err();
        let mut queues = read::replay_selected(
            store,
            cx,
            basis,
            &resolved.forge,
            &resolved.outbox,
            &BTreeSet::from([command.number]),
            &cancelled,
        )
        .await?;
        let previous = queues.remove(&command.number);
        // Selected coordinates, never spoofable command coordinates, govern
        // disclosure before state-specific lifecycle/version refusals.
        if let Some(queue) = &previous
            && (snapshot.hidden_refs.hides(queue.target_ref.as_bytes())
                || queue
                    .entries
                    .iter()
                    .any(|entry| snapshot.hidden_refs.hides(entry.source_ref.as_bytes())))
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
        }
        let observed = previous.as_ref().map(|queue| queue.version);
        if match command.expected_version {
            ExpectedVersion::NewStream => observed.is_some(),
            ExpectedVersion::Exactly(expected) => observed != Some(expected),
        } {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        if previous
            .as_ref()
            .is_some_and(|queue| queue.target_ref != command.target_ref)
        {
            return Err(
                ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into(),
            );
        }
        if let QueueCommandAction::Enqueue {
            pull_request,
            expected_pull_request_version,
            source_ref,
            head_tip,
            expected_target_tip,
            ..
        } = &command.action
        {
            let aggregate = AggregateId::PullRequest(*pull_request);
            let label = storage::aggregate_label(aggregate)?;
            let position = resolved
                .forge
                .entry(label)
                .ok_or(ProjectionFailure::Refuse(
                    RefusalCode::ProtectedRefTransitionDenied,
                ))?;
            let batch = storage::read_events(
                store,
                cx,
                basis.body().repository_id,
                position.event_batch_root(),
            )
            .await?;
            delivery::validate_position_batch(position, &batch)?;
            let selected = batch
                .events
                .iter()
                .rev()
                .find(|event| event.aggregate == aggregate)
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            let data = candidate_data(selected, *expected_pull_request_version, &|name| {
                snapshot.hidden_refs.hides(name.as_bytes())
            })
            .map_err(ProjectionFailure::Refuse)?;
            if data.source_ref != *source_ref
                || data.target_ref != command.target_ref
                || data.source_tip != *head_tip
                || data.target_tip != *expected_target_tip
            {
                return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
            }
            if snapshot.refs.get(source_ref) != Some(head_tip)
                || snapshot.refs.get(&command.target_ref) != Some(expected_target_tip)
            {
                return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into());
            }
        }
        let mut next = previous.unwrap_or_else(|| {
            fgit_forge::merge_queue::MergeQueueSnapshot::new(
                command.number,
                command.target_ref.clone(),
            )
        });
        if let QueueCommandAction::Reorder { order } = &command.action
            && (order.len() != next.len()
                || order
                    .iter()
                    .any(|number| next.find_entry(*number).is_none()))
        {
            return Err(
                ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into(),
            );
        }
        if matches!(command.action, QueueCommandAction::Enqueue { pull_request, .. } if next.find_entry(pull_request).is_none() && next.len() >= fgit_forge::event::queue::MAX_QUEUE_ENTRIES)
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::ResourceBudgetExceeded).into());
        }
        next.apply_event(event)
            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))?;
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
mod tests;
