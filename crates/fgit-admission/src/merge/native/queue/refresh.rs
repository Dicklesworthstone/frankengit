//! Refresh only the recorded target of one exact idle queue head. This is an
//! explicitly authorized PR update, not a merge, an enqueue replacement or an
//! implicit relaxation of review/check freshness. The unchanged queue keeps its
//! original order, priority and actors; the new PR version needs fresh evidence.

use std::collections::BTreeSet;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_forge::aggregate::{AggregateId, AggregateVersion, ExpectedVersion, QueueNumber};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, validate_transition};
use fgit_forge::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_types::{AsciiSlug, GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId, RefusalCode};

use super::super::pull_request::PullRequestProjection;
use super::super::{PreparationFailure, delivery, metadata, storage, unavailable};
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, ProjectionFailure,
    ValidatedClosure,
};

/// All observations belong to the immutable submitted request. The full PR
/// data is required so neither retries nor a target refresh can overwrite a
/// concurrent metadata edit, substitute source content or invent a new actor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueHeadRefreshCommand {
    pub number: QueueNumber,
    pub expected_queue_version: AggregateVersion,
    pub expected_policy_epoch: PolicyEpoch,
    pub expected_recorded_target_tip: GitOid,
    pub pull_request: PullRequestCommand,
}

impl QueueHeadRefreshCommand {
    /// Validate the pure command shape before sealing. Only the PR stream
    /// advances: refreshing a queue at its maximum version remains representable.
    pub fn proposed_event(
        &self,
        actor: PrincipalId,
        format: GitHashAlgorithm,
    ) -> Result<ForgeEvent, RefusalCode> {
        if self.pull_request.action != PullRequestAction::Update
            || !matches!(
                self.pull_request.expected_version,
                ExpectedVersion::Exactly(_)
            )
            || self.expected_recorded_target_tip.is_zero()
            || self.expected_recorded_target_tip.algorithm() != format
            || self.expected_recorded_target_tip == self.pull_request.data.target_tip
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        self.pull_request.proposed_event(actor, format)
    }
}

/// Bind the original queue, PR predecessor, policy epoch, recorded target and
/// complete offered metadata. No selected authority head or retry counter is
/// folded into identity, and the request contains no Git ref command.
pub fn queue_head_refresh_proposal(
    context: &AdmissionContext,
    command: &QueueHeadRefreshCommand,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    if command.expected_recorded_target_tip.algorithm() != context.object_format {
        return Err(AdmissionError::ObjectFormatMismatch);
    }
    let event = command
        .proposed_event(context.principal_id, context.object_format)
        .map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let guard = |name, value: Vec<u8>| {
        ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static(name),
            value,
        )
    };
    let request = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![
            guard(
                "queue-head-refresh.event-batch-root",
                root.bytes().as_bytes().to_vec(),
            )?,
            guard(
                "queue-head-refresh.queue-number",
                command.number.get().to_be_bytes().to_vec(),
            )?,
            guard(
                "queue-head-refresh.expected-queue-version",
                command.expected_queue_version.get().to_be_bytes().to_vec(),
            )?,
            guard(
                "queue-head-refresh.expected-policy-epoch",
                command.expected_policy_epoch.get().to_be_bytes().to_vec(),
            )?,
            guard(
                "queue-head-refresh.expected-recorded-target-tip",
                command
                    .expected_recorded_target_tip
                    .to_string()
                    .into_bytes(),
            )?,
        ],
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

/// Reconstruct the entire profile at the shared fold boundary. In particular,
/// dropping a queue guard must never turn this into an ordinary PR command.
pub(in crate::merge) fn verify_refresh_event_seal(
    context: &AdmissionContext,
    event: &ForgeEvent,
    attempt: &SealAttempt,
) -> Result<QueueHeadRefreshCommand, RefusalCode> {
    let (AggregateId::PullRequest(number), ForgeEventPayload::PullRequestChangedNative(change)) =
        (event.aggregate, &event.payload)
    else {
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
    let counter = |name| -> Result<u64, RefusalCode> {
        let bytes: [u8; 8] = guard(name)?
            .try_into()
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        Ok(u64::from_be_bytes(bytes))
    };
    let tip = std::str::from_utf8(guard("queue-head-refresh.expected-recorded-target-tip")?)
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let command = QueueHeadRefreshCommand {
        number: QueueNumber::try_new(counter("queue-head-refresh.queue-number")?)
            .ok_or(RefusalCode::EvidenceInvalid)?,
        expected_queue_version: AggregateVersion::try_new(counter(
            "queue-head-refresh.expected-queue-version",
        )?)
        .ok_or(RefusalCode::EvidenceInvalid)?,
        expected_policy_epoch: PolicyEpoch::try_new(counter(
            "queue-head-refresh.expected-policy-epoch",
        )?)
        .map_err(|_| RefusalCode::EvidenceInvalid)?,
        expected_recorded_target_tip: GitOid::from_hex(context.object_format, tip)
            .map_err(|_| RefusalCode::EvidenceInvalid)?,
        pull_request: PullRequestCommand {
            number,
            expected_version: ExpectedVersion::Exactly(
                AggregateVersion::try_new(event.version.get() - 1)
                    .ok_or(RefusalCode::EvidenceInvalid)?,
            ),
            action: change.action,
            data: change.data.clone(),
        },
    };
    let (expected_event, expected_attempt) =
        queue_head_refresh_proposal(context, &command).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected_event != *event || expected_attempt != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(command)
}

/// Reuse the ordinary metadata owner for sealing, outcome recovery, current
/// authorization, exact-basis revalidation, delivery and the head CAS.
pub async fn admit_queue_head_refresh_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &QueueHeadRefreshCommand,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: PullRequestProjection<S> + ?Sized,
{
    let (event, attempt) = queue_head_refresh_proposal(context, command)?;
    metadata::admit_metadata_async(
        store,
        cx,
        context,
        event,
        attempt,
        limits,
        projection,
        &RefreshValidation(command),
    )
    .await
}

struct RefreshValidation<'a>(&'a QueueHeadRefreshCommand);

impl<S, P> metadata::MetadataValidation<S, P> for RefreshValidation<'_>
where
    S: AsyncAuthorityStore + ?Sized,
    P: PullRequestProjection<S> + ?Sized,
{
    fn precheck(&self, snapshot: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        let data = &self.0.pull_request.data;
        if snapshot.hidden_refs.hides(data.source_ref.as_bytes())
            || snapshot.hidden_refs.hides(data.target_ref.as_bytes())
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
        resolved: &'a super::super::super::NativeMergeBasis,
        event: &'a ForgeEvent,
        projection: &'a P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        let command = self.0;
        let pull = &command.pull_request;
        let hidden = |name: &fgit_types::RefName| snapshot.hidden_refs.hides(name.as_bytes());
        let cancelled = || projection.merge_checkpoint(cx).is_err();
        let mut queues = super::read::replay_selected(
            store,
            cx,
            basis,
            &resolved.forge,
            &resolved.outbox,
            &BTreeSet::from([command.number]),
            &cancelled,
        )
        .await?;
        let queue = queues
            .remove(&command.number)
            .ok_or(ProjectionFailure::Refuse(
                RefusalCode::ProtectedRefTransitionDenied,
            ))?;
        if hidden(&queue.target_ref) || queue.entries.iter().any(|entry| hidden(&entry.source_ref))
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
        }

        let aggregate = AggregateId::PullRequest(pull.number);
        let position = resolved
            .forge
            .entry(storage::aggregate_label(aggregate)?)
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
        let (source, target) = match &selected.payload {
            ForgeEventPayload::PullRequestChangedNative(change) => {
                (&change.data.source_ref, &change.data.target_ref)
            }
            ForgeEventPayload::MergeCommittedNative(change) => {
                (&change.source_ref, &change.target_ref)
            }
            _ => {
                return Err(
                    ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into(),
                );
            }
        };
        if hidden(source) || hidden(target) {
            return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
        }
        if queue.version != command.expected_queue_version
            || basis.body().policy_epoch != command.expected_policy_epoch
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        if queue.target_ref != pull.data.target_ref
            || queue.active_batch.is_some()
            || queue.entries.first().map(|entry| entry.pull_request) != Some(pull.number)
        {
            return Err(
                ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into(),
            );
        }
        let entry = queue.entries.first().ok_or(ProjectionFailure::Refuse(
            RefusalCode::ProtectedRefTransitionDenied,
        ))?;
        if entry.source_ref != pull.data.source_ref || entry.head_tip != pull.data.source_tip {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        let ExpectedVersion::Exactly(previous_version) = pull.expected_version else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        let previous = super::candidate_data(selected, previous_version, &hidden)
            .map_err(ProjectionFailure::Refuse)?;
        validate_transition(Some(selected), event).map_err(ProjectionFailure::Refuse)?;
        let mut refreshed = previous.clone();
        refreshed.target_tip = pull.data.target_tip;
        if previous.target_tip != command.expected_recorded_target_tip || refreshed != pull.data {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        if snapshot.refs.get(&pull.data.source_ref) != Some(&pull.data.source_tip)
            || snapshot.refs.get(&pull.data.target_ref) != Some(&pull.data.target_tip)
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into());
        }
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        Ok(projection
            .validate_pull_request_async(store, cx, basis, authenticated, pull)
            .await?)
    }
}
