//! One explicitly reviewed two-parent candidate at the exact canonical queue
//! head. Candidate bytes remain the native merge projection's responsibility;
//! neither a queue batch identifier nor this command asserts passing checks.

use std::collections::BTreeMap;

use fgit_authority::{
    AsyncAuthorityStore, ExpectedOld, ProposedNew, RefCommand, ScopedEntry, SealAttempt,
    SemanticRequest, TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_forge::aggregate::{
    AggregateId, AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber,
};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::queue::{NativeQueueEvent, QueueAction};
use fgit_forge::merge_queue::{QueueBatchEntry, QueueBatchId};
use fgit_forge::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_reference::effect::RefEffect;
use fgit_reference::intent::{ForgeEntityId, ForgeEventKind};
use fgit_types::{AsciiSlug, PolicyEpoch, RefusalCode, TxId};

use super::super::{
    NativeMergeIntent, NativeMergeProjection, admit_merge_attempt_async, storage, unavailable,
};
use super::{Landing, QueueLandingCommand};
use crate::merge::prepare::{CoupledForgeEvents, prepare_coupled_events};
use crate::merge::{NativeMergeBasis, PreparedNativeMerge};
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, ValidatedClosure};

/// Immutable queue, PR and policy observations plus the independently selected
/// native candidate. This command always means a two-parent merge commit; it
/// never falls back to fast-forward, squash or a newly prepared candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueCandidateLandingCommand {
    pub number: QueueNumber,
    pub expected_version: AggregateVersion,
    pub expected_policy_epoch: PolicyEpoch,
    pub pull_request: PullRequestNumber,
    pub expected_pull_request_version: AggregateVersion,
    pub merge: NativeMerge,
}

impl QueueCandidateLandingCommand {
    pub(super) fn intent(&self) -> Result<NativeMergeIntent, AdmissionError> {
        validate_candidate_coordinates(&self.merge).map_err(unavailable)?;
        NativeMergeIntent::new(
            self.pull_request,
            ExpectedVersion::Exactly(self.expected_pull_request_version),
            self.merge.clone(),
        )
    }

    /// Shared queue selection guards only. The typed landing variant retains
    /// the candidate method and complete seal; these observations cannot turn
    /// candidate publication into the fast-forward profile.
    pub(super) fn guards(&self) -> QueueLandingCommand {
        QueueLandingCommand {
            number: self.number,
            expected_version: self.expected_version,
            expected_policy_epoch: self.expected_policy_epoch,
            pull_request: self.pull_request,
            expected_pull_request_version: self.expected_pull_request_version,
            source_ref: self.merge.source_ref.clone(),
            head_tip: self.merge.source_tip,
            target_ref: self.merge.target_ref.clone(),
            expected_target_tip: self.merge.target_tip_before,
        }
    }
}

fn validate_candidate_coordinates(merge: &NativeMerge) -> Result<(), RefusalCode> {
    merge.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
    if merge.source_tip == merge.target_tip_before
        || merge.merge_commit == merge.source_tip
        || merge.merge_commit == merge.base_tip
    {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(())
}

/// Bind every native coordinate, both stream predecessors, the exact policy
/// epoch and fixed merge method. The historical fast-forward seal is untouched.
pub fn candidate_landing_proposal(
    context: &AdmissionContext,
    command: &QueueCandidateLandingCommand,
) -> Result<(ForgeEventBatch, SealAttempt), AdmissionError> {
    let intent = command.intent()?;
    let merge = &command.merge;
    if merge.merge_commit.algorithm() != context.object_format {
        return Err(AdmissionError::ObjectFormatMismatch);
    }
    let formed_version = command
        .expected_version
        .next()
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    let landed_version = formed_version
        .next()
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    let batch_id = QueueBatchId::compute(
        &merge.target_ref,
        merge.target_tip_before,
        &[QueueBatchEntry {
            pull_request: command.pull_request,
            source_ref: merge.source_ref.clone(),
            head_tip: merge.source_tip,
        }],
    )
    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    let queue_event = |version, action| ForgeEvent {
        aggregate: AggregateId::MergeQueue(command.number),
        version,
        payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
            queue_number: command.number,
            target_ref: merge.target_ref.clone(),
            action,
        }),
    };
    let batch = ForgeEventBatch {
        events: vec![
            queue_event(
                formed_version,
                QueueAction::BatchFormed {
                    batch_id: *batch_id.digest(),
                    entries: vec![command.pull_request],
                },
            ),
            intent.event().clone(),
            queue_event(
                landed_version,
                QueueAction::BatchLanded {
                    batch_id: *batch_id.digest(),
                    entries: vec![command.pull_request],
                    target_tip: merge.merge_commit,
                },
            ),
        ],
    };
    validate_candidate_landing_shape(&batch).map_err(unavailable)?;
    let event_root = storage::root(&batch)?;
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
        vec![
            ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("queue.landing-event-batch-root"),
                event_root.bytes().as_bytes(),
            )?,
            ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("queue.landing-policy-epoch"),
                command.expected_policy_epoch.get().to_be_bytes(),
            )?,
            ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("queue.landing-profile"),
                b"two-parent-head/v1",
            )?,
            ScopedEntry::new(
                AsciiSlug::from_static("forge"),
                AsciiSlug::from_static("queue.landing-method"),
                b"merge-commit/v1",
            )?,
        ],
    )?;
    Ok((
        batch,
        SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(),
            request,
        },
    ))
}

/// Use ordinary native two-parent object validation, exact reviews and real
/// canonical workflow checks before the shared single-decision publication.
pub async fn admit_candidate_landing_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &QueueCandidateLandingCommand,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    limits.validate()?;
    let intent = command.intent()?;
    let (_, attempt) = candidate_landing_proposal(context, command)?;
    admit_merge_attempt_async(
        store,
        cx,
        context,
        &intent,
        &attempt,
        None,
        limits,
        projection,
        Some(Landing::Candidate(command)),
    )
    .await
}

/// Positive shape validation for the distinct candidate profile. Actual ordered
/// parents, common-base ancestry and object bytes are independently validated
/// by the native merge projection; no event payload can stand in for that work.
pub(in crate::merge) fn validate_candidate_landing_shape(
    batch: &ForgeEventBatch,
) -> Result<&ForgeEvent, RefusalCode> {
    let [formed, merged, landed] = batch.events.as_slice() else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let (
        ForgeEventPayload::MergeQueueChangedNative(formation),
        ForgeEventPayload::MergeCommittedNative(merge),
        ForgeEventPayload::MergeQueueChangedNative(landing),
        AggregateId::PullRequest(pull_request),
    ) = (
        &formed.payload,
        &merged.payload,
        &landed.payload,
        merged.aggregate,
    )
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    formation
        .validate()
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    landing
        .validate()
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    validate_candidate_coordinates(merge)?;
    let (
        QueueAction::BatchFormed { batch_id, entries },
        QueueAction::BatchLanded {
            batch_id: landed_id,
            entries: landed_entries,
            target_tip,
        },
    ) = (&formation.action, &landing.action)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    if formed.aggregate != AggregateId::MergeQueue(formation.queue_number)
        || landed.aggregate != formed.aggregate
        || formation.queue_number != landing.queue_number
        || formation.target_ref != merge.target_ref
        || landing.target_ref != merge.target_ref
        || formed.version == AggregateVersion::FIRST
        || formed.version.next().ok() != Some(landed.version)
        || merged.version == AggregateVersion::FIRST
        || entries.as_slice() != [pull_request]
        || landed_entries != entries
        || landed_id != batch_id
        || *target_tip != merge.merge_commit
    {
        return Err(RefusalCode::EvidenceInvalid);
    }
    let expected = QueueBatchId::compute(
        &merge.target_ref,
        merge.target_tip_before,
        &[QueueBatchEntry {
            pull_request,
            source_ref: merge.source_ref.clone(),
            head_tip: merge.source_tip,
        }],
    )
    .map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected.digest() != batch_id {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(merged)
}

pub(in crate::merge) fn prepare_candidate_landing(
    context: &AdmissionContext,
    command: &QueueCandidateLandingCommand,
    events: &ForgeEventBatch,
    closure: &ValidatedClosure,
    tx_id: TxId,
    attempt: &SealAttempt,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
) -> Result<PreparedNativeMerge, RefusalCode> {
    let (expected_events, expected_attempt) =
        candidate_landing_proposal(context, command).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected_events != *events || expected_attempt != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if basis.body().policy_epoch != command.expected_policy_epoch {
        return Err(RefusalCode::EvidenceStale);
    }
    let merge = &command.merge;
    if resolved.refs.refs().get(&merge.source_ref) != Some(&merge.source_tip)
        || resolved.refs.refs().get(&merge.target_ref) != Some(&merge.target_tip_before)
    {
        return Err(RefusalCode::TargetRefMoved);
    }
    if [
        merge.source_tip,
        merge.base_tip,
        merge.target_tip_before,
        merge.merge_commit,
    ]
    .iter()
    .any(|oid| !closure.objects.contains(oid))
    {
        return Err(RefusalCode::ObjectClosureIncomplete);
    }
    let queue = ForgeEntityId::new(
        storage::aggregate_label(AggregateId::MergeQueue(command.number))
            .map_err(|_| RefusalCode::EvidenceInvalid)?,
    );
    let pull_request = ForgeEntityId::new(
        storage::aggregate_label(AggregateId::PullRequest(command.pull_request))
            .map_err(|_| RefusalCode::EvidenceInvalid)?,
    );
    let queue_change = ForgeEventKind::MergeQueueChanged {
        queue,
        target: merge.target_ref.clone(),
    };
    prepare_coupled_events(
        context,
        CoupledForgeEvents {
            events: events.clone(),
            kinds: vec![
                queue_change.clone(),
                ForgeEventKind::PullRequestMerged {
                    pull_request,
                    target: merge.target_ref.clone(),
                },
                queue_change,
            ],
            refs: BTreeMap::from([(merge.target_ref.clone(), RefEffect::Set(merge.merge_commit))]),
        },
        closure,
        tx_id,
        attempt,
        basis,
        resolved,
    )
}

#[cfg(test)]
mod tests;
