//! Immediate execution of one exact queue head. Formation, the native PR merge
//! and completion are one sealed batch; there is no intermediate authoritative
//! batch or speculative ref. The existing native fast-forward validator still
//! proves ancestry and enforces the selected authentication, reviews and checks.

use std::collections::{BTreeMap, BTreeSet};

use fgit_authority::{
    AsyncAuthorityStore, ExpectedOld, ProposedNew, RefCommand, ScopedEntry, SealAttempt,
    SemanticRequest, TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_forge::aggregate::{AggregateId, AggregateVersion, PullRequestNumber, QueueNumber};
use fgit_forge::event::queue::{NativeQueueEvent, QueueAction};
use fgit_forge::merge_queue::{QueueBatchEntry, QueueBatchId};
use fgit_forge::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_reference::effect::RefEffect;
use fgit_reference::intent::{ForgeEntityId, ForgeEventKind};
use fgit_types::{AsciiSlug, Digest, GitOid, PolicyEpoch, PrincipalId, RefName, RefusalCode, TxId};

use super::super::{
    NativeMergeIntent, NativeMergeProjection, PreparationFailure, admit_merge_attempt_async,
    delivery, storage, unavailable,
};
use crate::merge::prepare::{CoupledForgeEvents, prepare_coupled_events};
use crate::merge::{NativeMergeBasis, PreparedNativeMerge};
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, ProjectionFailure,
    ValidatedClosure,
};

/// Exact observations authorizing the immediate fast-forward of one queue head.
/// Both streams and the policy epoch are immutable semantic guards, not values
/// silently refreshed on a CAS retry. No merge method fallback is permitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueLandingCommand {
    pub number: QueueNumber,
    pub expected_version: AggregateVersion,
    pub expected_policy_epoch: PolicyEpoch,
    pub pull_request: PullRequestNumber,
    pub expected_pull_request_version: AggregateVersion,
    pub source_ref: RefName,
    pub head_tip: GitOid,
    pub target_ref: RefName,
    pub expected_target_tip: GitOid,
}

impl QueueLandingCommand {
    pub(super) fn intent(&self) -> Result<NativeMergeIntent, AdmissionError> {
        NativeMergeIntent::fast_forward_only(
            self.pull_request,
            self.expected_pull_request_version,
            self.source_ref.clone(),
            self.head_tip,
            self.target_ref.clone(),
            self.expected_target_tip,
        )
    }
}

/// Attempt-local proof that this exact native merge is the authenticated queue
/// head at one immutable authority basis. Only queue admission can construct
/// it, after replaying that queue and checking the selected PR, live refs,
/// policy epoch, visibility and complete sealed publication. It is not a
/// caller-selected merge mode or a receipt that survives a CAS replan.
#[derive(Debug)]
pub struct ValidatedQueueLanding {
    context: AdmissionContext,
    basis: PublicationBasis,
    intent: NativeMergeIntent,
    attempt: SealAttempt,
    event_root: Digest,
}

impl ValidatedQueueLanding {
    pub(in crate::merge::native) fn verify_intent(
        &self,
        basis: &PublicationBasis,
        intent: &NativeMergeIntent,
        submitter: PrincipalId,
    ) -> Result<(), RefusalCode> {
        if self.basis != *basis || self.intent != *intent || self.context.principal_id != submitter
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }

    pub(in crate::merge::native) fn verify_effect(
        &self,
        basis: &PublicationBasis,
        submitter: Option<PrincipalId>,
        target: &RefName,
        previous: Option<GitOid>,
        effect: &RefEffect,
    ) -> Result<(), RefusalCode> {
        let merge = self
            .intent
            .merge()
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        if self.basis != *basis
            || submitter != Some(self.context.principal_id)
            || target != &merge.target_ref
            || previous != Some(merge.target_tip_before)
            || *effect != RefEffect::Set(merge.merge_commit)
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }

    /// The final policy attachment must see the same fully folded publication,
    /// not merely a caller choosing the generic `NativeMerge` policy profile.
    pub(in crate::merge::native) fn verify_prepared(
        &self,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        prepared: &PreparedNativeMerge,
    ) -> Result<(), RefusalCode> {
        let (tx_id, seal) = self
            .attempt
            .derive()
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        let event_root =
            storage::root(&prepared.event).map_err(|_| RefusalCode::EvidenceInvalid)?;
        let record = &prepared.materialization.record;
        let effects = prepared
            .fold
            .effects()
            .ok_or(RefusalCode::EvidenceInvalid)?;
        let merge = self
            .intent
            .merge()
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        if self.context != *context
            || self.basis != *basis
            || prepared.request.tx_id != tx_id
            || prepared.request.tenant != context.tenant_id
            || prepared.request.repository != context.repository_id
            || prepared.request.principal != context.principal_id
            || prepared.request.canonical_request_digest != seal.canonical_request_digest
            || record.tx_id != tx_id
            || record.canonical_request_digest != seal.canonical_request_digest
            || record.policy_epoch != basis.body().policy_epoch
            || event_root != self.event_root
            || record.forge_event_batch_root != self.event_root
            || super::validate_publication_shape(&prepared.event)? != self.intent.event()
            || effects.refs.len() != 1
            || effects.refs.get(&merge.target_ref) != Some(&RefEffect::Set(merge.merge_commit))
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }
}

/// Bind the complete ordered batch, exact non-force target move and selected
/// policy epoch. Existing ordinary native merge seals remain byte-identical.
pub fn landing_proposal(
    context: &AdmissionContext,
    command: &QueueLandingCommand,
) -> Result<(ForgeEventBatch, SealAttempt), AdmissionError> {
    let intent = command.intent()?;
    if command.head_tip.algorithm() != context.object_format
        || command.expected_target_tip.algorithm() != context.object_format
    {
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
        &command.target_ref,
        command.expected_target_tip,
        &[QueueBatchEntry {
            pull_request: command.pull_request,
            source_ref: command.source_ref.clone(),
            head_tip: command.head_tip,
        }],
    )
    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    let queue_event = |version, action| ForgeEvent {
        aggregate: AggregateId::MergeQueue(command.number),
        version,
        payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
            queue_number: command.number,
            target_ref: command.target_ref.clone(),
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
                    target_tip: command.head_tip,
                },
            ),
        ],
    };
    validate_landing_shape(&batch).map_err(unavailable)?;
    let event_root = storage::root(&batch)?;
    let request = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        vec![RefCommand {
            name: command.target_ref.clone(),
            expected_old: ExpectedOld::Exactly(command.expected_target_tip),
            proposed_new: ProposedNew::Update(command.head_tip),
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
                b"fast-forward-head/v1",
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

pub async fn admit_landing_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &QueueLandingCommand,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    limits.validate()?;
    let intent = command.intent()?;
    let (_, attempt) = landing_proposal(context, command)?;
    admit_merge_attempt_async(
        store,
        cx,
        context,
        &intent,
        &attempt,
        None,
        limits,
        projection,
        Some(super::Landing::FastForward(command)),
    )
    .await
}

/// The only supported multi-event native publication shape. A well-formed
/// arbitrary batch, a different merge method or a second PR cannot pass this
/// boundary. The returned middle event is the one protected native merge.
pub(in crate::merge) fn validate_landing_shape(
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
    merge.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
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
        || merge.merge_commit != merge.source_tip
        || merge.base_tip != merge.target_tip_before
        || merge.source_tip == merge.target_tip_before
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

pub(in crate::merge::native) async fn validate_landing_at<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    snapshot: &AdmissionSnapshot,
    resolved: &NativeMergeBasis,
    selection: super::Landing<'_>,
    events: &ForgeEventBatch,
    intent: &NativeMergeIntent,
    attempt: &SealAttempt,
    projection: &P,
) -> Result<ValidatedQueueLanding, PreparationFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let command = selection.guards();
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
    let mut queue = queues
        .remove(&command.number)
        .ok_or(ProjectionFailure::Refuse(
            RefusalCode::ProtectedRefTransitionDenied,
        ))?;
    let hidden = |name: &RefName| snapshot.hidden_refs.hides(name.as_bytes());
    if hidden(&queue.target_ref) || queue.entries.iter().any(|entry| hidden(&entry.source_ref)) {
        return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
    }
    let aggregate = AggregateId::PullRequest(command.pull_request);
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
    // Actual selected coordinates govern visibility before version probes.
    // A native merged PR may have been landed by a competing queue request:
    // retain that queue's stale-version refusal without exposing hidden refs.
    let (source, target) = match &selected.payload {
        ForgeEventPayload::PullRequestChangedNative(change) => {
            (&change.data.source_ref, &change.data.target_ref)
        }
        ForgeEventPayload::MergeCommittedNative(merge) => (&merge.source_ref, &merge.target_ref),
        _ => {
            return Err(
                ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into(),
            );
        }
    };
    if hidden(source) || hidden(target) {
        return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
    }
    if queue.version != command.expected_version
        || basis.body().policy_epoch != command.expected_policy_epoch
    {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
    }
    let data = super::candidate_data(selected, command.expected_pull_request_version, &hidden)
        .map_err(ProjectionFailure::Refuse)?;
    if queue.target_ref != command.target_ref
        || queue.active_batch.is_some()
        || queue.entries.first().map(|entry| entry.pull_request) != Some(command.pull_request)
    {
        return Err(ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied).into());
    }
    let entry = queue.entries.first().ok_or(ProjectionFailure::Refuse(
        RefusalCode::ProtectedRefTransitionDenied,
    ))?;
    if entry.source_ref != command.source_ref
        || entry.head_tip != command.head_tip
        || data.source_ref != command.source_ref
        || data.target_ref != command.target_ref
        || data.source_tip != command.head_tip
        || data.target_tip != command.expected_target_tip
    {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
    }
    if snapshot.refs.get(&command.source_ref) != Some(&command.head_tip)
        || snapshot.refs.get(&command.target_ref) != Some(&command.expected_target_tip)
    {
        return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into());
    }
    selection
        .validate_shape(events)
        .map_err(ProjectionFailure::Refuse)?;
    for event in [&events.events[0], &events.events[2]] {
        queue
            .apply_event(event)
            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied))?;
    }
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)?;
    let (expected_events, expected_attempt) = selection.proposal(context)?;
    if expected_events != *events
        || expected_attempt != *attempt
        || selection.intent()? != *intent
        || context.repository_id != basis.body().repository_id
    {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
    }
    Ok(ValidatedQueueLanding {
        context: context.clone(),
        basis: basis.clone(),
        intent: intent.clone(),
        attempt: attempt.clone(),
        event_root: storage::root(events)?,
    })
}

/// Independently reconstruct the sealed command at the shared fold boundary.
/// The async driver additionally proves queue replay, current PR state, native
/// object ancestry and selected protections at the same authenticated basis.
pub(in crate::merge) fn prepare_landing(
    context: &AdmissionContext,
    command: &QueueLandingCommand,
    events: &ForgeEventBatch,
    closure: &ValidatedClosure,
    tx_id: TxId,
    attempt: &SealAttempt,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
) -> Result<PreparedNativeMerge, RefusalCode> {
    let (expected_events, expected_attempt) =
        landing_proposal(context, command).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected_events != *events || expected_attempt != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if basis.body().policy_epoch != command.expected_policy_epoch {
        return Err(RefusalCode::EvidenceStale);
    }
    if resolved.refs.refs().get(&command.source_ref) != Some(&command.head_tip)
        || resolved.refs.refs().get(&command.target_ref) != Some(&command.expected_target_tip)
    {
        return Err(RefusalCode::TargetRefMoved);
    }
    if !closure.objects.contains(&command.head_tip)
        || !closure.objects.contains(&command.expected_target_tip)
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
        target: command.target_ref.clone(),
    };
    prepare_coupled_events(
        context,
        CoupledForgeEvents {
            events: events.clone(),
            kinds: vec![
                queue_change.clone(),
                ForgeEventKind::PullRequestMerged {
                    pull_request,
                    target: command.target_ref.clone(),
                },
                queue_change,
            ],
            refs: BTreeMap::from([(command.target_ref.clone(), RefEffect::Set(command.head_tip))]),
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
