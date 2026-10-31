//! Pure coupled forge preparation. Native merges, PR lifecycle commands and
//! reviewer decisions share the full fold, immutable evidence, delivery identity
//! and RCR builder. Only merges may move a ref; metadata/reviews never do.

use std::collections::{BTreeMap, BTreeSet};

use fgit_authority::SealAttempt;
use fgit_chronicle::{PublicationBasis, ResultingRoots};
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxEffectState, CanonicalOutboxState,
    OutboxDeliveryIdentityInput, RepositoryCommitRecord, derive_outbox_delivery_key,
};
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_forge::event::review::ReviewDecision;
use fgit_forge::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_reference::effect::{FoldBasis, FoldOutcome, RefEffect};
use fgit_reference::intent::{
    ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId, ForgeStreamPosition, Intent,
    OutboxDeliveryKey, OutboxIntent, TransactionRequest,
};
use fgit_reference::merge_delivery::{MergeDeliveryInput, apply_batch_delivery_transition};
use fgit_types::{AsciiSlug, RefusalCode, RootLayoutVersion, TxId};

use super::legacy::{SealedMerge, check_parts_describe_one_merge};
use crate::evidence::{DecisionEvidenceBodies, evidence_root, principal_snapshot_id};
use crate::{
    AdmissionContext, CanonicalRefState, CommitMaterialization, PermittedObjectClosure,
    ValidatedClosure,
};

/// Bodies resolved and verified at one authenticated authority basis.
#[derive(Clone, Debug)]
pub struct NativeMergeBasis {
    pub refs: CanonicalRefState,
    pub root_layout: RootLayoutVersion,
    pub forge: CanonicalForgePositionState,
    pub outbox: CanonicalOutboxState,
}

/// All immutable bodies produced by one evaluated forge transaction. Nothing
/// here is authoritative until its record and roots win the repository-head CAS.
/// The established type name is retained for existing merge callers.
#[derive(Clone, Debug)]
pub struct PreparedNativeMerge {
    pub refs: CanonicalRefState,
    pub root_layout: RootLayoutVersion,
    pub closure: PermittedObjectClosure,
    pub event: ForgeEventBatch,
    pub forge: CanonicalForgePositionState,
    pub outbox: CanonicalOutboxState,
    pub effect: CanonicalOutboxEffectState,
    pub request: TransactionRequest,
    pub fold: fgit_txn::TransactionFoldReport,
    pub evidence: DecisionEvidenceBodies,
    pub materialization: CommitMaterialization,
}

/// Prepare the existing sealed-package API without accepting caller-minted
/// policy evidence. The original seal, including workspace epoch, is retained.
/// The storage owner must have authenticated all predecessor bodies.
pub fn prepare_native_merge(
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    tx_id: TxId,
    attempt: &SealAttempt,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
) -> Result<PreparedNativeMerge, RefusalCode> {
    check_parts_describe_one_merge(sealed).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if super::seal_attempt_for(context, sealed).map_err(|_| RefusalCode::EvidenceInvalid)?
        != *attempt
    {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if sealed.workspace_epoch_now != sealed.attempt.workspace_epoch {
        return Err(RefusalCode::EvidenceStale);
    }
    prepare_event(
        context,
        &sealed.package.event,
        sealed.closure,
        tx_id,
        attempt,
        basis,
        resolved,
    )
}

/// Shared evaluator and evidence builder. Drivers authenticate the predecessor,
/// enforce the aggregate lifecycle and validate native object bytes first.
/// This function independently verifies roots, scope and the complete normal form.
pub fn prepare_event(
    context: &AdmissionContext,
    event: &ForgeEvent,
    closure: &ValidatedClosure,
    tx_id: TxId,
    attempt: &SealAttempt,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
) -> Result<PreparedNativeMerge, RefusalCode> {
    let aggregate_matches = match &event.payload {
        ForgeEventPayload::PullRequestReviewedNative(review) => {
            event.aggregate == review.aggregate()
        }
        ForgeEventPayload::IssueChangedNative(_) => {
            matches!(event.aggregate, fgit_forge::AggregateId::Issue(_))
        }
        ForgeEventPayload::ReviewProtectionChanged(_) => {
            event.aggregate == fgit_forge::AggregateId::ReviewProtection
        }
        ForgeEventPayload::WorkflowCheckObservedNative(change) => {
            event.aggregate == fgit_forge::AggregateId::WorkflowCheck(change.id())
                && event.version == fgit_forge::AggregateVersion::FIRST
        }
        ForgeEventPayload::PullRequestCommentedNative(_) => {
            matches!(
                event.aggregate,
                fgit_forge::AggregateId::PullRequestConversation(_)
            )
        }
        ForgeEventPayload::MergeQueueChangedNative(change) => {
            event.aggregate == fgit_forge::AggregateId::MergeQueue(change.queue_number)
        }
        _ => matches!(event.aggregate, fgit_forge::AggregateId::PullRequest(_)),
    };
    if !aggregate_matches
        || attempt.tenant_id != context.tenant_id
        || attempt.repository_id != context.repository_id
        || attempt.authenticated_principal_id != context.principal_id
        || attempt.idempotency_key != context.idempotency_key
        || attempt
            .derive()
            .map_err(|_| RefusalCode::EvidenceInvalid)?
            .0
            != tx_id
        || !attempt.request.atomic()
    {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if context.repository_id != basis.body().repository_id
        || resolved.forge.repository_id() != context.repository_id
        || resolved.outbox.repository_id() != context.repository_id
        || crate::ref_state_root(resolved.root_layout, &resolved.refs)? != basis.body().ref_root
    {
        return Err(RefusalCode::AuthorityReceiptStale);
    }
    let label = AsciiSlug::try_new("forge_stream", event.aggregate.to_string().as_bytes())
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let entity = ForgeEntityId::new(label);
    let (kind, required_objects, ref_effect) = match &event.payload {
        ForgeEventPayload::MergeQueueChangedNative(change) => {
            if !attempt.request.ref_commands().is_empty() || !closure.objects.is_empty() {
                return Err(RefusalCode::EvidenceInvalid);
            }
            let command = super::native::queue::verify_event_seal(context, event, attempt)?;
            if let fgit_forge::merge_queue::QueueCommandAction::Enqueue {
                pull_request,
                expected_pull_request_version,
                source_ref,
                head_tip,
                expected_target_tip,
                ..
            } = &command.action
            {
                let pull = AsciiSlug::try_new(
                    "forge_stream",
                    fgit_forge::AggregateId::PullRequest(*pull_request)
                        .to_string()
                        .as_bytes(),
                )
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
                if resolved
                    .forge
                    .entry(pull)
                    .map(|entry| entry.successor_position())
                    != Some(expected_pull_request_version.get())
                {
                    return Err(RefusalCode::EvidenceStale);
                }
                if resolved.refs.refs().get(source_ref) != Some(head_tip)
                    || resolved.refs.refs().get(&command.target_ref) != Some(expected_target_tip)
                {
                    return Err(RefusalCode::TargetRefMoved);
                }
            }
            (
                ForgeEventKind::MergeQueueChanged {
                    queue: entity,
                    target: change.target_ref.clone(),
                },
                Vec::new(),
                None,
            )
        }
        ForgeEventPayload::PullRequestCommentedNative(comment) => {
            comment
                .validate()
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
            if comment.actor != context.principal_id
                || !attempt.request.ref_commands().is_empty()
                || (comment.anchor.is_none() && !closure.objects.is_empty())
            {
                return Err(RefusalCode::EvidenceInvalid);
            }
            verify_pull_request_comment_seal(context, event, attempt)?;
            (
                ForgeEventKind::PullRequestCommented {
                    conversation: entity,
                },
                comment.anchor.as_ref().map_or_else(Vec::new, |anchor| {
                    vec![
                        anchor.source_tip,
                        anchor.target_tip,
                        anchor.compared_base,
                        anchor.blob,
                    ]
                }),
                None,
            )
        }
        ForgeEventPayload::WorkflowCheckObservedNative(change) => {
            // Bind the actual event, actor and inline evidence to this exact
            // original seal, not merely to a well-formed request of any kind.
            let (expected, sealed) =
                super::native::workflow_checks::proposal(context, &change.record)
                    .map_err(|_| RefusalCode::EvidenceInvalid)?;
            if expected != *event || sealed != *attempt {
                return Err(RefusalCode::EvidenceInvalid);
            }
            if resolved.refs.refs().get(&change.record.source_ref)
                != Some(&change.record.source_commit)
            {
                return Err(RefusalCode::TargetRefMoved);
            }
            (
                ForgeEventKind::WorkflowCheckObserved {
                    check: entity,
                    source: change.record.source_ref.clone(),
                },
                vec![change.record.source_commit],
                None,
            )
        }
        ForgeEventPayload::ReviewProtectionChanged(change) => {
            change
                .validate()
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
            if change.actor != context.principal_id
                || !attempt.request.ref_commands().is_empty()
                || !closure.objects.is_empty()
            {
                return Err(RefusalCode::EvidenceInvalid);
            }
            if change.expected_epoch != basis.body().policy_epoch {
                return Err(RefusalCode::EvidenceStale);
            }
            (
                ForgeEventKind::ReviewProtectionChanged { policy: entity },
                Vec::new(),
                None,
            )
        }
        ForgeEventPayload::IssueChangedNative(change) => {
            change
                .action
                .validate()
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
            if change.actor != context.principal_id
                || !attempt.request.ref_commands().is_empty()
                || !closure.objects.is_empty()
            {
                return Err(RefusalCode::EvidenceInvalid);
            }
            verify_issue_seal(context, event, attempt)?;
            (
                ForgeEventKind::IssueChanged { issue: entity },
                Vec::new(),
                None,
            )
        }
        ForgeEventPayload::MergeCommittedNative(merge) => {
            merge.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
            if merge.merge_commit.algorithm() != context.object_format {
                return Err(RefusalCode::EvidenceInvalid);
            }
            if resolved.refs.refs().get(&merge.source_ref) != Some(&merge.source_tip)
                || resolved.refs.refs().get(&merge.target_ref) != Some(&merge.target_tip_before)
            {
                return Err(RefusalCode::TargetRefMoved);
            }
            (
                ForgeEventKind::PullRequestMerged {
                    pull_request: entity,
                    target: merge.target_ref.clone(),
                },
                vec![
                    merge.source_tip,
                    merge.base_tip,
                    merge.target_tip_before,
                    merge.merge_commit,
                ],
                Some((merge.target_ref.clone(), RefEffect::Set(merge.merge_commit))),
            )
        }
        ForgeEventPayload::PullRequestChangedNative(change) => {
            change
                .data
                .validate()
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
            if change.actor != context.principal_id
                || change.data.source_tip.algorithm() != context.object_format
                || !attempt.request.ref_commands().is_empty()
            {
                return Err(RefusalCode::EvidenceInvalid);
            }
            // Closing preserves already recorded coordinates even after a
            // branch is deleted. Opening/updating must name both current tips.
            if change.action != PullRequestAction::Close
                && (resolved.refs.refs().get(&change.data.source_ref)
                    != Some(&change.data.source_tip)
                    || resolved.refs.refs().get(&change.data.target_ref)
                        != Some(&change.data.target_tip))
            {
                return Err(RefusalCode::TargetRefMoved);
            }
            let kind = match change.action {
                PullRequestAction::Open => ForgeEventKind::PullRequestOpened {
                    pull_request: entity,
                    target: change.data.target_ref.clone(),
                },
                // A reopen changes lifecycle state on the SAME branches without
                // moving a ref; the sealed batch carries the exact action, and
                // `validate_transition` admits it only from a closed stream.
                PullRequestAction::Update | PullRequestAction::Reopen => {
                    ForgeEventKind::PullRequestUpdated {
                        pull_request: entity,
                        target: change.data.target_ref.clone(),
                    }
                }
                PullRequestAction::Close => ForgeEventKind::PullRequestClosed {
                    pull_request: entity,
                },
            };
            (
                kind,
                vec![change.data.source_tip, change.data.target_tip],
                None,
            )
        }
        ForgeEventPayload::PullRequestReviewedNative(review) => {
            review
                .validate()
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
            let subject = &review.subject;
            if review.reviewer != context.principal_id
                || subject.source_tip.algorithm() != context.object_format
                || !attempt.request.ref_commands().is_empty()
            {
                return Err(RefusalCode::EvidenceInvalid);
            }
            if review.decision != ReviewDecision::Withdraw {
                let pr = AsciiSlug::try_new(
                    "forge_stream",
                    fgit_forge::AggregateId::PullRequest(subject.pull_request)
                        .to_string()
                        .as_bytes(),
                )
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
                if subject.policy_epoch != basis.body().policy_epoch
                    || resolved
                        .forge
                        .entry(pr)
                        .map(|entry| entry.successor_position())
                        != Some(subject.pull_request_version.get())
                {
                    return Err(RefusalCode::EvidenceStale);
                }
                if resolved.refs.refs().get(&subject.source_ref) != Some(&subject.source_tip)
                    || resolved.refs.refs().get(&subject.target_ref) != Some(&subject.target_tip)
                {
                    return Err(RefusalCode::TargetRefMoved);
                }
            }
            // Withdrawals preserve the exact old subject even when stale;
            // the driver has verified the current review-stream predecessor.
            (
                ForgeEventKind::PullRequestReviewed {
                    review: entity,
                    target: subject.target_ref.clone(),
                },
                vec![subject.source_tip, subject.target_tip],
                None,
            )
        }
        _ => return Err(RefusalCode::EvidenceInvalid),
    };
    if required_objects
        .iter()
        .any(|oid| !closure.objects.contains(oid))
    {
        return Err(RefusalCode::ObjectClosureIncomplete);
    }
    prepare_coupled_events(
        context,
        CoupledForgeEvents {
            events: ForgeEventBatch::of_one(event.clone()),
            kinds: vec![kind],
            refs: ref_effect.into_iter().collect(),
        },
        closure,
        tx_id,
        attempt,
        basis,
        resolved,
    )
}

/// Domain validators supply an exact event batch and its reference meanings.
/// This internal composition is shared by singleton commands and immediate
/// queue-head landing; it is not an arbitrary public batch-submission API.
pub(in crate::merge) struct CoupledForgeEvents {
    pub events: ForgeEventBatch,
    pub kinds: Vec<ForgeEventKind>,
    pub refs: BTreeMap<fgit_types::RefName, RefEffect>,
}

pub(in crate::merge) fn prepare_coupled_events(
    context: &AdmissionContext,
    input: CoupledForgeEvents,
    closure: &ValidatedClosure,
    tx_id: TxId,
    attempt: &SealAttempt,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
) -> Result<PreparedNativeMerge, RefusalCode> {
    let CoupledForgeEvents {
        events: event,
        kinds,
        refs: expected_refs,
    } = input;
    if event.events.len() != 1 {
        super::native::queue::validate_publication_shape(&event)?;
    }
    if event.events.is_empty()
        || event.events.len() > 3
        || event.events.len() != kinds.len()
        || attempt.tenant_id != context.tenant_id
        || attempt.repository_id != context.repository_id
        || attempt.authenticated_principal_id != context.principal_id
        || attempt.idempotency_key != context.idempotency_key
        || attempt
            .derive()
            .map_err(|_| RefusalCode::EvidenceInvalid)?
            .0
            != tx_id
        || !attempt.request.atomic()
    {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if context.repository_id != basis.body().repository_id
        || resolved.forge.repository_id() != context.repository_id
        || resolved.outbox.repository_id() != context.repository_id
        || crate::ref_state_root(resolved.root_layout, &resolved.refs)? != basis.body().ref_root
    {
        return Err(RefusalCode::AuthorityReceiptStale);
    }
    let objects = PermittedObjectClosure::new(closure.objects.clone());
    if crate::permitted_object_closure_root(&objects)? != closure.object_closure_root
        || closure
            .objects
            .iter()
            .any(|oid| oid.is_zero() || oid.algorithm() != context.object_format)
    {
        return Err(RefusalCode::ObjectClosureIncomplete);
    }
    let mut forge_intents = Vec::with_capacity(kinds.len());
    let mut expected_forge = BTreeMap::<ForgeStreamId, Vec<ForgeEventKind>>::new();
    for (event, kind) in event.events.iter().zip(kinds) {
        let label = AsciiSlug::try_new("forge_stream", event.aggregate.to_string().as_bytes())
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        if kind.entity() != ForgeEntityId::new(label) {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let stream = ForgeStreamId::new(label);
        let held = expected_forge.entry(stream).or_default();
        let original = resolved
            .forge
            .entry(label)
            .map_or(0, |entry| entry.successor_position());
        let predecessor = original
            .checked_add(held.len() as u64)
            .ok_or(RefusalCode::ResourceBudgetExceeded)?;
        if predecessor.checked_add(1) != Some(event.version.get()) {
            return Err(RefusalCode::EvidenceStale);
        }
        forge_intents.push(Intent::Forge(ForgeIntent {
            stream,
            expected_position: ForgeStreamPosition::new(predecessor),
            event: kind.clone(),
        }));
        held.push(kind);
    }
    let event_root = evidence_root(&event)?;
    let effect_class = AsciiSlug::from_static("forge-event");
    let destination = AsciiSlug::from_static("forge-projection");
    let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        context.repository_id,
        effect_class,
        destination,
        event_root,
        tx_id,
        basis.body().latest_committed_rcr_id,
    ))
    .map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
    let effect =
        CanonicalOutboxEffectState::committed(context.repository_id, key, tx_id, event_root);
    let advances = expected_forge
        .iter()
        .map(|(stream, events)| {
            Ok(MergeDeliveryInput::new(
                context.repository_id,
                *stream,
                ForgeStreamPosition::new(
                    resolved
                        .forge
                        .entry(stream.label())
                        .map_or(0, |entry| entry.successor_position()),
                ),
                u32::try_from(events.len()).map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
                event_root,
                effect_class,
                destination,
                event_root,
                tx_id,
                basis.body().latest_committed_rcr_id,
                effect
                    .root()
                    .map_err(|_| RefusalCode::CanonicalFramingInvalid)?,
            ))
        })
        .collect::<Result<Vec<_>, RefusalCode>>()?;
    let transition = apply_batch_delivery_transition(&resolved.forge, &resolved.outbox, &advances)
        .map_err(|_| RefusalCode::ConflictingSemanticEffects)?;
    let mut request = crate::model_request(context, &attempt.request, tx_id, closure)
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let statement = request
        .statements
        .first_mut()
        .ok_or(RefusalCode::EvidenceInvalid)?;
    statement.intents.extend(forge_intents);
    statement.intents.push(Intent::Outbox(OutboxIntent {
        delivery_key: OutboxDeliveryKey::new(key),
        parameters: event_root,
    }));
    let forge_positions = resolved
        .forge
        .entries()
        .iter()
        .map(|entry| {
            (
                ForgeStreamId::new(entry.stream()),
                ForgeStreamPosition::new(entry.successor_position()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let outbox = resolved
        .outbox
        .entries()
        .iter()
        .map(|entry| {
            (
                OutboxDeliveryKey::new(entry.delivery_key()),
                entry.payload_root(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let retention = BTreeSet::new();
    let evaluator = fgit_txn::IntentEvaluator::new();
    let fold = evaluator.evaluate(
        FoldBasis {
            refs: resolved.refs.refs(),
            forge_positions: &forge_positions,
            retention: &retention,
            outbox: &outbox,
        },
        &request,
    );
    evaluator.validate_report(&request, &fold)?;
    let effects = match &fold.outcome {
        FoldOutcome::Folded(effects) => effects,
        FoldOutcome::Aborted { code, .. } => return Err(*code),
    };
    if effects.refs != expected_refs
        || effects.forge != expected_forge
        || effects.outbox != BTreeMap::from([(OutboxDeliveryKey::new(key), event_root)])
        || !effects.retention.is_empty()
    {
        return Err(RefusalCode::ConflictingSemanticEffects);
    }
    let refs = resolved.refs.apply(&effects.refs)?;
    let evidence = DecisionEvidenceBodies::derive(context, basis, &request, &fold)?;
    let roots = ResultingRoots {
        ref_root: crate::ref_state_root(resolved.root_layout, &refs)?,
        forge_position_root: transition.forge_position_root(),
        outbox_root: transition.outbox_root(),
        retention_root: basis.body().retention_root,
        policy_epoch: match &event.events[0].payload {
            ForgeEventPayload::ReviewProtectionChanged(change) => change.resulting_epoch()?,
            _ => basis.body().policy_epoch,
        },
        compaction_generation_link: None,
    };
    let record = RepositoryCommitRecord {
        repository_id: context.repository_id,
        repository_sequence: fgit_types::RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id,
        principal_snapshot_id: principal_snapshot_id(evidence.principal_snapshot())?,
        canonical_request_digest: request.canonical_request_digest,
        ref_delta_root: crate::canonical_ref_delta_root(&crate::CanonicalRefDelta::from_effects(
            &effects.refs,
        ))?,
        resulting_ref_root: roots.ref_root,
        object_closure_root: closure.object_closure_root,
        forge_event_batch_root: event_root,
        resulting_forge_position_root: roots.forge_position_root,
        policy_epoch: basis.body().policy_epoch,
        policy_decision_root: evidence.policy_decision().root()?,
        invariant_evidence_root: evidence_root(evidence.invariant_evidence())?,
        outbox_effect_root: evidence_root(evidence.outbox_effect_batch())?,
        retention_delta_root: evidence_root(evidence.retention_delta())?,
    };
    Ok(PreparedNativeMerge {
        refs,
        root_layout: resolved.root_layout,
        closure: objects,
        event,
        forge: transition.forge_positions().clone(),
        outbox: transition.outbox().clone(),
        effect,
        request,
        fold,
        evidence,
        materialization: CommitMaterialization { record, roots },
    })
}

/// An event position may differ from the original commitment only for the
/// explicit append-comment profile. Rebuild both supported requests exactly;
/// a Comment payload alone cannot authorize changing a strict predecessor.
fn verify_issue_seal(
    context: &AdmissionContext,
    event: &ForgeEvent,
    attempt: &SealAttempt,
) -> Result<(), RefusalCode> {
    use fgit_forge::event::issue::{IssueAction, IssueCommand, IssueCommentIntent};
    use fgit_forge::{AggregateId, AggregateVersion, ExpectedVersion};

    let (AggregateId::Issue(number), ForgeEventPayload::IssueChangedNative(change)) =
        (event.aggregate, &event.payload)
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
    let command = IssueCommand {
        number,
        expected_version,
        action: change.action.clone(),
    };
    let (expected, strict) = super::native::issues::proposal(context, &command)
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected != *event {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if strict == *attempt {
        return Ok(());
    }
    let IssueAction::Comment { body } = &change.action else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let (_, append) = super::native::issues::append_proposal(
        context,
        &IssueCommentIntent {
            number,
            body: body.clone(),
        },
    )
    .map_err(|_| RefusalCode::EvidenceInvalid)?;
    if append != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod issue_seal_tests;

/// Reconstruct the entire supported seal independently of the append planner.
/// Only an exact match to the explicit append profile may omit a predecessor;
/// the common preparation path still verifies the current conversation frontier.
fn verify_pull_request_comment_seal(
    context: &AdmissionContext,
    event: &ForgeEvent,
    attempt: &SealAttempt,
) -> Result<(), RefusalCode> {
    use fgit_forge::event::pull_request_comment::{
        PullRequestAppendCommentCommand, PullRequestCommentCommand,
    };
    use fgit_forge::{AggregateId, AggregateVersion, ExpectedVersion};

    let (
        AggregateId::PullRequestConversation(number),
        ForgeEventPayload::PullRequestCommentedNative(comment),
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
    let command = PullRequestCommentCommand {
        number,
        expected_version,
        body: comment.body.clone(),
        anchor: comment.anchor.clone(),
    };
    let (expected, strict) = super::native::pull_request::comments::proposal(context, &command)
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected != *event {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if strict == *attempt {
        return Ok(());
    }
    let (_, append) = super::native::pull_request::comments::append_proposal(
        context,
        &PullRequestAppendCommentCommand {
            number,
            body: comment.body.clone(),
            anchor: comment.anchor.clone(),
        },
    )
    .map_err(|_| RefusalCode::EvidenceInvalid)?;
    if append != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod pull_comment_seal_tests;
