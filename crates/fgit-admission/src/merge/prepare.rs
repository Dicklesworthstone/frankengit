//! Pure, coupled native merge preparation. Both public admission surfaces use
//! this same Ref + Forge + Outbox fold; there is no ref-only intermediate RCR.

use std::collections::{BTreeMap, BTreeSet};

use fgit_authority::SealAttempt;
use fgit_chronicle::{PublicationBasis, ResultingRoots};
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxEffectState, CanonicalOutboxState,
    OutboxDeliveryIdentityInput, RepositoryCommitRecord, derive_outbox_delivery_key,
};
use fgit_forge::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_reference::effect::{FoldBasis, FoldOutcome};
use fgit_reference::intent::{
    ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId, ForgeStreamPosition, Intent,
    OutboxDeliveryKey, OutboxIntent, TransactionRequest,
};
use fgit_reference::merge_delivery::{MergeDeliveryInput, apply_merge_delivery_transition};
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

/// All immutable bodies produced by one evaluated merge. Nothing here is
/// authoritative until its record and roots win the repository-head CAS.
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
    if super::seal_attempt_for(context, sealed).map_err(|_| RefusalCode::EvidenceInvalid)? != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if sealed.workspace_epoch_now != sealed.attempt.workspace_epoch {
        return Err(RefusalCode::EvidenceStale);
    }
    prepare_event(context, &sealed.package.event, sealed.closure, tx_id, attempt, basis, resolved)
}

/// Shared implementation for the sealed-package and reviewed-native APIs.
/// Only their seal construction differs. Both feed the exact same evaluator,
/// deterministic delivery identity, evidence derivation, and record builder.
pub(crate) fn prepare_event(
    context: &AdmissionContext,
    event: &ForgeEvent,
    closure: &ValidatedClosure,
    tx_id: TxId,
    attempt: &SealAttempt,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
) -> Result<PreparedNativeMerge, RefusalCode> {
    let ForgeEventPayload::MergeCommittedNative(merge) = &event.payload else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    merge.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
    if !matches!(event.aggregate, fgit_forge::AggregateId::PullRequest(_))
        || merge.merge_commit.algorithm() != context.object_format
        || attempt.tenant_id != context.tenant_id
        || attempt.repository_id != context.repository_id
        || attempt.authenticated_principal_id != context.principal_id
        || attempt.idempotency_key != context.idempotency_key
        || attempt.derive().map_err(|_| RefusalCode::EvidenceInvalid)?.0 != tx_id
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
    if resolved.refs.refs().get(&merge.source_ref) != Some(&merge.source_tip)
        || resolved.refs.refs().get(&merge.target_ref) != Some(&merge.target_tip_before)
    {
        return Err(RefusalCode::TargetRefMoved);
    }
    let objects = PermittedObjectClosure::new(closure.objects.clone());
    if crate::permitted_object_closure_root(&objects)? != closure.object_closure_root
        || closure.objects.iter().any(|oid| oid.is_zero() || oid.algorithm() != context.object_format)
        || [merge.source_tip, merge.base_tip, merge.target_tip_before, merge.merge_commit]
            .iter().any(|oid| !closure.objects.contains(oid))
    {
        return Err(RefusalCode::ObjectClosureIncomplete);
    }
    let label = AsciiSlug::try_new("forge_stream", event.aggregate.to_string().as_bytes())
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let stream = ForgeStreamId::new(label);
    let predecessor = event.version.get() - 1;
    if resolved.forge.entry(label).map_or(0, |entry| entry.successor_position()) != predecessor {
        return Err(RefusalCode::EvidenceStale);
    }
    let position = ForgeStreamPosition::new(predecessor);
    let event = ForgeEventBatch::of_one(event.clone());
    let event_root = evidence_root(&event)?;
    let effect_class = AsciiSlug::from_static("forge-event");
    let destination = AsciiSlug::from_static("forge-projection");
    let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        context.repository_id, effect_class, destination, event_root, tx_id,
        basis.body().latest_committed_rcr_id,
    )).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
    let effect = CanonicalOutboxEffectState::committed(context.repository_id, key, tx_id, event_root);
    let transition = apply_merge_delivery_transition(&resolved.forge, &resolved.outbox,
        MergeDeliveryInput::new(context.repository_id, stream, position, 1, event_root,
            effect_class, destination, event_root, tx_id, basis.body().latest_committed_rcr_id,
            effect.root().map_err(|_| RefusalCode::CanonicalFramingInvalid)?))
        .map_err(|_| RefusalCode::ConflictingSemanticEffects)?;
    let mut request = crate::model_request(context, &attempt.request, tx_id, closure)
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let statement = request.statements.first_mut().ok_or(RefusalCode::EvidenceInvalid)?;
    statement.intents.extend([
        Intent::Forge(ForgeIntent {
            stream, expected_position: position,
            event: ForgeEventKind::PullRequestMerged {
                pull_request: ForgeEntityId::new(label), target: merge.target_ref.clone(),
            },
        }),
        Intent::Outbox(OutboxIntent { delivery_key: OutboxDeliveryKey::new(key), parameters: event_root }),
    ]);
    let forge_positions = resolved.forge.entries().iter().map(|entry|
        (ForgeStreamId::new(entry.stream()), ForgeStreamPosition::new(entry.successor_position())))
        .collect::<BTreeMap<_, _>>();
    let outbox = resolved.outbox.entries().iter().map(|entry|
        (OutboxDeliveryKey::new(entry.delivery_key()), entry.payload_root()))
        .collect::<BTreeMap<_, _>>();
    let retention = BTreeSet::new();
    let evaluator = fgit_txn::IntentEvaluator::new();
    let fold = evaluator.evaluate(FoldBasis {
        refs: resolved.refs.refs(), forge_positions: &forge_positions,
        retention: &retention, outbox: &outbox,
    }, &request);
    evaluator.validate_report(&request, &fold)?;
    let effects = match &fold.outcome {
        FoldOutcome::Folded(effects) => effects,
        FoldOutcome::Aborted { code, .. } => return Err(*code),
    };
    // Exactly one source movement, one forge event and one delivery are owned
    // by this profile. In particular no unrelated sealed ref command may leak
    // through the otherwise general model-request lowering helper.
    if effects.refs.len() != 1
        || effects.refs.get(&merge.target_ref) != Some(&fgit_reference::effect::RefEffect::Set(merge.merge_commit))
        || effects.forge.len() != 1 || effects.outbox.len() != 1 || !effects.retention.is_empty()
    {
        return Err(RefusalCode::ConflictingSemanticEffects);
    }
    let refs = resolved.refs.apply(&effects.refs)?;
    let evidence = DecisionEvidenceBodies::derive(context, basis, &request, &fold)?;
    let roots = ResultingRoots {
        ref_root: crate::ref_state_root(resolved.root_layout, &refs)?,
        forge_position_root: transition.forge_position_root(),
        outbox_root: transition.outbox_root(), retention_root: basis.body().retention_root,
        policy_epoch: basis.body().policy_epoch, compaction_generation_link: None,
    };
    let record = RepositoryCommitRecord {
        repository_id: context.repository_id,
        repository_sequence: fgit_types::RepositorySequence::FIRST, parent_rcr_id: None, tx_id,
        principal_snapshot_id: principal_snapshot_id(evidence.principal_snapshot())?,
        canonical_request_digest: request.canonical_request_digest,
        ref_delta_root: crate::canonical_ref_delta_root(&crate::CanonicalRefDelta::from_effects(&effects.refs))?,
        resulting_ref_root: roots.ref_root, object_closure_root: closure.object_closure_root,
        forge_event_batch_root: event_root,
        resulting_forge_position_root: roots.forge_position_root, policy_epoch: roots.policy_epoch,
        policy_decision_root: evidence_root(evidence.policy_decision())?,
        invariant_evidence_root: evidence_root(evidence.invariant_evidence())?,
        outbox_effect_root: evidence_root(evidence.outbox_effect_batch())?,
        retention_delta_root: evidence_root(evidence.retention_delta())?,
    };
    Ok(PreparedNativeMerge {
        refs, root_layout: resolved.root_layout, closure: objects, event,
        forge: transition.forge_positions().clone(), outbox: transition.outbox().clone(),
        effect, request, fold, evidence, materialization: CommitMaterialization { record, roots },
    })
}
