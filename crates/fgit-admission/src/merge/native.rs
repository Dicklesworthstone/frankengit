//! Pure native merge preparation shared by blocking and awaited staging.

use std::collections::{BTreeMap, BTreeSet};

use fgit_authority::SealAttempt;
use fgit_chronicle::{PublicationBasis, ResultingRoots};
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxEffectState, CanonicalOutboxState,
    OutboxDeliveryIdentityInput, derive_outbox_delivery_key,
};
use fgit_reference::intent::{
    ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId, ForgeStreamPosition, Intent,
    OutboxDeliveryKey, OutboxIntent, TransactionRequest,
};
use fgit_reference::merge_delivery::{MergeDeliveryInput, apply_merge_delivery_transition};
use fgit_types::{AsciiSlug, RefName, RefusalCode, RootLayoutVersion, TxId};

use super::{SealedMerge, check_parts_describe_one_merge};
use crate::evidence::{DecisionEvidenceBodies, evidence_root, principal_snapshot_id};
use crate::{AdmissionContext, CanonicalRefState, CommitMaterialization, PermittedObjectClosure};

/// Bodies resolved and verified at one authenticated authority basis.
#[derive(Clone, Debug)]
pub struct NativeMergeBasis {
    /// Exact predecessor ref state, including symbolic HEAD.
    pub refs: CanonicalRefState,
    /// Ref layout from the authenticated repository configuration.
    pub root_layout: RootLayoutVersion,
    /// Canonical forge position state resolved by the storage owner.
    pub forge: CanonicalForgePositionState,
    /// Canonical outbox state resolved by the storage owner.
    pub outbox: CanonicalOutboxState,
}

/// Complete immutable native merge, ready to stage before the one head CAS.
#[derive(Clone, Debug)]
pub struct PreparedNativeMerge {
    /// Successor direct refs and symbolic HEAD.
    pub refs: CanonicalRefState,
    /// Configuration-selected ref layout.
    pub root_layout: RootLayoutVersion,
    /// Validated object closure committed by the RCR.
    pub closure: PermittedObjectClosure,
    /// The author's native event bytes.
    pub event: fgit_forge::ForgeEventBatch,
    /// Successor canonical forge state.
    pub forge: CanonicalForgePositionState,
    /// Successor canonical outbox state.
    pub outbox: CanonicalOutboxState,
    /// Initial delivery obligation; visible only with the successor outbox.
    pub effect: CanonicalOutboxEffectState,
    /// Source-ordered typed intents evaluated for this exact basis.
    pub request: TransactionRequest,
    /// Reference-evaluator result, including all intent dispositions.
    pub fold: fgit_txn::TransactionFoldReport,
    /// Concrete policy, principal, and invariant evidence to stage.
    pub evidence: DecisionEvidenceBodies,
    /// Record and all successor roots; publication assigns sequence and parent.
    pub materialization: CommitMaterialization,
}

/// Folds one native merge into ref, forge, and outbox successors without I/O.
///
/// The storage owner resolves `resolved` from `basis`, including the legacy
/// genesis empty-state sentinels. No caller-provided evidence root is accepted:
/// evidence is derived from the authenticated context and this exact fold.
///
/// # Errors
/// Refuses incoherent coordinates, stale refs or aggregate version, unbound
/// predecessor state, absent merge objects, exhausted maps, and fold failures.
pub fn prepare_native_merge(
    context: &AdmissionContext,
    sealed: &SealedMerge<'_>,
    tx_id: TxId,
    attempt: &SealAttempt,
    basis: &PublicationBasis,
    resolved: &NativeMergeBasis,
) -> Result<PreparedNativeMerge, RefusalCode> {
    check_parts_describe_one_merge(sealed).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if !matches!(sealed.package.event.payload, fgit_forge::ForgeEventPayload::MergeCommittedNative(_)) {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if context.repository_id != basis.body().repository_id
        || resolved.forge.repository_id() != context.repository_id
        || resolved.outbox.repository_id() != context.repository_id
        || crate::ref_state_root(resolved.root_layout, &resolved.refs)? != basis.body().ref_root
    {
        return Err(RefusalCode::AuthorityReceiptStale);
    }
    // Recreate the sealed request to prevent a caller pairing a valid package
    // with an unrelated request digest or transaction identity.
    let expected = super::seal_attempt_for(context, sealed).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    if attempt.derive().map_err(|_| RefusalCode::EvidenceInvalid)?.0 != tx_id {
        return Err(RefusalCode::EvidenceInvalid);
    }
    let source = RefName::try_new(&sealed.attempt.source_ref).map_err(|_| RefusalCode::EvidenceInvalid)?;
    let target = RefName::try_new(&sealed.attempt.target_ref).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if resolved.refs.refs().get(&source) != Some(&sealed.attempt.source_tip)
        || resolved.refs.refs().get(&target) != Some(&sealed.attempt.target_tip)
    {
        return Err(RefusalCode::TargetRefMoved);
    }
    if sealed.workspace_epoch_now != sealed.attempt.workspace_epoch {
        return Err(RefusalCode::EvidenceStale);
    }
    let label = AsciiSlug::try_new("forge_stream", sealed.package.event.aggregate.to_string().as_bytes())
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let stream = ForgeStreamId::new(label);
    let position = ForgeStreamPosition::new(sealed.package.event.version.get() - 1);
    let event = fgit_forge::ForgeEventBatch::of_one(sealed.package.event.clone());
    let event_root = sealed.package.roots(&fgit_codec::CryptoBodyIdentity)
        .map_err(|_| RefusalCode::CanonicalFramingInvalid)?.forge_event_batch_root;
    // This destination names the repository's canonical forge-event consumer.
    // Remote destinations are separate subscriptions and cannot alter this ID.
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
    let mut request = crate::model_request(context, &attempt.request, tx_id, sealed.closure)
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    request.statements[0].intents.extend([
        Intent::Forge(ForgeIntent { stream, expected_position: position,
            event: ForgeEventKind::PullRequestMerged { pull_request: ForgeEntityId::new(label), target } }),
        Intent::Outbox(OutboxIntent { delivery_key: OutboxDeliveryKey::new(key), parameters: event_root }),
    ]);
    let forge_positions = resolved.forge.entries().iter().map(|entry|
        (ForgeStreamId::new(entry.stream()), ForgeStreamPosition::new(entry.successor_position())))
        .collect::<BTreeMap<_, _>>();
    let outbox = resolved.outbox.entries().iter().map(|entry|
        (OutboxDeliveryKey::new(entry.delivery_key()), entry.payload_root()))
        .collect::<BTreeMap<_, _>>();
    let fold = fgit_txn::IntentEvaluator::new().evaluate(fgit_reference::effect::FoldBasis {
        refs: resolved.refs.refs(), forge_positions: &forge_positions,
        retention: &BTreeSet::new(), outbox: &outbox,
    }, &request);
    fgit_txn::IntentEvaluator::new().validate_report(&request, &fold)?;
    let effects = fold.effects().ok_or(RefusalCode::ConflictingSemanticEffects)?;
    let refs = resolved.refs.apply(&effects.refs)?;
    let ref_root = crate::ref_state_root(resolved.root_layout, &refs)?;
    let evidence = DecisionEvidenceBodies::derive(context, basis, &request, &fold)?;
    let roots = ResultingRoots {
        ref_root, forge_position_root: transition.forge_position_root(),
        outbox_root: transition.outbox_root(), retention_root: basis.body().retention_root,
        policy_epoch: basis.body().policy_epoch, compaction_generation_link: None,
    };
    let frame = fgit_forge::merge::RecordFrame {
        repository_id: context.repository_id,
        repository_sequence: fgit_types::RepositorySequence::FIRST, parent_rcr_id: None, tx_id,
        principal_snapshot_id: principal_snapshot_id(evidence.principal_snapshot())?,
        canonical_request_digest: request.canonical_request_digest,
        ref_delta_root: crate::canonical_ref_delta_root(&crate::CanonicalRefDelta::from_effects(&effects.refs))?,
        resulting_ref_root: roots.ref_root, object_closure_root: sealed.closure.object_closure_root,
        resulting_forge_position_root: roots.forge_position_root, policy_epoch: roots.policy_epoch,
        policy_decision_root: evidence_root(evidence.policy_decision())?,
        invariant_evidence_root: evidence_root(evidence.invariant_evidence())?,
        outbox_effect_root: evidence_root(evidence.outbox_effect_batch())?,
        retention_delta_root: evidence_root(evidence.retention_delta())?,
    };
    let record = sealed.package.seal_into_record(&fgit_codec::CryptoBodyIdentity, frame)
        .map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
    Ok(PreparedNativeMerge {
        refs, root_layout: resolved.root_layout,
        closure: PermittedObjectClosure::new(sealed.closure.objects.clone()), event,
        forge: transition.forge_positions().clone(), outbox: transition.outbox().clone(),
        effect, request, fold, evidence, materialization: CommitMaterialization { record, roots },
    })
}
