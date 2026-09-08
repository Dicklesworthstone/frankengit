//! Pure preparation of a native merge from one already authenticated basis.
//!
//! Drivers supply the original seal instead of re-encoding it for their
//! transport. Object validation and immutable storage remain driver-owned;
//! ref/forge/outbox folding and the final record's evidence have one owner here.

use std::collections::BTreeMap;

use fgit_authority::SealAttempt;
use fgit_chronicle::PublicationBasis;
use fgit_codec::{
    CanonicalOutboxEffectState, OutboxDeliveryIdentityInput, derive_outbox_delivery_key,
};
use fgit_forge::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_reference::effect::FoldOutcome;
use fgit_reference::intent::{
    ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId, ForgeStreamPosition, Intent,
    OutboxDeliveryKey, OutboxIntent, TransactionRequest,
};
use fgit_reference::merge_delivery::{
    MergeDeliveryInput, MergeDeliveryTransition, apply_merge_delivery_transition,
};
use fgit_txn::{IntentEvaluator, TransactionFoldReport};
use fgit_types::{AsciiSlug, RefName, RefusalCode, TxId};

use super::delivery::DeliveryState;
use super::storage::{aggregate_label, root};
use super::{incoherent, unavailable};
use crate::evidence::{DecisionEvidenceBodies, principal_snapshot_id};
use crate::{
    AdmissionContext, AdmissionError, AdmissionSnapshot, CommitMaterialization, LoweredRequest,
    ProjectionFailure, PublicationPreparation, ValidatedClosure,
};

/// The reference partition and the complete coupled transition at one basis.
/// It contains no publication authority and performs no immutable-store write.
#[derive(Debug)]
pub struct PreparedNativeMerge {
    /// Request consumed by the existing ref/closure materializer.
    pub ref_request: TransactionRequest,
    /// Ref-only fold consumed by that materializer.
    pub ref_fold: TransactionFoldReport,
    /// Exact native event bytes to stage.
    pub events: ForgeEventBatch,
    /// Canonical forge/outbox successor maps and their roots.
    pub transition: MergeDeliveryTransition,
    /// Initial delivery obligation included in the successor outbox.
    pub effect: CanonicalOutboxEffectState,
    /// Concrete evidence for the complete coupled fold.
    pub evidence: DecisionEvidenceBodies,
    /// Symbolic HEAD selected by the authenticated predecessor.
    pub head_target: Option<RefName>,
}

impl PreparedNativeMerge {
    /// Check the independently materialized reference partition against the
    /// complete merge's principal, policy, and retention evidence.
    pub fn validate_ref_evidence(
        &self,
        materialization: &CommitMaterialization,
    ) -> Result<(), PreparationFailure> {
        if materialization.record.principal_snapshot_id
            != principal_snapshot_id(self.evidence.principal_snapshot())
                .map_err(ProjectionFailure::Unavailable)?
            || materialization.record.policy_decision_root != root(self.evidence.policy_decision())?
            || materialization.record.retention_delta_root != root(self.evidence.retention_delta())?
        {
            return Err(incoherent("native and ref partition evidence bindings").into());
        }
        Ok(())
    }

    /// Replace the ref partition's subset witnesses with the complete merge's
    /// event, invariant and outbox witnesses. The caller must stage every body
    /// before giving this materialization to the shared publication machinery.
    pub fn finish_materialization(
        &self,
        mut materialization: CommitMaterialization,
    ) -> Result<CommitMaterialization, AdmissionError> {
        materialization.record.forge_event_batch_root = root(&self.events)?;
        materialization.record.resulting_forge_position_root =
            self.transition.forge_position_root();
        materialization.record.invariant_evidence_root = root(self.evidence.invariant_evidence())?;
        materialization.record.outbox_effect_root = root(self.evidence.outbox_effect_batch())?;
        materialization.roots.forge_position_root = self.transition.forge_position_root();
        materialization.roots.outbox_root = self.transition.outbox_root();
        Ok(materialization)
    }
}

/// Fold one native event and its ref command through the existing evaluator.
///
/// The caller has authenticated `basis`/`snapshot`/`delivery_basis`, checked
/// source and target freshness and the current aggregate's terminal state, and
/// validated native object bytes into `closure`. `attempt` is the ORIGINAL
/// sealed semantic request; this function never substitutes a new seal schema.
pub fn prepare_native_merge(
    context: &AdmissionContext,
    basis: &PublicationBasis,
    tx_id: TxId,
    attempt: &SealAttempt,
    event: &ForgeEvent,
    snapshot: AdmissionSnapshot,
    closure: &ValidatedClosure,
    delivery_basis: &DeliveryState,
) -> Result<PreparedNativeMerge, PreparationFailure> {
    let merge = match &event.payload {
        ForgeEventPayload::MergeCommittedNative(merge) => merge,
        _ => return Err(incoherent("native event kind").into()),
    };
    let recomputed = crate::permitted_object_closure_root(&crate::PermittedObjectClosure::new(
        closure.objects.clone(),
    ))
    .map_err(ProjectionFailure::Unavailable)?;
    if recomputed != closure.object_closure_root || !closure.objects.contains(&merge.merge_commit) {
        return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid).into());
    }
    let lowered = LoweredRequest {
        semantic: attempt.request.clone(),
        idempotency_key: context.idempotency_key.clone(),
    };
    let positions = &delivery_basis.forge;
    let mut complete_snapshot = snapshot.clone();
    complete_snapshot.forge_positions = positions
        .entries()
        .iter()
        .map(|entry| {
            (
                ForgeStreamId::new(entry.stream()),
                ForgeStreamPosition::new(entry.successor_position()),
            )
        })
        .collect();
    complete_snapshot.outbox = delivery_basis.outbox_bindings();
    let ref_partition = match crate::prepare_publication_from_snapshot(
        context, &lowered, closure, tx_id, snapshot,
    )? {
        PublicationPreparation::Commit(prepared) => prepared,
        PublicationPreparation::Refuse(code) => return Err(ProjectionFailure::Refuse(code).into()),
    };
    let mut complete_request = ref_partition.request.clone();
    let label = aggregate_label(event.aggregate)?;
    let stream = ForgeStreamId::new(label);
    let events = ForgeEventBatch::of_one(event.clone());
    let event_root = root(&events)?;
    let effect_class = AsciiSlug::from_static("forge-event");
    let destination = AsciiSlug::from_static("forge-projection");
    let delivery_key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        context.repository_id,
        effect_class,
        destination,
        event_root,
        tx_id,
        basis.body().latest_committed_rcr_id,
    ))
    .map_err(|_| unavailable(RefusalCode::CanonicalFramingInvalid))?;
    let effect = CanonicalOutboxEffectState::committed(
        context.repository_id,
        delivery_key,
        tx_id,
        event_root,
    );
    let transition = apply_merge_delivery_transition(
        positions,
        &delivery_basis.outbox,
        MergeDeliveryInput::new(
            context.repository_id,
            stream,
            ForgeStreamPosition::new(event.version.get() - 1),
            1,
            event_root,
            effect_class,
            destination,
            event_root,
            tx_id,
            basis.body().latest_committed_rcr_id,
            effect
                .root()
                .map_err(|_| unavailable(RefusalCode::CanonicalFramingInvalid))?,
        ),
    )
    .map_err(|_| ProjectionFailure::Refuse(RefusalCode::ConflictingSemanticEffects))?;
    let event_kind = ForgeEventKind::PullRequestMerged {
        pull_request: ForgeEntityId::new(label),
        target: merge.target_ref.clone(),
    };
    let statement = complete_request
        .statements
        .first_mut()
        .ok_or_else(|| incoherent("missing ref statement"))?;
    statement.intents.push(Intent::Forge(ForgeIntent {
        stream,
        expected_position: ForgeStreamPosition::new(event.version.get() - 1),
        event: event_kind.clone(),
    }));
    statement.intents.push(Intent::Outbox(OutboxIntent {
        delivery_key: OutboxDeliveryKey::new(delivery_key),
        parameters: event_root,
    }));
    let complete_fold =
        IntentEvaluator::new().evaluate(complete_snapshot.as_fold_basis(), &complete_request);
    let complete_effects = match &complete_fold.outcome {
        FoldOutcome::Folded(effects) => effects,
        FoldOutcome::Aborted { code, .. } => return Err(ProjectionFailure::Refuse(*code).into()),
    };
    let ref_effects = ref_partition
        .fold
        .effects()
        .ok_or_else(|| incoherent("ref fold"))?;
    if complete_effects.refs != ref_effects.refs
        || complete_effects.forge != BTreeMap::from([(stream, vec![event_kind])])
        || !complete_effects.retention.is_empty()
        || complete_effects.outbox
            != BTreeMap::from([(OutboxDeliveryKey::new(delivery_key), event_root)])
    {
        return Err(incoherent("coupled merge normal form").into());
    }
    let evidence =
        DecisionEvidenceBodies::derive(context, basis, &complete_request, &complete_fold)
            .map_err(ProjectionFailure::Unavailable)?;
    Ok(PreparedNativeMerge {
        ref_request: ref_partition.request,
        ref_fold: ref_partition.fold,
        events,
        transition,
        effect,
        evidence,
        head_target: complete_snapshot.head_target,
    })
}

/// Preserve terminal refusals separately from unavailable evidence and storage
/// faults. Drivers may only publish the former as a terminal policy decision.
#[derive(Debug)]
pub enum PreparationFailure {
    /// Evaluated refusal or unavailable projection dependency.
    Projection(ProjectionFailure),
    /// An admission/storage fault whose original details are retained.
    Admission(Box<AdmissionError>),
}

impl From<ProjectionFailure> for PreparationFailure {
    fn from(value: ProjectionFailure) -> Self {
        Self::Projection(value)
    }
}

impl From<AdmissionError> for PreparationFailure {
    fn from(value: AdmissionError) -> Self {
        Self::Admission(Box::new(value))
    }
}
