#![forbid(unsafe_code)]
//! Public-path tests for complete task-state persistence reconciliation.

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityBoundTaskClaimApplication, AuthorityBoundTaskProjectionSnapshot,
    AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun, LogicalTime, OperationClass,
    PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose,
    PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet, PlanSurface,
    PlanSurfaceKind, RejectedShortcutSet, RunId, SituationComponent,
    SituationComponentKind, SituationOmissionReason, TaskProjectionAssignment,
    TaskProjectionMutationEnvelope, TaskProjectionPersistedState,
    TaskProjectionPersistenceDecision, TaskProjectionPersistenceRefusal, TaskPhase,
    WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs,
    WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{IdentityDomain, NativeObjectIdentity};
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

const TASK_BASIS: [u8; 32] = [0x44; 32];

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed-width RCR digest"),
    )
}

fn authority_receipt() -> AuthorityReadReceipt {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    let body = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x27; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr_id()),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: digest(0x31),
        outcome_index_root: digest(0x32),
        retention_root: digest(0x33),
        outbox_root: digest(0x34),
        configuration_root: digest(0x35),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(911));
    let key = HeadKey::new(b"complete-task-persistence-test".to_vec()).expect("bounded head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt");
    AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x71; 32],
    )
    .expect("authenticated agent receipt")
}

fn run(receipt: &AuthorityReadReceipt) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ]),
        ResourceVector::from_grades(&[
            (Grade::Bytes, 16_384),
            (Grade::CpuMicros, 20_000),
        ]),
        LogicalTime::new(100),
    )
    .expect("authenticated run opens")
}

fn situation(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    generation: [u8; 32],
) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), generation)
        } else {
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [u8::try_from(index + 1).expect("component index fits u8"); 32],
            )
        }
    });
    AgentSituationReceipt::build(
        receipt.clone(),
        Some(run),
        None,
        LogicalTime::new(20),
        components,
    )
    .expect("complete situation")
}

fn pulse_and_plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
) -> (AgentControlPulse, AgentChangePlan) {
    let current = situation(receipt, run, *snapshot.generation());
    let item = WorkItem::new(
        snapshot.task_id(),
        *snapshot.generation(),
        snapshot.phase(),
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
    );
    let frontier = WorkFrontier::build_action_scoped(&current, vec![item])
        .expect("task is eligible");
    let pulse = AgentControlPulse::build(&current, &frontier, Some(run))
        .expect("live run makes an actionable pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let spec = AgentChangePlanSpec::new(
        digest(0x60),
        run.allowed_operation_classes(),
        ResourceVector::from_grades(&[
            (Grade::Bytes, 4_096),
            (Grade::CpuMicros, 5_000),
        ]),
        PlanStopConditionSet::MANDATORY,
        RejectedShortcutSet::BASELINE,
        PlanApproval::NotRequired {
            policy_root: digest(0x62),
        },
    )
    .with_surfaces(vec![surface], vec![surface])
    .with_checkpoints(vec![PlanCheckpoint::new(
        PlanCheckpointId::from_bytes([0x63; 32]),
        PlanCheckpointPurpose::ImplementSlice,
        digest(0x64),
        digest(0x65),
    )])
    .with_evidence_plan(vec![PlanEvidenceRequirement::new(
        PlanRequirementId::from_bytes([0x66; 32]),
        EvidenceClass::Executed,
        digest(0x67),
        false,
    )]);
    let plan = AgentChangePlan::build(&pulse, run, &[], spec).expect("complete plan");
    (pulse, plan)
}

fn claim_application(adapter: u8, evidence: u8) -> AuthorityBoundTaskClaimApplication {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let snapshot = AuthorityBoundTaskProjectionSnapshot::observed(
        &receipt,
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("valid authority-bound task state");
    let (pulse, plan) = pulse_and_plan(&receipt, &run, &snapshot);
    snapshot
        .claim(
            &pulse,
            &plan,
            &run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [adapter; 32],
            digest(evidence),
        )
        .expect("repository-scoped claim")
}

fn reread(
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
    observed_at: u64,
) -> AuthorityBoundTaskProjectionSnapshot {
    match snapshot.lease() {
        Some(lease) => AuthorityBoundTaskProjectionSnapshot::observed_with_lease(
            snapshot.authority_read_receipt(),
            snapshot.task_id(),
            *snapshot.generation(),
            snapshot.phase(),
            lease.clone(),
            LogicalTime::new(observed_at),
        )
        .expect("valid persisted lease reread"),
        None => AuthorityBoundTaskProjectionSnapshot::observed(
            snapshot.authority_read_receipt(),
            snapshot.task_id(),
            *snapshot.generation(),
            snapshot.phase(),
            snapshot.assignment(),
            LogicalTime::new(observed_at),
        )
        .expect("valid persisted task reread"),
    }
}

fn predecessor_state(envelope: &TaskProjectionMutationEnvelope) -> TaskProjectionPersistedState {
    TaskProjectionPersistedState::new(
        reread(envelope.before_snapshot(), 26),
        None,
        None,
        None,
    )
}

fn successor_state(envelope: &TaskProjectionMutationEnvelope) -> TaskProjectionPersistedState {
    TaskProjectionPersistedState::new(
        reread(envelope.after_snapshot(), 26),
        Some(*envelope.transition_id().as_bytes()),
        Some(envelope.inner_transition_id()),
        Some(envelope.evidence_root()),
    )
}

#[test]
fn complete_predecessor_is_safe_to_retry() {
    let application = claim_application(0x81, 0x82);
    let envelope = TaskProjectionMutationEnvelope::from_claim(&application)
        .expect("complete mutation envelope");
    let observed = predecessor_state(&envelope);

    assert_eq!(
        envelope
            .reconcile(Some(&observed))
            .expect("unchanged predecessor is a typed decision"),
        TaskProjectionPersistenceDecision::RetrySafe {
            envelope_id: envelope.envelope_id(),
            current_snapshot_id: envelope.before_snapshot_id(),
            current_generation: envelope.previous_generation(),
        }
    );
}

#[test]
fn predecessor_may_reuse_the_evidence_contract_without_becoming_partial_write() {
    let application = claim_application(0x81, 0x82);
    let envelope = TaskProjectionMutationEnvelope::from_claim(&application)
        .expect("complete mutation envelope");
    let observed = TaskProjectionPersistedState::new(
        reread(envelope.before_snapshot(), 26),
        None,
        None,
        Some(envelope.evidence_root()),
    );

    assert!(matches!(
        envelope
            .reconcile(Some(&observed))
            .expect("evidence contract reuse alone does not identify this transition"),
        TaskProjectionPersistenceDecision::RetrySafe { .. }
    ));
}

#[test]
fn complete_successor_and_metadata_make_a_receipt() {
    let application = claim_application(0x81, 0x82);
    let envelope = TaskProjectionMutationEnvelope::from_claim(&application)
        .expect("complete mutation envelope");
    let observed = successor_state(&envelope);

    let first = envelope
        .reconcile(Some(&observed))
        .expect("exact successor is confirmed");
    let second = envelope
        .reconcile(Some(&observed))
        .expect("same reread is deterministic");
    assert_eq!(first, second);

    let TaskProjectionPersistenceDecision::Confirmed(receipt) = first else {
        panic!("exact successor must produce a receipt")
    };
    assert_eq!(receipt.envelope_id(), envelope.envelope_id());
    assert_eq!(receipt.snapshot_id(), envelope.after_snapshot_id());
    assert_eq!(receipt.generation(), envelope.resulting_generation());
    assert_eq!(receipt.transition_id(), *envelope.transition_id().as_bytes());
    assert_ne!(receipt.receipt_id().as_bytes(), &[0; 32]);
}

#[test]
fn same_generation_with_different_semantic_state_is_conflict() {
    let application = claim_application(0x81, 0x82);
    let envelope = TaskProjectionMutationEnvelope::from_claim(&application)
        .expect("complete mutation envelope");
    let different = AuthorityBoundTaskProjectionSnapshot::observed(
        envelope.before_snapshot().authority_read_receipt(),
        envelope.task_id(),
        envelope.resulting_generation(),
        TaskPhase::Rework,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(26),
    )
    .expect("different structurally valid state");
    let observed = TaskProjectionPersistedState::new(
        different.clone(),
        Some(*envelope.transition_id().as_bytes()),
        Some(envelope.inner_transition_id()),
        Some(envelope.evidence_root()),
    );

    assert_eq!(
        envelope
            .reconcile(Some(&observed))
            .expect("different semantic state is a typed conflict"),
        TaskProjectionPersistenceDecision::Conflict {
            envelope_id: envelope.envelope_id(),
            current_snapshot_id: different.snapshot_id(),
            current_generation: *different.generation(),
        }
    );
}

#[test]
fn successor_without_transition_metadata_fails_closed() {
    let application = claim_application(0x81, 0x82);
    let envelope = TaskProjectionMutationEnvelope::from_claim(&application)
        .expect("complete mutation envelope");
    let observed = TaskProjectionPersistedState::new(
        reread(envelope.after_snapshot(), 26),
        None,
        Some(envelope.inner_transition_id()),
        Some(envelope.evidence_root()),
    );

    assert_eq!(
        envelope
            .reconcile(Some(&observed))
            .expect_err("object presence without transition identity is not proof"),
        TaskProjectionPersistenceRefusal::SuccessorTransitionMissing
    );
}

#[test]
fn predecessor_with_attempted_transition_metadata_is_not_retry_safe() {
    let application = claim_application(0x81, 0x82);
    let envelope = TaskProjectionMutationEnvelope::from_claim(&application)
        .expect("complete mutation envelope");
    let observed = TaskProjectionPersistedState::new(
        reread(envelope.before_snapshot(), 26),
        Some(*envelope.transition_id().as_bytes()),
        Some(envelope.inner_transition_id()),
        Some(envelope.evidence_root()),
    );

    assert_eq!(
        envelope
            .reconcile(Some(&observed))
            .expect_err("partial metadata write must not be retried blindly"),
        TaskProjectionPersistenceRefusal::PredecessorCarriesAttemptedMetadata
    );
}

#[test]
fn logical_successor_is_independent_from_adapter_evidence_identity() {
    let first = claim_application(0x81, 0x82);
    let second = claim_application(0x83, 0x84);

    assert_eq!(first.snapshot().generation(), second.snapshot().generation());
    assert_eq!(first.snapshot().snapshot_id(), second.snapshot().snapshot_id());
    assert_ne!(first.transition().transition_id(), second.transition().transition_id());
    assert_ne!(first.projection().adapter_identity(), second.projection().adapter_identity());
}
