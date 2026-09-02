#![forbid(unsafe_code)]
//! Public-path tests for debt-preserving Agent Control Plane handoffs.

use fgit_agent::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentHandoffCapsule,
    AgentHandoffCapsuleSpec, AgentInstanceId, AgentSituationReceipt, AuthorityReadReceipt,
    CapabilityId, ClassSet, EffectClass, EffectId, EffectRecord, EffectResolutionAction,
    EvidenceClass, HandoffCapabilityAttenuation, HandoffRefusal, IntentRun, LogicalTime,
    OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose,
    PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet, PlanSurface, PlanSurfaceKind,
    RejectedShortcutSet, RequirementDisposition, RunId, RunReconciliationReadiness,
    RunReconciliationReport, SituationComponent, SituationComponentKind, SituationOmissionReason,
    TaskClaimProjection, TaskClaimReceipt, TaskPhase, WorkConflict, WorkEligibilityInputs,
    WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ObligationState, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositorySequence,
};

const TASK_BASIS: [u8; 32] = [0x44; 32];
const CLAIMED_GENERATION: [u8; 32] = [0x55; 32];

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome root");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed digest"),
    )
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed RCR digest"),
    )
}

fn authority_receipt() -> AuthorityReadReceipt {
    let repository_id = fgit_types::RepositoryId::from_bytes([0x22; 16]);
    let root = outcome_index_root(&[]).expect("empty outcome root");
    let head = RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr_id()),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root: digest(0x41),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let expected = authority_head_identity(&head).expect("head identity");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(151));
    let key = HeadKey::new(b"agent-handoff-test-head".to_vec()).expect("head key");
    let read = match initialize_repository(&store, &key, &head).expect("initialize") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("authenticate receipt");
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("complete receipt");
    assert_eq!(receipt.authority_head_id(), expected);
    receipt
}

fn run(receipt: &AuthorityReadReceipt) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::ExecuteSandboxedProcess,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ]),
        ResourceVector::from_grades(&[(Grade::Bytes, 16_384), (Grade::CpuMicros, 20_000)]),
        LogicalTime::new(100),
    )
    .expect("run opens")
}

fn situation(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    task_generation: [u8; 32],
    observed_at: u64,
) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), task_generation)
        } else {
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [u8::try_from(index + 1).expect("component index"); 32],
            )
        }
    });
    AgentSituationReceipt::build(
        receipt.clone(),
        Some(run),
        None,
        LogicalTime::new(observed_at),
        components,
    )
    .expect("complete situation")
}

fn plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
) -> (AgentControlPulse, AgentChangePlan, PlanSurface) {
    let situation = situation(receipt, run, TASK_BASIS, 20);
    let item = WorkItem::new(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, Some(run.run_id()), None, true, WorkConflict::Clear),
    );
    let frontier =
        WorkFrontier::build_action_scoped(&situation, vec![item]).expect("eligible frontier");
    let pulse = AgentControlPulse::build(&situation, &frontier, Some(run)).expect("pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let spec = AgentChangePlanSpec::new(
        digest(0x60),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::ExecuteSandboxedProcess,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ]),
        ResourceVector::from_grades(&[(Grade::Bytes, 4_096), (Grade::CpuMicros, 5_000)]),
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
    (pulse, plan, surface)
}

fn active_claim(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    pulse: &AgentControlPulse,
    plan: &AgentChangePlan,
    surface: PlanSurface,
) -> (ActiveTaskClaim, AgentSituationReceipt) {
    let projection = TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        TASK_BASIS,
        CLAIMED_GENERATION,
        vec![surface],
        LogicalTime::new(25),
        LogicalTime::new(80),
        [0x71; 32],
        digest(0x72),
    );
    let claim = TaskClaimReceipt::admit(pulse, plan, run, projection).expect("claim admitted");
    let latest = situation(receipt, run, CLAIMED_GENERATION, 40);
    let active = claim.activate(&latest, run).expect("claim activated");
    (active, latest)
}

fn reserved_effect(receipt: &AuthorityReadReceipt, run: &IntentRun) -> EffectRecord {
    EffectRecord {
        effect_id: EffectId::new(1),
        run_id: run.run_id(),
        run_commitment: run.commitment().expect("complete run commitment"),
        agent_instance_id: AgentInstanceId::new(1),
        parent_effect_id: None,
        capability_id: CapabilityId::new(2),
        effect_class: EffectClass::DerivedLocalWrite,
        operation: OperationClass::TreeFsWorkspace,
        input_commitment: [0x81; 32],
        source_authority_receipt: Some(receipt.clone()),
        budget_reserved: ResourceVector::single(Grade::Bytes, 256),
        budget_consumed: ResourceVector::ZERO,
        external_idempotency_key: None,
        obligation_state: ObligationState::Reserved,
        obligation_class: None,
        terminal_outcome: None,
        output_commitments: Vec::new(),
        reconciliation_evidence: None,
        accepted_at: LogicalTime::new(35),
    }
}

fn handoff_spec(
    operations: ClassSet,
    expiry: LogicalTime,
    target_selector: [u8; 32],
) -> AgentHandoffCapsuleSpec {
    AgentHandoffCapsuleSpec::new(
        AgentInstanceId::new(1),
        target_selector,
        HandoffCapabilityAttenuation::new(
            operations,
            ResourceVector::single(Grade::Bytes, 1_024),
            expiry,
        ),
        digest(0x91),
    )
    .with_changed_object_roots(vec![digest(0x92)])
    .with_evidence(
        vec![Some(RequirementDisposition::Unsatisfied)],
        Vec::new(),
        Vec::new(),
    )
    .with_unresolved_work(vec![digest(0x93)], vec![digest(0x94)])
    .with_requested_next_actions(vec![digest(0x95)])
}

#[test]
fn handoff_identity_is_deterministic_and_preserves_complete_effect_debt() {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let (pulse, plan, surface) = plan(&receipt, &run);
    let (active, latest) = active_claim(&receipt, &run, &pulse, &plan, surface);
    let reconciliation = RunReconciliationReport::build(
        &run,
        vec![reserved_effect(&receipt, &run)],
        latest.observed_at(),
    )
    .expect("complete effect inventory");
    let operations = ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]);
    let spec = handoff_spec(operations, LogicalTime::new(70), [0x77; 32]);

    let first = AgentHandoffCapsule::build(
        &latest,
        &plan,
        active,
        &run,
        reconciliation.clone(),
        spec.clone(),
    )
    .expect("complete handoff capsule");
    let second = AgentHandoffCapsule::build(&latest, &plan, active, &run, reconciliation, spec)
        .expect("identical inputs produce an identical capsule");

    assert_eq!(first.capsule_id(), second.capsule_id());
    assert_eq!(first.source_run_id(), run.run_id());
    assert_eq!(first.plan_id(), plan.plan_id());
    assert_eq!(first.active_claim_id(), active.activation_id());
    assert_eq!(first.outstanding_effect_count(), 1);
    assert_eq!(
        first.reconciliation_readiness(),
        RunReconciliationReadiness::ReservationAbortRequired
    );
    let effect = first
        .outstanding_effects()
        .next()
        .expect("reserved effect remains visible");
    assert_eq!(effect.record().effect_id, EffectId::new(1));
    assert_eq!(
        effect.required_action(),
        EffectResolutionAction::AbortReservation
    );
    assert_ne!(first.capsule_id().as_bytes(), &[0; 32]);
}

#[test]
fn receiver_scope_must_cover_every_carried_effect_action() {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let (pulse, plan, surface) = plan(&receipt, &run);
    let (active, latest) = active_claim(&receipt, &run, &pulse, &plan, surface);
    let reconciliation = RunReconciliationReport::build(
        &run,
        vec![reserved_effect(&receipt, &run)],
        latest.observed_at(),
    )
    .expect("complete effect inventory");
    let spec = handoff_spec(
        ClassSet::from_classes(&[OperationClass::SubmitEvidence]),
        LogicalTime::new(70),
        [0x77; 32],
    );

    assert_eq!(
        AgentHandoffCapsule::build(&latest, &plan, active, &run, reconciliation, spec)
            .expect_err("receiver cannot inherit debt it lacks scope to resolve"),
        HandoffRefusal::CapabilityCannotResolveEffect {
            effect_id: EffectId::new(1),
            operation: OperationClass::TreeFsWorkspace,
        }
    );
}

#[test]
fn receiver_scope_cannot_outlive_the_source_claim() {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let (pulse, plan, surface) = plan(&receipt, &run);
    let (active, latest) = active_claim(&receipt, &run, &pulse, &plan, surface);
    let reconciliation = RunReconciliationReport::build(&run, Vec::new(), latest.observed_at())
        .expect("empty complete effect inventory");
    let spec = handoff_spec(
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        LogicalTime::new(81),
        [0x77; 32],
    );

    assert_eq!(
        AgentHandoffCapsule::build(&latest, &plan, active, &run, reconciliation, spec)
            .expect_err("delegated lifetime is attenuated by the task claim"),
        HandoffRefusal::CapabilityOutlivesClaim {
            expiry: LogicalTime::new(81),
            claim_expiry: LogicalTime::new(80),
        }
    );
}

#[test]
fn all_zero_target_selector_is_refused() {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let (pulse, plan, surface) = plan(&receipt, &run);
    let (active, latest) = active_claim(&receipt, &run, &pulse, &plan, surface);
    let reconciliation = RunReconciliationReport::build(&run, Vec::new(), latest.observed_at())
        .expect("empty complete effect inventory");
    let spec = handoff_spec(
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        LogicalTime::new(70),
        [0; 32],
    );

    assert_eq!(
        AgentHandoffCapsule::build(&latest, &plan, active, &run, reconciliation, spec)
            .expect_err("reserved target identity must fail closed"),
        HandoffRefusal::ZeroTargetSelector
    );
}
