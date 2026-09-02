#![forbid(unsafe_code)]
//! Public-path tests for receiver-side handoff verification.

use fgit_agent::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentHandoffCapsule,
    AgentHandoffCapsuleSpec, AgentInstanceId, AgentSituationReceipt, AuthorityReadReceipt,
    CapabilityId, ClassSet, EffectClass, EffectId, EffectRecord, EffectResolutionAction,
    EvidenceClass, HandoffAcceptanceRefusal, HandoffCapabilityAttenuation, HandoffTargetResolution,
    IntentRun, LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet,
    PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RequirementDisposition, RunId,
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
const TARGET: [u8; 32] = [0x77; 32];

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome root");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed digest"),
    )
}

fn rcr_id(byte: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("fixed RCR digest"),
    )
}

fn authority_receipt(store_id: u64, repository_byte: u8) -> AuthorityReadReceipt {
    let repository_id = fgit_types::RepositoryId::from_bytes([repository_byte; 16]);
    let root = outcome_index_root(&[]).expect("empty outcome root");
    let head = RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr_id(repository_byte)),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root: digest(repository_byte.wrapping_add(1)),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let expected = authority_head_identity(&head).expect("head identity");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let key = HeadKey::new(format!("agent-handoff-accept-test-{store_id}").into_bytes())
        .expect("head key");
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

fn source_run(receipt: &AuthorityReadReceipt) -> IntentRun {
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
    .expect("source run opens")
}

fn receiver_run(
    receipt: &AuthorityReadReceipt,
    operations: ClassSet,
    bytes: u64,
    expiry: u64,
) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(8),
        receipt.clone(),
        operations,
        ResourceVector::single(Grade::Bytes, bytes),
        LogicalTime::new(expiry),
    )
    .expect("receiver run opens")
}

fn situation(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    observed_at: u64,
) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), CLAIMED_GENERATION)
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

fn source_plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
) -> (AgentControlPulse, AgentChangePlan, PlanSurface) {
    let source_situation = {
        let components = std::array::from_fn(|index| {
            let kind = SituationComponentKind::ALL[index];
            if kind == SituationComponentKind::TaskProjection {
                SituationComponent::observed(kind, receipt.authority_head_id(), TASK_BASIS)
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
            LogicalTime::new(20),
            components,
        )
        .expect("source planning situation")
    };
    let item = WorkItem::new(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, Some(run.run_id()), None, true, WorkConflict::Clear),
    );
    let frontier = WorkFrontier::build_action_scoped(&source_situation, vec![item])
        .expect("eligible frontier");
    let pulse = AgentControlPulse::build(&source_situation, &frontier, Some(run)).expect("pulse");
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
    let latest = situation(receipt, run, 40);
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

fn capsule(
    receipt: &AuthorityReadReceipt,
    source: &IntentRun,
    attenuation_operations: ClassSet,
) -> AgentHandoffCapsule {
    let (pulse, plan, surface) = source_plan(receipt, source);
    let (active, latest) = active_claim(receipt, source, &pulse, &plan, surface);
    let reconciliation = RunReconciliationReport::build(
        source,
        vec![reserved_effect(receipt, source)],
        latest.observed_at(),
    )
    .expect("complete source effect inventory");
    let spec = AgentHandoffCapsuleSpec::new(
        AgentInstanceId::new(1),
        TARGET,
        HandoffCapabilityAttenuation::new(
            attenuation_operations,
            ResourceVector::single(Grade::Bytes, 1_024),
            LogicalTime::new(70),
        ),
        digest(0x91),
    )
    .with_evidence(
        vec![Some(RequirementDisposition::Unsatisfied)],
        Vec::new(),
        Vec::new(),
    )
    .with_unresolved_work(vec![digest(0x92)], vec![digest(0x93)])
    .with_requested_next_actions(vec![digest(0x94)]);
    AgentHandoffCapsule::build(&latest, &plan, active, source, reconciliation, spec)
        .expect("complete handoff capsule")
}

fn resolution(receiver: &IntentRun, instance: AgentInstanceId) -> HandoffTargetResolution {
    HandoffTargetResolution::new(
        TARGET,
        receiver.run_id(),
        instance,
        [0xa1; 32],
        digest(0xa2),
    )
}

#[test]
fn receiver_acceptance_is_deterministic_and_preserves_carried_debt() {
    let receipt = authority_receipt(171, 0x22);
    let source = source_run(&receipt);
    let capsule = capsule(
        &receipt,
        &source,
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
    );
    let receiver = receiver_run(
        &receipt,
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        512,
        65,
    );
    let receiver_situation = situation(&receipt, &receiver, 45);
    let instance = AgentInstanceId::new(2);

    let first = capsule
        .accept(
            &receiver_situation,
            &receiver,
            instance,
            resolution(&receiver, instance),
        )
        .expect("attenuated receiver accepts the capsule");
    let second = capsule
        .accept(
            &receiver_situation,
            &receiver,
            instance,
            resolution(&receiver, instance),
        )
        .expect("same evidence produces the same acceptance");

    assert_eq!(first.acceptance_id(), second.acceptance_id());
    assert_eq!(first.capsule_id(), capsule.capsule_id());
    assert_eq!(first.receiver_run_id(), receiver.run_id());
    assert_eq!(first.effect_responsibilities().len(), 1);
    assert_eq!(
        first.effect_responsibilities()[0].effect_id(),
        EffectId::new(1)
    );
    assert_eq!(
        first.effect_responsibilities()[0].required_action(),
        EffectResolutionAction::AbortReservation
    );
    assert_ne!(first.acceptance_id().as_bytes(), &[0; 32]);
}

#[test]
fn receiver_scope_cannot_amplify_capsule_operations() {
    let receipt = authority_receipt(172, 0x23);
    let source = source_run(&receipt);
    let capsule = capsule(
        &receipt,
        &source,
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
    );
    let receiver = receiver_run(
        &receipt,
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
        ]),
        512,
        65,
    );
    let receiver_situation = situation(&receipt, &receiver, 45);
    let instance = AgentInstanceId::new(2);

    assert_eq!(
        capsule
            .accept(
                &receiver_situation,
                &receiver,
                instance,
                resolution(&receiver, instance),
            )
            .expect_err("receiver cannot widen source attenuation"),
        HandoffAcceptanceRefusal::OperationAmplification {
            missing: ClassSet::from_classes(&[OperationClass::SubmitEvidence]),
        }
    );
}

#[test]
fn narrower_receiver_must_still_cover_inherited_effect_debt() {
    let receipt = authority_receipt(173, 0x24);
    let source = source_run(&receipt);
    let capsule = capsule(
        &receipt,
        &source,
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
        ]),
    );
    let receiver = receiver_run(
        &receipt,
        ClassSet::from_classes(&[OperationClass::SubmitEvidence]),
        512,
        65,
    );
    let receiver_situation = situation(&receipt, &receiver, 45);
    let instance = AgentInstanceId::new(2);

    assert_eq!(
        capsule
            .accept(
                &receiver_situation,
                &receiver,
                instance,
                resolution(&receiver, instance),
            )
            .expect_err("narrowing cannot discard responsibility"),
        HandoffAcceptanceRefusal::CannotResolveEffect {
            effect_id: EffectId::new(1),
            operation: OperationClass::TreeFsWorkspace,
        }
    );
}

#[test]
fn receiver_from_another_repository_is_refused() {
    let receipt = authority_receipt(174, 0x25);
    let foreign = authority_receipt(175, 0x26);
    let source = source_run(&receipt);
    let capsule = capsule(
        &receipt,
        &source,
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
    );
    let receiver = receiver_run(
        &foreign,
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        512,
        65,
    );
    let receiver_situation = situation(&foreign, &receiver, 45);
    let instance = AgentInstanceId::new(2);

    assert_eq!(
        capsule
            .accept(
                &receiver_situation,
                &receiver,
                instance,
                resolution(&receiver, instance),
            )
            .expect_err("cross-repository handoff must fail closed"),
        HandoffAcceptanceRefusal::RepositoryMismatch
    );
}
