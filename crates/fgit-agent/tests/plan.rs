#![forbid(unsafe_code)]
//! Public-path tests for authority-bound Agent Change Plans.

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityReadReceipt, ClassSet, ContextControl, ContextPacket, ContextSource, EvidenceClass,
    IntentRun, LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRefusal, PlanRequirementId,
    PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RetrievalChannel,
    RunId, SITUATION_COMPONENT_COUNT, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskPhase, WorkAction, WorkConflict, WorkEligibilityInputs,
    WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{IdentityDomain, NativeObjectIdentity};
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositorySequence,
};

const TASK_GENERATION: [u8; 32] = [0x44; 32];

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn rcr_id(byte: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width RCR identity digest"),
    )
}

fn authority_receipt(store_id: u64, repository_byte: u8) -> AuthorityReadReceipt {
    let repository_id = fgit_types::RepositoryId::from_bytes([repository_byte; 16]);
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
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
    let expected_head_id = authority_head_identity(&head)
        .expect("a complete canonical authority head re-identifies itself");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let head_key = HeadKey::new(format!("agent-plan-test-head-{store_id}").into_bytes())
        .expect("bounded nonempty head key");
    let initialized = initialize_repository(&store, &head_key, &head)
        .expect("reference store initializes one complete authority head");
    let head_read = match initialized {
        HeadInit::Created(receipt) => receipt,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => {
            panic!("fresh reference store must create the head")
        }
    };
    let authenticated = store
        .authenticate_head_receipt(&head_read)
        .expect("the issuing store authenticates its own head receipt");
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("authenticated head makes a complete agent receipt");
    assert_eq!(receipt.authority_head_id(), expected_head_id);
    receipt
}

fn allowed_classes() -> ClassSet {
    ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::TreeFsWorkspace,
        OperationClass::ExecuteSandboxedProcess,
        OperationClass::SubmitEvidence,
        OperationClass::ConsumeBudget,
    ])
}

fn run(receipt: &AuthorityReadReceipt, run_id: u128) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(run_id),
        receipt.clone(),
        allowed_classes(),
        ResourceVector::from_grades(&[
            (Grade::Bytes, 32_768),
            (Grade::CpuMicros, 50_000),
        ]),
        LogicalTime::new(100),
    )
    .expect("authenticated run opens")
}

fn situation(receipt: &AuthorityReadReceipt, active_run: &IntentRun) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), TASK_GENERATION)
        } else {
            let byte = u8::try_from(index + 1).expect("component index fits u8");
            SituationComponent::omitted(
                kind,
                SituationOmissionReason::NotAvailable,
                [byte; 32],
            )
        }
    });
    AgentSituationReceipt::build(
        receipt.clone(),
        Some(active_run),
        None,
        LogicalTime::new(20),
        components,
    )
    .expect("complete authority-bound situation")
}

fn pulse(
    receipt: &AuthorityReadReceipt,
    active_run: &IntentRun,
    phase: TaskPhase,
) -> AgentControlPulse {
    let situation = situation(receipt, active_run);
    let item = WorkItem::new(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_GENERATION,
        phase,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(
            0,
            Some(active_run.run_id()),
            None,
            true,
            WorkConflict::Clear,
        ),
    );
    let frontier = WorkFrontier::build_action_scoped(&situation, vec![item])
        .expect("selected task is eligible");
    AgentControlPulse::build(&situation, &frontier, Some(active_run))
        .expect("live exact run makes an actionable pulse")
}

fn context(receipt: AuthorityReadReceipt, byte: u8) -> ContextPacket {
    let control = ContextControl::new(
        [byte; 32],
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        [byte.wrapping_add(1); 32],
        vec![[byte.wrapping_add(2); 32]],
        Vec::new(),
    );
    let source = ContextSource::new(
        [byte.wrapping_add(3); 32],
        RetrievalChannel::Exact,
        vec![byte; 16],
    )
    .expect("bounded source body");
    ContextPacket::build(receipt, control, vec![source])
        .expect("single-generation context packet")
}

fn spec(action: WorkAction) -> AgentChangePlanSpec {
    let purpose = match action {
        WorkAction::Implement => PlanCheckpointPurpose::ImplementSlice,
        WorkAction::Verify => PlanCheckpointPurpose::VerifySlice,
        WorkAction::Rework => PlanCheckpointPurpose::RepairSlice,
    };
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    AgentChangePlanSpec::new(
        digest(0x60),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::ExecuteSandboxedProcess,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ]),
        ResourceVector::from_grades(&[
            (Grade::Bytes, 8_192),
            (Grade::CpuMicros, 10_000),
        ]),
        PlanStopConditionSet::MANDATORY,
        RejectedShortcutSet::BASELINE,
        PlanApproval::NotRequired {
            policy_root: digest(0x62),
        },
    )
    .with_owning_invariants(vec![digest(0x63), digest(0x64)])
    .with_surfaces(vec![surface], vec![surface])
    .with_checkpoints(vec![PlanCheckpoint::new(
        PlanCheckpointId::from_bytes([0x65; 32]),
        purpose,
        digest(0x66),
        digest(0x67),
    )])
    .with_evidence_plan(vec![PlanEvidenceRequirement::new(
        PlanRequirementId::from_bytes([0x68; 32]),
        EvidenceClass::Executed,
        digest(0x69),
        action == WorkAction::Verify,
    )])
    .with_non_claims(vec![digest(0x6a)])
}

#[test]
fn plan_binds_selected_work_and_canonicalizes_unordered_inputs() {
    let receipt = authority_receipt(101, 0x22);
    let active_run = run(&receipt, 7);
    let pulse = pulse(&receipt, &active_run, TaskPhase::Open);
    let first_context = context(receipt.clone(), 0x71);
    let second_context = context(receipt.clone(), 0x72);

    let plan = AgentChangePlan::build(
        &pulse,
        &active_run,
        &[second_context.clone(), first_context.clone()],
        spec(WorkAction::Implement),
    )
    .expect("complete implementation plan");
    let reordered = AgentChangePlan::build(
        &pulse,
        &active_run,
        &[first_context, second_context],
        spec(WorkAction::Implement),
    )
    .expect("input order does not change a set-valued plan field");

    assert_eq!(plan.plan_id(), reordered.plan_id());
    assert_eq!(plan.pulse_id(), pulse.pulse_id().as_bytes());
    assert_eq!(plan.intent_run_id(), active_run.run_id());
    assert_eq!(plan.task_id(), WorkTaskId::from_bytes([0x31; 32]));
    assert_eq!(plan.action(), WorkAction::Implement);
    assert_eq!(plan.checkpoints().len(), 1);
    assert_eq!(plan.evidence_plan().len(), 1);
    assert_eq!(plan.intended_change_surface(), plan.conflict_surface());
    assert_ne!(plan.plan_id().as_bytes(), &[0; 32]);
}

#[test]
fn every_intended_change_requires_conflict_coverage() {
    let receipt = authority_receipt(102, 0x23);
    let active_run = run(&receipt, 7);
    let pulse = pulse(&receipt, &active_run, TaskPhase::Open);
    let intended = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let wrong = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x62));
    let incomplete = spec(WorkAction::Implement).with_surfaces(vec![intended], vec![wrong]);

    assert_eq!(
        AgentChangePlan::build(&pulse, &active_run, &[], incomplete)
            .expect_err("coordination coverage must include every intended surface"),
        PlanRefusal::ConflictSurfaceIncomplete { missing: intended }
    );
}

#[test]
fn plan_budget_cannot_amplify_the_run() {
    let receipt = authority_receipt(103, 0x24);
    let active_run = run(&receipt, 7);
    let pulse = pulse(&receipt, &active_run, TaskPhase::Open);
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let over_budget = AgentChangePlanSpec::new(
        digest(0x60),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 32_769),
        PlanStopConditionSet::MANDATORY,
        RejectedShortcutSet::BASELINE,
        PlanApproval::NotRequired {
            policy_root: digest(0x62),
        },
    )
    .with_surfaces(vec![surface], vec![surface])
    .with_checkpoints(vec![PlanCheckpoint::new(
        PlanCheckpointId::from_bytes([0x65; 32]),
        PlanCheckpointPurpose::ImplementSlice,
        digest(0x66),
        digest(0x67),
    )])
    .with_evidence_plan(vec![PlanEvidenceRequirement::new(
        PlanRequirementId::from_bytes([0x68; 32]),
        EvidenceClass::Executed,
        digest(0x69),
        false,
    )]);

    assert!(matches!(
        AgentChangePlan::build(&pulse, &active_run, &[], over_budget),
        Err(PlanRefusal::ResourceBudgetExceedsRun { .. })
    ));
}

#[test]
fn verification_plan_requires_independent_evidence() {
    let receipt = authority_receipt(104, 0x25);
    let active_run = run(&receipt, 7);
    let pulse = pulse(
        &receipt,
        &active_run,
        TaskPhase::VerificationPending,
    );
    let not_independent = spec(WorkAction::Verify).with_evidence_plan(vec![
        PlanEvidenceRequirement::new(
            PlanRequirementId::from_bytes([0x68; 32]),
            EvidenceClass::Executed,
            digest(0x69),
            false,
        ),
    ]);

    assert_eq!(
        AgentChangePlan::build(&pulse, &active_run, &[], not_independent)
            .expect_err("self-verification cannot satisfy an independent gate"),
        PlanRefusal::VerificationIndependenceMissing
    );
}

#[test]
fn context_from_another_authority_position_is_refused() {
    let receipt = authority_receipt(105, 0x26);
    let foreign = authority_receipt(106, 0x27);
    let active_run = run(&receipt, 7);
    let pulse = pulse(&receipt, &active_run, TaskPhase::Open);
    let foreign_packet = context(foreign, 0x71);

    assert_eq!(
        AgentChangePlan::build(
            &pulse,
            &active_run,
            &[foreign_packet.clone()],
            spec(WorkAction::Implement),
        )
        .expect_err("mixed authority context must fail closed"),
        PlanRefusal::ContextAuthorityMismatch {
            packet_id: foreign_packet.packet_id(),
        }
    );
}
