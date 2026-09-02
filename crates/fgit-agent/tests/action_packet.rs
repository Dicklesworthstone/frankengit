#![forbid(unsafe_code)]
//! Public-path tests for bounded Level-1 action packets.

use fgit_agent::{
    ActionPacketRefusal, ActionPreconditionSet, ActionStep, ActionStepId, ActiveTaskClaim,
    AgentActionPacket, AgentActionPacketSpec, AgentChangePlan, AgentChangePlanSpec,
    AgentControlPulse, AgentSituationReceipt, AuthorityReadReceipt, ClassSet, ContextControl,
    ContextPacket, EvidenceClass, IntentRun, LogicalTime, OperationClass, PlanApproval,
    PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose, PlanEvidenceRequirement,
    PlanRequirementId, PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcutSet,
    RunId, SituationComponent, SituationComponentKind, SituationOmissionReason,
    TaskClaimProjection, TaskClaimReceipt, TaskPhase, WorkConflict, WorkEligibilityInputs,
    WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositorySequence,
};

const TASK_BASIS: [u8; 32] = [0x44; 32];
const CLAIMED_GENERATION: [u8; 32] = [0x55; 32];
const REQUIREMENT_ID: PlanRequirementId = PlanRequirementId::from_bytes([0x66; 32]);

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
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed-width RCR identity digest"),
    )
}

fn authority_receipt() -> AuthorityReadReceipt {
    let repository_id = fgit_types::RepositoryId::from_bytes([0x22; 16]);
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
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
    let expected_head_id = authority_head_identity(&head)
        .expect("a complete canonical authority head re-identifies itself");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(181));
    let head_key =
        HeadKey::new(b"agent-action-packet-test-head".to_vec()).expect("bounded head key");
    let head_read = match initialize_repository(&store, &head_key, &head)
        .expect("reference store initializes one complete authority head")
    {
        HeadInit::Created(receipt) => receipt,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => {
            panic!("fresh reference store must create the head")
        }
    };
    let authenticated = store
        .authenticate_head_receipt(&head_read)
        .expect("issuing store authenticates its own receipt");
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("authenticated head makes a complete agent receipt");
    assert_eq!(receipt.authority_head_id(), expected_head_id);
    receipt
}

fn run(receipt: &AuthorityReadReceipt, classes: &[OperationClass], bytes: u64) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(classes),
        ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::CpuMicros, 20_000)]),
        LogicalTime::new(100),
    )
    .expect("authenticated run opens")
}

fn situation(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    task_generation: [u8; 32],
    observed_at: u64,
    search_generation: u8,
) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), task_generation)
        } else if kind == SituationComponentKind::Search {
            SituationComponent::observed(kind, receipt.authority_head_id(), [search_generation; 32])
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
        LogicalTime::new(observed_at),
        components,
    )
    .expect("complete authority-bound situation")
}

fn context(receipt: &AuthorityReadReceipt) -> ContextPacket {
    ContextPacket::build(
        receipt.clone(),
        ContextControl::new(
            [0x11; 32],
            ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
            [0x12; 32],
            vec![[0x13; 32]],
            Vec::new(),
        ),
        Vec::new(),
    )
    .expect("bounded context packet")
}

fn activated_plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    context: &ContextPacket,
) -> (
    AgentChangePlan,
    ActiveTaskClaim,
    AgentSituationReceipt,
    PlanSurface,
) {
    let planning_situation = situation(receipt, run, TASK_BASIS, 20, 0x71);
    let task_id = WorkTaskId::from_bytes([0x31; 32]);
    let item = WorkItem::new(
        task_id,
        TASK_BASIS,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, Some(run.run_id()), None, true, WorkConflict::Clear),
    );
    let frontier = WorkFrontier::build_action_scoped(&planning_situation, vec![item])
        .expect("task is eligible");
    let pulse = AgentControlPulse::build(&planning_situation, &frontier, Some(run))
        .expect("live run makes an actionable pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let spec = AgentChangePlanSpec::new(
        digest(0x60),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
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
        REQUIREMENT_ID,
        EvidenceClass::Executed,
        digest(0x67),
        false,
    )]);
    let plan = AgentChangePlan::build(&pulse, run, std::slice::from_ref(context), spec)
        .expect("complete change plan");
    let projection = TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        TASK_BASIS,
        CLAIMED_GENERATION,
        vec![surface],
        LogicalTime::new(25),
        LogicalTime::new(80),
        [0x72; 32],
        digest(0x73),
    );
    let claim =
        TaskClaimReceipt::admit(&pulse, &plan, run, projection).expect("task claim admitted");
    let activation_situation = situation(receipt, run, CLAIMED_GENERATION, 30, 0x74);
    let active_claim = claim
        .activate(&activation_situation, run)
        .expect("post-claim generation activates the claim");
    (plan, active_claim, activation_situation, surface)
}

fn packet_spec(surface: PlanSurface, bytes: u64) -> AgentActionPacketSpec {
    AgentActionPacketSpec::new(
        vec![ActionStep::new(
            ActionStepId::from_bytes([0x81; 32]),
            OperationClass::TreeFsWorkspace,
            surface,
            digest(0x82),
            digest(0x83),
            ResourceVector::single(Grade::Bytes, bytes),
            None,
        )],
        ActionPreconditionSet::MANDATORY,
        digest(0x84),
        digest(0x85),
        digest(0x86),
        [0x87; 32],
    )
    .with_peer_change_roots(vec![digest(0x88)])
}

#[test]
fn packet_is_deterministic_and_binds_complete_execution_inputs() {
    let receipt = authority_receipt();
    let run = run(
        &receipt,
        &[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ],
        16_384,
    );
    let context = context(&receipt);
    let (plan, active_claim, activation, surface) = activated_plan(&receipt, &run, &context);

    let first = AgentActionPacket::build(
        &activation,
        &plan,
        active_claim,
        &run,
        std::slice::from_ref(&context),
        packet_spec(surface, 512),
    )
    .expect("complete action packet");
    let second = AgentActionPacket::build(
        &activation,
        &plan,
        active_claim,
        &run,
        std::slice::from_ref(&context),
        packet_spec(surface, 512),
    )
    .expect("identical inputs make an identical packet");

    assert_eq!(first.packet_id(), second.packet_id());
    assert_eq!(first.situation_id(), activation.situation_id());
    assert_eq!(first.task_projection_generation(), &CLAIMED_GENERATION);
    assert_eq!(first.plan_id(), plan.plan_id());
    assert_eq!(first.active_claim_id(), active_claim.activation_id());
    assert_eq!(first.task_id(), plan.task_id());
    assert_eq!(first.run_id(), run.run_id());
    assert_eq!(
        first.run_commitment(),
        run.commitment().expect("complete execution-run identity")
    );
    assert_eq!(first.context_packet_ids(), &[context.packet_id()]);
    assert_eq!(first.steps().len(), 1);
    assert_eq!(
        first.aggregate_budget(),
        ResourceVector::single(Grade::Bytes, 512)
    );
    assert_ne!(first.packet_id().as_bytes(), &[0; 32]);
}

#[test]
fn packet_refuses_a_later_situation_without_a_continuity_witness() {
    let receipt = authority_receipt();
    let run = run(
        &receipt,
        &[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ],
        16_384,
    );
    let context = context(&receipt);
    let (plan, active_claim, activation, surface) = activated_plan(&receipt, &run, &context);
    let later = situation(&receipt, &run, CLAIMED_GENERATION, 31, 0x75);

    assert_eq!(
        AgentActionPacket::build(
            &later,
            &plan,
            active_claim,
            &run,
            &[context],
            packet_spec(surface, 512),
        )
        .expect_err("a different situation requires explicit continuity evidence"),
        ActionPacketRefusal::ClaimSituationMismatch {
            expected: *activation.situation_id().as_bytes(),
            observed: *later.situation_id().as_bytes(),
        }
    );
}

#[test]
fn packet_cannot_drop_context_admitted_by_the_plan() {
    let receipt = authority_receipt();
    let run = run(
        &receipt,
        &[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ],
        16_384,
    );
    let context = context(&receipt);
    let (plan, active_claim, activation, surface) = activated_plan(&receipt, &run, &context);

    assert_eq!(
        AgentActionPacket::build(
            &activation,
            &plan,
            active_claim,
            &run,
            &[],
            packet_spec(surface, 512),
        )
        .expect_err("plan inputs cannot disappear at execution"),
        ActionPacketRefusal::MissingContextPacket {
            packet_id: context.packet_id(),
        }
    );
}

#[test]
fn same_id_run_is_revalidated_instead_of_trusted_by_name() {
    let receipt = authority_receipt();
    let original = run(
        &receipt,
        &[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ],
        16_384,
    );
    let context = context(&receipt);
    let (plan, active_claim, activation, surface) = activated_plan(&receipt, &original, &context);
    let narrowed = run(&receipt, &[OperationClass::SubmitEvidence], 16_384);
    let narrowed_commitment = narrowed.commitment().expect("narrowed run identity");
    let original_commitment = original.commitment().expect("original run identity");

    assert_eq!(
        AgentActionPacket::build(
            &activation,
            &plan,
            active_claim,
            &narrowed,
            &[context],
            packet_spec(surface, 512),
        )
        .expect_err("same run ID does not substitute for machine scope"),
        ActionPacketRefusal::SituationRunCommitmentMismatch {
            expected: narrowed_commitment,
            observed: Some(original_commitment),
        }
    );
}

#[test]
fn step_operation_and_aggregate_budget_remain_inside_the_plan() {
    let receipt = authority_receipt();
    let run = run(
        &receipt,
        &[
            OperationClass::TreeFsWorkspace,
            OperationClass::ExecuteSandboxedProcess,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ],
        16_384,
    );
    let context = context(&receipt);
    let (plan, active_claim, activation, surface) = activated_plan(&receipt, &run, &context);
    let outside = AgentActionPacketSpec::new(
        vec![ActionStep::new(
            ActionStepId::from_bytes([0x81; 32]),
            OperationClass::ExecuteSandboxedProcess,
            surface,
            digest(0x82),
            digest(0x83),
            ResourceVector::single(Grade::Bytes, 512),
            None,
        )],
        ActionPreconditionSet::MANDATORY,
        digest(0x84),
        digest(0x85),
        digest(0x86),
        [0x87; 32],
    );
    assert_eq!(
        AgentActionPacket::build(
            &activation,
            &plan,
            active_claim,
            &run,
            std::slice::from_ref(&context),
            outside,
        )
        .expect_err("run authority cannot widen the narrower plan"),
        ActionPacketRefusal::OperationOutsidePlan {
            step_id: ActionStepId::from_bytes([0x81; 32]),
            operation: OperationClass::ExecuteSandboxedProcess,
        }
    );

    assert!(matches!(
        AgentActionPacket::build(
            &activation,
            &plan,
            active_claim,
            &run,
            &[context],
            packet_spec(surface, 4_097),
        ),
        Err(ActionPacketRefusal::AggregateBudgetExceedsPlan { .. })
    ));
}
