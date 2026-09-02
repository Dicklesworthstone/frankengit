#![forbid(unsafe_code)]
//! Public-path tests for task-claim admission and activation.

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun, LogicalTime, OperationClass,
    PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose, PlanEvidenceRequirement,
    PlanRequirementId, PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcutSet,
    RunId, SituationComponent, SituationComponentKind, SituationOmissionReason,
    TaskClaimProjection, TaskClaimReceipt, TaskClaimRefusal, TaskPhase, WorkConflict,
    WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(121));
    let key = HeadKey::new(b"agent-claim-test-head".to_vec()).expect("head key");
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

fn run(receipt: &AuthorityReadReceipt, id: u128) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(id),
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

fn control_turn(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    task_byte: u8,
) -> (AgentControlPulse, AgentChangePlan, PlanSurface) {
    let situation = situation(receipt, run, TASK_BASIS, 20);
    let task_id = WorkTaskId::from_bytes([task_byte; 32]);
    let item = WorkItem::new(
        task_id,
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

fn projection(
    plan: &AgentChangePlan,
    run: &IntentRun,
    surface: PlanSurface,
    claimed_generation: [u8; 32],
) -> TaskClaimProjection {
    TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        TASK_BASIS,
        claimed_generation,
        vec![surface],
        LogicalTime::new(25),
        LogicalTime::new(80),
        [0x71; 32],
        digest(0x72),
    )
}

#[test]
fn claim_becomes_active_only_after_refresh_observes_post_claim_generation() {
    let receipt = authority_receipt();
    let run = run(&receipt, 7);
    let (pulse, plan, surface) = control_turn(&receipt, &run, 0x31);
    let claimed_generation = [0x55; 32];
    let claim = TaskClaimReceipt::admit(
        &pulse,
        &plan,
        &run,
        projection(&plan, &run, surface, claimed_generation),
    )
    .expect("valid claim projection");
    let identical = TaskClaimReceipt::admit(
        &pulse,
        &plan,
        &run,
        projection(&plan, &run, surface, claimed_generation),
    )
    .expect("identical claim projection");
    assert_eq!(claim.claim_id(), identical.claim_id());

    let stale = situation(&receipt, &run, TASK_BASIS, 30);
    assert!(matches!(
        claim.activate(&stale, &run),
        Err(TaskClaimRefusal::ClaimGenerationNotObserved { .. })
    ));

    let refreshed = situation(&receipt, &run, claimed_generation, 30);
    let active = claim
        .activate(&refreshed, &run)
        .expect("post-claim generation activates the claim");
    assert_eq!(active.claim_id(), claim.claim_id());
    assert_eq!(active.plan_id(), plan.plan_id());
    assert_eq!(active.task_id(), plan.task_id());
    assert!(active.is_live_at(LogicalTime::new(30)));
}

#[test]
fn claim_refuses_stale_basis_and_incomplete_reservation_surface() {
    let receipt = authority_receipt();
    let run = run(&receipt, 7);
    let (pulse, plan, surface) = control_turn(&receipt, &run, 0x31);
    let stale = TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        [0x43; 32],
        [0x55; 32],
        vec![surface],
        LogicalTime::new(25),
        LogicalTime::new(80),
        [0x71; 32],
        digest(0x72),
    );
    assert!(matches!(
        TaskClaimReceipt::admit(&pulse, &plan, &run, stale),
        Err(TaskClaimRefusal::PreviousTaskGenerationMismatch { .. })
    ));

    let wrong_surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x62));
    let incomplete = TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        TASK_BASIS,
        [0x55; 32],
        vec![wrong_surface],
        LogicalTime::new(25),
        LogicalTime::new(80),
        [0x71; 32],
        digest(0x72),
    );
    assert_eq!(
        TaskClaimReceipt::admit(&pulse, &plan, &run, incomplete)
            .expect_err("reservation must match the plan exactly"),
        TaskClaimRefusal::ReservationSurfaceMismatch
    );
}

#[test]
fn claim_cannot_outlive_its_intent_run() {
    let receipt = authority_receipt();
    let run = run(&receipt, 7);
    let (pulse, plan, surface) = control_turn(&receipt, &run, 0x31);
    let projection = TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        TASK_BASIS,
        [0x55; 32],
        vec![surface],
        LogicalTime::new(25),
        LogicalTime::new(101),
        [0x71; 32],
        digest(0x72),
    );

    assert_eq!(
        TaskClaimReceipt::admit(&pulse, &plan, &run, projection)
            .expect_err("claim lifetime is attenuated by run lifetime"),
        TaskClaimRefusal::ClaimOutlivesRun {
            claim_expires_at: LogicalTime::new(101),
            run_expires_at: LogicalTime::new(100),
        }
    );
}

#[test]
fn overlapping_live_claims_by_different_runs_are_detectable() {
    let receipt = authority_receipt();
    let first_run = run(&receipt, 7);
    let second_run = run(&receipt, 8);
    let (first_pulse, first_plan, surface) = control_turn(&receipt, &first_run, 0x31);
    let (second_pulse, second_plan, _) = control_turn(&receipt, &second_run, 0x32);
    let first = TaskClaimReceipt::admit(
        &first_pulse,
        &first_plan,
        &first_run,
        projection(&first_plan, &first_run, surface, [0x55; 32]),
    )
    .expect("first claim");
    let second = TaskClaimReceipt::admit(
        &second_pulse,
        &second_plan,
        &second_run,
        projection(&second_plan, &second_run, surface, [0x56; 32]),
    )
    .expect("second claim");

    assert!(first.conflicts_with(&second, LogicalTime::new(30)));
    assert!(!first.conflicts_with(&second, LogicalTime::new(90)));
}
