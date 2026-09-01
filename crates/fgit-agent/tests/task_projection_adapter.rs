#![forbid(unsafe_code)]
//! Public-path tests for deterministic semantic task transitions.

use fgit_agent::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse,
    AgentSituationReceipt, AuthorityReadReceipt, ClassSet,
    CoordinatedTaskProjectionSnapshot as TaskProjectionSnapshot, EvidenceClass, IntentRun,
    LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet,
    PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RunId, SituationComponent,
    SituationComponentKind, SituationOmissionReason, TaskClaimReceipt,
    TaskProjectionAdapterRefusal, TaskProjectionAssignment, TaskReleaseDisposition, TaskPhase,
    WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(901));
    let key = HeadKey::new(b"semantic-task-transition-test".to_vec()).expect("bounded head key");
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

fn run(receipt: &AuthorityReadReceipt, run_id: u128) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(run_id),
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
    observed_at: u64,
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
        LogicalTime::new(observed_at),
        components,
    )
    .expect("complete situation")
}

fn pulse_and_plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    snapshot: &TaskProjectionSnapshot,
) -> (AgentControlPulse, AgentChangePlan, PlanSurface) {
    let current = situation(receipt, run, *snapshot.generation(), 20);
    let assignee = match snapshot.assignment() {
        TaskProjectionAssignment::Unassigned => None,
        TaskProjectionAssignment::Assigned(run_id) => Some(run_id),
    };
    let item = WorkItem::new(
        snapshot.task_id(),
        *snapshot.generation(),
        snapshot.phase(),
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, assignee, None, true, WorkConflict::Clear),
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
    (pulse, plan, surface)
}

struct ClaimedFixture {
    receipt: AuthorityReadReceipt,
    source_run: IntentRun,
    claimed_snapshot: TaskProjectionSnapshot,
    claim_receipt: TaskClaimReceipt,
    active_claim: ActiveTaskClaim,
}

fn claimed_fixture() -> ClaimedFixture {
    let receipt = authority_receipt();
    let source_run = run(&receipt, 7);
    let initial = TaskProjectionSnapshot::observed(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
    )
    .expect("valid initial state");
    let (pulse, plan, _) = pulse_and_plan(&receipt, &source_run, &initial);
    let application = initial
        .claim(
            &pulse,
            &plan,
            &source_run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [0x81; 32],
            digest(0x82),
        )
        .expect("claim transition");
    let claim_receipt = TaskClaimReceipt::admit(
        &pulse,
        &plan,
        &source_run,
        application.projection().clone(),
    )
    .expect("claim projection admission");
    let activation = situation(
        &receipt,
        &source_run,
        *application.snapshot().generation(),
        30,
    );
    let active_claim = claim_receipt
        .activate(&activation, &source_run)
        .expect("fresh generation activates claim");
    ClaimedFixture {
        receipt,
        source_run,
        claimed_snapshot: application.snapshot().clone(),
        claim_receipt,
        active_claim,
    }
}

#[test]
fn semantic_successor_is_independent_from_adapter_evidence() {
    let receipt = authority_receipt();
    let run = run(&receipt, 7);
    let initial = TaskProjectionSnapshot::observed(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
    )
    .expect("valid initial state");
    let (pulse, plan, surface) = pulse_and_plan(&receipt, &run, &initial);

    let first = initial
        .claim(
            &pulse,
            &plan,
            &run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [0x81; 32],
            digest(0x82),
        )
        .expect("first adapter result");
    let second = initial
        .claim(
            &pulse,
            &plan,
            &run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [0x83; 32],
            digest(0x84),
        )
        .expect("second adapter result");

    assert_eq!(first.snapshot().generation(), second.snapshot().generation());
    assert_eq!(first.snapshot().snapshot_id(), second.snapshot().snapshot_id());
    assert_ne!(first.transition().transition_id(), second.transition().transition_id());
    assert_eq!(
        first.snapshot().assignment(),
        TaskProjectionAssignment::Assigned(run.run_id())
    );
    assert_eq!(
        first
            .snapshot()
            .lease()
            .expect("claim establishes a lease")
            .reserved_surfaces(),
        &[surface]
    );
}

#[test]
fn stale_generation_refuses_before_state_change() {
    let receipt = authority_receipt();
    let run = run(&receipt, 7);
    let basis = TaskProjectionSnapshot::observed(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
    )
    .expect("basis state");
    let (pulse, plan, _) = pulse_and_plan(&receipt, &run, &basis);
    let stale = TaskProjectionSnapshot::observed(
        basis.task_id(),
        [0x45; 32],
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
    )
    .expect("another generation");

    assert_eq!(
        stale
            .claim(
                &pulse,
                &plan,
                &run,
                LogicalTime::new(25),
                LogicalTime::new(80),
                [0x81; 32],
                digest(0x82),
            )
            .expect_err("stale predecessor fails closed"),
        TaskProjectionAdapterRefusal::PulseGenerationMismatch {
            snapshot: [0x45; 32],
            pulse: TASK_BASIS,
        }
    );
}

#[test]
fn release_after_expiry_remains_available_for_cleanup() {
    let fixture = claimed_fixture();
    let released = fixture
        .claimed_snapshot
        .release(
            &fixture.claim_receipt,
            fixture.active_claim,
            &fixture.source_run,
            TaskReleaseDisposition::RequireRework,
            LogicalTime::new(81),
            [0x85; 32],
            digest(0x86),
        )
        .expect("expiry cannot prevent cleanup");

    assert_eq!(released.snapshot().phase(), TaskPhase::Rework);
    assert_eq!(
        released.snapshot().assignment(),
        TaskProjectionAssignment::Unassigned
    );
    assert!(released.snapshot().lease().is_none());
}

#[test]
fn transfer_releases_source_and_requires_successor_reclaim() {
    let fixture = claimed_fixture();
    let successor = run(&fixture.receipt, 8);
    let transferred = fixture
        .claimed_snapshot
        .transfer(
            &fixture.claim_receipt,
            fixture.active_claim,
            &fixture.source_run,
            &successor,
            LogicalTime::new(40),
            [0x87; 32],
            digest(0x88),
        )
        .expect("atomic assignment transfer");

    assert_eq!(
        transferred.snapshot().assignment(),
        TaskProjectionAssignment::Assigned(successor.run_id())
    );
    assert!(transferred.snapshot().lease().is_none());

    let (pulse, plan, _) = pulse_and_plan(&fixture.receipt, &successor, transferred.snapshot());
    let reclaimed = transferred
        .snapshot()
        .claim(
            &pulse,
            &plan,
            &successor,
            LogicalTime::new(45),
            LogicalTime::new(90),
            [0x89; 32],
            digest(0x8a),
        )
        .expect("successor establishes a fresh lease");
    assert!(reclaimed.snapshot().lease().is_some());
}
