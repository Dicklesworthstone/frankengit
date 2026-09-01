#![forbid(unsafe_code)]
//! Public-path tests for deterministic task-projection transitions.

use fgit_agent::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse,
    AgentSituationReceipt, AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun,
    LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet,
    PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RunId, SituationComponent,
    SituationComponentKind, SituationOmissionReason, TaskClaimReceipt,
    TaskProjectionAdapterRefusal, TaskProjectionAssignment, TaskProjectionSnapshot,
    TaskReleaseDisposition, TaskPhase, WorkConflict, WorkEligibilityInputs, WorkFrontier,
    WorkItem, WorkRankingInputs, WorkTaskId,
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

const TASK_BASIS: [u8; 32] = [0x44; 32];

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
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width RCR digest"),
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
    let expected = authority_head_identity(&head).expect("head identity");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let key = HeadKey::new(format!("task-adapter-test-{store_id}").into_bytes())
        .expect("bounded head key");
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
    .expect("complete authority-bound situation")
}

fn pulse_and_plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    snapshot: &TaskProjectionSnapshot,
) -> (AgentControlPulse, AgentChangePlan, PlanSurface) {
    let situation = situation(receipt, run, *snapshot.generation(), 20);
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
    let frontier = WorkFrontier::build_action_scoped(&situation, vec![item])
        .expect("task is eligible for its assigned run");
    let pulse = AgentControlPulse::build(&situation, &frontier, Some(run))
        .expect("live run makes an actionable pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let spec = AgentChangePlanSpec::new(
        digest(0x60),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ]),
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
    let plan = AgentChangePlan::build(&pulse, run, &[], spec)
        .expect("complete change plan");
    (pulse, plan, surface)
}

struct ClaimedFixture {
    receipt: AuthorityReadReceipt,
    source_run: IntentRun,
    claimed_snapshot: TaskProjectionSnapshot,
    claim_receipt: TaskClaimReceipt,
    active_claim: ActiveTaskClaim,
    surface: PlanSurface,
}

fn claimed_fixture() -> ClaimedFixture {
    let receipt = authority_receipt(301, 0x22);
    let source_run = run(&receipt, 7);
    let initial = TaskProjectionSnapshot::observed(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
    )
    .expect("valid initial snapshot");
    let (pulse, plan, surface) = pulse_and_plan(&receipt, &source_run, &initial);
    let application = initial
        .claim(
            &pulse,
            &plan,
            &source_run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [0x71; 32],
            digest(0x72),
        )
        .expect("claim transition");
    let claim_receipt = TaskClaimReceipt::admit(
        &pulse,
        &plan,
        &source_run,
        application.projection().clone(),
    )
    .expect("claim projection is accepted by the existing protocol");
    let activation = situation(
        &receipt,
        &source_run,
        *application.snapshot().generation(),
        30,
    );
    let active_claim = claim_receipt
        .activate(&activation, &source_run)
        .expect("post-claim generation activates the task");
    ClaimedFixture {
        receipt,
        source_run,
        claimed_snapshot: application.snapshot().clone(),
        claim_receipt,
        active_claim,
        surface,
    }
}

#[test]
fn claim_generation_and_transition_identity_are_deterministic() {
    let receipt = authority_receipt(302, 0x23);
    let run = run(&receipt, 7);
    let snapshot = TaskProjectionSnapshot::observed(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
    )
    .expect("valid initial snapshot");
    let (pulse, plan, surface) = pulse_and_plan(&receipt, &run, &snapshot);

    let first = snapshot
        .claim(
            &pulse,
            &plan,
            &run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [0x71; 32],
            digest(0x72),
        )
        .expect("claim transition");
    let second = snapshot
        .claim(
            &pulse,
            &plan,
            &run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [0x71; 32],
            digest(0x72),
        )
        .expect("same claim transition");

    assert_eq!(first.snapshot().snapshot_id(), second.snapshot().snapshot_id());
    assert_eq!(first.transition().transition_id(), second.transition().transition_id());
    assert_ne!(first.snapshot().generation(), &TASK_BASIS);
    assert_eq!(first.snapshot().phase(), TaskPhase::InProgress);
    assert_eq!(
        first.snapshot().assignment(),
        TaskProjectionAssignment::Assigned(run.run_id())
    );
    let lease = first.snapshot().lease().expect("claim establishes a lease");
    assert_eq!(lease.reserved_surfaces(), &[surface]);
    assert_eq!(first.projection().reserved_surfaces(), &[surface]);
}

#[test]
fn stale_snapshot_cannot_apply_a_pulse_from_another_generation() {
    let receipt = authority_receipt(303, 0x24);
    let run = run(&receipt, 7);
    let basis = TaskProjectionSnapshot::observed(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
    )
    .expect("basis snapshot");
    let (pulse, plan, _) = pulse_and_plan(&receipt, &run, &basis);
    let stale = TaskProjectionSnapshot::observed(
        WorkTaskId::from_bytes([0x31; 32]),
        [0x45; 32],
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
    )
    .expect("different observed generation");

    assert_eq!(
        stale
            .claim(
                &pulse,
                &plan,
                &run,
                LogicalTime::new(25),
                LogicalTime::new(80),
                [0x71; 32],
                digest(0x72),
            )
            .expect_err("stale predecessor must fail closed"),
        TaskProjectionAdapterRefusal::PulseGenerationMismatch {
            snapshot: [0x45; 32],
            pulse: TASK_BASIS,
        }
    );
}

#[test]
fn release_is_available_after_expiry_and_returns_explicit_rework() {
    let fixture = claimed_fixture();
    let released = fixture
        .claimed_snapshot
        .release(
            &fixture.claim_receipt,
            fixture.active_claim,
            &fixture.source_run,
            TaskReleaseDisposition::RequireRework,
            LogicalTime::new(81),
            [0x73; 32],
            digest(0x74),
        )
        .expect("expiry prevents work, not cleanup");

    assert_eq!(released.snapshot().phase(), TaskPhase::Rework);
    assert_eq!(
        released.snapshot().assignment(),
        TaskProjectionAssignment::Unassigned
    );
    assert!(released.snapshot().lease().is_none());
    assert_eq!(
        released.projection().outcome(),
        fgit_agent::TaskClaimCancellationOutcome::Released
    );
    assert_ne!(
        released.transition().previous_generation(),
        released.transition().resulting_generation()
    );
}

#[test]
fn transfer_releases_source_lease_and_successor_claims_a_new_plan() {
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
            [0x75; 32],
            digest(0x76),
        )
        .expect("atomic assignment transfer");

    assert_eq!(
        transferred.snapshot().assignment(),
        TaskProjectionAssignment::Assigned(successor.run_id())
    );
    assert!(transferred.snapshot().lease().is_none());
    assert_eq!(
        transferred.projection().outcome(),
        fgit_agent::TaskClaimCancellationOutcome::Transferred {
            successor_run_id: successor.run_id(),
        }
    );

    let (successor_pulse, successor_plan, _) =
        pulse_and_plan(&fixture.receipt, &successor, transferred.snapshot());
    let successor_claim = transferred
        .snapshot()
        .claim(
            &successor_pulse,
            &successor_plan,
            &successor,
            LogicalTime::new(45),
            LogicalTime::new(90),
            [0x77; 32],
            digest(0x78),
        )
        .expect("successor opens a fresh lease under a fresh plan");

    assert_eq!(
        successor_claim.snapshot().assignment(),
        TaskProjectionAssignment::Assigned(successor.run_id())
    );
    assert!(successor_claim.snapshot().lease().is_some());
    assert_ne!(
        successor_claim.transition().previous_generation(),
        successor_claim.transition().resulting_generation()
    );
}

#[test]
fn transfer_across_authority_receipts_is_refused() {
    let fixture = claimed_fixture();
    let foreign_receipt = authority_receipt(304, 0x25);
    let foreign_successor = run(&foreign_receipt, 8);

    assert_eq!(
        fixture
            .claimed_snapshot
            .transfer(
                &fixture.claim_receipt,
                fixture.active_claim,
                &fixture.source_run,
                &foreign_successor,
                LogicalTime::new(40),
                [0x79; 32],
                digest(0x7a),
            )
            .expect_err("task assignment cannot cross repository authority"),
        TaskProjectionAdapterRefusal::SuccessorAuthorityMismatch
    );
}
