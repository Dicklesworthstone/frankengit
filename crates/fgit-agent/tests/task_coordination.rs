#![forbid(unsafe_code)]
//! Public-path tests for repository- and time-bound task coordination.

use fgit_agent::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse,
    AgentSituationReceipt, AuthorityBoundTaskProjectionSnapshot, AuthorityReadReceipt,
    ClassSet, EvidenceClass, IntentRun, LogicalTime, OperationClass, PlanApproval,
    PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose, PlanEvidenceRequirement,
    PlanRequirementId, PlanStopConditionSet, PlanSurface, PlanSurfaceKind,
    RejectedShortcutSet, RunId, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskClaimReceipt, TaskCoordinationRefusal,
    TaskProjectionAssignment, TaskReleaseDisposition, TaskPhase, WorkConflict,
    WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
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
    let key = HeadKey::new(format!("task-coordination-test-{store_id}").into_bytes())
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
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
    observed_at: u64,
) -> (AgentControlPulse, AgentChangePlan, PlanSurface) {
    let situation = situation(receipt, run, *snapshot.generation(), observed_at);
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
    snapshot: AuthorityBoundTaskProjectionSnapshot,
    claim_receipt: TaskClaimReceipt,
    active_claim: ActiveTaskClaim,
}

fn claimed_fixture() -> ClaimedFixture {
    let receipt = authority_receipt(401, 0x22);
    let source_run = run(&receipt, 7);
    let initial = AuthorityBoundTaskProjectionSnapshot::observed(
        &receipt,
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("valid repository-scoped snapshot");
    let (pulse, plan, _) = pulse_and_plan(&receipt, &source_run, &initial, 20);
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
        .expect("repository-scoped claim");
    let claim_receipt = TaskClaimReceipt::admit(
        &pulse,
        &plan,
        &source_run,
        application.projection().clone(),
    )
    .expect("existing claim protocol accepts the scoped projection");
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
        snapshot: application.snapshot().clone(),
        claim_receipt,
        active_claim,
    }
}

#[test]
fn scoped_claim_identity_is_deterministic_and_protocol_compatible() {
    let receipt = authority_receipt(402, 0x23);
    let run = run(&receipt, 7);
    let snapshot = AuthorityBoundTaskProjectionSnapshot::observed(
        &receipt,
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("valid repository-scoped snapshot");
    let (pulse, plan, _) = pulse_and_plan(&receipt, &run, &snapshot, 20);

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
        .expect("scoped claim");
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
        .expect("identical scoped claim");

    assert_eq!(first.snapshot().snapshot_id(), second.snapshot().snapshot_id());
    assert_eq!(first.transition().transition_id(), second.transition().transition_id());
    assert_eq!(first.snapshot().repository_id(), receipt.repository_id());
    assert_eq!(first.snapshot().observed_at(), LogicalTime::new(25));
    assert_ne!(first.snapshot().snapshot_id().as_bytes(), &[0; 32]);

    TaskClaimReceipt::admit(&pulse, &plan, &run, first.projection().clone())
        .expect("facade output remains compatible with the claim protocol");
}

#[test]
fn pulse_observation_cannot_move_behind_the_task_snapshot() {
    let receipt = authority_receipt(403, 0x24);
    let run = run(&receipt, 7);
    let snapshot = AuthorityBoundTaskProjectionSnapshot::observed(
        &receipt,
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(30),
    )
    .expect("snapshot observed at time 30");
    let (pulse, plan, _) = pulse_and_plan(&receipt, &run, &snapshot, 20);

    assert_eq!(
        snapshot
            .claim(
                &pulse,
                &plan,
                &run,
                LogicalTime::new(35),
                LogicalTime::new(80),
                [0x71; 32],
                digest(0x72),
            )
            .expect_err("task projection observation cannot roll backward"),
        TaskCoordinationRefusal::ObservationRollback {
            snapshot_observed_at: LogicalTime::new(30),
            proposed_observed_at: LogicalTime::new(20),
        }
    );
}

#[test]
fn claim_from_another_repository_is_refused_before_projection() {
    let receipt = authority_receipt(404, 0x25);
    let foreign = authority_receipt(405, 0x26);
    let local_run = run(&receipt, 7);
    let foreign_run = run(&foreign, 7);
    let snapshot = AuthorityBoundTaskProjectionSnapshot::observed(
        &receipt,
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("local snapshot");
    let (pulse, plan, _) = pulse_and_plan(&foreign, &foreign_run, &snapshot, 20);
    let _ = local_run;

    assert_eq!(
        snapshot
            .claim(
                &pulse,
                &plan,
                &foreign_run,
                LogicalTime::new(25),
                LogicalTime::new(80),
                [0x71; 32],
                digest(0x72),
            )
            .expect_err("cross-repository task mutation must fail closed"),
        TaskCoordinationRefusal::RunRepositoryMismatch {
            expected: receipt.repository_id(),
            observed: foreign.repository_id(),
        }
    );
}

#[test]
fn scoped_release_advances_time_and_repository_identity() {
    let fixture = claimed_fixture();
    let released = fixture
        .snapshot
        .release(
            &fixture.claim_receipt,
            fixture.active_claim,
            &fixture.source_run,
            TaskReleaseDisposition::ReturnToOpen,
            LogicalTime::new(40),
            [0x73; 32],
            digest(0x74),
        )
        .expect("repository-scoped release");

    assert_eq!(released.snapshot().repository_id(), fixture.receipt.repository_id());
    assert_eq!(released.snapshot().observed_at(), LogicalTime::new(40));
    assert_eq!(released.snapshot().phase(), TaskPhase::Open);
    assert_eq!(
        released.snapshot().assignment(),
        TaskProjectionAssignment::Unassigned
    );
    assert_eq!(
        released.transition().repository_id(),
        fixture.receipt.repository_id()
    );
}

#[test]
fn successor_transfer_cannot_cross_repository_namespace() {
    let fixture = claimed_fixture();
    let foreign = authority_receipt(406, 0x27);
    let foreign_successor = run(&foreign, 8);

    assert_eq!(
        fixture
            .snapshot
            .transfer(
                &fixture.claim_receipt,
                fixture.active_claim,
                &fixture.source_run,
                &foreign_successor,
                LogicalTime::new(40),
                [0x75; 32],
                digest(0x76),
            )
            .expect_err("successor assignment remains repository-scoped"),
        TaskCoordinationRefusal::RunRepositoryMismatch {
            expected: fixture.receipt.repository_id(),
            observed: foreign.repository_id(),
        }
    );
}
