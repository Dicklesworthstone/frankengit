#![forbid(unsafe_code)]
//! Public-path tests for exact authenticated-read task provenance.

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityBoundTaskProjectionSnapshot, AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun,
    LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet,
    PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RunId, SituationComponent,
    SituationComponentKind, SituationOmissionReason, TaskCoordinationRefusal, TaskPhase,
    TaskProjectionAssignment, WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem,
    WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
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

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed-width RCR digest"),
    )
}

fn authority_receipts() -> (AuthorityReadReceipt, AuthorityReadReceipt) {
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(801));
    let key = HeadKey::new(b"task-authority-binding-head".to_vec()).expect("bounded head key");
    let read = match initialize_repository(&store, &key, &head).expect("initialize") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("authenticate receipt");
    let first = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("first complete receipt");
    let second = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(11),
        [0x52; 32],
    )
    .expect("second complete receipt");
    (first, second)
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
        ResourceVector::from_grades(&[(Grade::Bytes, 16_384), (Grade::CpuMicros, 20_000)]),
        LogicalTime::new(100),
    )
    .expect("authenticated run opens")
}

fn situation(receipt: &AuthorityReadReceipt, run: &IntentRun) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), TASK_GENERATION)
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
    .expect("complete authority-bound situation")
}

fn pulse_and_plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    task_id: WorkTaskId,
) -> (AgentControlPulse, AgentChangePlan) {
    let situation = situation(receipt, run);
    let item = WorkItem::new(
        task_id,
        TASK_GENERATION,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
    );
    let frontier =
        WorkFrontier::build_action_scoped(&situation, vec![item]).expect("task is eligible");
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
    let plan = AgentChangePlan::build(&pulse, run, &[], spec).expect("complete change plan");
    (pulse, plan)
}

#[test]
fn same_task_state_does_not_make_authority_reads_interchangeable() {
    let (first_receipt, second_receipt) = authority_receipts();
    assert_eq!(
        first_receipt.repository_id(),
        second_receipt.repository_id()
    );
    assert_eq!(
        first_receipt.authority_head_id(),
        second_receipt.authority_head_id()
    );
    assert_ne!(first_receipt, second_receipt);

    let task_id = WorkTaskId::from_bytes([0x31; 32]);
    let first_snapshot = AuthorityBoundTaskProjectionSnapshot::observed(
        &first_receipt,
        task_id,
        TASK_GENERATION,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("first task observation");
    let second_snapshot = AuthorityBoundTaskProjectionSnapshot::observed(
        &second_receipt,
        task_id,
        TASK_GENERATION,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("second task observation");

    assert_eq!(first_snapshot.snapshot_id(), second_snapshot.snapshot_id());
    assert_ne!(
        first_snapshot.authority_read_receipt(),
        second_snapshot.authority_read_receipt()
    );

    let second_run = run(&second_receipt);
    let (pulse, plan) = pulse_and_plan(&second_receipt, &second_run, task_id);
    assert_eq!(
        first_snapshot
            .claim(
                &pulse,
                &plan,
                &second_run,
                LogicalTime::new(25),
                LogicalTime::new(80),
                [0x71; 32],
                digest(0x72),
            )
            .expect_err("same repository/head cannot substitute an authenticated read"),
        TaskCoordinationRefusal::RunAuthorityMismatch
    );
}
