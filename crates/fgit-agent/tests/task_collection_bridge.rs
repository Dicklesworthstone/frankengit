#![forbid(unsafe_code)]
//! Public-path tests for collection-to-single-task conversion and recovery.

use fgit_agent::{
    AgentChangePlan, AgentChangePlanId, AgentChangePlanSpec, AgentControlPulse,
    AgentSituationReceipt, AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun,
    LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId,
    PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RunId,
    SituationComponent, SituationComponentKind, SituationOmissionReason,
    TaskClaimProjection, TaskClaimReceipt, TaskClaimRecoveryRefusal,
    TaskCollectionBridgeRefusal, TaskLeaseHistoryObservation, TaskProjectionAssignment,
    TaskProjectionCollectionObservation, TaskProjectionCollectionRequest,
    TaskProjectionCollector, TaskProjectionGeneration, TaskProjectionRow, TaskPhase,
    WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs,
    WorkTaskId, activate_reconstructed_task_claim, collect_task_projection,
    collected_unclaimed_task, reconstruct_collected_task_lease,
};
use fgit_authority::{
    AuthenticatedHead, AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore,
    StoreInstanceId, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{IdentityDomain, NativeObjectIdentity};
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

const GENERATION: [u8; 32] = [0x44; 32];
const PREVIOUS_GENERATION: [u8; 32] = [0x43; 32];

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

fn authenticated_head() -> AuthenticatedHead {
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(951));
    let key = HeadKey::new(b"task-collection-bridge-test".to_vec()).expect("bounded head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt")
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

struct Collector {
    row: TaskProjectionRow,
}

impl TaskProjectionCollector for Collector {
    fn adapter_identity(&self) -> [u8; 32] {
        [0x81; 32]
    }

    fn collect(
        &mut self,
        request: &TaskProjectionCollectionRequest,
    ) -> Result<
        TaskProjectionCollectionObservation,
        fgit_agent::TaskProjectionCollectionAdapterRefusal,
    > {
        Ok(TaskProjectionCollectionObservation::new(
            request.request_id(),
            TaskProjectionGeneration::try_from_bytes(GENERATION)
                .expect("nonzero generation"),
            LogicalTime::new(21),
            vec![self.row.clone()],
            [0x81; 32],
            digest(0x91),
        ))
    }
}

fn exact_read() -> AuthorityReadReceipt {
    AuthorityReadReceipt::from_authenticated_head(
        &authenticated_head(),
        LogicalTime::new(10),
        [0x71; 32],
    )
    .expect("exact authenticated read")
}

fn collect_row(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    row: TaskProjectionRow,
) -> fgit_agent::TaskProjectionCollectionReceipt {
    let mut collector = Collector { row };
    collect_task_projection(
        &mut collector,
        receipt,
        run,
        LogicalTime::new(20),
    )
    .expect("current task collection")
}

fn situation(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    generation: [u8; 32],
    observed_at: LogicalTime,
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
        observed_at,
        components,
    )
    .expect("complete task-bound situation")
}

fn real_plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    task_id: WorkTaskId,
    surface: PlanSurface,
) -> (AgentControlPulse, AgentChangePlan) {
    let planning = situation(
        receipt,
        run,
        PREVIOUS_GENERATION,
        LogicalTime::new(14),
    );
    let item = WorkItem::new(
        task_id,
        PREVIOUS_GENERATION,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
    );
    let frontier = WorkFrontier::build_action_scoped(&planning, vec![item])
        .expect("task is eligible");
    let pulse = AgentControlPulse::build(&planning, &frontier, Some(run))
        .expect("live run makes an actionable pulse");
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
            policy_root: digest(0x61),
        },
    )
    .with_surfaces(vec![surface], vec![surface])
    .with_checkpoints(vec![PlanCheckpoint::new(
        PlanCheckpointId::from_bytes([0x62; 32]),
        PlanCheckpointPurpose::ImplementSlice,
        digest(0x63),
        digest(0x64),
    )])
    .with_evidence_plan(vec![PlanEvidenceRequirement::new(
        PlanRequirementId::from_bytes([0x65; 32]),
        EvidenceClass::Executed,
        digest(0x66),
        false,
    )]);
    let plan = AgentChangePlan::build(&pulse, run, &[], spec)
        .expect("complete pre-claim change plan");
    (pulse, plan)
}

fn real_plan_id(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    task_id: WorkTaskId,
    surface: PlanSurface,
) -> AgentChangePlanId {
    real_plan(receipt, run, task_id, surface).1.plan_id()
}

#[test]
fn collected_unassigned_row_becomes_exact_claim_basis() {
    let receipt = exact_read();
    let run = run(&receipt);
    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let row = TaskProjectionRow::unclaimed(
        task_id,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        0,
        None,
        true,
        WorkConflict::Clear,
    )
    .expect("unassigned row");
    let collection = collect_row(&receipt, &run, row);

    let claim_basis = collected_unclaimed_task(&collection, &receipt, task_id)
        .expect("exact read and unclaimed row make a claim basis");
    assert_eq!(claim_basis.repository_id(), receipt.repository_id());
    assert_eq!(claim_basis.task_id(), task_id);
    assert_eq!(claim_basis.generation(), &GENERATION);
    assert_eq!(claim_basis.assignment(), TaskProjectionAssignment::Unassigned);
    assert_eq!(claim_basis.observed_at(), LogicalTime::new(21));
}

#[test]
fn same_head_later_read_is_not_interchangeable_for_mutation() {
    let authenticated = authenticated_head();
    let first = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x71; 32],
    )
    .expect("first exact read");
    let later = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(11),
        [0x71; 32],
    )
    .expect("later exact read of same head");
    let run = run(&first);
    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let row = TaskProjectionRow::unclaimed(
        task_id,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        0,
        None,
        true,
        WorkConflict::Clear,
    )
    .expect("unassigned row");
    let collection = collect_row(&first, &run, row);

    assert_eq!(
        collected_unclaimed_task(&collection, &later, task_id)
            .expect_err("another exact read event cannot become the mutation basis"),
        TaskCollectionBridgeRefusal::AuthorityMismatch
    );
}

#[test]
fn missing_task_fails_without_inventing_state() {
    let receipt = exact_read();
    let run = run(&receipt);
    let present = WorkTaskId::from_bytes([0x41; 32]);
    let missing = WorkTaskId::from_bytes([0x42; 32]);
    let row = TaskProjectionRow::unclaimed(
        present,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        0,
        None,
        true,
        WorkConflict::Clear,
    )
    .expect("unassigned row");
    let collection = collect_row(&receipt, &run, row);

    assert_eq!(
        collected_unclaimed_task(&collection, &receipt, missing)
            .expect_err("missing task cannot become a single-task snapshot"),
        TaskCollectionBridgeRefusal::TaskMissing { task_id: missing }
    );
}

#[test]
fn collected_claimed_row_reconstructs_exact_lease_deterministically() {
    let receipt = exact_read();
    let run = run(&receipt);
    let run_commitment = run.commitment().expect("complete claimant identity");
    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x72));
    let plan_id = real_plan_id(&receipt, &run, task_id, surface);
    let row = TaskProjectionRow::claimed(
        task_id,
        TaskPhase::InProgress,
        WorkRankingInputs::new(1, 2, 3),
        0,
        run.run_id(),
        None,
        true,
        plan_id,
        LogicalTime::new(15),
        LogicalTime::new(80),
        vec![surface],
    )
    .expect("claimed collection row");
    let collection = collect_row(&receipt, &run, row);
    let history = TaskLeaseHistoryObservation::new(
        collection.receipt_id(),
        task_id,
        collection.snapshot().generation(),
        run_commitment,
        PREVIOUS_GENERATION,
        LogicalTime::new(15),
        [0x82; 32],
        digest(0x92),
    );

    assert_eq!(
        collected_unclaimed_task(&collection, &receipt, task_id)
            .expect_err("claimed row cannot silently become an unclaimed basis"),
        TaskCollectionBridgeRefusal::LeaseReconstructionRequired { task_id }
    );

    let first = reconstruct_collected_task_lease(
        &collection,
        &receipt,
        task_id,
        history.clone(),
    )
    .expect("complete durable history reconstructs the lease");
    let second = reconstruct_collected_task_lease(&collection, &receipt, task_id, history)
        .expect("identical history reconstruction is deterministic");
    assert_eq!(first.receipt_id(), second.receipt_id());
    assert_eq!(first.snapshot().task_id(), task_id);
    assert_eq!(first.run_commitment(), run_commitment);
    assert_eq!(
        first.snapshot().assignment(),
        TaskProjectionAssignment::assigned(run.run_id(), run_commitment)
    );
    let lease = first.snapshot().lease().expect("active lease reconstructed");
    assert_eq!(lease.plan_id(), plan_id);
    assert_eq!(lease.assignee(), run.run_id());
    assert_eq!(lease.run_commitment(), run_commitment);
    assert_eq!(lease.previous_generation(), &PREVIOUS_GENERATION);
    assert_eq!(lease.claimed_generation(), &GENERATION);
    assert_eq!(lease.reserved_surfaces(), &[surface]);
    assert_eq!(lease.claimed_at(), LogicalTime::new(15));
    assert_eq!(lease.expires_at(), LogicalTime::new(80));
    assert_eq!(first.adapter_identity(), [0x82; 32]);
    assert_eq!(first.evidence_root(), digest(0x92));
    assert_ne!(first.receipt_id().as_bytes(), &[0; 32]);
}

#[test]
fn lease_history_cannot_be_replayed_across_generation() {
    let receipt = exact_read();
    let run = run(&receipt);
    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x72));
    let plan_id = real_plan_id(&receipt, &run, task_id, surface);
    let row = TaskProjectionRow::claimed(
        task_id,
        TaskPhase::InProgress,
        WorkRankingInputs::new(1, 2, 3),
        0,
        run.run_id(),
        None,
        true,
        plan_id,
        LogicalTime::new(15),
        LogicalTime::new(80),
        vec![surface],
    )
    .expect("claimed collection row");
    let collection = collect_row(&receipt, &run, row);
    let observed = TaskProjectionGeneration::try_from_bytes([0x45; 32])
        .expect("different nonzero generation");
    let history = TaskLeaseHistoryObservation::new(
        collection.receipt_id(),
        task_id,
        observed,
        run.commitment().expect("complete claimant identity"),
        PREVIOUS_GENERATION,
        LogicalTime::new(15),
        [0x82; 32],
        digest(0x92),
    );

    assert_eq!(
        reconstruct_collected_task_lease(&collection, &receipt, task_id, history)
            .expect_err("history from another generation must fail closed"),
        TaskCollectionBridgeRefusal::HistoryGenerationMismatch {
            expected: collection.snapshot().generation(),
            observed,
        }
    );
}

#[test]
fn lease_history_cannot_postdate_the_collection_that_already_reflects_it() {
    let receipt = exact_read();
    let run = run(&receipt);
    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x72));
    let plan_id = real_plan_id(&receipt, &run, task_id, surface);
    let row = TaskProjectionRow::claimed(
        task_id,
        TaskPhase::InProgress,
        WorkRankingInputs::new(1, 2, 3),
        0,
        run.run_id(),
        None,
        true,
        plan_id,
        LogicalTime::new(15),
        LogicalTime::new(80),
        vec![surface],
    )
    .expect("claimed collection row");
    let collection = collect_row(&receipt, &run, row);
    let history = TaskLeaseHistoryObservation::new(
        collection.receipt_id(),
        task_id,
        collection.snapshot().generation(),
        run.commitment().expect("complete claimant identity"),
        PREVIOUS_GENERATION,
        LogicalTime::new(22),
        [0x82; 32],
        digest(0x92),
    );

    assert_eq!(
        reconstruct_collected_task_lease(&collection, &receipt, task_id, history)
            .expect_err("claim history cannot begin after the observed claimed row"),
        TaskCollectionBridgeRefusal::ObservationBeforeClaim {
            claimed_at: LogicalTime::new(22),
            observed_at: LogicalTime::new(21),
        }
    );
}

#[test]
fn reconstructed_lease_recovers_active_claim_only_on_the_exact_read_event() {
    let authenticated = authenticated_head();
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x71; 32],
    )
    .expect("claim authority read");
    let later = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(11),
        [0x71; 32],
    )
    .expect("later read of the same authority head");
    let run = run(&receipt);
    let run_commitment = run.commitment().expect("complete claimant identity");
    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x72));
    let (pulse, plan) = real_plan(&receipt, &run, task_id, surface);
    let row = TaskProjectionRow::claimed(
        task_id,
        TaskPhase::InProgress,
        WorkRankingInputs::new(1, 2, 3),
        0,
        run.run_id(),
        None,
        true,
        plan.plan_id(),
        LogicalTime::new(15),
        LogicalTime::new(80),
        vec![surface],
    )
    .expect("claimed collection row");
    let collection = collect_row(&receipt, &run, row);
    let reconstruction = reconstruct_collected_task_lease(
        &collection,
        &receipt,
        task_id,
        TaskLeaseHistoryObservation::new(
            collection.receipt_id(),
            task_id,
            collection.snapshot().generation(),
            run_commitment,
            PREVIOUS_GENERATION,
            LogicalTime::new(15),
            [0x82; 32],
            digest(0x92),
        ),
    )
    .expect("durable lease reconstruction");
    let claim = TaskClaimReceipt::admit(
        &pulse,
        &plan,
        &run,
        TaskClaimProjection::new(
            task_id,
            plan.plan_id(),
            run.run_id(),
            PREVIOUS_GENERATION,
            GENERATION,
            vec![surface],
            LogicalTime::new(15),
            LogicalTime::new(80),
            [0x83; 32],
            digest(0x93),
        ),
    )
    .expect("original validated claim receipt");
    let refreshed = situation(&receipt, &run, GENERATION, LogicalTime::new(21));

    let recovered = activate_reconstructed_task_claim(
        &reconstruction,
        &claim,
        &refreshed,
        &run,
    )
    .expect("lease, claim, refresh, complete run, and exact read all agree");
    assert_eq!(recovered.lease_reconstruction_id(), reconstruction.receipt_id());
    assert_eq!(recovered.claim_id(), claim.claim_id());
    assert_eq!(recovered.active_claim().task_id(), task_id);
    assert_eq!(recovered.active_claim().plan_id(), plan.plan_id());
    assert_eq!(recovered.active_claim().assignee(), run.run_id());
    assert_eq!(recovered.active_claim().run_commitment(), run_commitment);
    assert_ne!(recovered.recovery_id().as_bytes(), &[0; 32]);

    let later_run = run(&later);
    let later_refreshed = situation(
        &later,
        &later_run,
        GENERATION,
        LogicalTime::new(21),
    );
    assert_eq!(
        activate_reconstructed_task_claim(
            &reconstruction,
            &claim,
            &later_refreshed,
            &later_run,
        )
        .expect_err("same head and RunId cannot substitute another exact read"),
        TaskClaimRecoveryRefusal::RunCommitmentMismatch {
            expected: run_commitment,
            claim: run_commitment,
            supplied: later_run.commitment().expect("later complete run identity"),
            refreshed: later_refreshed.intent_run_commitment(),
        }
    );
}

#[test]
fn same_id_changed_run_history_cannot_recover_the_original_claim() {
    let receipt = exact_read();
    let run = run(&receipt);
    let altered = IntentRun::new_authenticated(
        run.run_id(),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 1),
        LogicalTime::new(90),
    )
    .expect("same-ID altered run remains structurally valid");
    let original_commitment = run.commitment().expect("original complete run identity");
    let altered_commitment = altered.commitment().expect("altered complete run identity");
    assert_ne!(original_commitment, altered_commitment);

    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x72));
    let (pulse, plan) = real_plan(&receipt, &run, task_id, surface);
    let row = TaskProjectionRow::claimed(
        task_id,
        TaskPhase::InProgress,
        WorkRankingInputs::new(1, 2, 3),
        0,
        run.run_id(),
        None,
        true,
        plan.plan_id(),
        LogicalTime::new(15),
        LogicalTime::new(80),
        vec![surface],
    )
    .expect("claimed collection row");
    let collection = collect_row(&receipt, &run, row);
    let reconstruction = reconstruct_collected_task_lease(
        &collection,
        &receipt,
        task_id,
        TaskLeaseHistoryObservation::new(
            collection.receipt_id(),
            task_id,
            collection.snapshot().generation(),
            altered_commitment,
            PREVIOUS_GENERATION,
            LogicalTime::new(15),
            [0x82; 32],
            digest(0x92),
        ),
    )
    .expect("row alone cannot disprove the same-ID history response");
    let claim = TaskClaimReceipt::admit(
        &pulse,
        &plan,
        &run,
        TaskClaimProjection::new(
            task_id,
            plan.plan_id(),
            run.run_id(),
            PREVIOUS_GENERATION,
            GENERATION,
            vec![surface],
            LogicalTime::new(15),
            LogicalTime::new(80),
            [0x83; 32],
            digest(0x93),
        ),
    )
    .expect("original validated claim receipt");
    let refreshed = situation(&receipt, &run, GENERATION, LogicalTime::new(21));

    assert_eq!(
        activate_reconstructed_task_claim(
            &reconstruction,
            &claim,
            &refreshed,
            &run,
        )
        .expect_err("same-ID history cannot substitute another complete claimant"),
        TaskClaimRecoveryRefusal::RunCommitmentMismatch {
            expected: altered_commitment,
            claim: original_commitment,
            supplied: original_commitment,
            refreshed: Some(original_commitment),
        }
    );
}
