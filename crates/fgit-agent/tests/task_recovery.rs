#![forbid(unsafe_code)]
//! Public-path tests for persistence-gated restart cleanup.

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityBoundTaskProjectionSnapshot, AuthorityReadReceipt, ClassSet, EvidenceClass,
    IntentRun, LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId,
    PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RecoveredActiveTaskClaim,
    RecoveredTaskReleasePersistenceOutcome, RejectedShortcutSet, RunId,
    SituationComponent, SituationComponentKind, SituationOmissionReason,
    TaskClaimCancellationOutcome, TaskClaimProjection, TaskClaimReceipt,
    TaskLeaseHistoryObservation, TaskLeaseReconstructionReceipt, TaskProjectionAssignment,
    TaskProjectionCollectionObservation, TaskProjectionCollectionReceipt,
    TaskProjectionCollectionRequest, TaskProjectionCollector, TaskProjectionGeneration,
    TaskProjectionMutationEnvelope, TaskProjectionPersistedState, TaskProjectionRow,
    TaskProjectionStore, TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal,
    TaskProjectionStoreKey, TaskProjectionStoreReadRefusal,
    TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal,
    TaskRecoveryPersistenceRefusal, TaskReleaseDisposition, TaskPhase, WorkConflict,
    WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
    activate_reconstructed_task_claim, collect_task_projection,
    persist_recovered_task_release, reconstruct_collected_task_lease,
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

const PREVIOUS_GENERATION: [u8; 32] = [0x43; 32];
const CLAIMED_GENERATION: [u8; 32] = [0x44; 32];
const STORE_ID: [u8; 32] = [0x91; 32];
const RELEASED_AT: LogicalTime = LogicalTime::new(90);
const STORE_READ_AT: LogicalTime = LogicalTime::new(91);

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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(961));
    let key = HeadKey::new(b"task-recovery-test".to_vec()).expect("bounded head key");
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
    .expect("authenticated read")
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
    .expect("complete situation")
}

fn pulse_and_plan(
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
        .expect("actionable pulse");
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
    let plan = AgentChangePlan::build(&pulse, run, &[], spec).expect("complete plan");
    (pulse, plan)
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
            TaskProjectionGeneration::try_from_bytes(CLAIMED_GENERATION)
                .expect("nonzero claimed generation"),
            LogicalTime::new(21),
            vec![self.row.clone()],
            [0x81; 32],
            digest(0x82),
        ))
    }
}

struct RecoveryFixture {
    run: IntentRun,
    claim: TaskClaimReceipt,
    collection: TaskProjectionCollectionReceipt,
    reconstruction: TaskLeaseReconstructionReceipt,
    recovered: RecoveredActiveTaskClaim,
}

fn recovery_fixture(history_profile: u8, history_evidence: u8) -> RecoveryFixture {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let task_id = WorkTaskId::from_bytes([0x41; 32]);
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x72));
    let (pulse, plan) = pulse_and_plan(&receipt, &run, task_id, surface);
    let claim = TaskClaimReceipt::admit(
        &pulse,
        &plan,
        &run,
        TaskClaimProjection::new(
            task_id,
            plan.plan_id(),
            run.run_id(),
            PREVIOUS_GENERATION,
            CLAIMED_GENERATION,
            vec![surface],
            LogicalTime::new(15),
            LogicalTime::new(80),
            [0x83; 32],
            digest(0x84),
        ),
    )
    .expect("original claim receipt");
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
    .expect("claimed current row");
    let mut collector = Collector { row };
    let collection = collect_task_projection(
        &mut collector,
        &receipt,
        &run,
        LogicalTime::new(20),
    )
    .expect("current claimed generation");
    let reconstruction = reconstruct_collected_task_lease(
        &collection,
        &receipt,
        task_id,
        TaskLeaseHistoryObservation::new(
            collection.receipt_id(),
            task_id,
            collection.snapshot().generation(),
            PREVIOUS_GENERATION,
            LogicalTime::new(15),
            [history_profile; 32],
            digest(history_evidence),
        ),
    )
    .expect("lease reconstruction");
    let refreshed = situation(
        &receipt,
        &run,
        CLAIMED_GENERATION,
        LogicalTime::new(21),
    );
    let recovered = activate_reconstructed_task_claim(
        &reconstruction,
        &claim,
        &refreshed,
        &run,
    )
    .expect("active claim recovery");
    RecoveryFixture {
        run,
        claim,
        collection,
        reconstruction,
        recovered,
    }
}

fn reread(
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
    observed_at: LogicalTime,
) -> AuthorityBoundTaskProjectionSnapshot {
    match snapshot.lease() {
        Some(lease) => AuthorityBoundTaskProjectionSnapshot::observed_with_lease(
            snapshot.authority_read_receipt(),
            snapshot.task_id(),
            *snapshot.generation(),
            snapshot.phase(),
            lease.clone(),
            observed_at,
        )
        .expect("valid lease reread"),
        None => AuthorityBoundTaskProjectionSnapshot::observed(
            snapshot.authority_read_receipt(),
            snapshot.task_id(),
            *snapshot.generation(),
            snapshot.phase(),
            snapshot.assignment(),
            observed_at,
        )
        .expect("valid task reread"),
    }
}

#[derive(Clone, Copy)]
enum StoreMode {
    Confirm,
    AmbiguousPredecessor,
}

struct RecoveryStore {
    current: Option<TaskProjectionPersistedState>,
    mode: StoreMode,
    read_calls: usize,
    write_calls: usize,
    flush_calls: usize,
}

impl RecoveryStore {
    fn new(reconstruction: &TaskLeaseReconstructionReceipt, mode: StoreMode) -> Self {
        Self {
            current: Some(TaskProjectionPersistedState::new(
                reread(reconstruction.snapshot(), STORE_READ_AT),
                None,
                None,
                None,
            )),
            mode,
            read_calls: 0,
            write_calls: 0,
            flush_calls: 0,
        }
    }
}

impl TaskProjectionStore for RecoveryStore {
    fn adapter_identity(&self) -> [u8; 32] {
        STORE_ID
    }

    fn read(
        &mut self,
        _key: TaskProjectionStoreKey,
    ) -> Result<Option<TaskProjectionPersistedState>, TaskProjectionStoreReadRefusal> {
        self.read_calls += 1;
        Ok(self.current.clone())
    }

    fn compare_and_replace(
        &mut self,
        envelope: &TaskProjectionMutationEnvelope,
    ) -> Result<TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal> {
        self.write_calls += 1;
        match self.mode {
            StoreMode::Confirm => {
                self.current = Some(TaskProjectionPersistedState::new(
                    reread(
                        envelope.after_snapshot(),
                        LogicalTime::new(envelope.transition_observed_at().value() + 1),
                    ),
                    Some(*envelope.transition_id().as_bytes()),
                    Some(envelope.inner_transition_id()),
                    Some(envelope.evidence_root()),
                ));
                Ok(TaskProjectionStoreWriteOutcome::Applied)
            }
            StoreMode::AmbiguousPredecessor => Ok(TaskProjectionStoreWriteOutcome::Ambiguous {
                probe_root: digest(0xa1),
            }),
        }
    }

    fn flush(
        &mut self,
        _envelope: &TaskProjectionMutationEnvelope,
    ) -> Result<TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal> {
        self.flush_calls += 1;
        Ok(match self.mode {
            StoreMode::Confirm => TaskProjectionStoreFlushOutcome::Flushed,
            StoreMode::AmbiguousPredecessor => TaskProjectionStoreFlushOutcome::NotRequired,
        })
    }
}

#[test]
fn recovered_claim_releases_after_expiry_with_evidence_retained() {
    let fixture = recovery_fixture(0x85, 0x86);
    let mut store = RecoveryStore::new(&fixture.reconstruction, StoreMode::Confirm);
    let outcome = persist_recovered_task_release(
        &mut store,
        &fixture.reconstruction,
        fixture.recovered,
        &fixture.claim,
        &fixture.run,
        TaskReleaseDisposition::RequireRework,
        RELEASED_AT,
        digest(0x92),
    )
    .expect("expired work authority must not block durable cleanup");
    let RecoveredTaskReleasePersistenceOutcome::Persisted(persisted) = outcome else {
        panic!("confirming store must persist recovered release")
    };

    assert_eq!(persisted.recovery_id(), fixture.recovered.recovery_id());
    assert_eq!(
        persisted.lease_reconstruction_id(),
        fixture.reconstruction.receipt_id()
    );
    assert_eq!(persisted.resolution().snapshot().phase(), TaskPhase::Rework);
    assert_eq!(
        persisted.resolution().snapshot().assignment(),
        TaskProjectionAssignment::Unassigned
    );
    assert!(persisted.resolution().snapshot().lease().is_none());
    assert_eq!(
        persisted.resolution().cancellation_projection().outcome(),
        TaskClaimCancellationOutcome::Released
    );
    assert_ne!(persisted.receipt_id().as_bytes(), &[0; 32]);
    assert_eq!(store.read_calls, 2);
    assert_eq!(store.write_calls, 1);
    assert_eq!(store.flush_calls, 1);
}

#[test]
fn another_reconstruction_is_refused_before_store_io() {
    let first = recovery_fixture(0x85, 0x86);
    let alternate = reconstruct_collected_task_lease(
        &first.collection,
        first.reconstruction.snapshot().authority_read_receipt(),
        first.reconstruction.task_id(),
        TaskLeaseHistoryObservation::new(
            first.collection.receipt_id(),
            first.reconstruction.task_id(),
            first.collection.snapshot().generation(),
            PREVIOUS_GENERATION,
            LogicalTime::new(15),
            [0x87; 32],
            digest(0x88),
        ),
    )
    .expect("alternate evidence can describe the same semantic lease");
    assert_ne!(alternate.receipt_id(), first.reconstruction.receipt_id());
    let mut store = RecoveryStore::new(&alternate, StoreMode::Confirm);

    assert_eq!(
        persist_recovered_task_release(
            &mut store,
            &alternate,
            first.recovered,
            &first.claim,
            &first.run,
            TaskReleaseDisposition::ReturnToOpen,
            RELEASED_AT,
            digest(0x92),
        )
        .expect_err("recovery evidence cannot be substituted"),
        TaskRecoveryPersistenceRefusal::LeaseReconstructionMismatch {
            expected: alternate.receipt_id(),
            observed: first.reconstruction.receipt_id(),
        }
    );
    assert_eq!(store.read_calls, 0);
    assert_eq!(store.write_calls, 0);
    assert_eq!(store.flush_calls, 0);
}

#[test]
fn ambiguous_release_retains_recovery_identity_as_debt() {
    let fixture = recovery_fixture(0x85, 0x86);
    let mut store = RecoveryStore::new(
        &fixture.reconstruction,
        StoreMode::AmbiguousPredecessor,
    );
    let outcome = persist_recovered_task_release(
        &mut store,
        &fixture.reconstruction,
        fixture.recovered,
        &fixture.claim,
        &fixture.run,
        TaskReleaseDisposition::ReturnToOpen,
        RELEASED_AT,
        digest(0x92),
    )
    .expect("ambiguous write becomes typed reconciliation debt");

    match outcome {
        RecoveredTaskReleasePersistenceOutcome::NeedsReconciliation {
            recovery_id,
            lease_reconstruction_id,
            ..
        } => {
            assert_eq!(recovery_id, fixture.recovered.recovery_id());
            assert_eq!(lease_reconstruction_id, fixture.reconstruction.receipt_id());
        }
        other => panic!("unexpected recovered cleanup outcome: {other:?}"),
    }
    assert_eq!(store.read_calls, 2);
    assert_eq!(store.write_calls, 1);
    assert_eq!(store.flush_calls, 1);
}
