#![forbid(unsafe_code)]
//! Public-path tests for persistence-gated task claims and resolutions.

use std::collections::VecDeque;

use fgit_agent::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse,
    AgentSituationReceipt, AuthorityBoundTaskClaimApplication,
    AuthorityBoundTaskProjectionSnapshot, AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun,
    LogicalTime, OperationClass, PersistedTaskClaim, PlanApproval, PlanCheckpoint,
    PlanCheckpointId, PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId,
    PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RunId,
    SituationComponent, SituationComponentKind, SituationOmissionReason,
    TaskClaimPersistenceOutcome, TaskClaimRefusal, TaskPersistenceGateRefusal, TaskPhase,
    TaskProjectionAssignment, TaskProjectionMutationEnvelope, TaskProjectionPersistedState,
    TaskProjectionStore, TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal,
    TaskProjectionStoreKey, TaskProjectionStoreReadRefusal, TaskProjectionStoreWriteOutcome,
    TaskProjectionStoreWriteRefusal, TaskReleaseDisposition, TaskResolutionPersistenceOutcome,
    WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
    persist_task_claim, persist_task_resolution,
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
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

const TASK_BASIS: [u8; 32] = [0x44; 32];
const ADAPTER_ID: [u8; 32] = [0x81; 32];

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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(941));
    let key = HeadKey::new(b"task-persistence-gate-test".to_vec()).expect("bounded head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt");
    AuthorityReadReceipt::from_authenticated_head(&authenticated, LogicalTime::new(10), [0x71; 32])
        .expect("authenticated agent receipt")
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

fn plan(pulse: &AgentControlPulse, run: &IntentRun, contract_byte: u8) -> AgentChangePlan {
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let spec = AgentChangePlanSpec::new(
        digest(contract_byte),
        run.allowed_operation_classes(),
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
    AgentChangePlan::build(pulse, run, &[], spec).expect("complete plan")
}

struct PreparedClaim {
    receipt: AuthorityReadReceipt,
    run: IntentRun,
    pulse: AgentControlPulse,
    plan: AgentChangePlan,
    application: AuthorityBoundTaskClaimApplication,
}

fn prepared_claim() -> PreparedClaim {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let snapshot = AuthorityBoundTaskProjectionSnapshot::observed(
        &receipt,
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("valid task state");
    let current = situation(&receipt, &run, TASK_BASIS, 20);
    let item = WorkItem::new(
        snapshot.task_id(),
        TASK_BASIS,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
    );
    let frontier =
        WorkFrontier::build_action_scoped(&current, vec![item]).expect("task is eligible");
    let pulse =
        AgentControlPulse::build(&current, &frontier, Some(&run)).expect("actionable pulse");
    let plan = plan(&pulse, &run, 0x60);
    let application = snapshot
        .claim(
            &pulse,
            &plan,
            &run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            ADAPTER_ID,
            digest(0x82),
        )
        .expect("authority-bound claim application");
    PreparedClaim {
        receipt,
        run,
        pulse,
        plan,
        application,
    }
}

fn reread(
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
    observed_at: u64,
) -> AuthorityBoundTaskProjectionSnapshot {
    match snapshot.lease() {
        Some(lease) => AuthorityBoundTaskProjectionSnapshot::observed_with_lease(
            snapshot.authority_read_receipt(),
            snapshot.task_id(),
            *snapshot.generation(),
            snapshot.phase(),
            lease.clone(),
            LogicalTime::new(observed_at),
        )
        .expect("valid lease reread"),
        None => AuthorityBoundTaskProjectionSnapshot::observed(
            snapshot.authority_read_receipt(),
            snapshot.task_id(),
            *snapshot.generation(),
            snapshot.phase(),
            snapshot.assignment(),
            LogicalTime::new(observed_at),
        )
        .expect("valid task reread"),
    }
}

fn predecessor(envelope: &TaskProjectionMutationEnvelope) -> TaskProjectionPersistedState {
    TaskProjectionPersistedState::new(
        reread(
            envelope.before_snapshot(),
            envelope.transition_observed_at().value() + 1,
        ),
        None,
        None,
        None,
    )
}

fn successor(envelope: &TaskProjectionMutationEnvelope) -> TaskProjectionPersistedState {
    TaskProjectionPersistedState::new(
        reread(
            envelope.after_snapshot(),
            envelope.transition_observed_at().value() + 1,
        ),
        Some(*envelope.transition_id().as_bytes()),
        Some(envelope.inner_transition_id()),
        Some(envelope.evidence_root()),
    )
}

struct ScriptedStore {
    identity: [u8; 32],
    reads: VecDeque<Result<Option<TaskProjectionPersistedState>, TaskProjectionStoreReadRefusal>>,
    write: Result<TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal>,
    flush: Result<TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal>,
    read_calls: usize,
    write_calls: usize,
    flush_calls: usize,
}

impl ScriptedStore {
    fn confirmed(envelope: &TaskProjectionMutationEnvelope) -> Self {
        Self {
            identity: ADAPTER_ID,
            reads: vec![
                Ok(Some(predecessor(envelope))),
                Ok(Some(successor(envelope))),
            ]
            .into(),
            write: Ok(TaskProjectionStoreWriteOutcome::Applied),
            flush: Ok(TaskProjectionStoreFlushOutcome::Flushed),
            read_calls: 0,
            write_calls: 0,
            flush_calls: 0,
        }
    }

    fn ambiguous_predecessor(envelope: &TaskProjectionMutationEnvelope) -> Self {
        Self {
            identity: ADAPTER_ID,
            reads: vec![
                Ok(Some(predecessor(envelope))),
                Ok(Some(predecessor(envelope))),
            ]
            .into(),
            write: Ok(TaskProjectionStoreWriteOutcome::Ambiguous {
                probe_root: digest(0x91),
            }),
            flush: Ok(TaskProjectionStoreFlushOutcome::NotRequired),
            read_calls: 0,
            write_calls: 0,
            flush_calls: 0,
        }
    }

    const fn untouched() -> Self {
        Self {
            identity: ADAPTER_ID,
            reads: VecDeque::new(),
            write: Ok(TaskProjectionStoreWriteOutcome::Applied),
            flush: Ok(TaskProjectionStoreFlushOutcome::Flushed),
            read_calls: 0,
            write_calls: 0,
            flush_calls: 0,
        }
    }
}

impl TaskProjectionStore for ScriptedStore {
    fn adapter_identity(&self) -> [u8; 32] {
        self.identity
    }

    fn read(
        &mut self,
        _key: TaskProjectionStoreKey,
    ) -> Result<Option<TaskProjectionPersistedState>, TaskProjectionStoreReadRefusal> {
        self.read_calls += 1;
        self.reads
            .pop_front()
            .expect("test script contains every expected read")
    }

    fn compare_and_replace(
        &mut self,
        _envelope: &TaskProjectionMutationEnvelope,
    ) -> Result<TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal> {
        self.write_calls += 1;
        self.write
    }

    fn flush(
        &mut self,
        _envelope: &TaskProjectionMutationEnvelope,
    ) -> Result<TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal> {
        self.flush_calls += 1;
        self.flush
    }
}

fn persist_confirmed_claim(prepared: PreparedClaim) -> (PersistedTaskClaim, ScriptedStore) {
    let envelope = TaskProjectionMutationEnvelope::from_claim(&prepared.application)
        .expect("complete claim envelope");
    let mut store = ScriptedStore::confirmed(&envelope);
    let outcome = persist_task_claim(
        &mut store,
        prepared.application,
        &prepared.pulse,
        &prepared.plan,
        &prepared.run,
    )
    .expect("persistence-gated claim reaches a typed outcome");
    let TaskClaimPersistenceOutcome::Persisted(persisted) = outcome else {
        panic!("confirmed store must return a persisted claim")
    };
    (persisted, store)
}

#[test]
fn confirmed_persistence_is_the_claim_activation_boundary() {
    let prepared = prepared_claim();
    let receipt = prepared.receipt.clone();
    let run = prepared.run.clone();
    let (persisted, store) = persist_confirmed_claim(prepared);

    assert_eq!(store.read_calls, 2);
    assert_eq!(store.write_calls, 1);
    assert_eq!(store.flush_calls, 1);
    assert_eq!(
        persisted.persistence_receipt().snapshot_id(),
        persisted.snapshot().snapshot_id()
    );

    let refreshed = situation(&receipt, &run, *persisted.snapshot().generation(), 30);
    let active = persisted
        .claim_receipt()
        .activate(&refreshed, &run)
        .expect("confirmed successor generation activates the claim");
    assert_eq!(active.task_id(), persisted.snapshot().task_id());
}

#[test]
fn claim_control_substitution_refuses_before_store_io() {
    let prepared = prepared_claim();
    let alternate_plan = plan(&prepared.pulse, &prepared.run, 0x70);
    let mut store = ScriptedStore::untouched();

    assert!(matches!(
        persist_task_claim(
            &mut store,
            prepared.application,
            &prepared.pulse,
            &alternate_plan,
            &prepared.run,
        ),
        Err(TaskPersistenceGateRefusal::Claim(
            TaskClaimRefusal::ProjectionPlanMismatch { .. }
        ))
    ));
    assert_eq!(store.read_calls, 0);
    assert_eq!(store.write_calls, 0);
    assert_eq!(store.flush_calls, 0);
}

#[test]
fn ambiguous_write_does_not_leak_an_activatable_claim() {
    let prepared = prepared_claim();
    let envelope = TaskProjectionMutationEnvelope::from_claim(&prepared.application)
        .expect("complete claim envelope");
    let mut store = ScriptedStore::ambiguous_predecessor(&envelope);

    let outcome = persist_task_claim(
        &mut store,
        prepared.application,
        &prepared.pulse,
        &prepared.plan,
        &prepared.run,
    )
    .expect("ambiguous write becomes reconciliation debt");
    assert!(matches!(
        outcome,
        TaskClaimPersistenceOutcome::NeedsReconciliation { .. }
    ));
    assert_eq!(store.write_calls, 1);
}

#[test]
fn release_projection_is_exposed_only_after_release_persistence() {
    let prepared = prepared_claim();
    let receipt = prepared.receipt.clone();
    let run = prepared.run.clone();
    let (persisted_claim, _) = persist_confirmed_claim(prepared);
    let activation = situation(&receipt, &run, *persisted_claim.snapshot().generation(), 30);
    let active: ActiveTaskClaim = persisted_claim
        .claim_receipt()
        .activate(&activation, &run)
        .expect("persisted claim activates");
    let release_application = persisted_claim
        .snapshot()
        .release(
            persisted_claim.claim_receipt(),
            active,
            &run,
            TaskReleaseDisposition::RequireRework,
            LogicalTime::new(81),
            ADAPTER_ID,
            digest(0x92),
        )
        .expect("cleanup remains available after claim expiry");
    let envelope = TaskProjectionMutationEnvelope::from_resolution(&release_application)
        .expect("complete release envelope");
    let mut store = ScriptedStore::confirmed(&envelope);

    let outcome = persist_task_resolution(&mut store, release_application)
        .expect("release reaches a typed persistence outcome");
    let TaskResolutionPersistenceOutcome::Persisted(persisted) = outcome else {
        panic!("confirmed release store must produce persisted resolution")
    };
    assert_eq!(persisted.snapshot().phase(), TaskPhase::Rework);
    assert_eq!(
        persisted.cancellation_projection().outcome(),
        fgit_agent::TaskClaimCancellationOutcome::Released
    );
    assert_eq!(store.write_calls, 1);
}
