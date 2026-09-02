#![forbid(unsafe_code)]
//! Public-path tests for bounded durable task-store orchestration.

use std::collections::VecDeque;

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityBoundTaskProjectionSnapshot, AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun,
    LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet,
    PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RunId, SituationComponent,
    SituationComponentKind, SituationOmissionReason, TaskPhase, TaskProjectionAssignment,
    TaskProjectionMutationEnvelope, TaskProjectionPersistedState, TaskProjectionStore,
    TaskProjectionStoreExecution, TaskProjectionStoreExecutionRefusal,
    TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal,
    TaskProjectionStoreReadRefusal, TaskProjectionStoreReconciliationCause,
    TaskProjectionStoreStage, TaskProjectionStoreWriteDisposition, TaskProjectionStoreWriteOutcome,
    TaskProjectionStoreWriteRefusal, WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem,
    WorkRankingInputs, WorkTaskId, execute_task_projection_store,
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(921));
    let key = HeadKey::new(b"task-store-orchestration-test".to_vec()).expect("bounded head key");
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
        LogicalTime::new(20),
        components,
    )
    .expect("complete situation")
}

fn envelope() -> TaskProjectionMutationEnvelope {
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
    let current = situation(&receipt, &run, TASK_BASIS);
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
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let spec = AgentChangePlanSpec::new(
        digest(0x60),
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
    let plan = AgentChangePlan::build(&pulse, &run, &[], spec).expect("complete plan");
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
        .expect("claim transition");
    TaskProjectionMutationEnvelope::from_claim(&application).expect("complete mutation envelope")
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
    TaskProjectionPersistedState::new(reread(envelope.before_snapshot(), 26), None, None, None)
}

fn successor(envelope: &TaskProjectionMutationEnvelope) -> TaskProjectionPersistedState {
    TaskProjectionPersistedState::new(
        reread(envelope.after_snapshot(), 26),
        Some(*envelope.transition_id().as_bytes()),
        Some(envelope.inner_transition_id()),
        Some(envelope.evidence_root()),
    )
}

fn conflict(envelope: &TaskProjectionMutationEnvelope) -> TaskProjectionPersistedState {
    let snapshot = AuthorityBoundTaskProjectionSnapshot::observed(
        envelope.before_snapshot().authority_read_receipt(),
        envelope.task_id(),
        [0xa1; 32],
        TaskPhase::Rework,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(26),
    )
    .expect("valid conflicting state");
    TaskProjectionPersistedState::new(snapshot, None, None, None)
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
    fn new(
        reads: Vec<Result<Option<TaskProjectionPersistedState>, TaskProjectionStoreReadRefusal>>,
        write: Result<TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal>,
        flush: Result<TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal>,
    ) -> Self {
        Self {
            identity: ADAPTER_ID,
            reads: reads.into(),
            write,
            flush,
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
        _key: fgit_agent::TaskProjectionStoreKey,
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

#[test]
fn applied_write_flush_and_reread_confirm_once() {
    let envelope = envelope();
    let mut store = ScriptedStore::new(
        vec![
            Ok(Some(predecessor(&envelope))),
            Ok(Some(successor(&envelope))),
        ],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );

    let outcome = execute_task_projection_store(&mut store, &envelope)
        .expect("bounded store attempt reaches a result");
    assert!(matches!(
        outcome,
        TaskProjectionStoreExecution::Confirmed {
            write: TaskProjectionStoreWriteDisposition::Applied,
            ..
        }
    ));
    assert_eq!(store.read_calls, 2);
    assert_eq!(store.write_calls, 1);
    assert_eq!(store.flush_calls, 1);
}

#[test]
fn initial_exact_successor_is_identical_retry_without_cas() {
    let envelope = envelope();
    let current = successor(&envelope);
    let mut store = ScriptedStore::new(
        vec![Ok(Some(current.clone())), Ok(Some(current))],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::NotRequired),
    );

    let outcome = execute_task_projection_store(&mut store, &envelope)
        .expect("identical persisted result is confirmed");
    assert!(matches!(
        outcome,
        TaskProjectionStoreExecution::Confirmed {
            write: TaskProjectionStoreWriteDisposition::NotAttempted,
            ..
        }
    ));
    assert_eq!(store.write_calls, 0);
    assert_eq!(store.flush_calls, 1);
}

#[test]
fn already_applied_then_replaced_requires_history_not_simple_conflict() {
    let envelope = envelope();
    let mut store = ScriptedStore::new(
        vec![
            Ok(Some(successor(&envelope))),
            Ok(Some(conflict(&envelope))),
        ],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::NotRequired),
    );

    assert!(matches!(
        execute_task_projection_store(&mut store, &envelope)
            .expect("replacement after observed success is reconciliation debt"),
        TaskProjectionStoreExecution::NeedsReconciliation {
            stage: TaskProjectionStoreStage::Reconcile,
            write: TaskProjectionStoreWriteDisposition::NotAttempted,
            cause: TaskProjectionStoreReconciliationCause::HistoryRequired,
            ..
        }
    ));
    assert_eq!(store.write_calls, 0);
}

#[test]
fn initial_conflicting_state_returns_without_write_or_flush() {
    let envelope = envelope();
    let current = conflict(&envelope);
    let mut store = ScriptedStore::new(
        vec![Ok(Some(current))],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );

    assert!(matches!(
        execute_task_projection_store(&mut store, &envelope)
            .expect("initial conflict is definite before mutation"),
        TaskProjectionStoreExecution::Conflict {
            write: TaskProjectionStoreWriteDisposition::NotAttempted,
            ..
        }
    ));
    assert_eq!(store.write_calls, 0);
    assert_eq!(store.flush_calls, 0);
}

#[test]
fn ambiguous_write_is_resolved_by_exact_successor() {
    let envelope = envelope();
    let mut store = ScriptedStore::new(
        vec![
            Ok(Some(predecessor(&envelope))),
            Ok(Some(successor(&envelope))),
        ],
        Ok(TaskProjectionStoreWriteOutcome::Ambiguous {
            probe_root: digest(0x91),
        }),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );

    let outcome = execute_task_projection_store(&mut store, &envelope)
        .expect("exact successor resolves write ambiguity");
    assert!(matches!(
        outcome,
        TaskProjectionStoreExecution::Confirmed { .. }
    ));
    assert_eq!(store.write_calls, 1);
}

#[test]
fn ambiguous_write_followed_by_predecessor_is_not_retry_safe() {
    let envelope = envelope();
    let mut store = ScriptedStore::new(
        vec![
            Ok(Some(predecessor(&envelope))),
            Ok(Some(predecessor(&envelope))),
        ],
        Ok(TaskProjectionStoreWriteOutcome::Ambiguous {
            probe_root: digest(0x92),
        }),
        Ok(TaskProjectionStoreFlushOutcome::NotRequired),
    );

    assert!(matches!(
        execute_task_projection_store(&mut store, &envelope)
            .expect("uncertainty is returned as reconciliation debt"),
        TaskProjectionStoreExecution::NeedsReconciliation {
            stage: TaskProjectionStoreStage::Reconcile,
            cause: TaskProjectionStoreReconciliationCause::AmbiguousWriteUnresolved,
            ..
        }
    ));
    assert_eq!(store.write_calls, 1);
}

#[test]
fn definite_precondition_failure_and_conflicting_reread_are_conflict() {
    let envelope = envelope();
    let current = conflict(&envelope);
    let mut store = ScriptedStore::new(
        vec![Ok(Some(predecessor(&envelope))), Ok(Some(current))],
        Ok(TaskProjectionStoreWriteOutcome::PreconditionFailed),
        Ok(TaskProjectionStoreFlushOutcome::NotRequired),
    );

    assert!(matches!(
        execute_task_projection_store(&mut store, &envelope)
            .expect("definite no-write conflict is a typed result"),
        TaskProjectionStoreExecution::Conflict {
            write: TaskProjectionStoreWriteDisposition::PreconditionFailed,
            ..
        }
    ));
}

#[test]
fn flush_refusal_after_confirmed_successor_remains_debt() {
    let envelope = envelope();
    let mut store = ScriptedStore::new(
        vec![
            Ok(Some(predecessor(&envelope))),
            Ok(Some(successor(&envelope))),
        ],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Err(TaskProjectionStoreFlushRefusal::Unavailable),
    );

    assert!(matches!(
        execute_task_projection_store(&mut store, &envelope)
            .expect("post-write flush failure is not a pre-effect error"),
        TaskProjectionStoreExecution::NeedsReconciliation {
            stage: TaskProjectionStoreStage::Flush,
            cause: TaskProjectionStoreReconciliationCause::FlushRefused(
                TaskProjectionStoreFlushRefusal::Unavailable
            ),
            decision: Some(fgit_agent::TaskProjectionPersistenceDecision::Confirmed(_)),
            ..
        }
    ));
}

#[test]
fn confirming_read_failure_after_apply_remains_debt() {
    let envelope = envelope();
    let mut store = ScriptedStore::new(
        vec![
            Ok(Some(predecessor(&envelope))),
            Err(TaskProjectionStoreReadRefusal::Unavailable),
        ],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );

    assert!(matches!(
        execute_task_projection_store(&mut store, &envelope)
            .expect("post-write read failure is not a pre-effect error"),
        TaskProjectionStoreExecution::NeedsReconciliation {
            stage: TaskProjectionStoreStage::ConfirmingRead,
            cause: TaskProjectionStoreReconciliationCause::ConfirmingRead(
                TaskProjectionStoreReadRefusal::Unavailable
            ),
            ..
        }
    ));
}

#[test]
fn adapter_identity_mismatch_refuses_before_any_io() {
    let envelope = envelope();
    let mut store = ScriptedStore::new(
        Vec::new(),
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );
    store.identity = [0xff; 32];

    assert_eq!(
        execute_task_projection_store(&mut store, &envelope)
            .expect_err("another backend profile cannot execute the envelope"),
        TaskProjectionStoreExecutionRefusal::AdapterIdentityMismatch {
            expected: ADAPTER_ID,
            observed: [0xff; 32],
        }
    );
    assert_eq!(store.read_calls, 0);
    assert_eq!(store.write_calls, 0);
    assert_eq!(store.flush_calls, 0);
}
