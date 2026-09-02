#![forbid(unsafe_code)]
//! Public-path tests for proof-carrying cross-head task transfer.

use std::collections::VecDeque;

use fgit_agent::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse,
    AgentHandoffAcceptance, AgentHandoffCapsule, AgentHandoffCapsuleSpec, AgentInstanceId,
    AgentSituationReceipt, AuthorityBoundTaskClaimApplication,
    AuthorityBoundTaskProjectionSnapshot, AuthorityReadReceipt, ClassSet,
    CrossHeadTaskTransferActivationReceipt, CrossHeadTaskTransferEnvelope,
    CrossHeadTaskTransferExecution, CrossHeadTaskTransferExecutionRefusal,
    CrossHeadTaskTransferPersistedState, CrossHeadTaskTransferPersistenceOutcome,
    CrossHeadTaskTransferReconciliationCause, CrossHeadTaskTransferRefusal,
    CrossHeadTaskTransferStore, EvidenceClass, HandoffCapabilityAttenuation,
    HandoffTargetResolution, IntentRun, LogicalTime, OperationClass, PersistedCrossHeadTaskTransfer,
    PersistedTaskClaim, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId,
    PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcutSet,
    RequirementDisposition, RunId, RunReconciliationReport, SituationComponent,
    SituationComponentKind, SituationOmissionReason, TaskClaimPersistenceOutcome,
    TaskClaimReceipt, TaskPhase, TaskProjectionAssignment, TaskProjectionMutationEnvelope,
    TaskProjectionPersistedState, TaskProjectionStore, TaskProjectionStoreFlushOutcome,
    TaskProjectionStoreFlushRefusal, TaskProjectionStoreReadRefusal, TaskProjectionStoreStage,
    TaskProjectionStoreWriteDisposition, TaskProjectionStoreWriteOutcome,
    TaskProjectionStoreWriteRefusal, WorkConflict, WorkEligibilityInputs, WorkFrontier,
    WorkItem, WorkRankingInputs, WorkTaskId, accept_handoff_at_current_authority,
    persist_cross_head_task_transfer, persist_task_claim,
};
use fgit_authority::{
    AuthorityStore, CasOutcome, HeadInit, HeadKey, HeadRead, MemoryAuthorityStore, PutOutcome,
    StoreInstanceId, authority_head_identity, body_key, initialize_repository,
    outcome_index_root,
};
use fgit_codec::{RepositoryAuthorityHeadBody, encode_body};
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryId,
};

const TASK_BASIS: [u8; 32] = [0x44; 32];
const ADAPTER_ID: [u8; 32] = [0x71; 32];
const TARGET: [u8; 32] = [0x77; 32];

fn digest(marker: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[marker; 32]).expect("fixed-width digest"),
    )
}

fn head(
    repository_id: RepositoryId,
    generation: u64,
    predecessor_head_id: Option<RepositoryAuthorityHeadId>,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::try_new(generation).expect("positive head generation"),
        predecessor_head_id,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(marker),
        forge_position_root: digest(marker.wrapping_add(1)),
        outcome_index_root: digest(marker.wrapping_add(2)),
        retention_root: digest(marker.wrapping_add(3)),
        outbox_root: digest(marker.wrapping_add(4)),
        configuration_root: digest(marker.wrapping_add(5)),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn head_id(value: &RepositoryAuthorityHeadBody) -> RepositoryAuthorityHeadId {
    authority_head_identity(value).expect("canonical head identity")
}

fn initialize(store: &MemoryAuthorityStore, key: &HeadKey, body: &RepositoryAuthorityHeadBody) {
    assert!(matches!(
        initialize_repository(store, key, body).expect("initialize authority head"),
        HeadInit::Created(_)
    ));
}

fn advance(
    store: &MemoryAuthorityStore,
    key: &HeadKey,
    previous: &RepositoryAuthorityHeadBody,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    let next = head(
        previous.repository_id,
        previous.generation.get() + 1,
        Some(head_id(previous)),
        marker,
    );
    let bytes = encode_body(&next).expect("successor head encodes");
    let immutable_key = body_key(IdentityDomain::RepositoryAuthorityHead, &next)
        .expect("successor head key");
    assert!(matches!(
        store
            .put_if_absent(&immutable_key, &bytes)
            .expect("stage successor head"),
        PutOutcome::Created | PutOutcome::IdenticalRetry
    ));
    let HeadRead::Present(current) = store.read_head(key).expect("read current head") else {
        panic!("initialized authority head must exist");
    };
    assert!(matches!(
        store
            .compare_exchange_head(key, current.token(), next.generation, &bytes)
            .expect("advance authority head"),
        CasOutcome::Committed(_)
    ));
    next
}

fn authority_receipt(
    store: &MemoryAuthorityStore,
    key: &HeadKey,
    verified_at: u64,
    profile: u8,
) -> AuthorityReadReceipt {
    let HeadRead::Present(read) = store.read_head(key).expect("read authority head") else {
        panic!("authority head must exist");
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates the head");
    AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(verified_at),
        [profile; 32],
    )
    .expect("complete agent authority receipt")
}

fn run(receipt: &AuthorityReadReceipt, id: u128, bytes: u64, expiry: u64) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(id),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, bytes),
        LogicalTime::new(expiry),
    )
    .expect("authenticated Intent Run opens")
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
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
    observed_at: u64,
    marker: u8,
) -> (AgentControlPulse, AgentChangePlan) {
    let current = situation(receipt, run, *snapshot.generation(), observed_at);
    let item = WorkItem::new(
        snapshot.task_id(),
        *snapshot.generation(),
        snapshot.phase(),
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(
            0,
            snapshot.assignment().run_id(),
            None,
            true,
            WorkConflict::Clear,
        ),
    );
    let frontier =
        WorkFrontier::build_action_scoped(&current, vec![item]).expect("task is eligible");
    let pulse =
        AgentControlPulse::build(&current, &frontier, Some(run)).expect("actionable pulse");
    let surface =
        PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(marker.wrapping_add(1)));
    let plan = AgentChangePlan::build(
        &pulse,
        run,
        &[],
        AgentChangePlanSpec::new(
            digest(marker),
            ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
            ResourceVector::single(Grade::Bytes, 256),
            PlanStopConditionSet::MANDATORY,
            RejectedShortcutSet::BASELINE,
            PlanApproval::NotRequired {
                policy_root: digest(marker.wrapping_add(2)),
            },
        )
        .with_surfaces(vec![surface], vec![surface])
        .with_checkpoints(vec![PlanCheckpoint::new(
            PlanCheckpointId::from_bytes([marker.wrapping_add(3); 32]),
            PlanCheckpointPurpose::ImplementSlice,
            digest(marker.wrapping_add(4)),
            digest(marker.wrapping_add(5)),
        )])
        .with_evidence_plan(vec![PlanEvidenceRequirement::new(
            PlanRequirementId::from_bytes([marker.wrapping_add(6); 32]),
            EvidenceClass::Executed,
            digest(marker.wrapping_add(7)),
            false,
        )]),
    )
    .expect("complete change plan");
    (pulse, plan)
}

struct Fixture {
    source_receipt: AuthorityReadReceipt,
    receiver_receipt: AuthorityReadReceipt,
    source_run: IntentRun,
    receiver_run: IntentRun,
    source_snapshot: AuthorityBoundTaskProjectionSnapshot,
    source_claim: TaskClaimReceipt,
    source_active_claim: ActiveTaskClaim,
    capsule: AgentHandoffCapsule,
    receiver_situation: AgentSituationReceipt,
    receiver_predecessor: AuthorityBoundTaskProjectionSnapshot,
    acceptance: AgentHandoffAcceptance,
}

fn fixture(store_id: u64) -> Fixture {
    let authority_store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let head_key = HeadKey::new(format!("cross-head-task-transfer-{store_id}").into_bytes())
        .expect("bounded head key");
    let repository_id = RepositoryId::from_bytes([0x22; 16]);
    let genesis = head(repository_id, 1, None, 0x11);
    initialize(&authority_store, &head_key, &genesis);
    let source_receipt = authority_receipt(&authority_store, &head_key, 10, 0x51);
    let source_run = run(&source_receipt, 7, 16_384, 100);
    let initial = AuthorityBoundTaskProjectionSnapshot::observed(
        &source_receipt,
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("initial task snapshot");
    let (source_pulse, source_plan) =
        pulse_and_plan(&source_receipt, &source_run, &initial, 20, 0x60);
    let source_application = initial
        .claim(
            &source_pulse,
            &source_plan,
            &source_run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            ADAPTER_ID,
            digest(0x72),
        )
        .expect("source claim transition");
    let source_claim = TaskClaimReceipt::admit(
        &source_pulse,
        &source_plan,
        &source_run,
        source_application.projection().clone(),
    )
    .expect("source claim receipt");
    let source_activation = situation(
        &source_receipt,
        &source_run,
        *source_application.snapshot().generation(),
        30,
    );
    let source_active_claim = source_claim
        .activate(&source_activation, &source_run)
        .expect("source active claim");
    let source_snapshot = source_application.snapshot().clone();
    let reconciliation =
        RunReconciliationReport::build(&source_run, Vec::new(), source_activation.observed_at())
            .expect("source reconciliation");
    let capsule = AgentHandoffCapsule::build(
        &source_activation,
        &source_plan,
        source_active_claim,
        &source_run,
        reconciliation,
        AgentHandoffCapsuleSpec::new(
            AgentInstanceId::new(1),
            TARGET,
            HandoffCapabilityAttenuation::new(
                ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
                ResourceVector::single(Grade::Bytes, 1_024),
                LogicalTime::new(75),
            ),
            digest(0x91),
        )
        .with_evidence(
            vec![Some(RequirementDisposition::Unsatisfied)],
            Vec::new(),
            Vec::new(),
        )
        .with_unresolved_work(vec![digest(0x92)], Vec::new())
        .with_requested_next_actions(vec![digest(0x93)]),
    )
    .expect("source handoff capsule");

    let _descendant = advance(&authority_store, &head_key, &genesis, 0x21);
    let receiver_receipt = authority_receipt(&authority_store, &head_key, 40, 0x52);
    let receiver_run = run(&receiver_receipt, 8, 512, 70);
    let receiver_predecessor = AuthorityBoundTaskProjectionSnapshot::observed_with_lease(
        &receiver_receipt,
        source_snapshot.task_id(),
        *source_snapshot.generation(),
        source_snapshot.phase(),
        source_snapshot
            .lease()
            .expect("source snapshot carries its active lease")
            .clone(),
        LogicalTime::new(45),
    )
    .expect("receiver basis observes the same source lease");
    let receiver_situation = situation(
        &receiver_receipt,
        &receiver_run,
        *receiver_predecessor.generation(),
        45,
    );
    let acceptance = accept_handoff_at_current_authority(
        &authority_store,
        &head_key,
        &capsule,
        &receiver_situation,
        &receiver_run,
        AgentInstanceId::new(2),
        target_resolution(&receiver_run),
        1,
    )
    .expect("receiver accepts at the exact descendant head");

    Fixture {
        source_receipt,
        receiver_receipt,
        source_run,
        receiver_run,
        source_snapshot,
        source_claim,
        source_active_claim,
        capsule,
        receiver_situation,
        receiver_predecessor,
        acceptance,
    }
}

fn target_resolution(receiver: &IntentRun) -> HandoffTargetResolution {
    HandoffTargetResolution::new(
        TARGET,
        receiver.run_id(),
        AgentInstanceId::new(2),
        [0xa1; 32],
        digest(0xa2),
    )
}

fn transfer_envelope(fixture: &Fixture) -> CrossHeadTaskTransferEnvelope {
    CrossHeadTaskTransferEnvelope::build(
        &fixture.source_snapshot,
        &fixture.source_claim,
        fixture.source_active_claim,
        &fixture.source_run,
        &fixture.capsule,
        &fixture.acceptance,
        &fixture.receiver_situation,
        &fixture.receiver_predecessor,
        &fixture.receiver_run,
        LogicalTime::new(50),
        ADAPTER_ID,
        digest(0xb1),
    )
    .expect("complete cross-head transfer envelope")
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

fn cross_predecessor(
    envelope: &CrossHeadTaskTransferEnvelope,
) -> CrossHeadTaskTransferPersistedState {
    CrossHeadTaskTransferPersistedState::new(
        reread(envelope.receiver_predecessor(), 51),
        None,
        None,
        None,
        None,
    )
}

fn cross_successor(
    envelope: &CrossHeadTaskTransferEnvelope,
) -> CrossHeadTaskTransferPersistedState {
    CrossHeadTaskTransferPersistedState::new(
        reread(envelope.receiver_successor(), 51),
        Some(envelope.envelope_id()),
        Some(envelope.acceptance_id()),
        Some(envelope.ancestry_receipt_id()),
        Some(envelope.evidence_root()),
    )
}

fn cross_conflict(
    envelope: &CrossHeadTaskTransferEnvelope,
) -> CrossHeadTaskTransferPersistedState {
    let snapshot = AuthorityBoundTaskProjectionSnapshot::observed(
        envelope.receiver_successor().authority_read_receipt(),
        envelope.task_id(),
        [0xc1; 32],
        TaskPhase::Rework,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(51),
    )
    .expect("valid conflicting receiver-basis task state");
    CrossHeadTaskTransferPersistedState::new(snapshot, None, None, None, None)
}

struct ScriptedCrossStore {
    identity: [u8; 32],
    reads: VecDeque<
        Result<Option<CrossHeadTaskTransferPersistedState>, TaskProjectionStoreReadRefusal>,
    >,
    write: Result<TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal>,
    flush: Result<TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal>,
    read_calls: usize,
    write_calls: usize,
    flush_calls: usize,
}

impl ScriptedCrossStore {
    fn new(
        reads: Vec<
            Result<Option<CrossHeadTaskTransferPersistedState>, TaskProjectionStoreReadRefusal>,
        >,
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

impl CrossHeadTaskTransferStore for ScriptedCrossStore {
    fn adapter_identity(&self) -> [u8; 32] {
        self.identity
    }

    fn read(
        &mut self,
        _key: fgit_agent::TaskProjectionStoreKey,
    ) -> Result<Option<CrossHeadTaskTransferPersistedState>, TaskProjectionStoreReadRefusal> {
        self.read_calls += 1;
        self.reads
            .pop_front()
            .expect("cross-head store script contains each read")
    }

    fn compare_and_replace(
        &mut self,
        _envelope: &CrossHeadTaskTransferEnvelope,
    ) -> Result<TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal> {
        self.write_calls += 1;
        self.write
    }

    fn flush(
        &mut self,
        _envelope: &CrossHeadTaskTransferEnvelope,
    ) -> Result<TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal> {
        self.flush_calls += 1;
        self.flush
    }
}

#[test]
fn two_basis_envelope_is_deterministic_and_assigns_only_the_receiver() {
    let fixture = fixture(1_201);
    let first = transfer_envelope(&fixture);
    let second = transfer_envelope(&fixture);

    assert_eq!(first.envelope_id(), second.envelope_id());
    assert_ne!(
        first.source_authority_read_receipt_id(),
        first.receiver_authority_read_receipt_id()
    );
    assert_eq!(first.source_snapshot(), &fixture.source_snapshot);
    assert_eq!(first.receiver_predecessor(), &fixture.receiver_predecessor);
    assert_eq!(
        first.receiver_successor().authority_read_receipt(),
        &fixture.receiver_receipt
    );
    assert_eq!(
        first.receiver_successor().assignment(),
        TaskProjectionAssignment::assigned(
            fixture.receiver_run.run_id(),
            fixture
                .receiver_run
                .commitment()
                .expect("complete receiver identity"),
        )
    );
    assert!(first.receiver_successor().lease().is_none());
    assert_ne!(first.previous_generation(), first.resulting_generation());
    assert_eq!(first.acceptance_id(), fixture.acceptance.acceptance_id());
    assert_eq!(
        first.ancestry_receipt_id(),
        fixture
            .acceptance
            .authority_ancestry()
            .expect("descendant acceptance retains ancestry")
            .receipt_id()
    );
}

#[test]
fn same_head_acceptance_must_use_the_existing_single_basis_transfer() {
    let fixture = fixture(1_202);
    let same_head_receiver = run(&fixture.source_receipt, 8, 512, 70);
    let same_head_predecessor = AuthorityBoundTaskProjectionSnapshot::observed_with_lease(
        &fixture.source_receipt,
        fixture.source_snapshot.task_id(),
        *fixture.source_snapshot.generation(),
        fixture.source_snapshot.phase(),
        fixture
            .source_snapshot
            .lease()
            .expect("source lease")
            .clone(),
        LogicalTime::new(45),
    )
    .expect("same-head predecessor");
    let same_head_situation = situation(
        &fixture.source_receipt,
        &same_head_receiver,
        *same_head_predecessor.generation(),
        45,
    );
    let same_head_acceptance = fixture
        .capsule
        .accept(
            &same_head_situation,
            &same_head_receiver,
            AgentInstanceId::new(2),
            target_resolution(&same_head_receiver),
        )
        .expect("same-head handoff remains valid");

    assert_eq!(
        CrossHeadTaskTransferEnvelope::build(
            &fixture.source_snapshot,
            &fixture.source_claim,
            fixture.source_active_claim,
            &fixture.source_run,
            &fixture.capsule,
            &same_head_acceptance,
            &same_head_situation,
            &same_head_predecessor,
            &same_head_receiver,
            LogicalTime::new(50),
            ADAPTER_ID,
            digest(0xb1),
        )
        .expect_err("the cross-head path requires a real descendant proof"),
        CrossHeadTaskTransferRefusal::DescendantAcceptanceRequired
    );
}

#[test]
fn receiver_basis_must_observe_the_complete_source_lease() {
    let fixture = fixture(1_203);
    let altered = AuthorityBoundTaskProjectionSnapshot::observed(
        &fixture.receiver_receipt,
        fixture.source_snapshot.task_id(),
        *fixture.source_snapshot.generation(),
        fixture.source_snapshot.phase(),
        fixture.source_snapshot.assignment(),
        LogicalTime::new(45),
    )
    .expect("assigned row without the source lease is structurally representable");

    assert_eq!(
        CrossHeadTaskTransferEnvelope::build(
            &fixture.source_snapshot,
            &fixture.source_claim,
            fixture.source_active_claim,
            &fixture.source_run,
            &fixture.capsule,
            &fixture.acceptance,
            &fixture.receiver_situation,
            &altered,
            &fixture.receiver_run,
            LogicalTime::new(50),
            ADAPTER_ID,
            digest(0xb1),
        )
        .expect_err("receiver predecessor cannot omit the source lease"),
        CrossHeadTaskTransferRefusal::ReceiverPredecessorSemanticMismatch
    );
}

#[test]
fn transfer_cannot_silently_change_task_adapter_profiles() {
    let fixture = fixture(1_204);
    assert_eq!(
        CrossHeadTaskTransferEnvelope::build(
            &fixture.source_snapshot,
            &fixture.source_claim,
            fixture.source_active_claim,
            &fixture.source_run,
            &fixture.capsule,
            &fixture.acceptance,
            &fixture.receiver_situation,
            &fixture.receiver_predecessor,
            &fixture.receiver_run,
            LogicalTime::new(50),
            [0xff; 32],
            digest(0xb1),
        )
        .expect_err("backend migration needs explicit evidence"),
        CrossHeadTaskTransferRefusal::SourceAdapterMismatch {
            expected: ADAPTER_ID,
            observed: [0xff; 32],
        }
    );
}

#[test]
fn accepted_receiver_commitment_cannot_be_replaced_by_the_same_run_id() {
    let fixture = fixture(1_205);
    let altered_receiver = run(&fixture.receiver_receipt, 8, 256, 65);
    let altered_predecessor = AuthorityBoundTaskProjectionSnapshot::observed_with_lease(
        &fixture.receiver_receipt,
        fixture.source_snapshot.task_id(),
        *fixture.source_snapshot.generation(),
        fixture.source_snapshot.phase(),
        fixture
            .source_snapshot
            .lease()
            .expect("source lease")
            .clone(),
        LogicalTime::new(45),
    )
    .expect("altered receiver observes the same task row");
    let altered_situation = situation(
        &fixture.receiver_receipt,
        &altered_receiver,
        *altered_predecessor.generation(),
        45,
    );

    assert_eq!(
        CrossHeadTaskTransferEnvelope::build(
            &fixture.source_snapshot,
            &fixture.source_claim,
            fixture.source_active_claim,
            &fixture.source_run,
            &fixture.capsule,
            &fixture.acceptance,
            &altered_situation,
            &altered_predecessor,
            &altered_receiver,
            LogicalTime::new(50),
            ADAPTER_ID,
            digest(0xb1),
        )
        .expect_err("accepted complete receiver identity is immutable"),
        CrossHeadTaskTransferRefusal::AcceptanceMismatch
    );
}

#[test]
fn applied_transfer_flush_and_exact_reread_confirm_once() {
    let fixture = fixture(1_206);
    let envelope = transfer_envelope(&fixture);
    let mut store = ScriptedCrossStore::new(
        vec![
            Ok(Some(cross_predecessor(&envelope))),
            Ok(Some(cross_successor(&envelope))),
        ],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );

    let outcome = persist_cross_head_task_transfer(&mut store, envelope.clone())
        .expect("bounded cross-head persistence reaches a result");
    let CrossHeadTaskTransferPersistenceOutcome::Persisted(persisted) = outcome else {
        panic!("exact successor must confirm the transfer");
    };
    assert_eq!(persisted.envelope(), &envelope);
    assert_eq!(persisted.receipt().envelope_id(), envelope.envelope_id());
    assert_eq!(
        persisted.receipt().receiver_run_commitment(),
        fixture
            .receiver_run
            .commitment()
            .expect("complete receiver identity"),
    );
    assert_eq!(
        persisted.write_disposition(),
        TaskProjectionStoreWriteDisposition::Applied
    );
    assert_eq!(store.read_calls, 2);
    assert_eq!(store.write_calls, 1);
    assert_eq!(store.flush_calls, 1);
}

#[test]
fn ambiguous_write_followed_by_predecessor_is_not_retry_safe() {
    let fixture = fixture(1_207);
    let envelope = transfer_envelope(&fixture);
    let mut store = ScriptedCrossStore::new(
        vec![
            Ok(Some(cross_predecessor(&envelope))),
            Ok(Some(cross_predecessor(&envelope))),
        ],
        Ok(TaskProjectionStoreWriteOutcome::Ambiguous {
            probe_root: digest(0xd1),
        }),
        Ok(TaskProjectionStoreFlushOutcome::NotRequired),
    );

    assert!(matches!(
        persist_cross_head_task_transfer(&mut store, envelope)
            .expect("uncertainty is a typed terminal result"),
        CrossHeadTaskTransferPersistenceOutcome::NeedsReconciliation {
            execution: CrossHeadTaskTransferExecution::NeedsReconciliation {
                stage: TaskProjectionStoreStage::Reconcile,
                cause: CrossHeadTaskTransferReconciliationCause::AmbiguousWriteUnresolved,
                ..
            },
            ..
        }
    ));
    assert_eq!(store.write_calls, 1);
}

#[test]
fn initial_conflict_returns_without_write_or_flush() {
    let fixture = fixture(1_208);
    let envelope = transfer_envelope(&fixture);
    let mut store = ScriptedCrossStore::new(
        vec![Ok(Some(cross_conflict(&envelope)))],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );

    assert!(matches!(
        persist_cross_head_task_transfer(&mut store, envelope)
            .expect("initial semantic conflict is definite"),
        CrossHeadTaskTransferPersistenceOutcome::Conflict {
            execution: CrossHeadTaskTransferExecution::Conflict {
                write: TaskProjectionStoreWriteDisposition::NotAttempted,
                ..
            },
            ..
        }
    ));
    assert_eq!(store.write_calls, 0);
    assert_eq!(store.flush_calls, 0);
}

#[test]
fn exact_successor_without_ancestry_metadata_is_reconciliation_debt() {
    let fixture = fixture(1_209);
    let envelope = transfer_envelope(&fixture);
    let incomplete = CrossHeadTaskTransferPersistedState::new(
        reread(envelope.receiver_successor(), 51),
        Some(envelope.envelope_id()),
        Some(envelope.acceptance_id()),
        None,
        Some(envelope.evidence_root()),
    );
    let mut store = ScriptedCrossStore::new(
        vec![Ok(Some(incomplete))],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );

    assert!(matches!(
        persist_cross_head_task_transfer(&mut store, envelope)
            .expect("partial successor metadata remains debt"),
        CrossHeadTaskTransferPersistenceOutcome::NeedsReconciliation {
            execution: CrossHeadTaskTransferExecution::NeedsReconciliation {
                stage: TaskProjectionStoreStage::InitialRead,
                cause: CrossHeadTaskTransferReconciliationCause::InitialPersistence(
                    CrossHeadTaskTransferRefusal::SuccessorAncestryMismatch
                ),
                ..
            },
            ..
        }
    ));
    assert_eq!(store.write_calls, 0);
    assert_eq!(store.flush_calls, 0);
}

#[test]
fn store_profile_substitution_refuses_before_any_io() {
    let fixture = fixture(1_210);
    let envelope = transfer_envelope(&fixture);
    let mut store = ScriptedCrossStore::new(
        Vec::new(),
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );
    store.identity = [0xee; 32];

    assert_eq!(
        fgit_agent::execute_cross_head_task_transfer_store(&mut store, &envelope)
            .expect_err("another backend profile cannot execute the envelope"),
        CrossHeadTaskTransferExecutionRefusal::AdapterIdentityMismatch {
            expected: ADAPTER_ID,
            observed: [0xee; 32],
        }
    );
    assert_eq!(store.read_calls, 0);
    assert_eq!(store.write_calls, 0);
    assert_eq!(store.flush_calls, 0);
}

fn claim_predecessor(
    application: &AuthorityBoundTaskClaimApplication,
) -> TaskProjectionPersistedState {
    TaskProjectionPersistedState::new(
        reread(application.before_snapshot(), 57),
        None,
        None,
        None,
    )
}

fn claim_successor(
    application: &AuthorityBoundTaskClaimApplication,
) -> TaskProjectionPersistedState {
    TaskProjectionPersistedState::new(
        reread(application.snapshot(), 57),
        Some(*application.transition().transition_id().as_bytes()),
        Some(*application.transition().inner_transition_id()),
        Some(application.transition().evidence_root()),
    )
}

struct ScriptedClaimStore {
    reads: VecDeque<Result<Option<TaskProjectionPersistedState>, TaskProjectionStoreReadRefusal>>,
}

impl TaskProjectionStore for ScriptedClaimStore {
    fn adapter_identity(&self) -> [u8; 32] {
        ADAPTER_ID
    }

    fn read(
        &mut self,
        _key: fgit_agent::TaskProjectionStoreKey,
    ) -> Result<Option<TaskProjectionPersistedState>, TaskProjectionStoreReadRefusal> {
        self.reads
            .pop_front()
            .expect("claim store script contains each read")
    }

    fn compare_and_replace(
        &mut self,
        _envelope: &TaskProjectionMutationEnvelope,
    ) -> Result<TaskProjectionStoreWriteOutcome, TaskProjectionStoreWriteRefusal> {
        Ok(TaskProjectionStoreWriteOutcome::Applied)
    }

    fn flush(
        &mut self,
        _envelope: &TaskProjectionMutationEnvelope,
    ) -> Result<TaskProjectionStoreFlushOutcome, TaskProjectionStoreFlushRefusal> {
        Ok(TaskProjectionStoreFlushOutcome::Flushed)
    }
}

fn persisted_transfer(fixture: &Fixture) -> PersistedCrossHeadTaskTransfer {
    let envelope = transfer_envelope(fixture);
    let mut store = ScriptedCrossStore::new(
        vec![
            Ok(Some(cross_predecessor(&envelope))),
            Ok(Some(cross_successor(&envelope))),
        ],
        Ok(TaskProjectionStoreWriteOutcome::Applied),
        Ok(TaskProjectionStoreFlushOutcome::Flushed),
    );
    let outcome = persist_cross_head_task_transfer(&mut store, envelope)
        .expect("cross-head transfer persistence");
    let CrossHeadTaskTransferPersistenceOutcome::Persisted(persisted) = outcome else {
        panic!("script confirms transfer");
    };
    persisted
}

fn persisted_receiver_claim(
    fixture: &Fixture,
    transfer: &PersistedCrossHeadTaskTransfer,
) -> (AgentChangePlan, PersistedTaskClaim) {
    let (pulse, plan) = pulse_and_plan(
        &fixture.receiver_receipt,
        &fixture.receiver_run,
        transfer.snapshot(),
        55,
        0xb8,
    );
    let application = transfer
        .snapshot()
        .claim(
            &pulse,
            &plan,
            &fixture.receiver_run,
            LogicalTime::new(56),
            LogicalTime::new(65),
            ADAPTER_ID,
            digest(0xc8),
        )
        .expect("receiver ordinary claim transition");
    let mut store = ScriptedClaimStore {
        reads: vec![
            Ok(Some(claim_predecessor(&application))),
            Ok(Some(claim_successor(&application))),
        ]
        .into(),
    };
    let outcome = persist_task_claim(
        &mut store,
        application,
        &pulse,
        &plan,
        &fixture.receiver_run,
    )
    .expect("ordinary claim persistence reaches a result");
    let TaskClaimPersistenceOutcome::Persisted(persisted) = outcome else {
        panic!("script confirms receiver claim");
    };
    (plan, persisted)
}

#[test]
fn receiver_must_acquire_a_new_persisted_claim_before_activation() {
    let fixture = fixture(1_211);
    let transfer = persisted_transfer(&fixture);
    let (receiver_plan, persisted_claim) = persisted_receiver_claim(&fixture, &transfer);
    assert_ne!(receiver_plan.plan_id(), transfer.envelope().source_plan_id());

    let activation_situation = situation(
        &fixture.receiver_receipt,
        &fixture.receiver_run,
        *persisted_claim
            .claim_receipt()
            .claimed_task_projection_generation(),
        60,
    );
    let active = persisted_claim
        .claim_receipt()
        .activate(&activation_situation, &fixture.receiver_run)
        .expect("receiver persisted claim activates");
    let receipt = CrossHeadTaskTransferActivationReceipt::admit(
        &transfer,
        &fixture.receiver_run,
        &activation_situation,
        &persisted_claim,
        active,
    )
    .expect("activation chain retains transfer and ordinary claim evidence");

    assert_eq!(receipt.transfer_receipt_id(), transfer.receipt().receipt_id());
    assert_eq!(
        receipt.persisted_claim_receipt_id(),
        persisted_claim.persistence_receipt().receipt_id()
    );
    assert_eq!(
        receipt.receiver_run_commitment(),
        fixture
            .receiver_run
            .commitment()
            .expect("complete receiver identity")
    );
    assert_eq!(
        receipt.transfer_generation(),
        transfer.envelope().resulting_generation()
    );
    assert_ne!(receipt.transfer_generation(), receipt.claimed_generation());
    assert_ne!(receipt.receipt_id().as_bytes(), &[0; 32]);
}

#[test]
fn receiver_activation_rejects_same_id_machine_scope_substitution() {
    let fixture = fixture(1_212);
    let transfer = persisted_transfer(&fixture);
    let (_receiver_plan, persisted_claim) = persisted_receiver_claim(&fixture, &transfer);
    let activation_situation = situation(
        &fixture.receiver_receipt,
        &fixture.receiver_run,
        *persisted_claim
            .claim_receipt()
            .claimed_task_projection_generation(),
        60,
    );
    let active = persisted_claim
        .claim_receipt()
        .activate(&activation_situation, &fixture.receiver_run)
        .expect("receiver persisted claim activates");
    let altered = run(&fixture.receiver_receipt, 8, 256, 65);

    assert!(matches!(
        CrossHeadTaskTransferActivationReceipt::admit(
            &transfer,
            &altered,
            &activation_situation,
            &persisted_claim,
            active,
        )
        .expect_err("same-ID altered receiver cannot adopt transfer"),
        fgit_agent::CrossHeadTaskTransferActivationRefusal::ReceiverRunMismatch
    ));
}
