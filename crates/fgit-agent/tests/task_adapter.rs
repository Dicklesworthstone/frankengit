#![forbid(unsafe_code)]
//! Public-path tests for strict task claim and release coordination.

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityReadReceipt, ClaimTaskOutcome, ClassSet, EvidenceClass, IntentRun, LogicalTime,
    OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose,
    PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet, PlanSurface,
    PlanSurfaceKind, RejectedShortcutSet, RunId, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskAdapterRefusal, TaskCoordinatorRefusal,
    TaskMutationObservation, TaskMutationReplay, TaskMutationRequest, TaskPhase,
    TaskProjectionAdapter, TaskProjectionGeneration, TaskProjectionRow, TaskProjectionSnapshot,
    WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
    claim_selected_task, release_active_task,
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

const BASIS_GENERATION: [u8; 32] = [0x44; 32];

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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(331));
    let key = HeadKey::new(b"task-adapter-test".to_vec()).expect("bounded head key");
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

struct Fixture {
    receipt: AuthorityReadReceipt,
    run: IntentRun,
    pulse: AgentControlPulse,
    plan: AgentChangePlan,
    surface: PlanSurface,
    snapshot: TaskProjectionSnapshot,
}

fn fixture() -> Fixture {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let task_id = WorkTaskId::from_bytes([0x31; 32]);
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x51));
    let planning = situation(&receipt, &run, BASIS_GENERATION, 20);
    let row = TaskProjectionRow::unclaimed(
        task_id,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        0,
        None,
        true,
        WorkConflict::Clear,
    )
    .expect("valid unclaimed row");
    let snapshot = TaskProjectionSnapshot::build(
        &receipt,
        BASIS_GENERATION,
        LogicalTime::new(20),
        vec![row.clone()],
    )
    .expect("complete task projection");
    let frontier = WorkFrontier::build_action_scoped(&planning, snapshot.work_items())
        .expect("snapshot feeds the frontier");
    let pulse = AgentControlPulse::build(&planning, &frontier, Some(&run))
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
    let plan = AgentChangePlan::build(&pulse, &run, &[], spec).expect("complete plan");
    Fixture {
        receipt,
        run,
        pulse,
        plan,
        surface,
        snapshot,
    }
}

struct ApplyingAdapter {
    identity: [u8; 32],
    generation: TaskProjectionGeneration,
    row: TaskProjectionRow,
    next_generation: u8,
    calls: usize,
}

impl ApplyingAdapter {
    fn new(snapshot: &TaskProjectionSnapshot) -> Self {
        Self {
            identity: [0x91; 32],
            generation: snapshot.generation(),
            row: snapshot.rows()[0].clone(),
            next_generation: 0x55,
            calls: 0,
        }
    }
}

impl TaskProjectionAdapter for ApplyingAdapter {
    fn adapter_identity(&self) -> [u8; 32] {
        self.identity
    }

    fn mutate(
        &mut self,
        request: &TaskMutationRequest,
    ) -> Result<TaskMutationObservation, TaskAdapterRefusal> {
        self.calls += 1;
        if request.expected_generation() != self.generation || request.before() != &self.row {
            return Err(TaskAdapterRefusal::Rejected {
                request_id: request.request_id(),
                reason: fgit_agent::TaskAdapterRejection::Policy,
            });
        }
        let resulting_generation =
            TaskProjectionGeneration::try_from_bytes([self.next_generation; 32])
                .expect("nonzero reference generation");
        self.next_generation = self.next_generation.wrapping_add(1);
        let observation = TaskMutationObservation::new(
            request.request_id(),
            self.generation,
            resulting_generation,
            request.before().clone(),
            request.after().clone(),
            LogicalTime::new(request.requested_at().value() + 1),
            self.identity,
            digest(0x92),
            TaskMutationReplay::Applied,
        );
        self.generation = resulting_generation;
        self.row = request.after().clone();
        Ok(observation)
    }
}

#[test]
fn strict_claim_and_release_flow_into_existing_receipt_types() {
    let fixture = fixture();
    let mut adapter = ApplyingAdapter::new(&fixture.snapshot);
    let claim_outcome = claim_selected_task(
        &mut adapter,
        &fixture.snapshot,
        &fixture.receipt,
        &fixture.pulse,
        &fixture.plan,
        &fixture.run,
        LogicalTime::new(25),
        LogicalTime::new(80),
        digest(0x90),
    )
    .expect("strict coordinator reaches a definite result");
    let claimed = match claim_outcome {
        ClaimTaskOutcome::Claimed(claimed) => claimed,
        ClaimTaskOutcome::CommittedNeedsReconciliation { refusal, .. } => {
            panic!("valid integrated claim unexpectedly needs reconciliation: {refusal:?}")
        }
    };
    assert_eq!(
        claimed.claim_receipt().previous_task_projection_generation(),
        claimed.mutation_receipt().previous_generation().as_bytes()
    );
    assert_eq!(
        claimed.claim_receipt().claimed_task_projection_generation(),
        claimed.mutation_receipt().resulting_generation().as_bytes()
    );
    assert_eq!(claimed.claim_receipt().reserved_surfaces(), &[fixture.surface]);

    let activation = situation(
        &fixture.receipt,
        &fixture.run,
        *claimed.mutation_receipt().resulting_generation().as_bytes(),
        30,
    );
    let active = claimed
        .claim_receipt()
        .activate(&activation, &fixture.run)
        .expect("post-claim generation activates the claim");
    let claimed_snapshot = TaskProjectionSnapshot::build(
        &fixture.receipt,
        *claimed.mutation_receipt().resulting_generation().as_bytes(),
        LogicalTime::new(100),
        vec![claimed.mutation_receipt().after().clone()],
    )
    .expect("latest task snapshot remains observable after expiry");
    let latest = situation(
        &fixture.receipt,
        &fixture.run,
        *claimed.mutation_receipt().resulting_generation().as_bytes(),
        100,
    );
    let released = release_active_task(
        &mut adapter,
        &claimed_snapshot,
        &latest,
        &fixture.plan,
        active,
        &fixture.run,
        LogicalTime::new(100),
        digest(0xa0),
    )
    .expect("expired run still releases its exact claim");

    assert_eq!(released.cancellation_projection().active_claim_id(), active.activation_id());
    assert_eq!(
        released.cancellation_projection().outcome(),
        fgit_agent::TaskClaimCancellationOutcome::Released
    );
    assert_eq!(released.mutation_receipt().after().assignee(), None);
    assert!(released
        .mutation_receipt()
        .after()
        .reserved_surfaces()
        .is_empty());
    assert_eq!(adapter.calls, 2);
}

#[test]
fn pulse_snapshot_generation_mismatch_refuses_before_adapter_io() {
    let fixture = fixture();
    let mismatched = TaskProjectionSnapshot::build(
        &fixture.receipt,
        [0x45; 32],
        LogicalTime::new(20),
        fixture.snapshot.rows().to_vec(),
    )
    .expect("another well-formed task generation");
    let mut adapter = ApplyingAdapter::new(&mismatched);

    assert_eq!(
        claim_selected_task(
            &mut adapter,
            &mismatched,
            &fixture.receipt,
            &fixture.pulse,
            &fixture.plan,
            &fixture.run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            digest(0x90),
        )
        .expect_err("stale snapshot must fail before mutation"),
        TaskCoordinatorRefusal::PulseGenerationMismatch {
            expected: BASIS_GENERATION,
            observed: [0x45; 32],
        }
    );
    assert_eq!(adapter.calls, 0);
}
