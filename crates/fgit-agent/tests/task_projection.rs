#![forbid(unsafe_code)]
//! Public-path tests for task projection snapshots and idempotent mutation.

use std::collections::BTreeMap;

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun, LogicalTime, OperationClass,
    PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose,
    PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet, PlanSurface,
    PlanSurfaceKind, RejectedShortcutSet, RunId, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskAdapterRefusal, TaskClaimProjection, TaskClaimReceipt,
    TaskMutationAttempt, TaskMutationAttemptRefusal, TaskMutationObservation, TaskMutationReplay,
    TaskMutationRequest, TaskMutationRequestId, TaskMutationReceipt, TaskPhase,
    TaskProjectionAdapter, TaskProjectionGeneration, TaskProjectionRow, TaskProjectionSnapshot,
    WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
    apply_task_mutation,
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(321));
    let key = HeadKey::new(b"task-projection-test".to_vec()).expect("bounded head key");
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
    task_generation: [u8; 32],
    observed_at: u64,
) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), task_generation)
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

fn plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    task_id: WorkTaskId,
    surface: PlanSurface,
) -> (AgentControlPulse, AgentChangePlan) {
    let situation = situation(receipt, run, BASIS_GENERATION, 20);
    let item = WorkItem::new(
        task_id,
        BASIS_GENERATION,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
    );
    let frontier = WorkFrontier::build_action_scoped(&situation, vec![item])
        .expect("task is eligible");
    let pulse = AgentControlPulse::build(&situation, &frontier, Some(run))
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
    let plan = AgentChangePlan::build(&pulse, run, &[], spec).expect("complete plan");
    (pulse, plan)
}

#[derive(Clone)]
struct StoredMutation {
    observation: TaskMutationObservation,
}

struct ReferenceAdapter {
    identity: [u8; 32],
    generation: TaskProjectionGeneration,
    row: TaskProjectionRow,
    next_generation_byte: u8,
    seen: BTreeMap<TaskMutationRequestId, StoredMutation>,
    calls: usize,
}

impl ReferenceAdapter {
    fn new(generation: TaskProjectionGeneration, row: TaskProjectionRow) -> Self {
        Self {
            identity: [0x91; 32],
            generation,
            row,
            next_generation_byte: 0x55,
            seen: BTreeMap::new(),
            calls: 0,
        }
    }
}

impl TaskProjectionAdapter for ReferenceAdapter {
    fn adapter_identity(&self) -> [u8; 32] {
        self.identity
    }

    fn mutate(
        &mut self,
        request: &TaskMutationRequest,
    ) -> Result<TaskMutationObservation, TaskAdapterRefusal> {
        self.calls += 1;
        if let Some(stored) = self.seen.get(&request.request_id()) {
            let observation = &stored.observation;
            return Ok(TaskMutationObservation::new(
                observation.request_id(),
                observation.previous_generation(),
                observation.resulting_generation(),
                observation.before().clone(),
                observation.after().clone(),
                observation.observed_at(),
                observation.adapter_identity(),
                observation.evidence_root(),
                TaskMutationReplay::IdenticalRetry,
            ));
        }
        if request.expected_generation() != self.generation {
            return Err(TaskAdapterRefusal::Rejected {
                request_id: request.request_id(),
                reason: fgit_agent::TaskAdapterRejection::StaleGeneration {
                    expected: request.expected_generation(),
                    observed: self.generation,
                },
            });
        }
        if request.before() != &self.row {
            return Err(TaskAdapterRefusal::Rejected {
                request_id: request.request_id(),
                reason: fgit_agent::TaskAdapterRejection::Policy,
            });
        }
        let resulting_generation =
            TaskProjectionGeneration::try_from_bytes([self.next_generation_byte; 32])
                .expect("nonzero reference generation");
        self.next_generation_byte = self.next_generation_byte.wrapping_add(1);
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
        self.seen.insert(
            request.request_id(),
            StoredMutation {
                observation: observation.clone(),
            },
        );
        Ok(observation)
    }
}

struct AmbiguousAdapter {
    calls: usize,
}

impl TaskProjectionAdapter for AmbiguousAdapter {
    fn adapter_identity(&self) -> [u8; 32] {
        [0xa1; 32]
    }

    fn mutate(
        &mut self,
        request: &TaskMutationRequest,
    ) -> Result<TaskMutationObservation, TaskAdapterRefusal> {
        self.calls += 1;
        Err(TaskAdapterRefusal::Ambiguous {
            request_id: request.request_id(),
            probe_root: digest(0xa2),
        })
    }
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
    let (pulse, plan) = plan(&receipt, &run, task_id, surface);
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
        vec![row],
    )
    .expect("complete task projection");
    Fixture {
        receipt,
        run,
        pulse,
        plan,
        surface,
        snapshot,
    }
}

fn claim_request(fixture: &Fixture) -> TaskMutationRequest {
    TaskMutationRequest::claim(
        &fixture.snapshot,
        &fixture.receipt,
        &fixture.run,
        fixture.plan.task_id(),
        fixture.plan.plan_id(),
        LogicalTime::new(25),
        LogicalTime::new(80),
        vec![fixture.surface],
        digest(0x90),
    )
    .expect("exact ready row makes a claim request")
}

fn applied(attempt: TaskMutationAttempt) -> TaskMutationReceipt {
    match attempt {
        TaskMutationAttempt::Applied(receipt) => receipt,
        TaskMutationAttempt::NeedsReconciliation { refusal, .. } => {
            panic!("reference adapter returned an invalid observation: {refusal:?}")
        }
    }
}

#[test]
fn snapshot_feeds_frontier_and_claim_mutation_is_idempotent() {
    let fixture = fixture();
    assert_eq!(fixture.snapshot.work_items().len(), 1);
    assert_eq!(
        fixture.snapshot.work_items()[0].task_id(),
        fixture.plan.task_id()
    );

    let request = claim_request(&fixture);
    let mut adapter =
        ReferenceAdapter::new(fixture.snapshot.generation(), request.before().clone());
    let first = apply_task_mutation(&mut adapter, &request).expect("claim applies");
    let second = apply_task_mutation(&mut adapter, &request).expect("retry is recognized");
    let applied = applied(first);
    let retry = applied(second);

    assert_eq!(applied.receipt_id(), retry.receipt_id());
    assert_eq!(applied.replay(), TaskMutationReplay::Applied);
    assert_eq!(retry.replay(), TaskMutationReplay::IdenticalRetry);
    assert_eq!(applied.after().assignee(), Some(fixture.run.run_id()));
    assert_eq!(applied.after().plan_id(), Some(fixture.plan.plan_id()));
    assert_eq!(applied.after().reserved_surfaces(), &[fixture.surface]);
    assert_eq!(adapter.calls, 2);
}

#[test]
fn stale_generation_is_a_definite_typed_backend_refusal() {
    let fixture = fixture();
    let request = claim_request(&fixture);
    let current = TaskProjectionGeneration::try_from_bytes([0x54; 32])
        .expect("nonzero current generation");
    let mut adapter = ReferenceAdapter::new(current, request.before().clone());

    assert_eq!(
        apply_task_mutation(&mut adapter, &request).expect_err("compare basis is stale"),
        TaskMutationAttemptRefusal::Adapter(TaskAdapterRefusal::Rejected {
            request_id: request.request_id(),
            reason: fgit_agent::TaskAdapterRejection::StaleGeneration {
                expected: fixture.snapshot.generation(),
                observed: current,
            },
        })
    );
}

#[test]
fn ambiguous_outcome_is_not_retried_by_the_coordinator() {
    let fixture = fixture();
    let request = claim_request(&fixture);
    let mut adapter = AmbiguousAdapter { calls: 0 };

    assert_eq!(
        apply_task_mutation(&mut adapter, &request)
            .expect_err("ambiguous result requires a probe"),
        TaskMutationAttemptRefusal::Adapter(TaskAdapterRefusal::Ambiguous {
            request_id: request.request_id(),
            probe_root: digest(0xa2),
        })
    );
    assert_eq!(adapter.calls, 1);
}

#[test]
fn malformed_observation_is_a_reconciliation_outcome_not_an_error() {
    struct MalformedAdapter;

    impl TaskProjectionAdapter for MalformedAdapter {
        fn adapter_identity(&self) -> [u8; 32] {
            [0xb1; 32]
        }

        fn mutate(
            &mut self,
            request: &TaskMutationRequest,
        ) -> Result<TaskMutationObservation, TaskAdapterRefusal> {
            Ok(TaskMutationObservation::new(
                request.request_id(),
                request.expected_generation(),
                request.expected_generation(),
                request.before().clone(),
                request.after().clone(),
                request.requested_at(),
                [0xb1; 32],
                digest(0xb2),
                TaskMutationReplay::Applied,
            ))
        }
    }

    let fixture = fixture();
    let request = claim_request(&fixture);
    let mut adapter = MalformedAdapter;
    let outcome = apply_task_mutation(&mut adapter, &request)
        .expect("an inspectable malformed observation is not a pre-commit error");

    assert_eq!(
        outcome,
        TaskMutationAttempt::NeedsReconciliation {
            request_id: request.request_id(),
            observation: TaskMutationObservation::new(
                request.request_id(),
                request.expected_generation(),
                request.expected_generation(),
                request.before().clone(),
                request.after().clone(),
                request.requested_at(),
                [0xb1; 32],
                digest(0xb2),
                TaskMutationReplay::Applied,
            ),
            refusal: fgit_agent::TaskMutationRefusal::GenerationUnchanged,
        }
    );
}

#[test]
fn release_remains_constructible_after_the_source_run_expires() {
    let fixture = fixture();
    let claim_request = claim_request(&fixture);
    let mut adapter = ReferenceAdapter::new(
        fixture.snapshot.generation(),
        claim_request.before().clone(),
    );
    let mutation = applied(
        apply_task_mutation(&mut adapter, &claim_request).expect("claim mutation applies"),
    );
    let projection = TaskClaimProjection::new(
        fixture.plan.task_id(),
        fixture.plan.plan_id(),
        fixture.run.run_id(),
        *mutation.previous_generation().as_bytes(),
        *mutation.resulting_generation().as_bytes(),
        mutation.after().reserved_surfaces().to_vec(),
        claim_request.requested_at(),
        mutation
            .after()
            .claim_expiry()
            .expect("claimed row carries expiry"),
        mutation.adapter_identity(),
        mutation.evidence_root(),
    );
    let claim = TaskClaimReceipt::admit(
        &fixture.pulse,
        &fixture.plan,
        &fixture.run,
        projection,
    )
    .expect("task claim receipt admits exact adapter result");
    let activation = situation(
        &fixture.receipt,
        &fixture.run,
        *mutation.resulting_generation().as_bytes(),
        30,
    );
    let active = claim
        .activate(&activation, &fixture.run)
        .expect("post-claim generation activates the claim");
    let claimed_snapshot = TaskProjectionSnapshot::build(
        &fixture.receipt,
        *mutation.resulting_generation().as_bytes(),
        LogicalTime::new(100),
        vec![mutation.after().clone()],
    )
    .expect("claimed row remains observable after run expiry");

    let release = TaskMutationRequest::release(
        &claimed_snapshot,
        &fixture.receipt,
        &fixture.run,
        fixture.plan.task_id(),
        fixture.plan.plan_id(),
        active.activation_id(),
        LogicalTime::new(100),
        digest(0xc1),
    )
    .expect("run expiry must not disable reservation release");

    assert_eq!(release.before().assignee(), Some(fixture.run.run_id()));
    assert_eq!(release.after().assignee(), None);
    assert!(release.after().reserved_surfaces().is_empty());
}
