#![forbid(unsafe_code)]
//! Public-path tests for continuity-bound handoff and cancellation safety.

use fgit_agent::{
    ActiveClaimContinuityReceipt, ActiveClaimContinuityRefusal, ActiveTaskClaim, AgentChangePlan,
    AgentChangePlanSpec, AgentControlPulse, AgentHandoffCapsule, AgentHandoffCapsuleSpec,
    AgentInstanceId, AgentSituationReceipt, AuthorityReadReceipt, ClassSet, EvidenceClass,
    HandoffCapabilityAttenuation, HandoffConstructionRefusal, IntentRun, LogicalTime,
    OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose,
    PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet, PlanSurface, PlanSurfaceKind,
    RejectedShortcutSet, RequirementDisposition, RunCancellationIntent, RunCancellationState,
    RunId, RunReconciliationReport, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskClaimCancellationOutcome, TaskClaimCancellationProjection,
    TaskClaimProjection, TaskClaimReceipt, TaskPhase, WorkConflict, WorkEligibilityInputs,
    WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositorySequence,
};

const TASK_BASIS: [u8; 32] = [0x44; 32];
const CLAIMED_GENERATION: [u8; 32] = [0x55; 32];
const RELEASED_GENERATION: [u8; 32] = [0x56; 32];

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
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed-width RCR identity digest"),
    )
}

fn authority_receipt() -> AuthorityReadReceipt {
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
    let expected_head_id = authority_head_identity(&head)
        .expect("a complete canonical authority head re-identifies itself");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(211));
    let head_key =
        HeadKey::new(b"agent-lifecycle-continuity-test-head".to_vec()).expect("bounded head key");
    let head_read = match initialize_repository(&store, &head_key, &head)
        .expect("reference store initializes one complete authority head")
    {
        HeadInit::Created(receipt) => receipt,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => {
            panic!("fresh reference store must create the head")
        }
    };
    let authenticated = store
        .authenticate_head_receipt(&head_read)
        .expect("issuing store authenticates its own receipt");
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("authenticated head makes a complete agent receipt");
    assert_eq!(receipt.authority_head_id(), expected_head_id);
    receipt
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

fn situation_with_search(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    task_generation: [u8; 32],
    search_generation: u8,
    observed_at: u64,
) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), task_generation)
        } else if kind == SituationComponentKind::Search {
            SituationComponent::observed(kind, receipt.authority_head_id(), [search_generation; 32])
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

fn situation(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    task_generation: [u8; 32],
    observed_at: u64,
) -> AgentSituationReceipt {
    situation_with_search(receipt, run, task_generation, 0x74, observed_at)
}

struct Fixture {
    receipt: AuthorityReadReceipt,
    run: IntentRun,
    plan: AgentChangePlan,
    active_claim: ActiveTaskClaim,
    activation: AgentSituationReceipt,
}

fn fixture() -> Fixture {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let planning = situation(&receipt, &run, TASK_BASIS, 20);
    let task_id = WorkTaskId::from_bytes([0x31; 32]);
    let item = WorkItem::new(
        task_id,
        TASK_BASIS,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, Some(run.run_id()), None, true, WorkConflict::Clear),
    );
    let frontier =
        WorkFrontier::build_action_scoped(&planning, vec![item]).expect("task is eligible");
    let pulse = AgentControlPulse::build(&planning, &frontier, Some(&run))
        .expect("live run makes an actionable pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let plan_spec = AgentChangePlanSpec::new(
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
    let plan = AgentChangePlan::build(&pulse, &run, &[], plan_spec).expect("complete change plan");
    let projection = TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        TASK_BASIS,
        CLAIMED_GENERATION,
        vec![surface],
        LogicalTime::new(25),
        LogicalTime::new(80),
        [0x72; 32],
        digest(0x73),
    );
    let claim =
        TaskClaimReceipt::admit(&pulse, &plan, &run, projection).expect("task claim admitted");
    let activation = situation(&receipt, &run, CLAIMED_GENERATION, 30);
    let active_claim = claim
        .activate(&activation, &run)
        .expect("post-claim generation activates the claim");
    Fixture {
        receipt,
        run,
        plan,
        active_claim,
        activation,
    }
}

fn handoff_spec() -> AgentHandoffCapsuleSpec {
    AgentHandoffCapsuleSpec::new(
        AgentInstanceId::new(1),
        [0x77; 32],
        HandoffCapabilityAttenuation::new(
            ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
            ResourceVector::single(Grade::Bytes, 1_024),
            LogicalTime::new(70),
        ),
        digest(0x91),
    )
    .with_evidence(
        vec![Some(RequirementDisposition::Unsatisfied)],
        Vec::new(),
        Vec::new(),
    )
    .with_unresolved_work(vec![digest(0x92)], Vec::new())
    .with_requested_next_actions(vec![digest(0x93)])
}

fn task_release(
    active_claim: ActiveTaskClaim,
    resolved_at: u64,
) -> TaskClaimCancellationProjection {
    TaskClaimCancellationProjection::new(
        active_claim.activation_id(),
        active_claim.claim_id(),
        active_claim.plan_id(),
        active_claim.task_id(),
        active_claim.assignee(),
        CLAIMED_GENERATION,
        RELEASED_GENERATION,
        LogicalTime::new(resolved_at),
        TaskClaimCancellationOutcome::Released,
        [0xa1; 32],
        digest(0xa2),
    )
}

#[test]
fn later_handoff_requires_and_commits_full_context_continuity() {
    let fixture = fixture();
    let later = situation(&fixture.receipt, &fixture.run, CLAIMED_GENERATION, 40);
    let reconciliation =
        RunReconciliationReport::build(&fixture.run, Vec::new(), later.observed_at())
            .expect("complete later effect inventory");

    assert_eq!(
        AgentHandoffCapsule::build(
            &later,
            &fixture.plan,
            fixture.active_claim,
            &fixture.run,
            reconciliation.clone(),
            handoff_spec(),
        )
        .expect_err("later situation without continuity must fail closed"),
        HandoffConstructionRefusal::ClaimSituationMismatch {
            expected: fixture.active_claim.situation_id(),
            observed: *later.situation_id().as_bytes(),
        }
    );

    let continuity = ActiveClaimContinuityReceipt::establish(
        fixture.active_claim,
        &fixture.activation,
        &later,
        &fixture.run,
    )
    .expect("only logical time advanced");
    let first = AgentHandoffCapsule::build_with_continuity(
        &later,
        &fixture.plan,
        fixture.active_claim,
        continuity,
        &fixture.run,
        reconciliation.clone(),
        handoff_spec(),
    )
    .expect("continuity-bound handoff");
    let second = AgentHandoffCapsule::build_with_continuity(
        &later,
        &fixture.plan,
        fixture.active_claim,
        continuity,
        &fixture.run,
        reconciliation,
        handoff_spec(),
    )
    .expect("same proof produces the same public capsule");

    assert_eq!(first.capsule_id(), second.capsule_id());
    assert_eq!(first.claim_continuity_id(), Some(continuity.receipt_id()));
    assert_eq!(first.latest_situation_id(), later.situation_id());
    assert_ne!(first.capsule_id().as_bytes(), &[0; 32]);
}

#[test]
fn changed_context_does_not_block_cancellation() {
    let fixture = fixture();
    let changed =
        situation_with_search(&fixture.receipt, &fixture.run, CLAIMED_GENERATION, 0x75, 40);
    assert_eq!(
        ActiveClaimContinuityReceipt::establish(
            fixture.active_claim,
            &fixture.activation,
            &changed,
            &fixture.run,
        )
        .expect_err("changed Search context is not a continuation"),
        ActiveClaimContinuityRefusal::ComponentChanged {
            kind: SituationComponentKind::Search,
        }
    );

    let initial = RunReconciliationReport::build(&fixture.run, Vec::new(), changed.observed_at())
        .expect("complete changed-context effect inventory");
    let intent = RunCancellationIntent::request(
        &changed,
        &fixture.run,
        initial,
        Some(fixture.active_claim),
        AgentInstanceId::new(9),
        digest(0xa0),
    )
    .expect("a conservative stop remains available after context change");
    assert_eq!(intent.claim_continuity_id(), None);
    assert_eq!(intent.source_situation_id(), changed.situation_id());

    let final_report =
        RunReconciliationReport::build(&fixture.run, Vec::new(), LogicalTime::new(50))
            .expect("complete final effect inventory");
    let completion = intent
        .complete(
            final_report,
            Some(task_release(fixture.active_claim, 45)),
            Vec::new(),
            Vec::new(),
        )
        .expect("empty effect set and explicit task release complete cleanly");

    assert_eq!(completion.cancellation_id(), intent.cancellation_id());
    assert_eq!(completion.state(), RunCancellationState::Clean);
    assert_ne!(completion.completion_id().as_bytes(), &[0; 32]);
}

#[test]
fn unchanged_cancellation_can_retain_optional_continuity_evidence() {
    let fixture = fixture();
    let later = situation(&fixture.receipt, &fixture.run, CLAIMED_GENERATION, 40);
    let initial = RunReconciliationReport::build(&fixture.run, Vec::new(), later.observed_at())
        .expect("complete later effect inventory");
    let direct = RunCancellationIntent::request(
        &later,
        &fixture.run,
        initial.clone(),
        Some(fixture.active_claim),
        AgentInstanceId::new(9),
        digest(0xa0),
    )
    .expect("cancellation does not require continuity");

    let continuity = ActiveClaimContinuityReceipt::establish(
        fixture.active_claim,
        &fixture.activation,
        &later,
        &fixture.run,
    )
    .expect("only logical time advanced");
    let proven = RunCancellationIntent::request_with_continuity(
        &later,
        &fixture.run,
        initial,
        fixture.active_claim,
        continuity,
        AgentInstanceId::new(9),
        digest(0xa0),
    )
    .expect("optional continuity evidence is retained");

    assert_eq!(direct.claim_continuity_id(), None);
    assert_eq!(proven.claim_continuity_id(), Some(continuity.receipt_id()));
    assert_ne!(direct.cancellation_id(), proven.cancellation_id());
    assert_ne!(direct.cancellation_id().as_bytes(), &[0; 32]);
    assert_ne!(proven.cancellation_id().as_bytes(), &[0; 32]);
}
