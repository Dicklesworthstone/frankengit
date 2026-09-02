#![forbid(unsafe_code)]
//! End-to-end public-path tests for complete Intent Run identity propagation.

use fgit_agent::{
    ActionPacketRefusal, ActionPreconditionSet, ActionStep, ActionStepId, AgentActionPacket,
    AgentActionPacketSpec, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse,
    AgentSituationReceipt, AuthorityBoundTaskProjectionSnapshot, AuthorityReadReceipt, ClassSet,
    EvidenceClass, IntentRun, LogicalTime, OperationClass, PlanApproval, PlanCheckpoint,
    PlanCheckpointId, PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRefusal,
    PlanRequirementId, PlanStopConditionSet, PlanSurface, PlanSurfaceKind, PulseRefusal,
    RejectedShortcutSet, RunId, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskClaimProjection, TaskClaimReceipt, TaskClaimRefusal,
    TaskCoordinationRefusal, TaskPhase, TaskProjectionAdapterRefusal, TaskProjectionAssignment,
    TaskReleaseDisposition, WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem,
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
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

const TASK_BASIS: [u8; 32] = [0x44; 32];
const CLAIMED_GENERATION: [u8; 32] = [0x55; 32];
const REQUIREMENT_ID: PlanRequirementId = PlanRequirementId::from_bytes([0x66; 32]);

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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1_041));
    let key = HeadKey::new(b"run-commitment-propagation-test".to_vec()).expect("bounded head key");
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

fn run(
    receipt: &AuthorityReadReceipt,
    classes: &[OperationClass],
    bytes: u64,
    expiry: u64,
) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(classes),
        ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::CpuMicros, 20_000)]),
        LogicalTime::new(expiry),
    )
    .expect("authenticated run opens")
}

fn components(
    receipt: &AuthorityReadReceipt,
    generation: [u8; 32],
) -> [SituationComponent; fgit_agent::SITUATION_COMPONENT_COUNT] {
    std::array::from_fn(|index| {
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
    })
}

fn situation(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    generation: [u8; 32],
    observed_at: u64,
) -> AgentSituationReceipt {
    AgentSituationReceipt::build(
        receipt.clone(),
        Some(run),
        None,
        LogicalTime::new(observed_at),
        components(receipt, generation),
    )
    .expect("complete situation")
}

fn frontier(
    situation: &AgentSituationReceipt,
    run: &IntentRun,
    task_id: WorkTaskId,
) -> WorkFrontier {
    let item = WorkItem::new(
        task_id,
        TASK_BASIS,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, Some(run.run_id()), None, true, WorkConflict::Clear),
    );
    WorkFrontier::build_action_scoped(situation, vec![item]).expect("task is eligible")
}

fn plan_spec(surface: PlanSurface) -> AgentChangePlanSpec {
    AgentChangePlanSpec::new(
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
        REQUIREMENT_ID,
        EvidenceClass::Executed,
        digest(0x65),
        false,
    )])
}

fn claim_projection(
    plan: &AgentChangePlan,
    run: &IntentRun,
    surface: PlanSurface,
) -> TaskClaimProjection {
    TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        TASK_BASIS,
        CLAIMED_GENERATION,
        vec![surface],
        LogicalTime::new(25),
        LogicalTime::new(80),
        [0x81; 32],
        digest(0x82),
    )
}

fn packet_spec(surface: PlanSurface) -> AgentActionPacketSpec {
    AgentActionPacketSpec::new(
        vec![ActionStep::new(
            ActionStepId::from_bytes([0x91; 32]),
            OperationClass::TreeFsWorkspace,
            surface,
            digest(0x92),
            digest(0x93),
            ResourceVector::single(Grade::Bytes, 512),
            None,
        )],
        ActionPreconditionSet::MANDATORY,
        digest(0x94),
        digest(0x95),
        digest(0x96),
        [0x97; 32],
    )
}

struct ControlChain {
    receipt: AuthorityReadReceipt,
    run: IntentRun,
    situation: AgentSituationReceipt,
    frontier: WorkFrontier,
    pulse: AgentControlPulse,
    plan: AgentChangePlan,
    claim: TaskClaimReceipt,
    activation: AgentSituationReceipt,
    active: fgit_agent::ActiveTaskClaim,
    surface: PlanSurface,
}

fn control_chain(task_byte: u8) -> ControlChain {
    let receipt = authority_receipt();
    let run = run(
        &receipt,
        &[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ],
        16_384,
        100,
    );
    let task_id = WorkTaskId::from_bytes([task_byte; 32]);
    let situation = situation(&receipt, &run, TASK_BASIS, 20);
    let frontier = frontier(&situation, &run, task_id);
    let pulse =
        AgentControlPulse::build(&situation, &frontier, Some(&run)).expect("complete-run pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x51));
    let plan =
        AgentChangePlan::build(&pulse, &run, &[], plan_spec(surface)).expect("complete-run plan");
    let claim =
        TaskClaimReceipt::admit(&pulse, &plan, &run, claim_projection(&plan, &run, surface))
            .expect("complete-run claim");
    let activation = self::situation(&receipt, &run, CLAIMED_GENERATION, 30);
    let active = claim
        .activate(&activation, &run)
        .expect("complete-run activation");
    ControlChain {
        receipt,
        run,
        situation,
        frontier,
        pulse,
        plan,
        claim,
        activation,
        active,
        surface,
    }
}

#[test]
fn complete_run_identity_survives_the_full_execution_chain() {
    let chain = control_chain(0x41);
    let commitment = chain.run.commitment().expect("complete run identity");

    assert_eq!(chain.situation.intent_run_commitment(), Some(commitment));
    assert_eq!(chain.pulse.active_run_commitment(), Some(commitment));
    assert_eq!(chain.plan.intent_run_commitment(), commitment);
    assert_eq!(chain.claim.run_commitment(), commitment);
    assert_eq!(chain.active.run_commitment(), commitment);

    let packet = AgentActionPacket::build(
        &chain.activation,
        &chain.plan,
        chain.active,
        &chain.run,
        &[],
        packet_spec(chain.surface),
    )
    .expect("complete-run action packet");
    assert_eq!(packet.run_commitment(), commitment);

    let initial = AuthorityBoundTaskProjectionSnapshot::observed(
        &chain.receipt,
        chain.plan.task_id(),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("authority-bound task predecessor");
    let application = initial
        .claim(
            &chain.pulse,
            &chain.plan,
            &chain.run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [0xa1; 32],
            digest(0xa2),
        )
        .expect("semantic claim application");
    assert_eq!(
        application
            .snapshot()
            .lease()
            .expect("claimed state carries a lease")
            .run_commitment(),
        commitment
    );
}

#[test]
fn same_id_altered_run_is_refused_at_every_control_boundary() {
    let chain = control_chain(0x42);
    let original = chain.run.commitment().expect("original run identity");
    let altered = run(
        &chain.receipt,
        &[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ],
        1,
        90,
    );
    let changed = altered.commitment().expect("altered run identity");
    assert_ne!(original, changed);

    assert_eq!(
        AgentControlPulse::build(&chain.situation, &chain.frontier, Some(&altered))
            .expect_err("pulse cannot trust a reused numeric run ID"),
        PulseRefusal::ActiveRunCommitmentMismatch {
            expected: original,
            observed: changed,
        }
    );

    assert_eq!(
        AgentChangePlan::build(&chain.pulse, &altered, &[], plan_spec(chain.surface),)
            .expect_err("planning must refuse before resource-scope arithmetic"),
        PlanRefusal::ActiveRunCommitmentMismatch {
            expected: original,
            observed: changed,
        }
    );

    assert_eq!(
        TaskClaimReceipt::admit(
            &chain.pulse,
            &chain.plan,
            &altered,
            claim_projection(&chain.plan, &altered, chain.surface),
        )
        .expect_err("claim admission cannot substitute a same-ID run"),
        TaskClaimRefusal::PlanRunCommitmentMismatch {
            expected: original,
            observed: changed,
        }
    );

    assert!(matches!(
        chain.claim.activate(&chain.activation, &altered),
        Err(TaskClaimRefusal::RefreshedRunCommitmentMismatch { .. })
    ));

    assert!(matches!(
        AgentActionPacket::build(
            &chain.activation,
            &chain.plan,
            chain.active,
            &altered,
            &[],
            packet_spec(chain.surface),
        ),
        Err(ActionPacketRefusal::SituationRunCommitmentMismatch { .. })
    ));

    let initial = AuthorityBoundTaskProjectionSnapshot::observed(
        &chain.receipt,
        chain.plan.task_id(),
        TASK_BASIS,
        TaskPhase::Open,
        TaskProjectionAssignment::Unassigned,
        LogicalTime::new(20),
    )
    .expect("authority-bound task predecessor");
    let application = initial
        .claim(
            &chain.pulse,
            &chain.plan,
            &chain.run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [0xa1; 32],
            digest(0xa2),
        )
        .expect("semantic claim application");
    let semantic_claim = TaskClaimReceipt::admit(
        &chain.pulse,
        &chain.plan,
        &chain.run,
        application.projection().clone(),
    )
    .expect("semantic projection admits");
    let semantic_activation = situation(
        &chain.receipt,
        &chain.run,
        *application.snapshot().generation(),
        30,
    );
    let semantic_active = semantic_claim
        .activate(&semantic_activation, &chain.run)
        .expect("semantic claim activates");

    assert_eq!(
        application
            .snapshot()
            .release(
                &semantic_claim,
                semantic_active,
                &altered,
                TaskReleaseDisposition::ReturnToOpen,
                LogicalTime::new(40),
                [0xa3; 32],
                digest(0xa4),
            )
            .expect_err("durable lease cannot be cleaned up by another same-ID run"),
        TaskCoordinationRefusal::Adapter(
            TaskProjectionAdapterRefusal::LeaseRunCommitmentMismatch {
                expected: original,
                observed: changed,
            },
        )
    );
}

#[test]
fn overlapping_same_id_claims_with_different_commitments_are_conflicts() {
    let receipt = authority_receipt();
    let first_run = run(
        &receipt,
        &[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ],
        16_384,
        100,
    );
    let second_run = run(
        &receipt,
        &[
            OperationClass::TreeFsWorkspace,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ],
        8_192,
        90,
    );
    assert_eq!(first_run.run_id(), second_run.run_id());
    assert_ne!(
        first_run.commitment().expect("first run identity"),
        second_run.commitment().expect("second run identity")
    );

    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x51));
    let first_situation = situation(&receipt, &first_run, TASK_BASIS, 20);
    let first_frontier = frontier(
        &first_situation,
        &first_run,
        WorkTaskId::from_bytes([0x43; 32]),
    );
    let first_pulse = AgentControlPulse::build(&first_situation, &first_frontier, Some(&first_run))
        .expect("first pulse");
    let first_plan = AgentChangePlan::build(&first_pulse, &first_run, &[], plan_spec(surface))
        .expect("first plan");
    let first = TaskClaimReceipt::admit(
        &first_pulse,
        &first_plan,
        &first_run,
        claim_projection(&first_plan, &first_run, surface),
    )
    .expect("first claim");

    let second_situation = situation(&receipt, &second_run, TASK_BASIS, 20);
    let second_frontier = frontier(
        &second_situation,
        &second_run,
        WorkTaskId::from_bytes([0x44; 32]),
    );
    let second_pulse =
        AgentControlPulse::build(&second_situation, &second_frontier, Some(&second_run))
            .expect("second pulse");
    let second_plan = AgentChangePlan::build(&second_pulse, &second_run, &[], plan_spec(surface))
        .expect("second plan");
    let second = TaskClaimReceipt::admit(
        &second_pulse,
        &second_plan,
        &second_run,
        claim_projection(&second_plan, &second_run, surface),
    )
    .expect("second claim");

    assert_eq!(first.assignee(), second.assignee());
    assert_ne!(first.run_commitment(), second.run_commitment());
    assert!(first.conflicts_with(&second, LogicalTime::new(30)));
}
