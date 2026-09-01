#![forbid(unsafe_code)]
//! Public-path tests for evidence-grounded outcome learning.

use fgit_agent::{
    ActionPreconditionSet, ActionStep, ActionStepId, ActiveTaskClaim, AgentActionPacket,
    AgentActionPacketSpec, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse,
    AgentSituationReceipt, AuthorityReadReceipt, ClassSet, ConfirmedOwnership, EvidenceClass,
    EvidenceRecordRef, FailedHypothesis, IntentRun, LearningPhase, LearningRequirementOutcome,
    LearningResourceObservation, LearningTerminalOutcome, LogicalTime, OperationClass,
    OutcomeLearningRecord, OutcomeLearningRecordSpec, OutcomeLearningRefusal, PartyFacts,
    PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose,
    PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet, PlanSurface,
    PlanSurfaceKind, RejectedShortcutSet, RequirementDisposition, ReusablePattern, RunId,
    SITUATION_COMPONENT_COUNT, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskClaimProjection, TaskClaimReceipt, TaskPhase,
    VerifierAttestation, WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem,
    WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{IdentityDomain, NativeObjectIdentity};
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositorySequence,
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(191));
    let head_key =
        HeadKey::new(b"agent-learning-test-head".to_vec()).expect("bounded head key");
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
    .expect("complete authority-bound situation")
}

struct Fixture {
    run: IntentRun,
    activation: AgentSituationReceipt,
    plan: AgentChangePlan,
    packet: AgentActionPacket,
    surface: PlanSurface,
}

fn fixture(requires_independent_verifier: bool) -> Fixture {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let planning_situation = situation(&receipt, &run, TASK_BASIS, 20);
    let item = WorkItem::new(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(
            0,
            Some(run.run_id()),
            None,
            true,
            WorkConflict::Clear,
        ),
    );
    let frontier = WorkFrontier::build_action_scoped(&planning_situation, vec![item])
        .expect("task is eligible");
    let pulse = AgentControlPulse::build(&planning_situation, &frontier, Some(&run))
        .expect("live run makes an actionable pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let plan_spec = AgentChangePlanSpec::new(
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
        REQUIREMENT_ID,
        EvidenceClass::Executed,
        digest(0x67),
        requires_independent_verifier,
    )]);
    let plan = AgentChangePlan::build(&pulse, &run, &[], plan_spec)
        .expect("complete change plan");
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
    let active_claim: ActiveTaskClaim = claim
        .activate(&activation, &run)
        .expect("post-claim generation activates the claim");
    let packet_spec = AgentActionPacketSpec::new(
        vec![ActionStep::new(
            ActionStepId::from_bytes([0x81; 32]),
            OperationClass::TreeFsWorkspace,
            surface,
            digest(0x82),
            digest(0x83),
            ResourceVector::single(Grade::Bytes, 512),
            None,
        )],
        ActionPreconditionSet::MANDATORY,
        digest(0x84),
        digest(0x85),
        digest(0x86),
        [0x87; 32],
    );
    let packet = AgentActionPacket::build(
        &activation,
        &plan,
        active_claim,
        &run,
        &[],
        packet_spec,
    )
    .expect("bounded Level-1 packet");
    Fixture {
        run,
        activation,
        plan,
        packet,
        surface,
    }
}

fn facts(tag: u128) -> PartyFacts {
    PartyFacts {
        workspace: Some(tag),
        credentials: Some(tag + 1),
        model_harness: Some(tag + 2),
        context: Some(tag + 3),
        oracle: Some(tag + 4),
        sponsor: Some(tag + 5),
        human: Some(tag + 6),
    }
}

fn evidence(artifact: u128) -> EvidenceRecordRef {
    EvidenceRecordRef {
        class: EvidenceClass::Executed,
        artifact,
        refresh_side: None,
    }
}

fn base_spec(
    disposition: RequirementDisposition,
    evidence_rows: Vec<EvidenceRecordRef>,
    verifier_ids: Vec<u128>,
    producer: PartyFacts,
) -> OutcomeLearningRecordSpec {
    OutcomeLearningRecordSpec::new(
        LearningTerminalOutcome::Completed {
            result_root: digest(0x90),
        },
        LogicalTime::new(40),
        producer,
        digest(0x91),
        vec![digest(0x93), digest(0x92)],
    )
    .with_requirement_outcomes(vec![LearningRequirementOutcome::new(
        REQUIREMENT_ID,
        disposition,
        evidence_rows,
        verifier_ids,
        digest(0x94),
    )])
    .with_negative_evidence_refs(vec![digest(0x96), digest(0x95)])
}

fn rich_spec(surface: PlanSurface) -> OutcomeLearningRecordSpec {
    base_spec(
        RequirementDisposition::SatisfiedWithEvidence,
        vec![evidence(2), evidence(1)],
        Vec::new(),
        facts(10),
    )
    .with_confirmed_ownership(vec![ConfirmedOwnership::new(surface, digest(0xa0))])
    .with_failed_hypotheses(vec![FailedHypothesis::new(
        digest(0xa1),
        EvidenceRecordRef {
            class: EvidenceClass::Observed,
            artifact: 3,
            refresh_side: None,
        },
        digest(0xa2),
        vec![digest(0xa4), digest(0xa3)],
    )])
    .with_resource_observations(vec![LearningResourceObservation::new(
        digest(0xa5),
        LearningPhase::Execute,
        ResourceVector::single(Grade::Bytes, 256),
        digest(0xa6),
    )])
    .with_reusable_patterns(vec![ReusablePattern::new(
        digest(0xa7),
        digest(0xa8),
        vec![digest(0xaa), digest(0xa9)],
        ResourceVector::single(Grade::Bytes, 128),
        digest(0xab),
    )])
}

#[test]
fn learning_record_is_deterministic_and_preserves_bounded_evidence() {
    let fixture = fixture(false);
    let first = OutcomeLearningRecord::build(
        &fixture.activation,
        &fixture.packet,
        &fixture.plan,
        &fixture.run,
        rich_spec(fixture.surface),
    )
    .expect("evidence-grounded record");
    let second = OutcomeLearningRecord::build(
        &fixture.activation,
        &fixture.packet,
        &fixture.plan,
        &fixture.run,
        rich_spec(fixture.surface),
    )
    .expect("same semantic sets make the same record");

    assert_eq!(first.learning_id(), second.learning_id());
    assert_eq!(first.situation_id(), fixture.activation.situation_id());
    assert_eq!(first.action_packet_id(), fixture.packet.packet_id());
    assert_eq!(first.plan_id(), fixture.plan.plan_id());
    assert_eq!(first.source_run_id(), fixture.run.run_id());
    assert_eq!(first.task_id(), fixture.plan.task_id());
    assert_eq!(first.requirement_outcomes().len(), 1);
    assert_eq!(first.discriminating_evidence().len(), 2);
    assert_eq!(first.confirmed_ownership().len(), 1);
    assert_eq!(first.failed_hypotheses().len(), 1);
    assert_eq!(first.reusable_patterns().len(), 1);
    assert_eq!(
        first.total_resources_observed(),
        ResourceVector::single(Grade::Bytes, 256)
    );
    assert_ne!(first.learning_id().as_bytes(), &[0; 32]);
}

#[test]
fn completed_requirement_cannot_be_supported_by_confident_prose_or_no_evidence() {
    let fixture = fixture(false);
    let spec = base_spec(
        RequirementDisposition::SatisfiedWithEvidence,
        Vec::new(),
        Vec::new(),
        facts(10),
    );

    assert_eq!(
        OutcomeLearningRecord::build(
            &fixture.activation,
            &fixture.packet,
            &fixture.plan,
            &fixture.run,
            spec,
        )
        .expect_err("satisfaction requires an artifact-linked record"),
        OutcomeLearningRefusal::SatisfiedRequirementWithoutEvidence {
            requirement_id: REQUIREMENT_ID,
        }
    );
}

#[test]
fn completed_outcome_cannot_hide_an_unsatisfied_requirement() {
    let fixture = fixture(false);
    let spec = base_spec(
        RequirementDisposition::Unsatisfied,
        Vec::new(),
        Vec::new(),
        facts(10),
    );

    assert_eq!(
        OutcomeLearningRecord::build(
            &fixture.activation,
            &fixture.packet,
            &fixture.plan,
            &fixture.run,
            spec,
        )
        .expect_err("completed means every applicable requirement is met"),
        OutcomeLearningRefusal::CompletedWithUnmetRequirement {
            requirement_id: REQUIREMENT_ID,
            disposition: RequirementDisposition::Unsatisfied,
        }
    );
}

#[test]
fn ownership_and_measured_cost_remain_inside_the_plan() {
    let fixture = fixture(false);
    let outside = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0xff));
    let ownership = rich_spec(fixture.surface)
        .with_confirmed_ownership(vec![ConfirmedOwnership::new(outside, digest(0xa0))]);
    assert_eq!(
        OutcomeLearningRecord::build(
            &fixture.activation,
            &fixture.packet,
            &fixture.plan,
            &fixture.run,
            ownership,
        )
        .expect_err("learning cannot expand the claimed ownership surface"),
        OutcomeLearningRefusal::OwnershipOutsidePlan { surface: outside }
    );

    let excessive = rich_spec(fixture.surface).with_resource_observations(vec![
        LearningResourceObservation::new(
            digest(0xa5),
            LearningPhase::Execute,
            ResourceVector::single(Grade::Bytes, 4_097),
            digest(0xa6),
        ),
    ]);
    assert!(matches!(
        OutcomeLearningRecord::build(
            &fixture.activation,
            &fixture.packet,
            &fixture.plan,
            &fixture.run,
            excessive,
        ),
        Err(OutcomeLearningRefusal::ResourceTotalExceedsPlan { .. })
    ));
}

#[test]
fn independent_verification_is_classified_not_self_declared() {
    let fixture = fixture(true);
    let producer = facts(10);
    let shared = VerifierAttestation {
        verifier: 42,
        facts: producer,
        upheld: true,
    };
    let shared_spec = base_spec(
        RequirementDisposition::SatisfiedWithEvidence,
        vec![evidence(1)],
        vec![42],
        producer,
    )
    .with_verifier_attestations(vec![shared]);
    assert_eq!(
        OutcomeLearningRecord::build(
            &fixture.activation,
            &fixture.packet,
            &fixture.plan,
            &fixture.run,
            shared_spec,
        )
        .expect_err("same execution facts cannot satisfy independence"),
        OutcomeLearningRefusal::IndependentVerifierMissing {
            requirement_id: REQUIREMENT_ID,
        }
    );

    let independent = VerifierAttestation {
        verifier: 42,
        facts: facts(100),
        upheld: true,
    };
    let independent_spec = base_spec(
        RequirementDisposition::SatisfiedWithEvidence,
        vec![evidence(1)],
        vec![42],
        producer,
    )
    .with_verifier_attestations(vec![independent]);
    let record = OutcomeLearningRecord::build(
        &fixture.activation,
        &fixture.packet,
        &fixture.plan,
        &fixture.run,
        independent_spec,
    )
    .expect("fully different recorded facts satisfy the independent requirement");
    assert!(record.verifier_classifications()[0].is_fully_independent());
}
