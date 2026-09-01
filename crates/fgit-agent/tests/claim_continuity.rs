#![forbid(unsafe_code)]
//! Public-path tests for active-claim and action-packet continuity.

use fgit_agent::{
    ActionPreconditionSet, ActionStep, ActionStepId, ActiveClaimContinuityReceipt,
    ActiveClaimContinuityRefusal, ActiveTaskClaim, AgentActionPacket,
    AgentActionPacketContinuation, AgentActionPacketSpec, AgentChangePlan, AgentChangePlanSpec,
    AgentControlPulse, AgentSituationReceipt, AuthorityReadReceipt, ClassSet, EvidenceClass,
    IntentRun, LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet,
    PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RunId, SITUATION_COMPONENT_COUNT,
    SituationComponent, SituationComponentKind, SituationOmissionReason, TaskClaimProjection,
    TaskClaimReceipt, TaskPhase, WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem,
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(201));
    let head_key =
        HeadKey::new(b"agent-claim-continuity-test-head".to_vec()).expect("bounded head key");
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
    search_generation: u8,
    observed_at: u64,
) -> AgentSituationReceipt {
    let components = std::array::from_fn(|index| {
        let kind = SituationComponentKind::ALL[index];
        if kind == SituationComponentKind::TaskProjection {
            SituationComponent::observed(kind, receipt.authority_head_id(), task_generation)
        } else if kind == SituationComponentKind::Search {
            SituationComponent::observed(
                kind,
                receipt.authority_head_id(),
                [search_generation; 32],
            )
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
    receipt: AuthorityReadReceipt,
    run: IntentRun,
    active_claim: ActiveTaskClaim,
    activation: AgentSituationReceipt,
    packet: AgentActionPacket,
}

fn fixture() -> Fixture {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let planning = situation(&receipt, &run, TASK_BASIS, 0x71, 20);
    let task_id = WorkTaskId::from_bytes([0x31; 32]);
    let item = WorkItem::new(
        task_id,
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
    let frontier = WorkFrontier::build_action_scoped(&planning, vec![item])
        .expect("task is eligible");
    let pulse = AgentControlPulse::build(&planning, &frontier, Some(&run))
        .expect("live run makes an actionable pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let requirement_id = PlanRequirementId::from_bytes([0x66; 32]);
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
        requirement_id,
        EvidenceClass::Executed,
        digest(0x67),
        false,
    )]);
    let plan = AgentChangePlan::build(&pulse, &run, &[], plan_spec)
        .expect("complete change plan");
    let claim_projection = TaskClaimProjection::new(
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
    let claim = TaskClaimReceipt::admit(&pulse, &plan, &run, claim_projection)
        .expect("task claim admitted");
    let activation = situation(&receipt, &run, CLAIMED_GENERATION, 0x74, 30);
    let active_claim = claim
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
    .expect("bounded Level-1 action packet");
    Fixture {
        receipt,
        run,
        active_claim,
        activation,
        packet,
    }
}

#[test]
fn time_only_continuity_and_packet_binding_are_deterministic() {
    let fixture = fixture();
    let later = situation(
        &fixture.receipt,
        &fixture.run,
        CLAIMED_GENERATION,
        0x74,
        40,
    );
    let first = ActiveClaimContinuityReceipt::establish(
        fixture.active_claim,
        &fixture.activation,
        &later,
        &fixture.run,
    )
    .expect("only observation time advanced");
    let second = ActiveClaimContinuityReceipt::establish(
        fixture.active_claim,
        &fixture.activation,
        &later,
        &fixture.run,
    )
    .expect("same endpoints make the same receipt");
    assert_eq!(first.receipt_id(), second.receipt_id());
    assert_eq!(first.from_situation_id(), fixture.activation.situation_id());
    assert_eq!(first.to_situation_id(), later.situation_id());
    assert_eq!(first.task_projection_generation(), CLAIMED_GENERATION);

    let continuation = AgentActionPacketContinuation::build(
        &fixture.packet,
        first,
        &later,
        fixture.active_claim,
        &fixture.run,
        digest(0x90),
    )
    .expect("continuity binds the original packet to the later situation");
    let identical = AgentActionPacketContinuation::build(
        &fixture.packet,
        second,
        &later,
        fixture.active_claim,
        &fixture.run,
        digest(0x90),
    )
    .expect("same evidence makes the same continuation");
    assert_eq!(continuation.continuation_id(), identical.continuation_id());
    assert_eq!(continuation.action_packet_id(), fixture.packet.packet_id());
    assert_eq!(continuation.to_situation_id(), later.situation_id());
    assert_eq!(continuation.observed_at(), LogicalTime::new(40));
    assert_ne!(continuation.continuation_id().as_bytes(), &[0; 32]);
}

#[test]
fn any_context_generation_change_invalidates_continuity() {
    let fixture = fixture();
    let changed_search = situation(
        &fixture.receipt,
        &fixture.run,
        CLAIMED_GENERATION,
        0x75,
        40,
    );

    assert_eq!(
        ActiveClaimContinuityReceipt::establish(
            fixture.active_claim,
            &fixture.activation,
            &changed_search,
            &fixture.run,
        )
        .expect_err("unchanged task state is insufficient when context changed"),
        ActiveClaimContinuityRefusal::ComponentChanged {
            kind: SituationComponentKind::Search,
        }
    );
}

#[test]
fn observation_must_advance_strictly() {
    let fixture = fixture();
    let same_time = situation(
        &fixture.receipt,
        &fixture.run,
        CLAIMED_GENERATION,
        0x74,
        30,
    );

    assert_eq!(
        ActiveClaimContinuityReceipt::establish(
            fixture.active_claim,
            &fixture.activation,
            &same_time,
            &fixture.run,
        )
        .expect_err("an identical logical instant proves no continuation"),
        ActiveClaimContinuityRefusal::ObservationDidNotAdvance {
            from: LogicalTime::new(30),
            to: LogicalTime::new(30),
        }
    );
}

#[test]
fn expired_claim_cannot_be_revived_by_an_unchanged_snapshot() {
    let fixture = fixture();
    let after_expiry = situation(
        &fixture.receipt,
        &fixture.run,
        CLAIMED_GENERATION,
        0x74,
        80,
    );

    assert_eq!(
        ActiveClaimContinuityReceipt::establish(
            fixture.active_claim,
            &fixture.activation,
            &after_expiry,
            &fixture.run,
        )
        .expect_err("claim expiry is exclusive"),
        ActiveClaimContinuityRefusal::ClaimExpired {
            expires_at: LogicalTime::new(80),
            observed_at: LogicalTime::new(80),
        }
    );
}
