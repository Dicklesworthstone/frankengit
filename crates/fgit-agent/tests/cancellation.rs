#![forbid(unsafe_code)]
//! Public-path tests for debt-preserving Intent Run cancellation.

use fgit_agent::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentInstanceId,
    AgentSituationReceipt, AuthorityReadReceipt, CancellationDebtTransfer, CapabilityId, ClassSet,
    EffectClass, EffectId, EffectRecord, EffectTerminalOutcome, EvidenceClass, IntentRun,
    LogicalTime, OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId,
    PlanCheckpointPurpose, PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet,
    PlanSurface, PlanSurfaceKind, RejectedShortcutSet, RunCancellationIntent,
    RunCancellationRefusal, RunCancellationState, RunId, RunReconciliationReport,
    SituationComponent, SituationComponentKind, SituationOmissionReason,
    TaskClaimCancellationOutcome, TaskClaimCancellationProjection, TaskClaimProjection,
    TaskClaimReceipt, TaskPhase, WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem,
    WorkRankingInputs, WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    authority_head_identity, initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{
    EscalationReason, Grade, IdempotencyKey, ObligationClass, ObligationState, ResourceVector,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, PrincipalId,
    RegistryEpoch, RepositoryCommitId, RepositorySequence,
};

const TASK_BASIS: [u8; 32] = [0x44; 32];
const CLAIMED_GENERATION: [u8; 32] = [0x55; 32];
const RELEASED_GENERATION: [u8; 32] = [0x56; 32];

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome root");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed digest"),
    )
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed RCR digest"),
    )
}

fn authority_receipt() -> AuthorityReadReceipt {
    let repository_id = fgit_types::RepositoryId::from_bytes([0x22; 16]);
    let root = outcome_index_root(&[]).expect("empty outcome root");
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
    let expected = authority_head_identity(&head).expect("head identity");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(161));
    let key = HeadKey::new(b"agent-cancellation-test-head".to_vec()).expect("head key");
    let read = match initialize_repository(&store, &key, &head).expect("initialize") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("authenticate receipt");
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("complete receipt");
    assert_eq!(receipt.authority_head_id(), expected);
    receipt
}

fn run(receipt: &AuthorityReadReceipt) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::ExecuteSandboxedProcess,
            OperationClass::ExternalIntegration,
            OperationClass::SubmitEvidence,
            OperationClass::ConsumeBudget,
        ]),
        ResourceVector::from_grades(&[(Grade::Bytes, 16_384), (Grade::CpuMicros, 20_000)]),
        LogicalTime::new(100),
    )
    .expect("run opens")
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
                [u8::try_from(index + 1).expect("component index"); 32],
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
) -> (AgentControlPulse, AgentChangePlan, PlanSurface) {
    let situation = situation(receipt, run, TASK_BASIS, 20);
    let item = WorkItem::new(
        WorkTaskId::from_bytes([0x31; 32]),
        TASK_BASIS,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, Some(run.run_id()), None, true, WorkConflict::Clear),
    );
    let frontier =
        WorkFrontier::build_action_scoped(&situation, vec![item]).expect("eligible frontier");
    let pulse = AgentControlPulse::build(&situation, &frontier, Some(run)).expect("pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let spec = AgentChangePlanSpec::new(
        digest(0x60),
        ClassSet::from_classes(&[
            OperationClass::TreeFsWorkspace,
            OperationClass::ExecuteSandboxedProcess,
            OperationClass::ExternalIntegration,
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
    let plan = AgentChangePlan::build(&pulse, run, &[], spec).expect("complete plan");
    (pulse, plan, surface)
}

fn active_claim(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    pulse: &AgentControlPulse,
    plan: &AgentChangePlan,
    surface: PlanSurface,
) -> (ActiveTaskClaim, AgentSituationReceipt) {
    let projection = TaskClaimProjection::new(
        plan.task_id(),
        plan.plan_id(),
        run.run_id(),
        TASK_BASIS,
        CLAIMED_GENERATION,
        vec![surface],
        LogicalTime::new(25),
        LogicalTime::new(80),
        [0x71; 32],
        digest(0x72),
    );
    let claim = TaskClaimReceipt::admit(pulse, plan, run, projection).expect("claim admitted");
    let latest = situation(receipt, run, CLAIMED_GENERATION, 40);
    let active = claim.activate(&latest, run).expect("claim activated");
    (active, latest)
}

fn claim_resolution(active: ActiveTaskClaim, resolved_at: u64) -> TaskClaimCancellationProjection {
    TaskClaimCancellationProjection::new(
        active.activation_id(),
        active.claim_id(),
        active.plan_id(),
        active.task_id(),
        active.assignee(),
        CLAIMED_GENERATION,
        RELEASED_GENERATION,
        LogicalTime::new(resolved_at),
        TaskClaimCancellationOutcome::Released,
        [0xa1; 32],
        digest(0xa2),
    )
}

fn internal_effect(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    state: ObligationState,
    terminal_outcome: Option<EffectTerminalOutcome>,
    consumed: u64,
) -> EffectRecord {
    EffectRecord {
        effect_id: EffectId::new(1),
        run_id: run.run_id(),
        run_commitment: run.commitment().expect("complete run commitment"),
        agent_instance_id: AgentInstanceId::new(1),
        parent_effect_id: None,
        capability_id: CapabilityId::new(2),
        effect_class: EffectClass::DerivedLocalWrite,
        operation: OperationClass::TreeFsWorkspace,
        input_commitment: [0x81; 32],
        source_authority_receipt: Some(receipt.clone()),
        budget_reserved: ResourceVector::single(Grade::Bytes, 256),
        budget_consumed: ResourceVector::single(Grade::Bytes, consumed),
        external_idempotency_key: None,
        obligation_state: state,
        obligation_class: None,
        terminal_outcome,
        output_commitments: vec![[0x82; 32]],
        reconciliation_evidence: None,
        accepted_at: LogicalTime::new(35),
    }
}

fn external_effect(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    state: ObligationState,
    terminal_outcome: Option<EffectTerminalOutcome>,
) -> EffectRecord {
    EffectRecord {
        effect_id: EffectId::new(2),
        run_id: run.run_id(),
        run_commitment: run.commitment().expect("complete run commitment"),
        agent_instance_id: AgentInstanceId::new(1),
        parent_effect_id: None,
        capability_id: CapabilityId::new(3),
        effect_class: EffectClass::ExternalEffect,
        operation: OperationClass::ExternalIntegration,
        input_commitment: [0x83; 32],
        source_authority_receipt: Some(receipt.clone()),
        budget_reserved: ResourceVector::single(Grade::Bytes, 256),
        budget_consumed: ResourceVector::single(Grade::Bytes, 32),
        external_idempotency_key: Some(IdempotencyKey::new(digest(0x84))),
        obligation_state: state,
        obligation_class: Some(ObligationClass::OutboxEffectPermit),
        terminal_outcome,
        output_commitments: vec![[0x85; 32]],
        reconciliation_evidence: None,
        accepted_at: LogicalTime::new(36),
    }
}

fn cancellation_fixture() -> (
    AuthorityReadReceipt,
    IntentRun,
    ActiveTaskClaim,
    AgentSituationReceipt,
    RunCancellationIntent,
) {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let (pulse, plan, surface) = plan(&receipt, &run);
    let (active, latest) = active_claim(&receipt, &run, &pulse, &plan, surface);
    let initial = RunReconciliationReport::build(
        &run,
        vec![internal_effect(
            &receipt,
            &run,
            ObligationState::Reserved,
            None,
            0,
        )],
        latest.observed_at(),
    )
    .expect("initial complete effect inventory");
    let intent = RunCancellationIntent::request(
        &latest,
        &run,
        initial,
        Some(active),
        AgentInstanceId::new(9),
        digest(0x90),
    )
    .expect("cancellation request");
    (receipt, run, active, latest, intent)
}

#[test]
fn clean_completion_requires_terminal_effects_and_explicit_claim_release() {
    let (receipt, run, active, _latest, intent) = cancellation_fixture();
    let final_report = RunReconciliationReport::build(
        &run,
        vec![internal_effect(
            &receipt,
            &run,
            ObligationState::Aborted,
            Some(EffectTerminalOutcome::Aborted),
            8,
        )],
        LogicalTime::new(50),
    )
    .expect("final complete effect inventory");
    let first = intent
        .complete(
            final_report.clone(),
            Some(claim_resolution(active, 45)),
            Vec::new(),
            Vec::new(),
        )
        .expect("all responsibilities are terminal or released");
    let second = intent
        .complete(
            final_report,
            Some(claim_resolution(active, 45)),
            Vec::new(),
            Vec::new(),
        )
        .expect("same evidence produces same completion");

    assert_eq!(first.completion_id(), second.completion_id());
    assert_eq!(first.cancellation_id(), intent.cancellation_id());
    assert_eq!(first.state(), RunCancellationState::Clean);
    assert_eq!(first.final_reconciliation().counts().aborted(), 1);
    assert_ne!(first.completion_id().as_bytes(), &[0; 32]);
}

#[test]
fn reserved_effect_keeps_cancellation_in_progress() {
    let (receipt, run, active, _latest, intent) = cancellation_fixture();
    let final_report = RunReconciliationReport::build(
        &run,
        vec![internal_effect(
            &receipt,
            &run,
            ObligationState::Reserved,
            None,
            0,
        )],
        LogicalTime::new(50),
    )
    .expect("final complete effect inventory");

    assert_eq!(
        intent
            .complete(
                final_report,
                Some(claim_resolution(active, 45)),
                Vec::new(),
                Vec::new(),
            )
            .expect_err("a live reservation cannot be summarized as cancelled"),
        RunCancellationRefusal::CancellationStillInProgress {
            effect_id: EffectId::new(1),
            action: fgit_agent::EffectResolutionAction::AbortReservation,
        }
    );
}

#[test]
fn accepted_effect_identity_cannot_be_rewritten_during_cancellation() {
    let (receipt, run, active, _latest, intent) = cancellation_fixture();
    let mut changed = internal_effect(
        &receipt,
        &run,
        ObligationState::Aborted,
        Some(EffectTerminalOutcome::Aborted),
        8,
    );
    changed.input_commitment = [0xff; 32];
    let final_report = RunReconciliationReport::build(&run, vec![changed], LogicalTime::new(50))
        .expect("the final snapshot is internally valid but not the frozen effect");

    assert_eq!(
        intent
            .complete(
                final_report,
                Some(claim_resolution(active, 45)),
                Vec::new(),
                Vec::new(),
            )
            .expect_err("immutable effect identity must survive cancellation"),
        RunCancellationRefusal::EffectIdentityChanged {
            effect_id: EffectId::new(1),
            field: "input_commitment",
        }
    );
}

#[test]
fn effect_membership_is_frozen_at_cancellation_request() {
    let (receipt, run, active, _latest, intent) = cancellation_fixture();
    let final_report = RunReconciliationReport::build(
        &run,
        vec![
            internal_effect(
                &receipt,
                &run,
                ObligationState::Aborted,
                Some(EffectTerminalOutcome::Aborted),
                8,
            ),
            external_effect(
                &receipt,
                &run,
                ObligationState::Acknowledged,
                Some(EffectTerminalOutcome::Acknowledged),
            ),
        ],
        LogicalTime::new(50),
    )
    .expect("the expanded inventory is internally valid");

    assert_eq!(
        intent
            .complete(
                final_report,
                Some(claim_resolution(active, 45)),
                Vec::new(),
                Vec::new(),
            )
            .expect_err("new effects after cancellation request are forbidden"),
        RunCancellationRefusal::EffectSetSizeChanged {
            expected: 1,
            observed: 2,
        }
    );
}

#[test]
fn escalation_is_terminal_only_after_matching_owner_transfer() {
    let receipt = authority_receipt();
    let run = run(&receipt);
    let latest = situation(&receipt, &run, CLAIMED_GENERATION, 40);
    let initial = RunReconciliationReport::build(
        &run,
        vec![external_effect(
            &receipt,
            &run,
            ObligationState::DeferredExternally,
            None,
        )],
        latest.observed_at(),
    )
    .expect("initial external-effect inventory");
    let intent = RunCancellationIntent::request(
        &latest,
        &run,
        initial,
        None,
        AgentInstanceId::new(9),
        digest(0x90),
    )
    .expect("cancellation request without a task claim");
    let owner = PrincipalId::from_bytes([0x33; 16]);
    let escalated = RunReconciliationReport::build(
        &run,
        vec![external_effect(
            &receipt,
            &run,
            ObligationState::Escalated,
            Some(EffectTerminalOutcome::Escalated {
                owner,
                reason: EscalationReason::IndeterminateDelivery,
            }),
        )],
        LogicalTime::new(50),
    )
    .expect("escalated final inventory");

    assert_eq!(
        intent
            .complete(escalated.clone(), None, Vec::new(), Vec::new())
            .expect_err("escalation without ownership transfer remains debt"),
        RunCancellationRefusal::MissingDebtTransfer {
            effect_id: EffectId::new(2),
        }
    );

    let completion = intent
        .complete(
            escalated,
            None,
            vec![CancellationDebtTransfer::new(
                EffectId::new(2),
                owner,
                digest(0xb1),
            )],
            Vec::new(),
        )
        .expect("matching named-owner transfer completes automation");
    assert_eq!(
        completion.state(),
        RunCancellationState::DebtTransferred { count: 1 }
    );
    assert_eq!(completion.debt_transfers()[0].owner(), owner);
}
