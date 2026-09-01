#![forbid(unsafe_code)]
//! Public-path tests for task mutation CAS and ambiguous-write reconciliation.

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentSituationReceipt,
    AuthorityBoundTaskClaimApplication, AuthorityBoundTaskProjectionSnapshot,
    AuthorityReadReceipt, ClassSet, EvidenceClass, IntentRun, LogicalTime, OperationClass,
    PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose,
    PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet, PlanSurface,
    PlanSurfaceKind, RejectedShortcutSet, RunId, SituationComponent,
    SituationComponentKind, SituationOmissionReason, TaskProjectionAssignment,
    TaskProjectionMutationEnvelope, TaskProjectionPersistedState,
    TaskProjectionPersistenceDecision, TaskProjectionPersistenceRefusal, TaskPhase,
    WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs,
    WorkTaskId,
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
    let expected = authority_head_identity(&head).expect("head identity");
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(601));
    let key = HeadKey::new(b"task-persistence-test-head".to_vec()).expect("bounded head key");
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
    .expect("complete authority-bound situation")
}

fn pulse_and_plan(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    snapshot: &AuthorityBoundTaskProjectionSnapshot,
) -> (AgentControlPulse, AgentChangePlan) {
    let situation = situation(receipt, run, *snapshot.generation());
    let item = WorkItem::new(
        snapshot.task_id(),
        *snapshot.generation(),
        snapshot.phase(),
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, None, None, true, WorkConflict::Clear),
    );
    let frontier = WorkFrontier::build_action_scoped(&situation, vec![item])
        .expect("task is eligible");
    let pulse = AgentControlPulse::build(&situation, &frontier, Some(run))
        .expect("live run makes an actionable pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
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
    let plan = AgentChangePlan::build(&pulse, run, &[], spec)
        .expect("complete change plan");
    (pulse, plan)
}

struct Fixture {
    application: AuthorityBoundTaskClaimApplication,
}

fn claim_application(adapter: u8, evidence: u8) -> AuthorityBoundTaskClaimApplication {
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
    .expect("valid repository-scoped snapshot");
    let (pulse, plan) = pulse_and_plan(&receipt, &run, &snapshot);
    snapshot
        .claim(
            &pulse,
            &plan,
            &run,
            LogicalTime::new(25),
            LogicalTime::new(80),
            [adapter; 32],
            digest(evidence),
        )
        .expect("repository-scoped claim")
}

fn fixture() -> Fixture {
    Fixture {
        application: claim_application(0x71, 0x72),
    }
}

fn predecessor_state(
    envelope: TaskProjectionMutationEnvelope,
) -> TaskProjectionPersistedState {
    TaskProjectionPersistedState::new(
        envelope.repository_id(),
        envelope.task_id(),
        *envelope.before_snapshot_id().as_bytes(),
        envelope.previous_generation(),
        None,
        None,
        None,
        LogicalTime::new(26),
    )
}

fn successor_state(
    envelope: TaskProjectionMutationEnvelope,
) -> TaskProjectionPersistedState {
    TaskProjectionPersistedState::new(
        envelope.repository_id(),
        envelope.task_id(),
        *envelope.after_snapshot_id().as_bytes(),
        envelope.resulting_generation(),
        Some(*envelope.transition_id().as_bytes()),
        Some(envelope.inner_transition_id()),
        Some(envelope.evidence_root()),
        LogicalTime::new(26),
    )
}

#[test]
fn unchanged_predecessor_is_a_safe_exact_retry() {
    let fixture = fixture();
    let envelope = TaskProjectionMutationEnvelope::from_claim(&fixture.application)
        .expect("complete mutation envelope");
    let observed = predecessor_state(envelope);

    assert_eq!(
        envelope
            .reconcile(Some(&observed))
            .expect("unchanged predecessor is not an ambiguous success"),
        TaskProjectionPersistenceDecision::RetrySafe {
            envelope_id: envelope.envelope_id(),
            current_snapshot_id: *envelope.before_snapshot_id().as_bytes(),
            current_generation: envelope.previous_generation(),
        }
    );
}

#[test]
fn exact_successor_and_metadata_make_a_deterministic_receipt() {
    let fixture = fixture();
    let envelope = TaskProjectionMutationEnvelope::from_claim(&fixture.application)
        .expect("complete mutation envelope");
    let observed = successor_state(envelope);

    let first = envelope
        .reconcile(Some(&observed))
        .expect("exact successor is confirmed");
    let second = envelope
        .reconcile(Some(&observed))
        .expect("identical reread is deterministic");
    assert_eq!(first, second);

    let TaskProjectionPersistenceDecision::Confirmed(receipt) = first else {
        panic!("exact successor must produce a receipt")
    };
    assert_eq!(receipt.envelope_id(), envelope.envelope_id());
    assert_eq!(receipt.snapshot_id(), *envelope.after_snapshot_id().as_bytes());
    assert_eq!(receipt.generation(), envelope.resulting_generation());
    assert_eq!(receipt.transition_id(), *envelope.transition_id().as_bytes());
    assert_ne!(receipt.receipt_id().as_bytes(), &[0; 32]);
}

#[test]
fn another_successor_is_a_conflict_not_a_retry_or_success() {
    let fixture = fixture();
    let envelope = TaskProjectionMutationEnvelope::from_claim(&fixture.application)
        .expect("complete mutation envelope");
    let observed = TaskProjectionPersistedState::new(
        envelope.repository_id(),
        envelope.task_id(),
        [0xa1; 32],
        [0xa2; 32],
        Some([0xa3; 32]),
        Some([0xa4; 32]),
        Some(digest(0xa5)),
        LogicalTime::new(26),
    );

    assert_eq!(
        envelope
            .reconcile(Some(&observed))
            .expect("a conflicting row is a typed decision"),
        TaskProjectionPersistenceDecision::Conflict {
            envelope_id: envelope.envelope_id(),
            current_snapshot_id: [0xa1; 32],
            current_generation: [0xa2; 32],
        }
    );
}

#[test]
fn exact_successor_without_transition_metadata_fails_closed() {
    let fixture = fixture();
    let envelope = TaskProjectionMutationEnvelope::from_claim(&fixture.application)
        .expect("complete mutation envelope");
    let observed = TaskProjectionPersistedState::new(
        envelope.repository_id(),
        envelope.task_id(),
        *envelope.after_snapshot_id().as_bytes(),
        envelope.resulting_generation(),
        None,
        Some(envelope.inner_transition_id()),
        Some(envelope.evidence_root()),
        LogicalTime::new(26),
    );

    assert_eq!(
        envelope
            .reconcile(Some(&observed))
            .expect_err("object presence without transition identity is not proof"),
        TaskProjectionPersistenceRefusal::SuccessorTransitionMissing
    );
}

#[test]
fn substituted_evidence_on_the_exact_successor_is_refused() {
    let fixture = fixture();
    let envelope = TaskProjectionMutationEnvelope::from_claim(&fixture.application)
        .expect("complete mutation envelope");
    let observed = TaskProjectionPersistedState::new(
        envelope.repository_id(),
        envelope.task_id(),
        *envelope.after_snapshot_id().as_bytes(),
        envelope.resulting_generation(),
        Some(*envelope.transition_id().as_bytes()),
        Some(envelope.inner_transition_id()),
        Some(digest(0xff)),
        LogicalTime::new(26),
    );

    assert_eq!(
        envelope
            .reconcile(Some(&observed))
            .expect_err("successor evidence cannot be substituted"),
        TaskProjectionPersistenceRefusal::SuccessorEvidenceMismatch {
            expected: envelope.evidence_root(),
            observed: digest(0xff),
        }
    );
}

#[test]
fn logical_successor_is_independent_from_adapter_and_evidence_identity() {
    let first = claim_application(0x71, 0x72);
    let second = claim_application(0x73, 0x74);

    assert_eq!(first.snapshot().generation(), second.snapshot().generation());
    assert_eq!(first.snapshot().snapshot_id(), second.snapshot().snapshot_id());
    assert_ne!(first.transition().transition_id(), second.transition().transition_id());
    assert_ne!(first.projection().adapter_identity(), second.projection().adapter_identity());
    assert_ne!(
        first.projection().claim_evidence_root(),
        second.projection().claim_evidence_root()
    );
}
