#![forbid(unsafe_code)]
//! Public-path tests for descendant-authority handoff acceptance.

use fgit_agent::{
    ActiveTaskClaim, AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentHandoffCapsule,
    AgentHandoffCapsuleSpec, AgentInstanceId, AgentSituationReceipt, AuthorityReadReceipt,
    ClassSet, EvidenceClass, HandoffAcceptanceRefusal, HandoffAuthorityRelation,
    HandoffCapabilityAttenuation, HandoffTargetResolution, IntentRun, LogicalTime, OperationClass,
    PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose, PlanEvidenceRequirement,
    PlanRequirementId, PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcutSet,
    RequirementDisposition, RunId, RunReconciliationReport, SituationComponent,
    SituationComponentKind, SituationOmissionReason, TaskClaimProjection, TaskClaimReceipt,
    TaskPhase, WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs,
    WorkTaskId,
};
use fgit_authority::{
    AuthorityStore, CasOutcome, HeadInit, HeadKey, HeadRead, MemoryAuthorityStore, PutOutcome,
    StoreInstanceId, authority_head_identity, body_key, initialize_repository,
    read_current_authority_head_descendant,
};
use fgit_codec::{RepositoryAuthorityHeadBody, encode_body};
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId,
    RepositoryId,
};

const TASK_BASIS: [u8; 32] = [0x44; 32];
const CLAIMED_GENERATION: [u8; 32] = [0x55; 32];
const TARGET: [u8; 32] = [0x77; 32];

fn digest(marker: u8) -> Digest {
    Digest::new(
        IdentityDomain::RepositoryAuthorityHead.algorithm().id(),
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

fn head_key() -> HeadKey {
    HeadKey::new(b"agent-handoff-descendant-test".to_vec()).expect("bounded head key")
}

fn initialize(store: &MemoryAuthorityStore, key: &HeadKey, value: &RepositoryAuthorityHeadBody) {
    assert!(matches!(
        initialize_repository(store, key, value).expect("initialize authority head"),
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
    let immutable_key =
        body_key(IdentityDomain::RepositoryAuthorityHead, &next).expect("successor immutable key");
    let bytes = encode_body(&next).expect("successor encodes");
    assert!(matches!(
        store
            .put_if_absent(&immutable_key, &bytes)
            .expect("stage successor body"),
        PutOutcome::Created | PutOutcome::IdenticalRetry
    ));
    let HeadRead::Present(current) = store.read_head(key).expect("read current head") else {
        panic!("initialized head must be present");
    };
    assert!(matches!(
        store
            .compare_exchange_head(key, current.token(), next.generation, &bytes)
            .expect("advance head"),
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
    let HeadRead::Present(read) = store.read_head(key).expect("read head") else {
        panic!("head must be present");
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("store authenticates its head receipt");
    AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(verified_at),
        [profile; 32],
    )
    .expect("complete agent authority receipt")
}

fn run(receipt: &AuthorityReadReceipt, run_id: u128, bytes: u64, expiry: u64) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(run_id),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, bytes),
        LogicalTime::new(expiry),
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

fn source_capsule(receipt: &AuthorityReadReceipt, source: &IntentRun) -> AgentHandoffCapsule {
    let planning = situation(receipt, source, TASK_BASIS, 20);
    let task_id = WorkTaskId::from_bytes([0x31; 32]);
    let item = WorkItem::new(
        task_id,
        TASK_BASIS,
        TaskPhase::Open,
        WorkRankingInputs::new(1, 2, 3),
        WorkEligibilityInputs::new(0, Some(source.run_id()), None, true, WorkConflict::Clear),
    );
    let frontier =
        WorkFrontier::build_action_scoped(&planning, vec![item]).expect("eligible frontier");
    let pulse =
        AgentControlPulse::build(&planning, &frontier, Some(source)).expect("actionable pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let plan_spec = AgentChangePlanSpec::new(
        digest(0x60),
        ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
        ResourceVector::single(Grade::Bytes, 4_096),
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
    let plan = AgentChangePlan::build(&pulse, source, &[], plan_spec).expect("complete plan");
    let claim_projection = TaskClaimProjection::new(
        task_id,
        plan.plan_id(),
        source.run_id(),
        TASK_BASIS,
        CLAIMED_GENERATION,
        vec![surface],
        LogicalTime::new(25),
        LogicalTime::new(80),
        [0x71; 32],
        digest(0x72),
    );
    let claim = TaskClaimReceipt::admit(&pulse, &plan, source, claim_projection)
        .expect("source claim receipt");
    let activation = situation(receipt, source, CLAIMED_GENERATION, 30);
    let active: ActiveTaskClaim = claim
        .activate(&activation, source)
        .expect("source claim activation");
    let reconciliation =
        RunReconciliationReport::build(source, Vec::new(), activation.observed_at())
            .expect("complete empty effect inventory");
    let handoff_spec = AgentHandoffCapsuleSpec::new(
        AgentInstanceId::new(1),
        TARGET,
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
    .with_requested_next_actions(vec![digest(0x93)]);
    AgentHandoffCapsule::build(
        &activation,
        &plan,
        active,
        source,
        reconciliation,
        handoff_spec,
    )
    .expect("complete source handoff capsule")
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

struct Fixture {
    store: MemoryAuthorityStore,
    key: HeadKey,
    genesis: RepositoryAuthorityHeadBody,
    descendant: RepositoryAuthorityHeadBody,
    source_receipt: AuthorityReadReceipt,
    receiver_receipt: AuthorityReadReceipt,
    source: IntentRun,
    receiver: IntentRun,
    capsule: AgentHandoffCapsule,
    receiver_situation: AgentSituationReceipt,
}

fn fixture(store_id: u64) -> Fixture {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let key = head_key();
    let genesis = head(RepositoryId::from_bytes([0x22; 16]), 1, None, 0x11);
    initialize(&store, &key, &genesis);
    let source_receipt = authority_receipt(&store, &key, 10, 0x51);
    let source = run(&source_receipt, 7, 16_384, 100);
    let capsule = source_capsule(&source_receipt, &source);
    let descendant = advance(&store, &key, &genesis, 0x21);
    let receiver_receipt = authority_receipt(&store, &key, 40, 0x52);
    let receiver = run(&receiver_receipt, 8, 512, 65);
    let receiver_situation = situation(&receiver_receipt, &receiver, CLAIMED_GENERATION, 45);
    Fixture {
        store,
        key,
        genesis,
        descendant,
        source_receipt,
        receiver_receipt,
        source,
        receiver,
        capsule,
        receiver_situation,
    }
}

#[test]
fn exact_descendant_proof_enables_deterministic_acceptance() {
    let fixture = fixture(181);
    assert_eq!(fixture.source.run_id(), RunId::new(7));
    let current = read_current_authority_head_descendant(
        &fixture.store,
        &fixture.key,
        fixture.genesis.repository_id,
        head_id(&fixture.genesis),
        fixture.genesis.generation,
        1,
    )
    .expect("current head descends exactly from source head");
    let ancestry = current.ancestry();

    assert_eq!(
        fixture
            .capsule
            .accept(
                &fixture.receiver_situation,
                &fixture.receiver,
                AgentInstanceId::new(2),
                target_resolution(&fixture.receiver),
            )
            .expect_err("later head requires explicit ancestry"),
        HandoffAcceptanceRefusal::AuthorityHistoryWitnessRequired
    );

    let first = fixture
        .capsule
        .accept_at_descendant_head(
            &fixture.receiver_situation,
            &fixture.receiver,
            AgentInstanceId::new(2),
            target_resolution(&fixture.receiver),
            ancestry,
        )
        .expect("exact descendant proof permits acceptance");
    let second = fixture
        .capsule
        .accept_at_descendant_head(
            &fixture.receiver_situation,
            &fixture.receiver,
            AgentInstanceId::new(2),
            target_resolution(&fixture.receiver),
            ancestry,
        )
        .expect("same facts produce the same acceptance");

    assert_eq!(first.acceptance_id(), second.acceptance_id());
    assert_eq!(
        first.authority_relation(),
        HandoffAuthorityRelation::DescendantAuthenticatedHead
    );
    assert_eq!(first.authority_ancestry(), Some(ancestry));
    assert_eq!(
        first.receiver_run_commitment(),
        fixture
            .receiver
            .commitment()
            .expect("complete receiver run commitment")
    );
    assert_eq!(
        first.receiver_situation_id(),
        fixture.receiver_situation.situation_id()
    );
    assert_eq!(ancestry.descendant_head_id(), head_id(&fixture.descendant));
    assert_ne!(first.acceptance_id().as_bytes(), &[0; 32]);
}

#[test]
fn ancestry_for_the_wrong_source_head_is_refused() {
    let fixture = fixture(182);
    let current = read_current_authority_head_descendant(
        &fixture.store,
        &fixture.key,
        fixture.descendant.repository_id,
        head_id(&fixture.descendant),
        fixture.descendant.generation,
        0,
    )
    .expect("current head is its own zero-hop descendant");
    let ancestry = current.ancestry();

    assert_eq!(
        fixture
            .capsule
            .accept_at_descendant_head(
                &fixture.receiver_situation,
                &fixture.receiver,
                AgentInstanceId::new(2),
                target_resolution(&fixture.receiver),
                ancestry,
            )
            .expect_err(
                "a current-head proof for another ancestor proves nothing about the capsule"
            ),
        HandoffAcceptanceRefusal::AncestryAncestorMismatch {
            expected_head: fixture.source_receipt.authority_head_id(),
            observed_head: ancestry.ancestor_head_id(),
            expected_generation: fixture.source_receipt.authority_head_generation(),
            observed_generation: ancestry.ancestor_generation(),
        }
    );
}

#[test]
fn ancestry_is_bound_to_the_receivers_exact_current_slot_token() {
    let fixture = fixture(183);
    let current = read_current_authority_head_descendant(
        &fixture.store,
        &fixture.key,
        fixture.genesis.repository_id,
        head_id(&fixture.genesis),
        fixture.genesis.generation,
        1,
    )
    .expect("original store proves the descendant path");
    let ancestry = current.ancestry();

    let other_store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(184));
    initialize(&other_store, &fixture.key, &fixture.descendant);
    let other_receipt = authority_receipt(&other_store, &fixture.key, 40, 0x52);
    let other_receiver = run(&other_receipt, 8, 512, 65);
    let other_situation = situation(&other_receipt, &other_receiver, CLAIMED_GENERATION, 45);

    assert_eq!(
        fixture
            .capsule
            .accept_at_descendant_head(
                &other_situation,
                &other_receiver,
                AgentInstanceId::new(2),
                target_resolution(&other_receiver),
                ancestry,
            )
            .expect_err("a same-body read from another store is not the proved current slot"),
        HandoffAcceptanceRefusal::AncestryDescendantTokenMismatch {
            expected: other_receipt.backend_version_token(),
            observed: ancestry.descendant_version_token(),
        }
    );
}

#[test]
fn same_id_receiver_run_substitution_is_refused_before_scope_checks() {
    let fixture = fixture(185);
    let current = read_current_authority_head_descendant(
        &fixture.store,
        &fixture.key,
        fixture.genesis.repository_id,
        head_id(&fixture.genesis),
        fixture.genesis.generation,
        1,
    )
    .expect("current head descends exactly from source head");
    let ancestry = current.ancestry();
    let substituted = run(&fixture.receiver_receipt, 8, 256, 65);
    let substituted_commitment = substituted
        .commitment()
        .expect("substituted complete run commitment");

    assert_eq!(
        fixture
            .capsule
            .accept_at_descendant_head(
                &fixture.receiver_situation,
                &substituted,
                AgentInstanceId::new(2),
                target_resolution(&substituted),
                ancestry,
            )
            .expect_err("numeric run identity cannot substitute altered machine scope"),
        HandoffAcceptanceRefusal::ReceiverRunCommitmentMismatch {
            situation: fixture.receiver_situation.intent_run_commitment(),
            run: substituted_commitment,
        }
    );
}
