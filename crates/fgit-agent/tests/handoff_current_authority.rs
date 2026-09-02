#![forbid(unsafe_code)]
//! Public-path tests for atomic current-head handoff acceptance.

use core::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use fgit_agent::{
    AgentChangePlan, AgentChangePlanSpec, AgentControlPulse, AgentHandoffCapsule,
    AgentHandoffCapsuleSpec, AgentInstanceId, AgentSituationReceipt, AuthorityReadReceipt,
    ClassSet, CurrentAuthorityHandoffRefusal, EvidenceClass, HandoffAuthorityRelation,
    HandoffCapabilityAttenuation, HandoffTargetResolution, IntentRun, LogicalTime,
    OperationClass, PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose,
    PlanEvidenceRequirement, PlanRequirementId, PlanStopConditionSet, PlanSurface,
    PlanSurfaceKind, RejectedShortcutSet, RequirementDisposition, RunId,
    RunReconciliationReport, SituationComponent, SituationComponentKind,
    SituationOmissionReason, TaskClaimProjection, TaskClaimReceipt, TaskPhase, WorkConflict,
    WorkEligibilityInputs, WorkFrontier, WorkItem, WorkRankingInputs, WorkTaskId,
    accept_handoff_at_current_authority, accept_handoff_at_current_authority_async,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore,
    AuthorityVersionToken, CasOutcome, HeadInit, HeadKey, HeadRead, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PutOutcome, StoreInstanceId, authority_head_identity, body_key,
    initialize_repository,
};
use fgit_codec::{RepositoryAuthorityHeadBody, encode_body};
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryId,
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

fn initialize(store: &MemoryAuthorityStore, key: &HeadKey, value: &RepositoryAuthorityHeadBody) {
    assert!(matches!(
        initialize_repository(store, key, value).expect("initialize head"),
        HeadInit::Created(_)
    ));
}

fn advance(
    store: &MemoryAuthorityStore,
    key: &HeadKey,
    previous: &RepositoryAuthorityHeadBody,
) -> RepositoryAuthorityHeadBody {
    let next = head(
        previous.repository_id,
        previous.generation.get() + 1,
        Some(head_id(previous)),
        0x21,
    );
    let bytes = encode_body(&next).expect("successor encodes");
    let immutable_key = body_key(IdentityDomain::RepositoryAuthorityHead, &next)
        .expect("successor immutable key");
    assert!(matches!(
        store
            .put_if_absent(&immutable_key, &bytes)
            .expect("stage successor"),
        PutOutcome::Created | PutOutcome::IdenticalRetry
    ));
    let HeadRead::Present(current) = store.read_head(key).expect("read current head") else {
        panic!("initialized head must exist");
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
        panic!("head must exist");
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("authenticate exact head read");
    AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(verified_at),
        [profile; 32],
    )
    .expect("complete agent receipt")
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
    let frontier = WorkFrontier::build_action_scoped(
        &planning,
        vec![WorkItem::new(
            task_id,
            TASK_BASIS,
            TaskPhase::Open,
            WorkRankingInputs::new(1, 2, 3),
            WorkEligibilityInputs::new(
                0,
                Some(source.run_id()),
                None,
                true,
                WorkConflict::Clear,
            ),
        )],
    )
    .expect("eligible frontier");
    let pulse =
        AgentControlPulse::build(&planning, &frontier, Some(source)).expect("actionable pulse");
    let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(0x61));
    let plan = AgentChangePlan::build(
        &pulse,
        source,
        &[],
        AgentChangePlanSpec::new(
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
        )]),
    )
    .expect("complete plan");
    let claim = TaskClaimReceipt::admit(
        &pulse,
        &plan,
        source,
        TaskClaimProjection::new(
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
        ),
    )
    .expect("source claim receipt");
    let activation = situation(receipt, source, CLAIMED_GENERATION, 30);
    let active = claim
        .activate(&activation, source)
        .expect("source claim activation");
    let reconciliation = RunReconciliationReport::build(
        source,
        Vec::new(),
        activation.observed_at(),
    )
    .expect("complete empty reconciliation");
    AgentHandoffCapsule::build(
        &activation,
        &plan,
        active,
        source,
        reconciliation,
        AgentHandoffCapsuleSpec::new(
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
        .with_requested_next_actions(vec![digest(0x93)]),
    )
    .expect("complete source capsule")
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
    descendant: RepositoryAuthorityHeadBody,
    receiver_receipt: AuthorityReadReceipt,
    receiver: IntentRun,
    receiver_situation: AgentSituationReceipt,
    capsule: AgentHandoffCapsule,
}

fn fixture(store_id: u64) -> Fixture {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let key = HeadKey::new(b"atomic-handoff-current-head".to_vec()).expect("bounded head key");
    let genesis = head(RepositoryId::from_bytes([0x22; 16]), 1, None, 0x11);
    initialize(&store, &key, &genesis);
    let source_receipt = authority_receipt(&store, &key, 10, 0x51);
    let source = run(&source_receipt, 7, 16_384, 100);
    let capsule = source_capsule(&source_receipt, &source);
    let descendant = advance(&store, &key, &genesis);
    let receiver_receipt = authority_receipt(&store, &key, 40, 0x52);
    let receiver = run(&receiver_receipt, 8, 512, 65);
    let receiver_situation = situation(
        &receiver_receipt,
        &receiver,
        CLAIMED_GENERATION,
        45,
    );
    Fixture {
        store,
        key,
        descendant,
        receiver_receipt,
        receiver,
        receiver_situation,
        capsule,
    }
}

#[test]
fn synchronous_driver_consumes_the_exact_current_head_proof() {
    let fixture = fixture(191);
    let first = accept_handoff_at_current_authority(
        &fixture.store,
        &fixture.key,
        &fixture.capsule,
        &fixture.receiver_situation,
        &fixture.receiver,
        AgentInstanceId::new(2),
        target_resolution(&fixture.receiver),
        1,
    )
    .expect("bounded current-head proof enables acceptance");
    let second = accept_handoff_at_current_authority(
        &fixture.store,
        &fixture.key,
        &fixture.capsule,
        &fixture.receiver_situation,
        &fixture.receiver,
        AgentInstanceId::new(2),
        target_resolution(&fixture.receiver),
        1,
    )
    .expect("same current facts are deterministic");

    assert_eq!(first.acceptance_id(), second.acceptance_id());
    assert_eq!(
        first.authority_relation(),
        HandoffAuthorityRelation::DescendantAuthenticatedHead
    );
    let ancestry = first.authority_ancestry().expect("descendant proof is retained");
    assert_eq!(ancestry.descendant_head_id(), head_id(&fixture.descendant));
    assert_eq!(ancestry.descendant_version_token(), fixture.receiver_receipt.backend_version_token());
}

#[test]
fn receiver_from_another_store_is_refused_before_acceptance() {
    let fixture = fixture(192);
    let other_store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(193));
    initialize(&other_store, &fixture.key, &fixture.descendant);
    let other_receipt = authority_receipt(&other_store, &fixture.key, 40, 0x52);
    let other_receiver = run(&other_receipt, 8, 512, 65);
    let other_situation = situation(
        &other_receipt,
        &other_receiver,
        CLAIMED_GENERATION,
        45,
    );

    assert_eq!(
        accept_handoff_at_current_authority(
            &fixture.store,
            &fixture.key,
            &fixture.capsule,
            &other_situation,
            &other_receiver,
            AgentInstanceId::new(2),
            target_resolution(&other_receiver),
            1,
        )
        .expect_err("same body from another current slot is not interchangeable"),
        CurrentAuthorityHandoffRefusal::ReceiverCurrentTokenMismatch {
            expected: fixture.receiver_receipt.backend_version_token(),
            observed: other_receipt.backend_version_token(),
        }
    );
}

struct AsyncMirror<'a>(&'a MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncMirror<'_> {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        AuthorityStore::instance_id(self.0)
    }

    fn limits(&self) -> AuthorityLimits {
        AuthorityStore::limits(self.0)
    }

    fn put_if_absent(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::put_if_absent(self.0, key, body))
    }

    fn read_immutable(
        &self,
        _cx: &Self::Context,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::read_immutable(self.0, key))
    }

    fn initialize_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::initialize_head(
            self.0,
            key,
            generation,
            body,
        ))
    }

    fn read_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::read_head(self.0, key))
    }

    fn compare_exchange_head(
        &self,
        _cx: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::compare_exchange_head(
            self.0,
            key,
            expected,
            new_generation,
            new_body,
        ))
    }

    fn authenticate_head_receipt(
        &self,
        _cx: &Self::Context,
        receipt: &fgit_authority::HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::authenticate_head_receipt(self.0, receipt))
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[test]
fn synchronous_and_asynchronous_drivers_return_the_same_acceptance() {
    let fixture = fixture(194);
    let synchronous = accept_handoff_at_current_authority(
        &fixture.store,
        &fixture.key,
        &fixture.capsule,
        &fixture.receiver_situation,
        &fixture.receiver,
        AgentInstanceId::new(2),
        target_resolution(&fixture.receiver),
        1,
    )
    .expect("synchronous driver accepts");
    let asynchronous = block_on(accept_handoff_at_current_authority_async(
        &AsyncMirror(&fixture.store),
        &(),
        &fixture.key,
        &fixture.capsule,
        &fixture.receiver_situation,
        &fixture.receiver,
        AgentInstanceId::new(2),
        target_resolution(&fixture.receiver),
        1,
    ))
    .expect("asynchronous driver accepts");

    assert_eq!(synchronous, asynchronous);
}
