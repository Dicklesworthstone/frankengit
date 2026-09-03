#![forbid(unsafe_code)]
//! End-to-end tests for the current descendant-head effect broker.

use core::num::NonZeroU32;

use fgit_agent::{
    AgentInstanceId, AttenuationRequest, AuthorityReadReceipt, Capability,
    CapabilityEffectAuthorizationRefusal, CapabilityId, ClassSet,
    CurrentAuthorityExternalEffectOutcome, CurrentAuthorityOutboxDispatchRefused,
    CurrentAuthorityReconciliationRefused, CurrentAuthorityRevocationCheckedEffectBroker,
    CurrentAuthorityRevocationCheckedEffectRefusal, EffectId, EffectRequest, IntentRun,
    LogicalTime, OperationClass, RunId, VerifiedCapabilityChain,
    read_current_authority_capability_revocations,
};
use fgit_authority::{
    AuthorityStore, CapabilityRevocationGenerationBody, CasOutcome, HeadInit, HeadKey, HeadRead,
    MemoryAuthorityStore, PutOutcome, StoreInstanceId, authority_head_identity, body_key,
    initialize_repository, outcome_index_root, stage_capability_revocation_generation,
    stage_revocation_aware_repository_incarnation_configuration,
};
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryIncarnationConfigurationBodyV2_2, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_resource::{
    DownstreamChannel, DownstreamIdempotency, IdempotencyKey, OpaqueHandle, ReconcilePlan,
    ReconcilePolicy, RegionId, ResourceVector,
    algebra::Grade,
    kinds::{DispatchAbortReason, DownstreamAck, OutboxDispatch},
    settlement::{DeliveryVerdict, ProbeVerdict},
};
use fgit_types::{
    Digest, DigestBytes, HeadGeneration, PolicyEpoch, PrincipalId, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId, RepositoryIncarnationId,
    RootLayoutVersion, TenantId,
};

const ISSUER_KEY: &[u8] = b"current-authority-effect-dispatch-test";

const fn tenant() -> TenantId {
    TenantId::from_bytes([0x11; 16])
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}

const fn incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([0x33; 16])
}

fn digest(marker: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("the empty outcome root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[marker; 32]).expect("a fixed-width digest"),
    )
}

fn rcr_id(marker: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        fgit_types::CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[marker; 32]).expect("a fixed-width RCR digest"),
    )
}

fn stage_configuration(
    store: &MemoryAuthorityStore,
    revoked: &[CapabilityId],
    marker: u8,
) -> Digest {
    let generation = CapabilityRevocationGenerationBody::try_new(
        tenant(),
        repository(),
        incarnation(),
        PolicyEpoch::FIRST,
        None,
        revoked
            .iter()
            .map(|capability_id| capability_id.value().to_be_bytes())
            .collect(),
        digest(marker),
    )
    .expect("the bounded generation constructs");
    let generation =
        stage_capability_revocation_generation(store, &generation).expect("the generation stages");
    let configuration = RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: fgit_types::GitHashAlgorithm::Sha256,
        repository_incarnation_id: incarnation(),
        policy_root: None,
        capability_revocation_root: Some(generation.generation_root()),
    };
    stage_revocation_aware_repository_incarnation_configuration(store, &configuration)
        .expect("the configuration stages")
}

fn head(
    generation: u64,
    predecessor_head_id: Option<RepositoryAuthorityHeadId>,
    configuration_root: Digest,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    let root = outcome_index_root(&[]).expect("the empty outcome root is canonical");
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::try_new(generation).expect("a positive generation"),
        predecessor_head_id,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(marker),
        forge_position_root: root,
        outcome_index_root: root,
        retention_root: root,
        outbox_root: root,
        configuration_root,
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn head_id(value: &RepositoryAuthorityHeadBody) -> RepositoryAuthorityHeadId {
    authority_head_identity(value).expect("the head has a canonical identity")
}

fn stage_head(store: &MemoryAuthorityStore, value: &RepositoryAuthorityHeadBody) {
    let key = body_key(IdentityDomain::RepositoryAuthorityHead, value)
        .expect("the head has a canonical body key");
    assert!(matches!(
        store
            .put_if_absent(&key, &encode_body(value).expect("the head encodes"))
            .expect("the immutable write succeeds"),
        PutOutcome::Created | PutOutcome::IdenticalRetry
    ));
}

struct Fixture {
    store: MemoryAuthorityStore,
    head_key: HeadKey,
    genesis: RepositoryAuthorityHeadBody,
    run: IntentRun,
}

fn fixture(store_id: u64) -> Fixture {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let configuration_root = stage_configuration(&store, &[], 0x90);
    let genesis = head(1, None, configuration_root, 0x41);
    let head_key = HeadKey::new(format!("current-effect-{store_id}").into_bytes())
        .expect("a bounded head key");
    let head_read = match initialize_repository(&store, &head_key, &genesis)
        .expect("the genesis head initializes")
    {
        HeadInit::Created(receipt) => receipt,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => {
            panic!("a fresh store must create the head")
        }
    };
    let authenticated = store
        .authenticate_head_receipt(&head_read)
        .expect("the issuing store authenticates genesis");
    let authority = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("genesis becomes the run authority receipt");
    let run = IntentRun::new_authenticated(
        RunId::new(7),
        authority,
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        egress(1_000),
        LogicalTime::new(100),
    )
    .expect("the authenticated run opens");
    Fixture {
        store,
        head_key,
        genesis,
        run,
    }
}

fn advance(fixture: &Fixture, revoked: &[CapabilityId], marker: u8) -> RepositoryAuthorityHeadBody {
    let configuration_root = stage_configuration(&fixture.store, revoked, marker);
    let next = head(
        fixture.genesis.generation.get() + 1,
        Some(head_id(&fixture.genesis)),
        configuration_root,
        marker.wrapping_add(1),
    );
    stage_head(&fixture.store, &next);
    let HeadRead::Present(receipt) = fixture
        .store
        .read_head(&fixture.head_key)
        .expect("the head reads")
    else {
        panic!("the initialized head must be present");
    };
    assert!(matches!(
        fixture
            .store
            .compare_exchange_head(
                &fixture.head_key,
                receipt.token(),
                next.generation,
                &encode_body(&next).expect("the successor encodes"),
            )
            .expect("the conditional replacement succeeds"),
        CasOutcome::Committed(_)
    ));
    next
}

fn current_revocations(
    fixture: &Fixture,
    observed_at: u64,
    max_age: u64,
    max_hops: usize,
) -> fgit_agent::CurrentAuthorityCapabilityRevocationReceipt {
    read_current_authority_capability_revocations(
        &fixture.store,
        tenant(),
        &fixture.head_key,
        &fixture.run,
        LogicalTime::new(observed_at),
        max_age,
        32,
        max_hops,
    )
    .expect("the current selected generation resolves")
}

fn egress(amount: u64) -> ResourceVector {
    ResourceVector::single(Grade::EgressBytes, amount)
}

fn sealed_chain() -> Vec<fgit_agent::SealedCapability> {
    let root = Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        egress(1_000),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .expect("the root capability issues");
    let sealed_root = root.seal(ISSUER_KEY, None).expect("the root seals");
    let leaf = root
        .attenuate(&AttenuationRequest {
            id: CapabilityId::new(2),
            operations: ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
            quota: egress(800),
            not_before: LogicalTime::new(5),
            expires_at: LogicalTime::new(90),
        })
        .expect("the leaf attenuates");
    let sealed_leaf = leaf
        .seal(ISSUER_KEY, Some(sealed_root.tag()))
        .expect("the leaf seals against root");
    vec![sealed_root, sealed_leaf]
}

fn verified_chain() -> VerifiedCapabilityChain {
    VerifiedCapabilityChain::verify(&sealed_chain(), ISSUER_KEY)
        .expect("the attenuation chain verifies")
}

fn request(effect_id: u128) -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(effect_id),
        parent_effect_id: None,
        operation: OperationClass::ExternalIntegration,
        cost: egress(100),
        input_commitment: [0x81; 32],
    }
}

fn opaque(marker: u8) -> OpaqueHandle {
    OpaqueHandle::new(&[marker; 20]).expect("a bounded opaque handle")
}

fn dispatch(marker: u8) -> OutboxDispatch {
    OutboxDispatch {
        idempotency: IdempotencyKey::new(digest(marker)),
        precondition_rcr: rcr_id(marker.wrapping_add(1)),
        endpoint: opaque(marker.wrapping_add(2)),
        idempotency_strength: DownstreamIdempotency::Strong,
    }
}

struct Delivered;

impl DownstreamChannel for Delivered {
    fn deliver(&mut self, _: &IdempotencyKey, _: u32) -> DeliveryVerdict {
        DeliveryVerdict::Accepted
    }

    fn probe(&mut self, _: &IdempotencyKey) -> ProbeVerdict {
        ProbeVerdict::Delivered
    }
}

const fn plan(dispatch: &OutboxDispatch) -> ReconcilePlan {
    ReconcilePlan::new(
        dispatch.idempotency,
        dispatch.idempotency_strength,
        ReconcilePolicy::new(NonZeroU32::MIN),
    )
}

#[test]
fn current_head_authorizations_survive_acknowledged_reconciliation() {
    let fixture = fixture(501);
    let chain = verified_chain();
    let revocations = current_revocations(&fixture, 20, 30, 0);
    let request = request(1);
    let dispatch = dispatch(0x51);
    let mut broker = CurrentAuthorityRevocationCheckedEffectBroker::open(
        fixture.run,
        RegionId::new(1),
        AgentInstanceId::new(1),
    )
    .expect("the current-authority broker opens");
    let grant = broker
        .request_high_value(&chain, &revocations, LogicalTime::new(21), &request)
        .expect("the current generation authorizes acceptance");
    let initial = grant.authorization();
    assert_eq!(initial.revocation_receipt_id(), revocations.receipt_id());
    let reserved = broker
        .reserve_authorized_outbox(grant, dispatch)
        .expect("the proof-carrying grant becomes an outbox reservation");
    let deferred = broker
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &revocations,
            LogicalTime::new(22),
            1,
            &egress(100),
        )
        .expect("the fresh current generation authorizes dispatch");
    let dispatch_authorization = deferred.dispatch_authorization();
    assert_eq!(deferred.initial_authorization(), initial);
    assert_eq!(
        dispatch_authorization.revocation_receipt_id(),
        revocations.receipt_id()
    );

    let outcome = deferred
        .reconcile(
            &mut plan(&dispatch),
            &mut Delivered,
            PrincipalId::from_bytes([0x61; 16]),
            |attempt| DownstreamAck {
                receipt: opaque(0x52),
                attempt,
            },
            vec![[0x53; 32]],
        )
        .expect("the committed effect reconciles");
    let CurrentAuthorityExternalEffectOutcome::Acknowledged(settled) = outcome else {
        panic!("the delivered channel must acknowledge the effect");
    };
    assert_eq!(settled.initial_authorization(), initial);
    assert_eq!(settled.dispatch_authorization(), dispatch_authorization);
    assert_eq!(settled.request(), request);
    assert!(broker.close().is_quiescent());
}

#[test]
fn a_later_revocation_blocks_dispatch_and_preserves_abort_ownership() {
    let fixture = fixture(502);
    let chain = verified_chain();
    let initial_revocations = current_revocations(&fixture, 20, 30, 0);
    let request = request(2);
    let mut broker = CurrentAuthorityRevocationCheckedEffectBroker::open(
        fixture.run.clone(),
        RegionId::new(2),
        AgentInstanceId::new(2),
    )
    .expect("the broker opens");
    let grant = broker
        .request_high_value(&chain, &initial_revocations, LogicalTime::new(21), &request)
        .expect("the ancestor is initially clear");
    let reserved = broker
        .reserve_authorized_outbox(grant, dispatch(0x61))
        .expect("the external reservation opens");

    let _current = advance(&fixture, &[CapabilityId::new(1)], 0x91);
    let revoked = current_revocations(&fixture, 30, 20, 1);
    let refusal = broker
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &revoked,
            LogicalTime::new(31),
            1,
            &egress(100),
        )
        .expect_err("the later canonical revocation must block dispatch");
    assert!(matches!(
        &refusal,
        CurrentAuthorityOutboxDispatchRefused::Authorization {
            source: CapabilityEffectAuthorizationRefusal::CapabilityRevoked {
                capability_id,
                chain_index: 0,
                ..
            },
            ..
        } if *capability_id == CapabilityId::new(1)
    ));
    let reserved = refusal
        .into_reserved()
        .expect("pre-dispatch refusal retains the reservation");
    let _settled = reserved
        .abort_unused(DispatchAbortReason::Cancelled)
        .expect("revocation cannot block cleanup");
    assert!(broker.close().is_quiescent());
}

#[test]
fn a_wrong_reconciliation_plan_returns_the_same_proof_carrying_effect() {
    let fixture = fixture(503);
    let chain = verified_chain();
    let revocations = current_revocations(&fixture, 20, 30, 0);
    let request = request(3);
    let dispatch = dispatch(0x71);
    let mut broker = CurrentAuthorityRevocationCheckedEffectBroker::open(
        fixture.run,
        RegionId::new(3),
        AgentInstanceId::new(3),
    )
    .expect("the broker opens");
    let grant = broker
        .request_high_value(&chain, &revocations, LogicalTime::new(21), &request)
        .expect("request authorization succeeds");
    let reserved = broker
        .reserve_authorized_outbox(grant, dispatch)
        .expect("reservation succeeds");
    let deferred = broker
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &revocations,
            LogicalTime::new(22),
            1,
            &egress(100),
        )
        .expect("dispatch succeeds");
    let initial = deferred.initial_authorization();
    let dispatched = deferred.dispatch_authorization();
    let wrong_dispatch = self::dispatch(0x72);
    let refusal = deferred
        .reconcile(
            &mut plan(&wrong_dispatch),
            &mut Delivered,
            PrincipalId::from_bytes([0x62; 16]),
            |attempt| DownstreamAck {
                receipt: opaque(0x73),
                attempt,
            },
            Vec::new(),
        )
        .expect_err("a plan for another downstream key must refuse");
    assert!(matches!(
        &refusal,
        CurrentAuthorityReconciliationRefused::WrongPlan { .. }
    ));
    let deferred = refusal
        .into_effect()
        .expect("wrong-plan refusal retains the deferred effect");
    assert_eq!(deferred.initial_authorization(), initial);
    assert_eq!(deferred.dispatch_authorization(), dispatched);

    let outcome = deferred
        .reconcile(
            &mut plan(&dispatch),
            &mut Delivered,
            PrincipalId::from_bytes([0x62; 16]),
            |attempt| DownstreamAck {
                receipt: opaque(0x74),
                attempt,
            },
            Vec::new(),
        )
        .expect("the recovered effect accepts its exact plan");
    assert!(matches!(
        outcome,
        CurrentAuthorityExternalEffectOutcome::Acknowledged(_)
    ));
    assert!(broker.close().is_quiescent());
}

#[test]
fn a_stale_current_receipt_refuses_before_any_broker_record() {
    let fixture = fixture(504);
    let chain = verified_chain();
    let revocations = current_revocations(&fixture, 20, 5, 0);
    let mut broker = CurrentAuthorityRevocationCheckedEffectBroker::open(
        fixture.run,
        RegionId::new(4),
        AgentInstanceId::new(4),
    )
    .expect("the broker opens");

    let refusal = broker
        .request_high_value(&chain, &revocations, LogicalTime::new(25), &request(4))
        .expect_err("the exclusive freshness deadline must fail closed");
    assert!(matches!(
        refusal,
        CurrentAuthorityRevocationCheckedEffectRefusal::Authorization(
            CapabilityEffectAuthorizationRefusal::RevocationReadStale {
                observed_at,
                valid_until,
                authorized_at,
            }
        ) if observed_at == LogicalTime::new(20)
            && valid_until == LogicalTime::new(25)
            && authorized_at == LogicalTime::new(25)
    ));
    assert!(broker.records().is_empty());
    assert!(broker.authorizations().is_empty());
    assert!(broker.close().is_quiescent());
}
