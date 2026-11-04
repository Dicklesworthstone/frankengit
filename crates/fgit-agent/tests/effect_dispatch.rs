#![forbid(unsafe_code)]
//! Public-path tests for revocation revalidation at irreversible dispatch.

use core::num::NonZeroU32;

use fgit_agent::{
    AgentInstanceId, AttenuationRequest, AuthorityReadReceipt, AuthorizedOutboxDispatchRefused,
    Capability, CapabilityEffectAuthorizationRefusal, CapabilityId,
    CapabilityRevocationReadAdapterRefusal, CapabilityRevocationReadObservation,
    CapabilityRevocationReadRequest, CapabilityRevocationReader, ClassSet, EffectId, EffectRequest,
    IntentRun, LogicalTime, OperationClass, RevocationAuthorizedExternalEffectOutcome,
    RevocationCheckedEffectBroker, RunId, VerifiedCapabilityChain, read_capability_revocations,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{
    DownstreamChannel, DownstreamIdempotency, IdempotencyKey, OpaqueHandle, ReconcilePlan,
    ReconcilePolicy, RegionId, ResourceVector,
    algebra::Grade,
    kinds::{DispatchAbortReason, DownstreamAck, OutboxDispatch},
    settlement::{DeliveryVerdict, ProbeVerdict},
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, PrincipalId,
    RegistryEpoch, RepositoryCommitId, RepositoryId, RepositorySequence,
};

const ISSUER_KEY: &[u8] = b"dispatch-time-revocation-test-key";
const REVOCATION_GENERATION: [u8; 32] = [0x81; 32];

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn rcr_id(byte: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width RCR digest"),
    )
}

fn authority_receipt(store_id: u64) -> AuthorityReadReceipt {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    let body = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x27; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr_id(0x27)),
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
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let key =
        HeadKey::new(format!("effect-dispatch-{store_id}").into_bytes()).expect("bounded head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt");
    AuthorityReadReceipt::from_authenticated_head(&authenticated, LogicalTime::new(10), [0x71; 32])
        .expect("complete authenticated read")
}

fn egress(amount: u64) -> ResourceVector {
    ResourceVector::single(Grade::EgressBytes, amount)
}

fn run(receipt: &AuthorityReadReceipt) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        egress(1_000),
        LogicalTime::new(100),
    )
    .expect("authenticated run opens")
}

fn sealed_chain() -> Vec<fgit_agent::SealedCapability> {
    let root = Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        egress(1_000),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .expect("root capability issues");
    let sealed_root = root.seal(ISSUER_KEY, None).expect("root seals");
    let leaf = root
        .attenuate(&AttenuationRequest {
            id: CapabilityId::new(2),
            operations: ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
            quota: egress(800),
            not_before: LogicalTime::new(5),
            expires_at: LogicalTime::new(90),
        })
        .expect("leaf attenuates");
    let sealed_leaf = leaf
        .seal(ISSUER_KEY, Some(sealed_root.tag()))
        .expect("leaf seals against root");
    vec![sealed_root, sealed_leaf]
}

fn verified_chain() -> VerifiedCapabilityChain {
    VerifiedCapabilityChain::verify(&sealed_chain(), ISSUER_KEY)
        .expect("authentic attenuation chain verifies")
}

fn effect_request(effect_id: u128, cost: u64) -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(effect_id),
        parent_effect_id: None,
        operation: OperationClass::ExternalIntegration,
        cost: egress(cost),
        input_commitment: [0x91; 32],
    }
}

#[derive(Clone)]
struct Reader {
    observed_at: LogicalTime,
    revoked: Vec<CapabilityId>,
}

impl CapabilityRevocationReader for Reader {
    fn reader_profile(&self) -> [u8; 32] {
        [0x83; 32]
    }

    fn read(
        &mut self,
        request: &CapabilityRevocationReadRequest,
    ) -> Result<CapabilityRevocationReadObservation, CapabilityRevocationReadAdapterRefusal> {
        Ok(CapabilityRevocationReadObservation::new(
            request.request_id(),
            REVOCATION_GENERATION,
            self.observed_at,
            self.revoked.clone(),
            digest(0x82),
        ))
    }
}

fn revocations(
    receipt: &AuthorityReadReceipt,
    run: &IntentRun,
    revoked: Vec<CapabilityId>,
    observed_at: u64,
    max_age: u64,
) -> fgit_agent::CapabilityRevocationReceipt {
    let mut reader = Reader {
        observed_at: LogicalTime::new(observed_at),
        revoked,
    };
    read_capability_revocations(&mut reader, receipt, run, LogicalTime::new(20), max_age, 32)
        .expect("bounded revocation read")
}

fn opaque(tag: u8) -> OpaqueHandle {
    OpaqueHandle::new(&[tag; 20]).expect("bounded opaque handle")
}

fn dispatch(tag: u8) -> OutboxDispatch {
    OutboxDispatch {
        idempotency: IdempotencyKey::new(digest(tag)),
        precondition_rcr: rcr_id(tag.wrapping_add(1)),
        endpoint: opaque(tag.wrapping_add(2)),
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

#[test]
fn cross_broker_dispatch_cannot_extend_the_original_run_lifetime() {
    let receipt = authority_receipt(1_104);
    let receiver_run = run(&receipt);
    let original_run = IntentRun::new_authenticated(
        receiver_run.run_id(),
        receipt.clone(),
        receiver_run.allowed_operation_classes(),
        receiver_run.resource_budget(),
        LogicalTime::new(25),
    )
    .expect("the shorter run opens");
    assert_eq!(original_run.run_id(), receiver_run.run_id());
    assert_ne!(
        original_run
            .commitment()
            .expect("the original run identity"),
        receiver_run
            .commitment()
            .expect("the receiving run identity"),
    );
    assert!(!original_run.is_open_at(LogicalTime::new(31)));
    assert!(receiver_run.is_open_at(LogicalTime::new(31)));
    let chain = verified_chain();
    let initial = revocations(&receipt, &original_run, Vec::new(), 21, 30);
    let fresh = revocations(&receipt, &receiver_run, Vec::new(), 30, 20);
    let request = effect_request(4, 100);
    let dispatch = dispatch(0x81);
    let mut owner = RevocationCheckedEffectBroker::open(
        original_run,
        RegionId::new(4),
        AgentInstanceId::new(4),
    )
    .expect("the original broker opens");
    let mut receiver = RevocationCheckedEffectBroker::open(
        receiver_run.clone(),
        RegionId::new(4),
        AgentInstanceId::new(4),
    )
    .expect("the longer-lived broker opens");
    let grant = owner
        .request_high_value(&chain, &initial, LogicalTime::new(22), &request)
        .expect("the original run initially authorizes the request");
    let reserved = owner
        .reserve_authorized_outbox(grant, dispatch)
        .expect("the original broker reserves its effect");
    let original_authorization = reserved.initial_authorization();
    let journal = owner.journal();
    let records = owner.records();

    let refusal = receiver
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &fresh,
            LogicalTime::new(31),
            1,
            &egress(100),
        )
        .expect_err("another complete run cannot revive an expired reservation");
    assert!(matches!(
        &refusal,
        AuthorizedOutboxDispatchRefused::RunCommitmentChanged {
            expected, observed, ..
        } if *expected == owner.run_commitment() && *observed == receiver.run_commitment()
    ));
    assert_eq!(owner.journal(), journal);
    assert_eq!(owner.records(), records);
    assert!(receiver.records().is_empty());
    assert!(owner.dispatch_authorizations().is_empty());
    assert!(receiver.dispatch_authorizations().is_empty());
    let reserved = refusal
        .into_reserved()
        .expect("wrong-run dispatch preserves the live reservation");
    assert_eq!(reserved.initial_authorization(), original_authorization);
    assert_eq!(reserved.request(), request);
    let _settled = reserved
        .abort_unused(DispatchAbortReason::Cancelled)
        .expect("expiry does not prevent cleanup in the original broker");

    let grant = receiver
        .request_high_value(&chain, &fresh, LogicalTime::new(31), &request)
        .expect("the receiving run can authorize its own fresh request");
    let reserved = receiver
        .reserve_authorized_outbox(grant, dispatch)
        .expect("the receiving broker reserves its own effect");
    let committed = receiver
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &fresh,
            LogicalTime::new(31),
            1,
            &egress(100),
        )
        .expect("the original refusal does not prevent a legitimate dispatch");
    let commitment = receiver_run
        .commitment()
        .expect("the complete run identity");
    assert_eq!(
        committed.initial_authorization().run_commitment(),
        commitment
    );
    assert_eq!(
        committed.dispatch_authorization().run_commitment(),
        commitment
    );
    let mut plan = ReconcilePlan::new(
        dispatch.idempotency,
        dispatch.idempotency_strength,
        ReconcilePolicy::new(NonZeroU32::MIN),
    );
    assert!(matches!(
        committed.reconcile(
            &mut plan,
            &mut Delivered,
            PrincipalId::from_bytes([0x41; 16]),
            |attempt| DownstreamAck {
                receipt: opaque(0x82),
                attempt,
            },
            Vec::new(),
        ),
        Ok(RevocationAuthorizedExternalEffectOutcome::Acknowledged(_))
    ));
    assert!(owner.close().is_quiescent());
    assert!(receiver.close().is_quiescent());
}

#[test]
fn cross_broker_same_run_grants_and_reservations_keep_their_owner() {
    let receipt = authority_receipt(1_105);
    let run = run(&receipt);
    let chain = verified_chain();
    let revocations = revocations(&receipt, &run, Vec::new(), 21, 30);
    let mut owner =
        RevocationCheckedEffectBroker::open(run.clone(), RegionId::new(5), AgentInstanceId::new(5))
            .expect("the owner opens");
    let mut receiver =
        RevocationCheckedEffectBroker::open(run, RegionId::new(5), AgentInstanceId::new(5))
            .expect("a sibling with identical public identities opens");
    assert_eq!(owner.run_commitment(), receiver.run_commitment());
    let request = effect_request(5, 100);
    let dispatch = dispatch(0x91);
    let grant = owner
        .request_high_value(&chain, &revocations, LogicalTime::new(22), &request)
        .expect("the owner accepts the request");
    let authorization = grant.authorization();
    let journal = owner.journal();
    let records = owner.records();
    let refusal = receiver
        .reserve_authorized_outbox(grant, dispatch)
        .expect_err("identical public identities do not transfer a live grant");
    assert!(matches!(
        refusal.source(),
        fgit_agent::OutboxReservationRefused::BrokerMismatch { .. }
    ));
    assert_eq!(owner.journal(), journal);
    assert_eq!(owner.records(), records);
    assert!(receiver.records().is_empty());
    let grant = refusal
        .into_authorized_grant()
        .expect("wrong-broker reservation retains the authorized grant");
    assert_eq!(grant.authorization(), authorization);
    let reserved = owner
        .reserve_authorized_outbox(grant, dispatch)
        .expect("the recovered grant still reserves in its owning broker");
    let journal = owner.journal();
    let records = owner.records();
    let refusal = receiver
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &revocations,
            LogicalTime::new(23),
            1,
            &egress(100),
        )
        .expect_err("identical public identities do not transfer a reservation");
    assert!(matches!(
        &refusal,
        AuthorizedOutboxDispatchRefused::BrokerMismatch { .. }
    ));
    assert_eq!(owner.journal(), journal);
    assert_eq!(owner.records(), records);
    assert!(receiver.records().is_empty());
    assert!(owner.dispatch_authorizations().is_empty());
    assert!(receiver.dispatch_authorizations().is_empty());
    let reserved = refusal
        .into_reserved()
        .expect("wrong-broker dispatch preserves the live reservation");
    assert_eq!(reserved.initial_authorization(), authorization);
    assert_eq!(reserved.request(), request);
    let committed = owner
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &revocations,
            LogicalTime::new(23),
            1,
            &egress(100),
        )
        .expect("the recovered reservation still dispatches in its owning broker");
    let mut plan = ReconcilePlan::new(
        dispatch.idempotency,
        dispatch.idempotency_strength,
        ReconcilePolicy::new(NonZeroU32::MIN),
    );
    assert!(matches!(
        committed.reconcile(
            &mut plan,
            &mut Delivered,
            PrincipalId::from_bytes([0x41; 16]),
            |attempt| DownstreamAck {
                receipt: opaque(0x92),
                attempt,
            },
            Vec::new(),
        ),
        Ok(RevocationAuthorizedExternalEffectOutcome::Acknowledged(_))
    ));
    assert!(owner.close().is_quiescent());
    assert!(receiver.close().is_quiescent());
}

#[test]
fn request_time_proof_cannot_be_reused_after_its_dispatch_deadline() {
    let receipt = authority_receipt(1_101);
    let run = run(&receipt);
    let chain = verified_chain();
    let initial = revocations(&receipt, &run, Vec::new(), 21, 5);
    let request = effect_request(1, 100);
    let mut broker =
        RevocationCheckedEffectBroker::open(run, RegionId::new(1), AgentInstanceId::new(1))
            .expect("checked broker opens");
    let grant = broker
        .request_high_value(&chain, &initial, LogicalTime::new(22), &request)
        .expect("request-time proof is fresh");
    let reserved = broker
        .reserve_authorized_outbox(grant, dispatch(0x51))
        .expect("external grant becomes a proof-carrying reservation");

    let refusal = broker
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &initial,
            LogicalTime::new(26),
            1,
            &egress(100),
        )
        .expect_err("revocation freshness is checked again at dispatch");
    assert!(matches!(
        &refusal,
        AuthorizedOutboxDispatchRefused::Authorization {
            source: CapabilityEffectAuthorizationRefusal::RevocationReadStale {
                observed_at,
                valid_until,
                authorized_at,
            },
            ..
        } if *observed_at == LogicalTime::new(21)
            && *valid_until == LogicalTime::new(26)
            && *authorized_at == LogicalTime::new(26)
    ));
    assert!(broker.dispatch_authorizations().is_empty());
    let reserved = refusal
        .into_reserved()
        .expect("pre-dispatch refusal retains the reservation");
    let _settled = reserved
        .abort_unused(DispatchAbortReason::Cancelled)
        .expect("revocation cannot prevent abort cleanup");
    assert!(broker.close().is_quiescent());
}

#[test]
fn newly_revoked_ancestor_blocks_dispatch_without_leaking_reservation() {
    let receipt = authority_receipt(1_102);
    let run = run(&receipt);
    let chain = verified_chain();
    let initial = revocations(&receipt, &run, Vec::new(), 21, 30);
    let revoked = revocations(&receipt, &run, vec![CapabilityId::new(1)], 30, 20);
    let request = effect_request(2, 100);
    let mut broker =
        RevocationCheckedEffectBroker::open(run, RegionId::new(2), AgentInstanceId::new(2))
            .expect("checked broker opens");
    let grant = broker
        .request_high_value(&chain, &initial, LogicalTime::new(22), &request)
        .expect("ancestry is initially clear");
    let reserved = broker
        .reserve_authorized_outbox(grant, dispatch(0x61))
        .expect("reservation retains its initial proof");

    let refusal = broker
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &revoked,
            LogicalTime::new(31),
            1,
            &egress(100),
        )
        .expect_err("revoked root blocks the downstream-visible effect");
    assert!(matches!(
        &refusal,
        AuthorizedOutboxDispatchRefused::Authorization {
            source: CapabilityEffectAuthorizationRefusal::CapabilityRevoked {
                capability_id,
                chain_index: 0,
                revocation_generation: REVOCATION_GENERATION,
            },
            ..
        } if *capability_id == CapabilityId::new(1)
    ));
    let reserved = refusal
        .into_reserved()
        .expect("revocation refusal retains cleanup ownership");
    let _settled = reserved
        .abort_unused(DispatchAbortReason::Cancelled)
        .expect("revocation cannot block abort");
    assert!(broker.close().is_quiescent());
}

#[test]
fn fresh_dispatch_proof_commits_and_reconciliation_retains_both_proofs() {
    let receipt = authority_receipt(1_103);
    let run = run(&receipt);
    let chain = verified_chain();
    let initial = revocations(&receipt, &run, Vec::new(), 21, 30);
    let fresh = revocations(&receipt, &run, Vec::new(), 30, 20);
    let request = effect_request(3, 100);
    let dispatch = dispatch(0x71);
    let mut broker =
        RevocationCheckedEffectBroker::open(run.clone(), RegionId::new(3), AgentInstanceId::new(3))
            .expect("checked broker opens");
    let grant = broker
        .request_high_value(&chain, &initial, LogicalTime::new(22), &request)
        .expect("request-time proof is fresh");
    let reserved = broker
        .reserve_authorized_outbox(grant, dispatch)
        .expect("proof-carrying reservation opens");
    let committed = broker
        .dispatch_authorized_outbox(
            reserved,
            &chain,
            &fresh,
            LogicalTime::new(31),
            1,
            &egress(100),
        )
        .expect("fresh exact-request proof permits dispatch");

    assert_eq!(broker.dispatch_authorizations().len(), 1);
    assert_eq!(
        committed.dispatch_authorization().revocation_receipt_id(),
        fresh.receipt_id()
    );
    assert_eq!(committed.request(), request);
    assert_eq!(
        broker.records()[0].run_commitment,
        run.commitment().expect("complete run identity")
    );
    let initial_authorization = committed.initial_authorization();
    let dispatch_authorization = committed.dispatch_authorization();

    let mut plan = ReconcilePlan::new(
        dispatch.idempotency,
        dispatch.idempotency_strength,
        ReconcilePolicy::new(NonZeroU32::MIN),
    );
    let outcome = committed
        .reconcile(
            &mut plan,
            &mut Delivered,
            PrincipalId::from_bytes([0x41; 16]),
            |attempt| DownstreamAck {
                receipt: opaque(0x72),
                attempt,
            },
            vec![[0x73; 32]],
        )
        .expect("cleanup reconciliation remains available after dispatch");
    let RevocationAuthorizedExternalEffectOutcome::Acknowledged(settled) = outcome else {
        panic!("the delivered channel must acknowledge the effect");
    };
    assert_eq!(settled.initial_authorization(), initial_authorization);
    assert_eq!(settled.dispatch_authorization(), dispatch_authorization);
    assert_eq!(settled.request(), request);
    assert!(broker.close().is_quiescent());
}
