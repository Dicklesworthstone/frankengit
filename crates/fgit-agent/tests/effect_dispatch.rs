#![forbid(unsafe_code)]
//! Public-path tests for revocation revalidation at irreversible dispatch.

use core::num::NonZeroU32;

use fgit_agent::{
    AgentInstanceId, AttenuationRequest, AuthorizedOutboxDispatchRefused,
    AuthorityReadReceipt, Capability, CapabilityEffectAuthorizationRefusal, CapabilityId,
    CapabilityRevocationReadAdapterRefusal, CapabilityRevocationReadObservation,
    CapabilityRevocationReadRequest, CapabilityRevocationReader, ClassSet, EffectId,
    EffectRequest, IntentRun, LogicalTime, OperationClass, RevocationCheckedEffectBroker,
    RunId, VerifiedCapabilityChain, read_capability_revocations,
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
    let key = HeadKey::new(format!("effect-dispatch-{store_id}").into_bytes())
        .expect("bounded head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    let authenticated = store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt");
    AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x71; 32],
    )
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
    read_capability_revocations(
        &mut reader,
        receipt,
        run,
        LogicalTime::new(20),
        max_age,
        32,
    )
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
fn request_time_proof_cannot_be_reused_after_its_dispatch_deadline() {
    let receipt = authority_receipt(1_101);
    let run = run(&receipt);
    let chain = verified_chain();
    let initial = revocations(&receipt, &run, Vec::new(), 21, 5);
    let request = effect_request(1, 100);
    let mut broker = RevocationCheckedEffectBroker::open(
        run,
        RegionId::new(1),
        AgentInstanceId::new(1),
    )
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
    let mut broker = RevocationCheckedEffectBroker::open(
        run,
        RegionId::new(2),
        AgentInstanceId::new(2),
    )
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
fn fresh_dispatch_proof_commits_and_reconciliation_remains_available() {
    let receipt = authority_receipt(1_103);
    let run = run(&receipt);
    let chain = verified_chain();
    let initial = revocations(&receipt, &run, Vec::new(), 21, 30);
    let fresh = revocations(&receipt, &run, Vec::new(), 30, 20);
    let request = effect_request(3, 100);
    let dispatch = dispatch(0x71);
    let mut broker = RevocationCheckedEffectBroker::open(
        run.clone(),
        RegionId::new(3),
        AgentInstanceId::new(3),
    )
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

    let mut plan = ReconcilePlan::new(
        dispatch.idempotency,
        dispatch.idempotency_strength,
        ReconcilePolicy::new(NonZeroU32::MIN),
    );
    let outcome = committed
        .into_deferred()
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
    assert!(matches!(
        outcome,
        fgit_agent::ExternalEffectOutcome::Acknowledged(_)
    ));
    assert!(broker.close().is_quiescent());
}
