#![forbid(unsafe_code)]
//! Public-path tests for effect-time capability revocation and freshness.

use fgit_agent::{
    AgentInstanceId, AttenuationRequest, AuthorityReadReceipt, Capability,
    CapabilityEffectAuthorization, CapabilityEffectAuthorizationRefusal, CapabilityId,
    CapabilityRevocationReadAdapterRefusal, CapabilityRevocationReadObservation,
    CapabilityRevocationReadRefusal, CapabilityRevocationReadRequest, CapabilityRevocationReader,
    ClassSet, EffectId, EffectRequest, IntentRun, LogicalTime, OperationClass,
    RevocationCheckedEffectBroker, RevocationCheckedEffectRefusal, RunId, VerifiedCapabilityChain,
    VerifiedCapabilityChainRefusal, read_capability_revocations,
};
use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, RegionId, ResourceVector};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

const ISSUER_KEY: &[u8] = b"effect-time-revocation-test-key";
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

fn authority_receipt(store_id: u64, repository_byte: u8) -> AuthorityReadReceipt {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    let body = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([repository_byte; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr_id(repository_byte)),
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
    let key = HeadKey::new(format!("effect-revocation-{store_id}").into_bytes())
        .expect("bounded head key");
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

fn budget(egress: u64, bytes: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::EgressBytes, egress), (Grade::Bytes, bytes)])
}

fn authenticated_run(receipt: &AuthorityReadReceipt) -> IntentRun {
    IntentRun::new_authenticated(
        RunId::new(7),
        receipt.clone(),
        ClassSet::from_classes(&[
            OperationClass::ReadCanonicalObject,
            OperationClass::ExternalIntegration,
            OperationClass::SecretHandle,
        ]),
        budget(1_000, 1_000),
        LogicalTime::new(100),
    )
    .expect("authenticated run opens")
}

fn sealed_chain() -> Vec<fgit_agent::SealedCapability> {
    let root = Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[
            OperationClass::ExternalIntegration,
            OperationClass::SecretHandle,
        ]),
        ResourceVector::single(Grade::EgressBytes, 1_000),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .expect("root capability issues");
    let sealed_root = root.seal(ISSUER_KEY, None).expect("root capability seals");
    let leaf = root
        .attenuate(&AttenuationRequest {
            id: CapabilityId::new(2),
            operations: ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
            quota: ResourceVector::single(Grade::EgressBytes, 800),
            not_before: LogicalTime::new(5),
            expires_at: LogicalTime::new(90),
        })
        .expect("leaf attenuates");
    let sealed_leaf = leaf
        .seal(ISSUER_KEY, Some(sealed_root.tag()))
        .expect("leaf capability seals against its parent");
    vec![sealed_root, sealed_leaf]
}

fn verified_chain() -> VerifiedCapabilityChain {
    VerifiedCapabilityChain::verify(&sealed_chain(), ISSUER_KEY)
        .expect("bounded authentic ancestry verifies")
}

fn external_request(effect_id: u128, cost: u64) -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(effect_id),
        parent_effect_id: None,
        operation: OperationClass::ExternalIntegration,
        cost: ResourceVector::single(Grade::EgressBytes, cost),
        input_commitment: [0x91; 32],
    }
}

#[derive(Clone)]
struct Reader {
    observed_at: LogicalTime,
    revoked: Vec<CapabilityId>,
    profile: [u8; 32],
}

impl CapabilityRevocationReader for Reader {
    fn reader_profile(&self) -> [u8; 32] {
        self.profile
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
        profile: [0x83; 32],
    };
    read_capability_revocations(&mut reader, receipt, run, LogicalTime::new(20), max_age, 32)
        .expect("bounded revocation read")
}

#[test]
fn high_value_effect_binds_verified_ancestry_freshness_and_exact_request() {
    let receipt = authority_receipt(1_001, 0x21);
    let run = authenticated_run(&receipt);
    let chain = verified_chain();
    let revocations = revocations(&receipt, &run, Vec::new(), 21, 20);
    let request = external_request(1, 100);

    let first = CapabilityEffectAuthorization::authorize(
        &run,
        &chain,
        &revocations,
        LogicalTime::new(22),
        &request,
    )
    .expect("fresh non-revoked ancestry authorizes the exact effect");
    let second = CapabilityEffectAuthorization::authorize(
        &run,
        &chain,
        &revocations,
        LogicalTime::new(22),
        &request,
    )
    .expect("identical authorization is deterministic");
    assert_eq!(first.authorization_id(), second.authorization_id());
    assert_eq!(first.revocation_receipt_id(), revocations.receipt_id());
    assert_eq!(first.verified_chain_id(), chain.chain_id());
    assert_eq!(
        first.run_commitment(),
        run.commitment().expect("run identity")
    );
    assert_eq!(first.capability_id(), CapabilityId::new(2));
    assert_eq!(first.effect_id(), EffectId::new(1));
    assert_eq!(first.valid_until(), LogicalTime::new(41));

    let changed = CapabilityEffectAuthorization::authorize(
        &run,
        &chain,
        &revocations,
        LogicalTime::new(22),
        &external_request(2, 100),
    )
    .expect("another request can be authorized independently");
    assert_ne!(first.authorization_id(), changed.authorization_id());

    let mut broker =
        RevocationCheckedEffectBroker::open(run, RegionId::new(1), AgentInstanceId::new(1))
            .expect("complete run opens the checked broker");
    let grant = broker
        .request_high_value(&chain, &revocations, LogicalTime::new(22), &request)
        .expect("checked broker accepts the authorized high-value effect");
    assert_eq!(grant.authorization(), first);
    assert_eq!(grant.record().effect_id, EffectId::new(1));
    assert_eq!(grant.record().capability_id, CapabilityId::new(2));
    assert_eq!(broker.records().len(), 1);
    assert_eq!(broker.authorizations(), &[first]);
    let _release = broker
        .abort_high_value(grant)
        .expect("authorized reservation can abort cleanly");
    assert!(broker.close().is_quiescent());
}

#[test]
fn revoked_ancestor_refuses_before_budget_or_journal_state_moves() {
    let receipt = authority_receipt(1_002, 0x22);
    let run = authenticated_run(&receipt);
    let chain = verified_chain();
    let revoked = revocations(&receipt, &run, vec![CapabilityId::new(1)], 21, 20);
    let clean = revocations(&receipt, &run, Vec::new(), 21, 20);
    let request = external_request(1, 800);
    let mut broker =
        RevocationCheckedEffectBroker::open(run, RegionId::new(2), AgentInstanceId::new(2))
            .expect("checked broker opens");

    let refusal = broker
        .request_high_value(&chain, &revoked, LogicalTime::new(22), &request)
        .expect_err("revoking any ancestor invalidates the leaf");
    assert!(matches!(
        refusal,
        RevocationCheckedEffectRefusal::Authorization(
            CapabilityEffectAuthorizationRefusal::CapabilityRevoked {
                capability_id,
                chain_index: 0,
                revocation_generation: REVOCATION_GENERATION,
            }
        ) if capability_id == CapabilityId::new(1)
    ));
    assert!(broker.records().is_empty());
    assert!(broker.authorizations().is_empty());

    let grant = broker
        .request_high_value(&chain, &clean, LogicalTime::new(22), &request)
        .expect("the refused attempt consumed no budget or effect identity");
    let _release = broker
        .abort_high_value(grant)
        .expect("accepted reservation aborts");
    assert!(broker.close().is_quiescent());
}

#[test]
fn stale_revocation_read_and_same_id_run_equivocation_fail_closed() {
    let receipt = authority_receipt(1_003, 0x23);
    let run = authenticated_run(&receipt);
    let chain = verified_chain();
    let stale = revocations(&receipt, &run, Vec::new(), 21, 2);
    let request = external_request(1, 100);

    assert_eq!(
        CapabilityEffectAuthorization::authorize(
            &run,
            &chain,
            &stale,
            LogicalTime::new(23),
            &request,
        )
        .expect_err("freshness deadline is exclusive"),
        CapabilityEffectAuthorizationRefusal::RevocationReadStale {
            observed_at: LogicalTime::new(21),
            valid_until: LogicalTime::new(23),
            authorized_at: LogicalTime::new(23),
        }
    );

    let altered = IntentRun::new_authenticated(
        RunId::new(7),
        receipt,
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        ResourceVector::single(Grade::EgressBytes, 100),
        LogicalTime::new(200),
    )
    .expect("same-ID altered run is structurally valid");
    let expected = stale.run_commitment();
    let observed = altered.commitment().expect("altered run identity");
    assert_ne!(expected, observed);
    assert_eq!(
        CapabilityEffectAuthorization::authorize(
            &altered,
            &chain,
            &stale,
            LogicalTime::new(22),
            &request,
        )
        .expect_err("same numeric RunId cannot replace the complete run"),
        CapabilityEffectAuthorizationRefusal::RunCommitmentMismatch { expected, observed }
    );
}

#[test]
fn checked_broker_has_no_raw_high_value_fallthrough() {
    let receipt = authority_receipt(1_004, 0x24);
    let run = authenticated_run(&receipt);
    let high_capability = verified_chain().leaf().clone();
    let mut broker =
        RevocationCheckedEffectBroker::open(run, RegionId::new(4), AgentInstanceId::new(4))
            .expect("checked broker opens");
    let request = external_request(1, 100);

    assert!(matches!(
        broker
            .request_low_risk(&high_capability, LogicalTime::new(22), &request)
            .expect_err("high-value work cannot use the ordinary path"),
        RevocationCheckedEffectRefusal::RevocationEvidenceRequired {
            operation: OperationClass::ExternalIntegration,
        }
    ));
    assert!(broker.records().is_empty());
    assert!(broker.authorizations().is_empty());
    assert!(broker.close().is_quiescent());
}

#[test]
fn legacy_run_cannot_authorize_high_value_effects() {
    let receipt = authority_receipt(1_005, 0x25);
    let authenticated = authenticated_run(&receipt);
    let revocations = revocations(&receipt, &authenticated, Vec::new(), 21, 20);
    let legacy = IntentRun::new(
        RunId::new(7),
        authenticated.base_authority(),
        authenticated.allowed_operation_classes(),
        authenticated.resource_budget(),
        authenticated.expiry(),
    )
    .expect("legacy compatibility run opens");
    let chain = verified_chain();
    let request = external_request(1, 100);
    let mut broker =
        RevocationCheckedEffectBroker::open(legacy, RegionId::new(5), AgentInstanceId::new(5))
            .expect("legacy run still has a complete legacy commitment");

    assert!(matches!(
        broker
            .request_high_value(&chain, &revocations, LogicalTime::new(22), &request)
            .expect_err("high-value effects require a complete authenticated read"),
        RevocationCheckedEffectRefusal::Authorization(
            CapabilityEffectAuthorizationRefusal::RunAuthorityReceiptRequired
        )
    ));
    assert!(broker.records().is_empty());
    assert!(broker.close().is_quiescent());
}

#[test]
fn revocation_reader_is_bounded_deduplicated_and_profiled() {
    let receipt = authority_receipt(1_006, 0x26);
    let run = authenticated_run(&receipt);

    let mut excessive = Reader {
        observed_at: LogicalTime::new(21),
        revoked: vec![CapabilityId::new(1), CapabilityId::new(2)],
        profile: [0x83; 32],
    };
    assert_eq!(
        read_capability_revocations(&mut excessive, &receipt, &run, LogicalTime::new(20), 20, 1,)
            .expect_err("reader cannot exceed the request row bound"),
        CapabilityRevocationReadRefusal::TooManyRevocations {
            observed: 2,
            request_limit: 1,
            hard_limit: fgit_agent::MAX_CAPABILITY_REVOCATIONS,
        }
    );

    let mut duplicate = Reader {
        observed_at: LogicalTime::new(21),
        revoked: vec![CapabilityId::new(1), CapabilityId::new(1)],
        profile: [0x83; 32],
    };
    assert_eq!(
        read_capability_revocations(&mut duplicate, &receipt, &run, LogicalTime::new(20), 20, 32,)
            .expect_err("duplicate revocations are not silently collapsed"),
        CapabilityRevocationReadRefusal::DuplicateRevocation {
            capability_id: CapabilityId::new(1),
        }
    );

    let mut zero_profile = Reader {
        observed_at: LogicalTime::new(21),
        revoked: Vec::new(),
        profile: [0; 32],
    };
    assert_eq!(
        read_capability_revocations(
            &mut zero_profile,
            &receipt,
            &run,
            LogicalTime::new(20),
            20,
            32,
        )
        .expect_err("anonymous revocation readers are refused before I/O"),
        CapabilityRevocationReadRefusal::ZeroReaderProfile
    );
}

#[test]
fn verified_chain_rejects_empty_keys_and_repeated_capability_ids() {
    assert_eq!(
        VerifiedCapabilityChain::verify(&sealed_chain(), b"")
            .expect_err("issuer key identity cannot be omitted"),
        VerifiedCapabilityChainRefusal::EmptyIssuerKey
    );

    let root = Capability::issue(
        CapabilityId::new(9),
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        ResourceVector::single(Grade::EgressBytes, 100),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .expect("root capability issues");
    let sealed_root = root.seal(ISSUER_KEY, None).expect("root seals");
    let repeated = root
        .attenuate(&AttenuationRequest {
            id: CapabilityId::new(9),
            operations: root.operations(),
            quota: root.quota(),
            not_before: root.not_before(),
            expires_at: root.expires_at(),
        })
        .expect("legacy attenuation permits a repeated identifier");
    let sealed_repeated = repeated
        .seal(ISSUER_KEY, Some(sealed_root.tag()))
        .expect("repeated-ID child seals");

    assert_eq!(
        VerifiedCapabilityChain::verify(&[sealed_root, sealed_repeated], ISSUER_KEY)
            .expect_err("high-value ancestry requires unambiguous identities"),
        VerifiedCapabilityChainRefusal::DuplicateCapabilityId {
            capability_id: CapabilityId::new(9),
        }
    );
}
