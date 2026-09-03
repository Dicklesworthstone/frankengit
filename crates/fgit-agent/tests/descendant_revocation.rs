#![forbid(unsafe_code)]
//! Public-path tests for current descendant-head capability revocation reads.

use core::future::Future;
use std::task::{Context, Poll, Waker};

use fgit_agent::{
    AttenuationRequest, AuthorityReadReceipt, Capability, CapabilityEffectAuthorizationRefusal,
    CapabilityId, CapabilityRevocationReadRefusal, ClassSet,
    CurrentAuthorityCapabilityEffectAuthorization, CurrentAuthorityCapabilityRevocationReadRefusal,
    DESCENDANT_AUTHORITY_CAPABILITY_REVOCATION_READER_PROFILE, EffectId, EffectRequest, IntentRun,
    LogicalTime, OperationClass, RunId, VerifiedCapabilityChain,
    read_current_authority_capability_revocations,
    read_current_authority_capability_revocations_async,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityHeadAncestryRefusal,
    AuthorityLimits, AuthorityRefusal, AuthorityStore, AuthorityVersionToken,
    CapabilityRevocationGenerationBody, CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt,
    ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId,
    authority_head_identity, body_key, initialize_repository, outcome_index_root,
    stage_capability_revocation_generation,
    stage_revocation_aware_repository_incarnation_configuration,
};
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryIncarnationConfigurationBodyV2_2, encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId,
    RepositoryId, RepositoryIncarnationId, RootLayoutVersion, TenantId,
};

const ISSUER_KEY: &[u8] = b"descendant-authority-revocation-test";

const fn tenant(marker: u8) -> TenantId {
    TenantId::from_bytes([marker; 16])
}

const fn repository(marker: u8) -> RepositoryId {
    RepositoryId::from_bytes([marker; 16])
}

const fn incarnation(marker: u8) -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([marker; 16])
}

fn digest(marker: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("the empty outcome root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[marker; 32]).expect("a fixed-width digest"),
    )
}

fn stage_configuration(
    store: &MemoryAuthorityStore,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    repository_incarnation_id: RepositoryIncarnationId,
    revoked: &[CapabilityId],
    marker: u8,
) -> Digest {
    let generation = CapabilityRevocationGenerationBody::try_new(
        tenant_id,
        repository_id,
        repository_incarnation_id,
        PolicyEpoch::FIRST,
        None,
        revoked
            .iter()
            .map(|capability_id| capability_id.value().to_be_bytes())
            .collect(),
        digest(marker),
    )
    .expect("the bounded revocation generation constructs");
    let generation = stage_capability_revocation_generation(store, &generation)
        .expect("the revocation generation stages");
    let configuration = RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: fgit_types::GitHashAlgorithm::Sha256,
        repository_incarnation_id,
        policy_root: None,
        capability_revocation_root: Some(generation.generation_root()),
    };
    stage_revocation_aware_repository_incarnation_configuration(store, &configuration)
        .expect("the revocation-aware configuration stages")
}

fn head(
    repository_id: RepositoryId,
    generation: u64,
    predecessor_head_id: Option<RepositoryAuthorityHeadId>,
    configuration_root: Digest,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    let root = outcome_index_root(&[]).expect("the empty outcome root is canonical");
    RepositoryAuthorityHeadBody {
        repository_id,
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
            .expect("the immutable head write succeeds"),
        PutOutcome::Created | PutOutcome::IdenticalRetry
    ));
}

fn advance(
    store: &MemoryAuthorityStore,
    head_key: &HeadKey,
    predecessor: &RepositoryAuthorityHeadBody,
    configuration_root: Digest,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    let next = head(
        predecessor.repository_id,
        predecessor.generation.get() + 1,
        Some(head_id(predecessor)),
        configuration_root,
        marker,
    );
    stage_head(store, &next);
    let HeadRead::Present(receipt) = store.read_head(head_key).expect("the head reads") else {
        panic!("the initialized head must be present");
    };
    assert!(matches!(
        store
            .compare_exchange_head(
                head_key,
                receipt.token(),
                next.generation,
                &encode_body(&next).expect("the successor encodes"),
            )
            .expect("the conditional replacement succeeds"),
        CasOutcome::Committed(_)
    ));
    next
}

struct Fixture {
    tenant_id: TenantId,
    repository_id: RepositoryId,
    repository_incarnation_id: RepositoryIncarnationId,
    store: MemoryAuthorityStore,
    head_key: HeadKey,
    genesis: RepositoryAuthorityHeadBody,
    run: IntentRun,
}

fn fixture(store_id: u64) -> Fixture {
    let tenant_id = tenant(0x11);
    let repository_id = repository(0x22);
    let repository_incarnation_id = incarnation(0x33);
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let configuration_root = stage_configuration(
        &store,
        tenant_id,
        repository_id,
        repository_incarnation_id,
        &[],
        0x90,
    );
    let genesis = head(repository_id, 1, None, configuration_root, 0x41);
    let head_key = HeadKey::new(format!("descendant-revocation-{store_id}").into_bytes())
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
        ResourceVector::single(Grade::EgressBytes, 1_000),
        LogicalTime::new(100),
    )
    .expect("the authenticated run opens");
    Fixture {
        tenant_id,
        repository_id,
        repository_incarnation_id,
        store,
        head_key,
        genesis,
        run,
    }
}

fn sealed_chain() -> Vec<fgit_agent::SealedCapability> {
    let root = Capability::issue(
        CapabilityId::new(1),
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        ResourceVector::single(Grade::EgressBytes, 1_000),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .expect("the root capability issues");
    let sealed_root = root.seal(ISSUER_KEY, None).expect("the root seals");
    let leaf = root
        .attenuate(&AttenuationRequest {
            id: CapabilityId::new(2),
            operations: ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
            quota: ResourceVector::single(Grade::EgressBytes, 800),
            not_before: LogicalTime::new(5),
            expires_at: LogicalTime::new(90),
        })
        .expect("the leaf attenuates");
    let sealed_leaf = leaf
        .seal(ISSUER_KEY, Some(sealed_root.tag()))
        .expect("the leaf seals against the root");
    vec![sealed_root, sealed_leaf]
}

fn request() -> EffectRequest {
    EffectRequest {
        effect_id: EffectId::new(1),
        parent_effect_id: None,
        operation: OperationClass::ExternalIntegration,
        cost: ResourceVector::single(Grade::EgressBytes, 100),
        input_commitment: [0x81; 32],
    }
}

#[test]
fn a_run_opened_at_genesis_observes_a_later_revoked_ancestor() {
    let fixture = fixture(401);
    let current_configuration = stage_configuration(
        &fixture.store,
        fixture.tenant_id,
        fixture.repository_id,
        fixture.repository_incarnation_id,
        &[CapabilityId::new(1)],
        0x91,
    );
    let current = advance(
        &fixture.store,
        &fixture.head_key,
        &fixture.genesis,
        current_configuration,
        0x42,
    );

    let first = read_current_authority_capability_revocations(
        &fixture.store,
        fixture.tenant_id,
        &fixture.head_key,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
        1,
    )
    .expect("the current head descends from the run basis");
    let second = read_current_authority_capability_revocations(
        &fixture.store,
        fixture.tenant_id,
        &fixture.head_key,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
        1,
    )
    .expect("identical canonical input is deterministic");

    assert_eq!(first, second);
    assert_eq!(first.ancestry().hops(), 1);
    assert_eq!(
        first.ancestry().ancestor_head_id(),
        head_id(&fixture.genesis)
    );
    assert_eq!(first.current_authority_head_id(), head_id(&current));
    assert_eq!(first.revoked_capability_ids(), &[CapabilityId::new(1)]);
    assert_eq!(
        first.reader_profile(),
        DESCENDANT_AUTHORITY_CAPABILITY_REVOCATION_READER_PROFILE
    );

    let chain = VerifiedCapabilityChain::verify(&sealed_chain(), ISSUER_KEY)
        .expect("the capability ancestry verifies cryptographically");
    assert!(matches!(
        CurrentAuthorityCapabilityEffectAuthorization::authorize(
            &fixture.run,
            &chain,
            &first,
            LogicalTime::new(21),
            &request(),
        ),
        Err(CapabilityEffectAuthorizationRefusal::CapabilityRevoked {
            capability_id,
            chain_index: 0,
            ..
        }) if capability_id == CapabilityId::new(1)
    ));
}

#[test]
fn successful_effect_authorization_retains_the_combined_ancestry_receipt() {
    let fixture = fixture(402);
    let current_configuration = stage_configuration(
        &fixture.store,
        fixture.tenant_id,
        fixture.repository_id,
        fixture.repository_incarnation_id,
        &[],
        0x92,
    );
    let _current = advance(
        &fixture.store,
        &fixture.head_key,
        &fixture.genesis,
        current_configuration,
        0x43,
    );
    let revocations = read_current_authority_capability_revocations(
        &fixture.store,
        fixture.tenant_id,
        &fixture.head_key,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
        1,
    )
    .expect("the empty current generation resolves canonically");
    let chain = VerifiedCapabilityChain::verify(&sealed_chain(), ISSUER_KEY)
        .expect("the capability ancestry verifies");

    let first = CurrentAuthorityCapabilityEffectAuthorization::authorize(
        &fixture.run,
        &chain,
        &revocations,
        LogicalTime::new(21),
        &request(),
    )
    .expect("the non-revoked request authorizes");
    let second = CurrentAuthorityCapabilityEffectAuthorization::authorize(
        &fixture.run,
        &chain,
        &revocations,
        LogicalTime::new(21),
        &request(),
    )
    .expect("the same proof is deterministic");

    assert_eq!(first, second);
    assert_eq!(first.revocation_receipt_id(), revocations.receipt_id());
    assert_eq!(
        first.authorization().revocation_receipt_id(),
        revocations.admitted_receipt_id(),
        "the inner authorization and outer ancestry proof must name the two bound receipt layers"
    );
}

#[test]
fn a_canonical_head_pointing_to_a_same_generation_fork_is_rejected() {
    let fixture = fixture(403);
    let alternate_genesis = head(
        fixture.repository_id,
        1,
        None,
        fixture.genesis.configuration_root,
        0xA1,
    );
    assert_ne!(head_id(&alternate_genesis), head_id(&fixture.genesis));
    stage_head(&fixture.store, &alternate_genesis);
    let current_configuration = stage_configuration(
        &fixture.store,
        fixture.tenant_id,
        fixture.repository_id,
        fixture.repository_incarnation_id,
        &[],
        0x93,
    );
    let forked_current = head(
        fixture.repository_id,
        2,
        Some(head_id(&alternate_genesis)),
        current_configuration,
        0xA2,
    );
    stage_head(&fixture.store, &forked_current);
    let HeadRead::Present(receipt) = fixture
        .store
        .read_head(&fixture.head_key)
        .expect("the genesis head reads")
    else {
        panic!("the genesis head must exist");
    };
    assert!(matches!(
        fixture
            .store
            .compare_exchange_head(
                &fixture.head_key,
                receipt.token(),
                forked_current.generation,
                &encode_body(&forked_current).expect("the forked current head encodes"),
            )
            .expect("the storage CAS itself accepts the well-formed bytes"),
        CasOutcome::Committed(_)
    ));

    let refusal = read_current_authority_capability_revocations(
        &fixture.store,
        fixture.tenant_id,
        &fixture.head_key,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
        1,
    )
    .expect_err("a generation-correct fork must not select revocation state");

    assert_eq!(
        refusal,
        CurrentAuthorityCapabilityRevocationReadRefusal::Ancestry(Box::new(
            AuthorityHeadAncestryRefusal::NotDescendant {
                expected: Box::new(head_id(&fixture.genesis)),
                observed: Box::new(head_id(&alternate_genesis)),
            },
        ))
    );
}

#[test]
fn a_historical_token_cannot_cross_head_slots() {
    let fixture = fixture(404);
    let wrong_key =
        HeadKey::new(b"descendant-revocation-wrong-slot".to_vec()).expect("a bounded wrong key");

    assert!(matches!(
        read_current_authority_capability_revocations(
            &fixture.store,
            fixture.tenant_id,
            &wrong_key,
            &fixture.run,
            LogicalTime::new(20),
            20,
            32,
            0,
        ),
        Err(CurrentAuthorityCapabilityRevocationReadRefusal::HistoricalAuthentication(
            refusal,
        )) if *refusal == AuthorityFailure::Refused(AuthorityRefusal::TokenKeyMismatch)
    ));
}

#[test]
fn identical_historical_bytes_in_another_store_do_not_authenticate() {
    let fixture = fixture(405);
    let foreign = MemoryAuthorityStore::new(StoreInstanceId::from_raw(406));
    stage_head(&foreign, &fixture.genesis);

    assert!(matches!(
        read_current_authority_capability_revocations(
            &foreign,
            fixture.tenant_id,
            &fixture.head_key,
            &fixture.run,
            LogicalTime::new(20),
            20,
            32,
            0,
        ),
        Err(CurrentAuthorityCapabilityRevocationReadRefusal::HistoricalAuthentication(
            refusal,
        )) if *refusal == AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken)
    ));
}

#[test]
fn ancestry_limit_refuses_instead_of_using_a_partial_current_view() {
    let fixture = fixture(407);
    let current_configuration = stage_configuration(
        &fixture.store,
        fixture.tenant_id,
        fixture.repository_id,
        fixture.repository_incarnation_id,
        &[],
        0x94,
    );
    let _current = advance(
        &fixture.store,
        &fixture.head_key,
        &fixture.genesis,
        current_configuration,
        0x44,
    );

    assert_eq!(
        read_current_authority_capability_revocations(
            &fixture.store,
            fixture.tenant_id,
            &fixture.head_key,
            &fixture.run,
            LogicalTime::new(20),
            20,
            32,
            0,
        )
        .expect_err("zero admitted hops cannot truncate a one-hop proof"),
        CurrentAuthorityCapabilityRevocationReadRefusal::Ancestry(Box::new(
            AuthorityHeadAncestryRefusal::HopLimitExceeded {
                required: 1,
                limit: 0,
            },
        ))
    );
}

#[test]
fn malformed_request_refuses_before_historical_authority_resolution() {
    let fixture = fixture(408);
    let empty = MemoryAuthorityStore::new(StoreInstanceId::from_raw(409));

    assert_eq!(
        read_current_authority_capability_revocations(
            &empty,
            fixture.tenant_id,
            &fixture.head_key,
            &fixture.run,
            LogicalTime::new(20),
            0,
            32,
            0,
        )
        .expect_err("zero freshness is a request refusal, not a missing-head refusal"),
        CurrentAuthorityCapabilityRevocationReadRefusal::Read(Box::new(
            CapabilityRevocationReadRefusal::ZeroMaxAge,
        ))
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
        (): &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::put_if_absent(self.0, key, body))
    }

    fn read_immutable(
        &self,
        (): &Self::Context,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::read_immutable(self.0, key))
    }

    fn initialize_head(
        &self,
        (): &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::initialize_head(
            self.0, key, generation, body,
        ))
    }

    fn read_head(
        &self,
        (): &Self::Context,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::read_head(self.0, key))
    }

    fn compare_exchange_head(
        &self,
        (): &Self::Context,
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
        (): &Self::Context,
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::authenticate_head_receipt(self.0, receipt))
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[test]
fn synchronous_and_asynchronous_current_readers_are_identical() {
    let fixture = fixture(410);
    let current_configuration = stage_configuration(
        &fixture.store,
        fixture.tenant_id,
        fixture.repository_id,
        fixture.repository_incarnation_id,
        &[CapabilityId::new(2)],
        0x95,
    );
    let _current = advance(
        &fixture.store,
        &fixture.head_key,
        &fixture.genesis,
        current_configuration,
        0x45,
    );
    let synchronous = read_current_authority_capability_revocations(
        &fixture.store,
        fixture.tenant_id,
        &fixture.head_key,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
        1,
    )
    .expect("the synchronous current reader succeeds");
    let mirror = AsyncMirror(&fixture.store);
    let asynchronous = block_on(read_current_authority_capability_revocations_async(
        &mirror,
        &(),
        fixture.tenant_id,
        &fixture.head_key,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
        1,
    ))
    .expect("the asynchronous current reader succeeds");

    assert_eq!(synchronous, asynchronous);
}
