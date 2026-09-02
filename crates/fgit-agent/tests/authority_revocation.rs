#![forbid(unsafe_code)]
//! Public-path tests for the canonical authority-to-agent revocation adapter.

use core::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use fgit_agent::{
    AUTHORITY_CAPABILITY_REVOCATION_READER_PROFILE, AttenuationRequest,
    AuthorityCapabilityRevocationReadRefusal, AuthorityReadReceipt, Capability,
    CapabilityEffectAuthorization, CapabilityEffectAuthorizationRefusal, CapabilityId,
    CapabilityRevocationReadRefusal, ClassSet, EffectId, EffectRequest, IntentRun, LogicalTime,
    OperationClass, RunId, VerifiedCapabilityChain, read_authority_capability_revocations,
    read_authority_capability_revocations_async,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthorityFailure, AuthorityLimits, AuthorityRefusal, AuthorityStore,
    AuthorityVersionToken, CapabilityRevocationAuthorityFailure,
    CapabilityRevocationGenerationBody, CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt,
    ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId,
    initialize_repository, outcome_index_root, stage_capability_revocation_generation,
    stage_latest_repository_incarnation_configuration,
    stage_revocation_aware_repository_incarnation_configuration,
};
use fgit_codec::{
    RepositoryAuthorityHeadBody, RepositoryIncarnationConfigurationBodyV2_1,
    RepositoryIncarnationConfigurationBodyV2_2,
};
use fgit_resource::{Grade, ResourceVector};
use fgit_types::{
    Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryId,
    RepositoryIncarnationId, RootLayoutVersion, TenantId,
};

const ISSUER_KEY: &[u8] = b"canonical-authority-revocation-test";

const fn tenant(byte: u8) -> TenantId {
    TenantId::from_bytes([byte; 16])
}

const fn repository(byte: u8) -> RepositoryId {
    RepositoryId::from_bytes([byte; 16])
}

const fn incarnation(byte: u8) -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([byte; 16])
}

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn head(repository_id: RepositoryId, configuration_root: Digest) -> RepositoryAuthorityHeadBody {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    RepositoryAuthorityHeadBody {
        repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: root,
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

struct Fixture {
    tenant_id: TenantId,
    store: MemoryAuthorityStore,
    authenticated: fgit_authority::AuthenticatedHead,
    authority: AuthorityReadReceipt,
    run: IntentRun,
    generation_root: Digest,
}

fn fixture(store_id: u64, revoked: Vec<CapabilityId>) -> Fixture {
    let tenant_id = tenant(0x11);
    let repository_id = repository(0x22);
    let repository_incarnation_id = incarnation(0x33);
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let generation = CapabilityRevocationGenerationBody::try_new(
        tenant_id,
        repository_id,
        repository_incarnation_id,
        PolicyEpoch::FIRST,
        None,
        revoked
            .into_iter()
            .map(|capability_id| capability_id.value().to_be_bytes())
            .collect(),
        digest(0x91),
    )
    .expect("bounded canonical generation");
    let generation_stage = stage_capability_revocation_generation(&store, &generation)
        .expect("generation stages");
    let configuration = RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: fgit_types::GitHashAlgorithm::Sha256,
        repository_incarnation_id,
        policy_root: None,
        capability_revocation_root: Some(generation_stage.generation_root()),
    };
    let configuration_root =
        stage_revocation_aware_repository_incarnation_configuration(&store, &configuration)
            .expect("revocation-aware configuration stages");
    let head_key = HeadKey::new(format!("agent-authority-revocation-{store_id}").into_bytes())
        .expect("bounded head key");
    let head_read = match initialize_repository(&store, &head_key, &head(repository_id, configuration_root))
        .expect("head initializes")
    {
        HeadInit::Created(receipt) => receipt,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => {
            panic!("fresh store must create its head")
        }
    };
    let authenticated = store
        .authenticate_head_receipt(&head_read)
        .expect("issuing store authenticates its receipt");
    let authority = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("authenticated head becomes an agent receipt");
    let run = IntentRun::new_authenticated(
        RunId::new(7),
        authority.clone(),
        ClassSet::from_classes(&[
            OperationClass::ReadCanonicalObject,
            OperationClass::ExternalIntegration,
        ]),
        ResourceVector::single(Grade::EgressBytes, 1_000),
        LogicalTime::new(100),
    )
    .expect("authenticated run opens");
    Fixture {
        tenant_id,
        store,
        authenticated,
        authority,
        run,
        generation_root: generation_stage.generation_root(),
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
    .expect("root capability issues");
    let sealed_root = root.seal(ISSUER_KEY, None).expect("root seals");
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
        .expect("leaf seals against root");
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
fn canonical_generation_produces_a_deterministic_receipt_and_revokes_ancestors() {
    let fixture = fixture(301, vec![CapabilityId::new(1)]);
    let first = read_authority_capability_revocations(
        &fixture.store,
        fixture.tenant_id,
        &fixture.authenticated,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
    )
    .expect("canonical authority generation becomes a revocation receipt");
    let second = read_authority_capability_revocations(
        &fixture.store,
        fixture.tenant_id,
        &fixture.authenticated,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
    )
    .expect("identical input is deterministic");

    assert_eq!(first.receipt_id(), second.receipt_id());
    assert_eq!(first.authority_read_receipt(), &fixture.authority);
    assert_eq!(first.run_commitment(), fixture.run.commitment().expect("run identity"));
    assert_eq!(first.revoked_capability_ids(), &[CapabilityId::new(1)]);
    assert_eq!(
        first.reader_profile(),
        AUTHORITY_CAPABILITY_REVOCATION_READER_PROFILE
    );
    assert_eq!(first.observed_at(), LogicalTime::new(20));
    assert_eq!(first.valid_until(), LogicalTime::new(40));
    assert_eq!(
        first.revocation_generation(),
        <[u8; 32]>::try_from(fixture.generation_root.bytes().as_bytes())
            .expect("generation identity is SHA-256")
    );

    let chain = VerifiedCapabilityChain::verify(&sealed_chain(), ISSUER_KEY)
        .expect("authentic ancestry verifies");
    assert!(matches!(
        CapabilityEffectAuthorization::authorize(
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
fn malformed_request_refuses_before_foreign_store_authentication() {
    let fixture = fixture(302, Vec::new());
    let foreign = MemoryAuthorityStore::new(StoreInstanceId::from_raw(303));

    assert_eq!(
        read_authority_capability_revocations(
            &foreign,
            fixture.tenant_id,
            &fixture.authenticated,
            &fixture.run,
            LogicalTime::new(20),
            0,
            32,
        )
        .expect_err("zero freshness is rejected before backend access"),
        AuthorityCapabilityRevocationReadRefusal::Read(Box::new(
            CapabilityRevocationReadRefusal::ZeroMaxAge,
        ))
    );
    assert_eq!(
        read_authority_capability_revocations(
            &foreign,
            fixture.tenant_id,
            &fixture.authenticated,
            &fixture.run,
            LogicalTime::new(20),
            20,
            0,
        )
        .expect_err("zero row bound is rejected before backend access"),
        AuthorityCapabilityRevocationReadRefusal::Read(Box::new(
            CapabilityRevocationReadRefusal::InvalidRowLimit {
                observed: 0,
                limit: fgit_agent::MAX_CAPABILITY_REVOCATIONS,
            },
        ))
    );
}

#[test]
fn authenticated_head_and_run_receipt_must_be_the_same_read_event() {
    let first = fixture(304, Vec::new());
    let second = fixture(305, vec![CapabilityId::new(9)]);

    assert_eq!(
        read_authority_capability_revocations(
            &first.store,
            first.tenant_id,
            &second.authenticated,
            &first.run,
            LogicalTime::new(20),
            20,
            32,
        )
        .expect_err("another authenticated head cannot accompany the run"),
        AuthorityCapabilityRevocationReadRefusal::AuthorityReceiptMismatch
    );
}

#[test]
fn valid_request_requires_same_store_authentication() {
    let fixture = fixture(306, Vec::new());
    let foreign = MemoryAuthorityStore::new(StoreInstanceId::from_raw(307));

    assert!(matches!(
        read_authority_capability_revocations(
            &foreign,
            fixture.tenant_id,
            &fixture.authenticated,
            &fixture.run,
            LogicalTime::new(20),
            20,
            32,
        ),
        Err(AuthorityCapabilityRevocationReadRefusal::Authority(refusal))
            if *refusal == CapabilityRevocationAuthorityFailure::Authority(
                AuthorityFailure::Refused(AuthorityRefusal::UnknownVersionToken)
            )
    ));
}

#[test]
fn configuration_without_a_revocation_root_is_not_an_empty_set() {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(308));
    let repository_id = repository(0x22);
    let configuration = RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: fgit_types::GitHashAlgorithm::Sha256,
        repository_incarnation_id: incarnation(0x33),
        policy_root: None,
    };
    let configuration_root = stage_latest_repository_incarnation_configuration(&store, &configuration)
        .expect("historical configuration stages");
    let head_key = HeadKey::new(b"agent-authority-revocation-legacy".to_vec())
        .expect("bounded head key");
    let head_read = match initialize_repository(&store, &head_key, &head(repository_id, configuration_root))
        .expect("head initializes")
    {
        HeadInit::Created(receipt) => receipt,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh head"),
    };
    let authenticated = store
        .authenticate_head_receipt(&head_read)
        .expect("head authenticates");
    let authority = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(10),
        [0x51; 32],
    )
    .expect("agent receipt");
    let run = IntentRun::new_authenticated(
        RunId::new(7),
        authority,
        ClassSet::from_classes(&[OperationClass::ExternalIntegration]),
        ResourceVector::single(Grade::EgressBytes, 1_000),
        LogicalTime::new(100),
    )
    .expect("run opens");

    assert_eq!(
        read_authority_capability_revocations(
            &store,
            tenant(0x11),
            &authenticated,
            &run,
            LogicalTime::new(20),
            20,
            32,
        )
        .expect_err("absence cannot become allow-all"),
        AuthorityCapabilityRevocationReadRefusal::Authority(Box::new(
            CapabilityRevocationAuthorityFailure::ConfigurationHasNoRevocationRoot,
        ))
    );
}

#[test]
fn caller_row_bound_is_enforced_after_exact_generation_resolution() {
    let fixture = fixture(309, vec![CapabilityId::new(1), CapabilityId::new(2)]);

    assert_eq!(
        read_authority_capability_revocations(
            &fixture.store,
            fixture.tenant_id,
            &fixture.authenticated,
            &fixture.run,
            LogicalTime::new(20),
            20,
            1,
        )
        .expect_err("caller bound cannot be widened by canonical storage"),
        AuthorityCapabilityRevocationReadRefusal::Read(Box::new(
            CapabilityRevocationReadRefusal::TooManyRevocations {
                observed: 2,
                request_limit: 1,
                hard_limit: fgit_agent::MAX_CAPABILITY_REVOCATIONS,
            },
        ))
    );
}

#[test]
fn synchronous_and_asynchronous_adapters_produce_the_same_receipt() {
    let fixture = fixture(310, vec![CapabilityId::new(2)]);
    let synchronous = read_authority_capability_revocations(
        &fixture.store,
        fixture.tenant_id,
        &fixture.authenticated,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
    )
    .expect("synchronous reader succeeds");
    let store = AsyncMemoryStore(fixture.store);
    let asynchronous = block_on(read_authority_capability_revocations_async(
        &store,
        &(),
        fixture.tenant_id,
        &fixture.authenticated,
        &fixture.run,
        LogicalTime::new(20),
        20,
        32,
    ))
    .expect("asynchronous reader succeeds");

    assert_eq!(synchronous, asynchronous);
}

struct AsyncMemoryStore(MemoryAuthorityStore);

impl AsyncAuthorityStore for AsyncMemoryStore {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        AuthorityStore::instance_id(&self.0)
    }

    fn limits(&self) -> AuthorityLimits {
        AuthorityStore::limits(&self.0)
    }

    fn put_if_absent(
        &self,
        _: &Self::Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::put_if_absent(&self.0, key, body))
    }

    fn read_immutable(
        &self,
        _: &Self::Context,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::read_immutable(&self.0, key))
    }

    fn initialize_head(
        &self,
        _: &Self::Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::initialize_head(
            &self.0,
            key,
            generation,
            body,
        ))
    }

    fn read_head(
        &self,
        _: &Self::Context,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::read_head(&self.0, key))
    }

    fn compare_exchange_head(
        &self,
        _: &Self::Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        new_generation: HeadGeneration,
        new_body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::compare_exchange_head(
            &self.0,
            key,
            expected,
            new_generation,
            new_body,
        ))
    }

    fn authenticate_head_receipt(
        &self,
        _: &Self::Context,
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<fgit_authority::AuthenticatedHead, AuthorityFailure>> + Send {
        core::future::ready(AuthorityStore::authenticate_head_receipt(&self.0, receipt))
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
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
