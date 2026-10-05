//! Non-durable reference storage with counted I/O and exact-key fault injection.
use super::super::*;
use std::{future::Future, sync::{Mutex, atomic::{AtomicUsize, Ordering}}};
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore,
    AuthorityVersionToken, CasOutcome, HeadInit, HeadReadReceipt, ImmutableKey,
    ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId,
    initialize_repository, outcome_index_root, stage_hidden_ref_policy,
    stage_latest_repository_incarnation_configuration, stage_repository_incarnation_configuration,
};
use fgit_codec::{
    HiddenRefPolicyBody, RepositoryAuthorityHeadBody, RepositoryIncarnationConfigurationBody,
    RepositoryIncarnationConfigurationBodyV2_1,
};
use fgit_crypto::IdentityDomain;
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch, RootLayoutVersion};

pub(super) struct Store {
    pub(super) backend: MemoryAuthorityStore,
    pub(super) head_override: Mutex<Option<HeadReadReceipt>>,
    keys: Mutex<Vec<ImmutableKey>>,
    calls: AtomicUsize,
    head_reads: AtomicUsize,
    fault: Mutex<Option<(ImmutableKey, Option<Vec<u8>>)>>,
}
impl Store {
    pub(super) fn keys(&self) -> Vec<ImmutableKey> { self.keys.lock().unwrap().clone() }
    pub(super) fn calls(&self) -> usize { self.calls.load(Ordering::Relaxed) }
    pub(super) fn head_reads(&self) -> usize { self.head_reads.load(Ordering::Relaxed) }
    pub(super) fn replace(&self, key: ImmutableKey, value: Option<Vec<u8>>) {
        *self.fault.lock().unwrap() = Some((key, value));
    }
    pub(super) fn clear_fault(&self) { *self.fault.lock().unwrap() = None; }
}
impl AsyncAuthorityStore for Store {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId { self.backend.instance_id() }
    fn limits(&self) -> AuthorityLimits { self.backend.limits() }
    fn put_if_absent(&self, _: &(), key: &ImmutableKey, body: &[u8])
        -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send
    {
        let result = self.backend.put_if_absent(key, body);
        async move { result }
    }
    fn read_immutable(&self, _: &(), key: &ImmutableKey)
        -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send
    {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.keys.lock().unwrap().push(key.clone());
        let fault = self.fault.lock().unwrap().clone();
        let result = if let Some((_, replacement)) = fault.filter(|(target, _)| target == key) {
            Ok(replacement.map_or(ImmutableRead::Absent, ImmutableRead::Present))
        } else { self.backend.read_immutable(key) };
        async move { result }
    }
    fn initialize_head(&self, _: &(), key: &HeadKey, generation: HeadGeneration, body: &[u8])
        -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send
    {
        let result = self.backend.initialize_head(key, generation, body);
        async move { result }
    }
    fn read_head(&self, _: &(), key: &HeadKey)
        -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send
    {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.head_reads.fetch_add(1, Ordering::Relaxed);
        let result = if let Some(receipt) = self.head_override.lock().unwrap().clone() {
            Ok(HeadRead::Present(receipt))
        } else { self.backend.read_head(key) };
        async move { result }
    }
    fn compare_exchange_head(&self, _: &(), key: &HeadKey, expected: AuthorityVersionToken,
        generation: HeadGeneration, body: &[u8])
        -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send
    {
        let result = self.backend.compare_exchange_head(key, expected, generation, body);
        async move { result }
    }
    fn authenticate_head_receipt(&self, _: &(), receipt: &HeadReadReceipt)
        -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send
    {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let result = self.backend.authenticate_head_receipt(receipt);
        async move { result }
    }
}

pub(super) fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("model store unexpectedly suspended"),
    }
}

fn digest(byte: u8) -> Digest {
    Digest::new(DigestAlgorithmId::try_new(0xfff1).unwrap(), DigestBytes::try_new(&[byte; 32]).unwrap())
}
pub(super) struct Fixture {
    pub(super) store: Store,
    pub(super) key: HeadKey,
    pub(super) binding: Binding,
    pub(super) head: RepositoryAuthorityHeadBody,
    pub(super) configuration: RepositoryIncarnationConfigurationBodyV2_1,
    policy: HiddenRefPolicyBody,
}
impl Fixture {
    pub(super) fn new(format: GitHashAlgorithm, with_policy: bool) -> Self {
        let backend = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x5e1ec7));
        let key = HeadKey::new(b"event-selection-only".to_vec()).unwrap();
        let binding = Binding {
            repository: RepositoryId::from_bytes([0xd1; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([0xd2; 16]), format,
        };
        let policy = HiddenRefPolicyBody {
            rules: vec![b"refs/heads/private".to_vec(), b"!refs/heads/private/open".to_vec()],
        };
        let policy_root = if with_policy { Some(stage_hidden_ref_policy(&backend, &policy).unwrap()) } else { None };
        let configuration = RepositoryIncarnationConfigurationBodyV2_1 {
            root_layout: RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
            object_format: format, repository_incarnation_id: binding.incarnation, policy_root,
        };
        let configuration_root = stage_latest_repository_incarnation_configuration(&backend, &configuration).unwrap();
        let head = RepositoryAuthorityHeadBody {
            repository_id: binding.repository, generation: HeadGeneration::FIRST,
            predecessor_head_id: None, decision_tail_id: None,
            latest_decision_sequence: None, latest_committed_rcr_id: None,
            latest_repository_sequence: None,
            ref_root: digest(1), forge_position_root: digest(2),
            outcome_index_root: outcome_index_root(&[]).unwrap(),
            retention_root: digest(3), outbox_root: digest(4), configuration_root,
            policy_epoch: PolicyEpoch::FIRST, format_registry_epoch: RegistryEpoch::FIRST,
            last_checkpoint_id: None,
        };
        initialize_repository(&backend, &key, &head).unwrap();
        Self {
            store: Store { backend, head_override: Mutex::new(None), keys: Mutex::new(Vec::new()),
                calls: AtomicUsize::new(0), head_reads: AtomicUsize::new(0), fault: Mutex::new(None) },
            key, binding, head, configuration, policy,
        }
    }
    pub(super) fn configuration_key(&self) -> ImmutableKey {
        fgit_authority::body_key(IdentityDomain::RepositoryConfiguration, &self.configuration).unwrap()
    }
    pub(super) fn policy_key(&self) -> ImmutableKey {
        fgit_authority::body_key(IdentityDomain::HiddenRefPolicy, &self.policy).unwrap()
    }
    pub(super) fn head_id(&self) -> RepositoryAuthorityHeadId {
        authority_head_identity(&self.head).unwrap()
    }
    pub(super) fn select(&self, binding: Binding, expected: Option<RepositoryAuthorityHeadId>)
        -> Result<EventReadBasis, ForgeEventReadRefusal>
    {
        ready(read_basis(&self.store, &(), &self.key, binding, expected, &|| false))
    }
    pub(super) fn use_historical_configuration(&mut self) {
        let configuration = RepositoryIncarnationConfigurationBody {
            root_layout: self.configuration.root_layout, object_format: self.binding.format,
            repository_incarnation_id: self.binding.incarnation,
        };
        self.head.configuration_root = stage_repository_incarnation_configuration(&self.store.backend, &configuration).unwrap();
        self.key = HeadKey::new(b"historical-event-selection".to_vec()).unwrap();
        initialize_repository(&self.store.backend, &self.key, &self.head).unwrap();
    }
}
