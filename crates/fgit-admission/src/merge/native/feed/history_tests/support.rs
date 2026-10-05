//! Non-durable model storage. Publication, commitments and readers are real;
//! these fixtures do not claim semantic admission or filesystem durability.
use super::super::*;
use std::future::Future;
use std::sync::Mutex;
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityStore, AuthorityVersionToken, CasOutcome, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome,
    StoreInstanceId, authority_head_identity, collect_cumulative_outcomes,
    initialize_repository, outcome_index_root, publish_decisions,
};
use fgit_chronicle::{PublicationPlan, ResultingRoots};
use fgit_codec::{CryptoBodyIdentity, RepositoryAuthorityHeadBody, RepositoryCommitRecord};
use fgit_forge::{ExpectedVersion, ForgeEventBatch, IssueNumber};
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, HeadGeneration,
    PolicyEpoch, PrincipalId, PrincipalSnapshotId, RefusalRecordId, RegistryEpoch,
    RepositoryId, RepositorySequence, TenantId,
};

pub(super) struct Reads {
    pub(super) backend: MemoryAuthorityStore,
    keys: Mutex<Vec<ImmutableKey>>,
    fault: Mutex<Option<(ImmutableKey, bool)>>,
}
impl Reads {
    pub(super) fn count(&self) -> usize { self.keys.lock().unwrap().len() }
    pub(super) fn reset(&self) { self.keys.lock().unwrap().clear(); }
    pub(super) fn fault(&self, key: Option<ImmutableKey>, corrupt: bool) {
        *self.fault.lock().unwrap() = key.map(|key| (key, corrupt));
    }
}
impl AsyncAuthorityStore for Reads {
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
        self.keys.lock().unwrap().push(key.clone());
        let fault = self.fault.lock().unwrap().clone();
        let result = if let Some((_, corrupt)) = fault.filter(|(target, _)| target == key) {
            Ok(if corrupt { ImmutableRead::Present(vec![0]) } else { ImmutableRead::Absent })
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
        let result = self.backend.read_head(key);
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
fn bytes(n: u64) -> DigestBytes {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    DigestBytes::try_new(&bytes).unwrap()
}
fn digest(n: u64) -> Digest {
    Digest::new(DigestAlgorithmId::try_new(0xfff1).unwrap(), bytes(n))
}
macro_rules! identity {
    ($ty:ty, $n:expr) => {
        <$ty>::from_digest(DigestAlgorithmId::try_new(0xfff1).unwrap(), CANONICAL_CODEC_VERSION, bytes($n))
    };
}

pub(super) struct Fixture {
    pub(super) store: Reads,
    pub(super) basis: PublicationBasis,
    pub(super) heads: Vec<RepositoryAuthorityHeadBody>,
    key: HeadKey,
    next: u64,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let backend = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0xfeed));
        let key = HeadKey::new(b"forge-event-seek-test".to_vec()).unwrap();
        let genesis = RepositoryAuthorityHeadBody {
            repository_id: RepositoryId::from_bytes([0xb7; 16]),
            generation: HeadGeneration::FIRST,
            predecessor_head_id: None, decision_tail_id: None,
            latest_decision_sequence: None, latest_committed_rcr_id: None,
            latest_repository_sequence: None,
            ref_root: digest(1), forge_position_root: digest(2),
            outcome_index_root: outcome_index_root(&[]).unwrap(),
            retention_root: digest(3), outbox_root: digest(4), configuration_root: digest(5),
            policy_epoch: PolicyEpoch::FIRST, format_registry_epoch: RegistryEpoch::FIRST,
            last_checkpoint_id: None,
        };
        initialize_repository(&backend, &key, &genesis).unwrap();
        Self {
            store: Reads { backend, keys: Mutex::new(Vec::new()), fault: Mutex::new(None) },
            basis: PublicationBasis::new(authority_head_identity(&genesis).unwrap(), genesis),
            heads: Vec::new(), key, next: 100,
        }
    }
    // One length per committed RCR. An empty slice is a refusal-only batch;
    // a zero length is a committed RCR carrying a verified empty event batch.
    pub(super) fn append(&mut self, counts: &[usize]) {
        let HeadRead::Present(receipt) = self.store.backend.read_head(&self.key).unwrap() else {
            panic!("fixture head absent")
        };
        let witness = collect_cumulative_outcomes(&self.store.backend, &self.key).unwrap();
        let mut plan = PublicationPlan::open(self.basis.clone()).unwrap();
        if counts.is_empty() {
            self.next += 1;
            plan.refuse(identity!(TxId, self.next), RefusalCode::QuotaExceeded,
                identity!(RefusalRecordId, self.next));
        }
        for &count in counts {
            self.next += 1;
            let events = (0..count).map(|index| IssueCommand {
                number: IssueNumber::try_new(self.next * 100 + index as u64 + 1).unwrap(),
                expected_version: ExpectedVersion::NewStream,
                action: IssueAction::Open {
                    title: format!("Event {}:{index}", self.next),
                    body: "canonical event fixture".into(), labels: Vec::new(),
                },
            }.proposed_event(PrincipalId::from_bytes([0xb8; 16])).unwrap()).collect();
            let batch = ForgeEventBatch { events };
            let root = storage::root(&batch).unwrap();
            let key = storage::body_key(storage::EVENT_NAMESPACE, self.basis.body().repository_id, root).unwrap();
            self.store.backend.put_if_absent(&key, &encode_body(&batch).unwrap()).unwrap();
            plan.commit(RepositoryCommitRecord {
                repository_id: self.basis.body().repository_id,
                repository_sequence: RepositorySequence::FIRST, parent_rcr_id: None,
                tx_id: identity!(TxId, self.next),
                principal_snapshot_id: identity!(PrincipalSnapshotId, self.next),
                canonical_request_digest: digest(self.next), ref_delta_root: digest(self.next),
                resulting_ref_root: self.basis.body().ref_root,
                object_closure_root: digest(self.next), forge_event_batch_root: root,
                resulting_forge_position_root: self.basis.body().forge_position_root,
                policy_epoch: self.basis.body().policy_epoch, policy_decision_root: digest(self.next),
                invariant_evidence_root: digest(self.next), outbox_effect_root: digest(self.next),
                retention_delta_root: digest(self.next),
            });
        }
        let publication = plan.seal(&CryptoBodyIdentity, ResultingRoots::carried_forward(&self.basis),
            &witness, receipt.token()).unwrap();
        publish_decisions(&self.store.backend, &self.key, receipt.token(), publication.batch(),
            publication.head(), TenantId::from_bytes([0xb9; 16])).unwrap();
        self.heads.push(publication.head().clone());
        self.basis = PublicationBasis::new(authority_head_identity(publication.head()).unwrap(), publication.head().clone());
    }
    pub(super) fn page(&self, after: Option<ForgeEventCursor>, limit: u16)
        -> Result<ForgeEventPage, AdmissionError>
    {
        ready(read_page_at(&self.store, &(), &self.basis, after, limit, &|| false))
    }
    pub(super) fn records(&self, after: Option<ForgeEventCursor>, limits: history::Limits)
        -> Result<Vec<Record>, AdmissionError>
    {
        ready(history::read_records(&self.store, &(), &self.basis, after, limits, &|| false))
    }
}
pub(super) fn cursor(sequence: u64, index: u32) -> ForgeEventCursor {
    ForgeEventCursor::new(sequence, index).unwrap()
}
pub(super) fn batch_key(head: &RepositoryAuthorityHeadBody) -> ImmutableKey {
    fgit_authority::body_key_for_id(head.decision_tail_id.unwrap().as_internal_object_id()).unwrap()
}
