//! Canonical read-isolation regressions. The reference store is non-durable;
//! synthetic observations are not runner authentication or execution evidence.
use super::*;
use fgit_authority::{
    AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken, CasOutcome,
    HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PutOutcome, StoreInstanceId,
};
use fgit_codec::harness::genesis_head;
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry};
use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

fn run<F: Future>(future: F) -> F::Output {
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference store operations do not suspend"),
    }
}

struct Store {
    memory: MemoryAuthorityStore,
    missing: Mutex<Option<ImmutableKey>>,
    reads: AtomicUsize,
}
impl AsyncAuthorityStore for Store {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.memory.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.memory.limits()
    }
    fn put_if_absent(
        &self,
        (): &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.memory.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        (): &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.missing.lock().unwrap().as_ref() == Some(key) {
            return std::future::ready(Ok(ImmutableRead::Absent));
        }
        std::future::ready(self.memory.read_immutable(key))
    }
    fn initialize_head(
        &self,
        (): &(),
        key: &HeadKey,
        generation: fgit_types::HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.memory.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        (): &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.memory.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        (): &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: fgit_types::HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.memory.compare_exchange_head(key, expected, generation, body))
    }
    fn authenticate_head_receipt(
        &self,
        (): &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.memory.authenticate_head_receipt(receipt))
    }
}

struct Fixture {
    store: Store,
    basis: PublicationBasis,
    check: NativeWorkflowCheck,
    event_key: ImmutableKey,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, event_count: u32) -> Self {
        let store = Store {
            memory: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0xc4ec)),
            missing: Mutex::new(None),
            reads: AtomicUsize::new(0),
        };
        let repository = RepositoryId::from_bytes([0x34; 16]);
        let check = NativeWorkflowCheck {
            actor: PrincipalId::from_bytes([7; 16]),
            record: WorkflowCheckRecord {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                source_commit: GitOid::from_hex(format, &"11".repeat(format.digest_len()))
                    .unwrap(),
                run_id: [4; 32],
                attempt_id: [5; 32],
                graph_root: [6; 32],
                job: "build".into(),
                conclusion: WorkflowCheckConclusion::ActionRequired,
                evidence: b"reference observation, not an execution attestation".to_vec(),
            },
        };
        let batch = ForgeEventBatch::of_one(
            check.record.proposed_event(check.actor, format).unwrap(),
        );
        let event_root = run(storage::stage_body(
            &store, &(), repository, storage::EVENT_NAMESPACE, &batch,
        ))
        .unwrap();
        let event_key = storage::body_key(storage::EVENT_NAMESPACE, repository, event_root)
            .unwrap();
        let positions = CanonicalForgePositionState::try_new(
            repository,
            vec![ForgePositionStateEntry::try_new(
                storage::aggregate_label(AggregateId::WorkflowCheck(check.id())).unwrap(),
                0,
                event_count,
                event_root,
            )
            .unwrap()],
        )
        .unwrap();
        let mut head = genesis_head();
        head.repository_id = repository;
        head.forge_position_root = run(storage::stage_body(
            &store, &(), repository, storage::POSITION_NAMESPACE, &positions,
        ))
        .unwrap();
        // Deliberately do NOT stage the outbox body. A workflow observation is
        // selected by its forge frontier, not by a successful outbox replay.
        head.outbox_root = storage::root(
            &CanonicalOutboxState::try_new(repository, Vec::new()).unwrap(),
        )
        .unwrap();
        let key = HeadKey::new(b"workflow-read-isolation/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.memory, &key, &head).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        store.reads.store(0, Ordering::Relaxed);
        Self { store, basis, check, event_key }
    }
    fn read<C: Fn() -> bool + Sync>(
        &self,
        id: WorkflowCheckId,
        cancelled: &C,
    ) -> Result<Option<NativeWorkflowCheck>, AdmissionError> {
        run(read_at(&self.store, &(), &self.basis, id, cancelled))
    }
}

fn refuses<T: std::fmt::Debug>(result: Result<T, AdmissionError>, code: RefusalCode) {
    assert!(
        matches!(&result, Err(AdmissionError::AsyncProjectionUnavailable(found)) if *found == code),
        "expected {code:?}, got {result:?}"
    );
}

#[test]
fn selected_observation_is_readable_without_any_outbox_body_in_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, 1);
        assert_eq!(fixture.read(fixture.check.id(), &|| false).unwrap(), Some(fixture.check.clone()));
        assert_eq!(fixture.store.reads.load(Ordering::Relaxed), 2);
        assert_eq!(fixture.read(fixture.check.id(), &|| false).unwrap(), Some(fixture.check.clone()));
    }
}

#[test]
fn an_absent_observation_needs_only_the_selected_frontier() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, 1);
    let mut other = fixture.check.clone();
    other.actor = PrincipalId::from_bytes([99; 16]);
    assert_eq!(fixture.read(other.id(), &|| false).unwrap(), None);
    assert_eq!(fixture.store.reads.load(Ordering::Relaxed), 1);
}

#[test]
fn a_missing_selected_event_is_not_an_absent_observation() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, 1);
    *fixture.store.missing.lock().unwrap() = Some(fixture.event_key.clone());
    refuses(fixture.read(fixture.check.id(), &|| false), RefusalCode::EvidenceMissing);
}

#[test]
fn an_immutable_observation_cannot_claim_multiple_events() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, 2);
    refuses(fixture.read(fixture.check.id(), &|| false), RefusalCode::EvidenceInvalid);
    assert_eq!(fixture.store.reads.load(Ordering::Relaxed), 1);
}

#[test]
fn cancellation_before_or_after_frontier_selection_does_not_read_the_event() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, 1);
    refuses(fixture.read(fixture.check.id(), &|| true), RefusalCode::CancellationInProgress);
    assert_eq!(fixture.store.reads.load(Ordering::Relaxed), 0);
    refuses(
        fixture.read(fixture.check.id(), &|| fixture.store.reads.load(Ordering::Relaxed) != 0),
        RefusalCode::CancellationInProgress,
    );
    assert_eq!(fixture.store.reads.load(Ordering::Relaxed), 1);
}
