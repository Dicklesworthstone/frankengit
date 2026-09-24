//! The synchronous store here is an explicit test double for async waiting.
//! Real durable-backend coverage is separate; this suite checks decision parity
//! and injects races/lost responses around actual reference-store mutations.
use super::*;
use crate::{BuilderProfileId, GraphAuthorityClass, GraphSourceStamp, GraphViewId};
use fgit_authority::{
    AmbiguityReason, AuthorityFailure, AuthorityLimits, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore,
};
use fgit_crypto::{
    IdentityDomain, internal_algorithm_id, internal_digest_value, internal_object_id,
};
use fgit_types::{CodecVersion, Digest, RepositoryCommitId, SchemaFamily, SchemaId};
use std::future::Future;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll, Waker};

pub(in crate::generation) fn digest(label: &[u8]) -> Digest {
    Digest::new(
        internal_algorithm_id(IdentityDomain::MerkleLeaf),
        internal_digest_value(
            IdentityDomain::MerkleLeaf,
            SchemaId::new(SchemaFamily::from_static("graph-generation-test"), 1, 0),
            label,
        ),
    )
}

pub(in crate::generation) fn candidate(
    label: &[u8],
    predecessor: Option<GraphGenerationId>,
) -> GraphGenerationBody {
    GraphGenerationBody::new(
        GraphViewId::try_new(b"commit-ancestry").unwrap(),
        SchemaId::new(SchemaFamily::from_static("graph-test"), 1, 0),
        GraphAuthorityClass::DeterministicDerived,
        GraphSourceStamp {
            source_rcr_id: RepositoryCommitId::from_internal_object_id(internal_object_id(
                IdentityDomain::RepositoryCommitRecord,
                SchemaId::new(SchemaFamily::from_static("repository-commit-record"), 1, 0),
                CodecVersion::new(1, 0),
                b"generation-source-fixture",
            ))
            .unwrap(),
            source_forge_position_root: digest(b"forge"),
            builder_profile: BuilderProfileId::try_new(b"test-builder").unwrap(),
            parser_model_root: digest(b"parser"),
        },
        digest(b"vertices"),
        digest(b"edges"),
        digest(label),
        digest(b"evidence"),
        predecessor,
    )
}

pub(in crate::generation) fn key() -> HeadKey {
    HeadKey::new(b"tenant/repository/incarnation/graph/commit-ancestry".to_vec()).unwrap()
}

/// The default reference adapter is immediately ready. The explicit suspension
/// case polls manually; a Pending result here must not spin or install a runtime.
pub(in crate::generation) fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference-store adapter unexpectedly suspended"),
    }
}

pub(in crate::generation) struct AsyncStore {
    pub(in crate::generation) inner: MemoryAuthorityStore,
    pub(in crate::generation) calls: Mutex<Vec<(&'static str, u64)>>,
    before_failure: Mutex<Option<&'static str>>,
    lose_reply: AtomicBool,
    pause_before_put: AtomicBool,
    corrupt_reply: AtomicBool,
    foreign_read: Mutex<Option<HeadKey>>,
    race: Mutex<Option<(HeadGeneration, Vec<u8>)>>,
}
impl AsyncStore {
    pub(in crate::generation) fn new() -> Self {
        Self {
            inner: MemoryAuthorityStore::new(StoreInstanceId::from_raw(312)),
            calls: Mutex::new(Vec::new()),
            before_failure: Mutex::new(None),
            lose_reply: AtomicBool::new(false),
            pause_before_put: AtomicBool::new(false),
            corrupt_reply: AtomicBool::new(false),
            foreign_read: Mutex::new(None),
            race: Mutex::new(None),
        }
    }
    pub(in crate::generation) fn lose_next_reply(&self) {
        self.lose_reply.store(true, Ordering::SeqCst);
    }
    fn observe(&self, cx: u64, operation: &'static str) -> Result<(), AuthorityFailure> {
        self.calls.lock().unwrap().push((operation, cx));
        let mut fault = self.before_failure.lock().unwrap();
        if *fault == Some(operation) {
            *fault = None;
            return Err(AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled));
        }
        Ok(())
    }
    fn returned(&self, receipt: HeadReadReceipt) -> Result<HeadReadReceipt, AuthorityFailure> {
        if self.lose_reply.swap(false, Ordering::SeqCst) {
            return Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse));
        }
        if self.corrupt_reply.swap(false, Ordering::SeqCst) {
            return Ok(HeadReadReceipt::new(
                receipt.key().clone(),
                receipt.token(),
                receipt.generation().next().unwrap(),
                receipt.body().to_vec(),
            ));
        }
        Ok(receipt)
    }
    fn initialize_head_now(
        &self,
        cx: u64,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.observe(cx, "initialize")?;
        match self.inner.initialize_head(key, generation, body)? {
            HeadInit::Created(receipt) => self.returned(receipt).map(HeadInit::Created),
            HeadInit::IdenticalRetry(receipt) => {
                self.returned(receipt).map(HeadInit::IdenticalRetry)
            }
            HeadInit::Conflict => Ok(HeadInit::Conflict),
        }
    }
    fn compare_exchange_head_now(
        &self,
        cx: u64,
        key: &HeadKey,
        token: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.observe(cx, "cas")?;
        let race = self.race.lock().unwrap().take();
        if let Some((next, bytes)) = race {
            assert!(matches!(
                self.inner.compare_exchange_head(key, token, next, &bytes)?,
                CasOutcome::Committed(_)
            ));
        }
        match self
            .inner
            .compare_exchange_head(key, token, generation, body)?
        {
            CasOutcome::Committed(receipt) => self.returned(receipt).map(CasOutcome::Committed),
            CasOutcome::PredecessorMismatch => Ok(CasOutcome::PredecessorMismatch),
        }
    }
}
impl AsyncAuthorityStore for AsyncStore {
    type Context = u64;
    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }
    async fn put_if_absent(
        &self,
        cx: &u64,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        if self.pause_before_put.swap(false, Ordering::SeqCst) {
            let mut pending = true;
            std::future::poll_fn(|cx| {
                if std::mem::take(&mut pending) {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
        }
        self.observe(*cx, "put")?;
        self.inner.put_if_absent(key, body)
    }
    fn read_immutable(
        &self,
        cx: &u64,
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        std::future::ready(
            self.observe(*cx, "immutable")
                .and_then(|()| self.inner.read_immutable(key)),
        )
    }
    fn initialize_head(
        &self,
        cx: &u64,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.initialize_head_now(*cx, key, generation, body))
    }
    fn read_head(
        &self,
        cx: &u64,
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.observe(*cx, "head").and_then(|()| {
            let foreign = self.foreign_read.lock().unwrap();
            self.inner.read_head(foreign.as_ref().unwrap_or(key))
        }))
    }
    fn compare_exchange_head(
        &self,
        cx: &u64,
        key: &HeadKey,
        token: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.compare_exchange_head_now(*cx, key, token, generation, body))
    }
    fn authenticate_head_receipt(
        &self,
        cx: &u64,
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(
            self.observe(*cx, "authenticate")
                .and_then(|()| self.inner.authenticate_head_receipt(receipt)),
        )
    }
}

#[test]
fn sync_and_async_publish_identical_bodies_generations_and_staging() {
    let sync = MemoryAuthorityStore::new(StoreInstanceId::from_raw(312));
    let asynchronous = AsyncStore::new();
    let direct = GenerationAuthority::new(&sync, key());
    let production = GenerationAuthority::new(&asynchronous, key());
    let mut predecessor = None;
    for label in [b"first".as_slice(), b"second", b"third"] {
        let body = candidate(label, predecessor);
        let expected = direct.stage_and_activate(&body).unwrap();
        let actual = ready(production.stage_and_activate_async(&41, &body)).unwrap();
        assert_eq!(actual, expected);
        // Includes exact head token, key, body and monotone generation, not
        // just a lossy committed/refused classification.
        assert_eq!(
            sync.read_head(&key()).unwrap(),
            asynchronous.inner.read_head(&key()).unwrap()
        );
        let immutable = immutable_generation_key(expected.generation_id).unwrap();
        assert_eq!(
            sync.read_immutable(&immutable).unwrap(),
            asynchronous.inner.read_immutable(&immutable).unwrap()
        );
        assert_eq!(
            sync.read_immutable(&immutable).unwrap(),
            ImmutableRead::Present(encode_body(&body).unwrap())
        );
        predecessor = Some(expected.generation_id);
    }
    assert_eq!(
        asynchronous.calls.lock().unwrap().as_slice(),
        &[
            ("put", 41),
            ("head", 41),
            ("initialize", 41),
            ("put", 41),
            ("head", 41),
            ("authenticate", 41),
            ("cas", 41),
            ("put", 41),
            ("head", 41),
            ("authenticate", 41),
            ("cas", 41),
        ]
    );
}

#[test]
fn both_drivers_preserve_distinct_predecessor_and_view_refusals() {
    let sync = MemoryAuthorityStore::new(StoreInstanceId::from_raw(312));
    let asynchronous = AsyncStore::new();
    let direct = GenerationAuthority::new(&sync, key());
    let production = GenerationAuthority::new(&asynchronous, key());
    let first = candidate(b"first", None);
    let first_id = first.generation_id().unwrap();
    let premature = candidate(b"premature", Some(first_id));
    for result in [
        direct.stage_and_activate(&premature),
        ready(production.stage_and_activate_async(&1, &premature)),
    ] {
        assert!(
            matches!(result, Err(GenerationAuthorityError::GenesisHasPredecessor { generation_id }) if *generation_id == premature.generation_id().unwrap())
        );
    }
    direct.stage_and_activate(&first).unwrap();
    ready(production.stage_and_activate_async(&2, &first)).unwrap();
    let before = sync.read_head(&key()).unwrap();
    // The old API's exact-retry refusal is deliberately unchanged.
    for result in [
        direct.stage_and_activate(&first),
        ready(production.stage_and_activate_async(&3, &first)),
    ] {
        assert!(
            matches!(result, Err(GenerationAuthorityError::PredecessorMismatch { expected, supplied }) if *expected == first_id && supplied.is_none())
        );
    }
    let mut foreign = candidate(b"foreign", Some(first_id));
    foreign.graph_view_id = GraphViewId::try_new(b"another-view").unwrap();
    for result in [
        direct.stage_and_activate(&foreign),
        ready(production.stage_and_activate_async(&4, &foreign)),
    ] {
        assert!(
            matches!(result, Err(GenerationAuthorityError::ViewMismatch { active, proposed })
            if *active == first.graph_view_id() && *proposed == foreign.graph_view_id())
        );
    }
    assert_eq!(sync.read_head(&key()).unwrap(), before);
    assert_eq!(asynchronous.inner.read_head(&key()).unwrap(), before);
}

#[test]
fn immutable_conflict_never_reaches_head_publication() {
    let store = AsyncStore::new();
    let candidate = candidate(b"conflicting", None);
    let id = candidate.generation_id().unwrap();
    store
        .inner
        .put_if_absent(&immutable_generation_key(id).unwrap(), b"different bytes")
        .unwrap();
    let authority = GenerationAuthority::new(&store, key());
    assert!(
        matches!(ready(authority.stage_and_activate_async(&17, &candidate)),
        Err(GenerationAuthorityError::ImmutableConflict { generation_id }) if *generation_id == id)
    );
    assert_eq!(store.inner.read_head(&key()).unwrap(), HeadRead::Absent);
    assert_eq!(store.calls.lock().unwrap().as_slice(), &[("put", 17)]);
}

#[test]
fn per_invocation_context_is_not_retained_on_the_authority() {
    let store = AsyncStore::new();
    let authority = GenerationAuthority::new(&store, key());
    let first = candidate(b"one", None);
    ready(authority.stage_and_activate_async(&11, &first)).unwrap();
    let next = candidate(b"two", Some(first.generation_id().unwrap()));
    ready(authority.stage_and_activate_async(&92, &next)).unwrap();
    assert_eq!(
        store.calls.lock().unwrap().as_slice(),
        &[
            ("put", 11),
            ("head", 11),
            ("initialize", 11),
            ("put", 92),
            ("head", 92),
            ("authenticate", 92),
            ("cas", 92),
        ]
    );
    fn send<T: Send>(_: T) {}
    send(authority.stage_and_activate_async(&93, &next));
}

#[test]
fn authentic_receipt_from_another_head_cannot_authorize_this_head() {
    let store = AsyncStore::new();
    let foreign_key = HeadKey::new(b"another-tenant/graph".to_vec()).unwrap();
    let first = candidate(b"one", None);
    GenerationAuthority::new(&store.inner, foreign_key.clone())
        .stage_and_activate(&first)
        .unwrap();
    *store.foreign_read.lock().unwrap() = Some(foreign_key);
    let next = candidate(b"two", Some(first.generation_id().unwrap()));
    assert!(matches!(
        ready(GenerationAuthority::new(&store, key()).stage_and_activate_async(&1, &next)),
        Err(GenerationAuthorityError::InvalidHeadReceipt)
    ));
    assert_eq!(store.inner.read_head(&key()).unwrap(), HeadRead::Absent);
    assert!(
        !store
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|(operation, _)| *operation == "cas")
    );
}

#[test]
fn a_real_intervening_cas_wins_and_the_loser_never_refreshes_its_predecessor() {
    let store = AsyncStore::new();
    let first = candidate(b"first", None);
    let authority = GenerationAuthority::new(&store, key());
    let initial = ready(authority.stage_and_activate_async(&1, &first)).unwrap();
    let winner = candidate(b"winner", Some(initial.generation_id));
    let loser = candidate(b"loser", Some(initial.generation_id));
    let bytes = encode_body(&winner).unwrap();
    store
        .inner
        .put_if_absent(
            &immutable_generation_key(winner.generation_id().unwrap()).unwrap(),
            &bytes,
        )
        .unwrap();
    *store.race.lock().unwrap() =
        Some((initial.authority_generation.next().unwrap(), bytes.clone()));
    assert!(matches!(
        ready(authority.stage_and_activate_async(&2, &loser)),
        Err(GenerationAuthorityError::ConcurrentActivation)
    ));
    let HeadRead::Present(head) = store.inner.read_head(&key()).unwrap() else {
        panic!("winner absent")
    };
    assert_eq!(head.body(), bytes);
    assert!(
        store.race.lock().unwrap().is_none(),
        "fault must actually fire"
    );
    assert_eq!(
        store
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(operation, _)| *operation == "cas")
            .count(),
        1
    );
}

#[test]
fn lost_initialize_and_cas_replies_remain_ambiguous_after_real_publication() {
    let store = AsyncStore::new();
    let authority = GenerationAuthority::new(&store, key());
    let first = candidate(b"first", None);
    let second = candidate(b"second", Some(first.generation_id().unwrap()));
    for body in [&first, &second] {
        store.lose_reply.store(true, Ordering::SeqCst);
        let result = ready(authority.stage_and_activate_async(&3, body));
        assert!(matches!(
            result,
            Err(GenerationAuthorityError::Authority(
                AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse)
            ))
        ));
        let HeadRead::Present(head) = store.inner.read_head(&key()).unwrap() else {
            panic!("publication absent")
        };
        assert_eq!(head.body(), encode_body(body).unwrap());
        assert!(
            !store.lose_reply.load(Ordering::SeqCst),
            "fault must actually fire"
        );
    }
}

#[test]
fn cancellation_before_a_write_never_fabricates_a_terminal_refusal() {
    let store = AsyncStore::new();
    *store.before_failure.lock().unwrap() = Some("put");
    let body = candidate(b"cancelled", None);
    assert!(matches!(
        ready(GenerationAuthority::new(&store, key()).stage_and_activate_async(&1, &body)),
        Err(GenerationAuthorityError::Authority(
            AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled)
        ))
    ));
    assert_eq!(store.inner.read_head(&key()).unwrap(), HeadRead::Absent);
    assert_eq!(
        store
            .inner
            .read_immutable(&immutable_generation_key(body.generation_id().unwrap()).unwrap())
            .unwrap(),
        ImmutableRead::Absent
    );
    assert_eq!(store.calls.lock().unwrap().as_slice(), &[("put", 1)]);
}

#[test]
fn malformed_success_does_not_claim_either_confirmation_or_rollback() {
    let store = AsyncStore::new();
    store.corrupt_reply.store(true, Ordering::SeqCst);
    let body = candidate(b"actually-written", None);
    assert!(matches!(
        ready(GenerationAuthority::new(&store, key()).stage_and_activate_async(&1, &body)),
        Err(GenerationAuthorityError::InvalidActivationReceipt)
    ));
    let HeadRead::Present(head) = store.inner.read_head(&key()).unwrap() else {
        panic!("publication absent")
    };
    assert_eq!(head.body(), encode_body(&body).unwrap());
    assert_eq!(head.generation(), HeadGeneration::FIRST);
}

#[test]
fn a_pending_backend_operation_suspends_without_publishing_or_blocking() {
    let store = AsyncStore::new();
    store.pause_before_put.store(true, Ordering::SeqCst);
    let authority = GenerationAuthority::new(&store, key());
    let body = candidate(b"suspension", None);
    let future = authority.stage_and_activate_async(&39, &body);
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert!(store.calls.lock().unwrap().is_empty());
    assert_eq!(store.inner.read_head(&key()).unwrap(), HeadRead::Absent);
    let Poll::Ready(result) = future.as_mut().poll(&mut context) else {
        panic!("resume did not finish")
    };
    assert_eq!(result.unwrap().generation_id, body.generation_id().unwrap());
    assert_eq!(
        store.calls.lock().unwrap().as_slice(),
        &[("put", 39), ("head", 39), ("initialize", 39)]
    );
}

#[test]
fn interruption_after_staging_does_not_make_the_candidate_visible() {
    let store = AsyncStore::new();
    let authority = GenerationAuthority::new(&store, key());
    let first = candidate(b"first", None);
    ready(authority.stage_and_activate_async(&1, &first)).unwrap();
    let before = store.inner.read_head(&key()).unwrap();
    let next = candidate(b"next", Some(first.generation_id().unwrap()));
    *store.before_failure.lock().unwrap() = Some("cas");
    assert!(matches!(
        ready(authority.stage_and_activate_async(&2, &next)),
        Err(GenerationAuthorityError::Authority(
            AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled)
        ))
    ));
    assert_eq!(store.inner.read_head(&key()).unwrap(), before);
    assert_eq!(
        store
            .inner
            .read_immutable(&immutable_generation_key(next.generation_id().unwrap()).unwrap())
            .unwrap(),
        ImmutableRead::Present(encode_body(&next).unwrap())
    );
    assert!(
        store.before_failure.lock().unwrap().is_none(),
        "fault must actually fire"
    );
    let actual = ready(authority.stage_and_activate_async(&3, &next)).unwrap();
    assert_eq!(actual.generation_id, next.generation_id().unwrap());
}

#[test]
fn a_generation_counter_inconsistent_with_genesis_cannot_be_extended() {
    let store = AsyncStore::new();
    let first = candidate(b"first", None);
    store
        .inner
        .initialize_head(
            &key(),
            HeadGeneration::try_new(2).unwrap(),
            &encode_body(&first).unwrap(),
        )
        .unwrap();
    let next = candidate(b"next", Some(first.generation_id().unwrap()));
    let before = store.inner.read_head(&key()).unwrap();
    assert!(matches!(
        ready(GenerationAuthority::new(&store, key()).stage_and_activate_async(&1, &next)),
        Err(GenerationAuthorityError::HistoryInconsistent)
    ));
    assert_eq!(store.inner.read_head(&key()).unwrap(), before);
}
