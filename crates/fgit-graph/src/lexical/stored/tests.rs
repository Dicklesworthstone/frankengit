//! Real codecs and reference authority writes; the async forwarding/fault
//! adapter below is a test double, not a disk or production-runtime backend.
use super::*;
use fgit_authority::{
    AmbiguityReason, AuthenticatedHead, AuthorityLimits, AuthorityRefusal, AuthorityVersionToken,
    CasOutcome, HeadInit, HeadRead, HeadReadReceipt, MemoryAuthorityStore,
};
use fgit_crypto::{
    IdentityDomain, internal_algorithm_id, internal_digest_value, internal_object_id,
};
use fgit_types::{CodecVersion, HeadGeneration};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll, Wake, Waker};

struct Store {
    inner: MemoryAuthorityStore,
    missing: Mutex<Option<ImmutableKey>>,
    changed: Mutex<Option<(ImmutableKey, Vec<u8>)>>,
    operations: Mutex<Vec<&'static str>>,
    contexts: Mutex<Vec<usize>>,
    stop_root: AtomicBool,
    lose_root: AtomicBool,
    suspend: AtomicBool,
}
impl Store {
    fn new(id: u64) -> Self {
        Self {
            inner: MemoryAuthorityStore::new(StoreInstanceId::from_raw(id)),
            missing: Mutex::new(None),
            changed: Mutex::new(None),
            operations: Mutex::new(Vec::new()),
            contexts: Mutex::new(Vec::new()),
            stop_root: AtomicBool::new(false),
            lose_root: AtomicBool::new(false),
            suspend: AtomicBool::new(false),
        }
    }
    fn note(&self, op: &'static str) {
        self.operations.lock().unwrap().push(op);
    }
    fn before_root(&self) -> Result<(), AuthorityFailure> {
        if self.stop_root.load(Ordering::SeqCst) {
            Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable))
        } else {
            Ok(())
        }
    }
    fn root_result<T>(&self, result: T) -> Result<T, AuthorityFailure> {
        if self.lose_root.swap(false, Ordering::SeqCst) {
            Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse))
        } else {
            Ok(result)
        }
    }
    async fn step(&self, context: &usize) {
        self.contexts.lock().unwrap().push(*context);
        let mut pending = self.suspend.swap(false, Ordering::SeqCst);
        poll_fn(move |cx| {
            if pending {
                pending = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }
}
impl AuthorityStore for Store {
    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }
    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.note("put");
        self.inner.put_if_absent(key, body)
    }
    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.note("read");
        if self.missing.lock().unwrap().as_ref() == Some(key) {
            return Ok(ImmutableRead::Absent);
        }
        if let Some((target, value)) = self.changed.lock().unwrap().as_ref() {
            if target == key {
                return Ok(ImmutableRead::Present(value.clone()));
            }
        }
        self.inner.read_immutable(key)
    }
    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.note("initialize");
        self.before_root()?;
        self.root_result(self.inner.initialize_head(key, generation, body)?)
    }
    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.note("head");
        self.inner.read_head(key)
    }
    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.note("cas");
        self.before_root()?;
        self.root_result(
            self.inner
                .compare_exchange_head(key, expected, generation, body)?,
        )
    }
    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.note("authenticate");
        self.inner.authenticate_head_receipt(receipt)
    }
}
impl AsyncAuthorityStore for Store {
    type Context = usize;
    fn instance_id(&self) -> StoreInstanceId {
        AuthorityStore::instance_id(self)
    }
    fn limits(&self) -> AuthorityLimits {
        AuthorityStore::limits(self)
    }
    async fn put_if_absent(
        &self,
        cx: &usize,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.step(cx).await;
        AuthorityStore::put_if_absent(self, key, body)
    }
    async fn read_immutable(
        &self,
        cx: &usize,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        self.step(cx).await;
        AuthorityStore::read_immutable(self, key)
    }
    async fn initialize_head(
        &self,
        cx: &usize,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.step(cx).await;
        AuthorityStore::initialize_head(self, key, generation, body)
    }
    async fn read_head(&self, cx: &usize, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.step(cx).await;
        AuthorityStore::read_head(self, key)
    }
    async fn compare_exchange_head(
        &self,
        cx: &usize,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.step(cx).await;
        AuthorityStore::compare_exchange_head(self, key, expected, generation, body)
    }
    async fn authenticate_head_receipt(
        &self,
        cx: &usize,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.step(cx).await;
        AuthorityStore::authenticate_head_receipt(self, receipt)
    }
}
struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}
fn drive<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    for _ in 0..10_000 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return result;
        }
    }
    panic!("reference future failed to finish in its bounded polling harness")
}
fn digest(label: &[u8]) -> Digest {
    Digest::new(
        internal_algorithm_id(IdentityDomain::MerkleLeaf),
        internal_digest_value(
            IdentityDomain::MerkleLeaf,
            SchemaId::new(SchemaFamily::from_static("lexical-test"), 1, 0),
            label,
        ),
    )
}
fn source(format: GitHashAlgorithm, revision: u8) -> LexicalSource {
    let id = |domain, family: &'static str| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CodecVersion::new(1, 0),
            &[revision],
        )
    };
    LexicalSource {
        namespace: LexicalNamespace {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
            object_format: format,
        },
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        source_head: RepositoryAuthorityHeadId::from_internal_object_id(id(
            IdentityDomain::RepositoryAuthorityHead,
            "repository-authority-head",
        ))
        .unwrap(),
        source_rcr: RepositoryCommitId::from_internal_object_id(id(
            IdentityDomain::RepositoryCommitRecord,
            "repository-commit-record",
        ))
        .unwrap(),
        forge_position_root: digest(&[revision]),
        commit: git_object_id(format, GitObjectKind::Commit, &[revision]),
        tree: git_object_id(format, GitObjectKind::Tree, &[revision]),
    }
}
fn prepared(format: GitHashAlgorithm, revision: u8, words: &[&[u8]]) -> PreparedLexicalIndex {
    let segments = words
        .iter()
        .enumerate()
        .map(|(i, body)| {
            let path = format!("src/{i:03}.rs");
            LexicalSegment::build(
                source(format, revision).namespace,
                i as u64 + 1,
                [SourceDocument {
                    path: path.as_bytes(),
                    content: body,
                    blob: git_object_id(format, GitObjectKind::Blob, body),
                }],
                &mut || true,
            )
            .unwrap()
        })
        .collect();
    PreparedLexicalIndex::new(source(format, revision), segments, 2, &mut || true).unwrap()
}
fn index(store: &Store, format: GitHashAlgorithm) -> LexicalIndexStore<'_, Store> {
    LexicalIndexStore::new(
        store,
        source(format, 1).namespace,
        RefName::try_new(b"refs/heads/main").unwrap(),
    )
    .unwrap()
}
fn q(word: &[u8]) -> LexicalQuery {
    LexicalQuery::new(LexicalChannel::Content, &[word.to_vec()], &[]).unwrap()
}
fn search(
    index: &LexicalIndexStore<'_, Store>,
    selection: &LexicalSelection,
    word: &[u8],
) -> IndexedLexicalReport {
    index
        .search(
            selection,
            &q(word),
            None,
            Default::default(),
            Default::default(),
            &mut || true,
        )
        .unwrap()
}

#[test]
fn persisted_segments_are_queryable_from_a_fresh_handle_after_preparation_is_dropped() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let store = Store::new(710);
        let idx = index(&store, format);
        let p = prepared(format, 1, &[b"Alpha beta", b"beta"]);
        let encoded = p.encoded_bytes();
        let activated = idx.publish(&p, None, &mut || true).unwrap();
        assert_eq!(
            *store.operations.lock().unwrap().last().unwrap(),
            "initialize"
        );
        drop(p);
        drop(idx);
        let idx = index(&store, format);
        let selected = idx
            .select(None, None, Default::default(), &mut || true)
            .unwrap();
        let report = search(&idx, &selected, b"alpha");
        assert_eq!(report.generation, activated);
        assert_eq!(report.results.hits.len(), 1);
        assert_eq!(
            report.results.hits[0].blob,
            git_object_id(format, GitObjectKind::Blob, b"Alpha beta")
        );
        assert_eq!(report.payload_bytes_read, encoded);
        assert_eq!(report.segments_read, 2);
        assert_eq!(report.source, source(format, 1));
        assert!(report.results.complete);
        assert_eq!(report.indexed_documents, 2);
        assert_eq!(report.non_regular_entries, 2);
    }
}
#[test]
fn later_activation_never_replaces_an_exact_query_generation() {
    let store = Store::new(711);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    let a = idx
        .publish(
            &prepared(GitHashAlgorithm::Sha1, 1, &[b"old"]),
            None,
            &mut || true,
        )
        .unwrap();
    let selected = idx
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let b = idx
        .publish(
            &prepared(GitHashAlgorithm::Sha1, 2, &[b"new"]),
            Some(a.generation_id),
            &mut || true,
        )
        .unwrap();
    let old = idx
        .select(Some(&a), Some(&b), Default::default(), &mut || true)
        .unwrap();
    assert_eq!(old.activation(), &a);
    assert_eq!(old.selected_head(), &b);
    assert_eq!(
        search(&idx, &old, b"old").results.hits,
        search(&idx, &selected, b"old").results.hits
    );
    assert!(search(&idx, &old, b"new").results.hits.is_empty());
    let current = idx
        .select(None, Some(&a), Default::default(), &mut || true)
        .unwrap();
    assert_eq!(search(&idx, &current, b"new").results.hits.len(), 1);
    let wrong = GenerationActivation {
        generation_id: a.generation_id,
        authority_generation: b.authority_generation,
    };
    assert!(
        idx.select(Some(&wrong), None, Default::default(), &mut || true)
            .is_err()
    );
}
#[test]
fn interrupted_root_publication_recovers_without_reexecuting_or_reinterpreting_payloads() {
    let store = Store::new(712);
    let idx = index(&store, GitHashAlgorithm::Sha256);
    let p = prepared(GitHashAlgorithm::Sha256, 1, &[b"alpha"]);
    let candidate = idx.candidate_id(&p, None).unwrap();
    store.lose_root.store(true, Ordering::SeqCst);
    assert!(matches!(
        idx.publish(&p, None, &mut || true),
        Err(IndexError::Generation(GenerationAuthorityError::Authority(
            AuthorityFailure::Ambiguous(_)
        )))
    ));
    let a = match idx
        .recover(candidate, None, Default::default(), &mut || true)
        .unwrap()
    {
        crate::GenerationRecovery::Active { selected } => selected.activation().clone(),
        other => panic!("{other:?}"),
    };
    let b = idx
        .publish(
            &prepared(GitHashAlgorithm::Sha256, 2, &[b"beta"]),
            Some(a.generation_id),
            &mut || true,
        )
        .unwrap();
    store.operations.lock().unwrap().clear();
    assert!(
        matches!(idx.recover(candidate, Some(&b), Default::default(), &mut || true).unwrap(),
        crate::GenerationRecovery::Superseded { activation, .. } if activation == a)
    );
    assert!(
        !store
            .operations
            .lock()
            .unwrap()
            .iter()
            .any(|op| ["put", "cas", "initialize"].contains(op))
    );
}
#[test]
fn staged_payloads_are_not_an_index_and_empty_index_is_not_missing_index() {
    let store = Store::new(713);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    let p = prepared(GitHashAlgorithm::Sha1, 1, &[b"alpha"]);
    let id = idx.candidate_id(&p, None).unwrap();
    store.stop_root.store(true, Ordering::SeqCst);
    assert!(idx.publish(&p, None, &mut || true).is_err());
    assert!(matches!(
        idx.select(None, None, Default::default(), &mut || true),
        Err(IndexError::Uninitialized)
    ));
    assert!(matches!(
        idx.recover(id, None, Default::default(), &mut || true)
            .unwrap(),
        crate::GenerationRecovery::Uninitialized
    ));
    store.stop_root.store(false, Ordering::SeqCst);
    let empty = prepared(GitHashAlgorithm::Sha1, 1, &[]);
    idx.publish(&empty, None, &mut || true).unwrap();
    let report = search(
        &idx,
        &idx.select(None, None, Default::default(), &mut || true)
            .unwrap(),
        b"alpha",
    );
    assert!(report.results.complete && report.results.hits.is_empty());
    assert_eq!(report.indexed_documents, 0);
}
#[test]
fn needed_payload_absence_or_substitution_is_not_a_partial_success() {
    let store = Store::new(714);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    let p = prepared(GitHashAlgorithm::Sha1, 1, &[b"alpha", b"alpha"]);
    idx.publish(&p, None, &mut || true).unwrap();
    for metadata in &p.metadata {
        let key = payload_key(p.source().namespace, metadata.kind, metadata.root).unwrap();
        *store.missing.lock().unwrap() = Some(key.clone());
        assert!(matches!(
            idx.select(None, None, Default::default(), &mut || true),
            Err(IndexError::MissingPayload(_))
        ));
        *store.missing.lock().unwrap() = None;
        let mut bytes = metadata.bytes.clone();
        *bytes.last_mut().unwrap() ^= 1;
        *store.changed.lock().unwrap() = Some((key, bytes));
        assert!(
            idx.select(None, None, Default::default(), &mut || true)
                .is_err()
        );
        *store.changed.lock().unwrap() = None;
    }
    let selected = idx
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let payload = &p.segments[1];
    let key = payload_key(p.source().namespace, payload.kind, payload.root).unwrap();
    *store.missing.lock().unwrap() = Some(key.clone());
    assert!(matches!(
        idx.search(
            &selected,
            &q(b"alpha"),
            None,
            Default::default(),
            Default::default(),
            &mut || true
        ),
        Err(IndexError::MissingPayload(_))
    ));
    *store.missing.lock().unwrap() = None;
    *store.changed.lock().unwrap() = Some((key, p.segments[0].bytes.clone()));
    assert!(
        idx.search(
            &selected,
            &q(b"alpha"),
            None,
            Default::default(),
            Default::default(),
            &mut || true
        )
        .is_err()
    );
}
#[test]
fn global_pagination_and_work_budgets_cross_segment_boundaries() {
    let store = Store::new(715);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    idx.publish(
        &prepared(GitHashAlgorithm::Sha1, 1, &[b"x", b"y", b"x", b"x"]),
        None,
        &mut || true,
    )
    .unwrap();
    let selection = idx
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let limits = LexicalQueryLimits {
        max_results: 2,
        ..Default::default()
    };
    let first = idx
        .search(
            &selection,
            &q(b"x"),
            None,
            Default::default(),
            limits,
            &mut || true,
        )
        .unwrap();
    assert!(!first.results.complete);
    assert_eq!(first.results.next_after, Some(3));
    assert_eq!(first.segments_read, 4);
    let second = idx
        .search(
            &selection,
            &q(b"x"),
            first.results.next_after,
            Default::default(),
            limits,
            &mut || true,
        )
        .unwrap();
    assert!(second.results.complete);
    assert_eq!(second.results.hits[0].document_id, 4);
    assert_eq!(second.segments_read, 1);
    let full = search(&idx, &selection, b"x");
    let exact = LexicalQueryLimits {
        max_work: full.results.work_units,
        ..Default::default()
    };
    assert_eq!(
        idx.search(
            &selection,
            &q(b"x"),
            None,
            Default::default(),
            exact,
            &mut || true
        )
        .unwrap()
        .results,
        full.results
    );
    assert!(
        idx.search(
            &selection,
            &q(b"x"),
            None,
            Default::default(),
            LexicalQueryLimits {
                max_work: exact.max_work - 1,
                ..exact
            },
            &mut || true
        )
        .is_err()
    );
}
#[test]
fn read_bounds_cover_catalogs_and_segments_without_resetting_the_allowance() {
    let store = Store::new(716);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    let p = prepared(GitHashAlgorithm::Sha1, 1, &[b"x", b"x"]);
    idx.publish(&p, None, &mut || true).unwrap();
    let exact = LexicalReadLimits {
        max_payload_bytes: p.encoded_bytes(),
        ..Default::default()
    };
    let selected = idx.select(None, None, exact, &mut || true).unwrap();
    assert_eq!(
        idx.search(
            &selected,
            &q(b"x"),
            None,
            exact,
            Default::default(),
            &mut || true
        )
        .unwrap()
        .payload_bytes_read,
        p.encoded_bytes()
    );
    assert!(
        idx.search(
            &selected,
            &q(b"x"),
            None,
            LexicalReadLimits {
                max_payload_bytes: exact.max_payload_bytes - 1,
                ..exact
            },
            Default::default(),
            &mut || true
        )
        .is_err()
    );
    assert!(
        idx.search(
            &selected,
            &q(b"x"),
            None,
            LexicalReadLimits {
                max_segments: 1,
                ..exact
            },
            Default::default(),
            &mut || true
        )
        .is_err()
    );
}
#[test]
fn namespace_ref_and_store_identity_cannot_reuse_foreign_selections() {
    let store = Store::new(717);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    let p = prepared(GitHashAlgorithm::Sha1, 1, &[b"x"]);
    idx.publish(&p, None, &mut || true).unwrap();
    let selected = idx
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let other_ref = LexicalIndexStore::new(
        &store,
        p.source().namespace,
        RefName::try_new(b"refs/heads/other").unwrap(),
    )
    .unwrap();
    assert!(matches!(
        other_ref.publish(&p, None, &mut || true),
        Err(IndexError::SourceMismatch)
    ));
    assert!(matches!(
        other_ref.search(
            &selected,
            &q(b"x"),
            None,
            Default::default(),
            Default::default(),
            &mut || true
        ),
        Err(IndexError::SourceMismatch)
    ));
    let mut namespace = p.source().namespace;
    namespace.incarnation = RepositoryIncarnationId::from_bytes([7; 16]);
    let other_scope =
        LexicalIndexStore::new(&store, namespace, p.source().reference.clone()).unwrap();
    assert!(matches!(
        other_scope.publish(&p, None, &mut || true),
        Err(IndexError::SourceMismatch)
    ));
    let second = Store::new(718);
    let second_index = index(&second, GitHashAlgorithm::Sha1);
    assert!(matches!(
        second_index.search(
            &selected,
            &q(b"x"),
            None,
            Default::default(),
            Default::default(),
            &mut || true
        ),
        Err(IndexError::SourceMismatch)
    ));
}
#[test]
fn cancellation_between_staging_and_root_never_exposes_provisional_data() {
    let store = Store::new(719);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    let p = prepared(GitHashAlgorithm::Sha1, 1, &[b"x"]);
    let count = p.segments.len() + p.metadata.len();
    let mut live = || {
        store
            .operations
            .lock()
            .unwrap()
            .iter()
            .filter(|op| **op == "put")
            .count()
            < count
    };
    assert!(matches!(
        idx.publish(&p, None, &mut live),
        Err(IndexError::Lexical(LexicalError::Cancelled))
    ));
    assert!(!store.operations.lock().unwrap().contains(&"initialize"));
    assert!(matches!(
        idx.select(None, None, Default::default(), &mut || true),
        Err(IndexError::Uninitialized)
    ));
    let mut live = || !store.operations.lock().unwrap().contains(&"initialize");
    assert!(idx.publish(&p, None, &mut live).is_ok()); // no post-confirmation cancellation check
    let selected = idx
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    store.operations.lock().unwrap().clear();
    assert!(
        idx.search(
            &selected,
            &q(b"x"),
            None,
            Default::default(),
            Default::default(),
            &mut || false
        )
        .is_err()
    );
    assert!(store.operations.lock().unwrap().is_empty());
}
#[test]
fn asynchronous_roundtrip_suspends_and_preserves_context_and_result_parity() {
    let store = Store::new(720);
    let idx = index(&store, GitHashAlgorithm::Sha256);
    let p = prepared(GitHashAlgorithm::Sha256, 1, &[b"x", b"x y"]);
    store.suspend.store(true, Ordering::SeqCst);
    let a = drive(idx.publish_async(&41, &p, None, &mut || true)).unwrap();
    assert!(
        store
            .contexts
            .lock()
            .unwrap()
            .iter()
            .all(|value| *value == 41)
    );
    store.contexts.lock().unwrap().clear();
    let selected =
        drive(idx.select_async(&42, Some(&a), None, Default::default(), &mut || true)).unwrap();
    assert!(
        store
            .contexts
            .lock()
            .unwrap()
            .iter()
            .all(|value| *value == 42)
    );
    let asynchronous = drive(idx.search_async(
        &43,
        &selected,
        &q(b"x"),
        None,
        Default::default(),
        Default::default(),
        &mut || true,
    ))
    .unwrap();
    let synchronous = search(&idx, &selected, b"x");
    assert_eq!(asynchronous.results, synchronous.results);
    assert_eq!(
        asynchronous.payload_bytes_read,
        synchronous.payload_bytes_read
    );
    assert_eq!(asynchronous.source, synchronous.source);
    assert_eq!(asynchronous.generation, a);
    assert!(matches!(
        drive(idx.recover_async(&44, a.generation_id, None, Default::default(), &mut || true))
            .unwrap(),
        crate::GenerationRecovery::Active { .. }
    ));
}
#[test]
fn unpolled_or_cancelled_async_queries_do_not_issue_storage_work() {
    let store = Store::new(721);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    let p = prepared(GitHashAlgorithm::Sha1, 1, &[b"x"]);
    drop(idx.publish_async(&1, &p, None, &mut || true));
    assert!(store.operations.lock().unwrap().is_empty());
    assert!(drive(idx.publish_async(&2, &p, None, &mut || false)).is_err());
    assert!(store.contexts.lock().unwrap().is_empty());
    let mut live = || true;
    store.suspend.store(true, Ordering::SeqCst);
    let mut future = pin!(idx.publish_async(&3, &p, None, &mut live));
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert!(store.operations.lock().unwrap().is_empty());
    drop(future);
}
#[test]
fn catalogs_with_a_wrong_generation_authority_class_cannot_be_searched() {
    let store = Store::new(722);
    let idx = index(&store, GitHashAlgorithm::Sha1);
    let p = prepared(GitHashAlgorithm::Sha1, 1, &[b"x"]);
    for body in p.segments.iter().chain(&p.metadata) {
        AuthorityStore::put_if_absent(
            &store,
            &payload_key(p.source().namespace, body.kind, body.root).unwrap(),
            &body.bytes,
        )
        .unwrap();
    }
    let good = idx.generation(&p, None).unwrap();
    let wrong = GraphGenerationBody::new(
        good.graph_view_id(),
        good.graph_schema_id(),
        GraphAuthorityClass::Statistical,
        good.source().clone(),
        *good.vertices_root(),
        *good.edges_root(),
        *good.index_manifest_root(),
        *good.evidence_root(),
        None,
    );
    GenerationAuthority::new(&store, idx.head_key.clone())
        .stage_and_activate(&wrong)
        .unwrap();
    assert!(matches!(
        idx.select(None, None, Default::default(), &mut || true),
        Err(IndexError::Lexical(LexicalError::Invalid(
            "index generation profile"
        )))
    ));
}
