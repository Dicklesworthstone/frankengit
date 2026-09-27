//! Real lexical codecs and generation authority; the forwarding store is an
//! I/O spy, not a claim about a disk backend or a live node runtime.
use super::*;
use crate::lexical::LexicalChannel;
use fgit_authority::{
    AuthenticatedHead, AuthorityLimits, AuthorityVersionToken, CasOutcome, HeadInit, HeadRead,
    HeadReadReceipt, MemoryAuthorityStore,
};
use fgit_crypto::{
    GitObjectKind, IdentityDomain, git_object_id, internal_algorithm_id, internal_digest_value,
    internal_object_id,
};
use fgit_types::{CodecVersion, HeadGeneration, RepositoryId, RepositoryIncarnationId, TenantId};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};
use std::task::{Context, Poll, Waker};

struct Spy {
    inner: MemoryAuthorityStore,
    reads: AtomicUsize,
    missing: Mutex<Option<ImmutableKey>>,
    corrupt: Mutex<Option<ImmutableKey>>,
    contexts: Mutex<Vec<usize>>,
}
impl Spy {
    fn new(id: u64) -> Self {
        Self {
            inner: MemoryAuthorityStore::new(StoreInstanceId::from_raw(id)),
            reads: AtomicUsize::new(0),
            missing: Mutex::new(None),
            corrupt: Mutex::new(None),
            contexts: Mutex::new(Vec::new()),
        }
    }
    fn reset(&self) {
        self.reads.store(0, Ordering::SeqCst);
        self.contexts.lock().unwrap().clear();
    }
    async fn step(&self, context: &usize) {
        self.contexts.lock().unwrap().push(*context);
        let mut pending = true;
        poll_fn(move |cx| {
            if pending {
                pending = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }).await;
    }
}
impl AuthorityStore for Spy {
    fn instance_id(&self) -> StoreInstanceId { self.inner.instance_id() }
    fn limits(&self) -> AuthorityLimits { self.inner.limits() }
    fn put_if_absent(&self, key: &ImmutableKey, body: &[u8]) -> Result<PutOutcome, AuthorityFailure> {
        self.inner.put_if_absent(key, body)
    }
    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.missing.lock().unwrap().as_ref() == Some(key) { return Ok(ImmutableRead::Absent); }
        if self.corrupt.lock().unwrap().as_ref() == Some(key) {
            return Ok(ImmutableRead::Present(vec![0; 16]));
        }
        self.inner.read_immutable(key)
    }
    fn initialize_head(&self, key: &HeadKey, generation: HeadGeneration, body: &[u8]) -> Result<HeadInit, AuthorityFailure> {
        self.inner.initialize_head(key, generation, body)
    }
    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> { self.inner.read_head(key) }
    fn compare_exchange_head(&self, key: &HeadKey, expected: AuthorityVersionToken,
        generation: HeadGeneration, body: &[u8]) -> Result<CasOutcome, AuthorityFailure> {
        self.inner.compare_exchange_head(key, expected, generation, body)
    }
    fn authenticate_head_receipt(&self, receipt: &HeadReadReceipt) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.inner.authenticate_head_receipt(receipt)
    }
}
impl AsyncAuthorityStore for Spy {
    type Context = usize;
    fn instance_id(&self) -> StoreInstanceId { AuthorityStore::instance_id(self) }
    fn limits(&self) -> AuthorityLimits { AuthorityStore::limits(self) }
    async fn put_if_absent(&self, cx: &usize, key: &ImmutableKey, body: &[u8]) -> Result<PutOutcome, AuthorityFailure> {
        self.step(cx).await; AuthorityStore::put_if_absent(self, key, body)
    }
    async fn read_immutable(&self, cx: &usize, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.step(cx).await; AuthorityStore::read_immutable(self, key)
    }
    async fn initialize_head(&self, cx: &usize, key: &HeadKey, generation: HeadGeneration,
        body: &[u8]) -> Result<HeadInit, AuthorityFailure> {
        self.step(cx).await; AuthorityStore::initialize_head(self, key, generation, body)
    }
    async fn read_head(&self, cx: &usize, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.step(cx).await; AuthorityStore::read_head(self, key)
    }
    async fn compare_exchange_head(&self, cx: &usize, key: &HeadKey, expected: AuthorityVersionToken,
        generation: HeadGeneration, body: &[u8]) -> Result<CasOutcome, AuthorityFailure> {
        self.step(cx).await; AuthorityStore::compare_exchange_head(self, key, expected, generation, body)
    }
    async fn authenticate_head_receipt(&self, cx: &usize, receipt: &HeadReadReceipt) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.step(cx).await; AuthorityStore::authenticate_head_receipt(self, receipt)
    }
}
fn drive<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..10_000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) { return value; }
    }
    panic!("bounded forwarding-store future did not complete")
}
fn source(format: GitHashAlgorithm) -> LexicalSource {
    let id = |domain, family: &'static str| internal_object_id(
        domain, SchemaId::new(SchemaFamily::from_static(family), 1, 0),
        CodecVersion::new(1, 0), b"scoped-index-test",
    );
    LexicalSource {
        namespace: LexicalNamespace {
            tenant: TenantId::from_bytes([1; 16]), repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]), object_format: format,
        },
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        source_head: RepositoryAuthorityHeadId::from_internal_object_id(id(
            IdentityDomain::RepositoryAuthorityHead, "repository-authority-head")).unwrap(),
        source_rcr: RepositoryCommitId::from_internal_object_id(id(
            IdentityDomain::RepositoryCommitRecord, "repository-commit-record")).unwrap(),
        forge_position_root: Digest::new(internal_algorithm_id(IdentityDomain::MerkleLeaf),
            internal_digest_value(IdentityDomain::MerkleLeaf,
                SchemaId::new(SchemaFamily::from_static("lexical-test"), 1, 0), b"scope")),
        commit: git_object_id(format, GitObjectKind::Commit, b"commit"),
        tree: git_object_id(format, GitObjectKind::Tree, b"tree"),
    }
}
fn segment(source: &LexicalSource, first: u64, paths: &[&[u8]]) -> LexicalSegment {
    let content = b"needle shared";
    LexicalSegment::build(source.namespace, first, paths.iter().map(|path| SourceDocument {
        path, blob: git_object_id(source.namespace.object_format, GitObjectKind::Blob, content), content,
    }), &mut || true).unwrap()
}
fn query(channel: LexicalChannel, prefixes: &[&[u8]]) -> LexicalQuery {
    LexicalQuery::new(channel, &[b"needle".to_vec()],
        &prefixes.iter().map(|p| p.to_vec()).collect::<Vec<_>>()).unwrap()
}
struct Fixture { store: Spy, prepared: PreparedLexicalIndex }
impl Fixture {
    fn new(format: GitHashAlgorithm, groups: &[&[&[u8]]]) -> Self {
        let source = source(format);
        let mut next = 1;
        let segments = groups.iter().map(|paths| {
            let result = segment(&source, next, paths); next += paths.len() as u64; result
        }).collect();
        let result = Self { store: Spy::new(801), prepared: PreparedLexicalIndex::new(
            source, segments, 0, &mut || true).unwrap() };
        result.index().publish(&result.prepared, None, &mut || true).unwrap();
        result
    }
    fn index(&self) -> LexicalIndexStore<'_, Spy> {
        LexicalIndexStore::new(&self.store, self.prepared.source().namespace,
            self.prepared.source().reference.clone()).unwrap()
    }
    fn selected(&self, asynchronous: bool) -> LexicalSelection {
        if asynchronous {
            drive(self.index().select_async(&73, None, None, Default::default(), &mut || true)).unwrap()
        } else { self.index().select(None, None, Default::default(), &mut || true).unwrap() }
    }
    #[expect(clippy::too_many_arguments, reason = "the test varies both independent budgets and both reader implementations")]
    fn run(&self, asynchronous: bool, selected: &LexicalSelection, query: &LexicalQuery,
        after: Option<u64>, limits: LexicalReadLimits, work: LexicalQueryLimits,
        live: &mut (impl FnMut() -> bool + Send)) -> Result<IndexedLexicalReport, IndexError> {
        if asynchronous {
            drive(self.index().search_async(&73, selected, query, after, limits, work, live))
        } else { self.index().search(selected, query, after, limits, work, live) }
    }
    fn payload(&self, part: usize) -> ImmutableKey {
        payload_key(self.prepared.source().namespace, "segment", self.prepared.segments[part].root).unwrap()
    }
}
const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];

#[test]
fn scoped_content_and_path_queries_read_only_the_overlapping_segment() {
    for format in FORMATS { for asynchronous in [false, true] { for channel in [LexicalChannel::Content, LexicalChannel::Path] {
        let f = Fixture::new(format, &[&[b"docs/needle"], &[b"src/needle"], &[b"vendor/needle"]]);
        let selected = f.selected(asynchronous);
        let limits = LexicalReadLimits { max_segments: 1,
            max_payload_bytes: selected.payload_bytes + f.prepared.segments[1].bytes.len(),
            ..Default::default() };
        f.store.reset();
        let report = f.run(asynchronous, &selected, &query(channel, &[b"src"]), None,
            limits, Default::default(), &mut || true).unwrap();
        assert_eq!(report.results.hits.len(), 1);
        assert_eq!(report.results.hits[0].path, b"src/needle");
        assert_eq!(report.results.hits[0].document_id, 2);
        assert!(report.results.complete); assert_eq!(report.results.next_after, None);
        assert_eq!(report.indexed_documents, 3);
        assert_eq!(report.source, selected.source().clone());
        assert_eq!(report.generation, selected.activation().clone());
        assert_eq!(report.selected_generation_head, selected.selected_head().clone());
        assert_eq!(report.segments_read, 1);
        assert_eq!(report.payload_bytes_read, limits.max_payload_bytes);
        assert_eq!(f.store.reads.load(Ordering::SeqCst), 1);
        assert_eq!(*f.store.contexts.lock().unwrap(), if asynchronous { vec![73] } else { vec![] });
    } } }
}
#[test]
fn disjoint_scope_returns_complete_empty_with_metadata_only_allowance() {
    for asynchronous in [false, true] {
        let f = Fixture::new(GitHashAlgorithm::Sha256, &[&[b"docs/needle"], &[b"src-old/needle"]]);
        let selected = f.selected(asynchronous); f.store.reset();
        let report = f.run(asynchronous, &selected, &query(LexicalChannel::Content, &[b"src"]), None,
            LexicalReadLimits { max_payload_bytes: selected.payload_bytes, ..Default::default() },
            Default::default(), &mut || true).unwrap();
        assert!(report.results.complete); assert!(report.results.hits.is_empty());
        assert_eq!(report.segments_read, 0); assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
        assert_eq!(report.payload_bytes_read, selected.payload_bytes);
        assert!(report.results.work_units > 0);
    }
}
#[test]
fn pruning_does_not_mask_damage_in_an_overlapping_segment_or_skip_metadata_verification() {
    for asynchronous in [false, true] { for missing in [false, true] {
        let f = Fixture::new(GitHashAlgorithm::Sha1, &[&[b"docs/needle"], &[b"src/needle"]]);
        let selected = f.selected(asynchronous);
        let fault = if missing { &f.store.missing } else { &f.store.corrupt };
        *fault.lock().unwrap() = Some(f.payload(0)); f.store.reset();
        let scoped = query(LexicalChannel::Content, &[b"src"]);
        assert!(f.run(asynchronous, &selected, &scoped, None,
            Default::default(), Default::default(), &mut || true).is_ok());
        assert_eq!(f.store.reads.load(Ordering::SeqCst), 1);
        *fault.lock().unwrap() = Some(f.payload(1)); f.store.reset();
        assert!(f.run(asynchronous, &selected, &scoped, None,
            Default::default(), Default::default(), &mut || true).is_err());
        assert_eq!(f.store.reads.load(Ordering::SeqCst), 1);
        *fault.lock().unwrap() = Some(payload_key(f.prepared.source().namespace,
            "documents", f.prepared.metadata.iter().find(|p| p.kind == "documents").unwrap().root).unwrap());
        let rejected = if asynchronous {
            drive(f.index().select_async(&73, None, None, Default::default(), &mut || true))
        } else { f.index().select(None, None, Default::default(), &mut || true) };
        assert!(rejected.is_err());
    } }
}
#[test]
fn known_oversized_read_refuses_before_storage_and_exact_byte_boundary_succeeds() {
    for asynchronous in [false, true] {
        let f = Fixture::new(GitHashAlgorithm::Sha1, &[&[b"src/needle"]]);
        let selected = f.selected(asynchronous);
        let exact = selected.payload_bytes + f.prepared.segments[0].bytes.len();
        f.store.reset();
        assert!(matches!(f.run(asynchronous, &selected, &query(LexicalChannel::Content, &[b"src"]), None,
            LexicalReadLimits { max_payload_bytes: exact - 1, ..Default::default() },
            Default::default(), &mut || true), Err(IndexError::Lexical(LexicalError::Limit("index read bytes")))));
        assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
        let report = f.run(asynchronous, &selected, &query(LexicalChannel::Content, &[b"src"]), None,
            LexicalReadLimits { max_payload_bytes: exact, ..Default::default() },
            Default::default(), &mut || true).unwrap();
        assert_eq!(report.payload_bytes_read, exact);
    }
}
#[test]
fn disjunctive_prefixes_and_pagination_keep_real_lookahead_and_absolute_ids() {
    for asynchronous in [false, true] {
        let f = Fixture::new(GitHashAlgorithm::Sha256,
            &[&[b"a/needle"], &[b"b/needle"], &[b"c/needle"], &[b"y/needle"], &[b"z/needle"]]);
        let selected = f.selected(asynchronous);
        let query = query(LexicalChannel::Content, &[b"z", b"a", b"c", b"a"]);
        let mut cursor = None;
        for (id, reads, complete) in [(1, 2, false), (3, 2, false), (5, 1, true)] {
            f.store.reset();
            let page = f.run(asynchronous, &selected, &query, cursor,
                Default::default(), LexicalQueryLimits { max_results: 1, ..Default::default() }, &mut || true).unwrap();
            assert_eq!(page.results.hits.len(), 1); assert_eq!(page.results.hits[0].document_id, id);
            assert_eq!(page.results.complete, complete); assert_eq!(page.segments_read, reads);
            assert_eq!(f.store.reads.load(Ordering::SeqCst), reads);
            cursor = page.results.next_after;
            assert_eq!(cursor, if complete { None } else { Some(id) });
        }
    }
}
#[test]
fn overlapping_ranges_are_only_candidates_and_never_fabricate_matches() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, &[&[b"a/needle", b"z/needle"]]);
    let selected = f.selected(false); f.store.reset();
    let report = f.run(false, &selected, &query(LexicalChannel::Content, &[b"m"]), None,
        Default::default(), Default::default(), &mut || true).unwrap();
    assert!(report.results.complete); assert!(report.results.hits.is_empty());
    assert_eq!(report.segments_read, 1); assert_eq!(f.store.reads.load(Ordering::SeqCst), 1);
}
#[test]
fn unscoped_queries_still_visit_all_segments_and_refuse_unrelated_corruption() {
    for asynchronous in [false, true] {
        let f = Fixture::new(GitHashAlgorithm::Sha1, &[&[b"a/needle"], &[b"z/needle"]]);
        let selected = f.selected(asynchronous); f.store.reset();
        let q = query(LexicalChannel::Content, &[]);
        let result = f.run(asynchronous, &selected, &q, None,
            Default::default(), Default::default(), &mut || true).unwrap();
        assert_eq!(result.results.hits.len(), 2); assert_eq!(result.segments_read, 2);
        *f.store.missing.lock().unwrap() = Some(f.payload(1));
        assert!(matches!(f.run(asynchronous, &selected, &q, None,
            Default::default(), Default::default(), &mut || true), Err(IndexError::MissingPayload(_))));
    }
}
#[test]
fn work_is_shared_across_pruned_segments_with_exact_boundary_and_cancellation() {
    for asynchronous in [false, true] {
        let f = Fixture::new(GitHashAlgorithm::Sha1, &[&[b"a/needle"], &[b"z/needle"]]);
        let selected = f.selected(asynchronous); let q = query(LexicalChannel::Content, &[b"m"]);
        let mut checkpoints = 0;
        let result = f.run(asynchronous, &selected, &q, None, Default::default(),
            Default::default(), &mut || { checkpoints += 1; true }).unwrap();
        assert_eq!(result.results.work_units, 16); assert!(checkpoints >= 4);
        let exact = LexicalQueryLimits { max_work: 16, ..Default::default() };
        assert!(f.run(asynchronous, &selected, &q, None, Default::default(), exact, &mut || true).is_ok());
        assert!(matches!(f.run(asynchronous, &selected, &q, None, Default::default(),
            LexicalQueryLimits { max_work: 15, ..exact }, &mut || true),
            Err(IndexError::Lexical(LexicalError::Limit("query work")))));
        for stop in 1..=checkpoints {
            let mut calls = 0;
            assert!(matches!(f.run(asynchronous, &selected, &q, None, Default::default(),
                Default::default(), &mut || { calls += 1; calls != stop }),
                Err(IndexError::Lexical(LexicalError::Cancelled))));
            assert_eq!(calls, stop);
        }
    }
}
#[test]
fn exhausted_segment_budget_counts_only_actual_reads_but_remains_hard() {
    for asynchronous in [false, true] {
        let f = Fixture::new(GitHashAlgorithm::Sha1, &[&[b"a/needle"], &[b"src/a/needle"], &[b"src/z/needle"]]);
        let selected = f.selected(asynchronous); f.store.reset();
        assert!(matches!(f.run(asynchronous, &selected, &query(LexicalChannel::Content, &[b"src"]), None,
            LexicalReadLimits { max_segments: 1, ..Default::default() }, Default::default(), &mut || true),
            Err(IndexError::Lexical(LexicalError::Limit("index segment reads")))));
        assert_eq!(f.store.reads.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn pruning_never_bypasses_store_instance_namespace_or_ref_binding() {
    let f = Fixture::new(GitHashAlgorithm::Sha1, &[&[b"a/needle"]]);
    let selected = f.selected(false); let other = Spy::new(802);
    let mut namespace = f.prepared.source().namespace;
    for (store, ns, reference) in [
        (&other, namespace, f.prepared.source().reference.clone()),
        (&f.store, { namespace.repository = RepositoryId::from_bytes([7; 16]); namespace },
            f.prepared.source().reference.clone()),
        (&f.store, f.prepared.source().namespace, RefName::try_new(b"refs/heads/other").unwrap()),
    ] {
        store.reset();
        let index = LexicalIndexStore::new(store, ns, reference).unwrap();
        let q = query(LexicalChannel::Content, &[b"unrelated"]);
        assert!(matches!(index.search(&selected, &q, None, Default::default(),
            Default::default(), &mut || true), Err(IndexError::SourceMismatch)));
        assert!(matches!(drive(index.search_async(&73, &selected, &q, None, Default::default(),
            Default::default(), &mut || true)), Err(IndexError::SourceMismatch)));
        assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn exact_path_subtree_and_binary_boundaries_have_no_false_negative() {
    let source = source(GitHashAlgorithm::Sha256);
    let paths: &[&[u8]] = &[
        b"a", b"a!", b"a-", b"a/a", b"a/a/x", b"a/z", b"a0", b"aa", b"b",
        b"src", b"src-old", b"src/a", b"src/z", b"src0", b"srcfile", b"z",
        b"\x80", b"\x80/a", b"\xff", b"\xff/a",
    ];
    for (lo, first) in paths.iter().enumerate() { for last in &paths[lo..] {
        let inputs = if first == last { vec![*first] } else { vec![*first, *last] };
        let segment = segment(&source, 1, &inputs);
        let reference = SegmentRef::new(&segment, segment.root(&mut || true).unwrap(),
            segment.encode(&mut || true).unwrap().len()).unwrap();
        for prefix in paths {
            let q = query(LexicalChannel::Content, &[*prefix]);
            let may = reference.may_match(&q, &mut QueryBudget::new(Default::default()).unwrap(), &mut || true).unwrap();
            let matches = |path: &&[u8]| path == prefix || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/'));
            if paths.iter().filter(|p| *p >= first && *p <= last).any(matches) { assert!(may, "{first:?} {last:?} {prefix:?}"); }
            if first == last { assert_eq!(may, matches(first), "{first:?} {prefix:?}"); }
        }
    } }
    // No Unicode conversion, signed-char comparison or carry/successor rule.
    for byte in 1..=255u8 {
        if matches!(byte, b'.' | b'/') { continue; }
        let prefix = [byte]; let path = [byte, b'/', b'a'];
        let segment = segment(&source, 1, &[&path]);
        let reference = SegmentRef::new(&segment, segment.root(&mut || true).unwrap(),
            segment.encode(&mut || true).unwrap().len()).unwrap();
        assert!(reference.may_match(&query(LexicalChannel::Content, &[&prefix]),
            &mut QueryBudget::new(Default::default()).unwrap(), &mut || true).unwrap());
    }
}

#[test]
fn scoped_results_equal_the_previous_full_segment_scan() {
    for format in FORMATS {
        let f = Fixture::new(format, &[
            &[b"docs/needle", b"src-old/needle"],
            &[b"src/needle", b"src/shared/needle"],
            &[b"src0/needle", b"vendor/needle"],
            &[b"\xff/needle"],
        ]);
        let selected = f.selected(false);
        let scopes: &[&[&[u8]]] = &[
            &[], &[b"src"], &[b"src/needle"], &[b"docs", b"vendor"],
            &[b"src-old", b"src0"], &[b"\xff"], &[b"absent"],
        ];
        for channel in [LexicalChannel::Content, LexicalChannel::Path] {
            for terms in [vec![b"needle".to_vec()], vec![b"needle".to_vec(), b"shared".to_vec()]] {
                for prefixes in scopes {
                    let query = LexicalQuery::new(channel, &terms,
                        &prefixes.iter().map(|p| p.to_vec()).collect::<Vec<_>>()).unwrap();
                    for after in [None, Some(1), Some(2), Some(4), Some(u64::MAX)] {
                        for limit in [1, 2, 100] {
                            let limits = LexicalQueryLimits { max_results: limit, ..Default::default() };
                            let mut budget = QueryBudget::new(limits).unwrap();
                            let mut hits = Vec::new();
                            let mut more = false;
                            // Reference behavior: decode EVERY segment, without
                            // consulting the new path-range predicate at all.
                            for payload in &f.prepared.segments {
                                let segment = LexicalSegment::decode(&payload.bytes, payload.root,
                                    selected.source().namespace, &mut || true).unwrap();
                                more = segment.search_into(&query, after, &mut budget, &mut hits,
                                    &mut || true).unwrap();
                                if more { break; }
                            }
                            for asynchronous in [false, true] {
                                let result = f.run(asynchronous, &selected, &query, after,
                                    Default::default(), limits, &mut || true).unwrap();
                                assert_eq!(result.results.hits, hits);
                                assert_eq!(result.results.complete, !more);
                                assert_eq!(result.results.next_after,
                                    if more { hits.last().map(|h| h.document_id) } else { None });
                                assert_eq!(result.indexed_documents, 7);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn maximum_length_binary_prefix_is_exact_and_needs_no_allocated_successor() {
    let path = vec![0xff; 4096];
    let f = Fixture::new(GitHashAlgorithm::Sha256, &[&[&path]]);
    let selected = f.selected(false);
    for asynchronous in [false, true] {
        let exact = f.run(asynchronous, &selected, &query(LexicalChannel::Content, &[&path]), None,
            Default::default(), Default::default(), &mut || true).unwrap();
        assert_eq!(exact.results.hits.len(), 1);
        assert_eq!(exact.results.hits[0].path, path);
        let shorter = f.run(asynchronous, &selected, &query(LexicalChannel::Content, &[&path[..4095]]), None,
            Default::default(), Default::default(), &mut || true).unwrap();
        assert!(shorter.results.hits.is_empty());
        assert_eq!(shorter.segments_read, 0);
    }
}
