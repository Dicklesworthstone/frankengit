//! Exercises real generation encoding and reference-store publication through
//! the production read APIs. The async store is a named test double, not the
//! durable backend; no test here establishes live-node or crash conformance.
use super::*;
use crate::generation::activation::tests::{AsyncStore, candidate, digest, key, ready};
use crate::generation::immutable_generation_key;
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityVersionToken, CasOutcome,
    HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead, PutOutcome,
    StoreInstanceId,
};
use fgit_codec::encode_body;
use fgit_crypto::{IdentityDomain, internal_object_id};
use fgit_types::{CodecVersion, HeadGeneration, RepositoryCommitId, SchemaFamily, SchemaId};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

fn view() -> GraphViewId { GraphViewId::try_new(b"commit-ancestry").unwrap() }
fn chain(store: &AsyncStore, count: usize) -> Vec<(GraphGenerationBody, GenerationActivation)> {
    let mut generations = Vec::new();
    let mut parent = None;
    for n in 0..count {
        let mut body = candidate(format!("index-{n}").as_bytes(), parent);
        body.source.source_rcr_id = RepositoryCommitId::from_internal_object_id(internal_object_id(
            IdentityDomain::RepositoryCommitRecord,
            SchemaId::new(SchemaFamily::from_static("repository-commit-record"), 1, 0),
            CodecVersion::new(1, 0), format!("source-{n}").as_bytes(),
        )).unwrap();
        body.source.source_forge_position_root = digest(format!("forge-{n}").as_bytes());
        body.vertices_root = digest(format!("vertices-{n}").as_bytes());
        body.edges_root = digest(format!("edges-{n}").as_bytes());
        body.evidence_root = digest(format!("evidence-{n}").as_bytes());
        let activation = ready(GenerationAuthority::new(store, key())
            .stage_and_activate_async(&1, &body)).unwrap();
        parent = Some(activation.generation_id);
        generations.push((body, activation));
    }
    generations
}

#[test]
fn continuation_returns_the_requested_manifest_not_the_new_active_index() {
    let store = AsyncStore::new();
    let generations = chain(&store, 3);
    let authority = GenerationAuthority::new(&store, key());
    let target = &generations[0].1;
    let newest = &generations[2].1;
    let current = ready(authority.read_active_async(&2, view(), Some(target),
        Default::default(), &mut || true)).unwrap().unwrap();
    let pinned = ready(authority.read_at_async(&3, view(), target, None,
        Default::default(), &mut || true)).unwrap();
    assert_eq!(current.activation(), newest);
    assert_eq!(pinned.activation(), target);
    assert_eq!(pinned.selected_head(), newest);
    assert_eq!(pinned.body(), &generations[0].0);
    assert_ne!(pinned.body().index_manifest_root(), current.body().index_manifest_root());
    assert_ne!(pinned.body().source(), current.body().source());
    assert_eq!(pinned.body().vertices_root(), &generations[0].0.vertices_root);
    assert_eq!(pinned.body().edges_root(), &generations[0].0.edges_root);
    assert_eq!(pinned.body().evidence_root(), &generations[0].0.evidence_root);
    assert_eq!(pinned.generations_read(), 3);
}

#[test]
fn every_original_position_has_exact_sync_async_body_and_counter_parity() {
    let store = AsyncStore::new();
    let generations = chain(&store, 12);
    let authority = GenerationAuthority::new(&store, key());
    let reference = GenerationAuthority::new(&store.inner, key());
    let head_bytes = encode_body(&generations[11].0).unwrap().len();
    for (index, (body, activation)) in generations.iter().enumerate() {
        let asynchronous = ready(authority.read_at_async(&17, view(), activation, None,
            Default::default(), &mut || true)).unwrap();
        let synchronous = reference.read_at(view(), activation, None,
            Default::default(), &mut || true).unwrap();
        assert_eq!(synchronous, asynchronous);
        assert_eq!(asynchronous.body(), body);
        assert_eq!(asynchronous.activation(), activation);
        assert_eq!(asynchronous.selected_head(), &generations[11].1);
        assert_eq!(asynchronous.generations_read(), generations.len() - index);
        assert_eq!(asynchronous.bytes_read(), head_bytes + generations[index..].iter()
            .map(|(body, _)| encode_body(body).unwrap().len()).sum::<usize>());
    }
}

#[test]
fn independent_checkpoints_are_verified_on_both_sides_of_the_query_generation() {
    let store = AsyncStore::new();
    let generations = chain(&store, 4);
    let authority = GenerationAuthority::new(&store, key());
    let target = &generations[2].1;
    for index in 0..4 {
        let floor = &generations[index].1;
        let result = ready(authority.read_at_async(&2, view(), target, Some(floor),
            Default::default(), &mut || true)).unwrap();
        assert_eq!(result.body(), &generations[2].0);
        assert_eq!(result.activation(), target);
        assert_eq!(result.generations_read(), 4 - index.min(2));
        let wrong = GenerationActivation {
            generation_id: candidate(b"fork", None).generation_id().unwrap(),
            authority_generation: floor.authority_generation,
        };
        assert!(matches!(ready(authority.read_at_async(&3, view(), target, Some(&wrong),
            Default::default(), &mut || true)), Err(GenerationAuthorityError::CheckpointUnresolved)));
    }
    let unresolved = GenerationActivation {
        generation_id: target.generation_id,
        authority_generation: HeadGeneration::try_new(5).unwrap(),
    };
    assert!(matches!(ready(authority.read_at_async(&4, view(), target, Some(&unresolved),
        Default::default(), &mut || true)), Err(GenerationAuthorityError::CheckpointUnresolved)));
}

#[test]
fn an_existing_identity_at_the_wrong_original_position_is_not_a_valid_pin() {
    let store = AsyncStore::new();
    let generations = chain(&store, 3);
    let authority = GenerationAuthority::new(&store, key());
    for bad in [
        GenerationActivation { generation_id: generations[0].1.generation_id, authority_generation: generations[2].1.authority_generation },
        GenerationActivation { generation_id: generations[2].1.generation_id, authority_generation: HeadGeneration::FIRST },
        GenerationActivation { generation_id: generations[1].1.generation_id, authority_generation: HeadGeneration::try_new(4).unwrap() },
    ] {
        for minimum in [None, Some(&generations[0].1), Some(&generations[2].1)] {
            assert!(matches!(ready(authority.read_at_async(&2, view(), &bad, minimum,
                Default::default(), &mut || true)), Err(GenerationAuthorityError::CheckpointUnresolved)));
        }
    }
    assert!(matches!(ready(authority.read_at_async(&2, GraphViewId::try_new(b"another-view").unwrap(),
        &generations[0].1, None, Default::default(), &mut || true)), Err(GenerationAuthorityError::ViewMismatch { .. })));
}

#[test]
fn a_staged_fork_or_uninitialized_head_never_becomes_a_query_generation() {
    let store = AsyncStore::new();
    let orphan = candidate(b"orphan", None);
    let orphan_id = orphan.generation_id().unwrap();
    let slot = immutable_generation_key(orphan_id).unwrap();
    store.inner.put_if_absent(&slot, &encode_body(&orphan).unwrap()).unwrap();
    let expected = GenerationActivation { generation_id: orphan_id, authority_generation: HeadGeneration::FIRST };
    let authority = GenerationAuthority::new(&store, key());
    assert!(matches!(ready(authority.read_at_async(&2, view(), &expected, None,
        Default::default(), &mut || true)), Err(GenerationAuthorityError::CheckpointUnresolved)));
    chain(&store, 3);
    let before = store.inner.read_head(&key()).unwrap();
    assert!(matches!(ready(authority.read_at_async(&3, view(), &expected, None,
        Default::default(), &mut || true)), Err(GenerationAuthorityError::CheckpointUnresolved)));
    assert!(matches!(store.inner.read_immutable(&slot).unwrap(), ImmutableRead::Present(_)));
    assert_eq!(store.inner.read_head(&key()).unwrap(), before);
}

#[test]
fn missing_or_corrupt_backing_is_not_repaired_by_returning_a_different_generation() {
    for fault in ["missing-current", "missing-target", "wrong-target"] {
        let store = AsyncStore::new();
        let first = candidate(b"first", None);
        let first_id = first.generation_id().unwrap();
        let next = candidate(b"next", Some(first_id));
        let next_bytes = encode_body(&next).unwrap();
        store.inner.initialize_head(&key(), HeadGeneration::try_new(2).unwrap(), &next_bytes).unwrap();
        if fault != "missing-current" {
            store.inner.put_if_absent(&immutable_generation_key(next.generation_id().unwrap()).unwrap(), &next_bytes).unwrap();
        }
        if fault != "missing-target" {
            let body = if fault == "wrong-target" { candidate(b"substituted", None) } else { first };
            store.inner.put_if_absent(&immutable_generation_key(first_id).unwrap(), &encode_body(&body).unwrap()).unwrap();
        }
        let target = GenerationActivation { generation_id: first_id, authority_generation: HeadGeneration::FIRST };
        let result = ready(GenerationAuthority::new(&store, key()).read_at_async(&2, view(), &target,
            None, Default::default(), &mut || true));
        match (fault, result) {
            ("missing-current" | "missing-target", Err(GenerationAuthorityError::MissingGeneration { .. })) => {}
            ("wrong-target", Err(GenerationAuthorityError::GenerationIdentityMismatch { expected, observed })) => {
                assert_eq!(*expected, first_id); assert_ne!(expected, observed);
            }
            other => panic!("query accepted incomplete history: {other:?}"),
        }
    }
}

#[test]
fn exact_work_bounds_include_the_independent_floor_and_have_permitted_twins() {
    let store = AsyncStore::new();
    let generations = chain(&store, 3);
    let authority = GenerationAuthority::new(&store, key());
    let sizes: Vec<_> = generations.iter().map(|(body, _)| encode_body(body).unwrap().len()).collect();
    let exact = GenerationReadLimits {
        max_generations: 3, max_body_bytes: *sizes.iter().max().unwrap(),
        max_total_bytes: sizes[2] + sizes.iter().sum::<usize>(),
    };
    let expected = &generations[1].1;
    let minimum = Some(&generations[0].1);
    let result = ready(authority.read_at_async(&2, view(), expected, minimum, exact, &mut || true)).unwrap();
    assert_eq!(result.generations_read(), 3);
    assert_eq!(result.bytes_read(), exact.max_total_bytes);
    assert_eq!(result.body(), &generations[1].0);
    for short in [GenerationReadLimits { max_generations: 2, ..exact },
        GenerationReadLimits { max_total_bytes: exact.max_total_bytes - 1, ..exact },
        GenerationReadLimits { max_body_bytes: exact.max_body_bytes - 1, ..exact }] {
        assert!(matches!(ready(authority.read_at_async(&2, view(), expected, minimum, short, &mut || true)),
            Err(GenerationAuthorityError::ReadBudgetExceeded(_))));
    }
    store.calls.lock().unwrap().clear();
    assert!(matches!(ready(authority.read_at_async(&2, view(), expected, minimum,
        GenerationReadLimits { max_generations: 0, ..exact }, &mut || true)), Err(GenerationAuthorityError::InvalidReadLimits)));
    assert!(store.calls.lock().unwrap().is_empty());
}

#[test]
fn cancellation_before_or_after_a_read_exposes_no_provisional_manifest() {
    let store = AsyncStore::new();
    let generations = chain(&store, 3);
    let authority = GenerationAuthority::new(&store, key());
    store.calls.lock().unwrap().clear();
    assert!(matches!(ready(authority.read_at_async(&2, view(), &generations[0].1, None,
        Default::default(), &mut || false)), Err(GenerationAuthorityError::ReadCancelled)));
    assert!(store.calls.lock().unwrap().is_empty());
    let mut live = || store.calls.lock().unwrap().iter().filter(|(op, _)| *op == "immutable").count() < 2;
    assert!(matches!(ready(authority.read_at_async(&3, view(), &generations[0].1, None,
        Default::default(), &mut live)), Err(GenerationAuthorityError::ReadCancelled)));
    assert_eq!(store.calls.lock().unwrap().iter().filter(|(op, _)| *op == "immutable").count(), 2);
    let allowed = ready(authority.read_at_async(&4, view(), &generations[0].1, None,
        Default::default(), &mut || true)).unwrap();
    assert_eq!(allowed.body(), &generations[0].0);
}

#[test]
fn concurrent_activation_changes_the_observation_not_the_query_manifest() {
    let store = AsyncStore::new();
    let generations = chain(&store, 3);
    let later = candidate(b"later-index", Some(generations[2].1.generation_id));
    let authority = GenerationAuthority::new(&store, key());
    store.calls.lock().unwrap().clear();
    let mut fired = false;
    let mut live = || {
        if !fired && store.calls.lock().unwrap().iter().any(|(op, _)| *op == "immutable") {
            GenerationAuthority::new(&store.inner, key()).stage_and_activate(&later).unwrap();
            fired = true;
        }
        true
    };
    let first = ready(authority.read_at_async(&19, view(), &generations[1].1,
        Some(&generations[0].1), Default::default(), &mut live)).unwrap();
    assert!(fired, "writer must actually advance the head during the walk");
    assert_eq!(first.body(), &generations[1].0);
    assert_eq!(first.selected_head(), &generations[2].1);
    assert_eq!(store.calls.lock().unwrap().iter().filter(|(op, _)| *op == "head").count(), 1);
    assert!(store.calls.lock().unwrap().iter().all(|(op, cx)| ["head", "authenticate", "immutable"].contains(op) && *cx == 19));
    let second = ready(authority.read_at_async(&20, view(), first.activation(), Some(first.selected_head()),
        Default::default(), &mut || true)).unwrap();
    assert_eq!(second.activation(), first.activation());
    assert_eq!(second.body(), first.body());
    assert_eq!(second.selected_head().generation_id, later.generation_id().unwrap());
    assert_ne!(second.selected_head(), first.selected_head());
}

/// A real suspension in the test adapter, not a polling loop or another runtime.
struct PendingRead<'a> { inner: &'a AsyncStore, once: AtomicBool }
impl AsyncAuthorityStore for PendingRead<'_> {
    type Context = u64;
    fn instance_id(&self) -> StoreInstanceId { self.inner.instance_id() }
    fn limits(&self) -> AuthorityLimits { self.inner.limits() }
    async fn put_if_absent(&self, cx: &u64, key: &ImmutableKey, body: &[u8]) -> Result<PutOutcome, AuthorityFailure> {
        self.inner.put_if_absent(cx, key, body).await
    }
    async fn read_immutable(&self, cx: &u64, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        if self.once.swap(false, Ordering::SeqCst) {
            let mut pending = true;
            std::future::poll_fn(|cx| {
                if std::mem::take(&mut pending) { cx.waker().wake_by_ref(); Poll::Pending }
                else { Poll::Ready(()) }
            }).await;
        }
        self.inner.read_immutable(cx, key).await
    }
    async fn initialize_head(&self, cx: &u64, key: &HeadKey, generation: HeadGeneration, body: &[u8]) -> Result<HeadInit, AuthorityFailure> {
        self.inner.initialize_head(cx, key, generation, body).await
    }
    async fn read_head(&self, cx: &u64, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.inner.read_head(cx, key).await
    }
    async fn compare_exchange_head(&self, cx: &u64, key: &HeadKey, expected: AuthorityVersionToken,
        generation: HeadGeneration, body: &[u8]) -> Result<CasOutcome, AuthorityFailure> {
        self.inner.compare_exchange_head(cx, key, expected, generation, body).await
    }
    async fn authenticate_head_receipt(&self, cx: &u64, receipt: &HeadReadReceipt) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.inner.authenticate_head_receipt(cx, receipt).await
    }
}

#[test]
fn pending_reads_resume_or_cancel_without_returning_a_staged_query_result() {
    for cancel in [false, true] {
        let store = AsyncStore::new();
        let generations = chain(&store, 2);
        store.calls.lock().unwrap().clear();
        let delayed = PendingRead { inner: &store, once: AtomicBool::new(true) };
        let authority = GenerationAuthority::new(&delayed, key());
        let cancelled = AtomicBool::new(false);
        let mut live = || !cancelled.load(Ordering::SeqCst);
        let future = authority.read_at_async(&52, view(), &generations[0].1, None,
            Default::default(), &mut live);
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert_eq!(store.calls.lock().unwrap().as_slice(), &[("head", 52), ("authenticate", 52)]);
        cancelled.store(cancel, Ordering::SeqCst);
        let Poll::Ready(result) = future.as_mut().poll(&mut context) else { panic!("read did not resume") };
        if cancel { assert!(matches!(result, Err(GenerationAuthorityError::ReadCancelled))); }
        else { assert_eq!(result.unwrap().body(), &generations[0].0); }
        assert!(store.calls.lock().unwrap().iter().all(|(op, cx)| ["head", "authenticate", "immutable"].contains(op) && *cx == 52));
    }
}

#[test]
fn an_unpolled_sendable_read_has_no_effect_and_an_owned_pin_stays_unchanged() {
    let store = AsyncStore::new();
    let generations = chain(&store, 2);
    let authority = GenerationAuthority::new(&store, key());
    store.calls.lock().unwrap().clear();
    let mut live = || true;
    fn require_send<T: Send>(_: T) {}
    require_send(authority.read_at_async(&43, view(), &generations[0].1, None,
        Default::default(), &mut live));
    assert!(store.calls.lock().unwrap().is_empty());
    let pinned = ready(authority.read_at_async(&44, view(), &generations[0].1, None,
        Default::default(), &mut live)).unwrap();
    let next = candidate(b"advanced", Some(generations[1].1.generation_id));
    GenerationAuthority::new(&store.inner, key()).stage_and_activate(&next).unwrap();
    assert_eq!(pinned.body(), &generations[0].0);
    assert_eq!(pinned.selected_head(), &generations[1].1);
    // A fresh authority wrapper uses the same stored history, not a local cache.
    let again = GenerationAuthority::new(&store.inner, key()).read_at(view(), pinned.activation(),
        Some(pinned.selected_head()), Default::default(), &mut live).unwrap();
    assert_eq!(again.body(), pinned.body());
    assert_eq!(again.selected_head().generation_id, next.generation_id().unwrap());
}

#[test]
fn exact_only_queries_use_the_pinned_class_not_a_different_generations_class() {
    use crate::{GraphAuthorityClass, GraphAuthorityClassRefusal};
    let store = AsyncStore::new();
    let authority = GenerationAuthority::new(&store, key());
    let mut exact = candidate(b"exact", None);
    exact.authority_class = GraphAuthorityClass::Exact;
    let first = ready(authority.stage_and_activate_async(&1, &exact)).unwrap();
    let mut statistical = candidate(b"statistical", Some(first.generation_id));
    statistical.authority_class = GraphAuthorityClass::Statistical;
    let second = ready(authority.stage_and_activate_async(&1, &statistical)).unwrap();
    let old = ready(authority.read_at_async(&2, view(), &first, Some(&second),
        Default::default(), &mut || true)).unwrap();
    assert_eq!(old.body().require_exact().unwrap().body(), &exact);
    let latest = ready(authority.read_at_async(&2, view(), &second, Some(&first),
        Default::default(), &mut || true)).unwrap();
    assert_eq!(latest.body().require_exact(), Err(GraphAuthorityClassRefusal::ExactRequired {
        observed: GraphAuthorityClass::Statistical,
    }));
    assert_ne!(old.body().generation_id().unwrap(), latest.body().generation_id().unwrap());
}
