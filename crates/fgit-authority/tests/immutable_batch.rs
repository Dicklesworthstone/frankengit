#![forbid(unsafe_code)]
//! Exact immutable-write semantics for the portable synchronous and async
//! paths. The native backend's SQL/rollback tests live in its owning crate.

#[path = "immutable_batch/sealing.rs"]
mod sealing;

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityRefusal, AuthorityStore, AuthorityVersionToken, CasOutcome, HeadInit, HeadKey,
    HeadRead, HeadReadReceipt, ImmutableBatchFailure, ImmutableBatchRefusal, ImmutableKey,
    ImmutableRead, MAX_IMMUTABLE_BATCH_BYTES, MAX_IMMUTABLE_BATCH_ITEMS, MemoryAuthorityStore,
    MemoryStoreConfig, PutOutcome, StoreInstanceId,
};
use fgit_types::HeadGeneration;

struct Context {
    cancelled: AtomicBool,
    cancel_after: usize,
}

impl Context {
    fn live() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            cancel_after: 0,
        }
    }
}

/// Immediate futures over the reference store are a deterministic test
/// fixture, not a production blocking adapter or native cancellation proof.
struct AsyncStore {
    inner: MemoryAuthorityStore,
    writes: AtomicUsize,
    fail_before: AtomicUsize,
    lose_after: AtomicUsize,
}

impl AsyncStore {
    fn new(limits: AuthorityLimits) -> Self {
        Self {
            inner: memory(limits),
            writes: AtomicUsize::new(0),
            fail_before: AtomicUsize::new(0),
            lose_after: AtomicUsize::new(0),
        }
    }
}

impl AsyncAuthorityStore for AsyncStore {
    type Context = Context;

    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }

    async fn put_if_absent(
        &self,
        cx: &Context,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        if cx.cancelled.load(Ordering::SeqCst) {
            return Err(AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled));
        }
        let ordinal = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if ordinal == self.fail_before.load(Ordering::SeqCst) {
            return Err(AuthorityFailure::Refused(AuthorityRefusal::Unavailable));
        }
        let result = self.inner.put_if_absent(key, body);
        if ordinal == cx.cancel_after {
            cx.cancelled.store(true, Ordering::SeqCst);
        }
        if ordinal == self.lose_after.load(Ordering::SeqCst) && result.is_ok() {
            Err(AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse))
        } else {
            result
        }
    }

    async fn read_immutable(
        &self,
        _: &Context,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        self.inner.read_immutable(key)
    }

    async fn initialize_head(
        &self,
        _: &Context,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.inner.initialize_head(key, generation, body)
    }

    async fn read_head(&self, _: &Context, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.inner.read_head(key)
    }

    async fn compare_exchange_head(
        &self,
        _: &Context,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.inner
            .compare_exchange_head(key, expected, generation, body)
    }

    async fn authenticate_head_receipt(
        &self,
        _: &Context,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.inner.authenticate_head_receipt(receipt)
    }
}

fn memory(limits: AuthorityLimits) -> MemoryAuthorityStore {
    MemoryAuthorityStore::with_config(MemoryStoreConfig {
        instance: StoreInstanceId::from_raw(61),
        limits,
        ..MemoryStoreConfig::default()
    })
}

fn ready<F: Future>(future: F) -> F::Output {
    use std::task::{Context as TaskContext, Poll, Waker};
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut TaskContext::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference operations must complete immediately"),
    }
}

fn key(index: usize) -> ImmutableKey {
    ImmutableKey::new(format!("batch/{index:03}").into_bytes()).unwrap()
}

fn entries(count: usize) -> Vec<(ImmutableKey, Vec<u8>)> {
    (0..count)
        .map(|index| (key(index), format!("body-{index}").into_bytes()))
        .collect()
}

fn assert_absent(store: &MemoryAuthorityStore, key: &ImmutableKey) {
    assert_eq!(store.read_immutable(key).unwrap(), ImmutableRead::Absent);
}

#[test]
fn both_surfaces_preserve_order_and_duplicate_key_create_retry_conflict() {
    let batch = vec![
        (key(0), b"first".to_vec()),
        (key(1), b"other".to_vec()),
        (key(0), b"first".to_vec()),
        (key(0), b"changed".to_vec()),
        (key(1), b"other".to_vec()),
    ];
    let expected = vec![
        PutOutcome::Created,
        PutOutcome::Created,
        PutOutcome::IdenticalRetry,
        PutOutcome::Conflict,
        PutOutcome::IdenticalRetry,
    ];
    let sync = memory(AuthorityLimits::default());
    assert_eq!(sync.put_if_absent_batch(&batch).unwrap(), expected);
    let asynchronous = AsyncStore::new(AuthorityLimits::default());
    assert_eq!(
        ready(asynchronous.put_if_absent_batch(&Context::live(), &batch)).unwrap(),
        expected
    );
    for store in [&sync, &asynchronous.inner] {
        assert_eq!(
            store.read_immutable(&key(0)).unwrap(),
            ImmutableRead::Present(b"first".to_vec())
        );
    }
}

#[test]
fn item_and_aggregate_boundaries_have_exact_permitted_twins() {
    let store = AsyncStore::new(AuthorityLimits::default());
    let too_many = entries(MAX_IMMUTABLE_BATCH_ITEMS + 1);
    let failure = ready(store.put_if_absent_batch(&Context::live(), &too_many)).unwrap_err();
    assert_eq!(
        failure,
        ImmutableBatchFailure::Bounds(ImmutableBatchRefusal::TooManyItems {
            observed: MAX_IMMUTABLE_BATCH_ITEMS + 1,
            limit: MAX_IMMUTABLE_BATCH_ITEMS,
        })
    );
    assert!(failure.proves_no_effect());
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        ready(store.put_if_absent_batch(&Context::live(), &too_many[..MAX_IMMUTABLE_BATCH_ITEMS]))
            .unwrap(),
        vec![PutOutcome::Created; MAX_IMMUTABLE_BATCH_ITEMS]
    );

    let store = memory(AuthorityLimits::default());
    let target = key(99);
    let mut at_limit = vec![(
        target.clone(),
        vec![7; MAX_IMMUTABLE_BATCH_BYTES - target.as_bytes().len()],
    )];
    at_limit[0].1.push(7);
    assert_eq!(
        store.put_if_absent_batch(&at_limit).unwrap_err(),
        ImmutableBatchFailure::Bounds(ImmutableBatchRefusal::BytesExceeded {
            observed: MAX_IMMUTABLE_BATCH_BYTES + 1,
            limit: MAX_IMMUTABLE_BATCH_BYTES,
        })
    );
    assert_absent(&store, &target);
    at_limit[0].1.pop();
    assert_eq!(
        store.put_if_absent_batch(&at_limit).unwrap(),
        vec![PutOutcome::Created]
    );
}

#[test]
fn later_oversized_body_is_rejected_before_any_earlier_write() {
    let store = AsyncStore::new(AuthorityLimits {
        body_bytes: 3,
        ..AuthorityLimits::default()
    });
    let mut batch = vec![(key(0), vec![1; 3]), (key(1), vec![2; 4])];
    assert_eq!(
        ready(store.put_if_absent_batch(&Context::live(), &batch)).unwrap_err(),
        ImmutableBatchFailure::Bounds(ImmutableBatchRefusal::BodyTooLarge {
            index: 1,
            observed: 4,
            limit: 3,
        })
    );
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_absent(&store.inner, &key(0));
    batch[1].1.pop();
    assert_eq!(
        ready(store.put_if_absent_batch(&Context::live(), &batch)).unwrap(),
        vec![PutOutcome::Created, PutOutcome::Created]
    );
}

#[test]
fn capacity_refusal_preserves_the_portable_prefix_and_exact_retries_at_capacity() {
    let store = memory(AuthorityLimits {
        immutable_slots: 2,
        ..AuthorityLimits::default()
    });
    let batch = entries(3);
    let failure = store.put_if_absent_batch(&batch).unwrap_err();
    assert_eq!(
        failure,
        ImmutableBatchFailure::Interrupted {
            completed: 2,
            source: AuthorityFailure::Refused(AuthorityRefusal::CapacityExhausted {
                occupancy: 2,
                limit: 2,
            }),
        }
    );
    assert!(!failure.proves_no_effect());
    assert_absent(&store, &batch[2].0);
    assert_eq!(
        store.put_if_absent_batch(&batch[..2]).unwrap(),
        vec![PutOutcome::IdenticalRetry; 2]
    );
    let conflict = vec![(key(0), b"changed".to_vec()), batch[1].clone()];
    assert_eq!(
        store.put_if_absent_batch(&conflict).unwrap(),
        vec![PutOutcome::Conflict, PutOutcome::IdenticalRetry]
    );
}

#[test]
fn lost_response_retains_ambiguity_and_identical_retry_recovers_each_entry() {
    let store = AsyncStore::new(AuthorityLimits::default());
    store.lose_after.store(2, Ordering::SeqCst);
    let batch = entries(3);
    let failure = ready(store.put_if_absent_batch(&Context::live(), &batch)).unwrap_err();
    assert_eq!(
        failure,
        ImmutableBatchFailure::Interrupted {
            completed: 1,
            source: AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse),
        }
    );
    assert!(!failure.proves_no_effect());
    assert_eq!(
        store.inner.read_immutable(&batch[1].0).unwrap(),
        ImmutableRead::Present(batch[1].1.clone())
    );
    assert_absent(&store.inner, &batch[2].0);
    assert_eq!(
        ready(store.put_if_absent_batch(&Context::live(), &batch)).unwrap(),
        vec![
            PutOutcome::IdenticalRetry,
            PutOutcome::IdenticalRetry,
            PutOutcome::Created
        ]
    );
}

#[test]
fn cancellation_is_forwarded_per_item_and_never_erases_a_completed_prefix() {
    let store = AsyncStore::new(AuthorityLimits::default());
    let batch = entries(3);
    let cx = Context {
        cancelled: AtomicBool::new(false),
        cancel_after: 2,
    };
    let failure = ready(store.put_if_absent_batch(&cx, &batch)).unwrap_err();
    assert_eq!(
        failure,
        ImmutableBatchFailure::Interrupted {
            completed: 2,
            source: AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled),
        }
    );
    assert!(!failure.proves_no_effect());
    assert_absent(&store.inner, &batch[2].0);
    assert_eq!(
        ready(store.put_if_absent_batch(&Context::live(), &batch)).unwrap(),
        vec![
            PutOutcome::IdenticalRetry,
            PutOutcome::IdenticalRetry,
            PutOutcome::Created
        ]
    );
}

#[test]
fn first_refusal_and_later_refusal_have_distinct_effect_knowledge() {
    for (failure_at, no_effect) in [(1, true), (2, false)] {
        let store = AsyncStore::new(AuthorityLimits::default());
        store.fail_before.store(failure_at, Ordering::SeqCst);
        let failure = ready(store.put_if_absent_batch(&Context::live(), &entries(3))).unwrap_err();
        assert_eq!(failure.proves_no_effect(), no_effect);
        assert_eq!(
            failure,
            ImmutableBatchFailure::Interrupted {
                completed: failure_at - 1,
                source: AuthorityFailure::Refused(AuthorityRefusal::Unavailable),
            }
        );
    }
}

#[test]
fn empty_batch_is_a_noop_with_no_store_or_context_operation() {
    let store = AsyncStore::new(AuthorityLimits::default());
    let cx = Context {
        cancelled: AtomicBool::new(true),
        cancel_after: 0,
    };
    assert_eq!(ready(store.put_if_absent_batch(&cx, &[])).unwrap(), vec![]);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(store.inner.put_if_absent_batch(&[]).unwrap(), vec![]);
}
