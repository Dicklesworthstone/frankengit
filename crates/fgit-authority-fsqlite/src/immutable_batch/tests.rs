//! Native transaction and recovery cases for the shared immutable batch API.
//! These use the real file-backed engine and explicit live/cancelled contexts.

use super::*;
use std::future::{Future, poll_fn};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthorityFailure, AuthorityLimits, AuthorityStore,
    HeadKey, HeadRead, ImmutableBatchFailure, ImmutableBatchRefusal, ImmutableRead,
    MAX_IMMUTABLE_BATCH_BYTES, MAX_IMMUTABLE_BATCH_ITEMS, MemoryAuthorityStore, MemoryStoreConfig,
    StoreInstanceId,
};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::{BudgetClass, ClassLimits};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
const INSTANCE: StoreInstanceId = StoreInstanceId::from_raw(927);

struct Fixture {
    node: NodeRuntime,
    store: FsqliteAuthorityStore,
    cx: Cx,
    directory: PathBuf,
}

impl Fixture {
    fn new(limits: AuthorityLimits) -> Self {
        let node = RuntimeProfile::deterministic().build().expect("runtime");
        let cx = context(&node);
        let directory = std::env::temp_dir().join(format!(
            "fgit-native-immutable-batch-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("private database directory");
        let store = node
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                directory.join("authority.db").to_str().expect("UTF-8 path"),
                INSTANCE,
                limits,
            ))
            .expect("native store");
        Self {
            node,
            store,
            cx,
            directory,
        }
    }

    fn put(
        &self,
        entries: &[(ImmutableKey, Vec<u8>)],
    ) -> Result<Vec<PutOutcome>, ImmutableBatchFailure> {
        self.node.block_on(AsyncAuthorityStore::put_if_absent_batch(
            &self.store,
            &self.cx,
            entries,
        ))
    }

    fn read(&self, key: &ImmutableKey) -> ImmutableRead {
        self.node
            .block_on(self.store.read_immutable(&self.cx, key))
            .expect("live read")
    }

    fn reopen(&mut self) {
        let limits = self.store.limits();
        self.node
            .block_on(self.store.close(&self.cx))
            .expect("close");
        self.store = self
            .node
            .block_on(FsqliteAuthorityStore::open(
                &self.cx,
                self.directory
                    .join("authority.db")
                    .to_str()
                    .expect("UTF-8 path"),
                INSTANCE,
                limits,
            ))
            .expect("reopen");
    }

    fn close(mut self) {
        self.node
            .block_on(self.store.close(&self.cx))
            .expect("close");
        std::fs::remove_dir_all(&self.directory).expect("remove owned database directory");
    }
}

fn context(node: &NodeRuntime) -> Cx {
    let cx = Cx::new();
    cx.set_native_cx(node.request_cx(BudgetClass::Request));
    cx
}

fn key(value: &str) -> ImmutableKey {
    ImmutableKey::new(value.as_bytes().to_vec()).expect("bounded key")
}

fn entry(name: &str, value: &[u8]) -> (ImmutableKey, Vec<u8>) {
    (key(name), value.to_vec())
}

fn capacity(occupancy: usize, limit: usize) -> ImmutableBatchFailure {
    ImmutableBatchFailure::Interrupted {
        completed: 0,
        source: AuthorityFailure::Refused(AuthorityRefusal::CapacityExhausted { occupancy, limit }),
    }
}

fn cancelled() -> ImmutableBatchFailure {
    ImmutableBatchFailure::Interrupted {
        completed: 0,
        source: AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled),
    }
}

#[test]
fn native_batches_match_individual_reference_puts_in_input_order_and_survive_reopen() {
    let mut fixture = Fixture::new(AuthorityLimits::default());
    let reference = MemoryAuthorityStore::with_config(MemoryStoreConfig {
        instance: INSTANCE,
        ..MemoryStoreConfig::default()
    });
    let entries: Vec<_> = (0..MAX_IMMUTABLE_BATCH_ITEMS)
        .map(|index| {
            entry(
                &format!("ordered/{}", index % 13),
                if index % 5 == 0 {
                    b"different"
                } else {
                    b"original"
                },
            )
        })
        .collect();
    let reference_puts = || {
        entries
            .iter()
            .map(|(key, body)| reference.put_if_absent(key, body).expect("reference put"))
            .collect::<Vec<_>>()
    };
    let first = reference_puts();
    assert!(first.contains(&PutOutcome::Created));
    assert!(first.contains(&PutOutcome::IdenticalRetry));
    assert!(first.contains(&PutOutcome::Conflict));
    assert_eq!(fixture.put(&entries).expect("native batch"), first);
    let cached_before = fixture.store.body_cache_stats().put_hits;
    assert_eq!(
        fixture.put(&entries).expect("cached retry"),
        reference_puts()
    );
    assert_eq!(
        fixture.store.body_cache_stats().put_hits - cached_before,
        entries.len() as u64,
        "every existing key settles from committed cached bytes"
    );
    fixture.reopen();
    assert_eq!(fixture.store.body_cache_stats().entries, 0);
    assert_eq!(
        fixture.put(&entries).expect("reopened retry"),
        reference_puts()
    );
    for (key, _) in &entries {
        assert_eq!(
            fixture.read(key),
            reference.read_immutable(key).expect("reference read")
        );
    }
    let head = HeadKey::new(b"repository/main".to_vec()).expect("head key");
    assert_eq!(
        fixture
            .node
            .block_on(fixture.store.read_head(&fixture.cx, &head)),
        Ok(HeadRead::Absent),
        "staging immutable bodies never publishes a repository head"
    );
    fixture.close();
}

#[test]
fn a_full_store_answers_retries_and_conflicts_but_rolls_back_an_excess_batch() {
    let fixture = Fixture::new(AuthorityLimits {
        immutable_slots: 3,
        ..AuthorityLimits::default()
    });
    let initial = entry("initial", b"durable");
    assert_eq!(
        fixture.put(std::slice::from_ref(&initial)),
        Ok(vec![PutOutcome::Created])
    );
    let entries = vec![
        entry("a", b"a"),
        entry("b", b"b"),
        entry("a", b"a"),
        entry("a", b"different"),
        entry("one-too-many", b"no room"),
    ];
    let failure = fixture
        .put(&entries)
        .expect_err("the last new row exceeds capacity");
    assert_eq!(failure, capacity(3, 3));
    assert!(failure.proves_no_effect());
    assert!(!fixture.store.connection.in_transaction());
    assert_eq!(fixture.store.body_cache_stats().entries, 1);
    assert_eq!(
        fixture.read(&initial.0),
        ImmutableRead::Present(initial.1.clone())
    );
    for (key, _) in &entries {
        assert_eq!(
            fixture.read(key),
            ImmutableRead::Absent,
            "no staged prefix survived"
        );
    }
    assert_eq!(
        fixture.put(&entries[..4]),
        Ok(vec![
            PutOutcome::Created,
            PutOutcome::Created,
            PutOutcome::IdenticalRetry,
            PutOutcome::Conflict,
        ])
    );
    assert_eq!(
        fixture.put(&entries[..4]),
        Ok(vec![
            PutOutcome::IdenticalRetry,
            PutOutcome::IdenticalRetry,
            PutOutcome::IdenticalRetry,
            PutOutcome::Conflict,
        ]),
        "repeated keys consume no additional capacity"
    );
    fixture.close();
}

#[test]
fn capacity_is_checked_against_committed_rows_after_reopen() {
    let mut fixture = Fixture::new(AuthorityLimits {
        immutable_slots: 2,
        ..AuthorityLimits::default()
    });
    let entries = [entry("one", b"1"), entry("two", b"2")];
    assert_eq!(fixture.put(&entries), Ok(vec![PutOutcome::Created; 2]));
    fixture.reopen();
    let mixed = [entry("one", b"different"), entry("two", b"2")];
    assert_eq!(
        fixture.put(&mixed),
        Ok(vec![PutOutcome::Conflict, PutOutcome::IdenticalRetry])
    );
    assert_eq!(fixture.put(&[entry("three", b"3")]), Err(capacity(2, 2)));
    fixture.close();
}

#[test]
fn every_bound_is_preflighted_before_the_first_row_or_cache_comparison() {
    let fixture = Fixture::new(AuthorityLimits {
        body_bytes: 8,
        ..AuthorityLimits::default()
    });
    let entries = vec![entry("first", b"bounded"), entry("oversized", b"ninebytes")];
    assert_eq!(
        fixture.put(&entries),
        Err(ImmutableBatchFailure::Bounds(
            ImmutableBatchRefusal::BodyTooLarge {
                index: 1,
                observed: 9,
                limit: 8,
            }
        ))
    );
    assert_eq!(fixture.read(&entries[0].0), ImmutableRead::Absent);
    assert_eq!(fixture.put(&entries[..1]), Ok(vec![PutOutcome::Created]));
    let before = fixture.store.body_cache_stats().put_hits;
    let repeated = vec![entries[0].clone(); MAX_IMMUTABLE_BATCH_ITEMS + 1];
    assert_eq!(
        fixture.put(&repeated),
        Err(ImmutableBatchFailure::Bounds(
            ImmutableBatchRefusal::TooManyItems {
                observed: MAX_IMMUTABLE_BATCH_ITEMS + 1,
                limit: MAX_IMMUTABLE_BATCH_ITEMS,
            }
        ))
    );
    assert_eq!(fixture.store.body_cache_stats().put_hits, before);
    assert_eq!(fixture.put(&[]), Ok(Vec::new()));
    fixture.close();
}

#[test]
fn the_combined_key_and_body_boundary_accepts_exactly_one_mebibyte() {
    let fixture = Fixture::new(AuthorityLimits::default());
    let exact = (key("x"), vec![0x5a; MAX_IMMUTABLE_BATCH_BYTES - 1]);
    let excess = (key("y"), vec![0x5a; MAX_IMMUTABLE_BATCH_BYTES]);
    assert_eq!(
        fixture.put(std::slice::from_ref(&excess)),
        Err(ImmutableBatchFailure::Bounds(
            ImmutableBatchRefusal::BytesExceeded {
                observed: MAX_IMMUTABLE_BATCH_BYTES + 1,
                limit: MAX_IMMUTABLE_BATCH_BYTES,
            }
        ))
    );
    assert_eq!(fixture.read(&excess.0), ImmutableRead::Absent);
    assert_eq!(
        fixture.put(std::slice::from_ref(&exact)),
        Ok(vec![PutOutcome::Created])
    );
    assert_eq!(fixture.read(&exact.0), ImmutableRead::Present(exact.1));
    fixture.close();
}

#[test]
fn cache_hits_still_observe_local_native_and_budget_cancellation() {
    let fixture = Fixture::new(AuthorityLimits::default());
    let entries = [entry("cached", b"immutable")];
    assert_eq!(fixture.put(&entries), Ok(vec![PutOutcome::Created]));
    let before = fixture.store.body_cache_stats().put_hits;
    let local = context(&fixture.node);
    local.cancel();
    let native = context(&fixture.node);
    native
        .attached_native_cx()
        .expect("native context")
        .set_cancel_requested(true);
    let exhausted = Cx::new();
    exhausted.set_native_cx(fixture.node.request_cx_with_budget(
        ClassLimits::finite(Duration::from_secs(30), 0, 1_000_000).at(fixture.node.now()),
    ));
    for cx in [&local, &native, &exhausted] {
        assert_eq!(
            fixture
                .node
                .block_on(AsyncAuthorityStore::put_if_absent_batch(
                    &fixture.store,
                    cx,
                    &[],
                )),
            Ok(Vec::new()),
            "an empty batch admits no operation even under cancellation"
        );
        let result = fixture
            .node
            .block_on(AsyncAuthorityStore::put_if_absent_batch(
                &fixture.store,
                cx,
                &entries,
            ));
        assert_eq!(result, Err(cancelled()));
    }
    assert_eq!(fixture.store.body_cache_stats().put_hits, before);
    assert_eq!(fixture.put(&entries), Ok(vec![PutOutcome::IdenticalRetry]));
    fixture.close();
}

#[test]
fn cancelled_batch_waiters_cannot_roll_back_the_current_transaction() {
    for cancel_native in [false, true] {
        let fixture = Fixture::new(AuthorityLimits::default());
        let waiting = context(&fixture.node);
        let entries = [entry("waiting/a", b"a"), entry("waiting/b", b"b")];
        fixture.node.block_on(async {
            let mut owner = fixture.store.operation(&fixture.cx).await.expect("owner");
            fixture
                .store
                .begin(&fixture.cx, &mut owner)
                .await
                .expect("begin");
            let mut batch = Box::pin(AsyncAuthorityStore::put_if_absent_batch(
                &fixture.store,
                &waiting,
                &entries,
            ));
            poll_fn(|task| {
                assert!(batch.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            if cancel_native {
                waiting
                    .attached_native_cx()
                    .expect("native")
                    .set_cancel_requested(true);
            } else {
                waiting.cancel();
            }
            assert_eq!(batch.await, Err(cancelled()));
            assert!(fixture.store.connection.in_transaction());
            fixture
                .store
                .put_body(&fixture.cx, &key("owner"), b"retained")
                .await
                .expect("owner writes");
            fixture
                .store
                .commit(&fixture.cx, &mut owner)
                .await
                .expect("owner commits");
        });
        for (key, _) in &entries {
            assert_eq!(fixture.read(key), ImmutableRead::Absent);
        }
        assert_eq!(
            fixture.read(&key("owner")),
            ImmutableRead::Present(b"retained".to_vec())
        );
        fixture.close();
    }
}

#[test]
fn cancelled_staging_is_never_cached_and_a_live_caller_finishes_rollback() {
    let fixture = Fixture::new(AuthorityLimits::default());
    let owner = context(&fixture.node);
    let entries = [entry("cancel/a", b"a"), entry("cancel/b", b"b")];
    fixture.node.block_on(async {
        let mut lease = fixture.store.operation(&owner).await.expect("owner");
        fixture
            .store
            .begin(&owner, &mut lease)
            .await
            .expect("begin");
        let mut outcomes = vec![None; entries.len()];
        fixture
            .store
            .stage_batch(&owner, &entries, &mut outcomes)
            .await
            .expect("staged");
        assert_eq!(outcomes, vec![Some(PutOutcome::Created); 2]);
        assert_eq!(fixture.store.body_cache_stats().entries, 0);
        owner.cancel();
        let cause = fixture
            .store
            .commit(&owner, &mut lease)
            .await
            .expect_err("cancelled commit");
        assert_eq!(cause, EngineError::Engine(TransientClass::Cancelled));
        assert_eq!(
            fixture
                .store
                .rollback_after(&owner, &mut lease, cause.clone())
                .await,
            cause
        );
        assert!(lease.needs_recovery());
        drop(lease);
        assert_eq!(
            AsyncAuthorityStore::put_if_absent_batch(&fixture.store, &owner, &entries).await,
            Err(cancelled()),
            "a cancelled retry cannot discharge the old responsibility"
        );
    });
    for (key, _) in &entries {
        assert_eq!(fixture.read(key), ImmutableRead::Absent);
    }
    assert!(!fixture.store.connection.in_transaction());
    assert_eq!(fixture.put(&entries), Ok(vec![PutOutcome::Created; 2]));
    fixture.close();
}

#[test]
fn abandoning_a_dispatched_batch_drains_before_any_public_read() {
    let fixture = Fixture::new(AuthorityLimits::default());
    let entries: Vec<_> = (0..MAX_IMMUTABLE_BATCH_ITEMS)
        .map(|i| entry(&format!("abandoned/{i}"), b"not committed"))
        .collect();
    fixture.node.block_on(async {
        let mut lease = fixture.store.operation(&fixture.cx).await.expect("owner");
        fixture
            .store
            .begin(&fixture.cx, &mut lease)
            .await
            .expect("begin");
        // The helper owns every row operation but never COMMIT. Abandon its
        // first dispatched await without pretending that Drop completed abort.
        let mut outcomes = vec![None; entries.len()];
        let mut staging = Box::pin(
            fixture
                .store
                .stage_batch(&fixture.cx, &entries, &mut outcomes),
        );
        let _first = poll_fn(|task| Poll::Ready(staging.as_mut().poll(task))).await;
        drop(staging);
        assert!(lease.needs_recovery());
        assert_eq!(fixture.store.body_cache_stats().entries, 0);
        drop(lease);
    });
    for (key, _) in &entries {
        assert_eq!(fixture.read(key), ImmutableRead::Absent);
    }
    assert!(!fixture.store.connection.in_transaction());
    assert_eq!(
        fixture.put(&entries),
        Ok(vec![PutOutcome::Created; entries.len()])
    );
    fixture.close();
}

#[test]
fn concurrent_batches_hold_one_connection_lease_for_the_entire_group() {
    let fixture = Fixture::new(AuthorityLimits::default());
    let other = context(&fixture.node);
    let left = [entry("shared", b"left"), entry("only/left", b"left")];
    let right = [entry("shared", b"right"), entry("only/right", b"right")];
    let (left_result, right_result) = fixture.node.block_on(async {
        let owner = fixture
            .store
            .operation(&fixture.cx)
            .await
            .expect("hold gate");
        let mut left = std::pin::pin!(AsyncAuthorityStore::put_if_absent_batch(
            &fixture.store,
            &fixture.cx,
            &left
        ));
        let mut right = std::pin::pin!(AsyncAuthorityStore::put_if_absent_batch(
            &fixture.store,
            &other,
            &right
        ));
        poll_fn(|task| {
            assert!(left.as_mut().poll(task).is_pending());
            assert!(right.as_mut().poll(task).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(owner);
        let mut results = (None, None);
        poll_fn(|task| {
            if results.0.is_none()
                && let Poll::Ready(result) = left.as_mut().poll(task)
            {
                results.0 = Some(result);
            }
            if results.1.is_none()
                && let Poll::Ready(result) = right.as_mut().poll(task)
            {
                results.1 = Some(result);
            }
            if let (Some(_), Some(_)) = &results {
                Poll::Ready((
                    results.0.take().expect("left"),
                    results.1.take().expect("right"),
                ))
            } else {
                Poll::Pending
            }
        })
        .await
    });
    let left_result = left_result.expect("left batch");
    let right_result = right_result.expect("right batch");
    assert_eq!(left_result[1], PutOutcome::Created);
    assert_eq!(right_result[1], PutOutcome::Created);
    match (left_result[0], right_result[0]) {
        (PutOutcome::Created, PutOutcome::Conflict) => {
            assert_eq!(
                fixture.read(&key("shared")),
                ImmutableRead::Present(b"left".to_vec())
            );
        }
        (PutOutcome::Conflict, PutOutcome::Created) => {
            assert_eq!(
                fixture.read(&key("shared")),
                ImmutableRead::Present(b"right".to_vec())
            );
        }
        other => panic!("exactly one immutable creator: {other:?}"),
    }
    fixture.close();
}

#[test]
fn closed_workers_cannot_answer_nonempty_batches_from_the_old_cache() {
    let mut fixture = Fixture::new(AuthorityLimits::default());
    let entries = [entry("close", b"durable")];
    assert_eq!(fixture.put(&entries), Ok(vec![PutOutcome::Created]));
    fixture
        .node
        .block_on(fixture.store.close(&fixture.cx))
        .expect("close");
    assert_eq!(fixture.store.body_cache_stats().entries, 0);
    assert!(fixture.put(&entries).is_err());
    fixture.reopen();
    assert_eq!(fixture.put(&entries), Ok(vec![PutOutcome::IdenticalRetry]));
    fixture.close();
}
