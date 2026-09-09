//! Overlapping public authority operations on one real file-backed connection.
//! Private transaction-boundary cases live beside the connection gate; these
//! cases exercise the public surface without serializing callers in a wrapper.

use std::future::{Future, poll_fn};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;

use fgit_authority::{
    AuthorityLimits, CasOutcome, HeadGeneration, HeadInit, HeadKey, HeadRead, ImmutableKey,
    ImmutableRead, PutOutcome, StoreInstanceId,
};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    node: NodeRuntime,
    store: FsqliteAuthorityStore,
    contexts: [Cx; 2],
    directory: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let node = RuntimeProfile::deterministic().build().expect("runtime");
        let contexts = std::array::from_fn(|_| {
            let cx = Cx::new();
            cx.set_native_cx(node.request_cx(BudgetClass::Request));
            cx
        });
        let directory = std::env::temp_dir().join(format!(
            "fgit-concurrent-operations-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).expect("private test directory");
        let store = node
            .block_on(FsqliteAuthorityStore::open(
                &contexts[0],
                directory.join("authority.db").to_str().expect("UTF-8 path"),
                StoreInstanceId::from_raw(906),
                AuthorityLimits::default(),
            ))
            .expect("real file-backed authority opens");
        Self {
            node,
            store,
            contexts,
            directory,
        }
    }

    fn close(mut self) {
        self.node
            .block_on(self.store.close(&self.contexts[0]))
            .expect("worker closes");
        std::fs::remove_dir_all(&self.directory).expect("remove owned test directory");
    }
}

async fn overlap<A: Future, B: Future>(left: A, right: B) -> (A::Output, B::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut left_result = None;
    let mut right_result = None;
    let mut shared_pending = false;
    let result = poll_fn(|task| {
        if left_result.is_none()
            && let Poll::Ready(value) = left.as_mut().poll(task)
        {
            left_result = Some(value);
        }
        if right_result.is_none()
            && let Poll::Ready(value) = right.as_mut().poll(task)
        {
            right_result = Some(value);
        }
        shared_pending |= left_result.is_none() && right_result.is_none();
        if left_result.is_some() && right_result.is_some() {
            Poll::Ready((
                left_result.take().expect("left completed"),
                right_result.take().expect("right completed"),
            ))
        } else {
            Poll::Pending
        }
    })
    .await;
    assert!(shared_pending, "both actual operation futures must overlap");
    result
}

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("nonzero generation")
}

#[test]
fn concurrent_immutable_writers_keep_both_bodies_and_identical_retries() {
    let f = Fixture::new();
    let keys = [
        ImmutableKey::new(b"left".to_vec()).expect("key"),
        ImmutableKey::new(b"right".to_vec()).expect("key"),
    ];
    let (left, right) = f.node.block_on(overlap(
        f.store
            .put_if_absent(&f.contexts[0], &keys[0], b"left payload"),
        f.store
            .put_if_absent(&f.contexts[1], &keys[1], b"right payload"),
    ));
    assert_eq!(left.expect("left write"), PutOutcome::Created);
    assert_eq!(right.expect("right write"), PutOutcome::Created);
    for (index, payload) in [b"left payload".as_slice(), b"right payload".as_slice()]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            f.node
                .block_on(f.store.read_immutable(&f.contexts[index], &keys[index]))
                .expect("read"),
            ImmutableRead::Present(payload.to_vec())
        );
        assert_eq!(
            f.node
                .block_on(
                    f.store
                        .put_if_absent(&f.contexts[index], &keys[index], payload)
                )
                .expect("retry"),
            PutOutcome::IdenticalRetry
        );
    }
    f.close();
}

#[test]
fn concurrent_head_exchanges_return_one_winner_and_one_exact_predecessor_loser() {
    let f = Fixture::new();
    let key = HeadKey::new(b"head".to_vec()).expect("head key");
    let initial = match f
        .node
        .block_on(
            f.store
                .initialize_head(&f.contexts[0], &key, generation(1), b"initial"),
        )
        .expect("initialize")
    {
        HeadInit::Created(receipt) => receipt,
        other => panic!("unexpected initialization: {other:?}"),
    };
    let (left, right) = f.node.block_on(overlap(
        f.store.compare_exchange_head(
            &f.contexts[0],
            &key,
            initial.token(),
            generation(2),
            b"left",
        ),
        f.store.compare_exchange_head(
            &f.contexts[1],
            &key,
            initial.token(),
            generation(2),
            b"right",
        ),
    ));
    let winner = match (left.expect("left exchange"), right.expect("right exchange")) {
        (CasOutcome::Committed(receipt), CasOutcome::PredecessorMismatch)
        | (CasOutcome::PredecessorMismatch, CasOutcome::Committed(receipt)) => receipt,
        other => panic!("expected one committed winner and one stale loser: {other:?}"),
    };
    assert_eq!(
        f.node
            .block_on(f.store.read_head(&f.contexts[0], &key))
            .expect("canonical read"),
        HeadRead::Present(winner.clone())
    );
    f.node
        .block_on(f.store.authenticate_head_receipt(&f.contexts[1], &winner))
        .expect("winner issuance committed with head");
    assert_eq!(
        f.node
            .block_on(f.store.compare_exchange_head(
                &f.contexts[1],
                &key,
                initial.token(),
                generation(2),
                b"retry"
            ))
            .expect("loser retry"),
        CasOutcome::PredecessorMismatch
    );
    f.close();
}
