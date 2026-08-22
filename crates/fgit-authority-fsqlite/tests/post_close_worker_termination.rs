#![forbid(unsafe_code)]
//! FG-005 bullet 4: the residual half of "zero DB workers", proved by
//! termination rather than by counting.
//!
//! # The gap this closes
//!
//! The epic's bullet 4 asks that explicit close/join leave *"zero DB workers,
//! threads, descriptors, transactions, reservations, or ambiguous effects"*.
//! `process_quiescence.rs` measures **threads** against a real process and says
//! plainly what that does not reach:
//!
//! > Not proved: that *no* worker survives its store. A runtime that pools a
//! > thread and reuses it shows the same flat count whether or not any
//! > individual store was drained.
//!
//! That limitation is real and it is a property of *counting*: a pooled thread
//! is shared, so a per-store claim cannot be read off a process-global tally.
//! The residual was recorded as blocked on the worker exposing its identity,
//! which `frankengit-0kqi` records as unwired.
//!
//! # Why counting is not the only route
//!
//! The acceptance says **workers**, not threads, and a worker already has an
//! identity: its handle. `AsyncConnection::close` (fsqlite 0.1.13,
//! `async_api.rs:599`) is documented *"The worker task is joined before
//! returning"* and does exactly that — it takes `self.worker` and calls
//! `join_worker_task(handle)`, which is `handle.wait()`. That is a per-handle
//! join, so it is per-store by construction and is indifferent to whether the
//! underlying thread is pooled.
//!
//! `FsqliteAuthorityStore::close` delegates to it, and this crate declares no
//! `Drop` at all, so the explicit path is the only shutdown there is.
//!
//! # What this file adds
//!
//! The structural argument above is upstream's contract, and a test that only
//! restated it would be checking a doc comment. What is observable *here* is the
//! consequence: upstream also documents that after `close`, *"all subsequent
//! operations will return an error"*. So a store that still serves a read after
//! an awaited close would mean the close did not do what it claims.
//!
//! The probe runs **the same read, with the same arguments, on both sides of the
//! close**, so the only difference between the two calls is the close itself. A
//! failure that would have happened anyway — a missing head, a bad key — fails
//! the presence half first and cannot be mistaken for termination.
//!
//! # Non-claims
//!
//! * This does **not** count workers, and it does not supersede
//!   `process_quiescence.rs`. Threads and workers are different resources and
//!   both members of the bullet want evidence; that file measures one, this
//!   measures the other.
//! * It proves *this* store's worker was joined before `close` returned. It says
//!   nothing about workers belonging to other stores, or about a pool's own
//!   threads outliving every store, which is legitimate and is not what
//!   "zero DB workers" forbids.
//! * The join itself is upstream's code. What is asserted here is the
//!   observable behaviour that would be false if the join had not happened.

use fgit_authority::{AuthorityLimits, HeadGeneration, HeadKey, HeadRead, StoreInstanceId};
use fgit_authority_fsqlite::{EngineError, FsqliteAuthorityStore, TransientClass};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx as FsqliteCx;

/// A self-removing database path, so a failing run cannot leak a file into the
/// next one and make it pass on stale state.
struct Scratch {
    path: std::path::PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("fgit-fg005-{}-{label}.db", std::process::id()));
        let scratch = Self { path };
        scratch.remove();
        scratch
    }

    fn as_str(&self) -> &str {
        self.path.to_str().expect("a temp path is valid UTF-8")
    }

    fn remove(&self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut sidecar = self.path.clone().into_os_string();
            sidecar.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(sidecar));
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.remove();
    }
}

fn node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

fn head_key() -> HeadKey {
    HeadKey::new(b"refs/heads/main".to_vec()).expect("a short key is admissible")
}

/// Opens a file-backed store with one initialized head.
fn open_store(node: &NodeRuntime, path: &str) -> (FsqliteCx, FsqliteAuthorityStore) {
    let native = node.request_cx(BudgetClass::Request);
    let cx = FsqliteCx::new();
    cx.set_native_cx(native);
    let store = node
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            path.to_owned(),
            StoreInstanceId::from_raw(1),
            AuthorityLimits::default(),
        ))
        .expect("a file-backed store opens");

    let generation = HeadGeneration::try_new(1).expect("a small generation is admissible");
    node.block_on(store.initialize_head(&cx, &head_key(), generation, b"genesis"))
        .expect("the head is created");

    (cx, store)
}

/// An awaited `close` terminates this store's worker, shown by the store
/// refusing the very read it served moments before.
#[test]
fn a_closed_store_refuses_the_read_it_served_before_the_close() {
    let node = node();
    let scratch = Scratch::new("post-close");
    let (cx, mut store) = open_store(&node, scratch.as_str());
    let key = head_key();

    // PRESENCE. The identical call must succeed while the worker is alive,
    // otherwise the post-close failure below proves nothing: a read that was
    // always going to fail would give the same red as a terminated worker.
    let before = node
        .block_on(store.read_head(&cx, &key))
        .expect("an open store serves a head read");
    assert!(
        matches!(before, HeadRead::Present(_)),
        "the presence half must observe a real head, not an absent one, or the \
         probe is not exercising a working store"
    );

    node.block_on(store.close(&cx))
        .expect("an explicit close of a healthy store succeeds");

    // The SAME read, same key, same store. The close is the only difference.
    let after = node.block_on(store.read_head(&cx, &key));

    let Err(error) = after else {
        panic!(
            "a closed store served a head read, so `close` returned without \
             terminating the worker it claims to join"
        );
    };

    // Bound to the exact classification rather than accepting any error, for two
    // reasons. A marshalling or contract refusal would mean the read failed for
    // a reason unrelated to the connection being gone, and would not evidence
    // termination at all.
    //
    // And the class itself carries a safety property worth pinning: upstream
    // reports a closed connection as `FrankenError::Internal`, which this
    // crate's classifier sends to the catch-all, `TransientClass::Permanent`. If
    // it ever classified as retryable instead, `run_with_retry` would spin on a
    // store that can never answer — a closed connection is exactly the case
    // where retrying is unbounded and useless.
    assert!(
        matches!(error, EngineError::Engine(TransientClass::Permanent)),
        "a post-close read failed with {error:?}. Either it broke for a reason \
         unrelated to the connection being gone, or a closed connection now \
         classifies as retryable — and retrying a closed store never terminates"
    );
}

/// Closing twice is not an error, and the second close cannot re-join a worker
/// that is already gone.
///
/// This is the near-identical permitted case for the probe above (§16.3): it
/// shows `close` is idempotent rather than a one-shot that happens to fail
/// loudly the second time, so the refusal above is attributable to the
/// connection being closed and not to `close` having poisoned the store.
#[test]
fn closing_an_already_closed_store_is_not_an_error() {
    let node = node();
    let scratch = Scratch::new("double-close");
    let (cx, mut store) = open_store(&node, scratch.as_str());

    node.block_on(store.close(&cx))
        .expect("the first close succeeds");
    node.block_on(store.close(&cx))
        .expect("a second close is a no-op, not a failure");
}
