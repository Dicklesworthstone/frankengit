//! FG-005 / `frankengit-6cs9`: does close/join actually release the worker?
//!
//! The epic's acceptance says explicit close/join leaves *"zero DB workers,
//! threads, descriptors, transactions, reservations, or ambiguous effects"*.
//! Descriptors were the only member of that comma-joined list measured against
//! a real process — `crash_equivalence.rs` reads `/proc/self/fd`. The rest were
//! modelled, and `frankengit-0kqi` records that the model is wired to nothing.
//! This file adds threads.
//!
//! # Why this is its own test binary
//!
//! `/proc/self/task` and `/proc/self/fd` describe the **whole process**, and
//! `cargo test` runs the tests of one file concurrently in one binary. A probe
//! that samples a process-global counter is therefore measuring every other
//! test that happens to be running.
//!
//! That is not hypothetical, and it is why these tests moved here. Written
//! first inside `crash_equivalence.rs`, the instrumented run reported
//! `baseline=16 after=8` across eight open/close cycles: **the thread count
//! went down**, because other tests' runtimes were winding up and down around
//! it. The bound passed for a reason unrelated to leaking. Adding a mutex
//! shared by the probes was not enough either — it serialises the probes
//! against each other but not against the twenty other tests in that binary,
//! and the release assertion still failed roughly one run in five.
//!
//! Each `tests/*.rs` compiles to its own binary, so the probes here contend
//! only with each other, and the lock below settles that. **A signal that noise
//! can swamp is not a signal**; the fix is isolation, not a wider tolerance,
//! because widening until green is how a leak detector stops detecting.
//!
//! # What is proved, and what is not
//!
//! Proved: holding N stores open raises the live thread count by about N, and
//! closing them gives it back. So `close()` releases per-store workers.
//!
//! **Not** proved: that *no* worker survives its store. A runtime that pools a
//! thread and reuses it shows the same flat count whether or not any individual
//! store was drained, so "released" here means "not retained per store", which
//! is weaker than the acceptance's "zero DB workers". Distinguishing them needs
//! the worker to expose its own identity, which `frankengit-0kqi` records as
//! unwired. Stated rather than glossed, because that gap is the whole
//! difficulty of this bead.
//!
//! # Lane ownership
//!
//! These tests sample process-global state, so the default Cargo test path
//! only compiles them. The explicit authority e2e cell
//! `scripts/e2e/suites/authority/sqlite_crash_equivalence.sh` runs them with
//! `-- --ignored` under `FG-005B-E2E-028`, where their resource observation is
//! scheduled as quiescence evidence rather than allowed to flake unrelated
//! crate tests under swarm load. The assertion itself is unchanged there.

#![cfg(target_os = "linux")]

use fgit_authority::{AuthorityLimits, HeadGeneration, HeadKey, StoreInstanceId};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx as FsqliteCx;

/// Serialises the probes in this binary against each other.
///
/// Isolation to one binary removes the twenty unrelated tests; this removes the
/// two here from each other's samples.
static RESOURCE_PROBE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The largest post-close wait before this probe calls retained workers a leak.
///
/// `close()` has completed before the probe starts this window; the polling is
/// only for the operating system to observe a worker that is already joining.
/// The released-state bar below is unchanged. A bounded wait makes the probe
/// robust to CPU contention without converting a delayed or retained worker
/// into a success by widening its threshold.
const RELEASE_SETTLE_WINDOW: std::time::Duration = std::time::Duration::from_millis(500);
/// Polling interval inside [`RELEASE_SETTLE_WINDOW`].
const RELEASE_SETTLE_POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// Take the probe lock, ignoring poisoning: a panicking probe has already
/// failed, and poisoning the other would hide which one broke.
fn probe_guard() -> std::sync::MutexGuard<'static, ()> {
    RESOURCE_PROBE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Threads alive in this process. One `/proc/self/task` entry per thread.
fn live_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .expect("/proc/self/task is readable on linux")
        .count()
}

/// Waits only for a close that already completed to become visible in `/proc`.
///
/// The final sample is returned even when it remains above `limit`, so the
/// caller still applies the same released-state assertion and reports the
/// retained count. This helper never makes a higher retained floor acceptable.
fn settled_threads_at_most(limit: usize) -> usize {
    let deadline = std::time::Instant::now() + RELEASE_SETTLE_WINDOW;
    loop {
        let observed = live_threads();
        if observed <= limit || std::time::Instant::now() >= deadline {
            return observed;
        }
        std::thread::sleep(RELEASE_SETTLE_POLL);
    }
}

/// A self-removing database path, so a failing run cannot leak a file into the
/// next one and make it pass on stale state.
struct Scratch {
    path: std::path::PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("fgit-6cs9-{}-{label}.db", std::process::id()));
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

/// A store plus the context it was opened with, closed explicitly.
struct Held {
    cx: FsqliteCx,
    store: FsqliteAuthorityStore,
}

fn node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

fn open_store(node: &NodeRuntime, path: &str) -> Held {
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

    let key = HeadKey::new(b"refs/heads/main".to_vec()).expect("a short key is admissible");
    let generation = HeadGeneration::try_new(1).expect("a small generation is admissible");
    node.block_on(store.initialize_head(&cx, &key, generation, b"genesis"))
        .expect("the head is created");

    Held { cx, store }
}

fn close_store(node: &NodeRuntime, mut held: Held, label: &str) {
    node.block_on(held.store.close(&held.cx))
        .unwrap_or_else(|error| panic!("{label} failed to close cleanly: {error:?}"));
}

#[test]
#[ignore = "process-global quiescence probe driven by scripts/e2e/suites/authority/sqlite_crash_equivalence.sh"]
fn opening_a_store_starts_a_thread_this_metric_can_see() {
    // THE PRESENCE CASE, and the reason the release test is worth running.
    //
    // "the count came back to baseline" passes trivially against a metric that
    // never moves. If opening a store did not raise `live_threads`, the release
    // check would be measuring nothing and would stay green through any worker
    // leak at all — the shape that let five cancellation assertions pass
    // against a dead store earlier in this bead's history.
    //
    // Prove the instrument responds before trusting it to report zero.
    let _probe = probe_guard();
    let node = node();
    let scratch = Scratch::new("presence");

    let before = live_threads();
    let held = open_store(&node, scratch.as_str());
    let while_open = live_threads();

    assert!(
        while_open > before,
        "an open store must raise the observable thread count ({before} -> {while_open}); if it \
         does not, this metric cannot see the AsyncConnection worker and the release test is \
         vacuous"
    );

    close_store(&node, held, "the presence store");
}

#[test]
#[ignore = "process-global quiescence probe driven by scripts/e2e/suites/authority/sqlite_crash_equivalence.sh"]
fn closing_many_concurrent_stores_releases_every_worker_thread() {
    // Many stores at once rather than a baseline-and-cycles comparison: the
    // presence case above measures one open store as worth about +1 thread, so
    // N stores should produce a step far above the drift, and closing them
    // should give it back. A worker that is pooled rather than joined shows up
    // as a floor that never comes down.
    const STORES: usize = 8;
    let _probe = probe_guard();
    let node = node();

    // Warm-up: the first open lazily starts runtime threads that legitimately
    // outlive it, and counting those as a leak would fail this for a reason
    // that is not one.
    {
        let scratch = Scratch::new("warmup");
        let held = open_store(&node, scratch.as_str());
        close_store(&node, held, "the warm-up store");
    }

    let before = live_threads();

    let scratches: Vec<Scratch> = (0..STORES)
        .map(|index| Scratch::new(&format!("bulk-{index}")))
        .collect();
    let held: Vec<Held> = scratches
        .iter()
        .map(|scratch| open_store(&node, scratch.as_str()))
        .collect();

    let while_open = live_threads();

    for (index, store) in held.into_iter().enumerate() {
        close_store(&node, store, &format!("store {index}"));
    }

    // The rise must be real, or the fall proves nothing.
    let rose_by = while_open.saturating_sub(before);
    assert!(
        rose_by >= STORES / 2,
        "holding {STORES} stores open moved the thread count {before} -> {while_open} \
         (+{rose_by}); if opening stores does not visibly add threads, the release check below \
         is vacuous"
    );

    // And it must come back. A per-store worker that is never joined leaves the
    // count elevated by roughly `rose_by`; allowing back a quarter of the rise
    // tolerates pool retention without tolerating a per-store leak. The
    // bounded settle window does not relax that bar: it only waits for an
    // already-completed close to become observable under parallel CPU load.
    let after = settled_threads_at_most(before.saturating_add(rose_by / 4));
    let retained = after.saturating_sub(before);
    assert!(
        retained <= rose_by / 4,
        "after closing all {STORES} stores the thread count is {after}, still +{retained} over \
         the {before} it started at, having risen +{rose_by} while they were open; close/join \
         must release the workers rather than return them to a floor"
    );
}
