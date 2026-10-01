//! The immutable-body cache answers repeated reads from memory and never
//! changes what a read returns (x2mv.4.7 S0b).
//!
//! Two stores open the same file, as a CLI and a server would. Each has its own
//! cache, so a body one of them writes is new to the other. Every permitted
//! case has a near-identical twin that must not be served from memory.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use fgit_authority::{AuthorityLimits, ImmutableKey, ImmutableRead, PutOutcome, StoreInstanceId};
use fgit_authority_fsqlite::{BodyCacheStats, FsqliteAuthorityStore};
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite_types::cx::Cx as FsqliteCx;

/// A database path that removes itself, sidecars included.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("fgit-body-cache-{}-{label}.db", std::process::id()));
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
            let _ = std::fs::remove_file(PathBuf::from(sidecar));
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.remove();
    }
}

struct Harness {
    node: NodeRuntime,
    cx: FsqliteCx,
}

impl Harness {
    fn new() -> Self {
        let node = RuntimeProfile::deterministic()
            .build()
            .expect("the deterministic profile builds");
        let cx = FsqliteCx::new();
        cx.set_native_cx(node.request_cx(BudgetClass::Request));
        Self { node, cx }
    }

    fn open(&self, scratch: &Scratch, instance: u64) -> FsqliteAuthorityStore {
        self.node
            .block_on(FsqliteAuthorityStore::open(
                &self.cx,
                scratch.as_str().to_owned(),
                StoreInstanceId::from_raw(instance),
                AuthorityLimits::default(),
            ))
            .expect("a file-backed store opens")
    }

    fn put(&self, store: &FsqliteAuthorityStore, key: &ImmutableKey, body: &[u8]) -> PutOutcome {
        self.node
            .block_on(store.put_if_absent(&self.cx, key, body))
            .expect("put_if_absent answers")
    }

    fn read(&self, store: &FsqliteAuthorityStore, key: &ImmutableKey) -> ImmutableRead {
        self.node
            .block_on(store.read_immutable(&self.cx, key))
            .expect("read_immutable answers")
    }

    fn close(&self, mut store: FsqliteAuthorityStore) {
        self.node.block_on(store.close(&self.cx)).expect("the store closes");
    }
}

fn key(bytes: &[u8]) -> ImmutableKey {
    ImmutableKey::new(bytes.to_vec()).expect("a short key is valid")
}

fn present(bytes: &[u8]) -> ImmutableRead {
    ImmutableRead::Present(bytes.to_vec())
}

fn counts(stats: BodyCacheStats) -> (u64, u64, usize) {
    (stats.hits, stats.misses, stats.entries)
}

#[test]
fn a_body_this_store_wrote_is_read_back_from_memory() {
    let harness = Harness::new();
    let scratch = Scratch::new("own-write");
    let store = harness.open(&scratch, 1);
    let k = key(b"body/own");
    assert_eq!(harness.put(&store, &k, b"bytes one"), PutOutcome::Created);
    assert_eq!(harness.read(&store, &k), present(b"bytes one"));
    assert_eq!(harness.read(&store, &k), present(b"bytes one"));
    // Both reads were hits: the accepted write recorded the bytes.
    assert_eq!(counts(store.body_cache_stats()), (2, 0, 1));
    harness.close(store);
}

#[test]
fn a_body_another_store_wrote_is_read_from_disk_once_then_from_memory() {
    let harness = Harness::new();
    let scratch = Scratch::new("other-write");
    let writer = harness.open(&scratch, 1);
    let reader = harness.open(&scratch, 1);
    let k = key(b"body/other");
    assert_eq!(harness.put(&writer, &k, b"written elsewhere"), PutOutcome::Created);
    assert_eq!(harness.read(&reader, &k), present(b"written elsewhere"));
    assert_eq!(counts(reader.body_cache_stats()), (0, 1, 1), "the first read went to the engine");
    assert_eq!(harness.read(&reader, &k), present(b"written elsewhere"));
    assert_eq!(counts(reader.body_cache_stats()), (1, 1, 1), "the second read was a hit");
    harness.close(reader);
    harness.close(writer);
}

#[test]
fn an_absent_read_is_never_cached_so_a_later_write_is_seen() {
    let harness = Harness::new();
    let scratch = Scratch::new("absent");
    let reader = harness.open(&scratch, 1);
    let writer = harness.open(&scratch, 1);
    let k = key(b"body/late");
    assert_eq!(harness.read(&reader, &k), ImmutableRead::Absent);
    assert_eq!(counts(reader.body_cache_stats()), (0, 1, 0), "absence retained nothing");
    assert_eq!(harness.put(&writer, &k, b"arrived later"), PutOutcome::Created);
    assert_eq!(harness.read(&reader, &k), present(b"arrived later"));
    harness.close(writer);
    harness.close(reader);
}

#[test]
fn a_refused_conflicting_write_never_enters_the_cache() {
    let harness = Harness::new();
    let scratch = Scratch::new("conflict");
    let first = harness.open(&scratch, 1);
    let second = harness.open(&scratch, 1);
    let k = key(b"body/conflict");
    assert_eq!(harness.put(&first, &k, b"the stored bytes"), PutOutcome::Created);
    assert_eq!(harness.put(&second, &k, b"different bytes"), PutOutcome::Conflict);
    assert_eq!(counts(second.body_cache_stats()).2, 0, "the refused bytes were not recorded");
    // The second store reads the stored bytes from the engine, not its own attempt.
    assert_eq!(harness.read(&second, &k), present(b"the stored bytes"));
    // Its twin: an identical retry is accepted and recorded.
    assert_eq!(harness.put(&second, &k, b"the stored bytes"), PutOutcome::IdenticalRetry);
    assert_eq!(harness.read(&second, &k), present(b"the stored bytes"));
    harness.close(second);
    harness.close(first);
}
