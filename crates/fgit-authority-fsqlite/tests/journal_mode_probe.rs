//! What journal mode does this store actually run on?
//!
//! This question received three different answers in one hour, all by *reading*
//! source: "only `Command::Close` checkpoints", then "checkpoints happen
//! automatically under load", then "there is no WAL at all". The first two were
//! retracted. Every one of them was an inference from code, and two of them
//! rested on not finding something.
//!
//! So this asks the database instead. `PRAGMA journal_mode` is a measurement,
//! and it settles what no amount of further reading should be asked to.
//!
//! **It answered `wal`, and all three readings were wrong** — including the
//! third, which two of us had independently "confirmed" by re-deriving its
//! chain link by link. Every link was individually correct and the conclusion
//! was not, because `fsqlite_pager::JournalMode`'s `#[default] Delete` is a
//! *type* default at the pager layer and not the mode a new file database gets.
//! The connection layer decides that, and `fsqlite` pins it in its own suite:
//!
//! * `fsqlite-core/src/connection.rs:190588`
//!   `test_pragma_journal_mode_default_is_wal_for_new_file_database`
//! * `fsqlite-core/src/connection.rs:190574`
//!   `test_pragma_journal_mode_default_is_memory_for_private_memory_database`
//!
//! So this store runs on **WAL**, checkpoint-under-load is live rather than
//! unreachable, and the `-wal`/`-shm` sidecars the scratch helper already
//! cleaned up were the tell that four readings walked past.
//!
//! # Why this is not a `PRAGMA` in the production statement set
//!
//! The engine's closed statement set is deliberately 17 named statements with
//! no `PRAGMA`, and this test does not widen it. The probe opens its own
//! connection to a database the store has already created and closed, so what
//! it reports is a property of the file our production open path produced —
//! not of a connection configured for the occasion.
//!
//! # Why file-backed and not `:memory:`
//!
//! An in-memory database has no journal file and reports its own mode, so
//! probing one would answer a different question than the one that matters.
//! `engine_conformance` uses `:memory:` for good reasons of its own; that makes
//! its journal mode unrepresentative of a deployed store, which is itself worth
//! knowing and is asserted below.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use fgit_authority::{AuthorityLimits, StoreInstanceId};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite::{AsyncConnection, SqliteValue};
use fsqlite_types::cx::Cx as FsqliteCx;

/// A database path that removes itself, sidecars included.
///
/// A stale `-wal` or `-journal` sidecar would answer this test's question for
/// it, which is the one contamination that would matter here.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("fgit-zru1-{}-{label}.db", std::process::id()));
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

fn deterministic_node() -> NodeRuntime {
    RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds")
}

/// Ask an already-created database which journal mode it is in.
fn journal_mode_of(node: &NodeRuntime, path: &str) -> String {
    let native = node.request_cx(BudgetClass::Request);
    let cx = FsqliteCx::new();
    cx.set_native_cx(native.clone());

    let connection = node
        .block_on(AsyncConnection::open(&cx, path.to_owned()))
        .expect("the probe connection opens");
    let rows = node
        .block_on(connection.query(&cx, "PRAGMA journal_mode;"))
        .expect("PRAGMA journal_mode is answerable");

    let mode = match rows.first().and_then(|row| row.get(0)) {
        Some(SqliteValue::Text(text)) => text.to_string(),
        other => panic!("PRAGMA journal_mode returned {other:?}, not one text column"),
    };
    drop(connection);
    mode
}

/// The measurement, against a database this store's own open path created.
#[test]
fn a_file_backed_store_runs_on_the_journal_mode_this_pins() {
    let node = deterministic_node();
    let scratch = Scratch::new("file");

    // Create the database exactly the way production does, then close it, so
    // the probe reads a file our open path produced rather than one shaped by
    // the probe's own connection.
    {
        let native = node.request_cx(BudgetClass::Request);
        let cx = FsqliteCx::new();
        cx.set_native_cx(native.clone());
        let mut store = node
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                scratch.as_str().to_owned(),
                StoreInstanceId::from_raw(1),
                AuthorityLimits::default(),
            ))
            .expect("a file-backed store opens");
        node.block_on(store.close(&cx)).expect("the store closes");
    }

    let mode = journal_mode_of(&node, scratch.as_str());

    assert_eq!(
        mode.to_ascii_lowercase(),
        "wal",
        "MEASURED journal mode of a store-created database. If this fails, the \
         engine's durability semantics have changed and every claim resting on \
         the mode is stale: the crash matrix, the §3.5 concurrency envelope, \
         and whether checkpoint-under-load is even producible. Do not relax \
         this assertion — re-derive what depends on it."
    );
}

/// The conformance suite's `:memory:` store is a different configuration.
///
/// Not a defect — `:memory:` is right for that suite. It is pinned because a
/// reader can otherwise carry a mode measured there over to a deployed store,
/// and the two are not the same.
#[test]
fn an_in_memory_store_does_not_share_the_file_backed_journal_mode() {
    let node = deterministic_node();
    let scratch = Scratch::new("contrast");

    {
        let native = node.request_cx(BudgetClass::Request);
        let cx = FsqliteCx::new();
        cx.set_native_cx(native.clone());
        let mut store = node
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                scratch.as_str().to_owned(),
                StoreInstanceId::from_raw(2),
                AuthorityLimits::default(),
            ))
            .expect("a file-backed store opens");
        node.block_on(store.close(&cx)).expect("the store closes");
    }

    let file_mode = journal_mode_of(&node, scratch.as_str());
    let memory_mode = journal_mode_of(&node, ":memory:");

    assert_ne!(
        file_mode.to_ascii_lowercase(),
        memory_mode.to_ascii_lowercase(),
        "if these ever agree, the contrast this test exists to draw is gone and \
         the test should be deleted rather than left asserting nothing"
    );
}
