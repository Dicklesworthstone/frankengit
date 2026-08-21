//! FG-005c: the checkpoint-under-load cell, **exercised** rather than argued about.
//!
//! §3.5 lists checkpoint under load as one of six support-matrix scenarios, and
//! §5.2 names checkpoint a required kill/restart boundary alongside body write,
//! sync, CAS, acknowledgement and close. §5.2 also says *"Skipped, unsupported,
//! or unexercised matrix cells are terminal non-pass states"* — so this cell
//! cannot be closed by a typed non-claim, however carefully worded. Prose
//! documents a non-pass; it does not convert one into a pass. That is why this
//! file exists instead of a fourth paragraph in `NEG-022`.
//!
//! # What took four attempts
//!
//! Whether this cell was even *producible* was answered three times by reading
//! source, and all three were wrong: "only `Command::Close` checkpoints" (scanned
//! the `fsqlite` facade while the WAL lives in `fsqlite-wal`), then "checkpoints
//! happen automatically under load" (right mechanism, mode never established),
//! then "there is no WAL at all" (from `fsqlite-pager`'s `JournalMode` being
//! `#[default] Delete`, which is a *type* default at the pager layer and not the
//! mode a new file database receives).
//!
//! The third was positively enumerated over four links, every link correct, and
//! independently re-derived by a second pane before anyone doubted it —
//! **re-deriving a chain inherits the premise the chain rests on.** What settled
//! it was `PRAGMA journal_mode`, pinned by its own drill in
//! `journal_mode_probe.rs`. The store runs on WAL, so this cell is live.
//!
//! # Why this drill cannot pass vacuously
//!
//! A checkpoint drill that merely publishes, kills and reopens would assert the
//! same invariants whether or not a checkpoint ever occurred — an uninterrupted
//! run satisfies nearly everything an interrupted one does. That is the exact
//! shape that left a chronicle crash test green while testing nothing, and it
//! would be the worst instance yet here, because the property being witnessed is
//! the one under dispute.
//!
//! So the drill asserts a boundary was **crossed**, via
//! [`assert_wal_fully_backfilled`]: `PRAGMA wal_checkpoint` reports
//! `(busy, log, checkpointed)`, and the kill only counts if the log was
//! non-empty and every frame in it had reached the database file.
//!
//! # The witness this file started with was wrong, and its own pair caught it
//!
//! Draft one asserted `checkpointed > 0` and paired it with "an empty WAL
//! reports zero". **The pair failed** — a store opened and closed through the
//! awaited path still reported 13 backfilled frames. Draft two compared two
//! checkpoints back to back and asserted the second reported zero. **That
//! failed too**, identically: `(0, 93, 93)` then `(0, 93, 93)`.
//!
//! Measuring instead of assuming a third time gave the semantics:
//! `checkpointed` is *not* a per-call delta, it is how many of the frames
//! currently in the log have been backfilled — so a repeat call correctly
//! reports the same pair. Both drafts were testing a model of the return value
//! that nobody had checked.
//!
//! The discipline held even though the design didn't: **a witness for a missing
//! event is worthless until you have watched it report the event missing.**
//! Both drafts were caught by their own absence half rather than by a reviewer,
//! and the assertions were rebuilt around the measured semantics rather than
//! relaxed to fit. [`the_reported_log_scales_with_the_write_load`] is the
//! surviving discriminator: it proves the number is a measurement of this
//! store's writes and not a constant that would satisfy the drill regardless.
//!
//! # Recorded while measuring, not claimed by this drill
//!
//! `PRAGMA wal_checkpoint(TRUNCATE)` did not shrink the `-wal` file, and an
//! awaited `close()` left the log fully populated (173 frames, ~712 KB). Both
//! bear on whether the §5.4 *durable* epoch is observable at all; both are
//! recorded on `frankengit-g6s8` and `frankengit-zru1` rather than asserted
//! here, because this file's job is the kill/restart boundary.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use fgit_authority::{AuthorityLimits, ImmutableKey, ImmutableRead, StoreInstanceId};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_runtime::boot::{NodeRuntime, RuntimeProfile};
use fgit_runtime::meter::BudgetClass;
use fsqlite::{AsyncConnection, SqliteValue};
use fsqlite_types::cx::Cx as FsqliteCx;

/// A database path that removes itself, sidecars included.
///
/// A stale `-wal` would carry frames from a previous run into this one and
/// answer the backfill question for it, which is the one contamination that
/// would matter here.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("fgit-g6s8-{}-{label}.db", std::process::id()));
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

fn body_key(tag: &str) -> ImmutableKey {
    ImmutableKey::new(format!("blob/{tag}").into_bytes()).expect("admissible")
}

/// What `PRAGMA wal_checkpoint` reports: SQLite's `(busy, log, checkpointed)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointReport {
    /// Non-zero when a writer blocked the checkpoint from completing.
    busy: i64,
    /// Frames present in the WAL.
    log: i64,
    /// How many of `log`'s frames are backfilled into the database file.
    ///
    /// **Not a per-call delta.** Measured: a repeat checkpoint with nothing
    /// written between reports the identical pair. Two drafts of this file
    /// assumed otherwise and were caught by their own absence assertions.
    checkpointed: i64,
}

/// Drive a checkpoint from a **second** connection to the same database.
///
/// Deliberately not routed through [`FsqliteAuthorityStore`]: the store's closed
/// statement set is 17 named statements with no `PRAGMA`, and this drill does
/// not widen it. A second connection is also what makes the scenario
/// *checkpoint under load* rather than *checkpoint instead of load* — the store
/// stays open and keeps writing while this runs.
fn checkpoint_now(node: &NodeRuntime, path: &str) -> CheckpointReport {
    let cx = FsqliteCx::new();
    cx.set_native_cx(node.request_cx(BudgetClass::Request));

    let connection = node
        .block_on(AsyncConnection::open(&cx, path.to_owned()))
        .expect("the checkpoint connection opens");
    let rows = node
        .block_on(connection.query(&cx, "PRAGMA wal_checkpoint(PASSIVE);"))
        .expect("PRAGMA wal_checkpoint is answerable");

    let row = rows.first().expect("wal_checkpoint returns one row");
    let column = |index: usize| match row.get(index) {
        Some(SqliteValue::Integer(value)) => *value,
        other => panic!("wal_checkpoint column {index} was {other:?}, not an integer"),
    };
    let report = CheckpointReport {
        busy: column(0),
        log: column(1),
        checkpointed: column(2),
    };
    drop(connection);
    report
}

/// Require that the WAL was non-empty and fully backfilled at this instant.
///
/// # What `PRAGMA wal_checkpoint` actually reports here, measured
///
/// `(busy, log, checkpointed)` where `log` is the frames present and
/// `checkpointed` is how many of them are backfilled into the database file.
/// **`checkpointed` is not a per-call delta** — a second checkpoint with
/// nothing written between reports the identical pair, because all those frames
/// are still backfilled. A first draft of this file asserted the second call
/// would report zero, and the measurement said otherwise; the assertion was
/// rebuilt around the semantics rather than relaxed.
///
/// So this cannot be a "did *this* call do work" witness. What it can prove,
/// and what the drill needs, is that a checkpoint boundary was genuinely
/// crossed over a non-empty log: frames existed, and all of them are in the
/// database file.
fn assert_wal_fully_backfilled(report: CheckpointReport, context: &str) {
    assert_eq!(
        report.busy, 0,
        "the checkpoint was blocked by a writer ({context}); this drill needs one that \
         completed, so the load shape is wrong - re-derive it, do not relax the assertion. \
         Report: {report:?}"
    );
    assert!(
        report.log > 0,
        "THE WAL WAS EMPTY ({context}): this run crossed no checkpoint boundary and proved \
         nothing. Either the write load never reached the WAL or the journal mode is no longer \
         WAL - re-derive it, do not relax the assertion. Report: {report:?}"
    );
    assert_eq!(
        report.checkpointed,
        report.log,
        "the checkpoint left {} of {} frames un-backfilled ({context}), so the boundary this \
         drill kills at was never fully crossed. Report: {report:?}",
        report.log - report.checkpointed,
        report.log
    );
}

/// Write `count` distinct bodies through the production put path.
fn write_load(node: &NodeRuntime, store: &FsqliteAuthorityStore, cx: &FsqliteCx, tags: &[String]) {
    for tag in tags {
        node.block_on(store.put_if_absent(cx, &body_key(tag), tag.as_bytes()))
            .expect("a body write under load succeeds");
    }
}

fn tags(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{prefix}-{index:04}"))
        .collect()
}

// --------------------------------------------------------------- the drill

/// The §5.2 cell: kill/restart **at a checkpoint boundary**, under load.
///
/// The shape matters. Frames are written, a checkpoint is driven and *witnessed*
/// while the store is still open, more frames are written on top of the
/// checkpointed database, and only then is the store killed without its awaited
/// close. So the reopen crosses a boundary where part of the data lives in the
/// main database file (backfilled) and part lives in the WAL (written after) —
/// which is the state a checkpoint boundary actually produces and the reason
/// this cell is listed separately from a plain kill.
#[test]
fn a_kill_at_a_checkpoint_boundary_loses_neither_backfilled_nor_post_checkpoint_bodies() {
    let node = deterministic_node();
    let scratch = Scratch::new("boundary");

    let before = tags("before", 64);
    let after = tags("after", 16);

    let report = {
        let cx = FsqliteCx::new();
        cx.set_native_cx(node.request_cx(BudgetClass::Request));
        let store = node
            .block_on(FsqliteAuthorityStore::open(
                &cx,
                scratch.as_str().to_owned(),
                StoreInstanceId::from_raw(1),
                AuthorityLimits::default(),
            ))
            .expect("a file-backed store opens");

        // Load, so the WAL has frames worth moving.
        write_load(&node, &store, &cx, &before);

        // The boundary itself, with the store still open and live.
        let report = checkpoint_now(&node, scratch.as_str());

        // Load again, so the reopen has to reconcile backfilled pages with WAL
        // frames written after the checkpoint.
        write_load(&node, &store, &cx, &after);

        // THE KILL: abandon the store without the awaited close, exactly as the
        // crash matrix does. `store` and `cx` drop here.
        report
    };

    assert_wal_fully_backfilled(report, "the boundary drill");

    // Reopen and require every body from both sides of the boundary.
    let cx = FsqliteCx::new();
    cx.set_native_cx(node.request_cx(BudgetClass::Request));
    let mut store = node
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            scratch.as_str().to_owned(),
            StoreInstanceId::from_raw(1),
            AuthorityLimits::default(),
        ))
        .expect("the store reopens after the kill");

    for tag in before.iter().chain(after.iter()) {
        let read = node
            .block_on(store.read_immutable(&cx, &body_key(tag)))
            .expect("a reopened store answers body reads");
        match read {
            ImmutableRead::Present(bytes) => assert_eq!(
                bytes,
                tag.as_bytes(),
                "body {tag} came back with different bytes after a kill at a checkpoint boundary"
            ),
            ImmutableRead::Absent => panic!(
                "body {tag} was acknowledged before the kill and is missing after reopen. A \
                 checkpoint moves ALREADY-COMMITTED frames into the database file; it must never \
                 be able to lose one. Report: {report:?}"
            ),
        }
    }

    node.block_on(store.close(&cx)).expect("the store closes");
}

/// The discriminator: the reported log must TRACK this store's writes.
///
/// Without this, [`assert_wal_fully_backfilled`] could be satisfied by a
/// constant. A fresh store already reports a non-zero log (the schema DDL puts
/// frames there), so "greater than zero" alone proves nothing about the load —
/// which is exactly the trap the first two drafts of this file fell into from
/// the other direction.
///
/// So this pins movement rather than a threshold: a baseline taken before any
/// body is written, a strictly larger log after a load, and strictly larger
/// again after a second load. Three points, each caused by writes this test
/// made. A reading that ignored the store would have to be monotonically
/// increasing by coincidence, twice.
#[test]
fn the_reported_log_scales_with_the_write_load() {
    let node = deterministic_node();
    let scratch = Scratch::new("scales");

    let cx = FsqliteCx::new();
    cx.set_native_cx(node.request_cx(BudgetClass::Request));
    let mut store = node
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            scratch.as_str().to_owned(),
            StoreInstanceId::from_raw(2),
            AuthorityLimits::default(),
        ))
        .expect("a file-backed store opens");

    // Baseline: schema DDL only, no bodies. Deliberately NOT asserted to be
    // zero - it is not, and a draft of this file that assumed it was is the
    // reason this comment exists.
    let baseline = checkpoint_now(&node, scratch.as_str());

    write_load(&node, &store, &cx, &tags("scales-a", 40));
    let after_first = checkpoint_now(&node, scratch.as_str());

    write_load(&node, &store, &cx, &tags("scales-b", 40));
    let after_second = checkpoint_now(&node, scratch.as_str());

    assert!(
        after_first.log > baseline.log,
        "40 bodies did not grow the log at all: baseline={baseline:?} after={after_first:?}. \
         The reported number is then not measuring this store's writes, and the boundary \
         assertions resting on it are unsupported."
    );
    assert!(
        after_second.log > after_first.log,
        "a second 40 bodies did not grow the log: first={after_first:?} second={after_second:?}. \
         One increase could be incidental; two that track the load cannot be."
    );

    // And the property the drill actually leans on holds at each point.
    assert_wal_fully_backfilled(after_first, "the discriminator's first load");
    assert_wal_fully_backfilled(after_second, "the discriminator's second load");

    node.block_on(store.close(&cx)).expect("the store closes");
}
