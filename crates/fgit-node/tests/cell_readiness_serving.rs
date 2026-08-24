#![forbid(unsafe_code)]
//! A serving cell labels its answers and audits its readiness.
//!
//! `frankengit-fg036a`, acceptance lines 2 and 3, at the point where they are
//! actually claimed: a **cell serving**.
//!
//! I retracted my own `batch_pending` on this bead because the mechanisms were
//! correct and tested at L0/L1 while nothing called them — a reachability grep
//! returned zero production callers. These cases exist so that stops being
//! true: every assertion below goes through `OneNode`'s public API, so a
//! regression that unwired the gate would fail here rather than pass quietly.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_node::{LabelledReadRefusal, NodeConfig, OneNode};
use fgit_types::cell::{
    CellRefusal, CellState, CellTransitionCause, ReadLabel, ReadMode, StalenessBound,
    StalenessObservation,
};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{RepositoryId, TenantId};
use fgit_wire::WireLimits;
use fgit_wire::visibility::RefVisibility;

use core::time::Duration;

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-fg036a-serving-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x11; 16]),
        RepositoryId::from_bytes([0x22; 16]),
    )
}

fn node(scratch: &ScratchDirectory) -> OneNode {
    OneNode::init(config(scratch.0.clone()))
        .expect("the cell initializes")
        .0
}

fn bounded_stale() -> ReadLabel {
    ReadLabel::bounded_stale(
        StalenessBound::new(Duration::from_secs(30), 5),
        StalenessObservation::new(Duration::from_secs(3), 1),
    )
    .expect("inside the bound")
}

#[test]
fn a_fresh_cell_is_bootstrapping_and_serves_nothing() {
    let scratch = ScratchDirectory::new();
    let cell = node(&scratch);
    assert_eq!(cell.cell_state(), CellState::Bootstrapping);
    assert_eq!(cell.readiness_audit(), []);
    assert!(
        !cell.cell_state().admits_current_read(),
        "a cell that has only just opened must not already be serving reads"
    );
    cell.shutdown().expect("closes to quiescence");
}

#[test]
fn a_transition_is_audited_and_an_illegal_one_leaves_no_trace() {
    let scratch = ScratchDirectory::new();
    let mut cell = node(&scratch);

    let refusal = cell
        .transition_cell_state(
            CellState::Serving,
            CellTransitionCause::Operator,
            HeadGeneration::FIRST,
        )
        .expect_err("a cell may not begin serving straight out of bootstrap");
    assert!(matches!(
        refusal,
        CellRefusal::IllegalTransition {
            from: CellState::Bootstrapping,
            to: CellState::Serving
        }
    ));
    assert_eq!(
        cell.readiness_audit(),
        [],
        "a refused transition must not appear in the audit"
    );

    let entry = *cell
        .transition_cell_state(
            CellState::VerifiedReadOnly,
            CellTransitionCause::AuthorityObservation,
            HeadGeneration::FIRST,
        )
        .expect("the legal first hop");
    assert_eq!(entry.from(), CellState::Bootstrapping);
    assert_eq!(entry.to(), CellState::VerifiedReadOnly);
    assert_eq!(entry.cause(), CellTransitionCause::AuthorityObservation);
    assert_eq!(cell.readiness_audit().len(), 1);
    assert_eq!(cell.cell_state(), CellState::VerifiedReadOnly);

    cell.shutdown().expect("closes to quiescence");
}

#[test]
fn the_cells_state_gates_which_read_modes_it_will_serve() {
    // Line 3's vocabulary made load-bearing on the serving path: a state that
    // admits no current read must refuse one rather than produce a
    // fresh-looking answer it cannot back.
    let scratch = ScratchDirectory::new();
    let mut cell = node(&scratch);
    let limits = WireLimits::default();
    let visibility = RefVisibility::new();

    cell.transition_cell_state(
        CellState::VerifiedReadOnly,
        CellTransitionCause::AuthorityObservation,
        HeadGeneration::FIRST,
    )
    .expect("legal");
    cell.transition_cell_state(
        CellState::DegradedRead,
        CellTransitionCause::LocalHealth,
        HeadGeneration::FIRST,
    )
    .expect("legal");

    let refusal = cell
        .runtime()
        .block_on(cell.labelled_advertisement_in(
            &cell.request_context(),
            &visibility,
            &limits,
            ReadLabel::current(),
        ))
        .expect_err("a degraded cell cannot claim currentness");
    assert!(matches!(refusal, LabelledReadRefusal::State(_)));

    // The permitted twin at the same state: bounded-stale IS admitted here,
    // which is the whole reason DegradedRead exists. Without this the refusal
    // above is equally satisfied by a cell that serves nothing.
    let served = cell
        .runtime()
        .block_on(cell.labelled_advertisement_in(
            &cell.request_context(),
            &visibility,
            &limits,
            bounded_stale(),
        ))
        .expect("a degraded cell may serve within an explicit bound");
    assert!(matches!(served.label().mode(), ReadMode::BoundedStale(_)));

    cell.shutdown().expect("closes to quiescence");
}

#[test]
fn a_served_answer_carries_its_label_and_the_exact_bound() {
    // Line 2, at the serving boundary rather than in isolation.
    let scratch = ScratchDirectory::new();
    let mut cell = node(&scratch);
    cell.transition_cell_state(
        CellState::VerifiedReadOnly,
        CellTransitionCause::AuthorityObservation,
        HeadGeneration::FIRST,
    )
    .expect("legal");

    let served = cell
        .runtime()
        .block_on(cell.labelled_advertisement_in(
            &cell.request_context(),
            &RefVisibility::new(),
            &WireLimits::default(),
            bounded_stale(),
        ))
        .expect("serves");

    let ReadMode::BoundedStale(bound) = served.label().mode() else {
        panic!("the label must survive the serving path");
    };
    assert_eq!(bound.max_age(), Duration::from_secs(30));
    assert_eq!(bound.max_generation_lag(), 5);
    let observed = served
        .label()
        .observed()
        .expect("a measurement travels too");
    assert_eq!(observed.age(), Duration::from_secs(3));
    assert_eq!(observed.generation_lag(), 1);
    assert!(
        !served.label().mode().claims_currentness(),
        "a bounded-stale answer must not claim to be current"
    );

    cell.shutdown().expect("closes to quiescence");
}

#[test]
fn a_current_read_is_served_once_the_cell_admits_one() {
    // The permitted twin for the state gate, at the other end: the same call
    // that refused under DegradedRead succeeds under VerifiedReadOnly.
    let scratch = ScratchDirectory::new();
    let mut cell = node(&scratch);
    cell.transition_cell_state(
        CellState::VerifiedReadOnly,
        CellTransitionCause::AuthorityObservation,
        HeadGeneration::FIRST,
    )
    .expect("legal");

    let served = cell
        .runtime()
        .block_on(cell.labelled_advertisement_in(
            &cell.request_context(),
            &RefVisibility::new(),
            &WireLimits::default(),
            ReadLabel::current(),
        ))
        .expect("a verified-read-only cell serves a current read");
    assert_eq!(served.label().mode(), ReadMode::Current);
    assert!(served.label().observed().is_none());

    cell.shutdown().expect("closes to quiescence");
}
