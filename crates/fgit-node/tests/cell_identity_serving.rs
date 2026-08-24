#![forbid(unsafe_code)]
//! A served answer says which cell produced it. `frankengit-1egm`.
//!
//! # The gap this closes
//!
//! Three cells over one authority backend authenticate byte-identical heads —
//! `multicell_hint_routing.rs` pins exactly that, and it is correct. The
//! consequence was that nothing in a served answer distinguished them. The one
//! field that looked like it did, `AuthenticatedHead`'s former
//! `authenticated_by`, carried the *store's* identity: `establish()` returns the
//! id recorded when the database was created, so every cell sharing that
//! backend reports the same one. Renamed to `verified_against` in `ef4c93e`
//! because the value was right and the name was the defect.
//!
//! So an operator auditing a multi-cell deployment — §37.3 wants readiness
//! transitions audited *per cell*, §22.5 wants a labelled answer traceable to
//! the cell that drifted — had no way to ask "which cell answered?".
//!
//! # What these cases pin
//!
//! That a `CellId` reaches a served advertisement, that two cells are
//! distinguishable in their answers while still agreeing on content, and — the
//! property that keeps this honest — that naming a cell changes nothing about
//! what it is willing to serve. Provenance is not authorization.
//!
//! Written as a new file rather than folded into the fg036a suites under
//! `GoldLotus`'s degraded-mode instruction: `fgit-node` serving belongs to
//! `BoldIbis`, who is on fg036b.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_node::{NodeConfig, OneNode};
use fgit_types::cell::{CellState, CellTransitionCause, ReadLabel, ServingCell};
use fgit_types::hint::{Hint, HintSource};
use fgit_types::identity::CellId;
use fgit_types::numeric::HeadGeneration;
use fgit_types::{RepositoryId, TenantId};
use fgit_wire::WireLimits;
use fgit_wire::visibility::RefVisibility;

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-1egm-cell-identity-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const fn cell(id: u8) -> ServingCell {
    ServingCell::identified(Hint::new(
        CellId::from_bytes([id; 16]),
        HintSource::LocalProjection,
    ))
}

/// One repository, one storage root; the caller chooses the cell identity.
fn config(root: PathBuf, serving_cell: ServingCell) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x11; 16]),
        RepositoryId::from_bytes([0x22; 16]),
    )
    .with_serving_cell(serving_cell)
}

/// Bring a cell up far enough that it is allowed to answer a current read.
fn serving(node: &mut OneNode) {
    node.transition_cell_state(
        CellState::VerifiedReadOnly,
        CellTransitionCause::Operator,
        HeadGeneration::FIRST,
    )
    .expect("a bootstrapping cell may become verified-read-only");
}

fn advertisement_cell(node: &OneNode) -> ServingCell {
    node.runtime()
        .block_on(node.labelled_advertisement_in(
            &node.request_context(),
            &RefVisibility::new(),
            &WireLimits::default(),
            ReadLabel::current(),
        ))
        .expect("a verified-read-only cell serves a current read")
        .served_by()
}

#[test]
fn a_served_answer_names_the_cell_that_produced_it() {
    let scratch = ScratchDirectory::new();
    let (mut node, _initialization) =
        OneNode::init(config(scratch.0.clone(), cell(0x0c))).expect("the cell initializes");
    serving(&mut node);

    assert_eq!(
        advertisement_cell(&node).claimed().map(|hint| *hint.peek()),
        Some(CellId::from_bytes([0x0c; 16])),
        "the identity the cell was configured with reaches the answer it serves"
    );

    node.shutdown().expect("the cell closes to quiescence");
}

#[test]
fn a_cell_that_was_never_named_serves_a_typed_unidentified_answer() {
    // The permitted twin, and the case GoldLotus's acceptance names explicitly:
    // an unset identity must be TYPED. A deployment that does not name its
    // cells is a real configuration, not a mistake, and `Unidentified` says so
    // where a bare `None` would leave a reader unable to tell that from a value
    // dropped in transit.
    let scratch = ScratchDirectory::new();
    let (mut node, _initialization) =
        OneNode::init(config(scratch.0.clone(), ServingCell::Unidentified))
            .expect("an unnamed cell initializes");
    serving(&mut node);

    assert_eq!(advertisement_cell(&node), ServingCell::Unidentified);
    assert!(!advertisement_cell(&node).is_identified());

    node.shutdown().expect("the cell closes to quiescence");
}

#[test]
fn the_default_configuration_does_not_invent_an_identity() {
    // Nothing should conjure a cell id: a fabricated identity in an audit trail
    // is worse than an absent one, because it reads as a fact.
    let scratch = ScratchDirectory::new();
    let (mut node, _initialization) = OneNode::init(NodeConfig::new(
        scratch.0.clone(),
        TenantId::from_bytes([0x11; 16]),
        RepositoryId::from_bytes([0x22; 16]),
    ))
    .expect("a default-configured cell initializes");
    serving(&mut node);

    assert_eq!(node.serving_cell(), ServingCell::Unidentified);
    assert_eq!(advertisement_cell(&node), ServingCell::Unidentified);

    node.shutdown().expect("the cell closes to quiescence");
}

#[test]
fn naming_a_cell_does_not_change_what_it_will_serve() {
    // Provenance is not authorization. If attaching an identity could widen or
    // narrow what a cell answers, a cell could name itself into a disclosure or
    // out of a refusal. Same storage root, same state, same read — only the
    // identity differs — and the served refs must match.
    let anonymous_scratch = ScratchDirectory::new();
    let (mut anonymous, _first) = OneNode::init(config(
        anonymous_scratch.0.clone(),
        ServingCell::Unidentified,
    ))
    .expect("the unnamed cell initializes");
    serving(&mut anonymous);

    let named_scratch = ScratchDirectory::new();
    let (mut named, _second) = OneNode::init(config(named_scratch.0.clone(), cell(0xff)))
        .expect("the named cell initializes");
    serving(&mut named);

    let refs_of = |node: &OneNode| {
        node.runtime()
            .block_on(node.labelled_advertisement_in(
                &node.request_context(),
                &RefVisibility::new(),
                &WireLimits::default(),
                ReadLabel::current(),
            ))
            .expect("a verified-read-only cell serves a current read")
            .refs()
            .to_vec()
    };

    assert_eq!(
        refs_of(&anonymous),
        refs_of(&named),
        "an identity must not change the answer"
    );
    assert_ne!(
        anonymous.serving_cell(),
        named.serving_cell(),
        "and the two really were configured differently, so the equality above is not vacuous"
    );

    anonymous.shutdown().expect("closes to quiescence");
    named.shutdown().expect("closes to quiescence");
}

#[test]
fn a_bootstrapping_cell_serves_nothing_named_or_not() {
    // GoldLotus's acceptance notes that Bootstrapping cells already serve
    // nothing, so the unknown-identity case cannot arise there. Pinned, because
    // "it cannot happen" is the kind of claim that stops being true quietly.
    let scratch = ScratchDirectory::new();
    let (node, _initialization) =
        OneNode::init(config(scratch.0.clone(), cell(0x0b))).expect("the cell initializes");
    assert_eq!(node.cell_state(), CellState::Bootstrapping);

    let refusal = node.runtime().block_on(node.labelled_advertisement_in(
        &node.request_context(),
        &RefVisibility::new(),
        &WireLimits::default(),
        ReadLabel::current(),
    ));
    assert!(
        refusal.is_err(),
        "a bootstrapping cell refuses the read regardless of whether it has a name"
    );

    node.shutdown().expect("the cell closes to quiescence");
}
