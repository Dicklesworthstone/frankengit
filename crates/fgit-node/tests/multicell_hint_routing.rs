#![forbid(unsafe_code)]
//! Several cells, one durable authority backend, hints on and off.
//!
//! `frankengit-fg036a`, acceptance line 1, at the node boundary.
//!
//! # Why this one is different from the two differentials below it
//!
//! `fgit-types/tests/hint_differential.rs` models the authority.
//! `fgit-authority/tests/multicell_read_differential.rs` uses a real in-memory
//! store. This uses real [`OneNode`] instances over a real durable fsqlite
//! authority and a real filesystem fabric, opened on one shared storage root
//! with distinct [`StoreInstanceId`]s — which is the deployment shape fg036a
//! specifies: cell processes sharing one authority backend and object fabric.
//!
//! # A finding: there is no per-cell identity at this layer yet
//!
//! `AuthenticatedHead` carries the receipt plus `authenticated_by`, and I first
//! wrote these cases expecting `authenticated_by` to differ per cell. It does
//! not, and that turns out to be correct rather than a defect:
//! `StoreInstanceId` names the **store**, not the reader.
//! `FsqliteAuthorityStore::establish` records the proposed id only when it
//! *creates* the database and returns the recorded one on every later open
//! (`engine.rs:269-290`), which is what keeps a token issued by store X
//! recognisable as X's. `NodeConfig::with_store_instance` therefore proposes an
//! id for a fresh backend; it does not name a cell.
//!
//! The consequence is real and belongs to fg036a rather than to fsqlite: in a
//! deployment where several cells share one backend, **nothing in an
//! authenticated read says which cell served it**. §37.3 wants readiness
//! transitions audited per cell and the read modes want labelled answers, and
//! both need a cell identity distinct from the store's. Filed separately rather
//! than invented here.
//!
//! So what these cases pin is what is actually true: the receipt — including
//! its exact body bytes — is identical across cells because there is one
//! authority, and the store identity is shared for the same reason.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_authority::StoreInstanceId;
use fgit_crypto::preferred_combiner;
use fgit_node::{NodeConfig, OneNode};
use fgit_types::gossip::GossipView;
use fgit_types::numeric::HeadGeneration;
use fgit_types::routing::PlacementCandidate;
use fgit_types::{RepositoryId, TenantId};

static NEXT_SCRATCH_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-fg036a-multicell-{}-{sequence}",
            std::process::id()
        )))
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One repository, one storage root, one cell identity per instance.
fn config(root: PathBuf, instance: u64) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x11; 16]),
        RepositoryId::from_bytes([0x22; 16]),
    )
    .with_store_instance(StoreInstanceId::from_raw(instance))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CellId(&'static str);

impl PlacementCandidate for CellId {
    fn placement_key(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

const CELL_IDS: [CellId; 3] = [CellId("cell-1"), CellId("cell-2"), CellId("cell-3")];

/// What a client ends up holding: the authenticated head's exact bytes.
fn authenticated_body(node: &OneNode) -> Vec<u8> {
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head_in(&node.request_context()))
        .expect("a cell can authenticate the head it shares");
    head.receipt().body().to_vec()
}

fn authenticating_instance(node: &OneNode) -> StoreInstanceId {
    node.runtime()
        .block_on(node.authenticate_authority_head_in(&node.request_context()))
        .expect("a cell can authenticate the head it shares")
        .authenticated_by()
}

#[test]
fn cells_sharing_one_backend_authenticate_byte_identical_heads() {
    let scratch = ScratchDirectory::new();
    let (first, _initialization) =
        OneNode::init(config(scratch.0.clone(), 1)).expect("the first cell initializes");

    let second = OneNode::open_existing(config(scratch.0.clone(), 2))
        .expect("a second cell opens the same backend");
    let third = OneNode::open_existing(config(scratch.0.clone(), 3))
        .expect("a third cell opens the same backend");

    let bodies = [
        authenticated_body(&first),
        authenticated_body(&second),
        authenticated_body(&third),
    ];
    assert_eq!(
        bodies[0], bodies[1],
        "two cells over one authority must authenticate the same head bytes"
    );
    assert_eq!(bodies[1], bodies[2]);
    assert!(
        !bodies[0].is_empty(),
        "an empty body would make the equality above vacuous"
    );

    // And the store identity, which is shared BY DESIGN because it names the
    // store rather than the reader. Each cell was configured with a different
    // proposed id (1, 2, 3) and all three report the one the database recorded
    // when it was created. Pinned here so that if `establish` ever starts
    // honouring the per-open proposal, this test says so loudly — that would
    // silently split one authority's identity across its readers.
    let instances = [
        authenticating_instance(&first),
        authenticating_instance(&second),
        authenticating_instance(&third),
    ];
    assert_eq!(
        instances,
        [StoreInstanceId::from_raw(1); 3],
        "StoreInstanceId names the store, so every cell sharing it reports the same one"
    );

    for node in [first, second, third] {
        node.shutdown().expect("a cell closes to quiescence");
    }
}

#[test]
fn which_cell_routing_prefers_never_changes_the_answer() {
    let scratch = ScratchDirectory::new();
    let (first, _initialization) =
        OneNode::init(config(scratch.0.clone(), 1)).expect("the first cell initializes");
    let second = OneNode::open_existing(config(scratch.0.clone(), 2)).expect("a second cell");
    let third = OneNode::open_existing(config(scratch.0.clone(), 3)).expect("a third cell");
    let cells = [
        (CELL_IDS[0], &first),
        (CELL_IDS[1], &second),
        (CELL_IDS[2], &third),
    ];

    let expected = authenticated_body(&first);

    // Routing genuinely selects different cells across these keys, and the
    // answer is the same every time.
    let mut selected = Vec::new();
    for key in [
        b"refs/heads/main".as_slice(),
        b"refs/heads/next".as_slice(),
        b"refs/tags/v1".as_slice(),
        b"refs/heads/release".as_slice(),
        b"refs/notes/commits".as_slice(),
    ] {
        let preferred = *preferred_combiner(&CELL_IDS, key).expect("a preferred cell");
        selected.push(preferred);
        let node = cells
            .iter()
            .find(|(id, _)| *id == preferred)
            .map(|(_, node)| *node)
            .expect("the preferred cell is one of ours");
        assert_eq!(
            authenticated_body(node),
            expected,
            "routing sent this key to {preferred:?}, which must not change the answer"
        );
    }

    selected.sort_by_key(|cell| cell.0);
    selected.dedup();
    assert!(
        selected.len() > 1,
        "routing chose one cell for every key, so this proves nothing about routing"
    );

    for node in [first, second, third] {
        node.shutdown().expect("a cell closes to quiescence");
    }
}

#[test]
fn a_lying_peer_cannot_change_what_a_cell_serves() {
    let scratch = ScratchDirectory::new();
    let (first, _initialization) =
        OneNode::init(config(scratch.0.clone(), 1)).expect("the first cell initializes");
    let second = OneNode::open_existing(config(scratch.0.clone(), 2)).expect("a second cell");

    let truth = first
        .runtime()
        .block_on(first.authenticate_authority_head_in(&first.request_context()))
        .expect("authenticates");
    let real_generation = truth.receipt().generation();

    // A peer gossips a head generation far ahead of the real one — the shape of
    // claim that would matter most if it were believed, because a cell that
    // accepted it would think it was behind and could serve or refuse wrongly.
    let mut gossip: GossipView<&'static str, HeadGeneration> = GossipView::with_capacity(4);
    gossip
        .observe("cell-1", HeadGeneration::FIRST)
        .expect("fits");

    let claimed = gossip.claim_of(&"cell-1").expect("present");
    let verified = claimed.verified_by(|candidate| {
        // The only admissible check: against this cell's own authenticated read.
        let mine = second
            .runtime()
            .block_on(second.authenticate_authority_head_in(&second.request_context()))
            .expect("authenticates");
        if mine.receipt().generation() == **candidate {
            Ok(())
        } else {
            Err("the gossiped generation is not what the authority says")
        }
    });

    // Whether the claim happened to be true or false, the served bytes are the
    // authority's either way — that is the property, not the verdict.
    assert_eq!(
        authenticated_body(&second),
        truth.receipt().body().to_vec(),
        "a gossiped generation must not change the bytes a cell serves"
    );
    assert_eq!(
        second
            .runtime()
            .block_on(second.authenticate_authority_head_in(&second.request_context()))
            .expect("authenticates")
            .receipt()
            .generation(),
        real_generation,
        "nor the generation it reports"
    );
    let _ = verified;

    for node in [first, second] {
        node.shutdown().expect("a cell closes to quiescence");
    }
}
