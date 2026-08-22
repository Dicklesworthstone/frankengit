#![forbid(unsafe_code)]
//! The swarm scheduler's refusals (`frankengit-sezr`).
//!
//! `SwarmPieceTracker` admits a bounded piece/peer set and hands out
//! rarest-first assignments. Every refusal below is reachable through its
//! public API — the constructor, `next_assignment`, and `record_piece_result`.
//!
//! Measured per variant with a both-trees grep; the crate has no suite-like
//! module in `src/`, so a `tests/` scan is sound here (checked, after
//! `fgit-authority`'s `src/suite.rs` made a covered variant look untested).
//!
//! # I filed this bead on a premise that was half wrong
//!
//! It claimed the cluster held *two* split misorder/duplicate pairs,
//! corroborating `fgit-atp-git`'s convention against `fgit-object-fabric`'s
//! collapse. Reading the constructor before writing showed the truth is sharper
//! and less flattering — **the same function does both, twenty lines apart**:
//!
//! ```text
//! pieces (top-level)        match pair[0].cmp(&pair[1])
//!                             Equal   -> DuplicatePiece            SPLIT
//!                             Greater -> NonCanonicalPieceOrder
//!
//! per-peer availability     if pair[0] >= pair[1]
//!                             -> NonCanonicalPeerAvailability       COLLAPSED
//! ```
//!
//! So this is not a cross-crate style difference. `fgit-atp-git` splits the
//! pair for its piece list and collapses it for each peer's availability list,
//! in one constructor. `DuplicateSwarmPeer` is a *third* thing again — a
//! duplicate over a different collection (the peers themselves), not the
//! order/duplicate pair over one list.
//!
//! Both behaviours are pinned below exactly as they are. This file does **not**
//! claim either is wrong; it makes the inconsistency a measured fact so that
//! whoever rules on the convention is ruling on evidence.
//!
//! # One variant, three sites, one of them unreachable
//!
//! `UnknownSwarmPiece` is constructed in three places. Two are reachable and
//! probed. The third, in `next_assignment`, cannot fire: the piece it looks up
//! was just selected by iterating `self.pieces`, so `get_mut` cannot return
//! `None`. Documented rather than given a manufactured fixture — that is the
//! tenth defensive arm this sweep has surfaced, and the heuristic keeps
//! holding.
//!
//! `TooManyPieces` also has **two** sites: the top-level piece list and each
//! peer's availability list. Both are probed, because a refusal reached through
//! one says nothing about the other.
//!
//! # Non-claims
//!
//! Nine of the 19 remaining unnamed `AtpRefusal` variants. The limits/inventory
//! family, the payload family and the probabilistic/peer-capability pair remain.
//! LEAD count, not a remaining-work total.
//!
//! Nothing here modifies `crates/fgit-atp-git/src/**`.

use fgit_atp_git::{
    AtpRefusal, PeerAvailability, PeerIdentity, PeerPenaltyPolicy, PieceId, PieceStatus,
    SwarmLimits, SwarmPieceTracker,
};

const EPOCH: u64 = 1;

const fn peer(tag: u8) -> PeerIdentity {
    PeerIdentity::from_bytes([tag; 32])
}

const fn piece(value: u32) -> PieceId {
    PieceId::new(value)
}

/// A permissive penalty policy, so no probe here is refused for peer penalties
/// it is not about.
fn penalty_policy() -> PeerPenaltyPolicy {
    PeerPenaltyPolicy::new(8, 0).expect("a nonzero exclusion threshold is valid")
}

/// A generous profile, so a probe about one bound is never refused by another.
fn limits() -> SwarmLimits {
    SwarmLimits::new(8, 8, 8, 0, 2, penalty_policy())
        .expect("a bounded swarm profile is admissible")
}

/// A profile whose named bound is tightened and everything else left generous.
fn limits_with(max_pieces: usize, max_peers: usize, max_in_flight: usize) -> SwarmLimits {
    SwarmLimits::new(max_pieces, max_peers, max_in_flight, 0, 2, penalty_policy())
        .expect("a bounded swarm profile is admissible")
}

fn tracker(
    limits: SwarmLimits,
    pieces: Vec<PieceId>,
    peers: Vec<PeerAvailability>,
) -> Result<SwarmPieceTracker, AtpRefusal> {
    SwarmPieceTracker::new(limits, pieces, peers)
}

/// The canonical tracker: two pieces, one peer holding both.
fn canonical() -> SwarmPieceTracker {
    tracker(
        limits(),
        vec![piece(1), piece(2)],
        vec![PeerAvailability::new(peer(1), vec![piece(1), piece(2)])],
    )
    .expect("the canonical fixture must construct")
}

fn refusal(
    limits: SwarmLimits,
    pieces: Vec<PieceId>,
    peers: Vec<PeerAvailability>,
    what: &str,
) -> AtpRefusal {
    match tracker(limits, pieces, peers) {
        Ok(_) => panic!("{what} must be refused, but the tracker was constructed"),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// The accepted paths, built first
// ---------------------------------------------------------------------------

/// A canonical tracker constructs, assigns, and records a verified result.
///
/// Built and made to pass before any refusal probe. That ordering has caught a
/// real fixture error on three of my last five beads, so it is not a formality:
/// without it, every refusal below could be attributable to a malformed fixture
/// rather than to the guard it names.
#[test]
fn a_canonical_tracker_assigns_and_records_a_result() {
    let mut tracker = canonical();
    let assignment = tracker
        .next_assignment(EPOCH)
        .expect("a canonical tracker schedules")
        .expect("a piece is available to assign");
    assert_eq!(tracker.in_flight_assignments(), 1);

    tracker
        .record_piece_result(assignment.piece, assignment.peer, true, EPOCH)
        .expect("a verified result for an assigned piece is recorded");
    assert_eq!(
        tracker.status(assignment.piece),
        Some(PieceStatus::Verified)
    );
    assert_eq!(tracker.in_flight_assignments(), 0);
}

// ---------------------------------------------------------------------------
// The piece list SPLITS its order and duplicate faults
// ---------------------------------------------------------------------------

/// A misordered piece list and a duplicated one report **different** refusals.
///
/// The guard is a three-arm `match` on `cmp`, and both arms refuse — so a test
/// asserting only that construction failed would pass against a version that
/// merged them. That merge is exactly the lint hazard `0k6d` guarded against
/// with a load-bearing comment at the equivalent `TransferManifest` match.
#[test]
fn a_misordered_piece_list_and_a_duplicated_one_are_different_faults() {
    let misordered = refusal(
        limits(),
        vec![piece(2), piece(1)],
        Vec::new(),
        "a decreasing piece list",
    );
    let duplicated = refusal(
        limits(),
        vec![piece(1), piece(1)],
        Vec::new(),
        "a repeated piece",
    );

    assert_eq!(misordered, AtpRefusal::NonCanonicalPieceOrder);
    assert_eq!(duplicated, AtpRefusal::DuplicatePiece { piece: piece(1) });
    assert_ne!(
        misordered, duplicated,
        "the piece list distinguishes a misorder from a duplicate"
    );
}

// ---------------------------------------------------------------------------
// Per-peer availability COLLAPSES them — the same constructor, twenty lines on
// ---------------------------------------------------------------------------

/// A misordered availability list and a duplicated one report the **same**
/// refusal.
///
/// This is the collapse, and it sits in the same constructor as the split
/// above. `pair[0] >= pair[1]` cannot tell "out of order" from "repeated", so
/// one variant serves both — the convention `fgit-object-fabric` uses
/// throughout and the opposite of what the piece list does here.
///
/// Recorded, not judged. A future split would change this assertion on purpose.
#[test]
fn a_misordered_and_a_duplicated_availability_list_collapse_to_one_refusal() {
    let misordered = refusal(
        limits(),
        vec![piece(1), piece(2)],
        vec![PeerAvailability::new(peer(1), vec![piece(2), piece(1)])],
        "a decreasing availability list",
    );
    let duplicated = refusal(
        limits(),
        vec![piece(1), piece(2)],
        vec![PeerAvailability::new(peer(1), vec![piece(1), piece(1)])],
        "a repeated piece in an availability list",
    );

    assert_eq!(misordered, AtpRefusal::NonCanonicalPeerAvailability);
    assert_eq!(
        duplicated, misordered,
        "availability collapses the two faults the piece list keeps apart"
    );
}

/// `DuplicateSwarmPeer` is a third thing again: a duplicate over the *peers*,
/// not an order fault within one peer's list.
#[test]
fn two_entries_for_one_peer_are_refused() {
    let error = refusal(
        limits(),
        vec![piece(1)],
        vec![
            PeerAvailability::new(peer(1), vec![piece(1)]),
            PeerAvailability::new(peer(1), vec![piece(1)]),
        ],
        "one peer listed twice",
    );
    assert_eq!(error, AtpRefusal::DuplicateSwarmPeer { peer: peer(1) });
}

// ---------------------------------------------------------------------------
// Bounds — TooManyPieces has two sites
// ---------------------------------------------------------------------------

/// Site 1: the top-level piece list past its bound.
#[test]
fn a_piece_list_past_the_bound_is_refused() {
    let error = refusal(
        limits_with(2, 8, 8),
        vec![piece(1), piece(2), piece(3)],
        Vec::new(),
        "three pieces against a bound of two",
    );
    assert_eq!(
        error,
        AtpRefusal::TooManyPieces {
            offered: 3,
            maximum: 2
        }
    );
}

/// Site 2: **a peer's availability list** past the same bound.
///
/// Probed separately because a refusal reached through the top-level list says
/// nothing about the per-peer one — they are different call sites of one
/// variant, and the second is checked after the peer has already been accepted.
#[test]
fn a_peer_availability_list_past_the_bound_is_refused() {
    let error = refusal(
        limits_with(2, 8, 8),
        vec![piece(1), piece(2)],
        vec![PeerAvailability::new(
            peer(1),
            vec![piece(1), piece(2), piece(3)],
        )],
        "a peer claiming three pieces against a bound of two",
    );
    assert_eq!(
        error,
        AtpRefusal::TooManyPieces {
            offered: 3,
            maximum: 2
        }
    );
}

#[test]
fn a_peer_list_past_the_bound_is_refused() {
    let error = refusal(
        limits_with(8, 1, 8),
        vec![piece(1)],
        vec![
            PeerAvailability::new(peer(1), vec![piece(1)]),
            PeerAvailability::new(peer(2), vec![piece(1)]),
        ],
        "two peers against a bound of one",
    );
    assert_eq!(
        error,
        AtpRefusal::TooManySwarmPeers {
            offered: 2,
            maximum: 1
        }
    );
}

/// **The permitted twins at the exact bounds.** All three guards read `>`, so
/// the bound value itself is admitted — the case a refusal-only corpus cannot
/// see.
#[test]
fn piece_and_peer_counts_at_exactly_the_bound_are_admitted() {
    tracker(
        limits_with(2, 1, 8),
        vec![piece(1), piece(2)],
        vec![PeerAvailability::new(peer(1), vec![piece(1), piece(2)])],
    )
    .expect("counts of exactly the bound must be admitted");
}

// ---------------------------------------------------------------------------
// UnknownSwarmPiece — two reachable sites, one unreachable
// ---------------------------------------------------------------------------

/// Site 1: a peer claiming a piece that is not in the swarm's set.
#[test]
fn a_peer_claiming_an_unknown_piece_is_refused() {
    let error = refusal(
        limits(),
        vec![piece(1)],
        vec![PeerAvailability::new(peer(1), vec![piece(9)])],
        "a peer claiming a piece outside the set",
    );
    assert_eq!(error, AtpRefusal::UnknownSwarmPiece { piece: piece(9) });
}

/// Site 2: a result recorded for a piece the tracker does not know.
///
/// A different call site from the constructor's, and a probe hitting only the
/// constructor leaves this one unexercised.
#[test]
fn a_result_for_an_unknown_piece_is_refused() {
    let mut tracker = canonical();
    let error = tracker
        .record_piece_result(piece(9), peer(1), true, EPOCH)
        .expect_err("a result for a piece outside the set is refused");
    assert_eq!(error, AtpRefusal::UnknownSwarmPiece { piece: piece(9) });
}

// ---------------------------------------------------------------------------
// The scheduler's own guards
// ---------------------------------------------------------------------------

/// A result for a piece this peer was never assigned is refused.
///
/// The piece is known and the peer is known; only the assignment is missing,
/// so this is attributable to the assignment ledger rather than to either
/// identity being unrecognised.
#[test]
fn a_result_from_an_unassigned_peer_is_refused() {
    let mut tracker = canonical();
    let assignment = tracker
        .next_assignment(EPOCH)
        .expect("schedules")
        .expect("a piece is available");

    let error = tracker
        .record_piece_result(assignment.piece, peer(2), true, EPOCH)
        .expect_err("a peer that was never assigned this piece cannot report on it");
    assert_eq!(
        error,
        AtpRefusal::UnassignedPieceResult {
            piece: assignment.piece,
            peer: peer(2),
        }
    );
}

/// Scheduling past the in-flight bound is refused.
///
/// The bound reads `>=`, so with a maximum of one the second call refuses while
/// the first is admitted — the permitted half is asserted in the same test so
/// the refusal is attributable to the bound rather than to the tracker
/// declining to schedule at all.
#[test]
fn scheduling_past_the_in_flight_bound_is_refused() {
    let mut tracker = tracker(
        limits_with(8, 8, 1),
        vec![piece(1), piece(2)],
        vec![PeerAvailability::new(peer(1), vec![piece(1), piece(2)])],
    )
    .expect("a tracker with a one-assignment ceiling constructs");

    tracker
        .next_assignment(EPOCH)
        .expect("the first assignment is within the bound")
        .expect("a piece is available");
    assert_eq!(tracker.in_flight_assignments(), 1);

    let error = tracker
        .next_assignment(EPOCH)
        .expect_err("a second in-flight assignment exceeds a ceiling of one");
    assert_eq!(error, AtpRefusal::InFlightPieceLimitReached { maximum: 1 });
}
