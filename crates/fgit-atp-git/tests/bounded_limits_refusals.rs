#![forbid(unsafe_code)]
//! The bounded-limits constructors (`frankengit-2gzj`).
//!
//! These are where every other bound in the crate comes from. A limits object
//! that admits zero is a bound that never fires, so the constructors refusing a
//! degenerate profile is what makes the downstream ceilings meaningful at all.
//!
//! Measured per variant with a both-trees grep; the crate has no suite-like
//! module in `src/`, so a `tests/` scan is sound here (checked, after
//! `fgit-authority`'s `src/suite.rs` made a covered variant look untested).
//! After `0k6d`, `78ra` and `sezr`, these were still named by no file under
//! `tests/`.
//!
//! # One variant, two unrelated types
//!
//! `InvalidExecutionLimits` is returned by **both** `PathRaceLimits::new` and
//! `PeerPenaltyPolicy::new`. Those are unrelated limit objects — a path-racing
//! width and a peer-exclusion threshold — and the variant is the only thing
//! they share. It carries **no payload distinguishing them**, so a caller
//! seeing it cannot tell which construction refused.
//!
//! That is an observation about the enum, not a defect claim; the crate may
//! well want one "your execution limits are degenerate" code. But a probe of
//! one type says nothing about the other, so
//! [`both_execution_limit_types_share_one_refusal`] drives both and records the
//! shared variant explicitly.
//!
//! # Four axes hiding in one condition
//!
//! `TransferLimits::new` refuses if **any** of its four fields is zero. A probe
//! zeroing all four — or only the first — leaves the rest unexercised, so each
//! field gets its own probe with the other three valid. `PathRaceLimits` has
//! three such ways to be wrong, and the third is the interesting one:
//! `initial_width > max_candidates` refuses even though **both fields are
//! individually non-zero**.
//!
//! # The mutation here is the complement of the usual one
//!
//! Tightening `initial_width > max_candidates` to `>=` wrongly refuses the
//! equal case. **Every refusal probe in this crate stays green**; only
//! accepted-path tests notice.
//!
//! Measured rather than predicted, and the measurement corrected my first
//! guess. I expected the permitted twin below to be the *sole* detector. In
//! fact four tests fall, and all four are accepted-path cases: this file's twin
//! and its control, plus two pre-existing probes in `path_swarm_campaign.rs`
//! whose fixtures happen to build a race with `width == candidates` and so sit
//! on the boundary incidentally.
//!
//! So the honest claim is narrower than "only this twin catches it" and the
//! general lesson is unchanged: a tightened bound is invisible to refusals and
//! visible only to something that expects success. The existing suite caught it
//! by luck of fixture choice; the twin here catches it on purpose, and says so
//! at the boundary.
//!
//! # Non-claims
//!
//! Three of the ten `AtpRefusal` variants still unnamed after `0k6d`, `78ra`
//! and `sezr`. The payload family (`PayloadLengthMismatch`,
//! `NativeObjectIdentityMismatch`, `InternalObjectKindUnsupported`), the
//! probabilistic-summary family and the peer-capability pair remain — several
//! sit behind private helpers and may not be reachable from an integration test
//! at all. Not claimed without reaching them. LEAD count, not a remaining-work
//! total.
//!
//! Nothing here modifies `crates/fgit-atp-git/src/**`.

use fgit_atp_git::{
    AtpRefusal, PathRaceLimits, PeerPenaltyPolicy, ReconstructionPipeline, TransferLimits,
};
use fgit_object_fabric::SegmentLimits;

fn limits() -> TransferLimits {
    TransferLimits::new(16, 1 << 20, 1 << 24, 4096).expect("a non-degenerate transfer profile")
}

fn segment_limits() -> SegmentLimits {
    SegmentLimits::default()
}

// ---------------------------------------------------------------------------
// The accepted cases, built first
// ---------------------------------------------------------------------------

/// Every constructor admits a non-degenerate profile.
///
/// Built and made to pass before any refusal probe. Without it, each refusal
/// below could be a constructor rejecting everything rather than the axis the
/// test is named for.
#[test]
fn non_degenerate_profiles_are_admitted() {
    TransferLimits::new(1, 1, 1, 1).expect("one of everything is the smallest legal profile");
    PathRaceLimits::new(1, 1).expect("a single-candidate race is legal");
    PeerPenaltyPolicy::new(1, 0).expect("a one-strike exclusion threshold is legal");
    ReconstructionPipeline::new(b"ns".to_vec(), segment_limits(), limits())
        .expect("a bounded namespace builds a pipeline");
}

// ---------------------------------------------------------------------------
// InvalidLimits — one condition, four axes
// ---------------------------------------------------------------------------

/// Each of the four fields, zeroed **individually** with the other three valid.
///
/// One `||` condition covers four fields. A probe zeroing all four would pass
/// against an implementation that checked only the first, and a probe zeroing
/// only the first leaves three unexercised.
#[test]
fn each_zero_field_refuses_the_transfer_limits() {
    let cases: [(&str, TransferLimits2); 4] = [
        ("max_objects", (0, 1, 1, 1)),
        ("max_payload_bytes", (1, 0, 1, 1)),
        ("max_total_reconstruction_bytes", (1, 1, 0, 1)),
        ("max_probabilistic_summary_bytes", (1, 1, 1, 0)),
    ];
    for (field, (objects, payload, reconstruction, summary)) in cases {
        let error = TransferLimits::new(objects, payload, reconstruction, summary)
            .expect_err(&format!("a zero {field} must refuse"));
        assert_eq!(
            error,
            AtpRefusal::InvalidLimits,
            "a zero {field} must refuse as invalid limits"
        );
    }
}

/// Field tuple for the four-axis table above.
type TransferLimits2 = (u32, u64, u64, usize);

// ---------------------------------------------------------------------------
// InvalidExecutionLimits — three conditions, and a second type
// ---------------------------------------------------------------------------

/// A zero candidate ceiling admits no path at all.
#[test]
fn a_zero_candidate_ceiling_is_refused() {
    let error = PathRaceLimits::new(0, 1).expect_err("a race with no candidates decides nothing");
    assert_eq!(error, AtpRefusal::InvalidExecutionLimits);
}

/// A zero initial width probes nothing.
#[test]
fn a_zero_initial_width_is_refused() {
    let error = PathRaceLimits::new(4, 0).expect_err("a race that probes nothing decides nothing");
    assert_eq!(error, AtpRefusal::InvalidExecutionLimits);
}

/// **The interesting axis**: a width wider than the candidate ceiling, where
/// *both fields are individually non-zero*.
///
/// The first two axes are degenerate-value checks; this one is a relation
/// between the fields, and a corpus that only zeroed things would never reach
/// it.
#[test]
fn an_initial_width_wider_than_the_candidate_ceiling_is_refused() {
    let error =
        PathRaceLimits::new(2, 3).expect_err("a race cannot open wider than its candidate set");
    assert_eq!(error, AtpRefusal::InvalidExecutionLimits);
}

/// **The permitted twin at the exact boundary.** The guard reads
/// `initial_width > max_candidates`, so width **equal to** the ceiling is
/// legal.
///
/// This is the probe the bead's mutation targets. Tightening `>` to `>=` leaves
/// every refusal probe in the crate green; only accepted-path tests fall. Two
/// pre-existing probes in `path_swarm_campaign.rs` fall with it, because their
/// fixtures build a race with `width == candidates` and land on this boundary
/// incidentally — this one lands on it deliberately and names why.
#[test]
fn an_initial_width_equal_to_the_candidate_ceiling_is_admitted() {
    PathRaceLimits::new(3, 3).expect("opening exactly as wide as the candidate set is legal");
    PathRaceLimits::new(3, 2).expect("opening narrower is legal too");
}

/// The **second type** returning the same variant.
///
/// `PeerPenaltyPolicy` is an unrelated limit object, and `InvalidExecutionLimits`
/// carries no payload saying which construction refused. Both are driven here so
/// the shared variant is a recorded fact rather than an assumption from having
/// probed one of them.
#[test]
fn both_execution_limit_types_share_one_refusal() {
    let race = PathRaceLimits::new(0, 1).expect_err("a degenerate race profile refuses");
    let penalty =
        PeerPenaltyPolicy::new(0, 0).expect_err("a zero exclusion threshold excludes nobody");

    assert_eq!(race, AtpRefusal::InvalidExecutionLimits);
    assert_eq!(
        penalty, race,
        "two unrelated limit types report one variant, which does not say which refused"
    );
}

// ---------------------------------------------------------------------------
// Namespace bounds — and the ordering pair
// ---------------------------------------------------------------------------

/// A namespace past the segment bound is refused.
#[test]
fn a_namespace_past_the_bound_is_refused() {
    let oversized = vec![b'n'; segment_limits().max_namespace_bytes + 1];
    let error = ReconstructionPipeline::new(oversized, segment_limits(), limits())
        .expect_err("one byte past the namespace bound must refuse");
    assert_eq!(error, AtpRefusal::NamespaceTooLarge);
}

/// **The permitted twin at the exact boundary.** The guard reads `>`, so a
/// namespace of exactly the bound is admitted.
#[test]
fn a_namespace_at_exactly_the_bound_is_admitted() {
    let at_bound = vec![b'n'; segment_limits().max_namespace_bytes];
    ReconstructionPipeline::new(at_bound, segment_limits(), limits())
        .expect("a namespace of exactly the bound must be admitted");
}

/// The empty check runs **before** the size check.
///
/// An empty namespace is also trivially within any bound, so this input
/// qualifies for one check and not the other — but with a *zero-length* bound
/// it would qualify for neither reading, which is why the ordering is asserted
/// against the empty case specifically: `EmptyNamespace`, not
/// `NamespaceTooLarge`.
#[test]
fn an_empty_namespace_outranks_the_size_check() {
    let mut tiny = segment_limits();
    tiny.max_namespace_bytes = 0;
    let error = ReconstructionPipeline::new(Vec::new(), tiny, limits())
        .expect_err("an empty namespace names nothing");
    assert_eq!(
        error,
        AtpRefusal::EmptyNamespace,
        "the empty check runs before the size comparison"
    );
}
