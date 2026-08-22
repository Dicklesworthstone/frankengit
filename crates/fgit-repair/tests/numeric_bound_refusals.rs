#![forbid(unsafe_code)]
//! Three numeric-bound refusals in `fgit-repair`, each paired with the
//! permitted case at the exact boundary (`frankengit-bq4b`).
//!
//! # Why the permitted half is the half that matters
//!
//! A refusal-only test pins that a wall exists, never where it stands. Supply
//! only out-of-range values and an over-tight guard passes every assertion you
//! wrote — `>` and `>=` are indistinguishable to a test that never offers the
//! boundary value itself.
//!
//! Two of these three bounds have a boundary that **must** be accepted, and
//! accepting it is the entire point of the bound:
//!
//! - `minimum_coverage_per_mille == 1_000` is 100% coverage. The guard reads
//!   `> 1_000`, so it is admissible. Written `>=` it would be impossible to ask
//!   for full coverage, presumably the strictest setting anyone wants.
//! - `numerator == denominator` is "sample everything". The guard reads
//!   `> denominator`, so `n/n` is admissible. Written `>=` you could not scrub
//!   the whole set.
//!
//! Each refusal here also asserts the **payload**, not just the variant, so a
//! guard that fires on the right condition while reporting the wrong values is
//! still caught.
//!
//! # What this file does not decide
//!
//! [`a_health_sequence_that_repeats_is_admitted`] pins current behaviour and
//! deliberately does **not** rule on whether it is correct. See its own
//! documentation: the structurally similar guard in `fgit-resource` refuses the
//! equal case, and which reading is intended belongs to the crate owner, not to
//! a test author. The test exists so the answer is recorded either way, because
//! the next person to read the two guards side by side will otherwise assume one
//! is a typo.
//!
//! Every probe drives the public API; nothing here modifies
//! `crates/fgit-repair/src/**`.

use fgit_repair::{
    DurabilityHealth, DurableClass, HealthRecord, HealthThresholds, ScrubMode, ScrubRefusal,
};

/// Full scale for a per-mille coverage threshold: 1000 per mille is 100%.
const FULL_SCALE_PER_MILLE: u16 = 1_000;

/// A record carrying nothing but the schedule sequence under test.
///
/// `WalkCompleted` is chosen because its payload is entirely counters — the
/// sequence ordering under test is not entangled with manifest identity or an
/// observation outcome.
const fn walk_at(sequence: u64) -> HealthRecord {
    HealthRecord::WalkCompleted {
        class: DurableClass::MicrosegmentV1,
        sequence,
        checked_targets: 1,
        skipped_targets: 0,
        remaining_targets: 0,
    }
}

// ---------------------------------------------------------------------------
// HealthThresholds::new — minimum_coverage_per_mille
// ---------------------------------------------------------------------------

/// One per mille above full scale is refused, and the refusal reports the value
/// it rejected.
#[test]
fn a_coverage_threshold_above_full_scale_is_refused() {
    let refusal = HealthThresholds::new(64, FULL_SCALE_PER_MILLE + 1, 128)
        .expect_err("a coverage threshold above full scale must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::CoverageThresholdOutOfRange(FULL_SCALE_PER_MILLE + 1),
        "the refusal must name the out-of-range value it rejected"
    );
}

/// **The permitted twin, at the exact boundary.** Full coverage is admissible.
///
/// This is the case that distinguishes `>` from `>=`, and it is the one a
/// refusal-only corpus cannot see. A guard tightened to `>= 1_000` would make
/// it impossible to require 100% coverage — the strictest setting the type can
/// express — while every refusal assertion above continued to pass.
#[test]
fn a_coverage_threshold_at_exactly_full_scale_is_admitted() {
    HealthThresholds::new(64, FULL_SCALE_PER_MILLE, 128)
        .expect("requiring full coverage must be expressible");
}

/// The interior of the range is admissible, so the boundary case above is not
/// passing merely because the constructor accepts everything below some much
/// lower limit.
#[test]
fn a_coverage_threshold_inside_the_range_is_admitted() {
    HealthThresholds::new(64, FULL_SCALE_PER_MILLE / 2, 128)
        .expect("a mid-range coverage threshold must be admissible");
    HealthThresholds::new(64, 0, 128).expect("requiring no minimum coverage must be expressible");
}

// ---------------------------------------------------------------------------
// ScrubMode::sample — numerator / denominator
// ---------------------------------------------------------------------------

/// A zero denominator is refused, and by its **own** variant rather than as a
/// generic ratio complaint.
///
/// Asserted separately because the two refusals are reached by different
/// conditions: the denominator is checked before the ratio, so a test that only
/// ever supplied a zero denominator would never reach the ratio guard at all.
#[test]
fn a_zero_sample_denominator_is_refused() {
    let refusal = ScrubMode::sample(1, 0).expect_err("a zero sample denominator must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::ZeroSampleDenominator,
        "a zero denominator must refuse as itself, not as an invalid ratio"
    );
}

/// A zero numerator is refused: a sample of nothing is vacuous.
#[test]
fn a_zero_sample_numerator_is_refused() {
    let refusal = ScrubMode::sample(0, 8).expect_err("a zero numerator must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::InvalidSampleRatio {
            numerator: 0,
            denominator: 8,
        },
        "the refusal must report the ratio it rejected"
    );
}

/// One above the denominator is refused — the boundary approached from the
/// forbidden side.
#[test]
fn a_sample_numerator_above_the_denominator_is_refused() {
    let refusal = ScrubMode::sample(9, 8)
        .expect_err("a numerator larger than its denominator must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::InvalidSampleRatio {
            numerator: 9,
            denominator: 8,
        },
        "the refusal must report the ratio it rejected"
    );
}

/// **The permitted twin, at the exact boundary.** Sampling everything is
/// admissible.
///
/// `n/n` is the same one-step-inside-the-boundary case as full coverage above:
/// tightening the guard to `>=` would remove the ability to scrub the whole
/// set, and no refusal test would notice.
#[test]
fn sampling_every_target_is_admitted() {
    ScrubMode::sample(8, 8).expect("sampling every target must be expressible");
}

/// The smallest non-vacuous sample is admissible, pinning the other end of the
/// range so the boundary case above is not passing because the constructor
/// accepts any numerator at all.
#[test]
fn the_smallest_non_vacuous_sample_is_admitted() {
    ScrubMode::sample(1, 8).expect("a one-in-eight sample must be expressible");
}

// ---------------------------------------------------------------------------
// DurabilityHealth::replay — health record sequence monotonicity
// ---------------------------------------------------------------------------

/// A sequence that goes backwards is refused, reporting both the previous and
/// the observed value.
#[test]
fn a_health_sequence_that_goes_backwards_is_refused() {
    let refusal = DurabilityHealth::replay(&[walk_at(7), walk_at(6)])
        .expect_err("a health record whose sequence regresses must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::NonMonotoneHealthSequence {
            previous: 7,
            observed: 6,
        },
        "the refusal must name both the sequence it held and the one it saw"
    );
}

/// The permitted twin: an advancing sequence replays.
///
/// Without this the refusal above cannot be attributed to regression — a replay
/// that rejected every multi-record input would satisfy it just as well.
#[test]
fn a_health_sequence_that_advances_is_admitted() {
    DurabilityHealth::replay(&[walk_at(6), walk_at(7)])
        .expect("an advancing health sequence must replay");
}

/// A **repeated** sequence is admitted, and here `<` is required rather than
/// merely current.
///
/// `apply` guards with `record.sequence() < previous`, so an equal sequence
/// passes, while the structurally similar guard in `fgit-resource`'s
/// `replay_journal` uses `<=` and refuses an equal ordinal. `frankengit-bq4b`
/// raised that disagreement as an open question — whether one of them is a
/// typo — and the corpus already answers it.
///
/// `health_replay_tracks_injected_backlog_and_raises_threshold_alarm` in
/// `scrub_scheduler.rs` replays six records across two sequence values
/// (9, 9, 10, 10, 10, 10): a target is checked, found corrupt, marked suspect,
/// repaired, and the walk completes — **all within one schedule step**.
///
/// So the two guards are not inconsistent, they are about different things. A
/// `fgit-resource` ordinal is a *position*, and two records at one position are
/// a duplicate. A `fgit-repair` health sequence is a *schedule step*, and many
/// records per step is the normal case. Tightening this guard to `<=` breaks
/// that existing test, which is the evidence rather than an argument: I
/// measured it.
///
/// Recorded here so the next reader of the two guards side by side does not
/// have to re-derive it — and so that if the semantics ever change, this test
/// fails deliberately rather than by surprise.
#[test]
fn a_health_sequence_that_repeats_is_admitted() {
    DurabilityHealth::replay(&[walk_at(7), walk_at(7)]).expect(
        "an equal health sequence is currently admitted; if this now refuses, the guard was \
         changed from `<` to `<=` and the disagreement recorded on frankengit-bq4b was \
         resolved in favour of the fgit-resource reading",
    );
}
