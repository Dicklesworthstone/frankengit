//! `frankengit-s76z`: named reference points for the expected-loss integral.
//!
//! The bulk error evidence lives in `expected_loss_error_evidence.rs`, which
//! sweeps 500 parameter sets against an exact-rational oracle. This file holds
//! the handful of points worth naming: the symmetry control that needs no
//! oracle at all, the two parameter sets `NEG-025` recorded as returning
//! `0 ppm`, and the refusal boundary with its permitted case.
//!
//! # Why a symmetry control leads
//!
//! Every other golden here rests on an external computation. The symmetry
//! control does not: two Beta distributions each symmetric about one half give
//! `P(theta_b > theta_a) = 1/2` by symmetry alone, so `Beta(2,2)` against
//! `Beta(3,3)` is exactly `500000 ppm` and an implementation that misses it is
//! wrong on its face, whatever any oracle says. If the oracle and the control
//! ever disagreed, the control would win.
//!
//! It also earns its place empirically. The 500-set sweep measures `0 ppm`
//! error, but a randomly drawn parameter set essentially never lands on an
//! exact ppm boundary, and the boundary is the only place the flooring shows.
//! The control lands on one by construction, and it is where the module's
//! stated `1 ppm` bound is attained rather than merely bounded.

use fgit_statistics::beta_bernoulli::{BetaPrior, Outcomes, Posterior};
use fgit_statistics::expected_loss::{
    ExpectedLossRefusal, MAX_TERMS, compare_ppm, probability_b_exceeds_a_ppm,
};

/// Build a posterior with exactly the parameters `(alpha, beta)`.
///
/// A prior of `(alpha, beta)` and zero observations gives a posterior of
/// `(alpha, beta)`, which reaches a chosen parameter pair without asserting
/// anything about the update rule here.
fn posterior(alpha: u32, beta: u32) -> Posterior {
    BetaPrior::try_new(alpha, beta)
        .expect("a proper prior")
        .update(Outcomes {
            successes: 0,
            trials: 0,
        })
        .expect("zero observations update cleanly")
}

/// The bound the module's error evidence states.
///
/// One-directional: the result is never above the exact value, and never more
/// than this below it.
const MAX_UNDERSTATEMENT_PPM: u32 = 1;

/// `(alpha_a, beta_a, alpha_b, beta_b, exact_ppm_floor)`.
///
/// Exact values from `tests/oracle/generate.py`, cross-checked against direct
/// factorial evaluation of the Beta-function form, which shares no code path
/// with the recurrence. The span is deliberate: `1 ppm` to `999999 ppm`, so the
/// accuracy claim covers the tails and not just the comfortable middle.
const GOLDENS: [(u32, u32, u32, u32, u32); 8] = [
    // The symmetry control: exactly one half, provable without any reference.
    (2, 2, 3, 3, 500_000),
    // The low tail. A near-zero answer must still be a number, and the right
    // one -- this is where an implementation that silently underflows looks
    // most plausible.
    (30, 10, 10, 30, 1),
    (40, 20, 20, 40, 101),
    (20, 10, 10, 20, 4_037),
    (3, 4, 5, 2, 878_787),
    (10, 90, 20, 80, 978_472),
    // NEG-025's own extreme cases. The naive evaluation returned 0 ppm here.
    (101, 101, 151, 51, 999_999),
    (501, 501, 601, 401, 999_996),
];

#[test]
fn every_golden_is_reached_within_the_stated_bound() {
    for (alpha_a, beta_a, alpha_b, beta_b, exact) in GOLDENS {
        let name = format!("Beta({alpha_a},{beta_a}) vs Beta({alpha_b},{beta_b})");
        let got = probability_b_exceeds_a_ppm(posterior(alpha_a, beta_a), posterior(alpha_b, beta_b))
            .unwrap_or_else(|refusal| {
                panic!("{name} is inside the representable region and must produce a value; got {refusal:?}")
            });

        assert!(
            got <= exact,
            "{name} returned {got} ppm, ABOVE the exact {exact} ppm. Overstating \
             P(theta_b > theta_a) overstates a candidate policy's advantage over its fallback, \
             which is the one direction this error must never take"
        );
        assert!(
            exact - got <= MAX_UNDERSTATEMENT_PPM,
            "{name} returned {got} ppm against an exact {exact} ppm, understating by more than \
             the {MAX_UNDERSTATEMENT_PPM} ppm this module's evidence claims"
        );
    }
}

#[test]
fn the_symmetry_control_is_exact_without_reference_to_any_oracle() {
    // Two distributions each symmetric about one half. P is one half by
    // symmetry alone, so this depends on no external computation and fails
    // loudly if the closed form is transcribed wrongly.
    for (alpha, beta) in [(2_u32, 2_u32), (5, 5), (37, 37)] {
        let got = probability_b_exceeds_a_ppm(posterior(alpha, beta), posterior(alpha, beta))
            .expect("identical symmetric posteriors are representable");
        assert_eq!(
            got, 500_000,
            "Beta({alpha},{beta}) against itself must be EXACTLY one half. Both tails are \
             computed from identical inputs, so they are bit-identical and normalising one by \
             their total is exactly half -- there is no rounding choice left for this to get \
             wrong, so a band here would hide a real defect rather than tolerate a known limit"
        );
    }
}

#[test]
fn the_flooring_error_is_attained_only_at_a_boundary_and_never_exceeds_the_bound() {
    // WHERE THE 1 PPM ACTUALLY LIVES, after the normalisation fix.
    //
    // It is no longer the self-comparison. Normalising each tail by the two
    // tails' total made identical posteriors exact, because their tails are
    // bit-identical. The bound did not disappear with it: two DIFFERENT
    // posteriors that are each symmetric about one half are also exactly
    // 1/2, their tails are NOT bit-identical, and there the flooring still
    // shows.
    //
    // Beta(2,2) vs Beta(3,3) is that case and returns 499999.
    //
    // The 500-set random sweep measures 0 ppm error and cannot reach any of
    // this: a random draw essentially never lands on an exact ppm boundary,
    // and with accumulated error near 4e-27 a boundary is the only place the
    // reported integer can move. So this test is the reason the module claims
    // 1 ppm rather than 0.
    let mut attained = false;

    // Every posterior against itself: exact, no exceptions.
    for alpha in 1_u32..=200 {
        let got = probability_b_exceeds_a_ppm(posterior(alpha, alpha), posterior(alpha, alpha))
            .expect("a posterior against itself is representable");
        assert_eq!(
            got, 500_000,
            "Beta({alpha},{alpha}) against itself must be exactly one half; got {got} ppm"
        );
    }
    for (alpha, beta) in [(2_u32, 3_u32), (7, 11), (50, 3), (3, 50), (120, 240)] {
        let got = probability_b_exceeds_a_ppm(posterior(alpha, beta), posterior(alpha, beta))
            .expect("a posterior against itself is representable");
        assert_eq!(
            got, 500_000,
            "Beta({alpha},{beta}) against itself must be exactly one half; got {got} ppm"
        );
    }

    // Distinct posteriors that are each symmetric about one half: still
    // exactly 1/2, and this is where the bound is spent.
    for (left, right) in [
        ((2_u32, 2_u32), (3_u32, 3_u32)),
        ((2, 2), (7, 7)),
        ((2, 2), (40, 40)),
        ((3, 3), (40, 40)),
        ((5, 5), (3, 3)),
        ((11, 11), (7, 7)),
    ] {
        let got =
            probability_b_exceeds_a_ppm(posterior(left.0, left.1), posterior(right.0, right.1))
                .expect("symmetric posteriors are representable");
        assert!(
            got <= 500_000,
            "Beta{left:?} vs Beta{right:?} is exactly one half; {got} ppm is ABOVE it, and the \
             error must never take that direction"
        );
        assert!(
            500_000 - got <= MAX_UNDERSTATEMENT_PPM,
            "Beta{left:?} vs Beta{right:?} returned {got} ppm, short of one half by more than \
             the {MAX_UNDERSTATEMENT_PPM} ppm bound"
        );
        if got != 500_000 {
            attained = true;
        }
    }

    // The presence half: the bound is a measurement, not a cushion. If nothing
    // reached it, the module would be claiming a looser bound than it needs
    // and this test would be asserting nothing.
    assert!(
        attained,
        "no boundary case fell short of 500000 ppm, so the stated {MAX_UNDERSTATEMENT_PPM} ppm \
         bound is no longer attained anywhere and the module is understating its own accuracy"
    );
}

#[test]
fn both_tails_sum_to_exactly_one_million() {
    // The three-term invariant, and the reason it is worth having.
    //
    // P(B>A) + P(A>B) + P(A==B) == 1_000_000 ppm exactly. The tie term is
    // exactly zero because both posteriors are continuous -- there is no
    // diagonal mass to apportion -- and the ppm that flooring both tails drops
    // is reported as an explicit residual rather than absorbed into a tail,
    // since absorbing it would push that tail above its own exact value.
    //
    // NOT TAUTOLOGICAL, and that is the design point: both tails are computed
    // independently by the same evaluation rather than one being derived as
    // 1_000_000 minus the other. A sign or ordering error moves one tail
    // without moving the other and the sum stops holding. Deriving the
    // complement would make this pass against an evaluation wired backwards.
    for (alpha_a, beta_a, alpha_b, beta_b) in [
        (3_u32, 4_u32, 5_u32, 2_u32),
        (10, 90, 20, 80),
        (20, 10, 10, 20),
        (101, 101, 151, 51),
        (2, 2, 3, 3),
        (7, 3, 9, 5),
    ] {
        let pair = compare_ppm(posterior(alpha_a, beta_a), posterior(alpha_b, beta_b))
            .expect("both tails are representable here");

        assert!(
            pair.sums_to_one_million(),
            "Beta({alpha_a},{beta_a}) vs Beta({alpha_b},{beta_b}): {} + {} + {} + {} != 1000000",
            pair.b_exceeds_a_ppm(),
            pair.a_exceeds_b_ppm(),
            pair.tie_ppm(),
            pair.rounding_residual_ppm()
        );
        assert_eq!(pair.tie_ppm(), 0, "continuous posteriors have no tie mass");
        assert!(
            pair.rounding_residual_ppm() <= 1,
            "at most one ppm can go unassigned when two floors split an exact one million; got {}",
            pair.rounding_residual_ppm()
        );
        assert_eq!(
            pair.b_exceeds_a_ppm(),
            probability_b_exceeds_a_ppm(posterior(alpha_a, beta_a), posterior(alpha_b, beta_b))
                .expect("representable"),
            "the paired tail must agree with the single-tail entry point, or the two surfaces \
             have drifted apart"
        );
    }
}

#[test]
fn a_self_comparison_splits_exactly_evenly_with_no_residual() {
    // The presence case for the residual: it is 0 exactly when the split is
    // clean, and 1 otherwise. If it were always 1, the field would be a
    // constant rather than a measurement.
    for alpha in [1_u32, 2, 5, 17, 60, 199] {
        let pair = compare_ppm(posterior(alpha, alpha), posterior(alpha, alpha))
            .expect("a posterior against itself is representable");
        assert_eq!(pair.b_exceeds_a_ppm(), 500_000);
        assert_eq!(pair.a_exceeds_b_ppm(), 500_000);
        assert_eq!(
            pair.rounding_residual_ppm(),
            0,
            "an even split assigns every ppm; a residual here means the halves are not equal"
        );
        assert!(pair.sums_to_one_million());
    }

    // And the contrasting case, so the assertion above is not vacuous.
    let uneven = compare_ppm(posterior(3, 4), posterior(5, 2)).expect("representable");
    assert_eq!(
        uneven.rounding_residual_ppm(),
        1,
        "two floors of non-integer tails must leave exactly one ppm unassigned"
    );
}

#[test]
fn the_neg_025_cases_no_longer_return_zero() {
    // The regression this module exists to prevent, named as such.
    //
    // NEG-025 measured a u128 fixed-point walk from T(0) returning exactly
    // 0 ppm for these, because T(0) is ~1e-14 and ~1e-96 respectively and
    // truncates to nothing, after which every later term is 0 * ratio.
    //
    // Zero is not merely inaccurate here: it reads as "the candidate never
    // beats the fallback", which pins a controller to its fallback while
    // looking like evidence. So the assertion is specifically against zero,
    // kept separate from the accuracy goldens above so that deleting one does
    // not quietly delete the other.
    for (alpha_a, beta_a, alpha_b, beta_b) in
        [(101_u32, 101_u32, 151_u32, 51_u32), (501, 501, 601, 401)]
    {
        let got =
            probability_b_exceeds_a_ppm(posterior(alpha_a, beta_a), posterior(alpha_b, beta_b))
                .expect("NEG-025's cases are inside the representable region");
        assert!(
            got > 900_000,
            "Beta({alpha_a},{beta_a}) vs Beta({alpha_b},{beta_b}) is a near-certain advantage and \
             must not report {got} ppm; NEG-025's failure returned 0 here"
        );
    }
}

#[test]
fn an_unrepresentable_peak_refuses_rather_than_returning_a_number() {
    // THE POINT OF THE REFUSAL, and the difference from NEG-025.
    //
    // Concentrated, far-from-even posteriors push the peak term below the
    // fixed-point scale. That is the same region the naive evaluation fell
    // into; the difference is that underflow is observable here, so this
    // refuses instead of reporting a plausible number.
    //
    // Beta(90,10) against Beta(10,90) is measured to land there. Its exact
    // value is 1.3e-34, so nothing a caller could have used is lost -- the
    // sweep in expected_loss_error_evidence.rs asserts that property across
    // the whole refusal region rather than just here.
    let refusal = probability_b_exceeds_a_ppm(posterior(90, 10), posterior(10, 90))
        .expect_err("this parameter set underflows the scale and must refuse");

    assert!(
        matches!(refusal, ExpectedLossRefusal::PeakTermUnrepresentable { .. }),
        "the refusal must name the unrepresentable peak so an operator can tell it from a bound \
         violation; got {refusal:?}"
    );
}

#[test]
fn a_low_probability_is_answered_rather_than_refused() {
    // THE PERMITTED CASE the refusal above requires (AGENTS.md 16.3).
    //
    // Without this, `an_unrepresentable_peak_refuses...` passes just as happily
    // against a module that refuses everything, and the refusal would carry no
    // information at all.
    //
    // The pairing is near-identical by construction: both are lopsided
    // comparisons of the form Beta(m,n) against Beta(n,m) where a is heavily
    // favoured. The ONLY difference is concentration -- (20,10) vs (90,10) --
    // so what separates "answered" from "refused" is representability and
    // nothing else.
    //
    // 4037 ppm is emphatically a low probability, and the assertion is that it
    // comes back as a NUMBER, and the exactly right one. That is what makes the
    // refusal meaningful: a caller can tell "the candidate is losing" from "the
    // evaluation could not answer", which is precisely what NEG-025's Ok(0)
    // destroyed.
    let low = probability_b_exceeds_a_ppm(posterior(20, 10), posterior(10, 20))
        .expect("a lopsided but representable comparison must be answered, not refused");

    assert_eq!(
        low, 4_037,
        "Beta(20,10) vs Beta(10,20) is exactly 4037.5866 ppm and must floor to 4037; got {low}"
    );
    assert!(
        low < 100_000,
        "the permitted case must actually be a LOW probability, or it does not pair with the \
         refusal it exists to justify; got {low} ppm"
    );
}

#[test]
fn the_term_bound_is_checked_in_both_directions_and_not_at_the_boundary_itself() {
    // `probability_b_exceeds_a_ppm` walks BOTH tails, so both term counts need
    // the bound. Its own source says so: "checking only alpha_b would leave one
    // direction unbounded, and 'bounded evaluation' is the claim this makes."
    //
    // The loop is `for offered in [alpha_b, alpha_a]`, so alpha_b is tested
    // first. A guard that checked only the forward direction would pass a test
    // that only ever oversized `b` -- which is why the second case below keeps
    // `b` inside the bound and oversizes `a` alone.
    let over = u32::try_from(MAX_TERMS + 1).expect("the bound fits in a u32");
    let at = u32::try_from(MAX_TERMS).expect("the bound fits in a u32");

    // Direction one: b's alpha exceeds the bound.
    assert_eq!(
        probability_b_exceeds_a_ppm(posterior(2, 2), posterior(over, 2)),
        Err(ExpectedLossRefusal::TooManyTerms {
            offered: MAX_TERMS + 1,
            maximum: MAX_TERMS,
        }),
        "an oversized forward tail must refuse rather than walk unbounded work"
    );

    // Direction two, and this is the one a one-sided guard would miss: b is
    // comfortably inside the bound, so the first loop iteration passes, and
    // only the reverse tail is oversized.
    assert_eq!(
        probability_b_exceeds_a_ppm(posterior(over, 2), posterior(2, 2)),
        Err(ExpectedLossRefusal::TooManyTerms {
            offered: MAX_TERMS + 1,
            maximum: MAX_TERMS,
        }),
        "the reverse tail is walked too, so its term count is equally bounded"
    );

    // The exact boundary, which is the only case separating `>` from `>=`.
    // MAX_TERMS itself is admissible: the guard refuses what EXCEEDS the bound,
    // not what reaches it. This may still refuse for an unrelated reason -- a
    // posterior that extreme underflows the scale -- so the assertion is that
    // it is NOT a term-count refusal rather than that it succeeds.
    if let Err(ExpectedLossRefusal::TooManyTerms { offered, maximum }) =
        probability_b_exceeds_a_ppm(posterior(2, 2), posterior(at, 2))
    {
        panic!(
            "MAX_TERMS is the largest ADMISSIBLE count; refusing it means the guard reads >= \
             where it should read >  (offered {offered}, maximum {maximum})"
        );
    }
}
