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
use fgit_statistics::expected_loss::{ExpectedLossRefusal, probability_b_exceeds_a_ppm};

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
        assert!(
            (500_000 - MAX_UNDERSTATEMENT_PPM..=500_000).contains(&got),
            "Beta({alpha},{beta}) against itself must be one half to within the stated bound, \
             and never above it; got {got} ppm"
        );
    }
}

#[test]
fn the_flooring_error_is_attained_only_at_a_boundary_and_never_exceeds_the_bound() {
    // WHERE THE 1 PPM ACTUALLY LIVES.
    //
    // The 500-set sweep in expected_loss_error_evidence.rs measures 0 ppm
    // error, which would justify claiming a tighter bound than the module
    // states. It does not, because that sample cannot reach the worst case: a
    // randomly drawn parameter set essentially never lands on an exact ppm
    // boundary, and the accumulated flooring error is ~4e-27, so a boundary is
    // the only place it can change the reported integer.
    //
    // Any posterior compared against itself is exactly 1/2 -- a boundary by
    // construction, needing no oracle. This walks 200 of them plus a spread of
    // asymmetric self-pairs and asserts BOTH halves of the claim: never above
    // the exact value, and never more than the stated bound below it.
    //
    // Stating a bound of 1 while measuring 0 would be understating the module;
    // measuring 0 and claiming 0 would be overstating it. This is the test that
    // decides which number is honest.
    let mut attained = false;

    for alpha in 1_u32..=200 {
        let got = probability_b_exceeds_a_ppm(posterior(alpha, alpha), posterior(alpha, alpha))
            .expect("a posterior against itself is representable");
        assert!(
            got <= 500_000,
            "Beta({alpha},{alpha}) against itself is exactly one half; {got} ppm is ABOVE it, and \
             the error must never take that direction"
        );
        assert!(
            500_000 - got <= MAX_UNDERSTATEMENT_PPM,
            "Beta({alpha},{alpha}) against itself returned {got} ppm, short of one half by more \
             than the {MAX_UNDERSTATEMENT_PPM} ppm bound"
        );
        if got != 500_000 {
            attained = true;
        }
    }

    for (alpha, beta) in [(2_u32, 3_u32), (7, 11), (50, 3), (3, 50), (120, 240)] {
        let got = probability_b_exceeds_a_ppm(posterior(alpha, beta), posterior(alpha, beta))
            .expect("a posterior against itself is representable");
        assert!(
            (500_000 - MAX_UNDERSTATEMENT_PPM..=500_000).contains(&got),
            "Beta({alpha},{beta}) against itself must be one half to within the bound; got {got}"
        );
    }

    // The presence half: the bound is a measurement, not a cushion. If nothing
    // in this family ever fell short, the module would be claiming a looser
    // bound than it needs and this test would be asserting nothing.
    assert!(
        attained,
        "no self-comparison fell short of 500000 ppm, so the stated {MAX_UNDERSTATEMENT_PPM} ppm \
         bound is no longer attained anywhere and the module is understating its own accuracy"
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
