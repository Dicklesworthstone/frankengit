//! The Beta-Bernoulli expected-loss integral, evaluated peak-outward.
//!
//! `P(theta_b > theta_a)` for integer Beta parameters, in parts per million.
//! This closes `NEG-025` by taking the one escape route that record left open,
//! and it owes — and pays — a measured error bound.
//!
//! # What NEG-025 recorded, and why the obvious fix is the wrong one
//!
//! The closed form is a finite sum of `alpha_b` rational terms whose successive
//! ratio is factorial-free, so the obvious implementation walks the recurrence
//! from `T(0)` upward in fixed point. `NEG-025` measured that and found it
//! **silently wrong**: at scale `1e24` in `u128`, `T(0)` truncates to zero and
//! every later term is `0 * ratio = 0`, so the function returns exactly
//! `0 ppm`. Not an inaccurate answer — a confidently wrong one, and `0 ppm`
//! reads as *the candidate never beats the fallback*, which would pin a
//! controller to its fallback permanently while looking like evidence.
//!
//! The cause is dynamic range, not arithmetic: the series **starts negligible
//! and grows**. `Beta(1001,1001)` against `Beta(1501,501)` has `T(0) ~ 1e-129`
//! while the peak term is `~1e-2` in every case measured — about 127 orders of
//! magnitude, against the ~38 decimal digits `u128` offers.
//!
//! # The route taken
//!
//! `NEG-025` names three ways out and calls the third "plausible and
//! unanalysed": *restructure the summation to begin at the peak term and work
//! outward so no value near `T(0)` is ever represented.* That is what this
//! module does.
//!
//! * find the peak index — the ratio is monotone through 1, so the last index
//!   whose ratio is at least 1 is the peak;
//! * evaluate `T(peak)` directly as a **balanced product**: its numerator and
//!   denominator are runs of consecutive integers, and applying them in an
//!   order that keeps the running value near 1 never forms the enormous
//!   intermediate a naive factorial ratio would;
//! * walk outward in both directions with the same recurrence, stopping when a
//!   term reaches zero — by then it is below one part in `2^96` and cannot move
//!   a parts-per-million answer.
//!
//! `T(0)` is never represented, which is the whole point.
//!
//! # The error evidence this owes, measured
//!
//! Measured against **exact rational evaluation of the same closed form**,
//! walked from `T(0)` upward in `Fraction`s where this module walks it outward
//! from the peak in fixed point. The oracle and its generator are committed:
//! `tests/oracle/generate.py`, swept by `tests/expected_loss_error_evidence.rs`.
//!
//! Over **500 deterministic parameter sets**, all four parameters in `1..=300`:
//!
//! * **457 produce a value, and every one equals the exact floor exactly** —
//!   `0 ppm` error. 327 of them have a non-zero exact value, so the agreement
//!   is not the trivial one of two implementations both returning zero;
//! * **zero overestimates**;
//! * **43 refuse**, and every refused set has an exact value below `1 ppm` —
//!   nothing representable in parts per million is lost to the refusal.
//!
//! **The worst case is not in that sample, and saying so is the point.** A
//! randomly drawn parameter set essentially never lands on an exact ppm
//! boundary, and the boundary is where the flooring shows.
//!
//! Two kinds of boundary case exist and they now behave differently:
//!
//! * **a posterior against itself** is exactly `1/2`, and the answer is
//!   **exactly `500000 ppm`** — see the normalisation below. Measured across
//!   `Beta(n,n)` for `n` in `1..=200` plus a spread of asymmetric self-pairs:
//!   no exceptions;
//! * **two DIFFERENT posteriors each symmetric about one half** are also
//!   exactly `1/2`, but their tails are not bit-identical, so flooring can
//!   still cost one ppm. `Beta(2,2)` against `Beta(3,3)` returns `499999`.
//!
//! So the stated bound is **1 ppm, one-directional**, attained only at exact
//! ppm boundaries between distinct posteriors, and `0 ppm` everywhere else.
//!
//! # Why a self-comparison is exact, and why it is not a special case
//!
//! `P(theta_b > theta_a) + P(theta_a > theta_b) = 1` exactly: the posteriors
//! are continuous, so `P(theta_a == theta_b) = 0` and there is no tie mass to
//! apportion. Both tails are therefore evaluated and the answer is normalised
//! by **their actual total** rather than by [`ONE`].
//!
//! That cancels the flooring drift, because both sums lose it by the same
//! mechanism and it appears in numerator and denominator alike. When the two
//! posteriors are equal the two sums are computed from identical inputs, so
//! they are bit-identical and the quotient is exactly one half — **by
//! construction, with no tie-breaking, no rounding mode, and no branch in the
//! code testing for equality**. A special case would have been the wrong fix:
//! it would report the right number for the one input anybody checks while
//! leaving every neighbouring input as wrong as before.
//!
//! When the complementary tail underflows the scale, `P(theta_a > theta_b)` is
//! below `2^-96`, the two tails total `ONE` far beyond ppm resolution, and
//! `ONE` is used. Refusing instead would have cost **48 of the 500** sampled
//! sets this evaluation answers correctly — measured, which is why it is not
//! done.
//!
//! [`compare_ppm`] returns both tails together for callers that need the
//! three-term invariant to hold exactly:
//! `P(B>A) + P(A>B) + P(A==B) + residual == 1_000_000`. Both tails are
//! computed independently rather than one being derived as the complement of
//! the other, so the identity is a real cross-check: a sign or ordering error
//! moves one tail and not the other. The one ppm that flooring both tails can
//! drop is reported as an explicit residual rather than absorbed into a tail,
//! because absorbing it would push that tail above its own exact value.
//!
//! # Why that bound is structural rather than lucky
//!
//! Every **answered** step of the outward walk floors one division, costing at
//! most `2^-96` relative; a step whose exact product exceeds `u128` is a typed
//! refusal rather than a divide-first approximation. The walk is at most
//! `alpha_b` steps and `alpha_b <= 300` over the measured region, so
//! accumulated error is bounded by roughly
//! `300 * 2^-96 ~ 4e-27` against a `1e-6` quantum — twenty-one orders of
//! headroom. The computed value therefore lands within `4e-27` of the exact
//! one, and the reported ppm can differ from the exact floor **only** when the
//! exact value sits within that distance of a ppm boundary. Sitting exactly on
//! one, as `1/2` does, is that case. The measurement and the mechanism agree,
//! which is why the sweep asserts exact equality rather than a tolerance: a
//! disagreement away from a boundary would mean something other than flooring
//! is happening.
//!
//! # Why the error is one-directional, and why that is the part that matters
//!
//! Every division floors and nothing rounds up, so the result is always at or
//! below the exact value. A result that can only under-state
//! `P(theta_b > theta_a)` can only under-state a candidate policy's advantage
//! over its fallback, so the error can delay a policy switch but never provoke
//! one. A symmetric bound of the same magnitude would not support that
//! sentence, and it is the sentence a controller actually needs.
//!
//! Rounding the final conversion to nearest would make the boundary cases
//! exact and cost exactly that property, so it is not done.
//!
//! Reference points, exact versus computed:
//!
//! ```text
//! Beta(17,17)   vs Beta(17,17)    500000.0000    500000   (self: exact)
//! Beta(2,2)     vs Beta(3,3)      500000.0000    499999   (distinct halves)
//! Beta(30,10)   vs Beta(10,30)         1.7982         1
//! Beta(20,10)   vs Beta(10,20)      4037.5866      4037
//! Beta(3,4)     vs Beta(5,2)      878787.8788    878787
//! Beta(10,90)   vs Beta(20,80)    978472.9783    978472
//! Beta(101,101) vs Beta(151,51)   999999.8921    999999
//! Beta(501,501) vs Beta(601,401)  999996.5398    999996
//! ```
//!
//! The last two are `NEG-025`'s own extreme cases, where the naive evaluation
//! returned `0`.
//!
//! # Where it still fails, and why that is a refusal rather than a number
//!
//! In 43 of the 500 draws the peak term itself underflows: `T(peak)` is below
//! `2^-96` and no ordering of the factors can represent it. Those are
//! concentrated, far-from-even posteriors — and, measured, **every one of them
//! has an exact value below `1 ppm`**, so the refusal region currently contains
//! no answer a parts-per-million caller could have used. That is asserted, not
//! assumed: if a representable answer ever falls into it, the sweep fails.
//!
//! A distinct refusal covers an outward recurrence whose exact intermediate
//! product would exceed `u128`. Dividing before multiplying in that case would
//! change the floor and can erase a positive term, so the evaluator returns
//! [`ExpectedLossRefusal::StepProductOverflow`] and the policy path takes its
//! pinned deterministic fallback. This module does not claim an answer for
//! that numeric-degradation region.
//!
//! **That failure is detected, not returned.** It is the same region `NEG-025`
//! fell into; the difference is that underflow is observable here — the running
//! value reaches zero — so this refuses with
//! [`ExpectedLossRefusal::PeakTermUnrepresentable`] instead of reporting
//! `0 ppm`. A typed refusal a controller must handle beats a plausible number
//! that is wrong, which is the whole lesson of the record this closes.
//!
//! Widening that region needs a mantissa-plus-exponent representation or
//! arbitrary-precision rationals — the other two routes `NEG-025` names, both
//! of which need their own constitutional argument. Neither is attempted here.

use crate::beta_bernoulli::Posterior;

/// Fractional bits in the fixed-point accumulator.
///
/// 96 leaves 31 bits of headroom in a `u128` for the intermediate produced by
/// one multiplication by a factor, which is bounded by the largest parameter.
const FRACTION_BITS: u32 = 96;

/// One in fixed point.
const ONE: u128 = 1 << FRACTION_BITS;

/// The largest running value tolerated before a multiplication is unsafe.
const CEILING: u128 = u128::MAX >> 1;

/// Parts per million.
const PARTS_PER_MILLION: u128 = 1_000_000;

/// Why an expected-loss evaluation declined to answer.
///
/// Every variant is a refusal to produce a number, never a substitute for one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExpectedLossRefusal {
    /// The peak term is below the fixed-point scale and cannot be represented.
    ///
    /// This is `NEG-025`'s failure region, **detected**. The naive evaluation
    /// returned `0 ppm` here; returning a number at all was the defect.
    PeakTermUnrepresentable {
        /// Index of the peak term the evaluation could not represent.
        peak: u32,
    },
    /// A parameter exceeds what the bounded evaluation admits.
    ///
    /// The bound is on the *term count*, which is `alpha_b`: the outward walk
    /// is linear in it, and an unbounded loop is not admissible in a policy
    /// path.
    TooManyTerms {
        /// Terms the closed form would require.
        offered: u64,
        /// Terms this evaluation admits.
        maximum: u64,
    },
    /// The peak term would materialize more integer factors than admitted.
    ///
    /// The balanced product represents `T(peak)` as two factor lists whose
    /// combined length is linear in the BETA parameters as well as the
    /// alphas, so an admitted posterior can otherwise demand allocations
    /// proportional to billions of observed failures before any arithmetic
    /// runs. Refusing by count keeps the whole evaluation bounded.
    TooManyPeakFactors {
        /// Factors the balanced product would materialize.
        offered: u64,
        /// Factors this evaluation admits.
        maximum: u64,
    },
    /// A recurrence step needs an intermediate wider than `u128`.
    ///
    /// Dividing before multiplying would avoid the overflow only by changing
    /// where truncation occurs. That can silently discard a positive term, so
    /// this bounded implementation refuses and lets the caller select its
    /// deterministic fallback instead.
    StepProductOverflow,
}

/// The largest `alpha_b` this evaluation will walk.
pub const MAX_TERMS: u64 = 1 << 16;

/// The largest combined factor count [`peak_term`](fn@peak_term) materializes.
///
/// The four numerator runs and two denominator runs of the balanced product
/// are linear in the beta parameters, not only the alphas that [`MAX_TERMS`]
/// bounds, so this is the bound that actually caps the policy-path memory
/// and work: at most `MAX_PEAK_FACTORS` factors are ever collected or
/// multiplied.
pub const MAX_PEAK_FACTORS: u64 = 1 << 18;
/// `P(theta_b > theta_a)` in parts per million, or a typed refusal.
///
/// Both posteriors carry integer counts by construction, so the closed form
/// applies exactly and the only inexactness is the fixed-point evaluation whose
/// bound is stated in the module documentation: at most 1 ppm, and never above
/// the exact value.
///
/// # Examples
///
/// ```
/// use fgit_statistics::beta_bernoulli::{BetaPrior, Outcomes, Posterior};
/// use fgit_statistics::expected_loss::probability_b_exceeds_a_ppm;
///
/// fn posterior(alpha: u32, beta: u32) -> Posterior {
///     BetaPrior::try_new(alpha, beta)
///         .expect("a proper prior")
///         .update(Outcomes { successes: 0, trials: 0 })
///         .expect("zero observations update cleanly")
/// }
///
/// // An ordinary comparison, exact against the closed form.
/// assert_eq!(
///     probability_b_exceeds_a_ppm(posterior(3, 4), posterior(5, 2)),
///     Ok(878_787),
/// );
///
/// // A LOW probability comes back as a number, not a refusal.
/// assert_eq!(
///     probability_b_exceeds_a_ppm(posterior(20, 10), posterior(10, 20)),
///     Ok(4_037),
/// );
///
/// // An arm against itself is exactly one half, and this is exact -- both
/// // tails are computed from identical inputs, so they are bit-identical and
/// // normalising one by their total gives exactly half with no rounding
/// // choice involved.
/// assert_eq!(
///     probability_b_exceeds_a_ppm(posterior(17, 17), posterior(17, 17)),
///     Ok(500_000),
/// );
///
/// // THE ONE THAT STILL SURPRISES CALLERS. Two DIFFERENT posteriors, each
/// // symmetric about one half, are also exactly 500000 ppm -- but their tails
/// // are not bit-identical, so flooring can still cost one ppm at that
/// // boundary. Assert a range here, never equality against the ideal value.
/// let across = probability_b_exceeds_a_ppm(posterior(2, 2), posterior(3, 3))
///     .expect("representable");
/// assert_eq!(across, 499_999);
/// assert!((499_999..=500_000).contains(&across));
/// ```
///
/// # Errors
///
/// Returns [`ExpectedLossRefusal`] when the peak term is unrepresentable at
/// this scale, when the term count exceeds [`MAX_TERMS`], when the peak term's
/// factor runs exceed [`MAX_PEAK_FACTORS`], or when a recurrence product
/// exceeds `u128`.
///
/// A refusal is not a small probability. `Beta(90,10)` against `Beta(10,90)`
/// refuses rather than returning `Ok(0)`, because its peak term underflows the
/// scale; returning a number there was the whole of `NEG-025`'s defect. Callers
/// must distinguish the two:
///
/// ```
/// # use fgit_statistics::beta_bernoulli::{BetaPrior, Outcomes, Posterior};
/// # use fgit_statistics::expected_loss::{ExpectedLossRefusal, probability_b_exceeds_a_ppm};
/// # fn posterior(alpha: u32, beta: u32) -> Posterior {
/// #     BetaPrior::try_new(alpha, beta).unwrap()
/// #         .update(Outcomes { successes: 0, trials: 0 }).unwrap()
/// # }
/// assert!(matches!(
///     probability_b_exceeds_a_ppm(posterior(90, 10), posterior(10, 90)),
///     Err(ExpectedLossRefusal::PeakTermUnrepresentable { .. }),
/// ));
/// ```
pub fn probability_b_exceeds_a_ppm(a: Posterior, b: Posterior) -> Result<u32, ExpectedLossRefusal> {
    let (alpha_a, beta_a) = (a.alpha(), a.beta());
    let (alpha_b, beta_b) = (b.alpha(), b.beta());

    // Both directions are walked, so both term counts need the bound. The
    // reverse tail walks alpha_a terms; checking only alpha_b would leave one
    // direction unbounded, and "bounded evaluation" is the claim this makes.
    for offered in [alpha_b, alpha_a] {
        if offered > MAX_TERMS {
            return Err(ExpectedLossRefusal::TooManyTerms {
                offered,
                maximum: MAX_TERMS,
            });
        }
    }

    let forward = tail_sum(alpha_a, beta_a, alpha_b, beta_b)?;

    // Normalise by the two tails' ACTUAL total rather than by ONE.
    //
    // `P(theta_b > theta_a) + P(theta_a > theta_b) = 1` exactly -- the
    // posteriors are continuous, so there is no tie mass to apportion. Both
    // sums floor every division, so both sit a hair low by the SAME
    // mechanism; dividing one by their total cancels that drift because it
    // appears in numerator and denominator alike.
    //
    // That is what makes a self-comparison exact rather than nearly exact, and
    // exact BY CONSTRUCTION rather than by a rounding choice: equal posteriors
    // make the two sums bit-identical, so the quotient is exactly one half
    // with no tie-breaking, no rounding mode, and no special case in the code.
    //
    // When the complementary tail underflows, `P(theta_a > theta_b)` is below
    // `2^-96` and the two tails total `ONE` to far beyond ppm resolution, so
    // `ONE` is the right scale and nothing is lost. Refusing there instead
    // would discard 48 of the 500 sampled parameter sets that this evaluation
    // answers correctly -- measured, not assumed.
    let scale = tail_sum(alpha_b, beta_b, alpha_a, beta_a)
        .map_or(ONE, |reverse| forward.saturating_add(reverse));

    // `scale` is at least `forward`, which is at least 1: `peak_term` returns
    // `None` rather than zero, so an underflowed peak has already refused
    // above. And `forward <= ~2^96` keeps the product under `2^116`.
    let ppm = forward.saturating_mul(PARTS_PER_MILLION) / scale;
    Ok(u32::try_from(ppm.min(PARTS_PER_MILLION)).unwrap_or(u32::MAX))
}

/// Both tails of a comparison, summing to exactly one million ppm.
///
/// Each tail is computed independently by the same peak-outward evaluation and
/// floored against the same scale, so this is a genuine cross-check rather
/// than one number and its arithmetic complement: a sign or ordering error
/// moves one tail without moving the other, and
/// [`Self::sums_to_one_million`] stops holding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TailComparison {
    // The unit lives on the accessors, where a caller reads it. Repeating
    // `_ppm` on every field says nothing extra and trips `struct_field_names`.
    b_exceeds_a: u32,
    a_exceeds_b: u32,
    rounding_residual: u32,
}

impl TailComparison {
    /// `P(theta_b > theta_a)` in ppm, at or below the exact value.
    #[must_use]
    pub const fn b_exceeds_a_ppm(&self) -> u32 {
        self.b_exceeds_a
    }

    /// `P(theta_a > theta_b)` in ppm, at or below the exact value.
    #[must_use]
    pub const fn a_exceeds_b_ppm(&self) -> u32 {
        self.a_exceeds_b
    }

    /// `P(theta_a == theta_b)` in ppm, which is exactly zero.
    ///
    /// Both posteriors are continuous, so the event that two independent
    /// draws are equal has probability zero — there is no diagonal mass to
    /// apportion between the tails. This is a method rather than an omitted
    /// term so that the three-term invariant can be written out in full and
    /// checked, instead of being silently a two-term one.
    #[must_use]
    pub const fn tie_ppm(&self) -> u32 {
        0
    }

    /// Parts per million lost to flooring both tails.
    ///
    /// Zero or one. Both tails floor, and the exact values sum to exactly one
    /// million, so at most one ppm goes unassigned. It is reported rather than
    /// absorbed into a tail, because absorbing it would push that tail above
    /// its own exact value and break the one-directional guarantee.
    #[must_use]
    pub const fn rounding_residual_ppm(&self) -> u32 {
        self.rounding_residual
    }

    /// The three-term invariant, exactly.
    ///
    /// `P(B>A) + P(A>B) + P(A==B) + residual == 1_000_000`.
    #[must_use]
    pub const fn sums_to_one_million(&self) -> bool {
        self.b_exceeds_a + self.a_exceeds_b + self.tie_ppm() + self.rounding_residual == 1_000_000
    }
}

/// Both tails of `a` against `b`, normalised together.
///
/// Stricter than [`probability_b_exceeds_a_ppm`], deliberately: that function
/// falls back to a fixed scale when the complementary tail underflows, because
/// it only has to report one number. This one must report both, so it refuses
/// unless both are representable.
///
/// # Errors
///
/// Returns [`ExpectedLossRefusal`] when either tail's peak is unrepresentable
/// at this scale, when either term count exceeds [`MAX_TERMS`], when a peak
/// term's factor runs exceed [`MAX_PEAK_FACTORS`], or when a recurrence product
/// exceeds `u128`.
pub fn compare_ppm(a: Posterior, b: Posterior) -> Result<TailComparison, ExpectedLossRefusal> {
    let (alpha_a, beta_a) = (a.alpha(), a.beta());
    let (alpha_b, beta_b) = (b.alpha(), b.beta());

    for offered in [alpha_b, alpha_a] {
        if offered > MAX_TERMS {
            return Err(ExpectedLossRefusal::TooManyTerms {
                offered,
                maximum: MAX_TERMS,
            });
        }
    }

    let forward = tail_sum(alpha_a, beta_a, alpha_b, beta_b)?;
    let reverse = tail_sum(alpha_b, beta_b, alpha_a, beta_a)?;
    let scale = forward.saturating_add(reverse);

    let b_exceeds_a = floor_ppm(forward, scale);
    let a_exceeds_b = floor_ppm(reverse, scale);
    let assigned = b_exceeds_a.saturating_add(a_exceeds_b);

    Ok(TailComparison {
        b_exceeds_a,
        a_exceeds_b,
        rounding_residual: u32::try_from(PARTS_PER_MILLION)
            .unwrap_or(u32::MAX)
            .saturating_sub(assigned),
    })
}

/// `part / scale` in ppm, floored, saturating at one million.
fn floor_ppm(part: u128, scale: u128) -> u32 {
    if scale == 0 {
        return 0;
    }
    let ppm = part.saturating_mul(PARTS_PER_MILLION) / scale;
    u32::try_from(ppm.min(PARTS_PER_MILLION)).unwrap_or(u32::MAX)
}

/// The fixed-point sum for `P(theta_b > theta_a)`, before normalisation.
///
/// Evaluated peak-outward: `T(0)` is never represented. The returned value is
/// on the [`ONE`] scale and is always at or below the true tail, because every
/// division floors.
fn tail_sum(
    alpha_a: u64,
    beta_a: u64,
    alpha_b: u64,
    beta_b: u64,
) -> Result<u128, ExpectedLossRefusal> {
    let peak = peak_index(alpha_a, beta_a, alpha_b, beta_b);

    // BOUND BEFORE ALLOCATION. `peak_term` materializes one integer per
    // element of six input-derived runs, and those runs are linear in the
    // beta parameters that [`MAX_TERMS`] never sees: an admitted posterior
    // can carry billions of observed failures. Counting the runs first keeps
    // the whole evaluation bounded; saturation only ever over-counts, which
    // is the safe direction for a bound.
    let factors = peak_factor_count(alpha_a, beta_a, beta_b, peak);
    if factors > MAX_PEAK_FACTORS {
        return Err(ExpectedLossRefusal::TooManyPeakFactors {
            offered: factors,
            maximum: MAX_PEAK_FACTORS,
        });
    }

    let peak_value = peak_term(alpha_a, beta_a, beta_b, peak).ok_or_else(|| {
        ExpectedLossRefusal::PeakTermUnrepresentable {
            peak: u32::try_from(peak).unwrap_or(u32::MAX),
        }
    })?;
    let mut total = peak_value;

    // Downward from the peak: divide by the ratio that produced each step.
    let mut value = peak_value;
    for index in (0..peak).rev() {
        let (numerator, denominator) = ratio(alpha_a, beta_a, beta_b, index);
        value = mul_div(value, denominator, numerator)?;
        if value == 0 {
            break;
        }
        total = total.saturating_add(value);
    }

    // Upward from the peak.
    value = peak_value;
    for index in peak..alpha_b.saturating_sub(1) {
        let (numerator, denominator) = ratio(alpha_a, beta_a, beta_b, index);
        value = mul_div(value, numerator, denominator)?;
        if value == 0 {
            break;
        }
        total = total.saturating_add(value);
    }

    Ok(total)
}

/// Combined length of the six integer runs [`peak_term`](fn@peak_term)
/// materializes for one peak term, saturating instead of overflowing.
///
/// Mirrors `peak_term`'s four numerator runs (`alpha_a..alpha_a + peak`,
/// `beta_a..beta_a + beta_b`, `1..alpha_a + beta_a`, `beta_b..beta_b + peak`)
/// and two denominator runs (`1..=peak`,
/// `1..alpha_a + peak + beta_a + beta_b`) run for run, so a change to one
/// must change the other. Every admitted posterior makes the true total far
/// below `u64::MAX`; saturation only ever over-counts, which keeps the
/// [`MAX_PEAK_FACTORS`] bound sound.
const fn peak_factor_count(alpha_a: u64, beta_a: u64, beta_b: u64, peak: u64) -> u64 {
    // Inclusive-start, exclusive-end run length; saturation only ever
    // over-counts, which is the safe direction for a bound.
    const fn run(start: u64, end: u64) -> u64 {
        end.saturating_sub(start)
    }
    let numerators = peak
        .saturating_add(beta_b)
        .saturating_add(run(1, alpha_a.saturating_add(beta_a)))
        .saturating_add(peak);
    let denominators = peak.saturating_add(run(
        1,
        alpha_a
            .saturating_add(peak)
            .saturating_add(beta_a)
            .saturating_add(beta_b),
    ));
    numerators.saturating_add(denominators)
}

/// `T(i+1)/T(i)`, as an exact integer ratio.
///
/// Transcribed from the closed form documented on
/// [`crate::beta_bernoulli`], and factorial-free by construction:
///
/// ```text
/// (a_a+i)/(a_a+i+b_a+b_b) * (1+i+b_b)/(1+i) * (b_b+i)/(b_b+i+1)
/// ```
const fn ratio(alpha_a: u64, beta_a: u64, beta_b: u64, index: u64) -> (u128, u128) {
    let numerator =
        (alpha_a + index) as u128 * (1 + index + beta_b) as u128 * (beta_b + index) as u128;
    let denominator = (alpha_a + index + beta_a + beta_b) as u128
        * (1 + index) as u128
        * (beta_b + index + 1) as u128;
    (numerator, denominator)
}

/// The last index whose ratio is at least one: the peak.
///
/// The ratio is monotone decreasing in `index`, so the first index at which it
/// drops below one ends the ascent and no later index can climb back.
fn peak_index(alpha_a: u64, beta_a: u64, alpha_b: u64, beta_b: u64) -> u64 {
    let mut peak = 0;
    for index in 0..alpha_b.saturating_sub(1) {
        let (numerator, denominator) = ratio(alpha_a, beta_a, beta_b, index);
        if numerator < denominator {
            break;
        }
        peak = index + 1;
    }
    peak
}

/// `T(peak)` in fixed point, or `None` if it underflows the scale.
///
/// The term is a ratio of products of consecutive integers. Applying them in a
/// **balanced** order — a numerator factor while the running value is at or
/// below one, a denominator factor otherwise — keeps the accumulator near one
/// throughout, so neither the enormous intermediate of a naive factorial ratio
/// nor the vanishing intermediate of a naive sequential division is ever
/// formed.
fn peak_term(alpha_a: u64, beta_a: u64, beta_b: u64, peak: u64) -> Option<u128> {
    let mut numerators = Vec::new();
    numerators.extend(alpha_a..alpha_a + peak);
    numerators.extend(beta_a..beta_a + beta_b);
    numerators.extend(1..alpha_a + beta_a);
    numerators.extend(beta_b..beta_b + peak);

    let mut denominators = Vec::new();
    denominators.extend(1..=peak);
    denominators.extend(1..alpha_a + peak + beta_a + beta_b);

    // Largest first on both sides: pairing a big numerator against a big
    // denominator keeps the running value in the narrowest band, which is what
    // buys the headroom.
    numerators.sort_unstable_by(|left, right| right.cmp(left));
    denominators.sort_unstable_by(|left, right| right.cmp(left));

    let mut value: u128 = ONE;
    let mut next_numerator = 0;
    let mut next_denominator = 0;
    while next_numerator < numerators.len() || next_denominator < denominators.len() {
        let take_numerator = (value <= ONE && next_numerator < numerators.len())
            || next_denominator >= denominators.len();
        if take_numerator {
            value = value.checked_mul(u128::from(numerators[next_numerator]))?;
            next_numerator += 1;
        } else {
            value /= u128::from(denominators[next_denominator]);
            next_denominator += 1;
        }
        if value == 0 || value > CEILING {
            return None;
        }
    }
    Some(value)
}

/// `value * numerator / denominator`, with one well-defined floor.
///
/// # Errors
///
/// Returns [`ExpectedLossRefusal::StepProductOverflow`] when the exact
/// multiplication would exceed `u128`. Dividing first is not an equivalent
/// rescue: it moves the floor before multiplication and can turn a positive
/// quotient into zero. Refusing preserves the stated rounding contract and
/// lets callers select the pinned fallback for a numeric-bound violation.
fn mul_div(value: u128, numerator: u128, denominator: u128) -> Result<u128, ExpectedLossRefusal> {
    value
        .checked_mul(numerator)
        .map(|scaled| scaled / denominator)
        .ok_or(ExpectedLossRefusal::StepProductOverflow)
}

#[cfg(test)]
mod tests {
    use super::{ExpectedLossRefusal, mul_div};

    #[test]
    fn an_overflowing_step_refuses_instead_of_moving_the_floor() {
        // The exact quotient is 2^65. The old fallback divided the left
        // operand first (`2^66 / 2^67 == 0`) and consequently returned zero,
        // even though the mathematically floored result is positive.
        assert_eq!(
            mul_div(1_u128 << 66, 1_u128 << 66, 1_u128 << 67),
            Err(ExpectedLossRefusal::StepProductOverflow)
        );
    }

    #[test]
    fn a_nearby_representable_step_keeps_its_single_floor() {
        assert_eq!(
            mul_div(1_u128 << 60, 1_u128 << 60, 1_u128 << 67),
            Ok(1_u128 << 53)
        );
    }
}
