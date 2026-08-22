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
//! boundary, and the boundary is where the flooring shows. Any posterior
//! compared against itself is exactly `1/2` by symmetry — a boundary by
//! construction — and there this returns `499999 ppm`. Measured across
//! `Beta(n,n)` for `n` in `1..=200` and a spread of asymmetric self-pairs, the
//! shortfall is **exactly 1 ppm and never more** (`Beta(1,1)` is exact).
//!
//! So the stated bound is **1 ppm, one-directional**, attained at exact ppm
//! boundaries and `0 ppm` away from them.
//!
//! # Why that bound is structural rather than lucky
//!
//! Each step of the outward walk floors one division, costing at most `2^-96`
//! relative; the walk is at most `alpha_b` steps and `alpha_b <= 300` over the
//! measured region, so accumulated error is bounded by roughly
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
//! Beta(2,2)     vs Beta(3,3)      500000.0000    499999   (symmetry control)
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
}

/// The largest `alpha_b` this evaluation will walk.
pub const MAX_TERMS: u64 = 1 << 16;

/// `P(theta_b > theta_a)` in parts per million, or a typed refusal.
///
/// Both posteriors carry integer counts by construction, so the closed form
/// applies exactly and the only inexactness is the fixed-point evaluation whose
/// bound is stated in the module documentation: at most 1 ppm, and never above
/// the exact value.
///
/// # Errors
///
/// Returns [`ExpectedLossRefusal`] when the peak term is unrepresentable at
/// this scale, or when the term count exceeds [`MAX_TERMS`].
pub fn probability_b_exceeds_a_ppm(a: Posterior, b: Posterior) -> Result<u32, ExpectedLossRefusal> {
    let (alpha_a, beta_a) = (a.alpha(), a.beta());
    let (alpha_b, beta_b) = (b.alpha(), b.beta());

    if alpha_b > MAX_TERMS {
        return Err(ExpectedLossRefusal::TooManyTerms {
            offered: alpha_b,
            maximum: MAX_TERMS,
        });
    }

    let peak = peak_index(alpha_a, beta_a, alpha_b, beta_b);
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
        value = mul_div(value, denominator, numerator);
        if value == 0 {
            break;
        }
        total = total.saturating_add(value);
    }

    // Upward from the peak.
    value = peak_value;
    for index in peak..alpha_b.saturating_sub(1) {
        let (numerator, denominator) = ratio(alpha_a, beta_a, beta_b, index);
        value = mul_div(value, numerator, denominator);
        if value == 0 {
            break;
        }
        total = total.saturating_add(value);
    }

    let ppm = total.saturating_mul(PARTS_PER_MILLION) / ONE;
    Ok(u32::try_from(ppm.min(PARTS_PER_MILLION)).unwrap_or(u32::MAX))
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

/// `value * numerator / denominator`, refusing to wrap.
///
/// Saturation rather than wrapping: a wrapped term would re-enter the sum as a
/// plausible value, which is the failure class this whole module exists to
/// avoid.
fn mul_div(value: u128, numerator: u128, denominator: u128) -> u128 {
    value.checked_mul(numerator).map_or_else(
        || (value / denominator).saturating_mul(numerator),
        |scaled| scaled / denominator,
    )
}
