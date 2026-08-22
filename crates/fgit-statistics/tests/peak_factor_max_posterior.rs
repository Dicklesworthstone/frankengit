#![forbid(unsafe_code)]

//! The factor-count bound covers the largest posterior Beta count the public
//! constructor admits, not merely the largest prior count.

use fgit_statistics::beta_bernoulli::{BetaPrior, Outcomes};
use fgit_statistics::expected_loss::{
    ExpectedLossRefusal, MAX_PEAK_FACTORS, compare_ppm, probability_b_exceeds_a_ppm,
};

fn posterior(
    alpha: u32,
    beta: u32,
    outcomes: Outcomes,
) -> fgit_statistics::beta_bernoulli::Posterior {
    BetaPrior::try_new(alpha, beta)
        .expect("a proper prior")
        .update(outcomes)
        .expect("valid observed outcomes")
}

#[test]
fn the_largest_admitted_beta_is_refused_before_peak_factor_allocation() {
    // `Posterior::beta` is wider than `BetaPrior::beta`: a maximum prior plus
    // maximum observed failures reaches almost 2^33.  The bounded alpha walk
    // still admits this input, so the factor-count refusal is the only safe
    // exit before `peak_term` would materialize multi-gigabyte factor lists.
    let a = posterior(
        1,
        u32::MAX,
        Outcomes {
            successes: 0,
            trials: u32::MAX,
        },
    );
    assert_eq!(a.beta(), u64::from(u32::MAX) * 2);
    let b = posterior(
        2,
        2,
        Outcomes {
            successes: 0,
            trials: 0,
        },
    );

    for (name, result) in [
        (
            "probability_b_exceeds_a_ppm",
            probability_b_exceeds_a_ppm(a, b),
        ),
        (
            "compare_ppm",
            compare_ppm(a, b).map(|comparison| comparison.b_exceeds_a_ppm()),
        ),
    ] {
        assert!(
            matches!(
                result,
                Err(ExpectedLossRefusal::TooManyPeakFactors { offered, maximum })
                    if offered > u64::from(u32::MAX) && maximum == MAX_PEAK_FACTORS
            ),
            "{name} must refuse the largest admitted posterior before factor allocation"
        );
    }
}
