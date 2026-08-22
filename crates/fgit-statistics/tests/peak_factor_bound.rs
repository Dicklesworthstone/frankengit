//! The peak term's factor runs are bounded before they are materialized.
//!
//! Fresh-eyes review found that [`probability_b_exceeds_a_ppm`] and
//! [`compare_ppm`] bounded only their walk length (`MAX_TERMS`, linear in the
//! alphas) while `peak_term` materialized two factor vectors whose combined
//! length is linear in the BETA parameters too. Both counts come from checked
//! constructors, so an admitted posterior — billions of observed failures —
//! could demand tens of gigabytes of factors on a policy path before any
//! arithmetic ran.
//!
//! The fix is a pre-allocation count (`peak_factor_count`) refused by
//! [`ExpectedLossRefusal::TooManyPeakFactors`] above [`MAX_PEAK_FACTORS`].
//! These tests pin the two properties that make that fix honest: the
//! admitted-but-huge regime refuses promptly instead of allocating, and the
//! ordinary regime still answers exactly as before.

use fgit_statistics::beta_bernoulli::{BetaPrior, Outcomes, Posterior};
use fgit_statistics::expected_loss::{
    ExpectedLossRefusal, MAX_PEAK_FACTORS, compare_ppm, probability_b_exceeds_a_ppm,
};

fn posterior(alpha: u32, beta: u32) -> Posterior {
    BetaPrior::try_new(alpha, beta)
        .expect("a proper prior")
        .update(Outcomes {
            successes: 0,
            trials: 0,
        })
        .expect("zero observations update cleanly")
}

#[test]
fn an_admitted_huge_beta_refuses_by_factor_count_instead_of_allocating() {
    // Both alphas are inside MAX_TERMS, so the old guard admitted this pair;
    // beta_a alone contributes ~3e9 numerator factors, which must be counted
    // and refused BEFORE any vector is reserved. This test doubles as the
    // proof of promptness: it completes only because the refusal precedes
    // the allocation it names.
    let refusal = probability_b_exceeds_a_ppm(posterior(1, 3_000_000_000), posterior(2, 2));
    assert!(matches!(
        refusal,
        Err(ExpectedLossRefusal::TooManyPeakFactors { offered, maximum })
            if offered >= 3_000_000_000 && maximum == MAX_PEAK_FACTORS
    ));
}

#[test]
fn both_entry_points_share_the_peak_factor_bound() {
    // Small alphas so the MAX_TERMS walk guard admits the pair, huge betas
    // so only the peak-factor gate can answer it.
    let a = posterior(1, u32::MAX);
    let b = posterior(2, 2);
    for (name, result) in [
        (
            "probability_b_exceeds_a_ppm",
            probability_b_exceeds_a_ppm(a, b),
        ),
        (
            "compare_ppm",
            compare_ppm(a, b).map(|pair| pair.b_exceeds_a_ppm()),
        ),
    ] {
        assert!(
            matches!(result, Err(ExpectedLossRefusal::TooManyPeakFactors { .. })),
            "{name} answered or refused for a different reason at the u32::MAX parameter extreme"
        );
    }
}

#[test]
fn the_ordinary_regime_still_answers() {
    // Far below the bound: every parameter set in the measured 500-set oracle
    // corpus sits in this regime, and none may change behaviour because the
    // new gate exists.
    let answered = probability_b_exceeds_a_ppm(posterior(3, 4), posterior(5, 2))
        .expect("an ordinary comparison is unaffected by the factor-count gate");
    assert_eq!(answered, 878_787);
    let paired = compare_ppm(posterior(3, 4), posterior(5, 2)).expect("paired answer survives");
    assert!(paired.sums_to_one_million());
}
