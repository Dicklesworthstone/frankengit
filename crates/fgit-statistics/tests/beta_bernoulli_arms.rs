//! Known-answer tests for Beta-Bernoulli posteriors and the arm comparison.
//!
//! Every mean below was computed independently from `alpha / (alpha + beta)` in
//! parts per million before being asserted.
//!
//! The test that matters most is
//! `a_confident_looking_prior_with_no_trials_is_refused`: a `Beta(90, 10)` prior
//! reports a posterior mean of 900_000 after zero observations. Nothing about
//! that number distinguishes it from the same value after ten thousand trials,
//! which is exactly why the comparison counts trials rather than pseudo-counts.

use fgit_statistics::beta_bernoulli::{
    ArmComparison, ArmVerdict, BetaAssumptionFailure, BetaPrior, BetaRefusal, Outcomes,
};

fn outcomes(successes: u32, trials: u32) -> Outcomes {
    Outcomes { successes, trials }
}

fn comparison() -> ArmComparison {
    ArmComparison {
        min_trials_per_arm: 100,
        indifference_margin: 10_000,
    }
}

// -------------------------------------------------------------- posteriors

#[test]
fn the_posterior_mean_matches_the_hand_computed_ratio() {
    let prior = BetaPrior::uniform();

    // Beta(1,1): 1 / 2 = 500_000 ppm.
    let empty = prior.update(outcomes(0, 0)).expect("valid counts");
    assert_eq!(empty.mean_parts_per_million(), 500_000);
    assert_eq!((empty.alpha(), empty.beta()), (1, 1));

    // Beta(8,4): 8 / 12 = 666_666 ppm after truncation.
    let mixed = prior.update(outcomes(7, 10)).expect("valid counts");
    assert_eq!(mixed.mean_parts_per_million(), 666_666);
    assert_eq!((mixed.alpha(), mixed.beta()), (8, 4));

    // The two extremes stay strictly inside (0, 1), which is what the prior is
    // for: no amount of evidence makes a Beta posterior certain.
    let all = prior.update(outcomes(10, 10)).expect("valid counts");
    assert_eq!(all.mean_parts_per_million(), 916_666);
    let none = prior.update(outcomes(0, 10)).expect("valid counts");
    assert_eq!(none.mean_parts_per_million(), 83_333);
    assert!(all.mean_parts_per_million() < 1_000_000);
    assert!(none.mean_parts_per_million() > 0);
}

#[test]
fn the_trial_count_excludes_the_priors_pseudo_counts() {
    // The property the evidence gate depends on. If trials() counted the prior,
    // a strong prior would let an arm with no data claim a large sample.
    let strong = BetaPrior::try_new(90, 10).expect("proper");
    let posterior = strong.update(outcomes(0, 0)).expect("valid counts");
    assert_eq!(posterior.alpha(), 90);
    assert_eq!(posterior.beta(), 10);
    assert_eq!(
        posterior.trials(),
        0,
        "the prior contributes belief, not evidence"
    );

    let after = strong.update(outcomes(3, 7)).expect("valid counts");
    assert_eq!(after.trials(), 7);
}

#[test]
fn more_successes_than_trials_is_refused_rather_than_clamped() {
    let prior = BetaPrior::uniform();
    assert_eq!(
        prior.update(outcomes(5, 3)),
        Err(BetaRefusal::MoreSuccessesThanTrials {
            successes: 5,
            trials: 3
        }),
        "the caller's counting is wrong, and a clamped posterior would carry that error forward"
    );

    // The permitted twin, including the boundary where every trial succeeded.
    assert!(prior.update(outcomes(3, 3)).is_ok());
    assert!(prior.update(outcomes(0, 3)).is_ok());
}

// -------------------------------------------------------- the evidence gate

#[test]
fn a_confident_looking_prior_with_no_trials_is_refused() {
    // Beta(90, 10) reports a posterior mean of 900_000 after zero observations.
    // The number is indistinguishable from the same value after ten thousand
    // trials, and a comparison on means alone would rank this arm first.
    let strong = BetaPrior::try_new(90, 10).expect("proper");
    let confident = strong.update(outcomes(0, 0)).expect("valid counts");
    assert_eq!(
        confident.mean_parts_per_million(),
        900_000,
        "the mean really does look excellent, which is the whole problem"
    );

    let evidenced = BetaPrior::uniform()
        .update(outcomes(600, 1_000))
        .expect("valid counts");

    assert_eq!(
        comparison().compare(confident, evidenced),
        Err(BetaRefusal::InsufficientEvidence {
            observed: 0,
            required: 100
        }),
        "the thinner arm must be named, since it is the one needing data"
    );
}

#[test]
fn the_evidence_gate_is_a_threshold_and_not_a_blanket_refusal() {
    let prior = BetaPrior::uniform();
    let thick = prior.update(outcomes(700, 1_000)).expect("valid counts");

    // Exactly at the threshold is admitted.
    let boundary = prior.update(outcomes(50, 100)).expect("valid counts");
    assert!(
        comparison().compare(thick, boundary).is_ok(),
        "100 trials must satisfy a requirement of 100"
    );

    // One short is not.
    let short = prior.update(outcomes(50, 99)).expect("valid counts");
    assert_eq!(
        comparison().compare(thick, short),
        Err(BetaRefusal::InsufficientEvidence {
            observed: 99,
            required: 100
        })
    );
}

// ------------------------------------------------------------ the verdict

#[test]
fn a_clearly_better_candidate_is_preferred_by_its_exact_margin() {
    // Beta(701,301) = 699_600 ppm against Beta(601,401) = 599_800 ppm.
    let prior = BetaPrior::uniform();
    let candidate = prior.update(outcomes(700, 1_000)).expect("valid counts");
    let fallback = prior.update(outcomes(600, 1_000)).expect("valid counts");

    let verdict = comparison()
        .compare(candidate, fallback)
        .expect("both arms have evidence");
    assert_eq!(verdict, ArmVerdict::CandidatePreferred { margin: 99_800 });
    assert!(verdict.admits_candidate());

    // And the comparison is not one-sided: swapping the arms swaps the verdict.
    let reversed = comparison()
        .compare(fallback, candidate)
        .expect("both arms have evidence");
    assert_eq!(reversed, ArmVerdict::FallbackPreferred { margin: 99_800 });
    assert!(!reversed.admits_candidate());
}

#[test]
fn arms_inside_the_indifference_margin_are_not_ranked() {
    // Beta(502,500) = 500_998 ppm against Beta(501,501) = 500_000 ppm: a
    // difference of 998, well inside the 10_000 margin. Ranking on this would
    // make a controller switch policies on noise.
    let prior = BetaPrior::uniform();
    let candidate = prior.update(outcomes(501, 1_000)).expect("valid counts");
    let fallback = prior.update(outcomes(500, 1_000)).expect("valid counts");

    let verdict = comparison()
        .compare(candidate, fallback)
        .expect("both arms have evidence");
    assert_eq!(verdict, ArmVerdict::Indistinguishable { difference: 998 });
    assert!(
        !verdict.admits_candidate(),
        "with no demonstrated advantage the pinned deterministic policy is the one to keep; \
         switching on a tie is adaptation with nothing behind it"
    );
}

#[test]
fn the_margin_boundary_is_inclusive_on_the_preferred_side() {
    // A difference of exactly the margin prefers the candidate; one less does
    // not. This is where an off-by-one would live, and it decides whether a
    // controller adapts at precisely the difference it declared meaningful.
    let prior = BetaPrior::uniform();
    let fallback = prior.update(outcomes(500, 1_000)).expect("valid counts");
    let fallback_mean = fallback.mean_parts_per_million();

    let tight = ArmComparison {
        min_trials_per_arm: 100,
        indifference_margin: 998,
    };
    let candidate = prior.update(outcomes(501, 1_000)).expect("valid counts");
    assert_eq!(
        candidate.mean_parts_per_million() - fallback_mean,
        998,
        "the fixture must sit exactly on the margin"
    );
    assert_eq!(
        tight.compare(candidate, fallback),
        Ok(ArmVerdict::CandidatePreferred { margin: 998 })
    );

    let just_over = ArmComparison {
        min_trials_per_arm: 100,
        indifference_margin: 999,
    };
    assert_eq!(
        just_over.compare(candidate, fallback),
        Ok(ArmVerdict::Indistinguishable { difference: 998 })
    );
}

#[test]
fn two_identical_arms_are_indistinguishable_with_a_zero_difference() {
    // The degenerate case, and the absence half for the ranking tests: equal
    // evidence must not produce a preference in either direction.
    let prior = BetaPrior::uniform();
    let arm = prior.update(outcomes(500, 1_000)).expect("valid counts");
    assert_eq!(
        comparison().compare(arm, arm),
        Ok(ArmVerdict::Indistinguishable { difference: 0 })
    );
}

// ------------------------------------------------- executable assumptions

#[test]
fn an_improper_prior_cannot_be_constructed() {
    assert_eq!(
        BetaPrior::try_new(0, 1),
        Err(BetaAssumptionFailure::AlphaZero),
        "with alpha zero, no evidence could ever move the posterior up from a single failure"
    );
    assert_eq!(
        BetaPrior::try_new(1, 0),
        Err(BetaAssumptionFailure::BetaZero)
    );

    // The permitted twin, and the smallest proper prior.
    let smallest = BetaPrior::try_new(1, 1).expect("proper");
    assert_eq!(smallest, BetaPrior::uniform());
    assert_eq!((smallest.alpha(), smallest.beta()), (1, 1));
}

// --------------------------------------------------------------- determinism

#[test]
fn the_same_counts_produce_the_same_posterior_every_time() {
    let prior = BetaPrior::try_new(3, 7).expect("proper");
    let first = prior.update(outcomes(37, 91)).expect("valid counts");
    for _ in 0..100 {
        assert_eq!(prior.update(outcomes(37, 91)), Ok(first));
    }
    // Beta(40, 61): 40 / 101 = 396_039 ppm.
    assert_eq!(first.mean_parts_per_million(), 396_039);
}
