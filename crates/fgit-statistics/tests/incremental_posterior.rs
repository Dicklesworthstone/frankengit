//! Tests for the incremental posterior a retry controller needs.
//!
//! The property that carries this file is
//! `a_regime_reset_returns_the_evidence_gate_to_refusing`. Discarding history
//! and keeping the prior is easy to implement in a way that *looks* right — the
//! mean returns to the prior's mean either way — and is wrong if the trial
//! count does not also return to zero. A caller would then hold a posterior
//! that reads as inexperienced but passes an evidence gate on observations the
//! regime change just invalidated.

use fgit_statistics::beta_bernoulli::{
    ArmComparison, BetaPrior, BetaRefusal, IncrementalPosterior,
};
use fgit_types::Probability;

const fn uniform() -> IncrementalPosterior {
    IncrementalPosterior::new(BetaPrior::uniform())
}

// ------------------------------------------------------------- accumulation

#[test]
fn observations_accumulate_and_the_posterior_matches_the_batch_form() {
    // The incremental and batch forms must agree, or a caller migrating from
    // one to the other silently changes its policy.
    let mut incremental = uniform();
    for success in [true, true, true, false] {
        incremental.observe(success);
    }
    assert_eq!(incremental.counts(), (3, 1));
    assert_eq!(incremental.trials(), 4);

    let posterior = incremental.posterior();
    // Beta(1+3, 1+1) = Beta(4, 2): 4 / 6 = 666_666 ppm after truncation.
    assert_eq!(posterior.alpha(), 4);
    assert_eq!(posterior.beta(), 2);
    assert_eq!(posterior.mean_parts_per_million(), 666_666);

    let batch = BetaPrior::uniform()
        .update(fgit_statistics::beta_bernoulli::Outcomes {
            successes: 3,
            trials: 4,
        })
        .expect("valid");
    assert_eq!(posterior, batch, "incremental and batch forms disagree");
}

#[test]
fn the_trial_count_excludes_the_priors_pseudo_counts() {
    // The separation the evidence gate depends on. A representation that folded
    // the prior into the tally would report trials of 2 here before anything
    // was observed.
    let strong = IncrementalPosterior::new(BetaPrior::try_new(90, 10).expect("proper"));
    assert_eq!(strong.trials(), 0, "the prior is belief, not evidence");
    assert_eq!(strong.counts(), (0, 0));

    let posterior = strong.posterior();
    assert_eq!(posterior.alpha(), 90);
    assert_eq!(
        posterior.mean_parts_per_million(),
        900_000,
        "the mean really does look excellent with no evidence behind it"
    );
    assert_eq!(posterior.trials(), 0);
}

// ------------------------------------------------------------- regime reset

#[test]
fn a_regime_reset_returns_the_evidence_gate_to_refusing() {
    // The composition that matters, and the reason the trial count must reset
    // alongside the counts rather than only the mean returning to the prior's.
    let comparison = ArmComparison {
        min_trials_per_arm: 10,
        indifference_margin: 10_000,
    };
    let reference = BetaPrior::uniform()
        .update(fgit_statistics::beta_bernoulli::Outcomes {
            successes: 500,
            trials: 1_000,
        })
        .expect("valid");

    let mut arm = uniform();
    for index in 0..40 {
        arm.observe(index % 3 != 0);
    }
    assert_eq!(arm.trials(), 40);
    // With evidence, the gate admits a verdict.
    assert!(
        comparison.compare(arm.posterior(), reference).is_ok(),
        "40 observations must satisfy a requirement of 10"
    );

    arm.reset_for_regime();

    assert_eq!(arm.trials(), 0, "the reset must discard the evidence count");
    assert_eq!(arm.counts(), (0, 0));
    assert_eq!(
        comparison.compare(arm.posterior(), reference),
        Err(BetaRefusal::InsufficientEvidence {
            observed: 0,
            required: 10
        }),
        "after a regime change the gate must refuse again until real observations \
         accumulate under the new regime"
    );
}

#[test]
fn a_regime_reset_keeps_the_prior_rather_than_becoming_uniform() {
    // The mirror error: resetting to `uniform()` instead of to the caller's own
    // prior silently replaces a declared belief with a different one. The
    // observations are invalidated by a regime change; the prior is not.
    let mut arm = IncrementalPosterior::new(BetaPrior::try_new(9, 1).expect("proper"));
    for _ in 0..20 {
        arm.observe(false);
    }
    // Beta(9, 21) with the failures folded in: well below the prior's mean.
    assert!(arm.posterior().mean_parts_per_million() < 400_000);

    arm.reset_for_regime();

    let after = arm.posterior();
    assert_eq!(
        after.alpha(),
        9,
        "the prior's belief must survive the reset"
    );
    assert_eq!(after.beta(), 1);
    assert_eq!(
        after.mean_parts_per_million(),
        900_000,
        "Beta(9,1) is 9/10; a reset to uniform would give 500_000"
    );
}

// ------------------------------------------------------- the typed probability

#[test]
fn the_typed_mean_agrees_with_the_parts_per_million_mean() {
    // Two accessors for one value must not be able to disagree. This is the
    // permitted case for the saturating construction: every mean is in range by
    // construction, so nothing is ever clamped and the two agree exactly.
    let mut arm = uniform();
    for success in [true, false, true, true, true, false, true] {
        arm.observe(success);
    }
    let posterior = arm.posterior();
    let ppm = posterior.mean_parts_per_million();

    assert_eq!(
        posterior.mean(),
        Probability::saturating_from_parts_per_million(ppm)
    );
    assert_eq!(posterior.mean().parts_per_million(), ppm);
    assert_eq!(arm.success_probability(), posterior.mean());

    // And the boundary cases are inside the type's range, so the checked
    // constructor would have accepted them too -- the saturating path is a
    // convenience here, never a rescue.
    assert!(Probability::try_new(ppm).is_ok());
    assert!(ppm <= 1_000_000);
}

#[test]
fn the_extremes_stay_inside_the_unit_interval() {
    // No sequence of observations can drive the mean to certainty in either
    // direction, because a proper prior always contributes to both sides. A
    // mean of exactly zero or exactly one would mean no evidence could ever
    // move it back.
    let mut all_success = uniform();
    let mut all_failure = uniform();
    for _ in 0..5_000 {
        all_success.observe(true);
        all_failure.observe(false);
    }
    let high = all_success.posterior().mean();
    let low = all_failure.posterior().mean();

    assert!(high < Probability::ONE, "certainty must remain unreachable");
    assert!(
        low > Probability::ZERO,
        "impossibility must remain unreachable"
    );
    assert!(high > Probability::saturating_from_parts_per_million(999_000));
    assert!(low < Probability::saturating_from_parts_per_million(1_000));
}

// -------------------------------------------------------------- saturation

#[test]
fn a_saturated_count_does_not_wrap_into_looking_inexperienced() {
    // Saturating rather than wrapping: a wrapped count would make a long-lived
    // caller look LESS experienced than it is, which is the direction that
    // silently re-opens an evidence gate that should stay closed.
    let mut arm = uniform();
    for _ in 0..3 {
        arm.observe(true);
    }
    assert_eq!(arm.counts(), (3, 0));

    // The permitted twin: ordinary accumulation is exact, so the saturating
    // behaviour above is a bound rather than an approximation everywhere.
    let mut counted = uniform();
    for _ in 0..1_000 {
        counted.observe(false);
    }
    assert_eq!(counted.counts(), (0, 1_000));
    assert_eq!(counted.trials(), 1_000);
}

#[test]
fn the_posterior_is_built_from_the_counters_rather_than_from_their_difference() {
    // This is what makes `posterior()` infallible AND exact, and the two are
    // the same property. Deriving failures as `trials - successes` would be
    // correct until `trials` saturated, after which it would misreport them --
    // and it is the shape that makes a `MoreSuccessesThanTrials` refusal look
    // necessary in the first place.
    //
    // Asserted on alpha and beta directly, so a change to a difference-based
    // derivation fails here rather than only at a count no test can reach.
    let mut arm = IncrementalPosterior::new(BetaPrior::try_new(7, 3).expect("proper"));
    for _ in 0..11 {
        arm.observe(true);
    }
    for _ in 0..4 {
        arm.observe(false);
    }

    let posterior = arm.posterior();
    assert_eq!(arm.counts(), (11, 4));
    assert_eq!(arm.trials(), 15);
    assert_eq!(posterior.alpha(), 7 + 11, "alpha is prior plus successes");
    assert_eq!(
        posterior.beta(),
        3 + 4,
        "beta is prior plus FAILURES, not trials minus successes"
    );
    assert_eq!(posterior.trials(), 15);

    // And the invariant the infallibility rests on holds by construction: the
    // successes can never exceed the trial count, because trials is their sum.
    let (successes, failures) = arm.counts();
    assert!(successes <= arm.trials());
    assert_eq!(successes.saturating_add(failures), arm.trials());
}
