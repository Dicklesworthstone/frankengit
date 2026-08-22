//! Known-answer tests for off-policy evaluation and its two gates.
//!
//! The effective sample sizes below are hand-computed from
//! `ESS = (sum w)^2 / sum w^2`. The pair that matters is the uniform batch,
//! whose ESS equals its sample count, against the concentrated batch, whose ESS
//! collapses to one while still containing ten samples. An estimator without the
//! ESS gate returns a confident-looking average for the second.

use fgit_statistics::off_policy::{
    LoggedSample, OffPolicyConfig, OffPolicyEvaluator, OpeAssumptionFailure, OpeRefusal,
};

const HALF: u32 = 500_000;
const ONE: u32 = 1_000_000;

fn config() -> OffPolicyConfig {
    OffPolicyConfig {
        min_behavior_parts_per_million: 1_000,
        max_behavior_parts_per_million: ONE,
        min_effective_sample_size: 5,
    }
}

fn evaluator() -> OffPolicyEvaluator {
    OffPolicyEvaluator::new(config()).expect("assumptions hold")
}

fn sample(behavior: u32, target: u32, reward: i64) -> LoggedSample {
    LoggedSample {
        behavior_parts_per_million: behavior,
        target_parts_per_million: target,
        reward,
    }
}

// ------------------------------------------------------- the uniform baseline

#[test]
fn a_uniform_batch_has_an_effective_size_equal_to_its_sample_count() {
    // Every weight is 500_000 * 1_000_000 / 500_000 = 1_000_000, so
    // ESS = (10 * 1e6)^2 / (10 * 1e12) = 1e14 / 1e13 = 10.
    let samples: Vec<LoggedSample> = (0..10).map(|_| sample(HALF, HALF, 7)).collect();
    let estimate = evaluator().evaluate(&samples).expect("gates pass");

    assert_eq!(
        estimate.effective_sample_size, 10,
        "equal weights must give back the sample count, or the ESS formula is wrong in a way that \
         would make every later comparison meaningless"
    );
    assert_eq!(estimate.samples, 10);
    assert_eq!(
        estimate.value, 7,
        "with equal weights the self-normalised estimate is the plain mean"
    );
}

#[test]
fn the_estimate_truncates_deterministically_rather_than_rounding() {
    // Rewards 1..=10 under equal weights average 5.5. Integer division truncates
    // to 5, identically on every target. Pinned so the behaviour is a documented
    // property rather than a surprise at an integration.
    let samples: Vec<LoggedSample> = (1..=10).map(|reward| sample(HALF, HALF, reward)).collect();
    let estimate = evaluator().evaluate(&samples).expect("gates pass");
    assert_eq!(estimate.value, 5);
}

#[test]
fn importance_weighting_actually_reweights() {
    // The presence case for the mechanism itself. Two samples with equal
    // behaviour propensity but very different target propensities: the naive
    // mean is 50, the importance-weighted estimate is 90.
    //
    // w_a = 900_000 * 1e6 / 500_000 = 1_800_000; w_b = 200_000.
    // value = (1_800_000 * 100 + 200_000 * 0) / 2_000_000 = 90.
    let mut config = config();
    config.min_effective_sample_size = 1;
    let evaluator = OffPolicyEvaluator::new(config).expect("assumptions hold");

    let samples = vec![sample(HALF, 900_000, 100), sample(HALF, 100_000, 0)];
    let estimate = evaluator.evaluate(&samples).expect("gates pass");
    assert_eq!(
        estimate.value, 90,
        "an estimate equal to the naive mean of 50 would mean the weights were never applied"
    );
}

// ------------------------------------------------------------ the ESS gate

#[test]
fn a_concentrated_batch_is_refused_even_though_every_sample_is_in_support() {
    // Ten samples, all inside the declared support, but one at the floor
    // dominates: w_0 = 1e6 * 1e6 / 1_000 = 1e9 against nine weights of 1e6.
    //
    // sum w   = 1_009_000_000
    // sum w^2 = 1e18 + 9e12 = 1_000_009_000_000_000_000
    // ESS     = 1_018_081e12 / 1_000_009e12 = 1
    //
    // This is the failure the gate exists for: nothing about a returned average
    // would reveal that it rests on one observation.
    let mut samples = vec![sample(1_000, ONE, 1_000)];
    samples.extend((0..9).map(|_| sample(ONE, ONE, 0)));

    assert_eq!(
        evaluator().evaluate(&samples),
        Err(OpeRefusal::EffectiveSampleTooSmall {
            effective: 1,
            required: 5
        })
    );

    // The permitted twin: the same ten samples with uniform propensities pass,
    // so the refusal is about concentration and not about the batch size.
    let uniform: Vec<LoggedSample> = (0..10).map(|_| sample(ONE, ONE, 0)).collect();
    assert!(evaluator().evaluate(&uniform).is_ok());
}

#[test]
fn the_ess_gate_is_a_threshold_and_not_a_blanket_refusal() {
    // ESS of a uniform batch is exactly its size, so a batch of five passes a
    // requirement of five and a batch of four does not. The boundary is where an
    // off-by-one in the comparison would live.
    let five: Vec<LoggedSample> = (0..5).map(|_| sample(HALF, HALF, 3)).collect();
    let estimate = evaluator()
        .evaluate(&five)
        .expect("exactly at the threshold");
    assert_eq!(estimate.effective_sample_size, 5);

    let four: Vec<LoggedSample> = (0..4).map(|_| sample(HALF, HALF, 3)).collect();
    assert_eq!(
        evaluator().evaluate(&four),
        Err(OpeRefusal::EffectiveSampleTooSmall {
            effective: 4,
            required: 5
        })
    );
}

// -------------------------------------------------------- the support gate

#[test]
fn a_propensity_below_the_support_floor_is_refused_by_index() {
    let mut samples: Vec<LoggedSample> = (0..9).map(|_| sample(ONE, ONE, 1)).collect();
    samples.push(sample(999, ONE, 1));

    assert_eq!(
        evaluator().evaluate(&samples),
        Err(OpeRefusal::OutsideSupport {
            index: 9,
            behavior_parts_per_million: 999
        }),
        "the index must be named, or a caller cannot find which logged sample is bad"
    );

    // The permitted twin, one part per million higher: exactly at the floor is
    // in support, so the gate is a bound rather than a blanket refusal.
    let mut boundary: Vec<LoggedSample> = (0..9).map(|_| sample(ONE, ONE, 1)).collect();
    boundary.push(sample(1_000, 1, 1));
    assert!(evaluator().evaluate(&boundary).is_ok());
}

#[test]
fn a_zero_propensity_is_caught_by_the_gate_and_never_divides() {
    // A logged propensity of zero means the behaviour policy could not have
    // taken the action. Without the gate this is a division by zero; with it,
    // it is a refusal naming the sample.
    let samples = vec![sample(0, ONE, 1)];
    assert_eq!(
        evaluator().evaluate(&samples),
        Err(OpeRefusal::OutsideSupport {
            index: 0,
            behavior_parts_per_million: 0
        })
    );
}

#[test]
fn a_target_propensity_above_one_is_refused() {
    let samples = vec![sample(HALF, ONE + 1, 1)];
    assert_eq!(
        evaluator().evaluate(&samples),
        Err(OpeRefusal::TargetAboveOne {
            index: 0,
            target_parts_per_million: ONE + 1
        })
    );

    // The permitted twin: exactly one is a probability.
    let ok: Vec<LoggedSample> = (0..10).map(|_| sample(HALF, ONE, 1)).collect();
    assert!(evaluator().evaluate(&ok).is_ok());
}

#[test]
fn the_support_gate_runs_before_any_accumulation() {
    // An out-of-support sample must not reach the totals. If it did, the batch
    // could be reported as an ESS failure -- a plausible-sounding refusal for
    // the wrong reason, which would send a caller looking at batch size instead
    // of at the one bad propensity.
    let mut samples = vec![sample(1, ONE, 1)];
    samples.extend((0..3).map(|_| sample(ONE, ONE, 1)));
    assert_eq!(
        evaluator().evaluate(&samples),
        Err(OpeRefusal::OutsideSupport {
            index: 0,
            behavior_parts_per_million: 1
        }),
        "a four-sample batch would also fail the ESS gate; the support failure must win because it \
         is the actionable one"
    );
}

// --------------------------------------------------------- degenerate cases

#[test]
fn an_empty_batch_is_refused() {
    assert_eq!(evaluator().evaluate(&[]), Err(OpeRefusal::Empty));
}

#[test]
fn a_batch_the_target_policy_would_never_produce_is_refused() {
    // Every target propensity zero: the batch is entirely in support and says
    // nothing whatever about the target policy. Dividing by the zero total would
    // be a panic; reporting zero would be a confident answer about nothing.
    let samples: Vec<LoggedSample> = (0..10).map(|_| sample(ONE, 0, 5)).collect();
    assert_eq!(
        evaluator().evaluate(&samples),
        Err(OpeRefusal::ZeroTotalWeight)
    );
}

// ------------------------------------------------- executable assumptions

#[test]
fn a_zero_support_floor_is_refused_and_a_positive_one_is_admitted() {
    let mut bad = config();
    bad.min_behavior_parts_per_million = 0;
    assert_eq!(
        OffPolicyEvaluator::new(bad).err(),
        Some(OpeAssumptionFailure::SupportFloorZero),
        "a zero floor admits an unbounded weight, which is what the gate exists to prevent"
    );

    bad.min_behavior_parts_per_million = 1;
    assert!(OffPolicyEvaluator::new(bad).is_ok());
}

#[test]
fn an_inverted_or_impossible_support_range_is_refused() {
    let mut inverted = config();
    inverted.min_behavior_parts_per_million = 900_000;
    inverted.max_behavior_parts_per_million = 100_000;
    assert_eq!(
        OffPolicyEvaluator::new(inverted).err(),
        Some(OpeAssumptionFailure::SupportRangeInverted {
            min: 900_000,
            max: 100_000
        })
    );

    let mut above_one = config();
    above_one.max_behavior_parts_per_million = ONE + 1;
    assert_eq!(
        OffPolicyEvaluator::new(above_one).err(),
        Some(OpeAssumptionFailure::SupportCeilingAboveOne { max: ONE + 1 })
    );

    let mut zero_ess = config();
    zero_ess.min_effective_sample_size = 0;
    assert_eq!(
        OffPolicyEvaluator::new(zero_ess).err(),
        Some(OpeAssumptionFailure::EffectiveSampleSizeZero),
        "requiring an effective size of zero disables the gate while appearing to configure it"
    );

    // The permitted twin for all three.
    assert!(OffPolicyEvaluator::new(config()).is_ok());
}

#[test]
fn the_declared_floor_bounds_the_largest_weight() {
    // The property that makes accumulator capacity checkable rather than hoped
    // for: max weight is 1e12 / floor.
    assert_eq!(evaluator().max_weight(), 1_000_000_000);

    let mut tight = config();
    tight.min_behavior_parts_per_million = ONE;
    assert_eq!(
        OffPolicyEvaluator::new(tight)
            .expect("assumptions hold")
            .max_weight(),
        1_000_000,
        "a floor of one admits a weight of at most one"
    );
}

// --------------------------------------------------------------- determinism

#[test]
fn the_same_batch_evaluates_identically_every_time() {
    let samples: Vec<LoggedSample> = (1..=20)
        .map(|index| sample(HALF, 400_000 + index as u32 * 1_000, index))
        .collect();
    let first = evaluator().evaluate(&samples);
    for _ in 0..50 {
        assert_eq!(evaluator().evaluate(&samples), first);
    }
    assert!(first.is_ok(), "the fixture must exercise the passing path");
}

#[test]
fn an_accumulator_that_would_overflow_is_refused_rather_than_saturated() {
    // Reachable, and computed rather than guessed: with a support floor of one
    // part per million every weight is 1e12, so 100_000 samples give
    // sum w^2 = 1e29. Multiplying that by a required effective size of
    // u32::MAX gives ~4.29e38, past the u128 ceiling of ~3.40e38.
    //
    // Saturating instead would silently change the comparison the ESS gate
    // makes, turning a refusal into a pass for an arithmetic reason.
    let config = OffPolicyConfig {
        min_behavior_parts_per_million: 1,
        max_behavior_parts_per_million: ONE,
        min_effective_sample_size: u32::MAX,
    };
    let evaluator = OffPolicyEvaluator::new(config).expect("assumptions hold");
    let samples: Vec<LoggedSample> = (0..100_000).map(|_| sample(1, ONE, 1)).collect();

    assert_eq!(
        evaluator.evaluate(&samples),
        Err(OpeRefusal::AccumulatorOverflow)
    );

    // The permitted twin: the same batch under an ordinary required size does
    // not overflow, so the refusal is about capacity and not about batch size.
    let modest = OffPolicyConfig {
        min_effective_sample_size: 10,
        ..config
    };
    let evaluator = OffPolicyEvaluator::new(modest).expect("assumptions hold");
    let estimate = evaluator.evaluate(&samples).expect("no overflow");
    assert_eq!(estimate.samples, 100_000);
    assert_eq!(
        estimate.effective_sample_size, 100_000,
        "uniform weights, so the effective size is the sample count"
    );
}
