//! Property tests over seeded streams, covering the bead's test-plan line about
//! seeded distributions.
//!
//! The known-answer tests elsewhere pin what each mechanism does on a handful of
//! hand-traced cases. They cannot catch an invariant that holds on those cases
//! and breaks on the tenth thousand — an accumulator that goes negative only
//! after a particular run of values, an effective sample size that exceeds its
//! own batch, a surviving arm set that empties. Each test below states a
//! property that must hold on **every** stream and then drives thousands of
//! seeded observations at it.
//!
//! # The generator is an integer LCG, and it is not a distribution claim
//!
//! [`Lcg`] is a Lehmer-style linear congruential generator over wrapping `u64`
//! arithmetic. It is here to produce a *reproducible spread of values*, not to
//! model any distribution — no test below asserts anything about the shape of
//! the stream, only about the mechanism's response to it. Calling it a
//! "distribution" would be a claim it cannot support.
//!
//! Wrapping arithmetic is deliberate and is the one place in this crate where
//! overflow is not a refusal: a PRNG's whole job is to wrap, and its output
//! never reaches canonical bytes or a decision boundary.

use fgit_statistics::beta_bernoulli::{BetaPrior, Outcomes};
use fgit_statistics::conformal::{ConformalConfig, SplitConformal};
use fgit_statistics::elimination::SuccessiveElimination;
use fgit_statistics::lyapunov::{LyapunovConfig, LyapunovGovernor};
use fgit_statistics::off_policy::{LoggedSample, OffPolicyConfig, OffPolicyEvaluator};
use fgit_statistics::regime::{Cusum, CusumConfig};
use fgit_statistics::{EProcess, EProcessConfig};

/// A reproducible integer generator. Not a distribution — see the module docs.
struct Lcg(u64);

impl Lcg {
    const fn new(seed: u64) -> Self {
        // A zero state would be absorbing for some multipliers; offset it.
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    /// The next raw value.
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        // The high bits of an LCG are the well-mixed ones.
        self.0 >> 11
    }

    /// A value in `0..span`, for `span > 0`.
    fn below(&mut self, span: u64) -> u64 {
        self.next() % span
    }

    /// A value in `low..=high`.
    fn between(&mut self, low: i64, high: i64) -> i64 {
        debug_assert!(low <= high);
        let span = (high - low) as u64 + 1;
        low + self.below(span) as i64
    }
}

const SEEDS: [u64; 4] = [1, 0x5eed, 0xdead_beef, 0xffff_ffff_ffff_ffff];

// ------------------------------------------------------------------- regime

#[test]
fn cusum_accumulators_never_take_the_wrong_sign_on_any_stream() {
    // The clamp is what makes the accumulators one-sided, and a sign error would
    // let an upward excursion cancel a downward one. True on every stream, so a
    // seeded sweep is the right shape for it.
    for seed in SEEDS {
        let mut rng = Lcg::new(seed);
        let mut detector = Cusum::new(CusumConfig {
            target: 100,
            slack: 5,
            threshold: 20,
            max_deviation: 10_000,
            max_observations: 100_000,
        })
        .expect("assumptions hold");

        for _ in 0..20_000 {
            detector.observe(rng.between(-5_000, 5_000));
            assert!(
                detector.high() >= 0,
                "seed {seed}: the upward accumulator went negative"
            );
            assert!(
                detector.low() <= 0,
                "seed {seed}: the downward accumulator went positive"
            );
        }
    }
}

#[test]
fn cusum_never_alarms_on_a_stream_that_stays_inside_the_slack_band() {
    // Absorbing noise smaller than `slack` is the property `slack` exists for,
    // and it is the one a detector tuned by eye usually gets wrong. Any value
    // strictly inside the band drives both accumulators to zero every step, so
    // no seeded stream inside the band may ever alarm.
    for seed in SEEDS {
        let mut rng = Lcg::new(seed);
        let mut detector = Cusum::new(CusumConfig {
            target: 1_000,
            slack: 50,
            threshold: 100,
            max_deviation: 10_000,
            max_observations: 100_000,
        })
        .expect("assumptions hold");

        for index in 0..20_000 {
            let value = 1_000 + rng.between(-49, 49);
            assert_eq!(
                detector.observe(value),
                None,
                "seed {seed}: alarmed at observation {index} on a value inside the slack band"
            );
        }
        assert_eq!(detector.high(), 0);
        assert_eq!(detector.low(), 0);
    }
}

// ---------------------------------------------------------------- conformal

#[test]
fn the_conformal_bound_always_covers_at_least_its_rank() {
    // The coverage guarantee, restated as something checkable by counting: the
    // rank-th smallest value must have at least `rank` values at or below it, on
    // any calibration set whatever.
    for seed in SEEDS {
        let mut rng = Lcg::new(seed);
        for size in [19_u32, 20, 50, 99, 200] {
            let mut scores: Vec<i64> = (0..size).map(|_| rng.between(-10_000, 10_000)).collect();
            scores.sort_unstable();

            let bound = SplitConformal::new(ConformalConfig {
                alpha_parts_per_million: 50_000,
                calibration_size: size,
            })
            .expect("feasible at these sizes");

            let quantile = bound.quantile(&scores).expect("well-formed set");
            let covered = scores.iter().filter(|score| **score <= quantile).count();
            assert!(
                covered >= bound.rank() as usize,
                "seed {seed}, size {size}: bound covers {covered} of {size}, below its rank {}",
                bound.rank()
            );
            assert!(covered <= size as usize);
        }
    }
}

// --------------------------------------------------------------- off-policy

#[test]
fn the_effective_sample_size_never_exceeds_the_batch_it_came_from() {
    // Cauchy-Schwarz gives (sum w)^2 <= n * sum w^2, so ESS <= n on every batch.
    // An ESS above the sample count would mean the gate could be satisfied by
    // arithmetic rather than by evidence, which is the one way this gate could
    // fail open.
    let evaluator = OffPolicyEvaluator::new(OffPolicyConfig {
        min_behavior_parts_per_million: 1_000,
        max_behavior_parts_per_million: 1_000_000,
        min_effective_sample_size: 1,
    })
    .expect("assumptions hold");

    for seed in SEEDS {
        let mut rng = Lcg::new(seed);
        for size in [1_usize, 2, 10, 100, 1_000] {
            let samples: Vec<LoggedSample> = (0..size)
                .map(|_| LoggedSample {
                    behavior_parts_per_million: rng.between(1_000, 1_000_000) as u32,
                    target_parts_per_million: rng.between(1, 1_000_000) as u32,
                    reward: rng.between(-1_000, 1_000),
                })
                .collect();

            let estimate = evaluator.evaluate(&samples).expect("in support, ess >= 1");
            assert!(
                estimate.effective_sample_size <= size as u64,
                "seed {seed}, size {size}: ESS {} exceeds the batch",
                estimate.effective_sample_size
            );
            assert!(
                estimate.effective_sample_size >= 1,
                "seed {seed}, size {size}: ESS fell below one with positive weights"
            );
        }
    }
}

// ---------------------------------------------------------------- lyapunov

#[test]
fn a_lyapunov_violation_always_carries_the_drift_that_caused_it() {
    // A verdict a caller must act on has to say what it saw. Initialized is the
    // only verdict without a drift, and it is not a violation, so every
    // violation must report one on every stream.
    for seed in SEEDS {
        let mut rng = Lcg::new(seed);
        let mut governor = LyapunovGovernor::new(LyapunovConfig {
            drift_bound: 50,
            required_decrease: 5,
            congestion_threshold: 500,
        })
        .expect("assumptions hold");

        for _ in 0..20_000 {
            let verdict = governor
                .observe(rng.between(0, 2_000))
                .expect("non-negative potential");
            if verdict.is_violation() {
                assert!(
                    verdict.drift().is_some(),
                    "seed {seed}: a violation reported no drift"
                );
            }
        }
    }

    // The presence case is DETERMINISTIC rather than left to the stream. An
    // `is_violation()` that always returned false would satisfy the loop above
    // on every seed, and a seeded stream that happened not to provoke one would
    // fail for a fixture reason rather than a real one.
    let mut governor = LyapunovGovernor::new(LyapunovConfig {
        drift_bound: 50,
        required_decrease: 5,
        congestion_threshold: 500,
    })
    .expect("assumptions hold");
    governor.observe(1_000).expect("first");

    let bound_exceeded = governor.observe(1_100).expect("non-negative");
    assert!(bound_exceeded.is_violation());
    assert_eq!(bound_exceeded.drift(), Some(100));

    let insufficient = governor.observe(1_099).expect("non-negative");
    assert!(insufficient.is_violation());
    assert_eq!(insufficient.drift(), Some(-1));

    // And the absence case, so the two are distinguishable.
    let clean = governor.observe(1_000).expect("non-negative");
    assert!(!clean.is_violation());
    assert_eq!(clean.drift(), Some(-99));
}

// ------------------------------------------------------------- elimination

#[test]
fn the_surviving_arm_set_never_empties_and_never_grows() {
    // Two invariants a controller depends on: it always has something to choose,
    // and an eliminated arm stays eliminated. Either failing would need a silent
    // default somewhere to paper over it.
    for seed in SEEDS {
        let mut rng = Lcg::new(seed);
        let widths: Vec<u32> = vec![400_000, 200_000, 100_000, 50_000, 10_000, 1_000];
        let mut selector = SuccessiveElimination::new(6, widths.clone()).expect("well-formed");

        let mut previous = selector.active_arms().len();
        assert_eq!(previous, 6);

        for round in 0..widths.len() {
            let means: Vec<u32> = (0..6).map(|_| rng.between(0, 1_000_000) as u32).collect();
            let outcome = selector.advance(&means).expect("well-formed means");

            assert!(
                !outcome.surviving.is_empty(),
                "seed {seed}, round {round}: the arm set emptied"
            );
            assert!(
                outcome.surviving.len() <= previous,
                "seed {seed}, round {round}: the surviving set grew from {previous} to {}",
                outcome.surviving.len()
            );
            assert!(outcome.surviving.windows(2).all(|pair| pair[0] < pair[1]));
            previous = outcome.surviving.len();
        }
    }
}

// ----------------------------------------------------------------- e-process

#[test]
fn a_latched_e_process_alarm_never_moves_again() {
    // The guarantee is over the supremum across time, so after an alarm the
    // wealth must be frozen no matter what arrives next.
    for seed in SEEDS {
        let mut rng = Lcg::new(seed);
        let mut process = EProcess::new(EProcessConfig {
            null_rate_parts_per_million: 500_000,
            bet_parts_per_million: 500_000,
            alarm_alpha_parts_per_million: 100_000,
        })
        .expect("assumptions hold");

        // Reach the alarm DETERMINISTICALLY rather than hoping the seeded stream
        // gets there: alpha = 0.1 puts the threshold at wealth 10, and a
        // multiplier of 1.25 per success crosses it well inside 20 successes.
        // Leaving this to the stream would make the latch check silently
        // vacuous on any seed that never alarmed.
        let mut frozen = None;
        for _ in 0..20 {
            let step = process.observe(true).expect("no overflow");
            if step.alarmed() {
                frozen = Some(step.wealth_parts_per_million());
                break;
            }
        }
        let at_alarm = frozen.expect("an all-success prefix must alarm");
        assert!(at_alarm >= process.alarm_threshold_parts_per_million());

        // Now the seeded part: whatever arrives next, the alarm holds and the
        // wealth does not move.
        for _ in 0..5_000 {
            let step = process.observe(rng.below(2) == 0).expect("no overflow");
            assert!(step.alarmed(), "seed {seed}: a latched alarm un-fired");
            assert_eq!(
                step.wealth_parts_per_million(),
                at_alarm,
                "seed {seed}: wealth moved after the alarm latched"
            );
        }
    }
}

// -------------------------------------------------------------------- beta

#[test]
fn more_successes_never_lower_the_posterior_mean() {
    // Monotonicity in the observed successes, at a fixed trial count. A
    // mechanism that inverted this would recommend the arm with less evidence
    // for it, and no single known-answer case would reveal it.
    for seed in SEEDS {
        let mut rng = Lcg::new(seed);
        for _ in 0..2_000 {
            let prior = BetaPrior::try_new(rng.between(1, 50) as u32, rng.between(1, 50) as u32)
                .expect("proper");
            let trials = rng.between(1, 5_000) as u32;

            let mut previous = 0;
            for successes in [0, trials / 4, trials / 2, (trials * 3) / 4, trials] {
                let mean = prior
                    .update(Outcomes { successes, trials })
                    .expect("successes <= trials")
                    .mean_parts_per_million();
                assert!(
                    mean >= previous,
                    "seed {seed}: {successes} of {trials} lowered the mean to {mean} from {previous}"
                );
                assert!(mean <= 1_000_000);
                previous = mean;
            }
        }
    }
}
