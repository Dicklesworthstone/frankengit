//! Per-mechanism validation campaign with a structured NDJSON receipt.
//!
//! The other test files in this crate prove the mechanisms work. This one
//! produces evidence that can be *read back* — one NDJSON record per mechanism,
//! naming how many assumption refusals were exercised, how many known-answer
//! cases were checked, and how many seeded observations were absorbed.
//!
//! # Why a receipt rather than more assertions
//!
//! A campaign whose only output is a green test run cannot answer "which
//! mechanisms were actually validated, and how hard?". Its coverage is visible
//! only by reading the source, so a mechanism that quietly stopped being
//! exercised looks identical to one that never was. The receipt makes the
//! denominator explicit and machine-checkable, which is what lets the e2e lane
//! refuse a short campaign instead of trusting an exit code.
//!
//! # The receipt is a by-product of real checks, not a description of them
//!
//! Every count below is incremented by a check that can fail. Nothing is
//! asserted about a mechanism that was not run, and the record is written only
//! after the assertions pass, so a receipt cannot exist for a failed campaign.
//!
//! Set `FGIT_STATISTICS_CAMPAIGN_ARTIFACT_DIR` to collect the receipt; without
//! it the validation still runs and simply writes nothing, so an ordinary
//! `cargo test` is unaffected.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use fgit_statistics::beta_bernoulli::{BetaAssumptionFailure, BetaPrior, Outcomes};
use fgit_statistics::conformal::{ConformalAssumptionFailure, ConformalConfig, SplitConformal};
use fgit_statistics::e_process::{EProcess, EProcessAssumptionFailure, EProcessConfig};
use fgit_statistics::elimination::{EliminationAssumptionFailure, SuccessiveElimination};
use fgit_statistics::expected_loss::{MAX_TERMS, probability_b_exceeds_a_ppm};
use fgit_statistics::lyapunov::{LyapunovAssumptionFailure, LyapunovConfig, LyapunovGovernor};
use fgit_statistics::off_policy::{
    LoggedSample, OffPolicyConfig, OffPolicyEvaluator, OpeAssumptionFailure,
};
use fgit_statistics::regime::{AssumptionFailure, Cusum, CusumConfig, Shift};
use fgit_statistics::{FallbackTrigger, PolicyGate, PolicySelection};

/// One mechanism's validated evidence.
struct Record {
    mechanism: &'static str,
    /// Distinct assumption refusals provoked, each by its own configuration.
    refusals_exercised: u32,
    /// Hand-computed known-answer cases checked.
    known_answer_cases: u32,
    /// Seeded observations absorbed without violating an invariant.
    seeded_observations: u32,
}

impl Record {
    /// Renders one NDJSON line.
    ///
    /// Hand-written rather than via a serializer: every field is a fixed
    /// ASCII kebab-case label or a non-negative integer, so there is nothing to
    /// escape, and this keeps the crate's dependency surface at two.
    fn to_ndjson(&self) -> String {
        let mut line = String::new();
        let _ = write!(
            line,
            concat!(
                "{{\"mechanism\":\"{}\",\"refusals_exercised\":{},",
                "\"known_answer_cases\":{},\"seeded_observations\":{},\"outcome\":\"pass\"}}"
            ),
            self.mechanism,
            self.refusals_exercised,
            self.known_answer_cases,
            self.seeded_observations
        );
        line
    }
}

/// A reproducible integer generator. Not a distribution claim.
struct Lcg(u64);

impl Lcg {
    const fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }

    const fn below(&mut self, span: u64) -> u64 {
        self.next() % span
    }
}

// --------------------------------------------------------------- mechanisms

fn validate_regime() -> Record {
    let base = CusumConfig {
        target: 100,
        slack: 5,
        threshold: 20,
        max_deviation: 1_000,
        max_observations: 100_000,
    };

    // Assumption refusals, one configuration each.
    let mut refusals = 0;
    let mut slack = base;
    slack.slack = 0;
    assert_eq!(
        Cusum::new(slack).err(),
        Some(AssumptionFailure::SlackNotPositive)
    );
    refusals += 1;
    let mut threshold = base;
    threshold.threshold = 0;
    assert_eq!(
        Cusum::new(threshold).err(),
        Some(AssumptionFailure::ThresholdNotPositive)
    );
    refusals += 1;
    let mut deviation = base;
    deviation.max_deviation = -1;
    assert_eq!(
        Cusum::new(deviation).err(),
        Some(AssumptionFailure::MaxDeviationNegative)
    );
    refusals += 1;
    let saturating = CusumConfig {
        max_deviation: i64::MAX,
        ..base
    };
    assert!(matches!(
        Cusum::new(saturating),
        Err(AssumptionFailure::CanSaturate { .. })
    ));
    refusals += 1;

    // Known answers: the alarm lands on the fifth shifted observation, and the
    // direction is reported.
    let mut detector = Cusum::new(base).expect("assumptions hold");
    for _ in 0..4 {
        assert_eq!(detector.observe(110), None);
    }
    assert_eq!(detector.observe(110), Some(Shift::Upward));
    let mut down = Cusum::new(base).expect("assumptions hold");
    for _ in 0..4 {
        assert_eq!(down.observe(90), None);
    }
    assert_eq!(down.observe(90), Some(Shift::Downward));

    // Seeded: a stream strictly inside the slack band never alarms.
    let mut rng = Lcg::new(0x5eed);
    let mut quiet = Cusum::new(base).expect("assumptions hold");
    let mut absorbed = 0;
    for _ in 0..20_000 {
        let value = 100 + i64::try_from(rng.below(9)).unwrap_or(0) - 4;
        assert_eq!(quiet.observe(value), None, "alarmed inside the slack band");
        absorbed += 1;
    }
    assert_eq!(quiet.high(), 0);
    assert_eq!(quiet.low(), 0);

    Record {
        mechanism: "cusum-regime-detection",
        refusals_exercised: refusals,
        known_answer_cases: 2,
        seeded_observations: absorbed,
    }
}

fn validate_conformal() -> Record {
    let mut refusals = 0;
    for (alpha, size, expected) in [
        (0, 100, ConformalAssumptionFailure::AlphaZero),
        (
            1_000_000,
            100,
            ConformalAssumptionFailure::AlphaNotBelowOne {
                alpha_parts_per_million: 1_000_000,
            },
        ),
        (50_000, 0, ConformalAssumptionFailure::CalibrationEmpty),
        (
            50_000,
            18,
            ConformalAssumptionFailure::CalibrationTooSmall {
                required_rank: 19,
                available: 18,
            },
        ),
    ] {
        assert_eq!(
            SplitConformal::new(ConformalConfig {
                alpha_parts_per_million: alpha,
                calibration_size: size,
            }),
            Err(expected)
        );
        refusals += 1;
    }

    // Known answers: hand-computed ranks.
    for (size, rank) in [(99_u32, 95_u32), (19, 19), (39, 36)] {
        let alpha = if size == 39 { 100_000 } else { 50_000 };
        let bound = SplitConformal::new(ConformalConfig {
            alpha_parts_per_million: alpha,
            calibration_size: size,
        })
        .expect("feasible");
        assert_eq!(bound.rank(), rank);
    }

    // Seeded: coverage never falls below the chosen rank.
    let mut rng = Lcg::new(0x00c0_ffee);
    let mut observations = 0;
    for size in [19_u32, 50, 99, 200] {
        let mut scores: Vec<i64> = (0..size)
            .map(|_| i64::try_from(rng.below(20_001)).unwrap_or(0) - 10_000)
            .collect();
        scores.sort_unstable();
        let bound = SplitConformal::new(ConformalConfig {
            alpha_parts_per_million: 50_000,
            calibration_size: size,
        })
        .expect("feasible");
        let quantile = bound.quantile(&scores).expect("well formed");
        let covered = scores.iter().filter(|s| **s <= quantile).count();
        assert!(covered >= bound.rank() as usize, "coverage below the rank");
        observations += size;
    }

    Record {
        mechanism: "split-conformal-bounds",
        refusals_exercised: refusals,
        known_answer_cases: 3,
        seeded_observations: observations,
    }
}

fn validate_e_process() -> Record {
    let base = EProcessConfig {
        null_rate_parts_per_million: 500_000,
        bet_parts_per_million: 500_000,
        alarm_alpha_parts_per_million: 50_000,
    };
    let mut refusals = 0;
    for bad in [
        EProcessConfig {
            null_rate_parts_per_million: 0,
            ..base
        },
        EProcessConfig {
            bet_parts_per_million: 0,
            ..base
        },
        EProcessConfig {
            bet_parts_per_million: 1_999_999,
            ..base
        },
        EProcessConfig {
            alarm_alpha_parts_per_million: 1_000_000,
            ..base
        },
    ] {
        assert!(EProcess::new(bad).is_err());
        refusals += 1;
    }
    assert_eq!(
        EProcess::new(EProcessConfig {
            bet_parts_per_million: 1_999_999,
            ..base
        }),
        Err(EProcessAssumptionFailure::BetCanExhaustWealth {
            bet_parts_per_million: 1_999_999,
            null_rate_parts_per_million: 500_000,
        }),
        "the ceilinged-loss boundary must be the refusal, not a generic one"
    );

    // Known answer: threshold 20x, alarm on the fourteenth success at 22_737_353.
    let mut process = EProcess::new(base).expect("assumptions hold");
    assert_eq!(process.alarm_threshold_parts_per_million(), 20_000_000);
    let mut fired = None;
    for index in 1..=40_u32 {
        let step = process.observe(true).expect("no overflow");
        if step.alarmed() {
            fired = Some((index, step.wealth_parts_per_million()));
            break;
        }
    }
    assert_eq!(fired, Some((14, 22_737_353)));

    // Seeded: once latched the wealth never moves again.
    let mut rng = Lcg::new(0xbeef);
    let frozen = process.wealth_parts_per_million();
    let mut observations = 0;
    for _ in 0..5_000 {
        let step = process.observe(rng.below(2) == 0).expect("no overflow");
        assert!(step.alarmed());
        assert_eq!(step.wealth_parts_per_million(), frozen);
        observations += 1;
    }

    Record {
        mechanism: "e-process-alarm",
        refusals_exercised: refusals,
        known_answer_cases: 1,
        seeded_observations: observations,
    }
}

fn validate_elimination() -> Record {
    let mut refusals = 0;
    assert!(matches!(
        SuccessiveElimination::new(1, vec![100_000]),
        Err(EliminationAssumptionFailure::TooFewArms { arms: 1 })
    ));
    refusals += 1;
    assert_eq!(
        SuccessiveElimination::new(3, Vec::new()),
        Err(EliminationAssumptionFailure::WidthScheduleEmpty)
    );
    refusals += 1;
    assert!(matches!(
        SuccessiveElimination::new(3, vec![1_000_001]),
        Err(EliminationAssumptionFailure::WidthAboveOne { .. })
    ));
    refusals += 1;
    assert_eq!(
        SuccessiveElimination::new(3, vec![100_000, 200_000]),
        Err(EliminationAssumptionFailure::WidthScheduleNotNonIncreasing { index: 1 })
    );
    refusals += 1;

    // Known answer: progressive elimination under a narrowing schedule.
    let widths = vec![200_000, 100_000, 50_000, 25_000];
    let mut selector = SuccessiveElimination::new(4, widths.clone()).expect("well formed");
    let means = [900_000_u32, 800_000, 700_000, 300_000];
    assert_eq!(selector.advance(&means).expect("means").eliminated, vec![3]);
    assert_eq!(
        selector.advance(&means).expect("means").eliminated,
        Vec::<u32>::new()
    );
    assert_eq!(selector.advance(&means).expect("means").eliminated, vec![2]);
    assert_eq!(selector.advance(&means).expect("means").eliminated, vec![1]);
    assert!(selector.converged());

    // Seeded: the arm set never empties and never grows.
    let mut rng = Lcg::new(0xfeed);
    let mut observations = 0;
    let mut seeded = SuccessiveElimination::new(6, widths).expect("well formed");
    let mut previous = 6;
    for _ in 0..4 {
        let round: Vec<u32> = (0..6)
            .map(|_| u32::try_from(rng.below(1_000_001)).unwrap_or(0))
            .collect();
        let outcome = seeded.advance(&round).expect("means");
        assert!(!outcome.surviving.is_empty(), "the arm set emptied");
        assert!(outcome.surviving.len() <= previous, "the arm set grew");
        previous = outcome.surviving.len();
        observations += 6;
    }

    Record {
        mechanism: "successive-elimination",
        refusals_exercised: refusals,
        known_answer_cases: 1,
        seeded_observations: observations,
    }
}

fn validate_off_policy() -> Record {
    let base = OffPolicyConfig {
        min_behavior_parts_per_million: 1_000,
        max_behavior_parts_per_million: 1_000_000,
        min_effective_sample_size: 5,
    };
    let mut refusals = 0;
    for (bad, expected) in [
        (
            OffPolicyConfig {
                min_behavior_parts_per_million: 0,
                ..base
            },
            OpeAssumptionFailure::SupportFloorZero,
        ),
        (
            OffPolicyConfig {
                min_effective_sample_size: 0,
                ..base
            },
            OpeAssumptionFailure::EffectiveSampleSizeZero,
        ),
        (
            OffPolicyConfig {
                max_behavior_parts_per_million: 1_000_001,
                ..base
            },
            OpeAssumptionFailure::SupportCeilingAboveOne { max: 1_000_001 },
        ),
    ] {
        assert_eq!(OffPolicyEvaluator::new(bad).err(), Some(expected));
        refusals += 1;
    }

    let evaluator = OffPolicyEvaluator::new(base).expect("assumptions hold");
    // Known answer: a uniform batch has an effective size equal to its count.
    let uniform: Vec<LoggedSample> = (0..10)
        .map(|_| LoggedSample {
            behavior_parts_per_million: 500_000,
            target_parts_per_million: 500_000,
            reward: 7,
        })
        .collect();
    let estimate = evaluator.evaluate(&uniform).expect("gates pass");
    assert_eq!(estimate.effective_sample_size, 10);
    assert_eq!(estimate.value, 7);

    // Seeded: the effective size never exceeds the batch it came from.
    let mut rng = Lcg::new(0x1234);
    let permissive = OffPolicyEvaluator::new(OffPolicyConfig {
        min_effective_sample_size: 1,
        ..base
    })
    .expect("assumptions hold");
    let mut observations = 0;
    for size in [1_usize, 10, 100, 1_000] {
        let batch: Vec<LoggedSample> = (0..size)
            .map(|_| LoggedSample {
                behavior_parts_per_million: u32::try_from(rng.below(999_001)).unwrap_or(0) + 1_000,
                target_parts_per_million: u32::try_from(rng.below(1_000_000)).unwrap_or(0) + 1,
                reward: i64::try_from(rng.below(2_001)).unwrap_or(0) - 1_000,
            })
            .collect();
        let estimate = permissive.evaluate(&batch).expect("in support");
        assert!(
            estimate.effective_sample_size <= size as u64,
            "effective size exceeded the batch"
        );
        assert!(estimate.effective_sample_size >= 1);
        observations += u32::try_from(size).unwrap_or(0);
    }

    Record {
        mechanism: "off-policy-evaluation",
        refusals_exercised: refusals,
        known_answer_cases: 1,
        seeded_observations: observations,
    }
}

fn validate_beta_bernoulli() -> Record {
    let mut refusals = 0;
    assert_eq!(
        BetaPrior::try_new(0, 1),
        Err(BetaAssumptionFailure::AlphaZero)
    );
    refusals += 1;
    assert_eq!(
        BetaPrior::try_new(1, 0),
        Err(BetaAssumptionFailure::BetaZero)
    );
    refusals += 1;
    let prior = BetaPrior::uniform();
    assert!(
        prior
            .update(Outcomes {
                successes: 5,
                trials: 3
            })
            .is_err()
    );
    refusals += 1;

    // Known answers: hand-computed posterior means.
    for (successes, trials, mean) in [
        (0_u32, 0_u32, 500_000_u32),
        (7, 10, 666_666),
        (0, 10, 83_333),
    ] {
        let posterior = prior.update(Outcomes { successes, trials }).expect("valid");
        assert_eq!(posterior.mean_parts_per_million(), mean);
    }

    // Seeded: more successes never lower the posterior mean.
    let mut rng = Lcg::new(0xabcd);
    let mut observations = 0;
    for _ in 0..2_000 {
        let trials = u32::try_from(rng.below(5_000)).unwrap_or(0) + 1;
        let mut previous = 0;
        for successes in [0, trials / 2, trials] {
            let mean = prior
                .update(Outcomes { successes, trials })
                .expect("valid")
                .mean_parts_per_million();
            assert!(mean >= previous, "more successes lowered the mean");
            previous = mean;
        }
        observations += 1;
    }

    Record {
        mechanism: "beta-bernoulli-posterior",
        refusals_exercised: refusals,
        known_answer_cases: 3,
        seeded_observations: observations,
    }
}

fn validate_lyapunov() -> Record {
    let base = LyapunovConfig {
        drift_bound: 50,
        required_decrease: 5,
        congestion_threshold: 500,
    };
    let mut refusals = 0;
    for bad in [
        LyapunovConfig {
            required_decrease: 0,
            ..base
        },
        LyapunovConfig {
            drift_bound: -1,
            ..base
        },
        LyapunovConfig {
            congestion_threshold: -1,
            ..base
        },
    ] {
        assert!(LyapunovGovernor::new(bad).is_err());
        refusals += 1;
    }
    assert_eq!(
        LyapunovGovernor::new(LyapunovConfig {
            required_decrease: 0,
            ..base
        })
        .err(),
        Some(LyapunovAssumptionFailure::RequiredDecreaseNotPositive)
    );

    // Known answer: a flat congested system is a violation, a draining one is not.
    let mut governor = LyapunovGovernor::new(base).expect("assumptions hold");
    governor.observe(1_000).expect("first");
    assert!(governor.observe(1_000).expect("flat").is_violation());
    let mut draining = LyapunovGovernor::new(base).expect("assumptions hold");
    draining.observe(1_000).expect("first");
    assert!(!draining.observe(990).expect("draining").is_violation());

    // Seeded: a violation always carries the drift that caused it.
    let mut rng = Lcg::new(0x9999);
    let mut seeded = LyapunovGovernor::new(base).expect("assumptions hold");
    let mut observations = 0;
    for _ in 0..20_000 {
        let potential = i64::try_from(rng.below(2_001)).unwrap_or(0);
        let verdict = seeded.observe(potential).expect("non-negative");
        if verdict.is_violation() {
            assert!(verdict.drift().is_some(), "violation without a drift");
        }
        observations += 1;
    }

    Record {
        mechanism: "lyapunov-progress-governor",
        refusals_exercised: refusals,
        known_answer_cases: 2,
        seeded_observations: observations,
    }
}

fn validate_expected_loss() -> Record {
    // Landed under frankengit-s76z (529b8a7) after NEG-025 disproved the naive
    // T(0)-upward walk. Validated here independently: the known answers below
    // were computed from the closed form in exact rational arithmetic, not read
    // back from that module or copied from its own tests.
    let prior = |alpha: u32, beta: u32| {
        BetaPrior::try_new(alpha, beta)
            .expect("proper prior")
            .update(Outcomes {
                successes: 0,
                trials: 0,
            })
            .expect("no observations")
    };

    // Known answers. The module's stated error bound is ~2^-96 relative over at
    // most a few hundred steps, so ppm-exact agreement is the right assertion;
    // a tolerance would hide precisely the regression worth catching.
    for (a1, b1, a2, b2, want) in [
        (3_u32, 4_u32, 5_u32, 2_u32, 878_787_u32),
        (11, 3, 8, 6, 100_778),
    ] {
        let got = probability_b_exceeds_a_ppm(prior(a1, b1), prior(a2, b2)).expect("evaluable");
        assert_eq!(
            got, want,
            "P(Beta({a2},{b2}) > Beta({a1},{b1})) disagreed with exact rational evaluation"
        );
    }

    // The identity that catches a sign or ordering error no single value can:
    // a posterior compared against itself must be exactly one half.
    for alpha in [2_u32, 4, 17] {
        assert_eq!(
            probability_b_exceeds_a_ppm(prior(alpha, alpha), prior(alpha, alpha))
                .expect("evaluable"),
            500_000,
            "an arm compared against itself must be exactly even"
        );
    }

    // And NEG-025's own failure region is REFUSED rather than answered. This is
    // the check that matters most: the naive walk returned 0 ppm here, which
    // reads as "the candidate never wins" and would pin a controller to its
    // fallback forever. A refusal is the only safe answer.
    let refusals = u32::try_from(MAX_TERMS)
        .ok()
        .and_then(|max| max.checked_add(1))
        .map_or(0, |over| {
            probability_b_exceeds_a_ppm(prior(1, 1), prior(over, 1))
                .err()
                .map_or(0, |_| 1)
        });
    assert_eq!(refusals, 1, "an out-of-bound term count must be refused");

    Record {
        mechanism: "beta-bernoulli-expected-loss",
        refusals_exercised: refusals,
        known_answer_cases: 5,
        seeded_observations: 0,
    }
}

fn validate_fallback_gate() -> Record {
    // Every trigger, alone, selects the pinned fallback.
    let mut cases = 0;
    for trigger in FallbackTrigger::ALL {
        let mut gate = PolicyGate::all_clear();
        gate.set(trigger);
        assert_eq!(gate.select(), PolicySelection::Fallback(trigger));
        cases += 1;
    }
    // And the absence half, so the above is not satisfied by a constant.
    assert_eq!(PolicyGate::all_clear().select(), PolicySelection::Candidate);

    Record {
        mechanism: "deterministic-fallback-gate",
        refusals_exercised: 0,
        known_answer_cases: cases + 1,
        seeded_observations: 0,
    }
}

// ------------------------------------------------------------------ campaign

#[test]
fn the_validation_campaign_covers_every_mechanism_and_writes_its_receipt() {
    let records = vec![
        validate_regime(),
        validate_conformal(),
        validate_e_process(),
        validate_elimination(),
        validate_off_policy(),
        validate_beta_bernoulli(),
        validate_lyapunov(),
        validate_expected_loss(),
        validate_fallback_gate(),
    ];

    // The denominator, asserted here as well as in the e2e lane: a campaign that
    // silently stopped covering a mechanism must fail, not shrink quietly.
    assert_eq!(
        records.len(),
        9,
        "the campaign must cover all eight mechanisms plus the fallback gate"
    );
    for record in &records {
        assert!(
            record.known_answer_cases > 0,
            "{} contributed no known-answer case",
            record.mechanism
        );
    }
    let refusals: u32 = records.iter().map(|r| r.refusals_exercised).sum();
    assert!(
        refusals >= 20,
        "only {refusals} assumption refusals exercised across the library"
    );

    let mut receipt = String::new();
    for record in &records {
        receipt.push_str(&record.to_ndjson());
        receipt.push('\n');
    }

    // Written only after every assertion above passed, so a receipt cannot
    // exist for a failed campaign.
    if let Some(dir) = std::env::var_os("FGIT_STATISTICS_CAMPAIGN_ARTIFACT_DIR") {
        let dir = PathBuf::from(dir);
        fs::create_dir_all(&dir).expect("campaign artifact directory is creatable");
        fs::write(dir.join("statistics-validation.ndjson"), receipt)
            .expect("campaign receipt is writable");
    }
}
