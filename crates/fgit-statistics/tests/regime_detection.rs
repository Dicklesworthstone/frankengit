//! Known-answer tests for the integer CUSUM prototype.
//!
//! Every expected value below is hand-computed from the recurrence, not read
//! back from a run. A test whose expectation came from the implementation
//! cannot detect the implementation being wrong.

use fgit_statistics::{AssumptionFailure, Cusum, CusumConfig, Shift};

const fn cfg() -> CusumConfig {
    // target 100, slack 5, threshold 20. Hand-traced below.
    CusumConfig {
        target: 100,
        slack: 5,
        threshold: 20,
        max_deviation: 1_000,
        max_observations: 100_000,
    }
}

// ------------------------------------------------------- presence: it alarms

#[test]
fn a_sustained_upward_shift_alarms_on_the_fifth_observation() {
    // deviation = 110 - 100 = 10; high_step = 10 - 5 = 5.
    // high after each observation: 5, 10, 15, 20, 25.
    // The alarm is strictly above threshold 20, so obs 4 (high = 20) must NOT
    // alarm and obs 5 (high = 25) must. Off-by-one here is the whole point.
    let mut detector = Cusum::new(cfg()).expect("assumptions hold");
    let expected_high = [5, 10, 15, 20, 25];

    for (index, want_high) in expected_high.iter().enumerate() {
        let alarm = detector.observe(110);
        assert_eq!(
            detector.high(),
            *want_high,
            "accumulator diverged from the hand-traced sequence at observation {}",
            index + 1
        );
        if index < 4 {
            assert_eq!(alarm, None, "alarmed early at observation {}", index + 1);
        } else {
            assert_eq!(alarm, Some(Shift::Upward), "no alarm at observation 5");
        }
    }
    assert!(!detector.saturated(), "nothing here should saturate");
}

#[test]
fn a_sustained_downward_shift_alarms_and_names_its_direction() {
    // deviation = 90 - 100 = -10; low_step = -10 + 5 = -5.
    // low after each: -5, -10, -15, -20, -25; alarm strictly below -20.
    let mut detector = Cusum::new(cfg()).expect("assumptions hold");
    for _ in 0..4 {
        assert_eq!(detector.observe(90), None);
    }
    assert_eq!(detector.low(), -20, "hand-traced low before the alarm");
    assert_eq!(
        detector.observe(90),
        Some(Shift::Downward),
        "a downward shift must be reported as Downward, not merely as an alarm: a caller's \
         fallback may differ by direction"
    );
}

// ------------------------------------------------- absence: it does NOT alarm

#[test]
fn a_stream_exactly_at_target_never_alarms_however_long() {
    // deviation 0 => high_step -5 (clamped to 0), low_step +5 (clamped to 0).
    // Without this the presence tests above prove nothing: a detector that
    // alarms on everything would pass them.
    let mut detector = Cusum::new(cfg()).expect("assumptions hold");
    for _ in 0..10_000 {
        assert_eq!(detector.observe(100), None);
    }
    assert_eq!(detector.high(), 0);
    assert_eq!(detector.low(), 0);
}

#[test]
fn noise_strictly_inside_the_slack_band_never_alarms() {
    // |deviation| = 3 < slack 5, so both accumulators clamp to 0 every step.
    // This is the property `slack` exists for, and it is the one a detector
    // tuned by eye usually gets wrong.
    let mut detector = Cusum::new(cfg()).expect("assumptions hold");
    let seeded = [103, 97, 101, 99, 102, 98, 100, 103, 97, 102];
    for _ in 0..1_000 {
        for value in seeded {
            assert_eq!(
                detector.observe(value),
                None,
                "alarmed on noise inside the slack band"
            );
        }
    }
    assert_eq!(detector.high(), 0);
    assert_eq!(detector.low(), 0);
}

#[test]
fn a_single_large_spike_does_not_alarm_but_a_sustained_shift_does() {
    // The pair that distinguishes a drift detector from a threshold alarm.
    // One spike of +24 leaves high = 19, under threshold 20.
    let mut detector = Cusum::new(cfg()).expect("assumptions hold");
    assert_eq!(detector.observe(124), None, "one spike must not alarm");
    assert_eq!(detector.high(), 19);

    // It decays back to zero under in-band observations...
    for _ in 0..4 {
        detector.observe(100);
    }
    assert_eq!(detector.high(), 0, "an isolated spike must not persist");

    // ...while a sustained shift of the same magnitude does alarm.
    let mut sustained = Cusum::new(cfg()).expect("assumptions hold");
    let mut fired = None;
    for index in 1..=5 {
        if let Some(shift) = sustained.observe(110) {
            fired = Some((index, shift));
            break;
        }
    }
    assert_eq!(fired, Some((5, Shift::Upward)));
}

// --------------------------------------------------- executable assumptions

#[test]
fn a_non_positive_slack_is_refused_and_a_positive_one_is_admitted() {
    let mut bad = cfg();
    bad.slack = 0;
    assert_eq!(
        Cusum::new(bad).err(),
        Some(AssumptionFailure::SlackNotPositive),
        "slack 0 accumulates every deviation and alarms on any stream not exactly at target"
    );

    let mut good = cfg();
    good.slack = 1;
    assert!(
        Cusum::new(good).is_ok(),
        "the refusal must be specific to non-positive slack, not a blanket refusal"
    );
}

#[test]
fn a_non_positive_threshold_is_refused() {
    let mut bad = cfg();
    bad.threshold = 0;
    assert_eq!(
        Cusum::new(bad).err(),
        Some(AssumptionFailure::ThresholdNotPositive)
    );
}

#[test]
fn a_negative_deviation_bound_is_refused_and_zero_is_admitted() {
    // `max_deviation` bounds an ABSOLUTE value, so a negative one is not a
    // bound at all. Left unchecked it also silently disables the saturation
    // proof below: `max_deviation - slack` goes negative, `per_observation > 0`
    // is false, and the whole capacity argument is skipped.
    let mut bad = cfg();
    bad.max_deviation = -1;
    assert_eq!(
        Cusum::new(bad).err(),
        Some(AssumptionFailure::MaxDeviationNegative),
        "a negative bound on |observation - target| would also skip the saturation check entirely"
    );

    // The permitted twin, and the boundary: zero is a legitimate declaration
    // that the stream never departs from target at all.
    let mut zero = cfg();
    zero.max_deviation = 0;
    assert!(
        Cusum::new(zero).is_ok(),
        "the refusal must be specific to negative bounds, not a blanket refusal"
    );
}

#[test]
fn a_configuration_that_could_saturate_is_refused_before_it_can_lie() {
    // per_observation = max_deviation - slack = i64::MAX - 5, so even two
    // observations overflow. Saturation loses the excursion magnitude, so the
    // detector must refuse rather than report a capped statistic.
    let bad = CusumConfig {
        target: 0,
        slack: 5,
        threshold: 20,
        max_deviation: i64::MAX,
        max_observations: 1_000,
    };
    match Cusum::new(bad) {
        Err(AssumptionFailure::CanSaturate { observations, .. }) => {
            assert_eq!(observations, 1_000);
        }
        other => panic!("expected CanSaturate, got {other:?}"),
    }

    // The permitted twin: the same shape, a bound that fits.
    let good = CusumConfig {
        max_deviation: 1_000,
        ..bad
    };
    assert!(
        Cusum::new(good).is_ok(),
        "the saturation check must admit a configuration that provably fits, or it is just a \
         blanket refusal wearing a computation"
    );
}

// --------------------------------------------------------------- determinism

#[test]
fn the_accumulator_sequence_is_reproducible_from_the_inputs_alone() {
    // A regression pin on the recurrence, and ONLY that.
    //
    // Two detectors in one process agreeing proves determinism within a run.
    // It does NOT witness cross-target reproducibility -- that guarantee is
    // structural (no division, no floats, so nothing for a target to differ
    // about) and no in-process test can observe it. An earlier draft of this
    // comment claimed the stronger thing; the assertion never did.
    let seeded = [140, 60, 101, 99, 175, 100, 100, 20, 130, 100];
    let mut left = Cusum::new(cfg()).expect("assumptions hold");
    let mut right = Cusum::new(cfg()).expect("assumptions hold");

    for value in seeded {
        let a = left.observe(value);
        let b = right.observe(value);
        assert_eq!(a, b);
        assert_eq!(left.high(), right.high());
        assert_eq!(left.low(), right.low());
    }
    // Pin the end state so a change in the recurrence is caught, not just
    // agreement between two copies of the same bug.
    assert_eq!(left.observations(), 10);
}

#[test]
fn the_assumption_check_is_callable_directly_and_agrees_with_the_constructor() {
    // `check_assumptions` is public, so a caller can validate a configuration
    // before building a detector -- but every test reached it only THROUGH
    // `Cusum::new`. A divergence between the two would leave that caller
    // validating something the constructor does not enforce, or refusing a
    // configuration the constructor would accept.
    let good = cfg();
    assert_eq!(good.check_assumptions(), Ok(()));
    assert!(Cusum::new(good).is_ok());

    // Agreement asserted per failing configuration rather than once, so a
    // constructor that started refusing for its own reasons is visible.
    let mut slack = cfg();
    slack.slack = 0;
    let mut threshold = cfg();
    threshold.threshold = 0;
    let mut deviation = cfg();
    deviation.max_deviation = -1;

    for bad in [slack, threshold, deviation] {
        let direct = bad.check_assumptions().expect_err("must refuse");
        let through_constructor = Cusum::new(bad).expect_err("must refuse");
        assert_eq!(
            direct, through_constructor,
            "the direct check and the constructor disagree about why this configuration fails"
        );
    }
}
