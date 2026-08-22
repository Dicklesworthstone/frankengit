//! Known-answer tests for the integer e-process alarm.
//!
//! Every wealth below comes from tracing the exact integer recurrence, not from
//! a run of the implementation. The step-4 value is included on purpose: the
//! exact wealth there is 2_441_406.25 and the computed one is 2_441_406, so the
//! lower-bound rounding is visible in a concrete number rather than only in the
//! module's argument for it.

use fgit_statistics::e_process::{
    EProcess, EProcessAssumptionFailure, EProcessConfig, EProcessStep,
};

/// `p0 = 0.5`, `lambda = 0.5`, `alpha = 0.05`.
fn config() -> EProcessConfig {
    EProcessConfig {
        null_rate_parts_per_million: 500_000,
        bet_parts_per_million: 500_000,
        alarm_alpha_parts_per_million: 50_000,
    }
}

fn fresh() -> EProcess {
    EProcess::new(config()).expect("assumptions hold")
}

// ------------------------------------------------------------- known values

#[test]
fn the_alarm_threshold_is_one_over_alpha() {
    // alpha = 0.05 -> 1/alpha = 20 -> 20_000_000 in parts per million.
    let process = fresh();
    assert_eq!(process.alarm_threshold_parts_per_million(), 20_000_000);
    assert_eq!(
        process.wealth_parts_per_million(),
        1_000_000,
        "wealth starts at one"
    );
    assert!(!process.alarmed());
}

#[test]
fn the_wealth_sequence_matches_the_hand_traced_recurrence() {
    // Multiplier on a success is 1 + 0.5 * 0.5 = 1.25.
    let mut process = fresh();
    let expected = [1_250_000_u128, 1_562_500, 1_953_125, 2_441_406, 3_051_757];

    for (index, wealth) in expected.iter().enumerate() {
        let step = process.observe(true).expect("no overflow");
        assert_eq!(
            step.wealth_parts_per_million(),
            *wealth,
            "wealth diverged from the traced sequence at observation {}",
            index + 1
        );
        assert!(!step.alarmed());
    }
}

#[test]
fn the_rounding_is_visibly_downward() {
    // Step 4 is the concrete case: 1_953_125 * 1.25 is exactly 2_441_406.25.
    // A lower bound floors it; anything that rounded to nearest would give
    // 2_441_406 here too, so the check that distinguishes them is that the
    // computed value is never ABOVE the exact one, tested over many steps below.
    let mut process = fresh();
    for _ in 0..3 {
        process.observe(true).expect("no overflow");
    }
    assert_eq!(process.wealth_parts_per_million(), 1_953_125);
    let step = process.observe(true).expect("no overflow");
    assert_eq!(step.wealth_parts_per_million(), 2_441_406);

    // The exact value scaled by a further million, to show the discarded part
    // is real rather than a rounding artefact of the test's own arithmetic.
    assert_eq!(1_953_125_u128 * 1_250_000 / 1_000_000, 2_441_406);
    assert_eq!(1_953_125_u128 * 1_250_000 % 1_000_000, 250_000);
}

#[test]
fn a_sustained_departure_alarms_on_the_fourteenth_observation() {
    // 1.25^n >= 20 first at n = 14 under exact arithmetic, and the floored
    // recurrence agrees: wealth 22_737_353 crosses 20_000_000.
    let mut process = fresh();
    let mut fired = None;
    for index in 1..=40 {
        let step = process.observe(true).expect("no overflow");
        if step.alarmed() {
            fired = Some((index, step.wealth_parts_per_million()));
            break;
        }
    }
    assert_eq!(fired, Some((14, 22_737_353)));
    assert!(process.alarmed());
    assert_eq!(process.observations(), 14);
}

// ---------------------------------------------------------- absence cases

#[test]
fn a_stream_consistent_with_the_null_never_alarms() {
    // Without this the alarm tests prove nothing: a process that alarmed on
    // everything would pass them all.
    let mut process = fresh();
    for _ in 0..40 {
        let step = process.observe(false).expect("no overflow");
        assert!(!step.alarmed(), "alarmed on a stream of failures");
    }
    assert!(!process.alarmed());
    assert_eq!(
        process.wealth_parts_per_million(),
        9,
        "wealth decays toward zero on evidence for the null"
    );
}

#[test]
fn a_balanced_stream_at_the_null_rate_never_alarms() {
    // p0 = 0.5 and the stream is exactly half successes. Wealth drifts down,
    // because 1.25 * 0.75 = 0.9375 per pair -- betting costs something when the
    // null is true, which is what keeps the error guarantee.
    let mut process = fresh();
    for _ in 0..30 {
        assert!(!process.observe(true).expect("no overflow").alarmed());
        assert!(!process.observe(false).expect("no overflow").alarmed());
    }
    assert_eq!(process.wealth_parts_per_million(), 144_247);
    assert!(!process.alarmed());
}

// ----------------------------------------------------------------- latching

#[test]
fn the_alarm_latches_and_the_wealth_stops_moving() {
    // The guarantee is over the supremum across time, so an alarm that could be
    // un-fired by later observations would be a different and weaker claim.
    let mut process = fresh();
    for _ in 0..14 {
        process.observe(true).expect("no overflow");
    }
    assert!(process.alarmed());
    let at_alarm = process.wealth_parts_per_million();

    for _ in 0..1_000 {
        let step = process.observe(false).expect("no overflow");
        assert_eq!(
            step,
            EProcessStep::Alarmed {
                wealth_parts_per_million: at_alarm
            },
            "a fired alarm must not be undone, and the wealth must not keep moving"
        );
    }
    assert_eq!(
        process.observations(),
        14,
        "observations after the alarm are not absorbed into the process"
    );
}

// ------------------------------------------------- executable assumptions

#[test]
fn a_bet_that_could_exhaust_the_wealth_is_refused() {
    // lambda * p0 >= 1 means one failure drives wealth to zero or below. The
    // process is then permanently dead: non-negative no longer holds, it cannot
    // recover, and the alarm can never fire again. A silently dead detector.
    let mut bad = config();
    bad.bet_parts_per_million = 2_000_000;
    assert_eq!(
        EProcess::new(bad),
        Err(EProcessAssumptionFailure::BetCanExhaustWealth {
            bet_parts_per_million: 2_000_000,
            null_rate_parts_per_million: 500_000
        }),
        "lambda * p0 = 1 exactly, which zeroes the wealth on the first failure"
    );

    // The exact boundary, and the reason it is not where the textbook says.
    // lambda * p0 = 0.9999995 satisfies `lambda * p0 < 1`, but the loss term
    // ceilings to exactly one and the multiplier is zero. This value must be
    // refused even though the idealised inequality admits it.
    bad.bet_parts_per_million = 1_999_999;
    assert_eq!(
        EProcess::new(bad),
        Err(EProcessAssumptionFailure::BetCanExhaustWealth {
            bet_parts_per_million: 1_999_999,
            null_rate_parts_per_million: 500_000
        }),
        "a check written as `lambda * p0 < 1` admits this and produces a permanently dead process"
    );

    // The permitted twin: one part per million lower leaves a multiplier of
    // exactly one, the smallest positive value, and the process survives.
    bad.bet_parts_per_million = 1_999_998;
    let mut process = EProcess::new(bad).expect("just inside the assumption");
    let step = process.observe(false).expect("no overflow");
    assert_eq!(
        step.wealth_parts_per_million(),
        1,
        "the smallest admitted bet leaves a multiplier of one part per million, so wealth of one \
         becomes one -- strictly positive, and the process is still alive"
    );
    assert!(!step.alarmed());
}

#[test]
fn degenerate_null_rates_and_alarm_levels_are_refused() {
    for rate in [0_u32, 1_000_000, 1_000_001] {
        let mut bad = config();
        bad.null_rate_parts_per_million = rate;
        assert_eq!(
            EProcess::new(bad),
            Err(EProcessAssumptionFailure::NullRateNotInsideUnitInterval {
                null_rate_parts_per_million: rate
            }),
            "p0 = {rate} ppm is not strictly inside (0, 1)"
        );
    }

    let mut no_bet = config();
    no_bet.bet_parts_per_million = 0;
    assert_eq!(
        EProcess::new(no_bet),
        Err(EProcessAssumptionFailure::BetNotPositive),
        "a zero bet never moves the wealth, so the alarm could never fire"
    );

    for alpha in [0_u32, 1_000_000] {
        let mut bad = config();
        bad.alarm_alpha_parts_per_million = alpha;
        assert_eq!(
            EProcess::new(bad),
            Err(EProcessAssumptionFailure::AlarmLevelNotInsideUnitInterval {
                alarm_alpha_parts_per_million: alpha
            })
        );
    }

    // The permitted twin for all four.
    assert!(EProcess::new(config()).is_ok());
}

#[test]
fn a_smaller_alarm_level_demands_more_wealth() {
    // 1/alpha is the threshold, so a stricter level must be harder to reach. An
    // inverted relation here would make the strictest setting the easiest to
    // trip.
    let mut previous = 0;
    for alpha in [500_000_u32, 100_000, 50_000, 10_000, 1_000] {
        let mut config = config();
        config.alarm_alpha_parts_per_million = alpha;
        let threshold = EProcess::new(config)
            .expect("assumptions hold")
            .alarm_threshold_parts_per_million();
        assert!(
            threshold > previous,
            "alpha {alpha} set threshold {threshold}, not above the previous {previous}"
        );
        previous = threshold;
    }
    // alpha = 0.001 -> 1/alpha = 1000 -> 1_000_000_000 ppm.
    assert_eq!(previous, 1_000_000_000);
}

// --------------------------------------------------------------- determinism

#[test]
fn the_same_stream_produces_the_same_wealth_every_time() {
    let stream = [
        true, true, false, true, false, false, true, true, true, false,
    ];
    let mut first = fresh();
    for outcome in stream {
        first.observe(outcome).expect("no overflow");
    }
    let expected = first.wealth_parts_per_million();

    for _ in 0..50 {
        let mut repeat = fresh();
        for outcome in stream {
            repeat.observe(outcome).expect("no overflow");
        }
        assert_eq!(repeat.wealth_parts_per_million(), expected);
    }
    assert!(expected > 0, "the fixture must leave the process alive");
}
