//! Tests for the Lyapunov progress governor.
//!
//! The case the governor exists for is
//! `a_system_that_is_busy_but_never_drains_is_a_violation`: every step is within
//! the drift bound, no single measurement looks wrong, and the backlog ends
//! exactly where it started. That is what a controller doing lots of work and
//! making no progress looks like from the inside.

use fgit_statistics::lyapunov::{
    LyapunovAssumptionFailure, LyapunovConfig, LyapunovGovernor, LyapunovRefusal, ProgressVerdict,
};

const fn config() -> LyapunovConfig {
    LyapunovConfig {
        drift_bound: 10,
        required_decrease: 5,
        congestion_threshold: 20,
    }
}

fn fresh() -> LyapunovGovernor {
    LyapunovGovernor::new(config()).expect("assumptions hold")
}

// -------------------------------------------------------------- draining

#[test]
fn a_draining_system_progresses_every_step() {
    let mut governor = fresh();
    assert_eq!(
        governor.observe(100),
        Ok(ProgressVerdict::Initialized),
        "the first observation has no predecessor to drift from"
    );

    for potential in [90, 80, 70, 60, 50, 40, 30] {
        let verdict = governor.observe(potential).expect("non-negative");
        assert_eq!(verdict, ProgressVerdict::Progressing { drift: -10 });
        assert!(!verdict.is_violation());
    }
    assert_eq!(governor.potential(), Some(30));
}

#[test]
fn a_decrease_of_exactly_epsilon_counts_as_progress() {
    // The boundary. Requiring strictly more than epsilon would refuse a system
    // draining at precisely the declared rate, which is the rate the
    // configuration says is acceptable.
    let mut governor = fresh();
    governor.observe(100).expect("first");
    assert_eq!(
        governor.observe(95),
        Ok(ProgressVerdict::Progressing { drift: -5 })
    );

    // And one short of it does not.
    let mut short = governor;
    assert_eq!(
        short.observe(91),
        Ok(ProgressVerdict::InsufficientDecrease {
            drift: -4,
            required: 5
        })
    );
}

// ---------------------------------------------------- the case it exists for

#[test]
fn a_system_that_is_busy_but_never_drains_is_a_violation() {
    // Oscillating 100 -> 105 -> 100 -> 105. Every step is well inside the drift
    // bound of 10, so nothing about a single step looks wrong, and the backlog
    // ends exactly where it started. Throughput could be enormous.
    let mut governor = fresh();
    governor.observe(100).expect("first");

    let up = governor.observe(105).expect("non-negative");
    assert_eq!(
        up,
        ProgressVerdict::InsufficientDecrease {
            drift: 5,
            required: 5
        }
    );
    assert!(up.is_violation());

    // The step back down decreases by exactly epsilon, so it genuinely is
    // progress by the declared standard -- the governor is not pretending the
    // whole oscillation is bad. The violation is the up-step, and one violation
    // per cycle is enough to disqualify the candidate.
    let down = governor.observe(100).expect("non-negative");
    assert_eq!(down, ProgressVerdict::Progressing { drift: -5 });
    assert!(!down.is_violation());

    // Over the full cycle the potential is exactly where it started, which is
    // the shape a per-step metric cannot see and this governor can.
    assert_eq!(governor.potential(), Some(100));
}

#[test]
fn a_flat_congested_system_is_a_violation() {
    // The simplest form: nothing moves at all while above the threshold.
    let mut governor = fresh();
    governor.observe(100).expect("first");
    for _ in 0..10 {
        let verdict = governor.observe(100).expect("non-negative");
        assert_eq!(
            verdict,
            ProgressVerdict::InsufficientDecrease {
                drift: 0,
                required: 5
            }
        );
        assert!(verdict.is_violation());
    }
}

// ------------------------------------------------- the bounded region

#[test]
fn below_the_threshold_no_decrease_is_required() {
    // A nearly empty system has nothing to drain, and demanding progress there
    // would refuse a healthy idle state.
    let mut governor = fresh();
    governor.observe(10).expect("first");
    for _ in 0..10 {
        let verdict = governor.observe(10).expect("non-negative");
        assert_eq!(verdict, ProgressVerdict::WithinBoundedRegion { drift: 0 });
        assert!(!verdict.is_violation());
    }
}

#[test]
fn the_drift_bound_applies_inside_the_bounded_region_too() {
    // An idle system may have nothing to do; it may not explode. Starting at 10,
    // well under the threshold of 20, a jump of 15 still exceeds the bound of 10.
    let mut governor = fresh();
    governor.observe(10).expect("first");
    let verdict = governor.observe(25).expect("non-negative");
    assert_eq!(
        verdict,
        ProgressVerdict::DriftBoundExceeded {
            drift: 15,
            bound: 10
        }
    );
    assert!(verdict.is_violation());

    // The permitted twin: exactly at the bound is admitted.
    let mut boundary = fresh();
    boundary.observe(10).expect("first");
    assert_eq!(
        boundary.observe(20),
        Ok(ProgressVerdict::WithinBoundedRegion { drift: 10 })
    );
}

#[test]
fn the_decrease_requirement_is_conditioned_on_where_the_step_started() {
    // The inversion this guards against. With a threshold of 20 and epsilon of
    // 10, a step from 22 to 20 decreases by only 2 while congested -- a
    // violation. Testing the value the step REACHED would see 20 <= 20, report
    // WithinBoundedRegion, and clear the very step where the system was worst
    // off and moved least.
    let mut governor = LyapunovGovernor::new(LyapunovConfig {
        drift_bound: 10,
        required_decrease: 10,
        congestion_threshold: 20,
    })
    .expect("assumptions hold");

    governor.observe(22).expect("first");
    let verdict = governor.observe(20).expect("non-negative");
    assert_eq!(
        verdict,
        ProgressVerdict::InsufficientDecrease {
            drift: -2,
            required: 10
        },
        "conditioning on the new potential would report WithinBoundedRegion here"
    );

    // The permitted twin: a step that STARTS at the threshold is genuinely in
    // the bounded region and requires nothing.
    let mut inside = LyapunovGovernor::new(LyapunovConfig {
        drift_bound: 10,
        required_decrease: 10,
        congestion_threshold: 20,
    })
    .expect("assumptions hold");
    inside.observe(20).expect("first");
    assert_eq!(
        inside.observe(20),
        Ok(ProgressVerdict::WithinBoundedRegion { drift: 0 })
    );
}

// ------------------------------------------------------------ verdict shape

#[test]
fn initialization_is_not_treated_as_a_violation() {
    // Treating "no evidence yet" as "bad evidence" would put every controller on
    // its fallback for one step at startup, which is a fallback drill nobody
    // asked for and would train readers to ignore the signal.
    let mut governor = fresh();
    let first = governor.observe(1_000).expect("non-negative");
    assert_eq!(first, ProgressVerdict::Initialized);
    assert!(!first.is_violation());
    assert_eq!(first.drift(), None, "no drift is computable from one point");
}

#[test]
fn every_verdict_that_carries_a_drift_reports_it() {
    let cases = [
        ProgressVerdict::WithinBoundedRegion { drift: 3 },
        ProgressVerdict::Progressing { drift: -7 },
        ProgressVerdict::DriftBoundExceeded {
            drift: 99,
            bound: 10,
        },
        ProgressVerdict::InsufficientDecrease {
            drift: 0,
            required: 5,
        },
    ];
    for verdict in cases {
        assert!(
            verdict.drift().is_some(),
            "{verdict:?} carries a drift but does not report it"
        );
    }

    // And the violation classification discriminates rather than being constant.
    assert!(cases.iter().any(|verdict| verdict.is_violation()));
    assert!(cases.iter().any(|verdict| !verdict.is_violation()));
}

// ------------------------------------------------- executable assumptions

#[test]
fn a_non_positive_required_decrease_is_refused_and_a_positive_one_is_admitted() {
    let mut bad = config();
    bad.required_decrease = 0;
    assert_eq!(
        LyapunovGovernor::new(bad).err(),
        Some(LyapunovAssumptionFailure::RequiredDecreaseNotPositive),
        "epsilon <= 0 requires no progress at all while appearing to check for it"
    );

    bad.required_decrease = -1;
    assert_eq!(
        LyapunovGovernor::new(bad).err(),
        Some(LyapunovAssumptionFailure::RequiredDecreaseNotPositive)
    );

    bad.required_decrease = 1;
    assert!(LyapunovGovernor::new(bad).is_ok());
}

#[test]
fn a_negative_bound_or_threshold_is_refused() {
    let mut negative_bound = config();
    negative_bound.drift_bound = -1;
    assert_eq!(
        LyapunovGovernor::new(negative_bound).err(),
        Some(LyapunovAssumptionFailure::DriftBoundNegative)
    );

    let mut negative_threshold = config();
    negative_threshold.congestion_threshold = -1;
    assert_eq!(
        LyapunovGovernor::new(negative_threshold).err(),
        Some(LyapunovAssumptionFailure::ThresholdNegative),
        "an unreachable threshold would apply the decrease requirement to an empty system, which \
         can never satisfy it"
    );

    // The permitted twins: zero is fine for both.
    let mut zeroes = config();
    zeroes.drift_bound = 0;
    zeroes.congestion_threshold = 0;
    assert!(LyapunovGovernor::new(zeroes).is_ok());
}

#[test]
fn a_negative_potential_is_refused_and_zero_is_not() {
    let mut governor = fresh();
    assert_eq!(
        governor.observe(-1),
        Err(LyapunovRefusal::PotentialNegative { potential: -1 }),
        "a Lyapunov potential is non-negative by definition"
    );

    // The permitted twin: an empty queue is a perfectly good potential.
    assert_eq!(governor.observe(0), Ok(ProgressVerdict::Initialized));
    assert_eq!(governor.potential(), Some(0));

    // And the refusal does not disturb the stored state.
    assert_eq!(
        governor.observe(-5),
        Err(LyapunovRefusal::PotentialNegative { potential: -5 })
    );
    assert_eq!(
        governor.potential(),
        Some(0),
        "a refused observation must not advance the governor's state"
    );
}
