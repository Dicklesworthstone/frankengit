//! The bead's end-to-end demo: evidence in, policy epochs out, and a fallback
//! drill on an injected regime shift.
//!
//! The drill is the reason this file exists. A fallback that has never been
//! exercised is a fallback nobody knows works, and section 5.2's checkpoint
//! doctrine treats an unexercised path as a terminal non-pass rather than an
//! untested nicety. So the shift is injected, the transition is observed, and
//! the pinned delay is checked to be the pinned one rather than merely
//! different.

use fgit_codec::wire::canonical_body_bytes;
use fgit_statistics::authority::AdvisoryDecision;
use fgit_statistics::controller::{ControllerConfig, ControllerRefusal, RetryBackoffController};
use fgit_statistics::evidence::StatisticalEvidenceBody;
use fgit_statistics::regime::CusumConfig;
use fgit_statistics::{FallbackTrigger, PolicySelection};
use fgit_types::{AsciiSlug, Digest, DigestAlgorithmId, DigestBytes};

const TARGET: i64 = 100;
const BASE_BACKOFF: u64 = 1_000;
const PINNED_FALLBACK: u64 = 250_000;

fn config() -> ControllerConfig {
    ControllerConfig {
        cusum: CusumConfig {
            target: TARGET,
            slack: 5,
            threshold: 20,
            max_deviation: 1_000,
            max_observations: 100_000,
        },
        base_backoff_micros: BASE_BACKOFF,
        pinned_fallback_micros: PINNED_FALLBACK,
        max_retained_observations: 10_000,
    }
}

fn fresh() -> RetryBackoffController {
    RetryBackoffController::new(config()).expect("assumptions hold")
}

// ------------------------------------------------------------- the quiet case

#[test]
fn a_stream_at_target_keeps_the_candidate_and_never_republishes() {
    // The absence half of the drill. Without it, a controller that fell back
    // immediately and stayed there would pass every fallback test below.
    let mut controller = fresh();
    let first = controller.epoch();

    for sequence in 1..=500 {
        let step = controller
            .observe(sequence, TARGET)
            .expect("no epoch exhaustion");
        assert_eq!(step.selection, PolicySelection::Candidate);
        assert!(
            !step.published_epoch,
            "observation {sequence} republished an epoch without a selection change; epochs order \
             adaptive choices and a stream that never changes policy must not consume them"
        );
        assert_eq!(step.epoch, first);
        assert_eq!(
            step.decision,
            AdvisoryDecision::RetryBackoff {
                micros: BASE_BACKOFF
            },
            "a stream exactly at target must produce the base delay"
        );
    }
}

#[test]
fn the_candidate_backoff_tracks_the_observation() {
    // Proves the candidate is a real mechanism rather than a constant that
    // happens to equal the base delay in the test above.
    let mut controller = fresh();
    let step = controller.observe(1, TARGET + 40).expect("step");
    assert_eq!(step.selection, PolicySelection::Candidate);
    assert_eq!(
        step.decision,
        AdvisoryDecision::RetryBackoff {
            micros: BASE_BACKOFF + 40
        }
    );

    // And it does not go below base on an observation under target: a faster
    // stream is not a reason to retry sooner than the floor.
    let mut below = fresh();
    let step = below.observe(1, TARGET - 40).expect("step");
    assert_eq!(
        step.decision,
        AdvisoryDecision::RetryBackoff {
            micros: BASE_BACKOFF
        }
    );
}

// ---------------------------------------------------------------- the drill

#[test]
fn an_injected_regime_shift_drives_the_controller_onto_its_pinned_fallback() {
    let mut controller = fresh();
    let starting_epoch = controller.epoch();

    // Phase 1: in-regime. The candidate holds.
    for sequence in 1..=50 {
        let step = controller.observe(sequence, TARGET).expect("step");
        assert_eq!(step.selection, PolicySelection::Candidate);
    }
    assert_eq!(controller.epoch(), starting_epoch, "no epoch consumed yet");

    // Phase 2: inject the shift. deviation 10, slack 5, threshold 20, so the
    // accumulator crosses on the fifth shifted observation.
    let mut transition = None;
    for offset in 0..10 {
        let sequence = 51 + offset;
        let step = controller.observe(sequence, TARGET + 10).expect("step");
        if step.published_epoch && transition.is_none() {
            transition = Some((offset + 1, step));
        }
    }

    let (observations_to_alarm, step) = transition.expect("the shift must select the fallback");
    assert_eq!(
        observations_to_alarm, 5,
        "hand-traced from the recurrence: high advances by 5 per observation and alarms strictly \
         above 20"
    );
    assert_eq!(
        step.selection,
        PolicySelection::Fallback(FallbackTrigger::RegimeAlarm)
    );
    assert_eq!(
        step.decision,
        AdvisoryDecision::RetryBackoff {
            micros: PINNED_FALLBACK
        },
        "the fallback delay must be the pinned one, not merely different from the candidate's"
    );
    assert_eq!(
        step.epoch.get(),
        starting_epoch.get() + 1,
        "the selection change publishes exactly one epoch"
    );

    // Phase 3: the fallback latches. Observations returning to target do not
    // quietly restore the candidate, because the window still contains the shift.
    for sequence in 61..=200 {
        let step = controller.observe(sequence, TARGET).expect("step");
        assert_eq!(
            step.selection,
            PolicySelection::Fallback(FallbackTrigger::RegimeAlarm),
            "a good observation cleared a latched regime alarm; the window it is reasoning over \
             still contains the shift"
        );
        assert!(!step.published_epoch, "no further epochs are consumed");
        assert_eq!(
            step.decision,
            AdvisoryDecision::RetryBackoff {
                micros: PINNED_FALLBACK
            }
        );
    }

    // Phase 4: recovery is explicit and costs an epoch.
    let after_reset = controller.reset_window().expect("epoch available");
    assert_eq!(after_reset.get(), starting_epoch.get() + 2);
    let step = controller.observe(1, TARGET).expect("step");
    assert_eq!(
        step.selection,
        PolicySelection::Candidate,
        "a fresh window restores the candidate"
    );
    assert_eq!(step.epoch, after_reset);
}

// ------------------------------------------- every trigger is reachable here

#[test]
fn an_evidence_gap_selects_the_fallback() {
    let mut controller = fresh();
    controller.observe(1, TARGET).expect("step");
    controller.observe(2, TARGET).expect("step");

    // Sequence 4 is not 3's predecessor's successor: an observation is missing.
    let step = controller.observe(4, TARGET).expect("step");
    assert_eq!(
        step.selection,
        PolicySelection::Fallback(FallbackTrigger::EvidenceGap)
    );

    // The permitted twin: consecutive sequences do not trip it.
    let mut consecutive = fresh();
    for sequence in 1..=20 {
        let step = consecutive.observe(sequence, TARGET).expect("step");
        assert_eq!(step.selection, PolicySelection::Candidate);
    }
}

#[test]
fn an_observation_outside_declared_support_selects_the_fallback() {
    let mut controller = fresh();
    // max_deviation is 1_000, so 1_001 away from target is outside support.
    let step = controller.observe(1, TARGET + 1_001).expect("step");
    assert_eq!(
        step.selection,
        PolicySelection::Fallback(FallbackTrigger::SupportFailure)
    );

    // The permitted twin: exactly at the declared bound is inside support.
    let mut boundary = fresh();
    let step = boundary.observe(1, TARGET + 1_000).expect("step");
    assert_eq!(
        step.selection,
        PolicySelection::Candidate,
        "the bound is inclusive; refusing at exactly max_deviation would be a blanket refusal one \
         off from the declared contract"
    );
}

#[test]
fn exceeding_the_retention_bound_selects_the_fallback() {
    let mut config = config();
    config.max_retained_observations = 5;
    let mut controller = RetryBackoffController::new(config).expect("assumptions hold");

    for sequence in 1..=5 {
        let step = controller.observe(sequence, TARGET).expect("step");
        assert_eq!(
            step.selection,
            PolicySelection::Candidate,
            "observation {sequence} is within the declared bound"
        );
    }
    let step = controller.observe(6, TARGET).expect("step");
    assert_eq!(
        step.selection,
        PolicySelection::Fallback(FallbackTrigger::StaleWindow),
        "the sixth observation exceeds a bound of five"
    );
}

#[test]
fn a_saturating_accumulator_sets_the_numeric_bound_condition_even_when_a_regime_alarm_reports_first()
 {
    // Saturation and a regime alarm always co-occur -- an excursion large enough
    // to saturate is large enough to alarm -- and RegimeAlarm precedes
    // NumericBoundViolation in the fixed order, so the *reported* trigger is the
    // alarm. That is correct and replayable, but it would hide the saturation
    // from anyone reading only the selection, which is why the gate is exposed.
    let mut config = config();
    config.cusum.max_deviation = 2_000_000_000_000_000_000;
    config.cusum.max_observations = 4;
    let mut controller = RetryBackoffController::new(config).expect("four observations fit");

    for sequence in 1..=40 {
        controller
            .observe(sequence, TARGET + 2_000_000_000_000_000_000)
            .expect("step");
    }

    let gate = controller.gate();
    assert!(
        gate.numeric_bound_violation,
        "the accumulator saturated and the condition was not recorded; a saturated statistic is a \
         lower bound rather than a value"
    );
    assert!(gate.regime_alarm, "an excursion that large also alarms");
    assert_eq!(
        controller.selection(),
        PolicySelection::Fallback(FallbackTrigger::RegimeAlarm),
        "the first condition in ALL order is reported, deterministically"
    );

    // The permitted twin: an ordinary run records neither.
    let mut quiet = fresh();
    quiet.observe(1, TARGET).expect("step");
    assert!(!quiet.gate().numeric_bound_violation);
    assert!(!quiet.gate().regime_alarm);
}

// ------------------------------------------------- construction-time refusals

#[test]
fn a_zero_retention_bound_is_refused_and_one_is_not() {
    let mut config = config();
    config.max_retained_observations = 0;
    assert_eq!(
        RetryBackoffController::new(config).err(),
        Some(ControllerRefusal::RetentionBoundZero),
        "no window could ever be valid under a zero bound"
    );

    config.max_retained_observations = 1;
    assert!(
        RetryBackoffController::new(config).is_ok(),
        "the refusal must be specific to zero, not a blanket refusal"
    );
}

#[test]
fn a_detector_whose_assumptions_fail_is_refused_by_the_controller() {
    let mut config = config();
    config.cusum.slack = 0;
    assert!(
        matches!(
            RetryBackoffController::new(config),
            Err(ControllerRefusal::Detector(_))
        ),
        "the controller must not wrap a detector it could not build"
    );
}

// --------------------------------------------------- evidence closes the loop

#[test]
fn the_controller_produces_a_bindable_evidence_body() {
    // The end-to-end claim: observations in, and out comes a body carrying all
    // seven section 8 bindings with canonical bytes. This is what makes the
    // controller's decisions falsifiable rather than merely logged.
    let mut controller = fresh();
    for sequence in 1..=60 {
        let value = if sequence > 50 { TARGET + 10 } else { TARGET };
        controller.observe(sequence, value).expect("step");
    }
    assert_eq!(
        controller.selection(),
        PolicySelection::Fallback(FallbackTrigger::RegimeAlarm)
    );

    let window = controller
        .window()
        .expect("observations arrived")
        .expect("sequences ran forwards");
    assert_eq!(window.first(), 1);
    assert_eq!(window.last(), 60);
    assert_eq!(window.len(), 60);

    let body = StatisticalEvidenceBody {
        population: AsciiSlug::from_static("retry-attempts"),
        selection: AsciiSlug::from_static("every-attempt"),
        window,
        regime: controller.regime_binding(),
        policy: controller.selection(),
        assumptions: RetryBackoffController::assumptions().expect("fixed labels are valid"),
        fingerprint: Digest::new(
            DigestAlgorithmId::try_new(1).expect("nonzero"),
            DigestBytes::try_new(&[7; 32]).expect("32 bytes"),
        ),
    };

    let bytes = canonical_body_bytes(&body).expect("encodes");
    assert!(!bytes.is_empty());

    // The regime binding carries the detector state that justified the fallback,
    // not merely the epoch, so a reader can check the alarm rather than trust it.
    assert_eq!(body.regime.observations, 60);
    assert!(
        body.regime.detector_high > 20,
        "the accumulator that crossed the threshold is bound into the evidence"
    );
    assert!(!body.regime.saturated);
    assert_eq!(body.assumptions.len(), 5);
}
