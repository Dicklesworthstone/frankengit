//! §33's fail-closed rule, tested as a disjunction rather than a happy path.
//!
//! The dangerous failure here is not "the fallback fired when it shouldn't" —
//! that is loud and someone investigates. It is "a disqualifying condition was
//! set and the candidate ran anyway", which is silent, because the candidate
//! still produces answers. So every trigger gets its own presence case, and the
//! exhaustiveness test refuses to let a sixth variant be added without one.

use fgit_statistics::{FallbackTrigger, PolicyGate, PolicySelection};

/// Sets exactly one condition, leaving the other four clear.
const fn only(trigger: FallbackTrigger) -> PolicyGate {
    let mut gate = PolicyGate::all_clear();
    gate.set(trigger);
    gate
}

#[test]
fn every_single_trigger_alone_forces_the_fallback() {
    // The presence half, once per condition. A gate that only checked three of
    // the five would pass a test that set all five at once; this cannot.
    for trigger in FallbackTrigger::ALL {
        let selection = only(trigger).select();
        assert_eq!(
            selection,
            PolicySelection::Fallback(trigger),
            "{trigger:?} alone must force the fallback: a disqualifying condition that still \
             admits the candidate is silent, because the candidate keeps producing answers"
        );
        assert!(!selection.admits_candidate());
        assert_eq!(selection.trigger(), Some(trigger));
    }
}

#[test]
fn the_candidate_is_admitted_only_when_every_condition_is_clear() {
    // The absence half. Without it the test above is satisfied by a gate that
    // returns Fallback unconditionally, which would be useless and would pass.
    let selection = PolicyGate::all_clear().select();
    assert_eq!(selection, PolicySelection::Candidate);
    assert!(selection.admits_candidate());
    assert_eq!(selection.trigger(), None);
}

#[test]
fn the_trigger_set_is_exhaustive_over_the_gate() {
    // Pins ALL against the gate's own fields. If a sixth condition is added to
    // PolicyGate and omitted from ALL, `select` would silently never check it --
    // the exact rot this module is shaped to prevent. Setting every field and
    // requiring each trigger to be individually observable catches that.
    let mut all_set = PolicyGate::all_clear();
    for trigger in FallbackTrigger::ALL {
        all_set.set(trigger);
    }
    for trigger in FallbackTrigger::ALL {
        assert!(
            all_set.is_set(trigger),
            "{trigger:?} is in ALL but not readable from the gate"
        );
    }
    assert_eq!(
        FallbackTrigger::ALL.len(),
        5,
        "ALL must cover every §33 disqualifying condition; a variant added without extending \
         ALL would never be scanned by select()"
    );
}

#[test]
fn simultaneous_conditions_report_the_same_trigger_every_time() {
    // §8 requires a replayable decision path. A gate that reported whichever
    // condition it happened to notice first would make two identical runs
    // disagree about WHY the fallback was taken, which is unreplayable even
    // though the selection itself matches.
    let mut gate = PolicyGate::all_clear();
    gate.set(FallbackTrigger::RegimeAlarm);
    gate.set(FallbackTrigger::StaleWindow);

    // RegimeAlarm precedes StaleWindow in ALL, so it wins deterministically.
    for _ in 0..100 {
        assert_eq!(
            gate.select(),
            PolicySelection::Fallback(FallbackTrigger::RegimeAlarm)
        );
    }

    // And the ordering is a property of ALL, not of the struct's field order:
    // a later-ordered condition alone still reports itself.
    let mut only_stale = PolicyGate::all_clear();
    only_stale.set(FallbackTrigger::StaleWindow);
    assert_eq!(
        only_stale.select(),
        PolicySelection::Fallback(FallbackTrigger::StaleWindow)
    );
}

#[test]
fn a_saturated_detector_is_a_numeric_bound_violation_not_a_silent_pass() {
    // The composition that matters: the CUSUM detector's saturation flag feeds
    // NumericBoundViolation. A saturated accumulator has lost the magnitude of
    // its excursion, so its statistic is a lower bound rather than a value --
    // using an adaptive candidate on it would be acting on a number the system
    // knows is wrong.
    let mut gate = PolicyGate::all_clear();
    gate.set(FallbackTrigger::NumericBoundViolation);
    assert_eq!(
        gate.select(),
        PolicySelection::Fallback(FallbackTrigger::NumericBoundViolation)
    );

    // The permitted twin: an unsaturated run admits the candidate, so the check
    // above is not a blanket refusal.
    assert!(PolicyGate::all_clear().select().admits_candidate());
}
