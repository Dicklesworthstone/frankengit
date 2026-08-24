//! Cell readiness states and read-mode labels. `frankengit-fg036a`.
//!
//! Acceptance line 3 ("readiness transitions audited and typed") and the
//! labelling half of line 2 ("labels staleness with the exact bound"). The
//! disclosure half of line 2 binds to `RefVisibility` and cannot live at L0.

use core::time::Duration;

use fgit_types::cell::{
    CellReadiness, CellRefusal, CellState, CellTransitionCause, ReadLabel, ReadMode,
    StalenessBound, StalenessObservation, admits_read,
};
use fgit_types::error::TypeRefusal;
use fgit_types::numeric::HeadGeneration;

fn generation() -> HeadGeneration {
    HeadGeneration::FIRST
}

#[test]
fn every_cell_state_is_listed_and_round_trips_through_its_code_point() {
    // The completeness guard. `ALL` is what every exhaustive consumer iterates,
    // so a state added to the enum and forgotten here would be invisible to
    // every test in this file rather than failing one of them.
    assert_eq!(
        CellState::ALL.len(),
        10,
        "plan section 37.3 names ten states"
    );
    for state in CellState::ALL {
        assert_eq!(
            CellState::from_code_point(state.code_point()).expect("a known code point"),
            state
        );
    }

    let mut points: Vec<u16> = CellState::ALL.iter().map(|s| s.code_point()).collect();
    points.sort_unstable();
    points.dedup();
    assert_eq!(
        points.len(),
        CellState::ALL.len(),
        "two states sharing a code point would silently alias on the wire"
    );
}

#[test]
fn a_state_this_build_does_not_know_is_refused_rather_than_defaulted() {
    let refusal =
        CellState::from_code_point(9999).expect_err("an unknown cell state must not default");
    assert!(matches!(
        refusal,
        TypeRefusal::CodePointUnknown {
            field: "CellState",
            observed: 9999
        }
    ));

    // The permitted twin: a known point still resolves, so the refusal is not
    // satisfied by a decoder that refuses everything.
    assert_eq!(
        CellState::from_code_point(CellState::Serving.code_point()).expect("known"),
        CellState::Serving
    );
}

#[test]
fn a_transition_changes_capability_and_records_why_in_the_same_call() {
    // The property that makes the audit trustworthy: there is no way to change
    // what a cell may serve without leaving a record, because it is one call.
    let mut readiness = CellReadiness::bootstrapping();
    assert!(readiness.audit().is_empty());
    assert!(!readiness.state().admits_current_read());

    readiness
        .transition_to(
            CellState::VerifiedReadOnly,
            CellTransitionCause::AuthorityObservation,
            generation(),
        )
        .expect("bootstrapping may become verified-read-only");

    assert!(readiness.state().admits_current_read());
    assert!(
        !readiness.state().admits_mutation(),
        "verified-read-only must not have acquired mutation on the way"
    );
    assert_eq!(readiness.audit().len(), 1);
    let entry = readiness.audit()[0];
    assert_eq!(entry.from(), CellState::Bootstrapping);
    assert_eq!(entry.to(), CellState::VerifiedReadOnly);
    assert_eq!(entry.cause(), CellTransitionCause::AuthorityObservation);
    assert_eq!(entry.at_generation(), generation());
}

#[test]
fn an_illegal_transition_is_refused_and_leaves_no_audit_entry() {
    // A refused transition that still logged would make the audit a record of
    // attempts, and a reader could not tell which ones took effect.
    let mut readiness = CellReadiness::bootstrapping();
    let refusal = readiness
        .transition_to(
            CellState::Serving,
            CellTransitionCause::Operator,
            generation(),
        )
        .expect_err("a cell may not begin serving straight out of bootstrap");
    assert!(matches!(
        refusal,
        CellRefusal::IllegalTransition {
            from: CellState::Bootstrapping,
            to: CellState::Serving
        }
    ));
    assert_eq!(readiness.state(), CellState::Bootstrapping);
    assert!(
        readiness.audit().is_empty(),
        "a refused transition must not appear in the audit"
    );

    // The permitted twin at the same boundary: the legal first hop works.
    assert!(
        readiness
            .transition_to(
                CellState::VerifiedReadOnly,
                CellTransitionCause::Operator,
                generation()
            )
            .is_ok()
    );
}

#[test]
fn retirement_is_terminal_and_reachable_from_everywhere_else() {
    // Two edges must always exist or a cell can get stuck: anything may fail,
    // and anything not yet retired may retire.
    for state in CellState::ALL {
        if state.is_terminal() {
            for next in CellState::ALL {
                assert!(
                    !state.may_transition_to(next),
                    "{state} is terminal but admitted a move to {next}"
                );
            }
            continue;
        }
        assert!(
            state.may_transition_to(CellState::Retired),
            "{state} must be able to retire"
        );
        if state != CellState::Failed {
            assert!(
                state.may_transition_to(CellState::Failed),
                "{state} must be able to fail"
            );
        }
    }
    assert!(
        CellState::Retired.is_terminal(),
        "exactly one state is terminal"
    );
    assert_eq!(
        CellState::ALL
            .iter()
            .filter(|state| state.is_terminal())
            .count(),
        1
    );
}

#[test]
fn no_state_transitions_to_itself() {
    // A no-op edge would fill an audit with entries recording nothing, and a
    // reader could not distinguish "re-affirmed" from "changed".
    for state in CellState::ALL {
        assert!(
            !state.may_transition_to(state),
            "{state} admitted a transition to itself"
        );
    }
}

#[test]
fn only_serving_admits_mutation_and_the_read_capabilities_nest_correctly() {
    let mutating: Vec<CellState> = CellState::ALL
        .into_iter()
        .filter(|state| state.admits_mutation())
        .collect();
    assert_eq!(
        mutating,
        vec![CellState::Serving],
        "mutation is the narrowest capability and belongs to exactly one state"
    );

    // Bounded-stale is deliberately WIDER than current: a cell cut off from the
    // authority but holding verified older state is the partition case that
    // bounded-stale exists for. If this ever inverts, the mode is pointless.
    for state in CellState::ALL {
        if state.admits_current_read() {
            assert!(
                state.admits_bounded_stale_read(),
                "{state} serves current reads but not bounded-stale ones"
            );
        }
        if state.admits_mutation() {
            assert!(
                state.admits_current_read(),
                "{state} admits mutation without admitting a current read"
            );
        }
    }
    assert!(
        CellState::DegradedRead.admits_bounded_stale_read()
            && !CellState::DegradedRead.admits_current_read(),
        "degraded-read is the case that makes the two capabilities distinct"
    );
}

#[test]
fn a_bounded_stale_label_carries_the_bound_and_the_measurement() {
    // Acceptance line 2, the labelling half. A label carrying only the bound
    // tells a client the worst case it agreed to, not what it actually got.
    let bound = StalenessBound::new(Duration::from_secs(30), 5);
    let observed = StalenessObservation::new(Duration::from_secs(4), 2);
    let label = ReadLabel::bounded_stale(bound, observed).expect("inside the bound");

    assert_eq!(label.mode(), ReadMode::BoundedStale(bound));
    let carried = label.observed().expect("a bounded-stale label measures");
    assert_eq!(carried.age(), Duration::from_secs(4));
    assert_eq!(carried.generation_lag(), 2);
    let ReadMode::BoundedStale(carried_bound) = label.mode() else {
        panic!("the mode must carry the bound");
    };
    assert_eq!(carried_bound.max_age(), Duration::from_secs(30));
    assert_eq!(carried_bound.max_generation_lag(), 5);

    assert!(
        !label.mode().claims_currentness(),
        "a bounded-stale answer must not claim to be current"
    );
}

#[test]
fn each_half_of_the_bound_refuses_on_its_own_and_the_boundary_is_inclusive() {
    // Two conditions means two cases; one of them passing is not the guard
    // characterised. The inclusive boundary is checked on both axes because
    // that is the value a `<=` and a `<` disagree about.
    let bound = StalenessBound::new(Duration::from_secs(30), 5);

    let too_old = StalenessObservation::new(Duration::from_secs(31), 0);
    assert!(matches!(
        ReadLabel::bounded_stale(bound, too_old),
        Err(CellRefusal::StalenessExceedsBound { .. })
    ));

    let too_far_behind = StalenessObservation::new(Duration::from_secs(0), 6);
    assert!(matches!(
        ReadLabel::bounded_stale(bound, too_far_behind),
        Err(CellRefusal::StalenessExceedsBound { .. })
    ));

    // Exactly at the bound, on both axes at once, must be admitted.
    let exactly = StalenessObservation::new(Duration::from_secs(30), 5);
    assert!(
        ReadLabel::bounded_stale(bound, exactly).is_ok(),
        "the bound is inclusive; refusing here would make the declared limit unreachable"
    );

    // And one nanosecond past it must not be.
    let a_hair_over =
        StalenessObservation::new(Duration::from_secs(30) + Duration::from_nanos(1), 5);
    assert!(
        ReadLabel::bounded_stale(bound, a_hair_over).is_err(),
        "the smallest step past the bound must refuse"
    );
}

#[test]
fn only_the_current_mode_claims_currentness() {
    assert!(ReadLabel::current().mode().claims_currentness());
    assert!(!ReadLabel::snapshot().mode().claims_currentness());
    assert!(!ReadLabel::offline().mode().claims_currentness());

    // A snapshot is exact about WHICH revision and silent about whether a newer
    // one exists; an offline capsule claims nothing at all. Neither carries a
    // measurement, because neither is making a staleness promise to measure.
    assert!(ReadLabel::snapshot().observed().is_none());
    assert!(ReadLabel::offline().observed().is_none());
    assert!(ReadLabel::current().observed().is_none());
}

#[test]
fn a_state_that_cannot_serve_a_mode_refuses_it_by_name() {
    let bound = StalenessBound::new(Duration::from_secs(30), 5);

    // A bootstrapping cell serves nothing at all.
    for mode in [
        ReadMode::Current,
        ReadMode::BoundedStale(bound),
        ReadMode::Snapshot,
        ReadMode::Offline,
    ] {
        let refusal = admits_read(CellState::Bootstrapping, mode)
            .expect_err("a bootstrapping cell serves nothing");
        assert!(matches!(
            refusal,
            CellRefusal::StateAdmitsNoSuchRead {
                state: CellState::Bootstrapping,
                ..
            }
        ));
    }

    // Degraded-read is the discriminating case: it refuses a current read and
    // admits a bounded-stale one. A test using only bootstrapping would pass
    // against an `admits_read` that ignored the mode entirely.
    assert!(admits_read(CellState::DegradedRead, ReadMode::Current).is_err());
    assert!(admits_read(CellState::DegradedRead, ReadMode::BoundedStale(bound)).is_ok());
    assert!(admits_read(CellState::Serving, ReadMode::Current).is_ok());
}
