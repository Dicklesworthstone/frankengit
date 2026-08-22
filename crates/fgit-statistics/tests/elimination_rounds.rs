//! Tests for successive elimination.
//!
//! The pair that carries the file is `a_clearly_worse_arm_is_eliminated`
//! against `nothing_is_eliminated_while_the_width_still_explains_the_gap`: the
//! same arm means, the same rule, and opposite outcomes decided only by how much
//! evidence the width schedule says has accumulated. A rule that eliminated on
//! the means alone would pass the first and fail the second.

use fgit_statistics::elimination::{
    EliminationAssumptionFailure, EliminationRefusal, SuccessiveElimination,
};

/// A well-formed narrowing schedule: 20%, 10%, 5%, 2.5%, 1%.
fn schedule() -> Vec<u32> {
    vec![200_000, 100_000, 50_000, 25_000, 10_000]
}

// ------------------------------------------------------------- elimination

#[test]
fn a_clearly_worse_arm_is_eliminated_and_the_leader_survives() {
    // Round 1 width is 200_000, so the gap must exceed 400_000. Arm 2 is
    // 900_000 - 400_000 = 500_000 behind, which is more.
    let mut selector = SuccessiveElimination::new(3, schedule()).expect("well-formed schedule");
    let outcome = selector
        .advance(&[900_000, 850_000, 400_000])
        .expect("well-formed means");

    assert_eq!(outcome.eliminated, vec![2]);
    assert_eq!(outcome.surviving, vec![0, 1]);
    assert_eq!(outcome.width_parts_per_million, 200_000);
    assert!(!selector.converged());

    // Arm 1 is only 50_000 behind, far inside 400_000, so it survives -- the
    // rule is not simply "drop everything but the leader".
    assert!(outcome.surviving.contains(&1));
}

#[test]
fn nothing_is_eliminated_while_the_width_still_explains_the_gap() {
    // The same means as above but a gap of exactly 400_000, which is NOT more
    // than twice the width. The boundary is inclusive on the surviving side:
    // an arm exactly at the edge of what the evidence can distinguish must not
    // be dropped.
    let mut selector = SuccessiveElimination::new(3, schedule()).expect("well-formed schedule");
    let outcome = selector
        .advance(&[900_000, 850_000, 500_000])
        .expect("well-formed means");

    assert!(
        outcome.eliminated.is_empty(),
        "a gap of exactly 2 * width is within what the confidence widths explain"
    );
    assert_eq!(outcome.surviving, vec![0, 1, 2]);
}

#[test]
fn a_narrowing_schedule_eliminates_progressively() {
    // The same means every round. As the declared width narrows, arms fall in
    // order of how far behind they are -- which is the whole shape of the
    // algorithm, and it cannot be seen from a single round.
    let mut selector = SuccessiveElimination::new(4, schedule()).expect("well-formed schedule");
    let means = [900_000, 800_000, 700_000, 300_000];

    // width 200_000 -> gap 400_000. Only arm 3, at 600_000 behind, goes.
    let first = selector.advance(&means).expect("well-formed means");
    assert_eq!(first.eliminated, vec![3]);

    // width 100_000 -> gap 200_000. Arm 2 is 200_000 behind: not MORE than the
    // gap, so it survives one more round.
    let second = selector.advance(&means).expect("well-formed means");
    assert_eq!(second.eliminated, Vec::<u32>::new());
    assert_eq!(second.surviving, vec![0, 1, 2]);

    // width 50_000 -> gap 100_000. Arm 2 at 200_000 behind goes; arm 1 at
    // 100_000 behind is exactly at the gap and survives.
    let third = selector.advance(&means).expect("well-formed means");
    assert_eq!(third.eliminated, vec![2]);
    assert_eq!(third.surviving, vec![0, 1]);

    // width 25_000 -> gap 50_000. Arm 1 at 100_000 behind now goes, and the
    // selector has converged on the leader.
    let fourth = selector.advance(&means).expect("well-formed means");
    assert_eq!(fourth.eliminated, vec![1]);
    assert_eq!(fourth.surviving, vec![0]);
    assert!(selector.converged());
    assert_eq!(selector.rounds(), 4);
}

#[test]
fn the_leader_is_never_eliminated_even_when_every_arm_is_far_apart() {
    // The rule must never empty the arm set: a controller with nothing to choose
    // would need a silent default, which is the shape section 3.1 forbids.
    let mut selector =
        SuccessiveElimination::new(5, vec![1, 1, 1]).expect("a very narrow schedule");
    let outcome = selector
        .advance(&[1_000_000, 0, 0, 0, 0])
        .expect("well-formed means");

    assert_eq!(outcome.surviving, vec![0]);
    assert_eq!(outcome.eliminated, vec![1, 2, 3, 4]);
    assert!(selector.converged());

    // And a further round changes nothing rather than emptying the set.
    let again = selector
        .advance(&[1_000_000, 0, 0, 0, 0])
        .expect("well-formed means");
    assert_eq!(again.surviving, vec![0]);
    assert!(again.eliminated.is_empty());
}

#[test]
fn tied_arms_are_never_separated() {
    // Zero gap can never exceed twice a non-negative width, so identical arms
    // survive together however narrow the schedule becomes.
    let mut selector = SuccessiveElimination::new(3, vec![0, 0, 0]).expect("a zero-width schedule");
    for _ in 0..3 {
        let outcome = selector.advance(&[500_000; 3]).expect("well-formed means");
        assert!(outcome.eliminated.is_empty());
        assert_eq!(outcome.surviving, vec![0, 1, 2]);
    }
}

#[test]
fn an_eliminated_arm_cannot_set_the_bar_for_the_survivors() {
    // If a dropped arm's mean still counted toward the leader, an arm eliminated
    // for being far ahead of nothing could keep eliminating its rivals. Here arm
    // 0 is dropped first, then its high mean must stop mattering.
    let mut selector = SuccessiveElimination::new(3, vec![100_000, 100_000]).expect("schedule");

    // Round 1: leader is arm 0 at 900_000, gap 200_000. Arms 1 and 2 at 500_000
    // and 450_000 are both more than 200_000 behind, so both go.
    let first = selector
        .advance(&[900_000, 500_000, 450_000])
        .expect("means");
    assert_eq!(first.eliminated, vec![1, 2]);
    assert_eq!(first.surviving, vec![0]);

    // The other half. A fresh selector drops arm 0 first, then reports a high
    // mean for it. If that mean still set the bar, arm 1 would be 400_000 behind
    // a gap of 20_000 and would be eliminated too, leaving nothing.
    let mut other = SuccessiveElimination::new(3, vec![100_000, 10_000]).expect("schedule");
    let drop_far = other.advance(&[0, 500_000, 450_000]).expect("means");
    assert_eq!(
        drop_far.eliminated,
        vec![0],
        "arm 0 is 500_000 behind the active leader, past a gap of 200_000"
    );

    let next = other.advance(&[900_000, 500_000, 450_000]).expect("means");
    assert_eq!(
        next.surviving,
        vec![1],
        "arm 0's 900_000 must not set the bar once it is out: the active leader is arm 1 at \
         500_000, so arm 1 is zero behind and survives"
    );
    assert_eq!(
        next.eliminated,
        vec![2],
        "arm 2 is 50_000 behind the ACTIVE leader, past a gap of 20_000"
    );
}

// -------------------------------------------------- executable assumptions

#[test]
fn a_widening_schedule_is_refused() {
    // A confidence width that grows with evidence is not a confidence width, and
    // it would let an arm eliminated at one round become un-eliminable at the
    // next, so the rule would never converge.
    assert_eq!(
        SuccessiveElimination::new(3, vec![100_000, 200_000]),
        Err(EliminationAssumptionFailure::WidthScheduleNotNonIncreasing { index: 1 })
    );

    // The permitted twin: flat is non-increasing and must be admitted, since a
    // schedule may legitimately plateau.
    assert!(SuccessiveElimination::new(3, vec![100_000, 100_000]).is_ok());
    assert!(SuccessiveElimination::new(3, vec![100_000, 99_999]).is_ok());
}

#[test]
fn a_degenerate_arm_set_or_schedule_is_refused() {
    for arms in [0_u32, 1] {
        assert_eq!(
            SuccessiveElimination::new(arms, schedule()),
            Err(EliminationAssumptionFailure::TooFewArms { arms }),
            "fewer than two arms leaves nothing to select between"
        );
    }
    assert_eq!(
        SuccessiveElimination::new(3, Vec::new()),
        Err(EliminationAssumptionFailure::WidthScheduleEmpty)
    );
    assert_eq!(
        SuccessiveElimination::new(3, vec![1_000_001]),
        Err(EliminationAssumptionFailure::WidthAboveOne {
            index: 0,
            width: 1_000_001
        })
    );

    // The permitted twins.
    assert!(SuccessiveElimination::new(2, vec![1_000_000]).is_ok());
    assert!(SuccessiveElimination::new(3, schedule()).is_ok());
}

#[test]
fn running_past_the_declared_schedule_is_refused() {
    // Reusing the last width would keep eliminating on a confidence level the
    // schedule never claimed for that many pulls -- confident conclusions from
    // evidence nobody declared.
    let mut selector = SuccessiveElimination::new(3, vec![500_000, 400_000]).expect("schedule");
    selector.advance(&[500_000; 3]).expect("round 1");
    selector.advance(&[500_000; 3]).expect("round 2");
    assert_eq!(
        selector.advance(&[500_000; 3]),
        Err(EliminationRefusal::ScheduleExhausted {
            round: 2,
            covered: 2
        })
    );
}

#[test]
fn malformed_means_are_refused() {
    let mut selector = SuccessiveElimination::new(3, schedule()).expect("schedule");
    assert_eq!(
        selector.advance(&[500_000, 500_000]),
        Err(EliminationRefusal::ArmCountMismatch {
            expected: 3,
            observed: 2
        })
    );
    assert_eq!(
        selector.advance(&[500_000, 500_000, 1_000_001]),
        Err(EliminationRefusal::MeanAboveOne {
            arm: 2,
            mean_parts_per_million: 1_000_001
        })
    );

    // A refused round must not have consumed a schedule entry.
    assert_eq!(
        selector.rounds(),
        0,
        "a refused round advanced the schedule, so the next valid round would use the wrong width"
    );
    assert!(selector.advance(&[500_000; 3]).is_ok());
}
