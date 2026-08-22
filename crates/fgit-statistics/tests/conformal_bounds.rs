//! Known-answer tests for split conformal bounds.
//!
//! Every rank below is computed by hand from `ceil((n + 1) * (1 - alpha))`, not
//! read back from a run. The most important cases are the two either side of
//! feasibility: at `alpha = 0.05` a calibration set of 19 works exactly and a
//! set of 18 has no finite bound at all. A method that returned the largest
//! score for the second would look right in every test that only checked the
//! first.

use fgit_statistics::conformal::{
    ConformalAssumptionFailure, ConformalConfig, ConformalRefusal, SplitConformal,
};

/// `alpha = 0.05`, in parts per million.
const ALPHA_05: u32 = 50_000;

fn config(alpha_parts_per_million: u32, calibration_size: u32) -> ConformalConfig {
    ConformalConfig {
        alpha_parts_per_million,
        calibration_size,
    }
}

// ------------------------------------------------------------- known ranks

#[test]
fn the_rank_matches_the_hand_computed_ceiling() {
    // n = 99, alpha = 0.05: ceil(100 * 0.95) = ceil(95) = 95.
    let bound = SplitConformal::new(config(ALPHA_05, 99)).expect("feasible");
    assert_eq!(bound.rank(), 95);

    // n = 19, alpha = 0.05: ceil(20 * 0.95) = ceil(19) = 19. The exact boundary:
    // the rank equals the calibration size, so this is the smallest set for
    // which a finite 95% bound exists.
    let boundary = SplitConformal::new(config(ALPHA_05, 19)).expect("feasible at exactly 19");
    assert_eq!(boundary.rank(), 19);

    // n = 39, alpha = 0.10: ceil(40 * 0.90) = ceil(36) = 36.
    let ninety = SplitConformal::new(config(100_000, 39)).expect("feasible");
    assert_eq!(ninety.rank(), 36);

    // A case where the ceiling actually rounds up rather than landing exactly:
    // n = 10, alpha = 0.20 -> ceil(11 * 0.8) = ceil(8.8) = 9.
    let rounding = SplitConformal::new(config(200_000, 10)).expect("feasible");
    assert_eq!(
        rounding.rank(),
        9,
        "the ceiling must round up; truncating here would silently lower the coverage level"
    );
}

#[test]
fn a_smaller_alpha_never_takes_a_lower_rank() {
    // Monotonicity. A bound asked to cover more must reach at least as far into
    // the calibration scores; a mechanism that inverted this would be tighter
    // exactly where it was asked to be safer.
    let mut previous = 0;
    for alpha in [400_000, 300_000, 200_000, 100_000, ALPHA_05, 10_000] {
        let bound = SplitConformal::new(config(alpha, 999)).expect("feasible at n = 999");
        assert!(
            bound.rank() >= previous,
            "alpha {alpha} took rank {} after a larger alpha took {previous}",
            bound.rank()
        );
        previous = bound.rank();
    }
    assert!(previous > 0);
}

// ------------------------------------------- the assumption that is skipped

#[test]
fn a_calibration_set_one_short_of_feasible_is_refused_rather_than_capped() {
    // n = 18, alpha = 0.05: ceil(19 * 0.95) = ceil(18.05) = 19 > 18. There is no
    // 19th order statistic of 18 scores, so no finite bound holds at this level.
    assert_eq!(
        SplitConformal::new(config(ALPHA_05, 18)),
        Err(ConformalAssumptionFailure::CalibrationTooSmall {
            required_rank: 19,
            available: 18
        }),
        "returning the largest score here is the textbook convention and it produces a bound that \
         looks finite, looks tight, and guarantees nothing"
    );

    // The permitted twin, one score later. The refusal is specific to
    // infeasibility, not a blanket refusal of small calibration sets.
    assert!(
        SplitConformal::new(config(ALPHA_05, 19)).is_ok(),
        "19 is feasible at alpha = 0.05 and must be admitted"
    );
}

#[test]
fn the_feasibility_boundary_holds_at_several_levels() {
    // For alpha = 1/k the smallest feasible n is k - 1, since
    // ceil((n+1)(1 - 1/k)) <= n first holds there. Checked at three levels so
    // the boundary is a property of the formula rather than of one case.
    for (alpha, smallest_feasible) in [(500_000_u32, 1_u32), (100_000, 9), (ALPHA_05, 19)] {
        assert!(
            SplitConformal::new(config(alpha, smallest_feasible)).is_ok(),
            "alpha {alpha} should be feasible at n = {smallest_feasible}"
        );
        if smallest_feasible > 1 {
            assert!(
                matches!(
                    SplitConformal::new(config(alpha, smallest_feasible - 1)),
                    Err(ConformalAssumptionFailure::CalibrationTooSmall { .. })
                ),
                "alpha {alpha} should be infeasible at n = {}",
                smallest_feasible - 1
            );
        }
    }
}

#[test]
fn degenerate_levels_are_refused() {
    assert_eq!(
        SplitConformal::new(config(0, 100)),
        Err(ConformalAssumptionFailure::AlphaZero),
        "total coverage is not something a finite bound provides"
    );
    assert_eq!(
        SplitConformal::new(config(1_000_000, 100)),
        Err(ConformalAssumptionFailure::AlphaNotBelowOne {
            alpha_parts_per_million: 1_000_000
        })
    );
    assert_eq!(
        SplitConformal::new(config(ALPHA_05, 0)),
        Err(ConformalAssumptionFailure::CalibrationEmpty)
    );

    // The permitted twin: an ordinary level and size still builds.
    assert!(SplitConformal::new(config(ALPHA_05, 100)).is_ok());
}

// ------------------------------------------------------- the bound itself

#[test]
fn the_bound_is_the_rank_th_smallest_and_covers_that_many_scores() {
    // Scores 1..=99 sorted, so the 95th smallest is exactly 95 and the coverage
    // claim is checkable by counting rather than by trusting the index.
    let scores: Vec<i64> = (1..=99).collect();
    let bound = SplitConformal::new(config(ALPHA_05, 99)).expect("feasible");

    let quantile = bound
        .quantile(&scores)
        .expect("well-formed calibration set");
    assert_eq!(quantile, 95);

    let covered = scores.iter().filter(|score| **score <= quantile).count();
    assert_eq!(
        covered, 95,
        "the bound must cover exactly the rank it selected; a different count means the index is \
         off by one and the stated level is not the delivered one"
    );
    assert!(
        covered * 100 >= 95 * scores.len(),
        "the empirical coverage must reach the requested level"
    );
}

#[test]
fn repeated_scores_do_not_break_the_rank() {
    // Ties are ordinary in integer scores and the order statistic is still
    // well-defined; nothing here may assume distinct values.
    let scores = vec![5_i64; 19];
    let bound = SplitConformal::new(config(ALPHA_05, 19)).expect("feasible");
    assert_eq!(bound.quantile(&scores), Ok(5));

    let mut mixed = vec![1_i64; 10];
    mixed.extend(std::iter::repeat_n(7_i64, 9));
    assert_eq!(
        bound.quantile(&mixed),
        Ok(7),
        "the 19th of 19 is the largest"
    );
}

// ------------------------------------------------------ input is not repaired

#[test]
fn unsorted_scores_are_refused_rather_than_sorted() {
    // Sorting here would be one line and would hide the defect it exists to
    // catch: an unsorted slice is almost always the wrong slice.
    let bound = SplitConformal::new(config(ALPHA_05, 19)).expect("feasible");
    let mut scores: Vec<i64> = (1..=19).collect();
    scores.swap(3, 4);
    assert_eq!(
        bound.quantile(&scores),
        Err(ConformalRefusal::ScoresUnsorted { index: 4 })
    );

    // The permitted twin: the same values in order are accepted, so the refusal
    // is about order and not about the values.
    scores.swap(3, 4);
    assert_eq!(bound.quantile(&scores), Ok(19));
}

#[test]
fn a_calibration_set_of_the_wrong_size_is_refused() {
    // The rank was chosen for a specific n. Applying it to a different one
    // silently changes the coverage level, which is the failure that would never
    // announce itself.
    let bound = SplitConformal::new(config(ALPHA_05, 19)).expect("feasible");
    let short: Vec<i64> = (1..=18).collect();
    assert_eq!(
        bound.quantile(&short),
        Err(ConformalRefusal::CalibrationSizeMismatch {
            expected: 19,
            observed: 18
        })
    );

    let long: Vec<i64> = (1..=20).collect();
    assert_eq!(
        bound.quantile(&long),
        Err(ConformalRefusal::CalibrationSizeMismatch {
            expected: 19,
            observed: 20
        })
    );

    // The permitted twin.
    let exact: Vec<i64> = (1..=19).collect();
    assert!(bound.quantile(&exact).is_ok());
}

// ------------------------------------------------------------- determinism

#[test]
fn the_rank_is_identical_across_repeated_construction() {
    // The property the integer formulation exists for: no rounding mode, no
    // float, so the chosen rank cannot vary between builds or targets.
    for size in [19_u32, 20, 39, 99, 100, 999, 1_000] {
        let first = SplitConformal::new(config(ALPHA_05, size)).expect("feasible");
        let second = SplitConformal::new(config(ALPHA_05, size)).expect("feasible");
        assert_eq!(first.rank(), second.rank());
        assert_eq!(first.config(), second.config());
        assert!(first.rank() >= 1 && first.rank() <= size);
    }
}
