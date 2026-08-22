//! What a planned worker fleet costs, and which grades it costs it in.
//!
//! `WorkerBudget::charge` decides which pool a fleet spends from. Nothing
//! asserted that before this file: the determinism suite exercises merged
//! output across worker counts, and the planner's own unit tests exercise
//! refusals and sizing, but the *accounting* — which grade, how much — was
//! reachable only by reading it.
//!
//! That matters because a wrong grade is silent. Charging `CpuMicros` where the
//! fleet means `FailureDomainSlots` still produces a well-formed
//! `ResourceVector`, still conserves, and still settles; the region simply
//! draws down the wrong pool, and the failure surfaces somewhere else entirely
//! as a budget that ran out for no visible reason.

use fgit_resource::algebra::{GRADE_COUNT, Grade};
use fgit_resource::workers::{BatchPlan, VarianceClass, WorkerBudgetInputs, WorkerMode, plan};

const fn inputs(mode: WorkerMode, variance: VarianceClass) -> WorkerBudgetInputs {
    WorkerBudgetInputs {
        cpu_cap: 8,
        memory_budget_bytes: 1_024 * 1_024 * 64,
        per_job_rss_bytes: 1_024 * 1_024,
        mode,
        variance,
    }
}

#[test]
fn a_fleet_charges_exactly_memory_bytes_and_failure_domain_slots() {
    // The claim in `charge`'s own docs: a worker IS a concurrent slot in one
    // failure domain, so it spends the grade the algebra already has for that.
    // Asserted by grade rather than by position, so reordering the returned
    // array cannot make this pass while the meaning changes.
    let budget = plan(inputs(WorkerMode::Batch, VarianceClass::Tight)).expect("a plan fits");
    let charge = budget.charge();

    let memory = charge
        .iter()
        .find(|(grade, _)| *grade == Grade::MemoryBytes)
        .expect("a fleet holds resident bytes");
    let slots = charge
        .iter()
        .find(|(grade, _)| *grade == Grade::FailureDomainSlots)
        .expect("a worker is a concurrent slot in one failure domain");

    assert_eq!(
        memory.1,
        budget.memory_reserved_bytes(),
        "the memory charge must be the reservation the plan made, not a re-derivation"
    );
    assert_eq!(slots.1, u64::from(budget.workers()), "one slot per worker");
}

#[test]
fn the_charge_introduces_no_grade_outside_the_closed_set() {
    // "The grade list is closed and adding one is a protocol change." A fleet
    // that charged a grade the algebra does not have could not be settled
    // against a region's budget at all, so this is the check that keeps the
    // accounting inside the algebra rather than beside it.
    let budget = plan(inputs(WorkerMode::Interactive, VarianceClass::Wide)).expect("a plan fits");
    let charge = budget.charge();

    assert_eq!(Grade::ALL.len(), GRADE_COUNT);
    for (grade, _) in charge {
        assert!(
            Grade::ALL.contains(&grade),
            "{grade:?} is not a member of the closed grade set"
        );
    }

    // And no grade is charged twice, which would double-spend one pool while
    // leaving the array the right length.
    assert_ne!(
        charge[0].0, charge[1].0,
        "the same grade charged twice would draw down one pool twice"
    );
}

#[test]
fn every_mode_and_variance_charges_only_grades_it_declares() {
    // Swept rather than sampled: a mode or variance that changed the charged
    // grades would be a protocol change, and this is where it becomes visible.
    for mode in [
        WorkerMode::Interactive,
        WorkerMode::Batch,
        WorkerMode::Background,
    ] {
        for variance in [
            VarianceClass::Tight,
            VarianceClass::Moderate,
            VarianceClass::Wide,
            VarianceClass::Extreme,
        ] {
            let budget = plan(inputs(mode, variance)).expect("every combination fits this budget");
            let grades: Vec<Grade> = budget.charge().iter().map(|(g, _)| *g).collect();
            assert_eq!(
                grades,
                vec![Grade::MemoryBytes, Grade::FailureDomainSlots],
                "{mode:?}/{variance:?} charged {grades:?}"
            );
            assert!(
                budget.workers() >= 1,
                "a plan that fits has at least one worker"
            );
        }
    }
}

#[test]
fn a_wider_variance_never_plans_more_workers_than_a_tighter_one() {
    // The conservative-rounding invariant, stated where a caller can see it.
    // `headroom_percent` inflates the per-job estimate with ceiling division so
    // "a job is never planned as smaller than its estimate"; the consequence is
    // that trusting the estimate less can only ever buy fewer workers, never
    // more. An inflation that rounded down would break this at exactly the
    // boundary where a job is planned smaller than it is.
    let mut previous = u32::MAX;
    for variance in [
        VarianceClass::Tight,
        VarianceClass::Moderate,
        VarianceClass::Wide,
        VarianceClass::Extreme,
    ] {
        let budget = plan(inputs(WorkerMode::Batch, variance)).expect("a plan fits");
        assert!(
            budget.workers() <= previous,
            "{variance:?} planned {} workers after a tighter class planned {previous}",
            budget.workers()
        );
        previous = budget.workers();
    }
    assert!(previous >= 1, "even the widest class plans a usable fleet");
}

#[test]
fn a_batch_plan_reports_the_job_count_it_was_assigned() {
    // `BatchPlan::job_count` exists so a caller can tell how many jobs a fleet
    // was assembled for, independently of how wide the fleet is. Never asserted
    // before, and it is the only way to distinguish "few jobs, narrow fleet"
    // from "many jobs, fleet capped by resources" from the outside.
    let budget = plan(inputs(WorkerMode::Batch, VarianceClass::Tight)).expect("a plan fits");

    let small = BatchPlan::new(2, &budget);
    assert_eq!(small.job_count(), 2);
    assert!(
        small.workers() <= 2,
        "a plan is never wider than the batch it serves"
    );

    // The permitted twin: a batch larger than the fleet leaves the fleet at its
    // resource-derived width rather than growing to match the job count. That
    // is the direction a bug would go, because widening to fit looks helpful.
    let large = BatchPlan::new(10_000, &budget);
    assert_eq!(large.job_count(), 10_000);
    assert_eq!(
        large.workers(),
        budget.workers(),
        "job count above the fleet width must not widen the fleet"
    );

    // And the degenerate case: no jobs needs no workers.
    let empty = BatchPlan::new(0, &budget);
    assert_eq!(empty.job_count(), 0);
    assert_eq!(empty.workers(), 0, "an empty batch plans no workers");
}
