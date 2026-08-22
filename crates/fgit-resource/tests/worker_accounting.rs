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
use fgit_resource::workers::{
    BatchPlan, VarianceClass, WorkerBudgetInputs, WorkerMode, plan, plan_for_batch,
};

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
fn a_batch_plan_records_its_job_count_and_carries_the_fleet_width_unchanged() {
    // `BatchPlan::new` is a pairing, not a planner: it records `job_count` and
    // copies `budget.workers` verbatim. Narrowing a fleet to the batch it
    // serves is a DIFFERENT function -- `plan_for_batch` -- and the test below
    // pins that contract where it actually lives.
    //
    // This test previously asserted `small.workers() <= 2` and
    // `empty.workers() == 0` against `BatchPlan::new`. Both are
    // `plan_for_batch`'s semantics asserted against the wrong constructor, and
    // both were wrong from the moment they were written; they went in red
    // because the commit landed under the code-first wave without the test
    // being run.
    let budget = plan(inputs(WorkerMode::Batch, VarianceClass::Tight)).expect("a plan fits");

    for job_count in [0_usize, 2, 10_000] {
        let batch = BatchPlan::new(job_count, &budget);
        assert_eq!(batch.job_count(), job_count);
        assert_eq!(
            batch.workers(),
            budget.workers(),
            "BatchPlan::new must carry the fleet width unchanged for {job_count} jobs; \
             narrowing belongs to plan_for_batch"
        );
    }

    // What "no jobs" actually means here: the width is untouched, but no index
    // is owned and every worker is idle. That is the property a caller depends
    // on, and it is observable without pretending the width collapsed.
    let empty = BatchPlan::new(0, &budget);
    assert_eq!(empty.owner_of(0), None, "an empty batch owns no job index");
    for worker in 0..budget.workers() {
        assert!(
            empty.jobs_for(worker).is_empty(),
            "worker {worker} must have no work in an empty batch"
        );
    }

    // The discriminating twin: a non-empty batch does assign work, so the
    // emptiness above is a real distinction rather than accessors that always
    // return nothing.
    let two = BatchPlan::new(2, &budget);
    assert_eq!(two.owner_of(0), Some(0), "the first job has an owner");
    assert_eq!(two.owner_of(2), None, "index 2 is outside a two-job batch");
}

#[test]
fn plan_for_batch_narrows_the_fleet_to_the_batch_and_never_widens_it() {
    // The capping contract the test above was mistakenly asserting, pinned
    // against the function that actually implements it (`workers.rs:401`).
    let uncapped = plan(inputs(WorkerMode::Batch, VarianceClass::Tight)).expect("a plan fits");
    assert!(
        uncapped.workers() > 2,
        "the fixture must plan more than two workers ({} planned) or the narrowing below \
         proves nothing",
        uncapped.workers()
    );

    let narrowed =
        plan_for_batch(inputs(WorkerMode::Batch, VarianceClass::Tight), 2).expect("a plan fits");
    assert_eq!(
        narrowed.workers(),
        2,
        "two jobs must not reserve a fleet wider than two"
    );

    // The permitted twin: a batch at or above the resource-derived width is
    // returned unchanged rather than widened to match the job count. Widening
    // is the direction a bug would go, because growing to fit looks helpful.
    let wide = plan_for_batch(inputs(WorkerMode::Batch, VarianceClass::Tight), 10_000)
        .expect("a plan fits");
    assert_eq!(
        wide.workers(),
        uncapped.workers(),
        "a job count above the fleet width must not widen the fleet"
    );

    // The floor: zero jobs still plans one worker rather than an unusable
    // zero-width fleet that could divide by zero downstream.
    let none =
        plan_for_batch(inputs(WorkerMode::Batch, VarianceClass::Tight), 0).expect("a plan fits");
    assert_eq!(
        none.workers(),
        1,
        "the cap floors at one worker, never zero"
    );
}
