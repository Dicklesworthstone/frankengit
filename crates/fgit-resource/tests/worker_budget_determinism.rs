//! FG-089: the determinism and memory-bound contracts of the shared
//! worker-budget calculator.
//!
//! The acceptance line these drills answer is "for a fixed batch, output and
//! ordering are byte-identical across worker counts". That sentence is easy to
//! satisfy vacuously — a test that runs one worker count, or that compares a
//! result to itself, passes without establishing anything. Two disciplines are
//! applied throughout:
//!
//! **Every determinism claim carries a presence case.** Before asserting that
//! [`merge_in_job_order`] is invariant across worker counts, the suite asserts
//! that the naive alternative (concatenating per-worker buckets) genuinely is
//! *not*. If the naive order ever stopped diverging, the invariance assertion
//! would be measuring nothing, and the presence case fails loudly first.
//!
//! **Completion order is adversarial, not incidental.** Workers here report
//! their results in a deterministically permuted order rather than in job
//! order, so a merge that accidentally relies on arrival order cannot pass.
//!
//! No randomness is used anywhere: `rand` is not in the dependency universe,
//! and a determinism suite seeded by a clock would be its own counterexample.

use fgit_resource::workers::{
    BatchMergeRefusal, BatchPlan, BindingConstraint, VarianceClass, WorkerBudget,
    WorkerBudgetInputs, WorkerBudgetRefusal, WorkerMode, merge_in_job_order, plan, plan_for_batch,
};

/// The batch under test: a pure job -> result function, so any difference in
/// output is a difference in *ordering*, never in computation.
fn result_for(job_index: usize) -> String {
    format!(
        "job-{job_index:04}:{}",
        job_index.wrapping_mul(2_654_435_761)
    )
}

fn budget_for(workers: u32) -> WorkerBudget {
    // A generous memory budget so `workers` is exactly the CPU-bound answer,
    // letting these drills vary worker count independently of the formula.
    let budget = plan(WorkerBudgetInputs {
        cpu_cap: workers,
        memory_budget_bytes: 1 << 40,
        per_job_rss_bytes: 1024,
        mode: WorkerMode::Batch,
        variance: VarianceClass::Tight,
    })
    .expect("a generous budget must plan a fleet");
    assert_eq!(
        budget.workers(),
        workers,
        "this drill needs the cpu cap to bind, or it is not varying what it thinks it is"
    );
    budget
}

/// Run a batch on `workers` workers, reporting each worker's results in a
/// deliberately non-job order.
///
/// The permutation is deterministic (reverse within each bucket) but is not
/// job order, which is the point: a merge that depends on arrival order will
/// produce the wrong answer here rather than accidentally the right one.
fn run_batch(job_count: usize, workers: u32) -> Vec<Vec<(usize, String)>> {
    let budget = budget_for(workers);
    let batch = BatchPlan::new(job_count, &budget);

    (0..workers)
        .map(|worker| {
            let mut produced: Vec<(usize, String)> = batch
                .jobs_for(worker)
                .into_iter()
                .map(|index| (index, result_for(index)))
                .collect();
            produced.reverse();
            produced
        })
        .collect()
}

/// The bug this module exists to prevent: concatenating per-worker buckets.
fn naive_concatenation(completed: &[Vec<(usize, String)>]) -> Vec<String> {
    completed
        .iter()
        .flat_map(|bucket| bucket.iter().map(|(_, value)| value.clone()))
        .collect()
}

fn expected_output(job_count: usize) -> Vec<String> {
    (0..job_count).map(result_for).collect()
}

#[test]
fn the_naive_concatenation_really_does_diverge_across_worker_counts() {
    // PRESENCE CASE. Without this, the invariance test below could pass on a
    // batch where every worker count happens to agree, and would then be
    // asserting nothing at all.
    let job_count = 32;
    let one = naive_concatenation(&run_batch(job_count, 1));
    let many = naive_concatenation(&run_batch(job_count, 7));

    assert_ne!(
        one, many,
        "if concatenation were already order-stable, the determinism drills below \
         would be vacuous and this suite would be lying"
    );
}

#[test]
fn merged_output_is_byte_identical_across_every_worker_count() {
    let job_count = 97; // prime, so round-robin buckets are uneven
    let expected = expected_output(job_count);

    for workers in 1..=16_u32 {
        let completed = run_batch(job_count, workers);
        let merged =
            merge_in_job_order(job_count, completed).expect("a complete batch must reassemble");
        assert_eq!(
            merged, expected,
            "worker count {workers} changed the output; the batch is not replayable"
        );
    }
}

#[test]
fn merged_output_is_identical_for_one_worker_and_the_maximum() {
    // The acceptance line names N=1 vs N=max explicitly, so it is asserted
    // explicitly rather than left implied by the sweep above.
    let job_count = 500;
    let serial = merge_in_job_order(job_count, run_batch(job_count, 1))
        .expect("the serial batch must reassemble");
    let parallel = merge_in_job_order(job_count, run_batch(job_count, 64))
        .expect("the parallel batch must reassemble");

    assert_eq!(serial, parallel);
    assert_eq!(serial, expected_output(job_count));
}

#[test]
fn an_empty_batch_is_empty_at_every_worker_count() {
    for workers in 1..=8_u32 {
        let merged = merge_in_job_order(0, run_batch(0, workers))
            .expect("an empty batch reassembles to nothing");
        assert!(merged.is_empty(), "worker count {workers} invented results");
    }
}

#[test]
fn every_job_is_assigned_to_exactly_one_worker() {
    let job_count = 97;
    for workers in 1..=16_u32 {
        let budget = budget_for(workers);
        let batch = BatchPlan::new(job_count, &budget);

        let mut seen = vec![0_u32; job_count];
        for worker in 0..workers {
            for index in batch.jobs_for(worker) {
                seen[index] += 1;
                assert_eq!(
                    batch.owner_of(index),
                    Some(worker),
                    "jobs_for and owner_of disagree about job {index}"
                );
            }
        }

        assert!(
            seen.iter().all(|count| *count == 1),
            "worker count {workers} left a job unassigned or double-assigned"
        );
    }
}

#[test]
fn a_job_index_past_the_batch_has_no_owner() {
    let budget = budget_for(4);
    let batch = BatchPlan::new(10, &budget);
    assert_eq!(batch.owner_of(9), Some(1));
    assert_eq!(batch.owner_of(10), None);
    assert!(batch.jobs_for(4).is_empty(), "worker 4 does not exist");
}

#[test]
fn a_lost_job_is_a_refusal_rather_than_a_short_result() {
    let job_count = 8;
    let mut completed = run_batch(job_count, 3);
    let dropped = completed[0].pop().expect("worker 0 had jobs to drop");

    let outcome = merge_in_job_order::<String>(job_count, completed);
    assert_eq!(
        outcome,
        Err(BatchMergeRefusal::MissingJob { index: dropped.0 }),
        "a batch that lost a job must say so, not return a shorter vector"
    );
}

#[test]
fn a_duplicated_job_is_a_refusal() {
    let job_count = 8;
    let mut completed = run_batch(job_count, 3);
    let duplicate = completed[0][0].clone();
    completed[1].push(duplicate.clone());

    assert_eq!(
        merge_in_job_order::<String>(job_count, completed),
        Err(BatchMergeRefusal::DuplicateJob { index: duplicate.0 })
    );
}

#[test]
fn a_result_from_outside_the_batch_is_a_refusal() {
    let job_count = 4;
    let mut completed = run_batch(job_count, 2);
    completed[0].push((99, "smuggled".to_owned()));

    assert_eq!(
        merge_in_job_order::<String>(job_count, completed),
        Err(BatchMergeRefusal::IndexOutOfRange {
            index: 99,
            job_count: 4
        })
    );
}

#[test]
fn the_memory_bound_holds_across_the_parameter_space() {
    // The property the bead names: the calculator never returns a fleet whose
    // aggregate estimate exceeds the declared budget. Swept rather than
    // spot-checked, over every mode and variance class.
    let modes = [
        WorkerMode::Interactive,
        WorkerMode::Batch,
        WorkerMode::Background,
    ];
    let variances = [
        VarianceClass::Tight,
        VarianceClass::Moderate,
        VarianceClass::Wide,
        VarianceClass::Extreme,
    ];

    let mut planned = 0_u32;
    let mut refused = 0_u32;

    for cpu_cap in [1_u32, 2, 7, 16, 64, 256] {
        for budget_bytes in [1_u64, 1023, 4096, 1 << 20, 1 << 30] {
            for per_job in [1_u64, 512, 4096, 1 << 20] {
                for mode in modes {
                    for variance in variances {
                        let inputs = WorkerBudgetInputs {
                            cpu_cap,
                            memory_budget_bytes: budget_bytes,
                            per_job_rss_bytes: per_job,
                            mode,
                            variance,
                        };
                        match plan(inputs) {
                            Ok(budget) => {
                                planned += 1;
                                assert!(
                                    budget.memory_reserved_bytes() <= budget_bytes,
                                    "{mode}/{variance} cap {cpu_cap} reserved \
                                     {} bytes of a {budget_bytes} byte budget",
                                    budget.memory_reserved_bytes()
                                );
                                assert!(
                                    budget.workers() >= 1,
                                    "a planned fleet must be able to make progress"
                                );
                                let aggregate =
                                    u64::from(budget.workers()) * budget.effective_per_job_bytes();
                                assert_eq!(
                                    aggregate,
                                    budget.memory_reserved_bytes(),
                                    "the reservation must be the fleet's actual aggregate"
                                );
                            }
                            Err(refusal) => {
                                refused += 1;
                                // A refusal is only legitimate when no fleet fits.
                                assert!(
                                    matches!(
                                        refusal,
                                        WorkerBudgetRefusal::BudgetBelowOneJob { .. }
                                    ),
                                    "unexpected refusal {refusal:?} for a well-formed input"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Denominators asserted, so a sweep that silently stopped exercising
    // either branch fails instead of passing quietly.
    assert_eq!(
        planned + refused,
        6 * 5 * 4 * 3 * 4,
        "the sweep did not cover the parameter space it claims to"
    );
    assert!(planned > 0, "the sweep never planned a fleet");
    assert!(
        refused > 0,
        "the sweep never exercised the below-one-job refusal, so the bound is untested \
         at its boundary"
    );
}

#[test]
fn the_binding_constraint_reports_which_input_actually_bound() {
    let cpu_bound = plan(WorkerBudgetInputs {
        cpu_cap: 4,
        memory_budget_bytes: 1 << 30,
        per_job_rss_bytes: 1024,
        mode: WorkerMode::Batch,
        variance: VarianceClass::Tight,
    })
    .expect("must plan");
    assert_eq!(cpu_bound.binding(), BindingConstraint::Cpu);

    let memory_bound = plan(WorkerBudgetInputs {
        cpu_cap: 64,
        memory_budget_bytes: 2048,
        per_job_rss_bytes: 1024,
        mode: WorkerMode::Batch,
        variance: VarianceClass::Tight,
    })
    .expect("must plan");
    assert_eq!(memory_bound.binding(), BindingConstraint::Memory);

    let both = plan(WorkerBudgetInputs {
        cpu_cap: 4,
        memory_budget_bytes: 4096,
        per_job_rss_bytes: 1024,
        mode: WorkerMode::Batch,
        variance: VarianceClass::Tight,
    })
    .expect("must plan");
    assert_eq!(both.binding(), BindingConstraint::Both);
}

#[test]
fn planning_is_a_pure_function_of_its_inputs() {
    // Same inputs, many calls, one answer: the property every replay depends
    // on. If anything here ever consulted a clock, an environment variable, or
    // a core count, this drill is what catches it.
    let inputs = WorkerBudgetInputs {
        cpu_cap: 12,
        memory_budget_bytes: 9_437_184,
        per_job_rss_bytes: 786_432,
        mode: WorkerMode::Interactive,
        variance: VarianceClass::Moderate,
    };
    let first = plan(inputs).expect("must plan");
    for _ in 0..64 {
        assert_eq!(plan(inputs), Ok(first), "planning is not deterministic");
    }
}

#[test]
fn a_fleet_is_never_larger_than_the_batch_it_serves() {
    // Found by comparing against fgit-doc's independent implementation, which
    // caps by input count while the first cut of this one did not.
    let roomy = WorkerBudgetInputs {
        cpu_cap: 64,
        memory_budget_bytes: 1 << 40,
        per_job_rss_bytes: 1024,
        mode: WorkerMode::Batch,
        variance: VarianceClass::Tight,
    };

    let uncapped = plan(roomy).expect("must plan");
    assert_eq!(
        uncapped.workers(),
        64,
        "the drill needs an uncapped fleet of 64"
    );

    let capped = plan_for_batch(roomy, 3).expect("must plan");
    assert_eq!(
        capped.workers(),
        3,
        "three jobs cannot occupy sixty-four workers"
    );
    assert_eq!(capped.binding(), BindingConstraint::BatchSize);
}

#[test]
fn capping_by_batch_size_shrinks_the_reservation_too() {
    // The tempting bug: cap the worker count but carry the uncapped
    // reservation, over-reporting memory the batch will never hold.
    let inputs = WorkerBudgetInputs {
        cpu_cap: 32,
        memory_budget_bytes: 1 << 30,
        per_job_rss_bytes: 4096,
        mode: WorkerMode::Batch,
        variance: VarianceClass::Tight,
    };
    let capped = plan_for_batch(inputs, 2).expect("must plan");

    assert_eq!(capped.workers(), 2);
    assert_eq!(
        capped.memory_reserved_bytes(),
        2 * 4096,
        "the reservation must track the capped fleet, not the uncapped one"
    );
    assert_eq!(
        u64::from(capped.workers()) * capped.effective_per_job_bytes(),
        capped.memory_reserved_bytes()
    );
}

#[test]
fn capping_never_raises_the_count_or_relaxes_the_memory_bound() {
    // The cap must be a floor-preserving narrowing, never an escape hatch: if
    // memory already bound the fleet to 3, asking for a 100-job batch must not
    // yield 100 workers.
    let tight = WorkerBudgetInputs {
        cpu_cap: 64,
        memory_budget_bytes: 3 * 1024,
        per_job_rss_bytes: 1024,
        mode: WorkerMode::Batch,
        variance: VarianceClass::Tight,
    };
    let capped = plan_for_batch(tight, 100).expect("must plan");

    assert_eq!(
        capped.workers(),
        3,
        "batch size must not override the memory bound"
    );
    assert_eq!(capped.binding(), BindingConstraint::Memory);
    assert!(capped.memory_reserved_bytes() <= 3 * 1024);
}

#[test]
fn an_empty_batch_still_gets_a_fleet_that_could_make_progress() {
    let inputs = WorkerBudgetInputs {
        cpu_cap: 8,
        memory_budget_bytes: 1 << 30,
        per_job_rss_bytes: 1024,
        mode: WorkerMode::Batch,
        variance: VarianceClass::Tight,
    };
    let capped = plan_for_batch(inputs, 0).expect("must plan");
    assert_eq!(capped.workers(), 1, "zero is not a fleet");
}

#[test]
fn a_batch_capped_fleet_still_merges_deterministically() {
    // The cap must not create a hole in the determinism contract: a batch
    // planned through plan_for_batch reassembles exactly as one planned
    // through plan.
    let job_count = 5;
    let inputs = WorkerBudgetInputs {
        cpu_cap: 64,
        memory_budget_bytes: 1 << 40,
        per_job_rss_bytes: 1024,
        mode: WorkerMode::Batch,
        variance: VarianceClass::Tight,
    };
    let budget = plan_for_batch(inputs, job_count).expect("must plan");
    assert_eq!(budget.workers(), 5);

    let batch = BatchPlan::new(job_count, &budget);
    let completed: Vec<Vec<(usize, String)>> = (0..budget.workers())
        .map(|worker| {
            let mut produced: Vec<(usize, String)> = batch
                .jobs_for(worker)
                .into_iter()
                .map(|index| (index, result_for(index)))
                .collect();
            produced.reverse();
            produced
        })
        .collect();

    let merged = merge_in_job_order(job_count, completed).expect("must reassemble");
    assert_eq!(merged, expected_output(job_count));
}
