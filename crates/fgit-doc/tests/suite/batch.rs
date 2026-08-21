//! Batch rendering: derived worker budgets, and one receipt line per input.

use fgit_doc::{
    BatchInput, BatchPlan, InputOutcome, Limits, ParseProfile, RefusalKind, RenderProfile,
    VarianceClass, WorkloadProfile, batch::SkipReason, render_batch, worker_count,
};

const fn workload(
    cpu_cap: u32,
    memory: u64,
    per_job: u64,
    variance: VarianceClass,
) -> WorkloadProfile {
    WorkloadProfile {
        cpu_cap,
        memory_budget_bytes: memory,
        per_job_bytes: per_job,
        variance,
    }
}

#[test]
fn the_worker_count_is_the_declared_minimum() {
    let plenty = workload(8, 1024, 16, VarianceClass::Uniform);
    assert_eq!(
        worker_count(plenty, RenderProfile::PlainText, 100).expect("derivable"),
        8,
        "the core cap binds when memory and mode allow more"
    );
    let memory_bound = workload(64, 100, 16, VarianceClass::Uniform);
    assert_eq!(
        worker_count(memory_bound, RenderProfile::PlainText, 100).expect("derivable"),
        6,
        "one hundred bytes of budget at sixteen bytes a job is six workers"
    );
    let input_bound = workload(64, 1_000_000, 16, VarianceClass::Uniform);
    assert_eq!(
        worker_count(input_bound, RenderProfile::PlainText, 3).expect("derivable"),
        3,
        "there is never a worker without an input"
    );
    let mode_bound = workload(1000, 1_000_000_000, 16, VarianceClass::Uniform);
    assert_eq!(
        worker_count(mode_bound, RenderProfile::ApiJson, 10_000).expect("derivable"),
        32,
        "the heaviest surface caps lowest"
    );
}

#[test]
fn variance_reserves_memory_headroom() {
    let memory = 1024;
    let per_job = 64;
    let uniform = worker_count(
        workload(64, memory, per_job, VarianceClass::Uniform),
        RenderProfile::PlainText,
        1000,
    )
    .expect("derivable");
    let mixed = worker_count(
        workload(64, memory, per_job, VarianceClass::Mixed),
        RenderProfile::PlainText,
        1000,
    )
    .expect("derivable");
    let skewed = worker_count(
        workload(64, memory, per_job, VarianceClass::Skewed),
        RenderProfile::PlainText,
        1000,
    )
    .expect("derivable");
    assert_eq!((uniform, mixed, skewed), (16, 8, 4));
}

#[test]
fn an_unusable_workload_is_refused_and_a_usable_one_is_derived() {
    worker_count(
        workload(1, 1024, 16, VarianceClass::Uniform),
        RenderProfile::PlainText,
        1,
    )
    .expect("a usable workload is derivable");

    let no_cores = worker_count(
        workload(0, 1024, 16, VarianceClass::Uniform),
        RenderProfile::PlainText,
        1,
    )
    .expect_err("a zero core cap is refused");
    assert_eq!(no_cores.kind(), RefusalKind::WorkloadUnusable);

    let no_estimate = worker_count(
        workload(4, 1024, 0, VarianceClass::Uniform),
        RenderProfile::PlainText,
        1,
    )
    .expect_err("a zero per-job estimate is refused, not guessed");
    assert_eq!(no_estimate.kind(), RefusalKind::WorkloadUnusable);
}

#[test]
fn a_uniform_plan_uses_contiguous_blocks_and_a_skewed_plan_deals_round_robin() {
    let uniform = BatchPlan::derive(
        workload(4, 1_000_000, 16, VarianceClass::Uniform),
        RenderProfile::PlainText,
        8,
    )
    .expect("plan derives");
    assert_eq!(uniform.workers(), 4);
    assert_eq!(uniform.assignment(), &[0, 0, 1, 1, 2, 2, 3, 3]);

    let skewed = BatchPlan::derive(
        workload(4, 1_000_000, 16, VarianceClass::Skewed),
        RenderProfile::PlainText,
        8,
    )
    .expect("plan derives");
    assert_eq!(skewed.workers(), 4);
    assert_eq!(skewed.assignment(), &[0, 1, 2, 3, 0, 1, 2, 3]);
}

#[test]
fn every_plan_assigns_every_input_exactly_once() {
    for count in [0_u32, 1, 2, 5, 9, 17, 64] {
        for variance in [
            VarianceClass::Uniform,
            VarianceClass::Mixed,
            VarianceClass::Skewed,
        ] {
            let plan = BatchPlan::derive(
                workload(6, 1_000_000, 16, variance),
                RenderProfile::HtmlSafe,
                count,
            )
            .expect("plan derives");
            let mut seen = plan.shards().into_iter().flatten().collect::<Vec<_>>();
            seen.sort_unstable();
            assert_eq!(
                seen,
                (0..count).collect::<Vec<_>>(),
                "count {count} variance {} lost or duplicated an input",
                variance.tag()
            );
        }
    }
}

#[test]
fn every_input_receives_exactly_one_terminal_outcome_in_input_order() {
    let big = "a".repeat(4096);
    let inputs = vec![
        BatchInput::render("# first\n"),
        BatchInput::skipped("unchanged\n", SkipReason::Unchanged),
        BatchInput::render("second *doc*\n"),
        BatchInput::skipped("policy\n", SkipReason::ExcludedByHost),
        BatchInput::render(&big),
    ];
    let profile = ParseProfile::with_limits(Limits {
        max_input_bytes: 1024,
        ..Limits::DEFAULT
    });
    let receipt = render_batch(
        &inputs,
        profile,
        RenderProfile::HtmlSafe,
        workload(3, 1_000_000, 16, VarianceClass::Mixed),
    )
    .expect("the batch runs");

    assert_eq!(receipt.outcomes().len(), inputs.len());
    assert_eq!(receipt.rendered_count(), 2);
    assert_eq!(receipt.skipped_count(), 2);
    assert_eq!(receipt.refused_count(), 1);

    let tags = receipt
        .outcomes()
        .iter()
        .map(InputOutcome::tag)
        .collect::<Vec<_>>();
    assert_eq!(
        tags,
        vec!["rendered", "skipped", "rendered", "skipped", "refused"],
        "the receipt order must follow the input order"
    );

    match receipt.outcomes().first() {
        Some(InputOutcome::Rendered(rendered)) => {
            assert_eq!(rendered.as_str(), "<h1>first</h1>\n");
            assert_eq!(rendered.profile(), RenderProfile::HtmlSafe);
        }
        other => panic!("expected the first input to render, got {other:?}"),
    }
    match receipt.outcomes().get(4) {
        Some(InputOutcome::Refused(refusal)) => {
            assert_eq!(refusal.kind(), RefusalKind::InputTooLarge);
        }
        other => panic!("expected the oversized input to be refused, got {other:?}"),
    }
}

#[test]
fn one_refused_input_does_not_abort_the_rest_of_the_batch() {
    let oversized = "b".repeat(2048);
    let inputs = vec![
        BatchInput::render(&oversized),
        BatchInput::render("survivor\n"),
        BatchInput::render(&oversized),
    ];
    let profile = ParseProfile::with_limits(Limits {
        max_input_bytes: 64,
        ..Limits::DEFAULT
    });
    let receipt = render_batch(
        &inputs,
        profile,
        RenderProfile::PlainText,
        WorkloadProfile::SERIAL,
    )
    .expect("the batch runs");
    assert_eq!(receipt.refused_count(), 2);
    assert_eq!(receipt.rendered_count(), 1);
    match receipt.outcomes().get(1) {
        Some(InputOutcome::Rendered(rendered)) => assert_eq!(rendered.as_str(), "survivor\n"),
        other => panic!("the middle input must still render, got {other:?}"),
    }
}

#[test]
fn too_many_inputs_is_refused_and_the_ceiling_itself_is_accepted() {
    let profile = ParseProfile::with_limits(Limits {
        max_batch_inputs: 4,
        ..Limits::DEFAULT
    });
    let at_ceiling = vec![BatchInput::render("x\n"); 4];
    render_batch(
        &at_ceiling,
        profile,
        RenderProfile::PlainText,
        WorkloadProfile::SERIAL,
    )
    .expect("exactly the ceiling is accepted");

    let past_ceiling = vec![BatchInput::render("x\n"); 5];
    let refusal = render_batch(
        &past_ceiling,
        profile,
        RenderProfile::PlainText,
        WorkloadProfile::SERIAL,
    )
    .expect_err("one input past the ceiling is refused");
    assert_eq!(refusal.kind(), RefusalKind::TooManyBatchInputs);
    assert_eq!(refusal.limit(), 4);
    assert_eq!(refusal.observed(), 5);
}

#[test]
fn an_empty_batch_is_a_valid_complete_receipt() {
    let receipt = render_batch(
        &[],
        ParseProfile::DEFAULT,
        RenderProfile::PlainText,
        WorkloadProfile::SERIAL,
    )
    .expect("an empty batch runs");
    assert_eq!(receipt.outcomes(), []);
    assert_eq!(receipt.plan().workers(), 1);
}
