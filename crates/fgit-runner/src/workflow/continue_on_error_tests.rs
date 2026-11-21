//! Scheduler fault tests; actual shell execution is covered by workflow_matrix.
use super::*;
use std::collections::VecDeque;

const SOURCE: &str = "name: optional check\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: optional\n        continue-on-error: true\n      - run: after\n      - if: failure()\n        run: diagnose\n      - if: always()\n        run: cleanup\n  package:\n    needs: build\n    runs-on: fgit-trusted-local\n    steps:\n      - run: package\n";

fn observation(outcome: StepOutcome) -> StepObservation {
    StepObservation {
        outcome,
        exit_code: Some(if outcome == StepOutcome::Succeeded {
            0
        } else {
            7
        }),
        stdout: b"out".to_vec(),
        stderr: b"err".to_vec(),
        elapsed_millis: 1,
        output_complete: true,
        retain_workspace: false,
    }
}

struct Executor {
    observations: VecDeque<Result<StepObservation, WorkerFailure>>,
    scripts: Vec<String>,
    closed: Vec<bool>,
    close_refused: bool,
    terminal: Vec<JobReport>,
}
impl Executor {
    fn new(first: StepObservation) -> Self {
        Self {
            observations: VecDeque::from([Ok(first)]),
            scripts: Vec::new(),
            closed: Vec::new(),
            close_refused: false,
            terminal: Vec::new(),
        }
    }
}
impl WorkflowExecutor for Executor {
    fn begin_job(&mut self, _: usize, _: &Job, _: &dyn Fn() -> bool) -> Result<(), WorkerFailure> {
        Ok(())
    }
    fn execute_step(
        &mut self,
        _: usize,
        script: &str,
        _: StepLimits,
        _: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.scripts.push(script.to_owned());
        self.observations
            .pop_front()
            .unwrap_or_else(|| Ok(observation(StepOutcome::Succeeded)))
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        self.closed.push(retain);
        if self.close_refused {
            Err(WorkerFailure::new("fixture cleanup failure", true))
        } else {
            Ok(())
        }
    }
    fn observe_job(&mut self, report: &JobReport) {
        self.terminal.push(report.clone());
    }
}

fn run(source: &str, worker: &mut Executor) -> WorkflowReport {
    WorkflowPlan::compile(source)
        .unwrap()
        .execute(WorkflowLimits::default(), worker, &|| true)
        .unwrap()
}

#[test]
fn ordinary_optional_failure_preserves_evidence_and_allows_success_steps_and_dependencies() {
    let failed = observation(StepOutcome::Failed);
    let mut worker = Executor::new(failed.clone());
    let report = run(SOURCE, &mut worker);
    assert!(report.succeeded());
    assert_eq!(worker.scripts, ["optional", "after", "cleanup", "package"]);
    assert_eq!(worker.closed, [false, false]);
    assert_eq!(worker.terminal, report.jobs);
    let optional = &report.jobs[0].steps[0];
    assert_eq!(optional.observation, failed);
    assert!(optional.continue_on_error);
    assert!(optional.outcome_tolerated);
    assert!(!report.jobs[0].steps[1].outcome_tolerated);
    let json = report.to_json();
    assert!(json.starts_with("{\"schema_version\":3,"));
    assert!(
        json.contains(
            "\"continue_on_error\":true,\"outcome_tolerated\":true,\"outcome\":\"failed\""
        )
    );
    assert!(json.contains("\"shell\":\"/bin/sh\",\"shell_flags\":[\"-eu\",\"-c\"]"));
}

#[test]
fn omitted_and_false_policies_keep_failure_semantics_and_original_report_grammar() {
    for policy in ["", "        continue-on-error: false\n"] {
        let source = SOURCE.replace("        continue-on-error: true\n", policy);
        let mut worker = Executor::new(observation(StepOutcome::Failed));
        let report = run(&source, &mut worker);
        assert_eq!(report.jobs[0].outcome, JobOutcome::Failed);
        assert_eq!(report.jobs[1].outcome, JobOutcome::Skipped);
        assert_eq!(worker.scripts, ["optional", "diagnose", "cleanup"]);
        let json = report.to_json();
        assert!(json.starts_with("{\"schema_version\":1,"));
        assert!(!json.contains("continue_on_error"));
        assert!(!json.contains("outcome_tolerated"));
    }
}

#[test]
fn successful_optional_step_records_policy_without_inventing_a_tolerated_failure() {
    let mut worker = Executor::new(observation(StepOutcome::Succeeded));
    let report = run(SOURCE, &mut worker);
    assert!(report.succeeded());
    assert!(report.jobs[0].steps[0].continue_on_error);
    assert!(!report.jobs[0].steps[0].outcome_tolerated);
    assert!(report.to_json().starts_with("{\"schema_version\":3,"));
}

#[test]
fn optional_cleanup_failure_cannot_erase_an_earlier_required_failure() {
    let source = SOURCE.replace(
        "      - run: optional",
        "      - run: required\n      - if: always()\n        run: optional",
    );
    let mut worker = Executor::new(observation(StepOutcome::Failed));
    worker
        .observations
        .push_back(Ok(observation(StepOutcome::Failed)));
    let report = run(&source, &mut worker);
    assert_eq!(
        worker.scripts,
        ["required", "optional", "diagnose", "cleanup"]
    );
    assert_eq!(report.jobs[0].outcome, JobOutcome::Failed);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Skipped);
    assert!(!report.jobs[0].steps[0].outcome_tolerated);
    assert!(report.jobs[0].steps[1].outcome_tolerated);
}

#[test]
fn cancellation_timeout_output_and_containment_are_never_tolerated() {
    for outcome in [
        StepOutcome::Cancelled,
        StepOutcome::TimedOut,
        StepOutcome::OutputLimit,
        StepOutcome::ContainmentFailure,
    ] {
        let mut worker = Executor::new(observation(outcome));
        let report = run(SOURCE, &mut worker);
        assert_ne!(report.jobs[0].outcome, JobOutcome::Succeeded, "{outcome:?}");
        assert!(!report.jobs[0].steps[0].outcome_tolerated);
        assert_eq!(worker.scripts, ["optional"]);
        assert!(!report.succeeded());
    }
}

#[test]
fn incomplete_or_invalid_exit_evidence_cannot_acquire_optional_success() {
    for fault in 0..5 {
        let mut failed = observation(StepOutcome::Failed);
        match fault {
            0 => failed.exit_code = None,
            1 => failed.exit_code = Some(0),
            2 => failed.output_complete = false,
            3 => failed.retain_workspace = true,
            _ => failed.stdout = vec![b'x'; 256 * 1024 + 1],
        }
        let mut worker = Executor::new(failed);
        let report = run(SOURCE, &mut worker);
        assert_ne!(
            report.jobs[0].outcome,
            JobOutcome::Succeeded,
            "fault {fault}"
        );
        assert!(!report.jobs[0].steps[0].outcome_tolerated);
        assert!(!report.succeeded());
    }
}

#[test]
fn worker_and_cleanup_refusals_remain_failures_after_optional_execution() {
    let mut worker = Executor::new(observation(StepOutcome::Failed));
    worker.observations[0] = Err(WorkerFailure::new("fixture spawn refusal", false));
    let report = run(SOURCE, &mut worker);
    assert_eq!(report.jobs[0].outcome, JobOutcome::Refused);
    assert!(report.jobs[0].steps.is_empty());
    assert!(!report.succeeded());
    let mut worker = Executor::new(observation(StepOutcome::Failed));
    worker.close_refused = true;
    let report = run(SOURCE, &mut worker);
    assert_eq!(report.jobs[0].outcome, JobOutcome::Refused);
    assert!(report.jobs[0].requires_containment());
    assert!(report.jobs[0].steps[0].outcome_tolerated);
    assert!(!report.succeeded());
}

#[test]
fn a_tolerated_failure_does_not_stop_matrix_siblings_or_the_group_dependency() {
    let source = SOURCE.replace("    steps:\n      - run: optional", "    strategy:\n      matrix:\n        variant: [one, two]\n    steps:\n      - run: optional");
    let mut worker = Executor::new(observation(StepOutcome::Failed));
    let report = run(&source, &mut worker);
    assert_eq!(report.jobs.len(), 3);
    assert!(report.succeeded());
    assert_eq!(
        worker.scripts,
        [
            "optional", "after", "cleanup", "optional", "after", "cleanup", "package"
        ]
    );
    assert!(report.jobs[0].steps[0].outcome_tolerated);
    assert!(!report.jobs[1].steps[0].outcome_tolerated);
}

#[test]
fn configured_policy_does_not_refresh_the_shared_output_allowance() {
    let mut worker = Executor::new(observation(StepOutcome::Failed));
    let report = WorkflowPlan::compile(SOURCE)
        .unwrap()
        .execute(
            WorkflowLimits {
                stream_bytes: 3,
                total_output_bytes: 6,
                ..WorkflowLimits::default()
            },
            &mut worker,
            &|| true,
        )
        .unwrap();
    assert!(report.jobs[0].steps[0].outcome_tolerated);
    assert_eq!(report.jobs[0].outcome, JobOutcome::OutputLimit);
    assert_eq!(worker.scripts, ["optional"]);
    assert!(!report.succeeded());
}
