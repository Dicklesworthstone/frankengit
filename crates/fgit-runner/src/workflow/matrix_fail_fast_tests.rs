//! Deterministic scheduler faults; live shell/workspace tests are in
//! tests/workflow_matrix.rs. These do not claim OS containment evidence.
use super::*;

const SOURCE: &str = "name: failure policy\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    strategy:\n      matrix:\n        mode: [first, last]\n    steps:\n      - run: build\n  independent:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: independent\n  package:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: package\n";

struct Executor {
    outcome: StepOutcome,
    retained: bool,
    first: bool,
    oversized: bool,
    refuse_begin: bool,
    refuse_close: bool,
    current: Option<String>,
    started: Vec<String>,
    closed: Vec<bool>,
    observations: Vec<JobReport>,
}
impl Executor {
    fn new(outcome: StepOutcome) -> Self {
        Self {
            outcome,
            retained: false,
            first: true,
            oversized: false,
            refuse_begin: false,
            refuse_close: false,
            current: None,
            started: Vec::new(),
            closed: Vec::new(),
            observations: Vec::new(),
        }
    }
}
impl WorkflowExecutor for Executor {
    fn begin_job(
        &mut self,
        _: usize,
        job: &Job,
        _: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        assert!(self.current.is_none());
        self.started.push(job.id.clone());
        if self.refuse_begin && self.first {
            self.first = false;
            return Err(WorkerFailure::new("fixture pre-launch refusal", false));
        }
        self.current = Some(job.id.clone());
        Ok(())
    }
    fn execute_step(
        &mut self,
        _: usize,
        _: &str,
        limits: StepLimits,
        _: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        let first = std::mem::take(&mut self.first);
        let outcome = if first {
            self.outcome
        } else {
            StepOutcome::Succeeded
        };
        Ok(StepObservation {
            outcome,
            exit_code: Some(i32::from(outcome != StepOutcome::Succeeded)),
            stdout: if self.oversized {
                vec![b'x'; limits.stream_bytes + 1]
            } else {
                Vec::new()
            },
            stderr: Vec::new(),
            elapsed_millis: 1,
            output_complete: true,
            retain_workspace: first && self.retained,
        })
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        assert!(self.current.take().is_some());
        self.closed.push(retain);
        if self.refuse_close {
            Err(WorkerFailure::new("fixture unresolved close", true))
        } else {
            Ok(())
        }
    }
    fn observe_job(&mut self, report: &JobReport) {
        assert!(
            self.current.is_none(),
            "terminal observation follows closure"
        );
        self.observations.push(report.clone());
    }
}
fn run(worker: &mut Executor, source: &str, limits: WorkflowLimits) -> WorkflowReport {
    WorkflowPlan::compile(source)
        .unwrap()
        .execute(limits, worker, &|| true)
        .unwrap()
}

#[test]
fn clean_failure_timeout_output_and_refusal_suppress_the_group_without_cancelling_other_jobs() {
    for outcome in [
        StepOutcome::Failed,
        StepOutcome::TimedOut,
        StepOutcome::OutputLimit,
    ] {
        let mut worker = Executor::new(outcome);
        let report = run(&mut worker, SOURCE, WorkflowLimits::default());
        assert_eq!(worker.started, ["build__matrix_000", "independent"]);
        assert_eq!(report.jobs[1].outcome, JobOutcome::Skipped);
        assert_eq!(report.jobs[2].outcome, JobOutcome::Succeeded);
        assert_eq!(report.jobs[3].outcome, JobOutcome::Skipped);
        assert_ne!(report.jobs[0].outcome, JobOutcome::Succeeded);
        assert_eq!(worker.observations, report.jobs);
        assert_eq!(worker.closed, [false, false]);
        assert!(!report.succeeded());
        let twin = SOURCE.replace("    strategy:\n", "    strategy:\n      fail-fast: false\n");
        let mut permitted = Executor::new(outcome);
        let report = run(&mut permitted, &twin, WorkflowLimits::default());
        assert_eq!(report.jobs[1].outcome, JobOutcome::Succeeded);
        assert!(
            permitted
                .started
                .iter()
                .any(|job| job == "build__matrix_001")
        );
    }
    let mut worker = Executor::new(StepOutcome::Succeeded);
    worker.refuse_begin = true;
    let report = run(&mut worker, SOURCE, WorkflowLimits::default());
    assert_eq!(report.jobs[0].outcome, JobOutcome::Refused);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Skipped);
    assert_eq!(report.jobs[2].outcome, JobOutcome::Succeeded);
    assert_eq!(worker.closed, [false]);
}

#[test]
fn caller_cancellation_and_unresolved_containment_cannot_become_matrix_local_skips() {
    for (outcome, retained, bad_close) in [
        (StepOutcome::Cancelled, false, false),
        (StepOutcome::ContainmentFailure, false, false),
        (StepOutcome::TimedOut, true, false),
        (StepOutcome::Succeeded, false, true),
    ] {
        let mut worker = Executor::new(outcome);
        worker.retained = retained;
        worker.refuse_close = bad_close;
        let report = run(&mut worker, SOURCE, WorkflowLimits::default());
        assert_eq!(worker.started, ["build__matrix_000"]);
        assert!(
            report.jobs[1..]
                .iter()
                .all(|job| job.outcome == JobOutcome::Cancelled)
        );
        assert!(!report.succeeded());
        assert_eq!(worker.observations, report.jobs);
    }
}

#[test]
fn fail_fast_never_resets_the_shared_output_allowance() {
    let mut worker = Executor::new(StepOutcome::Succeeded);
    worker.oversized = true;
    let report = run(
        &mut worker,
        SOURCE,
        WorkflowLimits {
            stream_bytes: 4,
            total_output_bytes: 4,
            ..WorkflowLimits::default()
        },
    );
    assert_eq!(report.jobs[0].outcome, JobOutcome::OutputLimit);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Skipped);
    assert_eq!(report.jobs[2].outcome, JobOutcome::OutputLimit);
    assert_eq!(report.jobs[0].steps[0].observation.stdout.len(), 2);
    assert_eq!(report.jobs[2].steps[0].observation.stdout.len(), 1);
    assert!(!report.succeeded());
}
