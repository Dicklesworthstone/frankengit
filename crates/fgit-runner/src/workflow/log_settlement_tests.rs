//! Log-finalization ordering and budgets; no OS isolation claim.
use super::*;
use std::cell::Cell;
use std::collections::VecDeque;

const WORKFLOW: &str = "name: retained-logs\non: push\njobs:\n  first:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo first\n  independent:\n    runs-on: fgit-trusted-local\n    if: always()\n    steps:\n      - run: echo independent\n";

fn observation(outcome: StepOutcome) -> StepObservation {
    StepObservation {
        outcome,
        exit_code: Some(i32::from(outcome != StepOutcome::Succeeded)),
        stdout: b"out\0\xff".to_vec(),
        stderr: b"err\0\xfe".to_vec(),
        elapsed_millis: 1,
        output_complete: true,
        retain_workspace: false,
    }
}

struct Executor<'a> {
    pending: VecDeque<StepObservation>,
    events: Vec<String>,
    observed: Vec<JobReport>,
    captured: Vec<JobReport>,
    enabled: bool,
    begin_error: bool,
    log_error: Option<WorkerFailure>,
    cancel_on_finish: Option<&'a Cell<bool>>,
    cancel_on_log: Option<&'a Cell<bool>>,
    clock: Option<&'a Cell<Duration>>,
    log_costs: VecDeque<Duration>,
}
impl Executor<'_> {
    fn new(first: StepObservation) -> Self {
        Self {
            pending: VecDeque::from([
                first,
                observation(StepOutcome::Succeeded),
                observation(StepOutcome::Succeeded),
            ]),
            events: Vec::new(),
            observed: Vec::new(),
            captured: Vec::new(),
            enabled: true,
            begin_error: false,
            log_error: None,
            cancel_on_finish: None,
            cancel_on_log: None,
            clock: None,
            log_costs: VecDeque::new(),
        }
    }
}
impl WorkflowExecutor for Executor<'_> {
    fn begin_job(
        &mut self,
        _: usize,
        job: &Job,
        _: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        self.events.push(format!("begin:{}", job.id));
        if self.begin_error {
            Err(WorkerFailure::new("no workspace acquired", false))
        } else {
            Ok(())
        }
    }
    fn execute_step(
        &mut self,
        _: usize,
        script: &str,
        _: StepLimits,
        _: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.events.push(format!("step:{script}"));
        Ok(self.pending.pop_front().expect("one observation per step"))
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        self.events.push(format!("close:{retain}"));
        if let Some(live) = self.cancel_on_finish {
            live.set(false);
        }
        Ok(())
    }
    fn has_job_logs(&self) -> bool {
        self.enabled
    }
    fn capture_job_logs(
        &mut self,
        report: &JobReport,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        // The finalization predicate is separate from execution cancellation.
        assert!(live());
        assert!(self.events.last().unwrap().starts_with("close:"));
        self.events.push(format!("logs:{}", report.id));
        self.captured.push(report.clone());
        if let Some(cancel) = self.cancel_on_log {
            cancel.set(false);
        }
        if let Some(clock) = self.clock {
            clock.set(clock.get() + self.log_costs.pop_front().unwrap_or_default());
        }
        self.log_error.clone().map_or(Ok(()), Err)
    }
    fn observe_job(&mut self, report: &JobReport) {
        self.events.push(format!("observe:{}", report.id));
        self.observed.push(report.clone());
    }
}

fn run(executor: &mut Executor<'_>) -> WorkflowReport {
    WorkflowPlan::compile(WORKFLOW)
        .unwrap()
        .execute(WorkflowLimits::default(), executor, &|| true)
        .unwrap()
}

#[test]
fn logs_follow_close_and_precede_terminal_observation() {
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    let report = run(&mut executor);
    assert!(report.succeeded());
    assert_eq!(executor.captured, report.jobs);
    assert_eq!(executor.observed, report.jobs);
    assert_eq!(
        executor.events,
        [
            "begin:first",
            "step:echo first",
            "close:false",
            "logs:first",
            "observe:first",
            "begin:independent",
            "step:echo independent",
            "close:false",
            "logs:independent",
            "observe:independent",
        ]
    );
    assert_eq!(
        executor.captured[0].steps[0].observation.stdout,
        b"out\0\xff"
    );
    assert_eq!(
        executor.captured[0].steps[0].observation.stderr,
        b"err\0\xfe"
    );
}

#[test]
fn disabled_logs_preserve_terminal_reports_without_a_capture_hook() {
    let mut executor = Executor::new(observation(StepOutcome::Failed));
    executor.enabled = false;
    let report = run(&mut executor);
    assert!(executor.captured.is_empty());
    assert_eq!(report.jobs[0].outcome, JobOutcome::Failed);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Succeeded);
    assert_eq!(executor.observed, report.jobs);
    assert_eq!(&executor.events[2..4], ["close:false", "observe:first"]);
}

#[test]
fn capture_receives_normalized_bounded_output_and_completeness() {
    let mut first = observation(StepOutcome::Succeeded);
    first.stdout = vec![0xff; 32];
    let mut executor = Executor::new(first);
    let report = WorkflowPlan::compile(WORKFLOW)
        .unwrap()
        .execute(
            WorkflowLimits {
                stream_bytes: 8,
                ..WorkflowLimits::default()
            },
            &mut executor,
            &|| true,
        )
        .unwrap();
    let captured = &executor.captured[0];
    assert_eq!(captured, &report.jobs[0]);
    assert_eq!(captured.outcome, JobOutcome::OutputLimit);
    assert_eq!(captured.steps[0].observation.stdout, vec![0xff; 8]);
    assert!(!captured.steps[0].observation.output_complete);
}

#[test]
fn stopped_or_failed_observations_are_retained_without_changing_the_outcome() {
    for (step, job) in [
        (StepOutcome::Failed, JobOutcome::Failed),
        (StepOutcome::Cancelled, JobOutcome::Cancelled),
        (StepOutcome::TimedOut, JobOutcome::TimedOut),
        (StepOutcome::OutputLimit, JobOutcome::OutputLimit),
    ] {
        let mut executor = Executor::new(observation(step));
        let report = run(&mut executor);
        assert_eq!(executor.captured[0], report.jobs[0]);
        assert_eq!(report.jobs[0].outcome, job);
        assert!(!report.succeeded());
        if step == StepOutcome::Cancelled {
            assert_eq!(executor.captured.len(), 1);
            assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
        }
    }
}

#[test]
fn cancellation_during_close_still_drains_owned_logs() {
    let live = Cell::new(true);
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    executor.cancel_on_finish = Some(&live);
    let report = WorkflowPlan::compile(WORKFLOW)
        .unwrap()
        .execute(WorkflowLimits::default(), &mut executor, &|| live.get())
        .unwrap();
    assert_eq!(executor.captured.len(), 1);
    assert_eq!(executor.captured[0].outcome, JobOutcome::Cancelled);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
    assert_eq!(executor.observed, report.jobs);
}

#[test]
fn cancellation_during_log_drain_cannot_publish_success_or_start_another_job() {
    let live = Cell::new(true);
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    executor.cancel_on_log = Some(&live);
    let report = WorkflowPlan::compile(WORKFLOW)
        .unwrap()
        .execute(WorkflowLimits::default(), &mut executor, &|| live.get())
        .unwrap();
    // The immutable custody snapshot is not terminal success authority.
    assert_eq!(executor.captured[0].outcome, JobOutcome::Succeeded);
    assert_eq!(report.jobs[0].outcome, JobOutcome::Cancelled);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
    assert_eq!(executor.captured.len(), 1);
    assert_eq!(executor.observed, report.jobs);
}

#[test]
fn required_log_failure_refuses_success_and_skips_success_dependents() {
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    executor.log_error = Some(WorkerFailure::new("store unavailable", false));
    let workflow = WORKFLOW.replace("    if: always()\n", "    needs: first\n");
    let report = WorkflowPlan::compile(&workflow)
        .unwrap()
        .execute(WorkflowLimits::default(), &mut executor, &|| true)
        .unwrap();
    assert_eq!(report.jobs[0].outcome, JobOutcome::Refused);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Skipped);
    assert_eq!(executor.captured.len(), 1);
    assert!(
        report.jobs[0]
            .failure
            .as_ref()
            .unwrap()
            .detail
            .contains("store unavailable")
    );
    assert!(!report.jobs[0].requires_containment());
    assert_eq!(executor.observed, report.jobs);
}

#[test]
fn log_failure_preserves_primary_stop_or_failure_and_records_the_custody_error() {
    for (step, job) in [
        (StepOutcome::Failed, JobOutcome::Failed),
        (StepOutcome::Cancelled, JobOutcome::Cancelled),
        (StepOutcome::TimedOut, JobOutcome::TimedOut),
        (StepOutcome::OutputLimit, JobOutcome::OutputLimit),
    ] {
        let mut executor = Executor::new(observation(step));
        executor.log_error = Some(WorkerFailure::new("store unavailable", false));
        let report = run(&mut executor);
        assert_eq!(report.jobs[0].outcome, job);
        assert!(
            report.jobs[0]
                .failure
                .as_ref()
                .unwrap()
                .detail
                .contains("logs:")
        );
        assert!(!report.succeeded());
    }
}

#[test]
fn unresolved_log_stage_cleanup_holds_the_run_and_prevents_independent_work() {
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    executor.log_error = Some(WorkerFailure::new("stage cleanup unresolved", true));
    let report = run(&mut executor);
    assert_eq!(report.jobs[0].outcome, JobOutcome::Refused);
    assert!(report.jobs[0].requires_containment());
    assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
    assert_eq!(executor.captured.len(), 1);
    assert_eq!(executor.observed, report.jobs);
}

#[test]
fn existing_containment_still_allows_owned_log_drain_and_blocks_further_execution() {
    let mut executor = Executor::new(observation(StepOutcome::ContainmentFailure));
    let report = run(&mut executor);
    assert_eq!(executor.captured.len(), 1);
    assert!(executor.captured[0].requires_containment());
    assert!(report.jobs[0].requires_containment());
    assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
    assert_eq!(
        &executor.events[2..5],
        ["close:true", "logs:first", "observe:first"]
    );
}

#[test]
fn no_logs_are_invented_for_jobs_that_never_acquire_a_workspace_or_run_steps() {
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    executor.begin_error = true;
    let report = run(&mut executor);
    assert!(executor.captured.is_empty());
    assert!(report.jobs.iter().all(|job| job.steps.is_empty()));
    assert!(
        !executor
            .events
            .iter()
            .any(|event| event.starts_with("close:"))
    );
}

#[test]
fn all_jobs_share_one_finalization_allowance_and_late_success_is_refused() {
    let clock = Cell::new(Duration::ZERO);
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    executor.clock = Some(&clock);
    executor.log_costs = VecDeque::from([Duration::from_secs(20), Duration::from_secs(12)]);
    let workflow = format!(
        "{WORKFLOW}  third:\n    runs-on: fgit-trusted-local\n    if: always()\n    steps:\n      - run: echo third\n"
    );
    let report = WorkflowPlan::compile(&workflow)
        .unwrap()
        .execute_with_elapsed(WorkflowLimits::default(), &mut executor, &|| true, &|| {
            clock.get()
        })
        .unwrap();
    assert_eq!(report.jobs.len(), 3);
    assert_eq!(report.jobs[0].outcome, JobOutcome::Succeeded);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Refused);
    assert_eq!(report.jobs[2].outcome, JobOutcome::Refused);
    // The third job cannot replenish the exhausted drain allowance.
    assert_eq!(executor.captured.len(), 2);
    for job in &report.jobs[1..] {
        assert!(
            job.failure
                .as_ref()
                .unwrap()
                .detail
                .contains("finalization deadline exhausted")
        );
    }
    assert_eq!(executor.observed, report.jobs);
}

#[test]
fn execution_deadline_expiring_during_log_drain_cannot_turn_green() {
    let clock = Cell::new(Duration::ZERO);
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    executor.clock = Some(&clock);
    executor.log_costs = VecDeque::from([Duration::from_secs(3)]);
    let report = WorkflowPlan::compile(WORKFLOW)
        .unwrap()
        .execute_with_elapsed(
            WorkflowLimits {
                step_timeout: Duration::from_secs(1),
                run_timeout: Duration::from_secs(2),
                ..WorkflowLimits::default()
            },
            &mut executor,
            &|| true,
            &|| clock.get(),
        )
        .unwrap();
    assert_eq!(executor.captured.len(), 1);
    assert!(
        report
            .jobs
            .iter()
            .all(|job| job.outcome == JobOutcome::TimedOut)
    );
    assert_eq!(executor.observed, report.jobs);
}

#[test]
fn advertised_logs_without_an_implementation_fail_closed() {
    struct Missing;
    impl WorkflowExecutor for Missing {
        fn begin_job(
            &mut self,
            _: usize,
            _: &Job,
            _: &dyn Fn() -> bool,
        ) -> Result<(), WorkerFailure> {
            Ok(())
        }
        fn execute_step(
            &mut self,
            _: usize,
            _: &str,
            _: StepLimits,
            _: &dyn Fn() -> bool,
        ) -> Result<StepObservation, WorkerFailure> {
            Ok(observation(StepOutcome::Succeeded))
        }
        fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> {
            Ok(())
        }
        fn has_job_logs(&self) -> bool {
            true
        }
    }
    let report = WorkflowPlan::compile(WORKFLOW)
        .unwrap()
        .execute(WorkflowLimits::default(), &mut Missing, &|| true)
        .unwrap();
    assert!(
        report
            .jobs
            .iter()
            .all(|job| job.outcome == JobOutcome::Refused)
    );
    assert!(
        report.jobs[0]
            .failure
            .as_ref()
            .unwrap()
            .detail
            .contains("does not implement log custody")
    );
}
