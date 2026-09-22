//! Bounded executor observations, not evidence of an OS isolation boundary.
use super::*;
use std::cell::Cell;
use std::collections::VecDeque;

const WORKFLOW: &str = "name: settlement\non: push\njobs:\n  first:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo first\n  independent:\n    runs-on: fgit-trusted-local\n    if: always()\n    steps:\n      - run: echo independent\n";

fn observation(outcome: StepOutcome) -> StepObservation {
    StepObservation {
        outcome,
        exit_code: Some(if outcome == StepOutcome::Succeeded {
            0
        } else {
            1
        }),
        stdout: b"output".to_vec(),
        stderr: Vec::new(),
        elapsed_millis: 1,
        output_complete: true,
        retain_workspace: false,
    }
}

struct Executor<'a> {
    pending: VecDeque<StepObservation>,
    events: Vec<String>,
    observations: Vec<JobReport>,
    cancel_on_finish: Option<&'a Cell<bool>>,
    close_error: bool,
}
impl Executor<'_> {
    fn new(first: StepObservation) -> Self {
        Self {
            pending: VecDeque::from([first, observation(StepOutcome::Succeeded)]),
            events: Vec::new(),
            observations: Vec::new(),
            cancel_on_finish: None,
            close_error: false,
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
        Ok(())
    }
    fn execute_step(
        &mut self,
        _: usize,
        script: &str,
        _: StepLimits,
        _: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.events.push(format!("step:{script}"));
        Ok(self
            .pending
            .pop_front()
            .expect("one observation per started step"))
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        self.events.push(format!("close:{retain}"));
        if let Some(live) = self.cancel_on_finish {
            live.set(false);
        }
        if self.close_error {
            Err(WorkerFailure::new("close failed", false))
        } else {
            Ok(())
        }
    }
    fn observe_job(&mut self, report: &JobReport) {
        self.events.push(format!("observe:{}", report.id));
        self.observations.push(report.clone());
    }
}

fn run(executor: &mut Executor<'_>) -> WorkflowReport {
    WorkflowPlan::compile(WORKFLOW)
        .unwrap()
        .execute(WorkflowLimits::default(), executor, &|| true)
        .unwrap()
}

#[test]
fn explicit_containment_failure_stops_independent_always_job_without_retention_hint() {
    let mut executor = Executor::new(observation(StepOutcome::ContainmentFailure));
    let report = run(&mut executor);
    assert!(report.jobs[0].requires_containment());
    assert!(report.jobs[0].steps[0].observation.retain_workspace);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
    assert!(!executor.events.iter().any(|e| e == "begin:independent"));
    assert!(executor.events.iter().any(|e| e == "close:true"));
}

#[test]
fn output_clamping_cannot_hide_containment_failure_or_bad_success_exit() {
    for outcome in [StepOutcome::ContainmentFailure, StepOutcome::Succeeded] {
        let mut observed = observation(outcome);
        observed.exit_code = Some(7);
        observed.stdout = vec![b'x'; 32];
        let mut executor = Executor::new(observed);
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
        let step = &report.jobs[0].steps[0].observation;
        assert_eq!(step.stdout.len(), 8);
        assert!(!step.output_complete);
        assert_eq!(step.outcome, StepOutcome::ContainmentFailure);
        assert!(report.jobs[0].requires_containment());
        assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
    }
}

#[test]
fn worker_cancellation_is_sticky_across_independent_jobs_even_with_oversized_output() {
    let mut observed = observation(StepOutcome::Cancelled);
    observed.stdout = vec![b'x'; 32];
    let mut executor = Executor::new(observed);
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
    assert_eq!(report.jobs[0].outcome, JobOutcome::Cancelled);
    assert_eq!(report.jobs[0].steps[0].observation.stdout.len(), 8);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
    assert!(!executor.events.iter().any(|e| e == "begin:independent"));
}

#[test]
fn cancellation_during_cleanup_is_observed_before_terminal_success_notification() {
    let live = Cell::new(true);
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    executor.cancel_on_finish = Some(&live);
    let report = WorkflowPlan::compile(WORKFLOW)
        .unwrap()
        .execute(WorkflowLimits::default(), &mut executor, &|| live.get())
        .unwrap();
    assert_eq!(report.jobs[0].outcome, JobOutcome::Cancelled);
    assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
    assert_eq!(executor.observations, report.jobs);
    assert_eq!(executor.events[2], "close:false");
    assert_eq!(executor.events[3], "observe:first");
    assert!(!report.succeeded());
}

#[test]
fn cleanup_failure_is_terminally_observed_and_prevents_further_work() {
    let mut executor = Executor::new(observation(StepOutcome::Succeeded));
    executor.close_error = true;
    let report = run(&mut executor);
    assert_eq!(report.jobs[0].outcome, JobOutcome::Refused);
    assert!(report.jobs[0].requires_containment());
    assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
    assert_eq!(executor.observations, report.jobs);
}

#[test]
fn ordinary_failure_permits_independent_work_and_observations_follow_close() {
    let mut executor = Executor::new(observation(StepOutcome::Failed));
    let report = run(&mut executor);
    assert_eq!(report.jobs[0].outcome, JobOutcome::Failed);
    assert!(!report.jobs[0].requires_containment());
    assert_eq!(report.jobs[1].outcome, JobOutcome::Succeeded);
    assert_eq!(
        executor.events,
        [
            "begin:first",
            "step:echo first",
            "close:false",
            "observe:first",
            "begin:independent",
            "step:echo independent",
            "close:false",
            "observe:independent",
        ]
    );
    assert_eq!(executor.observations, report.jobs);
}

#[test]
fn output_limit_remains_distinct_from_containment_on_clean_refusal_twin() {
    let mut observed = observation(StepOutcome::Succeeded);
    observed.stdout = vec![b'x'; 32];
    let mut executor = Executor::new(observed);
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
    assert_eq!(report.jobs[0].outcome, JobOutcome::OutputLimit);
    assert!(!report.jobs[0].requires_containment());
    assert_eq!(report.jobs[1].outcome, JobOutcome::Succeeded);
}
