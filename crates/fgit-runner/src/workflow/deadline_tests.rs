//! Exact clock-boundary tests exercise the real workflow interpreter. The
//! executor is a phase-controlled fixture, not an OS containment claim.
use super::*;
use std::collections::VecDeque;

const SOURCE: &str = "name: deadlines\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    timeout-minutes: 1\n    steps:\n      - run: first\n      - run: second\n      - run: third\n  dependent:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: dependent\n  independent:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: independent\n";

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum Fault {
    #[default]
    None,
    Begin,
    Step,
    Capture,
    Finish,
    CancelThenRebound,
    IndependentCancellation,
    BadSuccess,
    LostContainment,
}

struct ClockExecutor<'a> {
    clock: &'a Cell<Duration>,
    caller: &'a Cell<bool>,
    job: String,
    begin_time: Duration,
    step_times: VecDeque<Duration>,
    capture_time: Option<Duration>,
    finish_time: Duration,
    fault: Fault,
    events: Vec<String>,
    budgets: Vec<Duration>,
}

impl<'a> ClockExecutor<'a> {
    fn new(clock: &'a Cell<Duration>, caller: &'a Cell<bool>) -> Self {
        Self {
            clock,
            caller,
            job: String::new(),
            begin_time: Duration::ZERO,
            step_times: VecDeque::new(),
            capture_time: None,
            finish_time: Duration::ZERO,
            fault: Fault::None,
            events: Vec::new(),
            budgets: Vec::new(),
        }
    }
    fn advance(&self, duration: Duration) {
        self.clock.set(self.clock.get() + duration);
    }
    fn building(&self) -> bool {
        self.job == "build"
    }
}

impl WorkflowExecutor for ClockExecutor<'_> {
    fn begin_job(
        &mut self,
        _: usize,
        job: &Job,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        self.job.clone_from(&job.id);
        self.events.push(format!("begin:{}", job.id));
        if self.building() {
            self.advance(self.begin_time);
            if self.fault == Fault::Begin {
                let _observed = live();
                return Err(WorkerFailure::new("workspace startup stopped", false));
            }
        }
        Ok(())
    }

    fn execute_step(
        &mut self,
        _: usize,
        script: &str,
        limits: StepLimits,
        live: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.events.push(format!("step:{script}"));
        self.budgets.push(limits.timeout);
        if self.building() {
            let spent = self.step_times.pop_front().unwrap_or(Duration::ZERO);
            self.advance(spent);
            if self.fault == Fault::Step {
                let _observed = live();
                return Err(WorkerFailure::new("step setup stopped", false));
            }
            if self.fault == Fault::CancelThenRebound {
                self.caller.set(false);
                assert!(!live());
                self.caller.set(true);
            }
        }
        let fault = if self.building() {
            self.fault
        } else {
            Fault::None
        };
        let outcome = match fault {
            Fault::CancelThenRebound | Fault::IndependentCancellation => StepOutcome::Cancelled,
            Fault::BadSuccess => StepOutcome::Succeeded,
            Fault::LostContainment => StepOutcome::ContainmentFailure,
            _ if !live() => StepOutcome::Cancelled,
            _ => StepOutcome::Succeeded,
        };
        Ok(StepObservation {
            outcome,
            exit_code: Some(i32::from(fault == Fault::BadSuccess)),
            stdout: Vec::new(),
            stderr: Vec::new(),
            elapsed_millis: 0,
            output_complete: true,
            retain_workspace: false,
        })
    }

    fn has_job_outputs(&self, _: &Job) -> bool {
        self.building() && self.capture_time.is_some()
    }

    fn capture_job_outputs(
        &mut self,
        _: &Job,
        live: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        self.events.push("capture:build".into());
        self.advance(self.capture_time.unwrap());
        let _observed = live();
        if self.fault == Fault::Capture {
            Err(WorkerFailure::new("capture stopped", false))
        } else {
            Ok(())
        }
    }

    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        self.events.push(format!("finish:{}:{retain}", self.job));
        if self.building() {
            self.advance(self.finish_time);
            if self.fault == Fault::Finish {
                return Err(WorkerFailure::new("cleanup unresolved", true));
            }
        }
        Ok(())
    }
}

fn execute(source: &str, worker: &mut ClockExecutor<'_>, limits: WorkflowLimits) -> WorkflowReport {
    let clock = worker.clock;
    let caller = worker.caller;
    WorkflowPlan::compile(source)
        .unwrap()
        .execute_with_elapsed(limits, worker, &|| caller.get(), &|| clock.get())
        .unwrap()
}

fn limits() -> WorkflowLimits {
    WorkflowLimits {
        step_timeout: Duration::from_secs(300),
        ..WorkflowLimits::default()
    }
}

#[test]
fn job_budget_charges_startup_and_all_steps_and_timeout_does_not_cancel_independent_jobs() {
    for last in [14, 15] {
        let (clock, caller) = (Cell::new(Duration::ZERO), Cell::new(true));
        let mut worker = ClockExecutor::new(&clock, &caller);
        worker.begin_time = Duration::from_secs(20);
        worker.step_times = VecDeque::from([Duration::from_secs(25), Duration::from_secs(last)]);
        let report = execute(SOURCE, &mut worker, limits());
        assert_eq!(
            &worker.budgets[..2],
            &[Duration::from_secs(40), Duration::from_secs(15)]
        );
        if last == 14 {
            assert!(report.succeeded());
            assert!(worker.events.iter().any(|event| event == "step:third"));
            assert_eq!(worker.budgets[2], Duration::from_secs(1));
        } else {
            assert_eq!(report.jobs[0].outcome, JobOutcome::TimedOut);
            assert_eq!(
                report.jobs[0].steps[1].observation.outcome,
                StepOutcome::TimedOut
            );
            assert_eq!(report.jobs[1].outcome, JobOutcome::Skipped);
            assert_eq!(report.jobs[2].outcome, JobOutcome::Succeeded);
            assert!(!worker.events.iter().any(|event| event == "step:third"));
            assert!(!report.succeeded());
        }
        assert!(
            worker
                .events
                .iter()
                .any(|event| event == "finish:build:false")
        );
    }
}

#[test]
fn each_step_gets_a_fresh_cap_within_one_nonrenewable_job_budget() {
    let source = SOURCE
        .replace("timeout-minutes: 1", "timeout-minutes: 3")
        .replace(
            "      - run: first\n",
            "      - run: first\n        timeout-minutes: 1\n",
        )
        .replace(
            "      - run: second\n",
            "      - run: second\n        timeout-minutes: 1\n",
        )
        .replace(
            "      - run: third\n",
            "      - run: third\n        timeout-minutes: 1\n",
        );
    for source in [
        source.clone(),
        source.replace("    timeout-minutes: 3\n", ""),
    ] {
        for duration in [50, 60] {
            let (clock, caller) = (Cell::new(Duration::ZERO), Cell::new(true));
            let mut worker = ClockExecutor::new(&clock, &caller);
            worker.step_times = VecDeque::from([Duration::from_secs(duration); 3]);
            let report = execute(&source, &mut worker, limits());
            assert_eq!(worker.budgets[0], Duration::from_secs(60));
            if duration == 50 {
                assert!(report.succeeded());
                assert_eq!(&worker.budgets[..3], &[Duration::from_secs(60); 3]);
            } else {
                assert_eq!(report.jobs[0].outcome, JobOutcome::TimedOut);
                assert_eq!(report.jobs[0].steps.len(), 1);
                assert_eq!(report.jobs[2].outcome, JobOutcome::Succeeded);
            }
        }
    }
}

#[test]
fn startup_capture_and_cleanup_cannot_publish_success_after_the_job_deadline() {
    for phase in ["begin", "capture", "finish"] {
        for seconds in [59, 60] {
            let (clock, caller) = (Cell::new(Duration::ZERO), Cell::new(true));
            let mut worker = ClockExecutor::new(&clock, &caller);
            let duration = Duration::from_secs(seconds);
            match phase {
                "begin" => worker.begin_time = duration,
                "capture" => worker.capture_time = Some(duration),
                "finish" => worker.finish_time = duration,
                _ => unreachable!(),
            }
            let report = execute(SOURCE, &mut worker, limits());
            assert_eq!(
                report.jobs[0].outcome,
                if seconds == 59 {
                    JobOutcome::Succeeded
                } else {
                    JobOutcome::TimedOut
                },
                "{phase}:{seconds}"
            );
            assert_eq!(
                worker
                    .events
                    .iter()
                    .filter(|event| *event == "finish:build:false")
                    .count(),
                1
            );
            assert_eq!(report.jobs[2].outcome, JobOutcome::Succeeded);
            if phase == "begin" && seconds == 60 {
                assert!(report.jobs[0].steps.is_empty());
            }
        }
    }
}

#[test]
fn setup_and_capture_errors_after_cap_exhaustion_are_timeouts_but_real_errors_stay_refusals() {
    for fault in [Fault::Begin, Fault::Step, Fault::Capture] {
        for seconds in [59, 60] {
            let (clock, caller) = (Cell::new(Duration::ZERO), Cell::new(true));
            let mut worker = ClockExecutor::new(&clock, &caller);
            worker.fault = fault;
            let duration = Duration::from_secs(seconds);
            match fault {
                Fault::Begin => worker.begin_time = duration,
                Fault::Step => worker.step_times = VecDeque::from([duration]),
                Fault::Capture => worker.capture_time = Some(duration),
                _ => unreachable!(),
            }
            let report = execute(SOURCE, &mut worker, limits());
            assert_eq!(
                report.jobs[0].outcome,
                if seconds == 59 {
                    JobOutcome::Refused
                } else {
                    JobOutcome::TimedOut
                }
            );
            assert!(report.jobs[0].failure.is_some());
            assert_eq!(report.jobs[2].outcome, JobOutcome::Succeeded);
            assert_eq!(
                worker
                    .events
                    .iter()
                    .filter(|event| *event == "finish:build:false")
                    .count(),
                usize::from(fault != Fault::Begin)
            );
        }
    }
}

#[test]
fn operator_run_and_step_ceilings_are_never_widened_by_yaml() {
    let source = SOURCE
        .replace("timeout-minutes: 1", "timeout-minutes: 60")
        .replace(
            "      - run: first\n",
            "      - run: first\n        timeout-minutes: 60\n",
        );
    for begin in [0, 8] {
        let (clock, caller) = (Cell::new(Duration::ZERO), Cell::new(true));
        let mut worker = ClockExecutor::new(&clock, &caller);
        worker.begin_time = Duration::from_secs(begin);
        let report = execute(
            &source,
            &mut worker,
            WorkflowLimits {
                step_timeout: Duration::from_secs(5),
                run_timeout: Duration::from_secs(10),
                ..WorkflowLimits::default()
            },
        );
        assert_eq!(
            worker.budgets[0],
            Duration::from_secs(if begin == 0 { 5 } else { 2 })
        );
        assert!(report.succeeded());
    }
    let (clock, caller) = (Cell::new(Duration::ZERO), Cell::new(true));
    let mut worker = ClockExecutor::new(&clock, &caller);
    worker.begin_time = Duration::from_secs(8);
    worker.step_times = VecDeque::from([Duration::from_secs(2)]);
    let report = execute(
        &source,
        &mut worker,
        WorkflowLimits {
            step_timeout: Duration::from_secs(5),
            run_timeout: Duration::from_secs(10),
            ..WorkflowLimits::default()
        },
    );
    assert!(
        report
            .jobs
            .iter()
            .all(|job| job.outcome == JobOutcome::TimedOut)
    );
}

#[test]
fn cancellation_and_containment_keep_precedence_over_an_exhausted_cap() {
    for fault in [
        Fault::CancelThenRebound,
        Fault::IndependentCancellation,
        Fault::BadSuccess,
        Fault::LostContainment,
        Fault::Finish,
    ] {
        let (clock, caller) = (Cell::new(Duration::ZERO), Cell::new(true));
        let mut worker = ClockExecutor::new(&clock, &caller);
        worker.fault = fault;
        worker.step_times = VecDeque::from([Duration::from_secs(60)]);
        let report = execute(SOURCE, &mut worker, limits());
        assert!(!report.succeeded());
        assert_eq!(report.jobs[2].outcome, JobOutcome::Cancelled);
        assert!(
            !worker
                .events
                .iter()
                .any(|event| event == "begin:independent")
        );
        match fault {
            Fault::CancelThenRebound | Fault::IndependentCancellation => {
                assert_eq!(report.jobs[0].outcome, JobOutcome::Cancelled)
            }
            Fault::Finish => assert_eq!(report.jobs[0].outcome, JobOutcome::Refused),
            _ => {
                assert_eq!(
                    report.jobs[0].steps[0].observation.outcome,
                    StepOutcome::ContainmentFailure
                );
                assert!(report.jobs[0].requires_containment());
            }
        }
    }
}

#[test]
fn invalid_late_cap_is_rejected_before_a_plan_can_start_any_job() {
    let invalid = SOURCE.replace(
        "  independent:\n",
        "  independent:\n    timeout-minutes: 0\n",
    );
    assert!(matches!(
        WorkflowPlan::compile(&invalid),
        Err(WorkflowError::Schema(_))
    ));
    assert!(WorkflowPlan::compile(SOURCE).is_ok());
}
