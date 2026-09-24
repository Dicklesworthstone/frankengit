#![forbid(unsafe_code)]
use fgit_runner::workflow::{
    JobOutcome, StepLimits, StepObservation, StepOutcome, WorkerFailure, WorkflowExecutor,
    WorkflowLimits, WorkflowPlan,
};
use fgit_schema::workflow::Job;
use std::cell::Cell;

const DAG: &str = "name: dependencies\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf first\n      - run: printf second\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: printf dependent\n  c:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf independent\n";
#[derive(Default)]
struct Fake {
    calls: Vec<String>,
    fail: bool,
    truncated: bool,
    retain: bool,
    cleanup_failure: bool,
    wrong_exit: bool,
}
impl WorkflowExecutor for Fake {
    fn begin_job(
        &mut self,
        _: usize,
        job: &Job,
        _: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        self.calls.push(format!("begin:{}", job.id));
        Ok(())
    }
    fn execute_step(
        &mut self,
        index: usize,
        script: &str,
        _: StepLimits,
        _: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.calls.push(format!("step:{index}:{script}"));
        Ok(StepObservation {
            outcome: if self.fail && script == "printf first" {
                StepOutcome::Failed
            } else {
                StepOutcome::Succeeded
            },
            exit_code: Some(i32::from(
                self.wrong_exit || (self.fail && script == "printf first"),
            )),
            stdout: b"output".to_vec(),
            stderr: Vec::new(),
            elapsed_millis: 1,
            output_complete: !self.truncated,
            retain_workspace: self.retain,
        })
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        self.calls.push(format!("finish:{retain}"));
        if self.cleanup_failure {
            Err(WorkerFailure::new("cleanup did not settle", true))
        } else {
            Ok(())
        }
    }
}
#[test]
fn ordered_steps_dependency_skip_and_independent_continuation() {
    let plan = WorkflowPlan::compile(DAG).unwrap();
    let mut worker = Fake {
        fail: true,
        ..Fake::default()
    };
    let report = plan
        .execute(WorkflowLimits::default(), &mut worker, &|| true)
        .unwrap();
    assert_eq!(
        report
            .jobs
            .iter()
            .map(|job| job.outcome)
            .collect::<Vec<_>>(),
        [
            JobOutcome::Failed,
            JobOutcome::Skipped,
            JobOutcome::Succeeded
        ]
    );
    assert_eq!(
        worker.calls,
        [
            "begin:a",
            "step:0:printf first",
            "finish:false",
            "begin:c",
            "step:0:printf independent",
            "finish:false"
        ]
    );
    assert!(!report.succeeded());
    let mut worker = Fake::default();
    let report = plan
        .execute(WorkflowLimits::default(), &mut worker, &|| true)
        .unwrap();
    assert!(report.succeeded());
    assert_eq!(worker.calls[2], "step:1:printf second");
    assert_eq!(
        report.jobs.iter().map(|job| job.steps.len()).sum::<usize>(),
        4
    );
    assert!(report.to_json().contains("\"authoritative_check\":false"));
}
#[test]
fn unknown_labels_and_expressions_refuse_before_any_work() {
    assert!(WorkflowPlan::compile(&DAG.replace("fgit-trusted-local", "ubuntu-latest")).is_err());
    assert!(
        WorkflowPlan::compile(&DAG.replace("printf independent", "printf ${{ secrets.TOKEN }}"))
            .is_err()
    );
    assert!(WorkflowPlan::compile(&DAG.replace("printf independent", "\0")).is_err());
}
#[test]
fn cancellation_never_starts_a_workspace() {
    let plan = WorkflowPlan::compile(DAG).unwrap();
    let mut worker = Fake::default();
    let report = plan
        .execute(WorkflowLimits::default(), &mut worker, &|| false)
        .unwrap();
    assert!(worker.calls.is_empty());
    assert!(
        report
            .jobs
            .iter()
            .all(|job| job.outcome == JobOutcome::Cancelled)
    );
}
#[test]
fn cancellation_between_steps_still_closes_the_started_job() {
    struct CancelAfterStep<'a>(&'a Cell<bool>, Fake);
    impl WorkflowExecutor for CancelAfterStep<'_> {
        fn begin_job(
            &mut self,
            i: usize,
            j: &Job,
            live: &dyn Fn() -> bool,
        ) -> Result<(), WorkerFailure> {
            self.1.begin_job(i, j, live)
        }
        fn execute_step(
            &mut self,
            i: usize,
            s: &str,
            l: StepLimits,
            live: &dyn Fn() -> bool,
        ) -> Result<StepObservation, WorkerFailure> {
            let result = self.1.execute_step(i, s, l, live);
            self.0.set(false);
            result
        }
        fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
            self.1.finish_job(retain)
        }
    }
    let live = Cell::new(true);
    let mut worker = CancelAfterStep(&live, Fake::default());
    let report = WorkflowPlan::compile(DAG)
        .unwrap()
        .execute(WorkflowLimits::default(), &mut worker, &|| live.get())
        .unwrap();
    assert_eq!(report.jobs[0].steps.len(), 1);
    assert_eq!(report.jobs[0].outcome, JobOutcome::Cancelled);
    assert_eq!(worker.1.calls.last().unwrap(), "finish:false");
}
#[test]
fn incomplete_output_and_failed_cleanup_can_never_be_green() {
    for (truncated, retain, cleanup_failure) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let mut worker = Fake {
            truncated,
            retain,
            cleanup_failure,
            ..Fake::default()
        };
        let report = WorkflowPlan::compile(DAG)
            .unwrap()
            .execute(WorkflowLimits::default(), &mut worker, &|| true)
            .unwrap();
        assert!(!report.succeeded());
        if retain || cleanup_failure {
            assert_eq!(report.jobs[1].outcome, JobOutcome::Cancelled);
            assert_eq!(report.jobs[2].outcome, JobOutcome::Cancelled);
        }
    }
}
#[test]
fn output_budget_is_aggregate_and_clamps_a_misreporting_worker() {
    let mut worker = Fake::default();
    let limits = WorkflowLimits {
        total_output_bytes: 8,
        stream_bytes: 4,
        ..WorkflowLimits::default()
    };
    let report = WorkflowPlan::compile(DAG)
        .unwrap()
        .execute(limits, &mut worker, &|| true)
        .unwrap();
    assert!(!report.succeeded());
    assert!(
        report
            .jobs
            .iter()
            .flat_map(|job| &job.steps)
            .map(|s| s.observation.stdout.len() + s.observation.stderr.len())
            .sum::<usize>()
            <= 8
    );
    assert!(
        report
            .jobs
            .iter()
            .flat_map(|job| &job.steps)
            .all(|s| !s.observation.output_complete)
    );
}

#[cfg(target_os = "linux")]
mod process {
    use super::*;
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    static ID: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fg-workflow-process-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn file(&self, name: &str) -> File {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.0.join(name))
                .unwrap()
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    const fn limits() -> StepLimits {
        StepLimits {
            timeout: Duration::from_secs(2),
            stream_bytes: 4096,
        }
    }
    #[test]
    fn real_shell_preserves_multiline_quotes_unicode_and_nonzero_exits() {
        let temp = Temp::new();
        let output = temp.file("out");
        let errors = temp.file("err");
        let result = fgit_runner::workflow::run_trusted_step(
            &temp.0,
            "printf '%s\\n' 'hello world' 'λ'\nprintf '%s' 'diagnostic' >&2\nexit 7",
            limits(),
            &output,
            &errors,
            &|| true,
        )
        .unwrap();
        assert_eq!(result.outcome, StepOutcome::Failed);
        assert_eq!(result.exit_code, Some(7));
        assert_eq!(result.stdout, "hello world\nλ\n".as_bytes());
        assert_eq!(result.stderr, b"diagnostic");
        assert!(result.output_complete);
        assert!(!result.retain_workspace);
    }
    #[test]
    fn real_output_overflow_is_not_success_and_capture_is_bounded() {
        let temp = Temp::new();
        let output = temp.file("out");
        let errors = temp.file("err");
        let result = fgit_runner::workflow::run_trusted_step(
            &temp.0,
            "printf '%10000s' x",
            limits(),
            &output,
            &errors,
            &|| true,
        )
        .unwrap();
        assert_eq!(result.outcome, StepOutcome::OutputLimit);
        assert_eq!(result.stdout.len(), 4096);
        assert!(!result.output_complete);
    }
    #[test]
    fn timeout_reaps_direct_child_without_claiming_descendant_quiescence() {
        let temp = Temp::new();
        let output = temp.file("out");
        let errors = temp.file("err");
        let start = Instant::now();
        let result = fgit_runner::workflow::run_trusted_step(
            &temp.0,
            "exec /bin/sleep 5",
            StepLimits {
                timeout: Duration::from_millis(30),
                ..limits()
            },
            &output,
            &errors,
            &|| true,
        )
        .unwrap();
        assert_eq!(result.outcome, StepOutcome::TimedOut);
        assert!(result.retain_workspace);
        assert!(start.elapsed() < Duration::from_secs(4));
    }
    #[test]
    fn cancellation_at_spawn_boundary_executes_nothing() {
        let temp = Temp::new();
        let output = temp.file("out");
        let errors = temp.file("err");
        let result = fgit_runner::workflow::run_trusted_step(
            &temp.0,
            "printf unsafe",
            limits(),
            &output,
            &errors,
            &|| false,
        )
        .unwrap();
        assert_eq!(result.outcome, StepOutcome::Cancelled);
        assert!(result.stdout.is_empty());
        assert_eq!(output.metadata().unwrap().len(), 0);
    }
}

#[test]
fn a_fabricated_success_exit_is_not_accepted_and_stops_further_jobs() {
    let plan = WorkflowPlan::compile(DAG).unwrap();
    let mut worker = Fake {
        wrong_exit: true,
        ..Fake::default()
    };
    let report = plan
        .execute(WorkflowLimits::default(), &mut worker, &|| true)
        .unwrap();
    assert!(!report.succeeded());
    assert_eq!(
        report.jobs[0].steps[0].observation.outcome,
        StepOutcome::ContainmentFailure
    );
    assert!(report.jobs[0].steps[0].observation.retain_workspace);
    assert_eq!(worker.calls.last().unwrap(), "finish:true");
    assert_eq!(report.jobs[2].outcome, JobOutcome::Cancelled);
}
