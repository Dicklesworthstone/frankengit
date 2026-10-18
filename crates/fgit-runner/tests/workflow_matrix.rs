#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
use fgit_runner::workflow::{
    JobOutcome, StepContext, StepLimits, StepObservation, WorkerFailure, WorkflowExecutor,
    WorkflowJob, WorkflowLimits, WorkflowPlan, run_trusted_step_with_context,
};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Worker {
    root: PathBuf,
    current: Option<PathBuf>,
    started: Vec<String>,
    finished: usize,
    stop_after_first: Option<Arc<AtomicBool>>,
}
impl Worker {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-matrix-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self {
            root,
            current: None,
            started: Vec::new(),
            finished: 0,
            stop_after_first: None,
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
impl WorkflowExecutor for Worker {
    fn begin_job(
        &mut self,
        index: usize,
        job: &WorkflowJob,
        _: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        assert!(self.current.is_none());
        assert_eq!(self.started.len(), self.finished);
        let directory = self.root.join(format!("job-{index}"));
        fs::create_dir(&directory).unwrap();
        self.current = Some(directory);
        self.started.push(job.id.clone());
        Ok(())
    }
    fn execute_step(
        &mut self,
        i: usize,
        script: &str,
        limits: StepLimits,
        live: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.execute_step_with_context(i, script, &StepContext::default(), limits, live)
    }
    fn supports_step_context(&self) -> bool {
        true
    }
    fn execute_step_with_context(
        &mut self,
        index: usize,
        script: &str,
        context: &StepContext,
        limits: StepLimits,
        live: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        let directory = self.current.as_ref().unwrap();
        let capture = |kind| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(format!("step-{index}-{kind}")))
                .unwrap()
        };
        run_trusted_step_with_context(
            directory,
            script,
            context,
            limits,
            &capture("out"),
            &capture("err"),
            live,
        )
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        let directory = self.current.take().unwrap();
        assert!(!directory.join("injected").exists());
        // Retain forced-stop diagnostics through the terminal observation.
        // These fixtures use only shell builtins, so Drop can remove them
        // after the native adapter has reaped that single direct process.
        if !retain {
            fs::remove_dir_all(directory).unwrap();
        }
        self.finished += 1;
        Ok(())
    }
    fn observe_job(&mut self, _: &fgit_runner::workflow::JobReport) {
        if self.finished == 1
            && let Some(live) = &self.stop_after_first
        {
            live.store(false, Ordering::SeqCst);
        }
    }
}
const SOURCE: &str = r#"name: actual matrix process
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    strategy:
      fail-fast: false
      matrix:
        mode:
          - first
          - bad
          - last
    steps:
      - run: test ! -e state; printf '%s' "$MODE" > state; printf '%s' "$MODE"; test "$MODE" != bad
        env:
          MODE: '${{ matrix.mode }}'
      - run: test -f state; test -z "${MODE+x}"
  package:
    runs-on: fgit-trusted-local
    needs: build
    steps:
      - run: echo packaged
  diagnose:
    runs-on: fgit-trusted-local
    needs: build
    if: failure()
    steps:
      - run: echo diagnosed
"#;

#[test]
fn real_matrix_processes_isolate_workspaces_and_join_before_failure_conditions() {
    let plan = WorkflowPlan::compile(SOURCE).unwrap();
    let mut worker = Worker::new();
    let report = plan
        .execute(WorkflowLimits::default(), &mut worker, &|| true)
        .unwrap();
    assert_eq!(
        report
            .jobs
            .iter()
            .map(|j| (j.id.as_str(), j.outcome))
            .collect::<Vec<_>>(),
        [
            ("build__matrix_000", JobOutcome::Succeeded),
            ("build__matrix_001", JobOutcome::Failed),
            ("build__matrix_002", JobOutcome::Succeeded),
            ("diagnose", JobOutcome::Succeeded),
            ("package", JobOutcome::Skipped)
        ]
    );
    assert_eq!(
        report.jobs[..3]
            .iter()
            .map(|j| j.steps[0].observation.stdout.as_slice())
            .collect::<Vec<_>>(),
        [b"first".as_slice(), b"bad".as_slice(), b"last".as_slice()]
    );
    assert_eq!(worker.finished, 4);
    assert_eq!(worker.started.last().unwrap(), "diagnose");
    assert!(!report.succeeded());
}

#[test]
fn successful_variants_release_one_dependent_and_literals_are_not_shell_programs() {
    let source = SOURCE
        .replace("- bad", "- literal")
        .replace("- first", "- '$(touch injected)' ");
    let plan = WorkflowPlan::compile(&source).unwrap();
    let mut worker = Worker::new();
    let report = plan
        .execute(WorkflowLimits::default(), &mut worker, &|| true)
        .unwrap();
    assert_eq!(
        report.jobs[0].steps[0].observation.stdout,
        b"$(touch injected)"
    );
    assert_eq!(
        report
            .jobs
            .iter()
            .find(|j| j.id == "package")
            .unwrap()
            .outcome,
        JobOutcome::Succeeded
    );
    assert_eq!(
        report
            .jobs
            .iter()
            .find(|j| j.id == "diagnose")
            .unwrap()
            .outcome,
        JobOutcome::Skipped
    );
    assert_eq!(worker.finished, 4);
}

#[test]
fn cancellation_between_variants_starts_no_later_process() {
    let plan = WorkflowPlan::compile(SOURCE).unwrap();
    let live = Arc::new(AtomicBool::new(true));
    let mut worker = Worker::new();
    worker.stop_after_first = Some(Arc::clone(&live));
    let report = plan
        .execute(WorkflowLimits::default(), &mut worker, &|| {
            live.load(Ordering::SeqCst)
        })
        .unwrap();
    assert_eq!(worker.started, ["build__matrix_000"]);
    assert_eq!(worker.finished, 1);
    assert!(
        report.jobs[1..]
            .iter()
            .all(|j| j.outcome == JobOutcome::Cancelled)
    );
}

#[test]
fn aggregate_output_budget_does_not_reset_for_new_matrix_variants() {
    let source = SOURCE.replace("- bad", "- literal");
    let plan = WorkflowPlan::compile(&source).unwrap();
    let mut worker = Worker::new();
    let limits = WorkflowLimits {
        stream_bytes: 8,
        total_output_bytes: 12,
        ..WorkflowLimits::default()
    };
    let report = plan.execute(limits, &mut worker, &|| true).unwrap();
    let retained: usize = report
        .jobs
        .iter()
        .flat_map(|j| &j.steps)
        .map(|s| s.observation.stdout.len() + s.observation.stderr.len())
        .sum();
    assert!(retained <= 12);
    assert!(
        report
            .jobs
            .iter()
            .any(|j| j.outcome == JobOutcome::OutputLimit)
    );
    assert!(!report.succeeded());
    let mut permitted = Worker::new();
    let report = plan
        .execute(WorkflowLimits::default(), &mut permitted, &|| true)
        .unwrap();
    assert!(
        report.jobs[..3]
            .iter()
            .all(|j| j.outcome == JobOutcome::Succeeded)
    );
}

#[test]
fn script_interpolation_and_invalid_context_in_any_variant_fail_preflight() {
    assert!(
        WorkflowPlan::compile(
            &SOURCE.replace("printf '%s' \"$MODE\"", "printf '${{ matrix.mode }}'")
        )
        .is_err()
    );
    let source = SOURCE.replace("- last", "- '${{ secrets.SECRET }}'");
    assert!(WorkflowPlan::compile(&source).is_err());
    let source = SOURCE.replace("- last", "- '../outside'").replace(
        "        env:\n          MODE: '${{ matrix.mode }}'",
        "        working-directory: '${{ matrix.mode }}'",
    );
    assert!(WorkflowPlan::compile(&source).is_err());
    assert!(WorkflowPlan::compile(SOURCE).is_ok());
}
