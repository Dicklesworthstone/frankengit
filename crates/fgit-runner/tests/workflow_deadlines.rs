#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]

//! Real trusted shell execution through WorkflowPlan's deadline interpretation.
//! This does not claim hostile-code isolation or execute a native fg binary.
use fgit_runner::workflow::{
    JobOutcome, StepLimits, StepObservation, StepOutcome, WorkerFailure, WorkflowExecutor,
    WorkflowLimits, WorkflowPlan, run_trusted_step,
};
use fgit_schema::workflow::Job;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Worker {
    root: PathBuf,
    timeout: Option<Duration>,
    closed: Option<bool>,
}
impl Worker {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-workflow-deadline-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self {
            root,
            timeout: None,
            closed: None,
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // These fixtures use exec with no descendants; the process-group
        // runner has reaped the sole child before returning either outcome.
        fs::remove_dir_all(&self.root).unwrap();
    }
}
impl WorkflowExecutor for Worker {
    fn begin_job(&mut self, _: usize, _: &Job, _: &dyn Fn() -> bool) -> Result<(), WorkerFailure> {
        Ok(())
    }
    fn execute_step(
        &mut self,
        _: usize,
        script: &str,
        limits: StepLimits,
        live: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.timeout = Some(limits.timeout);
        let capture = |name| {
            OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(self.root.join(name))
                .unwrap()
        };
        run_trusted_step(
            &self.root,
            script,
            limits,
            &capture("stdout"),
            &capture("stderr"),
            live,
        )
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        assert!(
            self.closed.replace(retain).is_none(),
            "one close per started job"
        );
        Ok(())
    }
}

#[test]
fn yaml_caps_cannot_extend_the_real_process_operator_deadline() {
    for (script, expected) in [
        ("exec /bin/sleep 2", JobOutcome::TimedOut),
        ("printf ready", JobOutcome::Succeeded),
    ] {
        let source = format!(
            "name: real deadline\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    timeout-minutes: 60\n    steps:\n      - run: {script}\n        timeout-minutes: 60\n"
        );
        let mut worker = Worker::new();
        let report = WorkflowPlan::compile(&source)
            .unwrap()
            .execute(
                WorkflowLimits {
                    step_timeout: Duration::from_millis(400),
                    run_timeout: Duration::from_secs(3),
                    ..WorkflowLimits::default()
                },
                &mut worker,
                &|| true,
            )
            .unwrap();
        assert_eq!(report.jobs[0].outcome, expected);
        assert!(worker.timeout.unwrap() <= Duration::from_millis(400));
        if expected == JobOutcome::TimedOut {
            assert_eq!(
                report.jobs[0].steps[0].observation.outcome,
                StepOutcome::TimedOut
            );
            assert!(report.jobs[0].requires_containment());
            assert_eq!(worker.closed, Some(true));
            assert!(!report.succeeded());
        } else {
            assert_eq!(report.jobs[0].steps[0].observation.stdout, b"ready");
            assert_eq!(worker.closed, Some(false));
            assert!(report.succeeded());
        }
    }
}
