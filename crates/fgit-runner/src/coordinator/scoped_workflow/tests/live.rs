//! Real trusted foreground shells with private file-backed capture. This tests
//! multi-step composition, not native Git admission or hostile containment.
use super::*;
use crate::RunOutcome;
use std::fs::{self, File};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-coordinated-workflow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Shell {
    directory: Directory,
    active: Option<PathBuf>,
    captures: u64,
}
impl Shell {
    fn new() -> Self {
        Self {
            directory: Directory::new(),
            active: None,
            captures: 0,
        }
    }
    fn capture(&self, kind: &str) -> Result<File, WorkerFailure> {
        File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(
                self.directory
                    .0
                    .join(format!("capture-{}-{kind}", self.captures)),
            )
            .map_err(|error| WorkerFailure::new(error.to_string(), false))
    }
}
impl WorkflowExecutor for Shell {
    fn begin_job(
        &mut self,
        index: usize,
        _: &fgit_schema::workflow::Job,
        _: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        if self.active.is_some() {
            return Err(WorkerFailure::new("previous scope not closed", true));
        }
        let path = self.directory.0.join(index.to_string());
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|error| WorkerFailure::new(error.to_string(), false))?;
        self.active = Some(path);
        Ok(())
    }
    fn execute_step(
        &mut self,
        _: usize,
        script: &str,
        limits: StepLimits,
        live: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        self.captures += 1;
        let stdout = self.capture("out")?;
        let stderr = self.capture("err")?;
        crate::workflow::run_trusted_step(
            self.active.as_ref().expect("started scope"),
            script,
            limits,
            &stdout,
            &stderr,
            live,
        )
    }
    fn finish_job(&mut self, retain: bool) -> Result<(), WorkerFailure> {
        if retain {
            return Err(WorkerFailure::new("scope retained for inspection", true));
        }
        fs::remove_dir_all(self.active.take().expect("started scope"))
            .map_err(|error| WorkerFailure::new(error.to_string(), true))
    }
}

#[test]
fn native_shell_steps_share_files_but_dependent_jobs_get_fresh_workspaces() {
    let source = "name: live\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf 'hello world\\n' > marker\n      - run: cat marker\n  test:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: test ! -e marker\n";
    let mut c = coordinator();
    let mut prepared = enqueue(
        &mut c,
        source,
        1,
        WorkflowLimits::default(),
        TriggerContext::trusted_push("operator"),
    );
    let id = prepared.run_id();
    let mut shell = Shell::new();
    let receipt = c
        .execute_trusted_workflow(&mut prepared, &mut shell, 200, &|| true)
        .unwrap();
    assert!(receipt.report().succeeded(), "{:?}", receipt.report());
    assert_eq!(
        receipt.report().jobs[0].steps[1].observation.stdout,
        b"hello world\n"
    );
    assert!(
        receipt.report().jobs[1].steps[0]
            .observation
            .stdout
            .is_empty()
    );
    assert!(shell.active.is_none());
    assert!(!shell.directory.0.join("0").exists());
    assert!(!shell.directory.0.join("1").exists());
    assert_eq!(shell.captures, 3);
    assert_eq!(
        c.active_runs[&id].status,
        RunStatus::Terminal(RunOutcome::Succeeded)
    );
    assert_eq!(c.obligations.workflow_scopes_opened, 2);
    assert_eq!(c.obligations.workflow_scopes_closed, 2);
    assert!(
        c.drain_check_facts()
            .iter()
            .all(|f| f.conclusion != Some(CheckRunConclusion::Success))
    );
    c.verify_quiescence().unwrap();
}
