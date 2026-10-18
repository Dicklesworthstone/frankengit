use super::*;
use crate::workflow::{
    JobReport, WorkflowError, WorkflowExecutor, WorkflowJob, WorkflowLimits, WorkflowPlan,
};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-context-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn execute(
        &self,
        script: &str,
        context: &StepContext,
        live: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        let capture = |suffix| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.0.join(format!(
                    "capture-{}-{suffix}",
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )))
                .unwrap()
        };
        run_trusted_step_with_context(
            &self.0,
            script,
            context,
            StepLimits {
                timeout: Duration::from_secs(10),
                stream_bytes: 16384,
            },
            &capture("out"),
            &capture("err"),
            live,
        )
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn literal_environment_never_becomes_shell_code_or_leaks_into_later_steps() {
    let temp = Temp::new();
    let value = "literal $(touch injected) ; ' \" $HOME\nsecond line";
    let context = StepContext::new(
        vec![
            ("BUILD_MODE".into(), value.into()),
            ("EMPTY".into(), String::new()),
            ("LANG".into(), "explicit".into()),
        ],
        None,
    )
    .unwrap();
    let result = temp
        .execute(
            "test \"$LANG\" = explicit; test \"${EMPTY+x}\" = x; printf '%s' \"$BUILD_MODE\"",
            &context,
            &|| true,
        )
        .unwrap();
    assert_eq!(result.outcome, StepOutcome::Succeeded);
    assert_eq!(result.stdout, value.as_bytes());
    assert!(!temp.0.join("injected").exists());
    let second = temp.execute("test -z \"${BUILD_MODE+x}\"; test -z \"${EMPTY+x}\"; printf '%s|%s' \"$PATH\" \"$LANG\"", &StepContext::default(), &|| true).unwrap();
    assert_eq!(second.outcome, StepOutcome::Succeeded);
    assert_eq!(second.stdout, b"/usr/bin:/bin|C");
}

#[test]
fn working_directory_is_step_local_and_each_component_must_be_a_real_directory() {
    let temp = Temp::new();
    fs::create_dir_all(temp.0.join("src/nested")).unwrap();
    fs::write(temp.0.join("src/nested/input"), b"exact nested source").unwrap();
    let context = StepContext::new(Vec::new(), Some("./src/nested".into())).unwrap();
    let result = temp
        .execute("cat input; printf created > output", &context, &|| true)
        .unwrap();
    assert_eq!(result.outcome, StepOutcome::Succeeded);
    assert_eq!(result.stdout, b"exact nested source");
    assert_eq!(
        fs::read(temp.0.join("src/nested/output")).unwrap(),
        b"created"
    );
    let root = temp
        .execute(
            "test -f src/nested/output; test ! -f output",
            &StepContext::default(),
            &|| true,
        )
        .unwrap();
    assert_eq!(root.outcome, StepOutcome::Succeeded);
    symlink(temp.0.join("src"), temp.0.join("alias")).unwrap();
    for directory in ["absent", "src/nested/input", "alias", "alias/nested"] {
        let context = StepContext::new(Vec::new(), Some(directory.into())).unwrap();
        let failed = temp
            .execute("touch must-not-run", &context, &|| true)
            .unwrap_err();
        assert!(!failed.retain_workspace);
    }
    assert!(!temp.0.join("src/nested/must-not-run").exists());
    let cancelled = temp
        .execute("touch must-not-run", &context, &|| false)
        .unwrap();
    assert_eq!(cancelled.outcome, StepOutcome::Cancelled);
    assert!(!temp.0.join("src/nested/must-not-run").exists());
}

#[test]
fn old_executors_refuse_the_complete_graph_before_starting_any_job() {
    struct Old {
        calls: usize,
    }
    impl WorkflowExecutor for Old {
        fn begin_job(
            &mut self,
            _: usize,
            _: &WorkflowJob,
            _: &dyn Fn() -> bool,
        ) -> Result<(), WorkerFailure> {
            self.calls += 1;
            Ok(())
        }
        fn execute_step(
            &mut self,
            _: usize,
            _: &str,
            _: StepLimits,
            _: &dyn Fn() -> bool,
        ) -> Result<StepObservation, WorkerFailure> {
            self.calls += 1;
            Ok(StepObservation {
                outcome: StepOutcome::Succeeded,
                exit_code: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
                elapsed_millis: 0,
                output_complete: true,
                retain_workspace: false,
            })
        }
        fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> {
            self.calls += 1;
            Ok(())
        }
        fn observe_job(&mut self, _: &JobReport) {}
    }
    let source = "name: context\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo first\n      - run: echo second\n        env:\n          VALUE: explicit\n";
    let plan = WorkflowPlan::compile(source).unwrap();
    let mut old = Old { calls: 0 };
    assert!(matches!(
        plan.execute(WorkflowLimits::default(), &mut old, &|| true),
        Err(WorkflowError::UnsupportedStepContext)
    ));
    assert_eq!(old.calls, 0);
    let plain =
        WorkflowPlan::compile(&source.replace("        env:\n          VALUE: explicit\n", ""))
            .unwrap();
    assert!(
        plain
            .execute(WorkflowLimits::default(), &mut old, &|| true)
            .is_ok()
    );
    assert_eq!(old.calls, 4);
}
