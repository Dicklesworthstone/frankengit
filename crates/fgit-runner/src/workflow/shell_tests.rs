//! Real trusted-host shell tests. These exercise interpreter selection and the
//! existing process-group/capture owner, not hostile-code isolation.
use super::*;
use crate::workflow::{
    JobReport, StepShell, WorkflowError, WorkflowExecutor, WorkflowJob, WorkflowLimits,
    WorkflowPlan,
};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Workspace(PathBuf);
impl Workspace {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-shell-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn execute(
        &self,
        script: &str,
        context: &StepContext,
        limits: StepLimits,
        live: &dyn Fn() -> bool,
    ) -> StepObservation {
        let capture = |stream| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.0.join(format!(
                    "capture-{}-{stream}",
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )))
                .unwrap()
        };
        run_trusted_step_with_context(
            &self.0,
            script,
            context,
            limits,
            &capture("out"),
            &capture("err"),
            live,
        )
        .unwrap()
    }

    fn run(&self, script: &str, context: &StepContext) -> StepObservation {
        self.execute(script, context, limits(), &|| true)
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn limits() -> StepLimits {
    StepLimits {
        timeout: Duration::from_secs(10),
        stream_bytes: 16_384,
    }
}

#[test]
fn bash_arrays_use_the_fixed_interpreter_even_when_path_cannot_resolve_it() {
    let workspace = Workspace::new();
    let context = StepContext::new(vec![("PATH".into(), "/no-programs-here".into())], None)
        .unwrap()
        .with_shell(StepShell::Bash);
    let script = "values=(first second); [[ ${#values[@]} == 2 ]]; printf '%s|%s' \"${values[0]}\" \"${values[1]}\"";
    let bash = workspace.run(script, &context);
    assert_eq!(bash.outcome, StepOutcome::Succeeded);
    assert_eq!(bash.stdout, b"first|second");
    assert!(!bash.retain_workspace);
    assert!(bash.output_complete);
    let sh = workspace.run(script, &context.with_shell(StepShell::Sh));
    assert_eq!(sh.outcome, StepOutcome::Failed);
    assert_ne!(sh.exit_code, Some(0));
}

#[test]
fn explicit_shell_profiles_have_documented_failure_flags_and_preserve_legacy_nounset() {
    let workspace = Workspace::new();
    for shell in [None, Some(StepShell::Sh), Some(StepShell::Bash)] {
        let context = shell.map_or_else(StepContext::default, |shell| {
            StepContext::default().with_shell(shell)
        });
        let failed = workspace.run("false; printf unreachable", &context);
        assert_eq!(failed.outcome, StepOutcome::Failed, "{shell:?}");
        assert!(failed.stdout.is_empty());
        let pipeline = workspace.run("false | true; printf survived", &context);
        if shell == Some(StepShell::Bash) {
            assert_eq!(pipeline.outcome, StepOutcome::Failed);
            assert!(pipeline.stdout.is_empty());
        } else {
            assert_eq!(pipeline.outcome, StepOutcome::Succeeded);
            assert_eq!(pipeline.stdout, b"survived");
        }
        let unset = workspace.run("printf '<%s>' \"$FGIT_TEST_UNSET_VALUE\"", &context);
        if shell.is_none() {
            assert_eq!(unset.outcome, StepOutcome::Failed);
            assert!(unset.stdout.is_empty());
        } else {
            assert_eq!(unset.outcome, StepOutcome::Succeeded);
            assert_eq!(unset.stdout, b"<>");
        }
    }
}

#[test]
fn explicit_shells_keep_literal_clean_environment_and_step_local_working_directories() {
    let workspace = Workspace::new();
    fs::create_dir(workspace.0.join("nested")).unwrap();
    for shell in [StepShell::Sh, StepShell::Bash] {
        let context = StepContext::new(
            vec![("LITERAL".into(), "$(touch injected); literal".into())],
            Some("nested".into()),
        )
        .unwrap()
        .with_shell(shell);
        let result = workspace.run(
            "test -z \"${HOME+x}\"; test -z \"${BASH_ENV+x}\"; test -z \"${ENV+x}\"; printf '%s|%s|%s' \"$PATH\" \"$LANG\" \"$LITERAL\"; printf file > selected",
            &context,
        );
        assert_eq!(result.outcome, StepOutcome::Succeeded, "{shell:?}");
        assert_eq!(result.stdout, b"/usr/bin:/bin|C|$(touch injected); literal");
        assert!(workspace.0.join("nested/selected").exists());
        assert!(!workspace.0.join("nested/injected").exists());
    }
    let ordinary = workspace.run(
        "test -z \"${LITERAL+x}\"; test ! -e selected; test -f nested/selected",
        &StepContext::default(),
    );
    assert_eq!(ordinary.outcome, StepOutcome::Succeeded);
}

#[test]
fn explicit_shells_retain_output_limits_cancellation_and_owned_child_reaping() {
    for shell in [StepShell::Sh, StepShell::Bash] {
        let workspace = Workspace::new();
        let context = StepContext::default().with_shell(shell);
        let too_much = workspace.execute(
            "printf 123456789",
            &context,
            StepLimits {
                stream_bytes: 4,
                ..limits()
            },
            &|| true,
        );
        assert_eq!(too_much.outcome, StepOutcome::OutputLimit);
        assert_eq!(too_much.stdout, b"1234");
        assert!(!too_much.output_complete);
        let marker = workspace.0.join("pid");
        let cancelled = workspace.execute(
            "printf '%s' \"$$\" > pid; exec /bin/sleep 30",
            &context,
            limits(),
            &|| {
                fs::read_to_string(&marker)
                    .ok()
                    .and_then(|pid| pid.parse::<u32>().ok())
                    .is_none()
            },
        );
        assert_eq!(cancelled.outcome, StepOutcome::Cancelled, "{shell:?}");
        assert!(cancelled.retain_workspace);
        let pid = fs::read_to_string(marker).unwrap().parse::<u32>().unwrap();
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "child was reaped"
        );
    }
}

#[test]
fn explicit_shells_share_the_existing_timeout_and_pre_spawn_cancellation_path() {
    for shell in [StepShell::Sh, StepShell::Bash] {
        let workspace = Workspace::new();
        let context = StepContext::default().with_shell(shell);
        let before_spawn = workspace.execute(
            "printf unexpected > must-not-exist",
            &context,
            limits(),
            &|| false,
        );
        assert_eq!(before_spawn.outcome, StepOutcome::Cancelled);
        assert!(!workspace.0.join("must-not-exist").exists());
        assert!(!before_spawn.retain_workspace);
        let timeout = workspace.execute(
            "exec /bin/sleep 30",
            &context,
            StepLimits {
                timeout: Duration::from_millis(30),
                ..limits()
            },
            &|| true,
        );
        assert_eq!(timeout.outcome, StepOutcome::TimedOut);
        assert!(timeout.retain_workspace);
    }
}

#[test]
fn environment_aware_adapters_must_opt_in_before_any_shell_job_can_start() {
    struct EnvironmentOnly {
        calls: usize,
    }
    impl WorkflowExecutor for EnvironmentOnly {
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
            unreachable!("preflight must precede every process")
        }
        fn supports_step_context(&self) -> bool {
            true
        }
        fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> {
            self.calls += 1;
            Ok(())
        }
        fn observe_job(&mut self, _: &JobReport) {
            self.calls += 1;
        }
    }
    for shell in ["sh", "bash"] {
        let source = format!(
            "name: preflight\non: push\njobs:\n  first:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo ordinary\n  second:\n    runs-on: fgit-trusted-local\n    needs: first\n    steps:\n      - run: echo selected\n        shell: {shell}\n"
        );
        let plan = WorkflowPlan::compile(&source).unwrap();
        let mut adapter = EnvironmentOnly { calls: 0 };
        assert!(matches!(
            plan.execute(WorkflowLimits::default(), &mut adapter, &|| true),
            Err(WorkflowError::UnsupportedStepShell)
        ));
        assert_eq!(adapter.calls, 0);
    }
}
