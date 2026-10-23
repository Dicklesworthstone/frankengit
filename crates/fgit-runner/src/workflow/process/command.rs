//! Arbitrary explicitly trusted foreground tools share the workflow process owner.
use super::super::WorkerFailure;
use super::group::{CompletionStop, ProcessGroup};
use std::os::unix::{ffi::OsStrExt, process::CommandExt};
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

/// Why foreground execution ended. This does not grant publication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedCommandOutcome {
    Exited,
    Cancelled,
    TimedOut,
    ContainmentFailure,
}

/// The direct child's real status plus explicit workspace-retention responsibility.
#[derive(Debug)]
pub struct TrustedCommandObservation {
    pub outcome: TrustedCommandOutcome,
    /// Absent only when cancellation prevented spawn.
    pub status: Option<ExitStatus>,
    pub retain_workspace: bool,
}

/// Run a caller-configured trusted command in a fresh owned process group.
///
/// The caller owns environment, working directory and nonblocking diagnostics.
/// Never supply unbounded output pipes without independently draining them.
/// No shell is inserted and no argument is interpreted by this adapter. The
/// absolute executable, argv and timeout are bounded before any child starts.
/// The surrounding runtime owns `live`; cancellation drains before returning.
/// Unjoined group members, signals and post-spawn interruption retain the
/// workspace even when known group members stopped. Escaped descendants and
/// hostile-code isolation are not proved. The caller must not reap SIGCHLD.
pub fn run_trusted_command(
    command: &mut Command,
    timeout: Duration,
    live: &dyn Fn() -> bool,
) -> Result<TrustedCommandObservation, WorkerFailure> {
    if !Path::new(command.get_program()).is_absolute()
        || command.get_program().as_bytes().len() > 4096
        || command.get_args().count() > 128
        || command
            .get_args()
            .any(|arg| arg.as_bytes().len() > 16 * 1024)
        || timeout.is_zero()
        || timeout > Duration::from_secs(3600)
    {
        return Err(WorkerFailure::new(
            "invalid trusted command envelope",
            false,
        ));
    }
    if !live() {
        return Ok(TrustedCommandObservation {
            outcome: TrustedCommandOutcome::Cancelled,
            status: None,
            retain_workspace: false,
        });
    }
    let started = Instant::now();
    let child = command
        .process_group(0)
        .spawn()
        .map_err(|error| WorkerFailure::new(format!("spawn trusted command: {error}"), false))?;
    let mut child = ProcessGroup::new(child);
    loop {
        match child.exited() {
            Ok(true) => {
                let completion = child.complete(started + timeout, live).map_err(|error| {
                    WorkerFailure::new(format!("process-group completion: {error}"), true)
                })?;
                let status = completion.status;
                let containment_failure = completion.leftover || status.code().is_none();
                let outcome = if containment_failure {
                    TrustedCommandOutcome::ContainmentFailure
                } else if completion.stopped == Some(CompletionStop::Cancelled) || !live() {
                    TrustedCommandOutcome::Cancelled
                } else if completion.stopped == Some(CompletionStop::TimedOut)
                    || started.elapsed() >= timeout
                {
                    TrustedCommandOutcome::TimedOut
                } else {
                    TrustedCommandOutcome::Exited
                };
                let retain_workspace = !matches!(outcome, TrustedCommandOutcome::Exited);
                return Ok(TrustedCommandObservation {
                    outcome,
                    status: Some(status),
                    retain_workspace,
                });
            }
            Ok(false) => {}
            Err(error) => {
                let cleanup = child.terminate();
                return Err(WorkerFailure::new(
                    format!("child status unavailable: {error}; cleanup={cleanup:?}"),
                    true,
                ));
            }
        }
        let stop = if !live() {
            Some(TrustedCommandOutcome::Cancelled)
        } else if started.elapsed() >= timeout {
            Some(TrustedCommandOutcome::TimedOut)
        } else {
            None
        };
        if let Some(outcome) = stop {
            let status = child.terminate().map_err(|error| {
                WorkerFailure::new(format!("process-group cleanup unresolved: {error}"), true)
            })?;
            return Ok(TrustedCommandObservation {
                outcome,
                status: Some(status),
                retain_workspace: true,
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
