//! Trusted execution with an owned process group; no hostile isolation claim.
//! File-backed capture cannot hang on a descendant holding a pipe open. On a
//! timeout, signal or cancellation the caller must retain the workspace: direct
//! child reaping does not prove that escaped descendants relinquished access.

use super::{StepContext, StepLimits, StepObservation, StepOutcome, WorkerFailure};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
mod command;
mod group;
pub use command::{TrustedCommandObservation, TrustedCommandOutcome, run_trusted_command};
use group::{CompletionStop, ProcessGroup};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Runs exactly `/bin/sh -eu -c <script>` in the named disposable working copy.
/// `stdout` and `stderr` must be distinct, empty, private regular files opened
/// read/write by the owner. The surrounding Asupersync request owns `live`.
/// The script is explicitly trusted to join its children before normal exit.
pub fn run_trusted_step_with_context(
    directory: &Path,
    script: &str,
    context: &StepContext,
    limits: StepLimits,
    stdout: &File,
    stderr: &File,
    live: &dyn Fn() -> bool,
) -> Result<StepObservation, WorkerFailure> {
    let fail = |detail: &str| WorkerFailure::new(detail, false);
    if !directory.is_absolute()
        || script.is_empty()
        || script.len() > 8192
        || script.contains('\0')
        || limits.timeout.is_zero()
        || limits.timeout > Duration::from_secs(3600)
        || limits.stream_bytes == 0
        || limits.stream_bytes > 2 * 1024 * 1024
    {
        return Err(fail("invalid trusted step envelope"));
    }
    let out_meta = stdout
        .metadata()
        .map_err(|e| WorkerFailure::new(e.to_string(), false))?;
    let err_meta = stderr
        .metadata()
        .map_err(|e| WorkerFailure::new(e.to_string(), false))?;
    if !out_meta.is_file()
        || !err_meta.is_file()
        || out_meta.len() != 0
        || err_meta.len() != 0
        || (out_meta.dev(), out_meta.ino()) == (err_meta.dev(), err_meta.ino())
    {
        return Err(fail(
            "capture descriptors must name distinct empty regular files",
        ));
    }
    let started = Instant::now();
    let mut result = StepObservation {
        outcome: StepOutcome::Cancelled,
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        elapsed_millis: 0,
        output_complete: true,
        retain_workspace: false,
    };
    if !live() {
        return Ok(result);
    }
    let output = stdout
        .try_clone()
        .map_err(|e| WorkerFailure::new(e.to_string(), false))?;
    let errors = stderr
        .try_clone()
        .map_err(|e| WorkerFailure::new(e.to_string(), false))?;
    let selected_directory = select_directory(directory, context)?;
    if !live() {
        return Ok(result);
    }
    let child = Command::new("/bin/sh")
        .args(["-eu", "-c", script])
        .current_dir(&selected_directory)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .envs(context.environment())
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(errors)
        .spawn()
        .map_err(|e| WorkerFailure::new(format!("spawn trusted shell: {e}"), false))?;
    let mut child = ProcessGroup::new(child);
    loop {
        match child.exited() {
            Ok(true) => {
                let completion =
                    child
                        .complete(started + limits.timeout, live)
                        .map_err(|error| {
                            WorkerFailure::new(format!("process-group completion: {error}"), true)
                        })?;
                let status = completion.status;
                result.exit_code = status.code();
                let containment_failure = completion.leftover || status.code().is_none();
                result.outcome = if containment_failure {
                    StepOutcome::ContainmentFailure
                } else if completion.stopped == Some(CompletionStop::Cancelled) || !live() {
                    StepOutcome::Cancelled
                } else if completion.stopped == Some(CompletionStop::TimedOut)
                    || started.elapsed() >= limits.timeout
                {
                    StepOutcome::TimedOut
                } else if status.success() {
                    StepOutcome::Succeeded
                } else {
                    StepOutcome::Failed
                };
                result.retain_workspace = matches!(
                    result.outcome,
                    StepOutcome::ContainmentFailure
                        | StepOutcome::Cancelled
                        | StepOutcome::TimedOut
                );
                break;
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
        let sizes = stdout
            .metadata()
            .and_then(|out| stderr.metadata().map(|err| (out.len(), err.len())));
        let stop = match sizes {
            Err(_) => Some(StepOutcome::ContainmentFailure),
            _ if !live() => Some(StepOutcome::Cancelled),
            _ if started.elapsed() >= limits.timeout => Some(StepOutcome::TimedOut),
            Ok((out, err))
                if out > limits.stream_bytes as u64 || err > limits.stream_bytes as u64 =>
            {
                Some(StepOutcome::OutputLimit)
            }
            _ => None,
        };
        if let Some(outcome) = stop {
            result.retain_workspace = true;
            result.outcome = outcome;
            let status = child.terminate().map_err(|error| {
                WorkerFailure::new(format!("process-group cleanup unresolved: {error}"), true)
            })?;
            result.exit_code = status.code();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let (out, out_complete) = capture(stdout, limits.stream_bytes)
        .map_err(|e| WorkerFailure::new(format!("stdout capture: {e}"), result.retain_workspace))?;
    let (err, err_complete) = capture(stderr, limits.stream_bytes)
        .map_err(|e| WorkerFailure::new(format!("stderr capture: {e}"), result.retain_workspace))?;
    result.output_complete = out_complete && err_complete;
    result.stdout = out;
    result.stderr = err;
    if (!out_complete || !err_complete) && result.outcome == StepOutcome::Succeeded {
        result.outcome = StepOutcome::OutputLimit;
    }
    result.elapsed_millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Ok(result)
}
fn capture(file: &File, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let before = file.metadata()?.len();
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    reader.take(limit as u64).read_to_end(&mut bytes)?;
    let after = file.metadata()?.len();
    Ok((bytes, before == after && after <= limit as u64))
}

/// Original context-free entry point, retaining its fixed clean environment.
pub fn run_trusted_step(
    directory: &Path,
    script: &str,
    limits: StepLimits,
    stdout: &File,
    stderr: &File,
    live: &dyn Fn() -> bool,
) -> Result<StepObservation, WorkerFailure> {
    run_trusted_step_with_context(
        directory,
        script,
        &StepContext::default(),
        limits,
        stdout,
        stderr,
        live,
    )
}

/// The workspace is operator-owned trusted storage, not a hostile-filesystem
/// sandbox. Check every selected component and reject symlinks before spawning;
/// these checks do not claim atomic containment against concurrent host mutation.
fn select_directory(
    root: &Path,
    context: &StepContext,
) -> Result<std::path::PathBuf, WorkerFailure> {
    let Some(relative) = context.working_directory() else {
        return Ok(root.to_path_buf());
    };
    let root = root
        .canonicalize()
        .map_err(|e| WorkerFailure::new(format!("workspace directory unavailable: {e}"), false))?;
    let mut selected = root.clone();
    for component in relative.split('/') {
        selected.push(component);
        let metadata = std::fs::symlink_metadata(&selected).map_err(|e| {
            WorkerFailure::new(format!("step working-directory unavailable: {e}"), false)
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(WorkerFailure::new(
                "step working-directory must contain only real directories, not symlinks",
                false,
            ));
        }
    }
    let resolved = selected.canonicalize().map_err(|e| {
        WorkerFailure::new(format!("step working-directory unavailable: {e}"), false)
    })?;
    if !resolved.starts_with(&root) {
        return Err(WorkerFailure::new(
            "step working-directory is outside its workspace",
            false,
        ));
    }
    Ok(resolved)
}

#[cfg(test)]
#[path = "context_tests.rs"]
mod context_tests;
