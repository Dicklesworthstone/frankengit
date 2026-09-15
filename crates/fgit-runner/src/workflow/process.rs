//! Direct-child trusted execution; no namespace, network or descendant claims.
//! File-backed capture cannot hang on a descendant holding a pipe open. On a
//! timeout, signal or cancellation the caller must retain the workspace: direct
//! child reaping does not prove that escaped descendants relinquished access.

use super::{StepLimits, StepObservation, StepOutcome, WorkerFailure};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Runs exactly `/bin/sh -eu -c <script>` in the named disposable working copy.
/// `stdout` and `stderr` must be distinct, empty, private regular files opened
/// read/write by the owner. The surrounding Asupersync request owns `live`.
/// The script is explicitly trusted to join its children before normal exit.
pub fn run_trusted_step(
    directory: &Path,
    script: &str,
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
    let mut child = Command::new("/bin/sh")
        .args(["-eu", "-c", script])
        .current_dir(directory)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(errors)
        .spawn()
        .map_err(|e| WorkerFailure::new(format!("spawn trusted shell: {e}"), false))?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                result.exit_code = status.code();
                result.retain_workspace = status.code().is_none();
                result.outcome = if result.retain_workspace {
                    StepOutcome::ContainmentFailure
                } else if !live() {
                    StepOutcome::Cancelled
                } else if started.elapsed() >= limits.timeout {
                    StepOutcome::TimedOut
                } else if status.success() {
                    StepOutcome::Succeeded
                } else {
                    StepOutcome::Failed
                };
                break;
            }
            Ok(None) => {}
            Err(error) => {
                let _kill = child.kill();
                let _reap = reap_until(&mut child, Duration::from_secs(3));
                return Err(WorkerFailure::new(
                    format!("child status unavailable: {error}"),
                    true,
                ));
            }
        }
        let sizes = stdout
            .metadata()
            .and_then(|out| stderr.metadata().map(|err| (out.len(), err.len())));
        let stop = match sizes {
            Err(_) => Some(StepOutcome::ContainmentFailure),
            Ok((out, err))
                if out > limits.stream_bytes as u64 || err > limits.stream_bytes as u64 =>
            {
                Some(StepOutcome::OutputLimit)
            }
            _ if !live() => Some(StepOutcome::Cancelled),
            _ if started.elapsed() >= limits.timeout => Some(StepOutcome::TimedOut),
            _ => None,
        };
        if let Some(outcome) = stop {
            let killed = child.kill();
            let reaped = reap_until(&mut child, Duration::from_secs(3));
            result.retain_workspace = true;
            result.outcome = outcome;
            match reaped {
                Ok(status) => result.exit_code = status.code(),
                Err(error) => {
                    return Err(WorkerFailure::new(
                        format!("direct child unresolved: kill={killed:?}, reap={error}"),
                        true,
                    ));
                }
            }
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
fn reap_until(
    child: &mut std::process::Child,
    budget: Duration,
) -> std::io::Result<std::process::ExitStatus> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if started.elapsed() >= budget {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "direct child did not reap",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
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
