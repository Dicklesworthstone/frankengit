#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
use fgit_runner::workflow::{
    StepLimits, StepObservation, StepOutcome, TrustedCommandOutcome, run_trusted_command,
    run_trusted_step,
};
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Work(PathBuf);
impl Work {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-owned-group-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str) -> File {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(self.0.join(name))
            .unwrap()
    }
    fn run(
        &self,
        script: &str,
        timeout: Duration,
        bytes: usize,
        live: &dyn Fn() -> bool,
    ) -> StepObservation {
        run_trusted_step(
            &self.0,
            script,
            StepLimits {
                timeout,
                stream_bytes: bytes,
            },
            &self.file("out"),
            &self.file("err"),
            live,
        )
        .unwrap()
    }
    fn pid(&self, name: &str) -> u32 {
        fs::read_to_string(self.0.join(name))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }
}
impl Drop for Work {
    fn drop(&mut self) {
        // Every fixture descendant has a finite two-second lifetime, including
        // when testing an older runner that fails to terminate it. Do not clean
        // its working directory while it might still write delayed output.
        let end = Instant::now() + Duration::from_secs(3);
        for name in ["worker.pid", "grandchild.pid"] {
            if let Ok(text) = fs::read_to_string(self.0.join(name)) {
                if let Ok(pid) = text.trim().parse::<u32>() {
                    while running(pid) && Instant::now() < end {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn running(pid: u32) -> bool {
    let Ok(bytes) = fs::read(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let close = bytes.iter().rposition(|b| *b == b')').unwrap();
    let state = bytes[close + 1..]
        .split(|b| b.is_ascii_whitespace())
        .find(|s| !s.is_empty())
        .unwrap()[0];
    !matches!(state, b'Z' | b'X')
}
fn assert_stopped(pid: u32) {
    let end = Instant::now() + Duration::from_millis(500);
    while running(pid) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !running(pid),
        "owned descendant {pid} remained live after cleanup"
    );
}
const JOIN: &str = "sleep 2 & echo $! > worker.pid; wait";

#[test]
fn cancellation_stops_the_owned_child_and_grandchild_not_only_the_shell() {
    let work = Work::new();
    let script = "sh -c 'sleep 2 & echo $! > grandchild.pid; wait' & echo $! > worker.pid; wait";
    let result = work.run(script, Duration::from_secs(5), 4096, &|| {
        !work.0.join("grandchild.pid").exists()
    });
    assert_eq!(result.outcome, StepOutcome::Cancelled);
    assert!(result.retain_workspace);
    assert_stopped(work.pid("worker.pid"));
    assert_stopped(work.pid("grandchild.pid"));
}

#[test]
fn timeout_stops_a_waiting_shells_child_and_keeps_nonpass_custody() {
    let work = Work::new();
    let result = work.run(JOIN, Duration::from_millis(150), 4096, &|| true);
    assert_eq!(result.outcome, StepOutcome::TimedOut);
    assert!(result.retain_workspace);
    assert_stopped(work.pid("worker.pid"));
}

#[test]
fn successful_shell_exit_with_a_live_child_is_containment_failure() {
    let work = Work::new();
    let result = work.run(
        "sleep 2 & echo $! > worker.pid; exit 0",
        Duration::from_secs(5),
        4096,
        &|| true,
    );
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.outcome, StepOutcome::ContainmentFailure);
    assert!(result.retain_workspace);
    assert_stopped(work.pid("worker.pid"));
}

#[test]
fn signalled_shell_and_output_exhaustion_do_not_leave_children_running() {
    for script in [
        "sleep 2 & echo $! > worker.pid; kill -TERM $$",
        "sleep 2 & echo $! > worker.pid; while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done",
    ] {
        let work = Work::new();
        let result = work.run(script, Duration::from_secs(5), 64, &|| true);
        assert!(matches!(
            result.outcome,
            StepOutcome::ContainmentFailure | StepOutcome::OutputLimit
        ));
        assert!(result.retain_workspace);
        assert!(result.stdout.len() <= 64);
        assert_stopped(work.pid("worker.pid"));
    }
}

#[test]
fn joined_children_and_ordinary_command_failure_preserve_exact_results() {
    for (script, outcome, code) in [
        (
            "printf 'exact'; sleep 0.02 & wait; exit 0",
            StepOutcome::Succeeded,
            0,
        ),
        (
            "printf 'exact'; sleep 0.02 & wait; exit 7",
            StepOutcome::Failed,
            7,
        ),
    ] {
        let work = Work::new();
        let result = work.run(script, Duration::from_secs(5), 4096, &|| true);
        assert_eq!(result.outcome, outcome);
        assert_eq!(result.exit_code, Some(code));
        assert_eq!(result.stdout, b"exact");
        assert!(result.output_complete);
        assert!(!result.retain_workspace);
    }
}

#[test]
fn cancellation_during_terminal_observation_is_latched_and_retains_both_adapters() {
    for command_adapter in [false, true] {
        let work = Work::new();
        let terminal_observations = Cell::new(0);
        let live = || {
            let Some(pid) = fs::read_to_string(work.0.join("leader.pid"))
                .ok()
                .and_then(|text| text.trim().parse::<u32>().ok())
            else {
                return true;
            };
            let Ok(bytes) = fs::read(format!("/proc/{pid}/stat")) else {
                return true;
            };
            let close = bytes.iter().rposition(|byte| *byte == b')').unwrap();
            let state = bytes[close + 1..]
                .split(|byte| byte.is_ascii_whitespace())
                .find(|field| !field.is_empty())
                .unwrap()[0];
            if state == b'Z' {
                let observations = terminal_observations.get() + 1;
                terminal_observations.set(observations);
                // The first terminal observation may race the outer waitid.
                // The second occurs in completion, while PID custody remains.
                // Return false only once: a later true cannot erase the stop.
                return observations != 2;
            }
            true
        };
        let script = "echo $$ > leader.pid; exit 0";
        if command_adapter {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", script])
                .current_dir(&work.0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let result = run_trusted_command(&mut command, Duration::from_secs(5), &live).unwrap();
            assert_eq!(result.outcome, TrustedCommandOutcome::Cancelled);
            assert_eq!(result.status.unwrap().code(), Some(0));
            assert!(result.retain_workspace);
        } else {
            let result = work.run(script, Duration::from_secs(5), 4096, &live);
            assert_eq!(result.outcome, StepOutcome::Cancelled);
            assert_eq!(result.exit_code, Some(0));
            assert!(result.retain_workspace);
        }
        assert_eq!(terminal_observations.get(), 2);
        assert!(
            live(),
            "later liveness is true but must not retroactively pass"
        );
        let pid = work.pid("leader.pid");
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}/stat")).exists(),
            "cancelled completion must drain and reap before returning"
        );
    }
}

#[test]
fn cancellation_after_final_reap_retains_the_workspace_beside_a_successful_twin() {
    for command_adapter in [false, true] {
        for cancelled in [false, true] {
            let work = Work::new();
            let post_reap_observed = Cell::new(false);
            let live = || {
                let Some(pid) = fs::read_to_string(work.0.join("leader.pid"))
                    .ok()
                    .and_then(|text| text.trim().parse::<u32>().ok())
                else {
                    return true;
                };
                if std::path::Path::new(&format!("/proc/{pid}/stat")).exists() {
                    return true;
                }
                post_reap_observed.set(true);
                !cancelled
            };
            let script = "echo $$ > leader.pid; exit 0";
            let timeout = Duration::from_secs(5);
            if command_adapter {
                let mut command = Command::new("/bin/sh");
                command
                    .args(["-c", script])
                    .current_dir(&work.0)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                let result = run_trusted_command(&mut command, timeout, &live).unwrap();
                assert_eq!(
                    result.outcome,
                    if cancelled {
                        TrustedCommandOutcome::Cancelled
                    } else {
                        TrustedCommandOutcome::Exited
                    }
                );
                assert_eq!(result.status.unwrap().code(), Some(0));
                assert_eq!(result.retain_workspace, cancelled);
            } else {
                let result = work.run(script, timeout, 4096, &live);
                assert_eq!(
                    result.outcome,
                    if cancelled {
                        StepOutcome::Cancelled
                    } else {
                        StepOutcome::Succeeded
                    }
                );
                assert_eq!(result.exit_code, Some(0));
                assert_eq!(result.retain_workspace, cancelled);
            }
            assert!(post_reap_observed.get());
        }
    }
}

#[test]
fn sibling_process_group_is_not_signalled_and_prestart_cancel_starts_nothing() {
    let mut sibling = Command::new("/bin/sleep")
        .arg("2")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let work = Work::new();
    let result = work.run(JOIN, Duration::from_secs(5), 4096, &|| {
        !work.0.join("worker.pid").exists()
    });
    let alive = sibling.try_wait().unwrap().is_none();
    let _stop = sibling.kill();
    sibling.wait().unwrap();
    assert!(alive);
    assert_eq!(result.outcome, StepOutcome::Cancelled);
    assert_stopped(work.pid("worker.pid"));
    let never = Work::new();
    let result = never.run(
        "printf forbidden > marker",
        Duration::from_secs(5),
        4096,
        &|| false,
    );
    assert_eq!(result.outcome, StepOutcome::Cancelled);
    assert!(!result.retain_workspace);
    assert!(!never.0.join("marker").exists());
}

#[test]
fn callback_unwind_cleans_the_owned_group_before_returning_to_the_coordinator() {
    let work = Work::new();
    let result = std::panic::catch_unwind(|| {
        work.run(JOIN, Duration::from_secs(5), 4096, &|| {
            assert!(
                !work.0.join("worker.pid").exists(),
                "intentional fixture callback unwind"
            );
            true
        })
    });
    assert!(result.is_err());
    assert_stopped(work.pid("worker.pid"));
}
