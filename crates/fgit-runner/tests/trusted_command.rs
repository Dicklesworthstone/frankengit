#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
use fgit_runner::workflow::{TrustedCommandOutcome, run_trusted_command};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn shell(script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[test]
fn literal_argv_and_real_exit_status_are_preserved() {
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "test \"$1\" = 'a; exit 99' && exit 7",
        "fixture",
        "a; exit 99",
    ]);
    let result = run_trusted_command(&mut command, Duration::from_secs(3), &|| true).unwrap();
    assert_eq!(result.outcome, TrustedCommandOutcome::Exited);
    assert_eq!(result.status.unwrap().code(), Some(7));
    assert!(!result.retain_workspace);
}

#[test]
fn rejected_envelopes_and_pre_cancel_do_not_spawn() {
    let mut absent = Command::new("/this-program-must-not-exist/fg-test");
    let cancelled = run_trusted_command(&mut absent, Duration::from_secs(3), &|| false).unwrap();
    assert_eq!(cancelled.outcome, TrustedCommandOutcome::Cancelled);
    assert!(cancelled.status.is_none() && !cancelled.retain_workspace);
    for timeout in [Duration::ZERO, Duration::from_secs(3601)] {
        let refused = run_trusted_command(&mut absent, timeout, &|| true).unwrap_err();
        assert_eq!(refused.detail, "invalid trusted command envelope");
        assert!(!refused.retain_workspace);
    }
    let spawn = run_trusted_command(&mut absent, Duration::from_secs(3), &|| true).unwrap_err();
    assert!(spawn.detail.starts_with("spawn trusted command:"));
    assert!(!spawn.retain_workspace);
    let mut relative = Command::new("relative");
    assert!(
        !run_trusted_command(&mut relative, Duration::from_secs(3), &|| true)
            .unwrap_err()
            .retain_workspace
    );
    let mut oversized = shell("exit 0");
    oversized.arg("x".repeat(16 * 1024 + 1));
    assert!(
        !run_trusted_command(&mut oversized, Duration::from_secs(3), &|| true)
            .unwrap_err()
            .retain_workspace
    );
    let mut many = shell("exit 0");
    many.args(vec!["argument"; 129]);
    assert!(
        !run_trusted_command(&mut many, Duration::from_secs(3), &|| true)
            .unwrap_err()
            .retain_workspace
    );
}

#[test]
fn normal_joined_children_pass_but_orphans_and_signals_do_not() {
    let joined = run_trusted_command(
        &mut shell("sleep 0.02 & wait"),
        Duration::from_secs(3),
        &|| true,
    )
    .unwrap();
    assert_eq!(joined.outcome, TrustedCommandOutcome::Exited);
    assert!(joined.status.unwrap().success() && !joined.retain_workspace);
    for script in ["sleep 30 &", "kill -TERM $$"] {
        let result =
            run_trusted_command(&mut shell(script), Duration::from_secs(3), &|| true).unwrap();
        assert_eq!(result.outcome, TrustedCommandOutcome::ContainmentFailure);
        assert!(result.retain_workspace);
    }
}

#[test]
fn time_and_request_cancellation_drain_before_returning() {
    for cancelled in [false, true] {
        let start = Instant::now();
        let timeout = if cancelled {
            Duration::from_secs(10)
        } else {
            Duration::from_millis(80)
        };
        let result = run_trusted_command(&mut shell("sleep 30 & wait"), timeout, &|| {
            !cancelled || start.elapsed() < Duration::from_millis(80)
        })
        .unwrap();
        assert_eq!(
            result.outcome,
            if cancelled {
                TrustedCommandOutcome::Cancelled
            } else {
                TrustedCommandOutcome::TimedOut
            }
        );
        assert!(result.retain_workspace && result.status.is_some());
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
