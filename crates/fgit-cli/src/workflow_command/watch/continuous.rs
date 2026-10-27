//! Operator-owned service lifetime; every polling attempt keeps finite authority.

use super::{Summary, WatchOptions, poll_once, wait_interval};
use crate::service_stop::StopFile;
use fgit_node::{
    GitDaemonSessionTimeout, OneNode, TerminationSignals, TrustedWorkflowArtifactConfig,
};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct State {
    file: StopFile,
    signals: TerminationSignals,
    deadline: Option<Instant>,
    operator_stopped: bool,
    expired: bool,
    error: Option<String>,
}

impl State {
    fn requested(&mut self) -> bool {
        self.expired |= self.deadline.is_some_and(|end| Instant::now() >= end);
        if self.signals.requested() {
            self.operator_stopped = true;
        }
        if !self.operator_stopped && self.error.is_none() {
            match self.file.should_stop() {
                Ok(stopped) => self.operator_stopped |= stopped,
                Err(error) => self.error = Some(format!("watch stop control failed: {error}")),
            }
        }
        self.operator_stopped || self.expired || self.error.is_some()
    }
}

/// Keep the SAME signal subscriptions and latched control across idle waits,
/// execution, and explicit observer joins. No gap reinstalls process handlers.
#[derive(Clone)]
struct Control(Arc<Mutex<State>>);

impl Control {
    fn requested(&self) -> bool {
        // A poisoned control cannot grant another execution attempt.
        self.0.lock().map_or(true, |mut state| state.requested())
    }

    fn observe(&self, summary: &mut Summary) -> Result<bool, String> {
        let mut state = self.0.lock().map_err(|_| "watch stop control poisoned")?;
        let stopped = state.requested();
        summary.operator_stopped |= state.operator_stopped;
        summary.lifetime_expired |= state.expired;
        summary.stopped |= state.expired;
        if let Some(error) = &state.error {
            return Err(error.clone());
        }
        Ok(stopped)
    }

    fn attempt_timeout(&self, configured: Duration) -> Result<GitDaemonSessionTimeout, String> {
        let state = self.0.lock().map_err(|_| "watch stop control poisoned")?;
        let remaining = state.deadline.map_or(configured, |end| {
            configured.min(end.saturating_duration_since(Instant::now()))
        });
        GitDaemonSessionTimeout::try_new(remaining)
            .map_err(|_| "watch service deadline exhausted before another attempt".into())
    }
}

pub(super) fn run(
    node: &OneNode,
    options: &WatchOptions,
    artifacts: Option<&TrustedWorkflowArtifactConfig>,
    signals: TerminationSignals,
    file: StopFile,
    started: Instant,
    summary: &mut Summary,
    monitor: &mut Option<String>,
    output: &mut impl Write,
) -> Result<(), String> {
    let lifetime = fgit_cli::command_timeout_override_duration();
    let deadline = lifetime
        .map(|timeout| {
            started.checked_add(timeout).ok_or_else(|| {
                "watch lifetime exceeds the monotonic clock's supported range".to_owned()
            })
        })
        .transpose()?;
    let control = Control(Arc::new(Mutex::new(State {
        file,
        signals,
        deadline,
        operator_stopped: false,
        expired: false,
        error: None,
    })));
    if control.observe(summary)? {
        return Ok(());
    }
    let attempt = lifetime.map_or(options.attempt_timeout, |limit| {
        options.attempt_timeout.min(limit)
    });
    writeln!(
        output,
        "{{\"type\":\"workflow_watch_ready\",\"schema_version\":1,\"continuous\":true,\"attempt_timeout_secs\":{},\"lifetime_timeout_secs\":{}}}",
        attempt.as_secs_f64(),
        lifetime.map_or_else(|| "null".into(), |value| value.as_secs_f64().to_string()),
    )
    .and_then(|()| output.flush())
    .map_err(|error| format!("watch readiness output failed; no workflow admitted: {error}"))?;

    loop {
        if control.observe(summary)? {
            break;
        }
        let timeout = match control.attempt_timeout(options.attempt_timeout) {
            Ok(timeout) => timeout,
            Err(error) => {
                // Expiry between the observation and budget calculation is a
                // normal lifetime stop, not an infrastructure failure.
                if control.observe(summary)? {
                    break;
                }
                return Err(error);
            }
        };
        let parent = node.command_request_context(Some(timeout));
        let probe = control.clone();
        let (result, cleanup) = parent
            .run_until_stopped(
                node.runtime(),
                move || probe.requested(),
                |request| poll_once(node, request, options, artifacts, summary, output),
            )
            .map_err(|error| error.to_string())?;
        *monitor = cleanup.err().map(|error| error.to_string());
        // Capture a control failure even if it interrupted active work. Never
        // report it as an ordinary operator stop or forget a persisted report.
        let stopped = match (result, control.observe(summary)) {
            (Err(operation), Err(control)) => return Err(format!("{operation}; {control}")),
            (Err(error), _) | (_, Err(error)) => return Err(error),
            (Ok(()), Ok(stopped)) => stopped,
        };
        if stopped || monitor.is_some() || summary.stopped || summary.reconcile {
            break;
        }
        if !wait_interval(options.interval, &|| !control.requested()) {
            control.observe(summary)?;
            break;
        }
    }
    Ok(())
}
