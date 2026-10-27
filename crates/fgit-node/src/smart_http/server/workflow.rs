//! An operator-configured workflow controller is a sibling of HTTP sessions.
//! It owns no route and receives no request data or credentials from a session.

use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use super::{Controllers, NodeSmartHttpRefusal, io_error, lifetime::Acceptance};
use crate::index_maintenance::MaintenanceConfig;
use crate::workflow_watch::{
    WorkflowWatchConfig, WorkflowWatchControl, WorkflowWatchError, WorkflowWatchReceipt,
    run_service_with_ready,
};
use crate::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};

pub(super) struct Worker {
    control: WorkflowWatchControl,
    finished: Arc<AtomicBool>,
    join: Option<Box<dyn FnOnce()>>,
    launch: Option<SyncSender<()>>,
    outcome: Receiver<Result<WorkflowWatchReceipt, WorkflowWatchError>>,
}

struct Completion(Arc<AtomicBool>);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl Worker {
    pub(super) fn start(
        node: &OneNode,
        config: WorkflowWatchConfig,
        on_drained: &dyn Fn(&WorkflowWatchReceipt) -> io::Result<()>,
        should_stop: Option<&dyn Fn() -> io::Result<bool>>,
    ) -> Result<Option<Self>, NodeSmartHttpRefusal> {
        let node_config = node
            .service_config
            .clone()
            .with_expected_repository_incarnation(node.repository_incarnation_id());
        let control = WorkflowWatchControl::default();
        let child_control = control.clone();
        let gate_control = control.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let completion = Completion(Arc::clone(&finished));
        let (ready_sender, ready) = mpsc::sync_channel(1);
        let (launch, launched) = mpsc::sync_channel(1);
        let (outcome_sender, outcome) = mpsc::sync_channel(1);
        let task = node
            .runtime()
            .submit_blocking(move || {
                let _completion = completion;
                let result = run_service_with_ready(node_config, config, child_control, || {
                    ready_sender.send(()).map_err(|_| {
                        io::Error::other("HTTP workflow owner left before readiness")
                    })?;
                    match launched.recv() {
                        Ok(()) => Ok(()),
                        Err(_) if gate_control.is_stopped() => Ok(()),
                        Err(_) => Err(io::Error::other(
                            "HTTP workflow startup owner left before readiness",
                        )),
                    }
                });
                let _ = outcome_sender.send(result);
            })
            .map_err(|error| {
                io_error(
                    "schedule workflow service",
                    io::Error::other(error.to_string()),
                )
            })?;
        let worker = Self {
            control,
            finished,
            join: Some(Box::new(move || {
                task.wait();
            })),
            launch: Some(launch),
            outcome,
        };
        loop {
            // Only continuous listeners supply a stop callback. Starting a
            // bounded embedding must not consume its idle acceptance window.
            let stopped = should_stop.map_or(Ok(false), |probe| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(probe)).unwrap_or_else(|_| {
                    Err(io::Error::other("HTTP startup stop callback panicked"))
                })
            });
            match stopped {
                Ok(false) => {}
                Ok(true) => return worker.finish_inner(on_drained, true).map(|_| None),
                Err(error) => {
                    let cleanup = worker.finish_inner(on_drained, true).err();
                    return Err(io_error(
                        "poll HTTP stop during workflow startup",
                        io::Error::other(match cleanup {
                            None => error.to_string(),
                            Some(cleanup) => {
                                format!("{error}; workflow drain also failed: {cleanup}")
                            }
                        }),
                    ));
                }
            }
            match ready.recv_timeout(Duration::from_millis(10)) {
                Ok(()) => return Ok(Some(worker)),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return match worker.finish(on_drained) {
                        Err(error) => Err(error),
                        Ok(_) => Err(io_error(
                            "start workflow service",
                            io::Error::other("workflow service stopped before readiness"),
                        )),
                    };
                }
            }
        }
    }

    pub(super) fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }
    pub(super) fn request_stop(&self) {
        self.control.request_stop();
    }

    pub(super) fn activate(&mut self) -> Result<(), NodeSmartHttpRefusal> {
        if let Some(launch) = self.launch.take() {
            launch.send(()).map_err(|_| {
                io_error(
                    "activate workflow service",
                    io::Error::other("workflow child left before HTTP readiness"),
                )
            })?;
        }
        Ok(())
    }

    pub(super) fn finish(
        self,
        on_drained: &dyn Fn(&WorkflowWatchReceipt) -> io::Result<()>,
    ) -> Result<WorkflowWatchReceipt, NodeSmartHttpRefusal> {
        self.finish_inner(on_drained, false)
    }

    fn finish_inner(
        mut self,
        on_drained: &dyn Fn(&WorkflowWatchReceipt) -> io::Result<()>,
        startup_stop: bool,
    ) -> Result<WorkflowWatchReceipt, NodeSmartHttpRefusal> {
        self.request_stop();
        drop(self.launch.take());
        if let Some(join) = self.join.take() {
            join();
        }
        let result = self.outcome.recv().map_err(|_| {
            io_error(
                "join workflow service",
                io::Error::other("workflow child exited without a terminal observation"),
            )
        })?;
        let stopped = result
            .as_ref()
            .err()
            .filter(|error| startup_stop && error.stopped_before_readiness())
            .and_then(WorkflowWatchError::receipt)
            .cloned();
        let result = stopped.map_or(result, Ok);
        let observed = match &result {
            Ok(receipt) => Some(receipt),
            Err(error) => error.receipt(),
        }
        .map_or(Ok(()), |receipt| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| on_drained(receipt)))
                .unwrap_or_else(|_| Err(io::Error::other("workflow drain observer panicked")))
        });
        match (result, observed) {
            (Ok(receipt), Ok(())) => Ok(receipt),
            (Err(error), Ok(())) => {
                Err(io_error("drain workflow service", io::Error::other(error)))
            }
            (Ok(_), Err(error)) => Err(io_error("report workflow service drain", error)),
            (Err(error), Err(output)) => Err(io_error(
                "report failed workflow service drain",
                io::Error::other(format!("{error}; observation failed: {output}")),
            )),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.request_stop();
        drop(self.launch.take());
        if let Some(join) = self.join.take() {
            join();
        }
    }
}

impl OneNode {
    /// Serve with one explicitly trusted operator workflow controller. Every
    /// future script selected by `workflow` must be trusted with host privileges;
    /// HTTP write grants are not hostile-code isolation or execution credentials.
    /// No execution route is installed. All endpoint grants stay independent.
    ///
    /// Readiness follows both optional controllers. A controller failure stops
    /// acceptance; every accepted request and both controllers drain before return.
    pub fn serve_repository_http_with_workflow_service_bounded(
        &self,
        listener: &TcpListener,
        limits: GitDaemonServerLimits,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        allow_source: bool,
        idle_timeout: Duration,
        workflow: WorkflowWatchConfig,
        maintenance: Option<MaintenanceConfig>,
        on_ready: &dyn Fn() -> io::Result<()>,
        on_workflow_drained: &dyn Fn(&WorkflowWatchReceipt) -> io::Result<()>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            limits.max_in_flight(),
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            allow_issues,
            allow_outcomes,
            allow_pulls,
            allow_source,
            Acceptance::Bounded {
                max_sessions: limits.max_sessions(),
                idle_timeout,
            },
            Controllers {
                maintenance,
                workflow: Some(workflow),
                on_workflow_drained: Some(on_workflow_drained),
                on_ready: Some(on_ready),
            },
        )
    }

    /// Keep one HTTP profile and one workflow controller until the owner stops
    /// acceptance. The controller's active request is cancelled and settled
    /// without cancelling the native root needed for workspace and node cleanup.
    pub fn serve_repository_http_with_workflow_service_until_stopped(
        &self,
        listener: &TcpListener,
        max_in_flight: usize,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        allow_source: bool,
        workflow: WorkflowWatchConfig,
        maintenance: Option<MaintenanceConfig>,
        should_stop: &dyn Fn() -> io::Result<bool>,
        on_ready: &dyn Fn() -> io::Result<()>,
        on_workflow_drained: &dyn Fn(&WorkflowWatchReceipt) -> io::Result<()>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            max_in_flight,
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            allow_issues,
            allow_outcomes,
            allow_pulls,
            allow_source,
            Acceptance::UntilStopped(should_stop),
            Controllers {
                maintenance,
                workflow: Some(workflow),
                on_workflow_drained: Some(on_workflow_drained),
                on_ready: Some(on_ready),
            },
        )
    }
}
