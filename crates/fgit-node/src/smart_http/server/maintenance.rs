//! The listener owns a bounded group of independent maintenance children.
//! Every progress owner is ready before any child may build an index. Every
//! return requests stop and releases all launch gates before joining children.

use super::{RepositoryHttpService, RepositoryHttpServices};
use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use crate::index_maintenance::{
    MaintenanceConfig, MaintenanceControl, MaintenanceGroup, MaintenanceReceipt,
    run_service_with_ready,
};
use crate::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};

use super::{Controllers, NodeSmartHttpRefusal, io_error, lifetime::Acceptance};

pub(super) struct Worker {
    children: Vec<Child>,
}

struct Child {
    control: MaintenanceControl,
    finished: Arc<AtomicBool>,
    join: Option<Box<dyn FnOnce()>>,
    launch: Option<SyncSender<()>>,
    outcome: Receiver<Result<MaintenanceReceipt, String>>,
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
        group: MaintenanceGroup,
        should_stop: Option<&dyn Fn() -> io::Result<bool>>,
    ) -> Result<Option<Self>, NodeSmartHttpRefusal> {
        let mut worker = Self {
            children: Vec::with_capacity(group.configs().len()),
        };
        for config in group.into_configs() {
            match startup_stop(should_stop) {
                Ok(false) => {}
                Ok(true) => return worker.finish().map(|_| None),
                Err(error) => {
                    return Err(worker.startup_failure(io_error(
                        "poll HTTP stop during index maintenance startup",
                        error,
                    )));
                }
            }
            let (child, ready) = match Child::start(node, config) {
                Ok(child) => child,
                Err(error) => return Err(worker.startup_failure(error)),
            };
            worker.children.push(child);
            loop {
                match startup_stop(should_stop) {
                    Ok(false) => {}
                    Ok(true) => return worker.finish().map(|_| None),
                    Err(error) => {
                        return Err(worker.startup_failure(io_error(
                            "poll HTTP stop during index maintenance startup",
                            error,
                        )));
                    }
                }
                match ready.recv_timeout(Duration::from_millis(10)) {
                    Ok(()) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err(worker.startup_failure(io_error(
                            "start source index maintenance",
                            io::Error::other("maintenance child stopped before readiness"),
                        )));
                    }
                }
            }
        }
        Ok(Some(worker))
    }

    fn startup_failure(self, error: NodeSmartHttpRefusal) -> NodeSmartHttpRefusal {
        match self.finish() {
            Ok(_) => error,
            Err(cleanup) => io_error(
                "drain index maintenance after startup failure",
                io::Error::other(format!("{error}; {cleanup}")),
            ),
        }
    }

    pub(super) fn finished(&self) -> bool {
        self.children
            .iter()
            .any(|child| child.finished.load(Ordering::Acquire))
    }

    pub(super) fn request_stop(&mut self) {
        // Signal every sibling before joining any. A child still waiting on
        // readiness must also be released, without authorizing its first pass.
        for child in &mut self.children {
            child.request_stop();
        }
    }

    pub(super) fn activate(&mut self) -> Result<(), NodeSmartHttpRefusal> {
        for child in &mut self.children {
            if let Some(launch) = child.launch.take()
                && launch.send(()).is_err()
            {
                self.request_stop();
                return Err(io_error(
                    "activate source index maintenance",
                    io::Error::other("maintenance child left before HTTP readiness"),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<Vec<MaintenanceReceipt>, NodeSmartHttpRefusal> {
        self.request_stop();
        let mut receipts = Vec::with_capacity(self.children.len());
        let mut failure: Option<NodeSmartHttpRefusal> = None;
        for child in std::mem::take(&mut self.children) {
            match child.finish() {
                Ok(receipt) => receipts.push(receipt),
                Err(error) => {
                    failure = Some(match failure {
                        Some(previous) => io_error(
                            "drain multiple index maintenance children",
                            io::Error::other(format!("{previous}; {error}")),
                        ),
                        None => error,
                    });
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(receipts),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Normal paths consume every result through finish. This backstop
        // still stops all siblings before any Child destructor may join.
        self.request_stop();
    }
}

pub(super) fn startup_stop(probe: Option<&dyn Fn() -> io::Result<bool>>) -> io::Result<bool> {
    probe.map_or(Ok(false), |probe| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(probe))
            .unwrap_or_else(|_| Err(io::Error::other("HTTP startup stop callback panicked")))
    })
}

impl Child {
    fn start(
        node: &OneNode,
        config: MaintenanceConfig,
    ) -> Result<(Self, Receiver<()>), NodeSmartHttpRefusal> {
        let node_config = node
            .service_config
            .clone()
            .with_expected_repository_incarnation(node.repository_incarnation_id());
        let control = MaintenanceControl::default();
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
                        io::Error::other("HTTP maintenance owner left before readiness")
                    })?;
                    match launched.recv() {
                        Ok(()) => Ok(()),
                        Err(_) if gate_control.is_stop_requested() => Ok(()),
                        Err(_) => Err(io::Error::other(
                            "HTTP maintenance startup owner left before readiness",
                        )),
                    }
                })
                .map_err(|error| error.to_string());
                // Bounded channels retain the terminal observation even when
                // acceptance is busy; no callback borrows the listener thread.
                let _ = outcome_sender.send(result);
            })
            .map_err(|error| {
                io_error(
                    "schedule source index maintenance",
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
        Ok((worker, ready))
    }

    fn request_stop(&mut self) {
        self.control.request_stop();
        drop(self.launch.take());
    }

    fn finish(mut self) -> Result<MaintenanceReceipt, NodeSmartHttpRefusal> {
        self.request_stop();
        if let Some(join) = self.join.take() {
            join();
        }
        self.outcome
            .recv()
            .map_err(|_| {
                io_error(
                    "join source index maintenance",
                    io::Error::other("maintenance child exited without a terminal observation"),
                )
            })?
            .map_err(|error| io_error("drain source index maintenance", io::Error::other(error)))
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        // Unwinding is a backstop only. Normal startup failures, stop requests,
        // listener errors and completed services all call finish explicitly.
        self.request_stop();
        if let Some(join) = self.join.take() {
            join();
        }
    }
}

impl OneNode {
    /// Serve source queries while runtime-owned controllers maintain the
    /// explicitly configured references. Existing indexes remain derived state.
    ///
    /// The readiness callback runs on the accepting thread only after exclusive
    /// progress ownership and repository authentication succeed. It must not
    /// block or panic. A controller failure retires acceptance and drains every
    /// child; ordinary bounded reconcile refusals stay in the retry loop.
    /// This enables source reads under the existing credential grant. It never
    /// grants remote index maintenance or changes repository authority.
    pub fn serve_repository_http_with_index_maintenance_bounded(
        &self,
        listener: &TcpListener,
        limits: GitDaemonServerLimits,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        idle_timeout: Duration,
        maintenance: impl Into<MaintenanceGroup>,
        on_ready: &dyn Fn() -> io::Result<()>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            limits.max_in_flight(),
            self.smart_http_credentials_source(credentials_file),
            RepositoryHttpServices::NONE
                .with(RepositoryHttpService::Receive, allow_receive)
                .with(RepositoryHttpService::Issues, allow_issues)
                .with(RepositoryHttpService::Outcomes, allow_outcomes)
                .with(RepositoryHttpService::Pulls, allow_pulls)
                .with(RepositoryHttpService::Source, true),
            Acceptance::Bounded {
                max_sessions: limits.max_sessions(),
                idle_timeout,
            },
            Controllers {
                maintenance: Some(maintenance.into()),
                on_ready: Some(on_ready),
                ..Controllers::default()
            },
        )
    }

    /// Continuously serve with one or two progress owners and the same
    /// HTTP quotas for the whole lifetime. Stop requests cancel and drain the
    /// active maintenance attempt and join it alongside accepted requests
    /// before this method returns.
    pub fn serve_repository_http_with_index_maintenance_until_stopped(
        &self,
        listener: &TcpListener,
        max_in_flight: usize,
        credentials_file: &Path,
        allow_receive: bool,
        allow_issues: bool,
        allow_outcomes: bool,
        allow_pulls: bool,
        maintenance: impl Into<MaintenanceGroup>,
        should_stop: &dyn Fn() -> io::Result<bool>,
        on_ready: &dyn Fn() -> io::Result<()>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            max_in_flight,
            self.smart_http_credentials_source(credentials_file),
            RepositoryHttpServices::NONE
                .with(RepositoryHttpService::Receive, allow_receive)
                .with(RepositoryHttpService::Issues, allow_issues)
                .with(RepositoryHttpService::Outcomes, allow_outcomes)
                .with(RepositoryHttpService::Pulls, allow_pulls)
                .with(RepositoryHttpService::Source, true),
            Acceptance::UntilStopped(should_stop),
            Controllers {
                maintenance: Some(maintenance.into()),
                on_ready: Some(on_ready),
                ..Controllers::default()
            },
        )
    }
}
