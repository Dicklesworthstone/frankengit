//! The listener owns one maintenance child for its complete serving lifetime.
//! Readiness follows progress ownership; every return requests stop and joins.

use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use crate::index_maintenance::{
    MaintenanceConfig, MaintenanceControl, MaintenanceReceipt, run_service_with_ready,
};
use crate::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};

use super::{Controllers, NodeSmartHttpRefusal, io_error, lifetime::Acceptance};

pub(super) struct Worker {
    control: MaintenanceControl,
    finished: Arc<AtomicBool>,
    join: Option<Box<dyn FnOnce()>>,
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
        config: MaintenanceConfig,
    ) -> Result<Self, NodeSmartHttpRefusal> {
        let node_config = node
            .service_config
            .clone()
            .with_expected_repository_incarnation(node.repository_incarnation_id());
        let control = MaintenanceControl::default();
        let child_control = control.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let completion = Completion(Arc::clone(&finished));
        let (ready_sender, ready) = mpsc::sync_channel(1);
        let (outcome_sender, outcome) = mpsc::sync_channel(1);
        let task = node
            .runtime()
            .submit_blocking(move || {
                let _completion = completion;
                let result = run_service_with_ready(node_config, config, child_control, || {
                    ready_sender.send(()).map_err(|_| {
                        io::Error::other("HTTP maintenance owner left before readiness")
                    })
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
            outcome,
        };
        if ready.recv().is_err() {
            return match worker.finish() {
                Err(error) => Err(error),
                Ok(_) => Err(io_error(
                    "start source index maintenance",
                    io::Error::other("index maintenance stopped before readiness"),
                )),
            };
        }
        Ok(worker)
    }

    pub(super) fn finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    pub(super) fn request_stop(&self) {
        self.control.request_stop();
    }

    pub(super) fn finish(mut self) -> Result<MaintenanceReceipt, NodeSmartHttpRefusal> {
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

impl Drop for Worker {
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
    /// Serve source queries while one runtime-owned controller maintains the
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
        maintenance: MaintenanceConfig,
        on_ready: &dyn Fn() -> io::Result<()>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            limits.max_in_flight(),
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            allow_issues,
            allow_outcomes,
            allow_pulls,
            true,
            Acceptance::Bounded {
                max_sessions: limits.max_sessions(),
                idle_timeout,
            },
            Controllers {
                maintenance: Some(maintenance),
                on_ready: Some(on_ready),
                ..Controllers::default()
            },
        )
    }

    /// Continuously serve with one progress owner and controller and the same
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
        maintenance: MaintenanceConfig,
        should_stop: &dyn Fn() -> io::Result<bool>,
        on_ready: &dyn Fn() -> io::Result<()>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_smart_http_with_source_lifetime(
            listener,
            max_in_flight,
            self.smart_http_credentials_source(credentials_file),
            allow_receive,
            allow_issues,
            allow_outcomes,
            allow_pulls,
            true,
            Acceptance::UntilStopped(should_stop),
            Controllers {
                maintenance: Some(maintenance),
                on_ready: Some(on_ready),
                ..Controllers::default()
            },
        )
    }
}
