//! A service owns a bounded group of existing durable index controllers.
//! Progress authentication and ownership complete before any child may build.
//! Every return requests stop and releases launch gates before joining children.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::Duration;

use crate::OneNode;
use crate::index_maintenance::{
    MaintenanceConfig, MaintenanceControl, MaintenanceGroup, MaintenanceReceipt,
    run_service_with_ready,
};

/// Owned background maintenance for a locally configured service. Remote reads
/// never create this owner or grant it authority. Call `finish` before shutting
/// down the parent node; `Drop` is a stop/join backstop, not a cleanup receipt.
#[must_use = "the owner must stop and join every index maintenance child"]
pub struct SourceIndexService {
    children: Vec<Child>,
    control: MaintenanceControl,
}

struct Child {
    control: MaintenanceControl,
    finished: Arc<AtomicBool>,
    join: Option<Box<dyn FnOnce()>>,
    launch: Option<SyncSender<()>>,
    outcome: Receiver<Result<MaintenanceReceipt, String>>,
}

struct Completion {
    finished: Arc<AtomicBool>,
    control: MaintenanceControl,
}
impl Drop for Completion {
    fn drop(&mut self) {
        // An idle synchronous client need not poll its owner to stop siblings.
        // A terminal child, including unwinding, stops the whole configured group.
        self.control.request_stop();
        self.finished.store(true, Ordering::Release);
    }
}

impl SourceIndexService {
    /// Authenticate and lock every configured progress owner while holding all
    /// first-attempt launch gates. A stop callback may cancel startup. No index
    /// work runs until `activate`; failed startup drains every acquired child.
    /// The parent runtime must reserve room for all children and one request.
    pub fn start(
        node: &OneNode,
        group: MaintenanceGroup,
        should_stop: Option<&dyn Fn() -> io::Result<bool>>,
    ) -> io::Result<Option<Self>> {
        validate_capacity(
            node.runtime().identity().blocking_max_threads,
            group.configs().len(),
        )?;
        if node.cell_state() != crate::CellState::Serving {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bring the node into service before index maintenance",
            ));
        }
        if group
            .configs()
            .iter()
            .any(|config| config.format() != node.object_format())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "index maintenance object format differs from the authenticated node",
            ));
        }
        let mut worker = Self {
            children: Vec::with_capacity(group.configs().len()),
            control: MaintenanceControl::default(),
        };
        for config in group.into_configs() {
            match startup_stop(should_stop) {
                Ok(false) => {}
                Ok(true) => return worker.finish().map(|_| None),
                Err(error) => {
                    return Err(worker.startup_failure(service_error(
                        "poll service stop during index maintenance startup",
                        error,
                    )));
                }
            }
            let (child, ready) = match Child::start(node, config, worker.control.clone()) {
                Ok(child) => child,
                Err(error) => return Err(worker.startup_failure(error)),
            };
            worker.children.push(child);
            loop {
                match startup_stop(should_stop) {
                    Ok(false) => {}
                    Ok(true) => return worker.finish().map(|_| None),
                    Err(error) => {
                        return Err(worker.startup_failure(service_error(
                            "poll service stop during index maintenance startup",
                            error,
                        )));
                    }
                }
                match ready.recv_timeout(Duration::from_millis(10)) {
                    Ok(()) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err(worker.startup_failure(service_error(
                            "start source index maintenance",
                            io::Error::other("maintenance child stopped before readiness"),
                        )));
                    }
                }
            }
        }
        Ok(Some(worker))
    }

    fn startup_failure(self, error: io::Error) -> io::Error {
        match self.finish() {
            Ok(_) => error,
            Err(cleanup) => service_error(
                "drain index maintenance after startup failure",
                io::Error::other(format!("{error}; {cleanup}")),
            ),
        }
    }

    /// Whether any child has returned. A child exit also stops its siblings;
    /// callers must retire service admission and retain terminal results via `finish`.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.children
            .iter()
            .any(|child| child.finished.load(Ordering::Acquire))
    }

    /// Request stop on the original active contexts and release unactivated gates.
    /// This is irreversible and does not join; follow it with `finish`.
    pub fn request_stop(&mut self) {
        self.control.request_stop();
        // Signal every sibling before joining any. A child still waiting on
        // readiness must also be released, without authorizing its first pass.
        for child in &mut self.children {
            child.request_stop();
        }
    }

    /// Release the first-attempt gates after the transport acknowledges readiness.
    /// This does not promise that either persisted index is already current.
    pub fn activate(&mut self) -> io::Result<()> {
        if self.control.is_stop_requested() {
            self.request_stop();
            return Err(io::Error::other(
                "index maintenance stopped before activation",
            ));
        }
        for child in &mut self.children {
            if let Some(launch) = child.launch.take()
                && launch.send(()).is_err()
            {
                self.request_stop();
                return Err(service_error(
                    "activate source index maintenance",
                    io::Error::other("maintenance child left before service readiness"),
                ));
            }
        }
        Ok(())
    }

    /// Stop all children before joining any, preserving every cleanup failure.
    /// A receipt can retain an unresolved original candidate for guarded recovery.
    pub fn finish(mut self) -> io::Result<Vec<MaintenanceReceipt>> {
        self.request_stop();
        let mut receipts = Vec::with_capacity(self.children.len());
        let mut failure: Option<io::Error> = None;
        for child in std::mem::take(&mut self.children) {
            match child.finish() {
                Ok(receipt) => receipts.push(receipt),
                Err(error) => {
                    failure = Some(match failure {
                        Some(previous) => service_error(
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

impl Drop for SourceIndexService {
    fn drop(&mut self) {
        // Normal paths consume every result through finish. This backstop
        // still stops all siblings before any Child destructor may join.
        self.request_stop();
    }
}

pub(crate) fn startup_stop(probe: Option<&dyn Fn() -> io::Result<bool>>) -> io::Result<bool> {
    probe.map_or(Ok(false), |probe| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(probe))
            .unwrap_or_else(|_| Err(io::Error::other("service startup stop callback panicked")))
    })
}

impl Child {
    fn start(
        node: &OneNode,
        config: MaintenanceConfig,
        control: MaintenanceControl,
    ) -> io::Result<(Self, Receiver<()>)> {
        let node_config = node
            .service_config
            .clone()
            .with_expected_repository_incarnation(node.repository_incarnation_id());
        let child_control = control.clone();
        let gate_control = control.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let completion = Completion {
            finished: Arc::clone(&finished),
            control: control.clone(),
        };
        let (ready_sender, ready) = mpsc::sync_channel(1);
        let (launch, launched) = mpsc::sync_channel(1);
        let (outcome_sender, outcome) = mpsc::sync_channel(1);
        let task = node
            .runtime()
            .submit_blocking(move || {
                let _completion = completion;
                let result = run_service_with_ready(node_config, config, child_control, || {
                    ready_sender.send(()).map_err(|_| {
                        io::Error::other("index maintenance owner left before readiness")
                    })?;
                    match launched.recv() {
                        Ok(()) => Ok(()),
                        Err(_) if gate_control.is_stop_requested() => Ok(()),
                        Err(_) => Err(io::Error::other(
                            "index maintenance startup owner left before readiness",
                        )),
                    }
                })
                .map_err(|error| error.to_string());
                // Bounded channels retain the terminal observation even when
                // acceptance is busy; no callback borrows the listener thread.
                let _ = outcome_sender.send(result);
            })
            .map_err(|error| {
                service_error(
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

    fn finish(mut self) -> io::Result<MaintenanceReceipt> {
        self.request_stop();
        if let Some(join) = self.join.take() {
            join();
        }
        self.outcome
            .recv()
            .map_err(|_| {
                service_error(
                    "join source index maintenance",
                    io::Error::other("maintenance child exited without a terminal observation"),
                )
            })?
            .map_err(|error| {
                service_error("drain source index maintenance", io::Error::other(error))
            })
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

fn service_error(operation: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

fn validate_capacity(available: usize, controllers: usize) -> io::Result<()> {
    if controllers
        .checked_add(1)
        .is_none_or(|required| required > available)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "blocking pool must fit every index controller and one request worker",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
