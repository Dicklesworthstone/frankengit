//! Accepted raw Git connections belong to the existing Asupersync blocking
//! pool, not detached OS threads. Every child settles before the listener exits.

use super::{GitDaemonSessionDeadline, NodeSmartHttpRefusal, invalid, io_error};
use crate::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode, PushQuota};
use fgit_types::cell::CellState;
use std::borrow::Borrow;
use std::io;
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

enum Acceptance<'a> {
    Bounded(usize),
    UntilStopped(&'a dyn Fn() -> io::Result<bool>),
}

impl Acceptance<'_> {
    fn keep_accepting(&self, accepted: usize) -> io::Result<bool> {
        match self {
            Self::Bounded(maximum) => Ok(accepted < *maximum),
            Self::UntilStopped(stop) => {
                let stopped =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stop()))
                        .map_err(|_| io::Error::other("guarded daemon stop control panicked"))??;
                if stopped {
                    return Ok(false);
                }
                if accepted == usize::MAX {
                    return Err(io::Error::other(
                        "guarded daemon lifetime counter exhausted",
                    ));
                }
                Ok(true)
            }
        }
    }
}

struct Pending {
    finished: Arc<AtomicBool>,
    join: Box<dyn FnOnce()>,
}
struct Completion {
    finished: Arc<AtomicBool>,
    completed: Arc<AtomicUsize>,
    refused: Arc<AtomicUsize>,
    success: bool,
}
impl Drop for Completion {
    fn drop(&mut self) {
        if self.success {
            self.completed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
        self.finished.store(true, Ordering::Release);
    }
}

impl OneNode {
    /// Bounded raw Git service using guarded receive admission and the existing
    /// upload engine. Like the legacy service, acceptance stops at max_sessions;
    /// idle waiting does not invent an earlier session limit. At most 16 children
    /// run concurrently. All accepted children are joined, even after scheduling
    /// or accept failure. This transport authenticates NO remote user: enabling
    /// its operator principal grants that identity to every connecting writer.
    ///
    /// Each child leases a node opened for this exact repository incarnation,
    /// re-authenticated and in service (profile section 3.3 pools connections
    /// per service rather than opening one per connection); a failed session's
    /// node is closed, not reused. Quotas are shared across children.
    /// Connection refusal/cleanup counts never establish whether a push committed.
    pub fn serve_guarded_git_daemon_bounded(
        &self,
        listener: &TcpListener,
        limits: GitDaemonServerLimits,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        if !(1..=1_000_000).contains(&limits.max_sessions()) {
            return Err(invalid("guarded daemon connection limits exceeded"));
        }
        self.serve_guarded_git_daemon_lifetime(
            listener,
            limits.max_in_flight(),
            Acceptance::Bounded(limits.max_sessions()),
        )
    }

    /// Serve until the owner requests stop, without a session-count or idle cap.
    ///
    /// The service owns this listener and closes it BEFORE joining accepted
    /// children. Peers arriving during drain therefore cannot queue on a live
    /// listener that will never accept them. Existing children retain their
    /// ingress, processing, response and cleanup bounds and their native outcome
    /// semantics; stopping never implies that an accepted push did not commit.
    /// One set of node lanes, quotas and writer gates spans the whole lifetime.
    ///
    /// `should_stop` runs on the accepting thread, including while every slot is
    /// occupied, and must be bounded and nonblocking. An error or unwinding panic
    /// closes acceptance and drains children before returning an error. A
    /// panic-abort build cannot recover an aborting callback.
    pub fn serve_guarded_git_daemon_until_stopped(
        &self,
        listener: TcpListener,
        max_in_flight: usize,
        should_stop: &dyn Fn() -> io::Result<bool>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        self.serve_guarded_git_daemon_lifetime(
            listener,
            max_in_flight,
            Acceptance::UntilStopped(should_stop),
        )
    }

    fn serve_guarded_git_daemon_lifetime<L: Borrow<TcpListener>>(
        &self,
        listener: L,
        max_in_flight: usize,
        acceptance: Acceptance<'_>,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        if self.cell_state() != CellState::Serving {
            return Err(invalid("guarded daemon requires a serving node"));
        }
        if !(1..=16).contains(&max_in_flight) {
            return Err(invalid("guarded daemon connection limits exceeded"));
        }
        let config = self
            .service_config
            .clone()
            .with_expected_repository_incarnation(self.repository_incarnation_id());
        let quota = Arc::new(PushQuota::default());
        let writers = Arc::new(crate::WriterGate::new(crate::MAX_CONCURRENT_WRITERS));
        let nodes = Arc::new(crate::node_lanes::NodeLanes::new(
            config,
            max_in_flight,
            "guarded daemon",
        ));
        let completed = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let mut pending: Vec<Pending> = Vec::new();
        let mut accepted = 0;
        let mut failure = None;
        listener
            .borrow()
            .set_nonblocking(true)
            .map_err(|e| io_error("configure guarded daemon listener", e))?;
        loop {
            let mut index = 0;
            while index < pending.len() {
                if pending[index].finished.load(Ordering::Acquire) {
                    (pending.swap_remove(index).join)();
                } else {
                    index += 1;
                }
            }
            match acceptance.keep_accepting(accepted) {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    failure = Some(io_error("poll guarded daemon service stop", error));
                    break;
                }
            }
            if pending.len() >= max_in_flight {
                self.runtime.wait_for(Duration::from_millis(1));
                continue;
            }
            let (stream, _) = match listener.borrow().accept() {
                Ok(connection) => connection,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.runtime.wait_for(Duration::from_millis(1));
                    continue;
                }
                Err(e) => {
                    failure = Some(io_error("accept guarded daemon connection", e));
                    break;
                }
            };
            accepted += 1;
            let finished = Arc::new(AtomicBool::new(false));
            let completion = Completion {
                finished: Arc::clone(&finished),
                completed: Arc::clone(&completed),
                refused: Arc::clone(&refused),
                success: false,
            };
            let nodes = Arc::clone(&nodes);
            let quota = Arc::clone(&quota);
            let writers = Arc::clone(&writers);
            // Queue delay counts against the same ingress deadline as socket work.
            let deadline = GitDaemonSessionDeadline::new(
                self.git_daemon_session_timeout,
                self.git_daemon_session_work_scaling,
            );
            let task = self.runtime.submit_blocking(move || {
                let mut completion = completion;
                // The pool logs why when it cannot supply a node.
                let Some(node) = nodes.lease() else {
                    return;
                };
                let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    node.serve_guarded_git_daemon_stream_in(
                        stream,
                        deadline,
                        Some(quota.as_ref()),
                        Some(writers.as_ref()),
                    )
                    .map(|_| ())
                }))
                .unwrap_or_else(|_| {
                    Err(io_error(
                        "guarded daemon child panicked; publication outcome may be unknown",
                        io::Error::other("native Git session panicked"),
                    ))
                });
                // Keep service and cleanup observations separate. Neither can
                // undo an outcome already published by the connection's session.
                // Only a node whose session succeeded goes back to the pool.
                let cleanup = if served.is_ok() {
                    nodes.restore(node)
                } else {
                    node.shutdown()
                };
                completion.success = served.is_ok() && cleanup.is_ok();
                if let Err(error) = served {
                    eprintln!("guarded daemon connection failed: {error}");
                }
                if let Err(error) = cleanup {
                    eprintln!("guarded daemon child cleanup failed: {error}");
                }
            });
            match task {
                Ok(task) => pending.push(Pending {
                    finished,
                    join: Box::new(move || {
                        task.wait();
                    }),
                }),
                Err(error) => {
                    failure = Some(io_error(
                        "schedule guarded daemon connection",
                        std::io::Error::other(error.to_string()),
                    ));
                    break;
                }
            }
        }
        // The owned continuous listener closes before any potentially blocking
        // join. For a borrowed bounded listener this restores its prior contract
        // and releases only the borrow; the caller retains its socket.
        let restored = listener
            .borrow()
            .set_nonblocking(false)
            .map_err(|e| io_error("restore guarded daemon listener", e));
        drop(listener);
        for child in pending {
            (child.join)();
        }
        if let Err(error) = nodes.close() {
            eprintln!("guarded daemon could not close its pooled nodes: {error}");
            failure.get_or_insert_with(|| {
                io_error(
                    "close pooled guarded daemon nodes",
                    std::io::Error::other(error.to_string()),
                )
            });
        }
        if let Some(error) = failure {
            if let Err(cleanup) = restored {
                return Err(io_error(
                    "guarded daemon failed with listener cleanup failure",
                    std::io::Error::other(format!("{error}; {cleanup}")),
                ));
            }
            return Err(error);
        }
        restored?;
        let completed_sessions = completed.load(Ordering::Acquire);
        let refused_sessions = refused.load(Ordering::Acquire);
        if completed_sessions.checked_add(refused_sessions) != Some(accepted) {
            return Err(invalid(
                "guarded daemon did not settle every accepted child",
            ));
        }
        Ok(GitDaemonServerReceipt {
            accepted_sessions: accepted,
            completed_sessions,
            refused_sessions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn continuous_acceptance_survives_finite_limits_and_observes_the_stop_control() {
        let stopped = Cell::new(false);
        let stop = || Ok(stopped.get());
        let continuous = Acceptance::UntilStopped(&stop);
        for count in [0, 1, 1_000, 1_000_000, 1_000_001] {
            assert!(continuous.keep_accepting(count).unwrap());
        }
        stopped.set(true);
        assert!(!continuous.keep_accepting(1_000_001).unwrap());
        assert!(!continuous.keep_accepting(usize::MAX).unwrap());
        assert!(Acceptance::Bounded(1).keep_accepting(0).unwrap());
        assert!(!Acceptance::Bounded(1).keep_accepting(1).unwrap());
    }

    #[test]
    fn stop_errors_panics_and_counter_exhaustion_take_the_draining_error_path() {
        let error = || {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "control unreadable",
            ))
        };
        assert_eq!(
            Acceptance::UntilStopped(&error)
                .keep_accepting(0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let panic = || -> io::Result<bool> { panic!("planted stop failure") };
        assert!(Acceptance::UntilStopped(&panic).keep_accepting(0).is_err());
        let running = || Ok(false);
        assert!(
            Acceptance::UntilStopped(&running)
                .keep_accepting(usize::MAX - 1)
                .unwrap()
        );
        assert!(
            Acceptance::UntilStopped(&running)
                .keep_accepting(usize::MAX)
                .is_err()
        );
    }

    #[test]
    fn unwinding_a_child_settles_refusal_and_releases_its_completion_slot() {
        let finished = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let unwind = std::panic::catch_unwind({
            let finished = Arc::clone(&finished);
            let completed = Arc::clone(&completed);
            let refused = Arc::clone(&refused);
            move || {
                let _completion = Completion {
                    finished,
                    completed,
                    refused,
                    success: false,
                };
                panic!("planted child failure");
            }
        });
        assert!(unwind.is_err());
        assert!(finished.load(Ordering::Acquire));
        assert_eq!(completed.load(Ordering::Acquire), 0);
        assert_eq!(refused.load(Ordering::Acquire), 1);
        drop(Completion {
            finished,
            completed: Arc::clone(&completed),
            refused: Arc::clone(&refused),
            success: true,
        });
        assert_eq!(completed.load(Ordering::Acquire), 1);
        assert_eq!(refused.load(Ordering::Acquire), 1);
    }
}
