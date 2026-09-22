//! Accepted raw Git connections belong to the existing Asupersync blocking
//! pool, not detached OS threads. Every child settles before the listener exits.

use super::{GitDaemonSessionDeadline, NodeSmartHttpRefusal, invalid, io_error};
use crate::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode, PushQuota};
use fgit_types::cell::CellState;
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

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
    /// Each child opens this exact repository incarnation, authenticates current
    /// authority, and explicitly enters service. Quotas are shared across children.
    /// Connection refusal/cleanup counts never establish whether a push committed.
    pub fn serve_guarded_git_daemon_bounded(
        &self,
        listener: &TcpListener,
        limits: GitDaemonServerLimits,
    ) -> Result<GitDaemonServerReceipt, NodeSmartHttpRefusal> {
        if self.cell_state() != CellState::Serving {
            return Err(invalid("guarded daemon requires a serving node"));
        }
        if !(1..=16).contains(&limits.max_in_flight())
            || !(1..=1_000_000).contains(&limits.max_sessions())
        {
            return Err(invalid("guarded daemon connection limits exceeded"));
        }
        let config = self
            .service_config
            .clone()
            .with_expected_repository_incarnation(self.repository_incarnation_id());
        let quota = Arc::new(PushQuota::default());
        let completed = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let mut pending: Vec<Pending> = Vec::new();
        let mut accepted = 0;
        let mut failure = None;
        listener
            .set_nonblocking(true)
            .map_err(|e| io_error("configure guarded daemon listener", e))?;
        while accepted < limits.max_sessions() {
            let mut index = 0;
            while index < pending.len() {
                if pending[index].finished.load(Ordering::Acquire) {
                    (pending.swap_remove(index).join)();
                } else {
                    index += 1;
                }
            }
            if pending.len() >= limits.max_in_flight() {
                self.runtime.wait_for(Duration::from_millis(1));
                continue;
            }
            let (stream, _) = match listener.accept() {
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
            let config = config.clone();
            let quota = Arc::clone(&quota);
            // Queue delay counts against the same ingress deadline as socket work.
            let deadline = GitDaemonSessionDeadline::new(
                self.git_daemon_session_timeout,
                self.git_daemon_session_work_scaling,
            );
            let task = self.runtime.submit_blocking(move || {
                let mut completion = completion;
                let mut node = match OneNode::open_existing(config) {
                    Ok(node) => node,
                    Err(error) => {
                        eprintln!("guarded daemon child open failed: {error}");
                        return;
                    }
                };
                let served: Result<(), NodeSmartHttpRefusal> = (|| {
                    let selected = node
                        .runtime()
                        .block_on(node.authenticate_authority_head())
                        .map_err(|e| {
                            io_error(
                                "authenticate guarded daemon child",
                                std::io::Error::other(e.to_string()),
                            )
                        })?;
                    node.bring_into_service(selected.receipt().generation())
                        .map_err(|e| {
                            io_error(
                                "bring guarded daemon child into service",
                                std::io::Error::other(e.to_string()),
                            )
                        })?;
                    node.serve_guarded_git_daemon_stream_in(
                        stream,
                        deadline,
                        Some(quota.as_ref()),
                    )?;
                    Ok(())
                })();
                // Keep service and cleanup observations separate. Neither can
                // undo an outcome already published by the connection's session.
                let cleanup = node.shutdown();
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
        for child in pending {
            (child.join)();
        }
        let restored = listener
            .set_nonblocking(false)
            .map_err(|e| io_error("restore guarded daemon listener", e));
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
