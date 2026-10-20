//! A signal observer owned by the same runtime as a foreground request.
//! Synchronous workflow steps cannot poll a companion future on their caller's
//! thread. One bounded blocking-pool child relays signals to a derived local
//! context instead, without cancelling the native root needed for settlement.

use super::TerminationSignals;
use crate::NodeRequestContext;
use asupersync::runtime::BlockingTaskHandle;
use fgit_runtime::NodeRuntime;
use fsqlite_types::cx::CancelReason;
use std::io;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MONITOR_TIMEOUT: Duration = Duration::from_secs(5);

/// Owns signal observation and a cancellation-scoped foreground request.
/// Call `finish` after the operation settles and before shutting down its node.
/// Dropping this value only provides a bounded best-effort cleanup backstop.
#[must_use]
struct TerminationRequest {
    request: NodeRequestContext,
    stop: Option<Sender<()>>,
    completed: Receiver<()>,
    task: BlockingTaskHandle,
    finished: bool,
}

impl NodeRequestContext {
    /// Observe cooperative request liveness, charging the existing runtime
    /// checkpoint budget. A false result stops NEW work; callers still own
    /// non-cancellable drain/finalization and cannot infer transaction rollback.
    pub fn checkpoint_is_live(&self) -> bool {
        matches!(
            crate::checkpoint_pack_context(self.authority()),
            crate::PackContextCheckpoint::Live
        )
    }
}

impl TerminationSignals {
    /// Bind explicitly installed process signals to one derived request.
    ///
    /// The callback must settle its request effects before returning. Its result
    /// is returned separately from observer cleanup, so a cleanup error cannot
    /// erase a persisted workflow report. The observer always joins afterward.
    /// Signal cancellation never cancels the parent's native runtime context.
    /// A monitor that cannot start refuses before the caller may execute work.
    pub fn run_request<T>(
        self,
        runtime: &NodeRuntime,
        parent: &NodeRequestContext,
        work: impl FnOnce(&NodeRequestContext) -> T,
    ) -> io::Result<(T, io::Result<()>)> {
        let owner = bind(runtime, parent, move || self.requested())?;
        let result = work(owner.request());
        Ok((result, owner.finish()))
    }
}

fn bind(
    runtime: &NodeRuntime,
    parent: &NodeRequestContext,
    requested: impl Fn() -> bool + Send + 'static,
) -> io::Result<TerminationRequest> {
    let (authority, cancellation) = parent.authority().create_child_with_local_cancel_relay();
    let (stop, stopped) = mpsc::channel();
    let (ready, started) = mpsc::sync_channel(1);
    let (complete, completed) = mpsc::sync_channel(1);
    let task = runtime
        .submit_blocking(move || {
            let mut cancelled = requested();
            if cancelled {
                let _ = cancellation.cancel_local(CancelReason::UserInterrupt);
            }
            if ready.send(()).is_err() {
                return;
            }
            loop {
                match stopped.recv_timeout(POLL_INTERVAL) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                }
                if !cancelled && requested() {
                    let _ = cancellation.cancel_local(CancelReason::UserInterrupt);
                    cancelled = true;
                }
            }
            // Keep signal subscriptions alive through operation settlement.
            drop(requested);
            let _ = complete.send(());
        })
        .map_err(io::Error::other)?;
    let mut owner = TerminationRequest {
        request: NodeRequestContext { authority },
        stop: Some(stop),
        completed,
        task,
        finished: false,
    };
    if owner.task.is_cancelled() || started.recv_timeout(MONITOR_TIMEOUT).is_err() {
        let cleanup = owner.finish_inner();
        return Err(io::Error::other(match cleanup {
            Ok(()) => "workflow signal monitor did not start; no workflow admitted".to_owned(),
            Err(error) => {
                format!("workflow signal monitor did not start: {error}; no workflow admitted")
            }
        }));
    }
    Ok(owner)
}

impl TerminationRequest {
    #[must_use]
    pub const fn request(&self) -> &NodeRequestContext {
        &self.request
    }

    /// Stop and join the observer without interpreting cancellation as rollback.
    /// Completion of the workflow and completion of this owner are independent:
    /// callers retain the original report even when observer cleanup fails.
    pub fn finish(mut self) -> io::Result<()> {
        self.finish_inner()
    }

    fn finish_inner(&mut self) -> io::Result<()> {
        self.finished = true;
        drop(self.stop.take());
        // This skips a still-queued child; it never kills a running observer.
        self.task.cancel();
        if !self.task.wait_timeout(MONITOR_TIMEOUT) {
            return Err(io::Error::other("workflow signal monitor did not drain"));
        }
        self.completed.try_recv().map_err(|_| {
            io::Error::other("workflow signal monitor stopped without acknowledging cleanup")
        })
    }
}

impl Drop for TerminationRequest {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish_inner();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_runtime::RuntimeProfile;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    fn setup() -> (NodeRuntime, NodeRequestContext) {
        let runtime = RuntimeProfile::verification().build().unwrap();
        let parent = NodeRequestContext {
            authority: crate::authority_context_for(&runtime),
        };
        (runtime, parent)
    }

    #[test]
    fn public_request_checkpoint_observes_local_stop_without_cancelling_parent() {
        let (runtime, parent) = setup();
        assert!(parent.checkpoint_is_live());
        let owner = bind(&runtime, &parent, || true).unwrap();
        assert!(!owner.request().checkpoint_is_live());
        owner.finish().unwrap();
        assert!(parent.checkpoint_is_live());
        parent.cancel();
        assert!(!parent.checkpoint_is_live());
        assert!(runtime.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn an_armed_signal_cancels_only_the_derived_request_and_drains() {
        let (runtime, parent) = setup();
        let sibling = parent.authority().create_child();
        let owner = bind(&runtime, &parent, || true).unwrap();
        assert_eq!(
            owner.request().authority().cancel_reason(),
            Some(CancelReason::UserInterrupt)
        );
        assert_eq!(parent.authority().cancel_reason(), None);
        assert_eq!(sibling.cancel_reason(), None);
        owner.finish().unwrap();
        assert!(runtime.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn a_signal_during_synchronous_work_reaches_the_request() {
        let (runtime, parent) = setup();
        let stop = Arc::new(AtomicBool::new(false));
        let probe = Arc::clone(&stop);
        let owner = bind(&runtime, &parent, move || probe.load(Ordering::Acquire)).unwrap();
        assert_eq!(owner.request().authority().cancel_reason(), None);
        stop.store(true, Ordering::Release);
        let until = Instant::now() + Duration::from_secs(2);
        while owner.request().authority().cancel_reason().is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            owner.request().authority().cancel_reason(),
            Some(CancelReason::UserInterrupt)
        );
        assert_eq!(parent.authority().cancel_reason(), None);
        owner.finish().unwrap();
        assert!(runtime.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn no_signal_and_drop_backstop_leave_the_parent_usable() {
        let (runtime, parent) = setup();
        let owner = bind(&runtime, &parent, || false).unwrap();
        assert_eq!(owner.request().authority().cancel_reason(), None);
        owner.finish().unwrap();
        drop(bind(&runtime, &parent, || false).unwrap());
        assert_eq!(parent.authority().cancel_reason(), None);
        assert!(runtime.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn inherited_cancellation_is_not_cleared_by_signal_binding() {
        let (runtime, parent) = setup();
        parent.cancel();
        let reason = parent.authority().cancel_reason();
        assert!(reason.is_some());
        let owner = bind(&runtime, &parent, || false).unwrap();
        assert_eq!(owner.request().authority().cancel_reason(), reason);
        owner.finish().unwrap();
        assert!(runtime.join_root(Duration::from_secs(5)));
    }
}
