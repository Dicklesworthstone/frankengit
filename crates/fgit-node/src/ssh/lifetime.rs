//! Bounded child ownership and controlled acceptance for the SSH supervisor.

use super::{Arc, AtomicBool, AtomicUsize, NodeSshRefusal, Ordering, io};

pub(super) enum Acceptance<'a> {
    Bounded(usize),
    UntilStopped(&'a dyn Fn() -> io::Result<bool>),
}

impl Acceptance<'_> {
    pub(super) fn keep_accepting(&self, accepted: usize) -> Result<bool, NodeSshRefusal> {
        match self {
            Self::Bounded(max) => Ok(accepted < *max),
            Self::UntilStopped(should_stop) => {
                let stop = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| should_stop()))
                    .map_err(|_| {
                        NodeSshRefusal::StopControl(io::Error::other("SSH stop control panicked"))
                    })?
                    .map_err(NodeSshRefusal::StopControl)?;
                if stop {
                    return Ok(false);
                }
                if accepted == usize::MAX {
                    return Err(NodeSshRefusal::CounterExhausted);
                }
                Ok(true)
            }
        }
    }
}

pub(super) struct Pending {
    pub(super) finished: Arc<AtomicBool>,
    pub(super) join: Box<dyn FnOnce()>,
}

/// Scan only the bounded live set, including completions out of arrival order.
pub(super) fn reap(pending: &mut Vec<Pending>) {
    let mut index = 0;
    while index < pending.len() {
        if pending[index].finished.load(Ordering::Acquire) {
            let child = pending.swap_remove(index);
            (child.join)();
        } else {
            index += 1;
        }
    }
}

/// One guard is moved into each accepted child, before submission. A rejected
/// submission or unwinding child drops it just as a normally returning child
/// does, so capacity and receipt accounting cannot leak.
pub(super) struct Completion {
    pub(super) finished: Arc<AtomicBool>,
    pub(super) completed: Arc<AtomicUsize>,
    pub(super) refused: Arc<AtomicUsize>,
    pub(super) success: bool,
}

impl Drop for Completion {
    fn drop(&mut self) {
        // Each guard owns one checked acceptance. Neither counter can exceed
        // accepted, and acceptance refuses before its next increment overflows.
        let counter = if self.success {
            &self.completed
        } else {
            &self.refused
        };
        counter.fetch_add(1, Ordering::AcqRel);
        self.finished.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_compatibility_and_continuous_lifetime_have_distinct_limits() {
        let bounded = Acceptance::Bounded(1);
        assert!(bounded.keep_accepting(0).unwrap());
        assert!(!bounded.keep_accepting(1).unwrap());
        let continuous = Acceptance::UntilStopped(&|| Ok(false));
        for accepted in [0, 1, 1000, 1_000_001, usize::MAX - 1] {
            assert!(continuous.keep_accepting(accepted).unwrap());
        }
        assert!(matches!(
            continuous.keep_accepting(usize::MAX),
            Err(NodeSshRefusal::CounterExhausted)
        ));
        assert!(!Acceptance::UntilStopped(&|| Ok(true))
            .keep_accepting(usize::MAX)
            .unwrap());
    }

    #[test]
    fn control_errors_and_panics_are_refusals_not_successful_retirement() {
        assert!(matches!(
            Acceptance::UntilStopped(&|| Err(io::Error::other("control failed")))
                .keep_accepting(0),
            Err(NodeSshRefusal::StopControl(_))
        ));
        assert!(matches!(
            Acceptance::UntilStopped(&|| panic!("control panic")).keep_accepting(0),
            Err(NodeSshRefusal::StopControl(_))
        ));
        assert!(!Acceptance::UntilStopped(&|| Ok(true))
            .keep_accepting(0)
            .unwrap());
    }

    #[test]
    fn completion_settles_once_on_success_refusal_unwind_and_unscheduled_drop() {
        let completed = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));
        let guard = |success| Completion {
            finished: Arc::new(AtomicBool::new(false)),
            completed: Arc::clone(&completed),
            refused: Arc::clone(&refused),
            success,
        };
        let successful = guard(true);
        let success_finished = Arc::clone(&successful.finished);
        drop(successful);
        assert!(success_finished.load(Ordering::Acquire));
        let refusal = guard(false);
        let refusal_finished = Arc::clone(&refusal.finished);
        drop(refusal);
        assert!(refusal_finished.load(Ordering::Acquire));

        let unwinding = guard(false);
        let panic_finished = Arc::clone(&unwinding.finished);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _completion = unwinding;
            panic!("session panic");
        }))
        .is_err());
        assert!(panic_finished.load(Ordering::Acquire));

        let unscheduled = guard(false);
        let unscheduled_finished = Arc::clone(&unscheduled.finished);
        let submission = move || drop(unscheduled);
        drop(submission);
        assert!(unscheduled_finished.load(Ordering::Acquire));
        assert_eq!(completed.load(Ordering::Acquire), 1);
        assert_eq!(refused.load(Ordering::Acquire), 3);
    }

    #[test]
    fn finished_handles_are_reaped_out_of_order_and_never_accumulate() {
        let joined = Arc::new(AtomicUsize::new(0));
        let held = Arc::new(AtomicBool::new(false));
        let held_joined = Arc::clone(&joined);
        let mut pending = vec![Pending {
            finished: Arc::clone(&held),
            join: Box::new(move || {
                held_joined.fetch_add(1, Ordering::AcqRel);
            }),
        }];
        for _ in 0..200 {
            let child_joined = Arc::clone(&joined);
            pending.push(Pending {
                finished: Arc::new(AtomicBool::new(true)),
                join: Box::new(move || {
                    child_joined.fetch_add(1, Ordering::AcqRel);
                }),
            });
            reap(&mut pending);
            assert_eq!(pending.len(), 1);
        }
        assert_eq!(joined.load(Ordering::Acquire), 200);
        held.store(true, Ordering::Release);
        reap(&mut pending);
        assert!(pending.is_empty());
        assert_eq!(joined.load(Ordering::Acquire), 201);
    }
}
