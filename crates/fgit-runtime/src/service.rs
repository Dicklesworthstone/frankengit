//! One real demonstration service, and the ledger that proves it ran.
//!
//! Everything else in this crate describes how a node *would* run: budget
//! classes, capability profiles, a compiled start order, a shutdown sequence.
//! None of that is evidence that a service ever started. A topology that
//! compiles and a topology that runs are different claims, and an independent
//! audit of this crate found exactly that gap — [`NodeSpec::to_app_spec`]
//! produced a supervisor spec whose start bodies had never once been asked to
//! start anything.
//!
//! [`NodeSpec::to_app_spec`]: crate::topology::NodeSpec::to_app_spec
//!
//! This module closes that gap with a service that does real work under the
//! supervisor: it is spawned as a genuine runtime task inside the region the
//! supervisor created for it, it advances across real await points so the
//! scheduler can interleave it with its siblings, and it records what it did
//! in a [`ServiceLedger`] the caller can read afterwards.
//!
//! # Why a ledger rather than a return value
//!
//! A supervised child is started for its effects, not for a value handed back
//! to whoever compiled the topology: the supervisor owns the task, and
//! [`ChildStart::start`] may only return a [`TaskId`]. So the observable
//! evidence that a service ran has to live somewhere both the service and the
//! test can see. The ledger is that place, and its counters are the reason a
//! start assertion can fail: a service that never started leaves
//! [`ServiceLedger::started`] at zero, and no amount of successful *compiling*
//! moves it.
//!
//! # What this service is not
//!
//! It is a demonstration of the lifecycle, not of `FrankenGit` semantics. It
//! moves a counter; it does not publish an authority head, serve a protocol
//! request, or touch an object store. Those services belong to the crates that
//! own those subsystems, and they will supply their own start bodies to the
//! same [`to_app_spec`](crate::topology::NodeSpec::to_app_spec) seam. What is
//! shared, and what this module exists to prove, is the seam itself.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Budget;
use asupersync::cx::Cx;
use asupersync::cx::Scope;
use asupersync::runtime::{RuntimeState, SpawnError, yield_now};
use asupersync::supervision::ChildStart;
use asupersync::types::id::TaskId;
use asupersync::types::policy::FailFast;

/// What a service actually did, recorded where an observer can read it.
///
/// Counters are separate rather than a single "progress" number because they
/// answer different questions and a sum would erase the distinction: a service
/// that started and stalled, and one that never started, both have zero
/// completions but only one of them has a start.
#[derive(Debug, Default)]
pub struct ServiceLedger {
    started: AtomicU64,
    steps: AtomicU64,
    completed: AtomicU64,
}

impl ServiceLedger {
    /// A ledger with every counter at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            started: AtomicU64::new(0),
            steps: AtomicU64::new(0),
            completed: AtomicU64::new(0),
        }
    }

    /// How many times a start body ran to the point of spawning its task.
    #[must_use]
    pub fn started(&self) -> u64 {
        self.started.load(Ordering::Acquire)
    }

    /// How many units of work the service body advanced through.
    #[must_use]
    pub fn steps(&self) -> u64 {
        self.steps.load(Ordering::Acquire)
    }

    /// How many times the service body reached its own final statement.
    ///
    /// A service that was cancelled mid-flight increments [`steps`](Self::steps)
    /// but never this, which is what makes cancellation observable rather than
    /// merely assumed.
    #[must_use]
    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::Acquire)
    }

    fn record_start(&self) {
        self.started.fetch_add(1, Ordering::AcqRel);
    }

    fn record_step(&self) {
        self.steps.fetch_add(1, Ordering::AcqRel);
    }

    fn record_completion(&self) {
        self.completed.fetch_add(1, Ordering::AcqRel);
    }
}

/// A supervised service that performs a bounded amount of real work.
///
/// The work is deliberately trivial; what is not trivial is that it happens
/// inside a supervisor-created region, on a task the supervisor owns, across
/// await points the scheduler chooses. Those are the properties the profile
/// claims, and this is the type that exercises them.
#[derive(Debug, Clone)]
pub struct LedgerService {
    ledger: Arc<ServiceLedger>,
    steps: u64,
    budget: Budget,
}

impl LedgerService {
    /// A service that advances `steps` units of work under `budget`.
    ///
    /// `budget` is the child's own budget and must already be the result of
    /// [`derive_child`](crate::meter::derive_child) against the node root, so
    /// a service cannot be handed more than the node holds.
    #[must_use]
    pub const fn new(ledger: Arc<ServiceLedger>, steps: u64, budget: Budget) -> Self {
        Self {
            ledger,
            steps,
            budget,
        }
    }

    /// The ledger this service writes to.
    #[must_use]
    pub const fn ledger(&self) -> &Arc<ServiceLedger> {
        &self.ledger
    }

    /// A boxed start body for [`NodeSpec::to_app_spec`].
    ///
    /// [`NodeSpec::to_app_spec`]: crate::topology::NodeSpec::to_app_spec
    #[must_use]
    pub fn into_child_start(self) -> Box<dyn ChildStart> {
        Box::new(self)
    }
}

impl ChildStart for LedgerService {
    /// Spawn the service body as a real task in the supervisor's region.
    ///
    /// The task is created against `scope.region_id()` — the region the
    /// supervisor made for this child — rather than against a region of this
    /// crate's choosing, so cancelling the app cancels this service through
    /// the ordinary region path instead of through a side channel.
    fn start(
        &mut self,
        scope: &Scope<'static, FailFast>,
        state: &mut RuntimeState,
        _cx: &Cx,
    ) -> Result<TaskId, SpawnError> {
        let ledger = Arc::clone(&self.ledger);
        let steps = self.steps;

        let (task_id, _handle) = state.create_task(scope.region_id(), self.budget, async move {
            ledger.record_start();
            for _ in 0..steps {
                // A real await point: the scheduler may run a sibling here,
                // which is what makes the start order observable rather than
                // an artifact of everything completing synchronously.
                yield_now().await;
                ledger.record_step();
            }
            ledger.record_completion();
        })?;

        Ok(task_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_ledger_reads_zero_everywhere() {
        let ledger = ServiceLedger::new();
        assert_eq!(ledger.started(), 0);
        assert_eq!(ledger.steps(), 0);
        assert_eq!(ledger.completed(), 0);
    }

    #[test]
    fn the_counters_are_independent() {
        // A sum would make "started but stalled" indistinguishable from
        // "never started", which is the distinction the ledger exists for.
        let ledger = ServiceLedger::new();
        ledger.record_start();
        ledger.record_step();
        ledger.record_step();

        assert_eq!(ledger.started(), 1);
        assert_eq!(ledger.steps(), 2);
        assert_eq!(ledger.completed(), 0);
    }

    #[test]
    fn a_service_exposes_the_ledger_it_was_built_with() {
        let ledger = Arc::new(ServiceLedger::new());
        let service = LedgerService::new(Arc::clone(&ledger), 3, Budget::INFINITE);

        ledger.record_start();
        assert_eq!(service.ledger().started(), 1);
    }
}
