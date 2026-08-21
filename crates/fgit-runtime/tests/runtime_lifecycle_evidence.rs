#![forbid(unsafe_code)]
//! Independent FG-011b lifecycle and cancellation evidence.
//!
//! These tests deliberately start `AppSpec` only on an owned
//! `LabRuntime::state`.  Asupersync 0.4.9 does not expose the production
//! runtime's `RuntimeState`, so this is evidence for the compiled supervisor
//! lifecycle and cancellation semantics, **not** a claim that `AppSpec` runs
//! on the production executor.  The `Cx` is nevertheless minted through
//! `NodeRuntime`'s production factory, never through a test-only constructor.
//!
//! The companion `live_outcomes` test covers the demo protocol under both
//! runtime profiles.  This file instead keeps the `AppSpec` non-claim explicit
//! while independently exercising the live-node drain boundary that is only
//! available with an owned runtime state.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Budget;
use asupersync::app::{AppHandle, AppSpec};
use asupersync::cx::{Cx, Scope};
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::region::RegionState;
use asupersync::runtime::{RuntimeState, SpawnError, yield_now};
use asupersync::supervision::ChildStart;
use asupersync::types::cancel::{CancelKind, CancelReason};
use asupersync::types::id::{RegionId, TaskId, Time};
use asupersync::types::policy::FailFast;

use fgit_runtime::boot::{ProfileClass, RuntimeProfile};
use fgit_runtime::grant::CapabilityProfile;
use fgit_runtime::meter::{BudgetClass, BudgetPolicy, derive_child};
use fgit_runtime::service::{LedgerService, ServiceLedger};
use fgit_runtime::topology::{NodeSpec, ServiceSpec};

const NOW: Time = Time::from_secs(0);
const LONG_RUNNING_STEPS: u64 = 10_000;
const START_STEPS: u32 = 16;

/// An `AppSpec` started on an owned Lab `RuntimeState`.
///
/// Keeping the production runtime alive is necessary because it owns the
/// production-minted context that the supervisor receives at start.
struct StartedApp {
    _node: fgit_runtime::NodeRuntime,
    runtime: LabRuntime,
    app: AppHandle,
}

/// Build the smallest complete node around one supplied service start body.
fn one_service_app(start: Box<dyn ChildStart>) -> AppSpec {
    let policy = BudgetPolicy::finite_defaults();
    let mut start = Some(start);
    NodeSpec::new("fg011b-evidence", policy)
        .service(ServiceSpec::new(
            "ledger",
            BudgetClass::Request,
            CapabilityProfile::node_root(),
        ))
        .to_app_spec(NOW, |_| {
            start
                .take()
                .expect("the one-service fixture starts exactly one child")
        })
        .expect("the one-service evidence topology is valid")
}

/// Start the supplied `AppSpec` and schedule every supervisor-created child.
fn start_app(app_spec: AppSpec) -> StartedApp {
    let profile = RuntimeProfile::deterministic();
    let identity = profile.identity();
    assert_eq!(identity.class, ProfileClass::Deterministic);
    assert_eq!(identity.asupersync_version, "0.4.9");
    assert_eq!(identity.worker_threads, 1);
    assert!(!identity.enable_parking);
    assert_eq!(identity.leak_policy, "fail_fast");
    assert!(!identity.unbounded_root);

    let node = profile.build().expect("the fixed evidence profile builds");
    let cx = node.request_cx(BudgetClass::NodeRoot);
    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let app = app_spec
        .start(&mut runtime.state, &cx, root)
        .expect("the compiled AppSpec starts on its owned RuntimeState");

    let tasks: Vec<TaskId> = app
        .supervisor()
        .started
        .iter()
        .map(|child| child.task_id)
        .collect();
    assert_eq!(tasks.len(), 1, "the fixture owns one live child task");
    {
        let mut scheduler = runtime.scheduler.lock();
        for task in tasks {
            scheduler.schedule(task, 0);
        }
    }

    StartedApp {
        _node: node,
        runtime,
        app,
    }
}

/// Drive the explicit request -> drain -> finalize shutdown protocol.
fn drive_shutdown(runtime: &mut LabRuntime, app_region: RegionId) {
    for _ in 0..8 {
        let effects = runtime.state.cancel_request(
            app_region,
            &CancelReason::new(CancelKind::Shutdown),
            None,
        );
        let (to_cancel, _) = effects.into_parts();
        {
            let mut scheduler = runtime.scheduler.lock();
            for (task, priority) in to_cancel {
                scheduler.schedule_cancel(task, priority);
            }
        }
        runtime.run_until_quiescent();
        runtime.state.advance_region_state(app_region);
        if runtime
            .state
            .region(app_region)
            .is_none_or(|region| region.state() == RegionState::Closed)
        {
            return;
        }
    }

    panic!("request -> drain -> finalize did not close region {app_region:?}");
}

/// Counters showing which context actually observed a cancellation.
#[derive(Debug, Default)]
struct ContextProbe {
    started: AtomicU64,
    task_context_cancelled: AtomicU64,
    supervisor_context_cancelled: AtomicU64,
    task_context_missing: AtomicU64,
    checkpoints: AtomicU64,
}

/// A planted negative that retains the supervisor's `Cx` inside its child.
///
/// It also checks the task's `Cx::current()` so it can exit cleanly after
/// recording the comparison.  The asserted result is the critical negative:
/// the supervisor context does *not* observe the child-region cancellation,
/// whereas the task-owned current context does.
#[derive(Debug)]
struct SupervisorCxNegative {
    probe: Arc<ContextProbe>,
    budget: Budget,
}

impl SupervisorCxNegative {
    const fn new(probe: Arc<ContextProbe>, budget: Budget) -> Self {
        Self { probe, budget }
    }
}

impl ChildStart for SupervisorCxNegative {
    fn start(
        &mut self,
        scope: &Scope<'static, FailFast>,
        state: &mut RuntimeState,
        supervisor_cx: &Cx,
    ) -> Result<TaskId, SpawnError> {
        let probe = Arc::clone(&self.probe);
        let supervisor_cx = supervisor_cx.clone();
        let (task, _) = state.create_task(scope.region_id(), self.budget, async move {
            probe.started.fetch_add(1, Ordering::AcqRel);
            loop {
                // This is the deliberately wrong shape. It compiles, but the
                // supervisor's context is not the spawned task's context.
                if supervisor_cx.checkpoint().is_err() {
                    probe
                        .supervisor_context_cancelled
                        .fetch_add(1, Ordering::AcqRel);
                    return;
                }

                let Some(task_cx) = Cx::current() else {
                    probe.task_context_missing.fetch_add(1, Ordering::AcqRel);
                    return;
                };
                if task_cx.checkpoint().is_err() {
                    probe.task_context_cancelled.fetch_add(1, Ordering::AcqRel);
                    return;
                }
                probe.checkpoints.fetch_add(1, Ordering::AcqRel);
                yield_now().await;
            }
        })?;
        Ok(task)
    }
}

fn request_budget() -> Budget {
    let policy = BudgetPolicy::finite_defaults();
    derive_child(
        policy.budget_at(NOW, BudgetClass::NodeRoot),
        policy.budget_at(NOW, BudgetClass::Request),
    )
    .expect("the request budget is a finite child of the node root")
}

#[test]
fn live_ledger_service_drains_before_its_long_work_completes() {
    let ledger = Arc::new(ServiceLedger::new());
    let service = LedgerService::new(Arc::clone(&ledger), LONG_RUNNING_STEPS, request_budget());
    let mut started = start_app(one_service_app(service.into_child_start()));

    for _ in 0..START_STEPS {
        started.runtime.step_for_test();
    }
    assert_eq!(ledger.started(), 1, "the real child must have started");
    assert!(
        ledger.steps() > 0 && ledger.steps() < LONG_RUNNING_STEPS,
        "the child must be mid-flight before cancellation, got {} steps",
        ledger.steps()
    );
    assert_eq!(
        ledger.completed(),
        0,
        "the long-running child must still be live"
    );

    let region = started.app.root_region();
    started
        .app
        .stop(&mut started.runtime.state)
        .expect("the node accepts its stop request");
    drive_shutdown(&mut started.runtime, region);

    assert!(started.app.is_stopped(&started.runtime.state));
    assert!(
        started.app.is_quiescent(&started.runtime.state),
        "a cancelled child must not leave tasks or obligations behind"
    );
    assert_eq!(
        ledger.completed(),
        0,
        "drain must interrupt the child rather than wait for all {LONG_RUNNING_STEPS} steps"
    );
}

#[test]
fn supervisor_cx_is_a_planted_negative_for_child_cancellation() {
    let probe = Arc::new(ContextProbe::default());
    let negative = SupervisorCxNegative::new(Arc::clone(&probe), request_budget());
    let mut started = start_app(one_service_app(Box::new(negative)));

    for _ in 0..START_STEPS {
        started.runtime.step_for_test();
    }
    assert_eq!(probe.started.load(Ordering::Acquire), 1);
    assert!(
        probe.checkpoints.load(Ordering::Acquire) > 0,
        "the child must have reached its task-owned checkpoint before cancellation"
    );

    let region = started.app.root_region();
    started
        .app
        .stop(&mut started.runtime.state)
        .expect("the node accepts its stop request");
    drive_shutdown(&mut started.runtime, region);

    assert_eq!(
        probe.supervisor_context_cancelled.load(Ordering::Acquire),
        0,
        "the supervisor Cx must not masquerade as the child cancellation context"
    );
    assert_eq!(
        probe.task_context_missing.load(Ordering::Acquire),
        0,
        "the runtime must install a task-owned Cx while polling the child"
    );
    assert_eq!(
        probe.task_context_cancelled.load(Ordering::Acquire),
        1,
        "only Cx::current() inside the child observes its cancellation"
    );
    assert!(started.app.is_quiescent(&started.runtime.state));
}
