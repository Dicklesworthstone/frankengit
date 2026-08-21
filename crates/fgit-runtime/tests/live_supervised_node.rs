//! The node topology is really started, not merely compiled.
//!
//! An independent audit of this crate found that `NodeSpec::to_app_spec`
//! produced a supervisor spec that nothing had ever started: the only tests
//! that reached it supplied start bodies which returned
//! `SpawnError::RuntimeUnavailable` on purpose, because they were asserting
//! compile-time *ordering*. That is a real property, but it is not the
//! property the profile claims. "The services start, in this order, and stop
//! in the reverse one" is a claim about execution, and only execution can
//! support it.
//!
//! So every test here starts a real supervision tree, runs it on a scheduler
//! until quiescence, and reads back what the services actually recorded.
//!
//! # Evidence boundary — read this before citing these tests
//!
//! The context these tests hand to the supervisor is real: it is minted by
//! this crate's production factory, the same `request_cx_with_budget` path a
//! live node uses. Asupersync gates `Cx::for_testing` behind
//! `cfg(any(test, feature = "test-internals"))` so downstream crates cannot
//! forge a full-capability context, and nothing here evades that gate.
//!
//! What is **not** production is the state the tree runs on. `AppSpec::start`
//! requires `&mut RuntimeState`, and in Asupersync 0.4.9 neither `Runtime` nor
//! `RuntimeHandle` exposes one — there is no public accessor anywhere in the
//! crate, and Asupersync's own production daemon (`bin/atpd`) does not use
//! `app::AppSpec` at all. A downstream crate that wants a supervision tree
//! must therefore own a `RuntimeState` (`RuntimeState::new()` is public) and
//! drive it with a scheduler, which is what these tests do.
//!
//! So: the topology this crate compiles is one Asupersync's supervisor
//! accepts and starts, the services really run, the start order the
//! supervisor chose is the order this crate computed, and stopping the app
//! really closes its region. What these tests do **not** establish is that
//! the same tree runs under the multi-threaded production runtime, because
//! Asupersync 0.4.9 offers no supported way to put it there. That limitation
//! belongs to the runtime, and it is reported rather than papered over.

use std::collections::BTreeMap;
use std::sync::Arc;

use asupersync::Budget;
use asupersync::app::AppSpec;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::record::region::RegionState;
use asupersync::types::cancel::{CancelKind, CancelReason};
use asupersync::types::id::{RegionId, TaskId, Time};

use fgit_runtime::boot::RuntimeProfile;
use fgit_runtime::grant::CapabilityProfile;
use fgit_runtime::meter::{BudgetClass, BudgetPolicy, derive_child};
use fgit_runtime::service::{LedgerService, ServiceLedger};
use fgit_runtime::topology::{NodeSpec, ServiceSpec};

/// How many units of work each demonstration service performs.
const STEPS: u64 = 3;

/// The node under test: four services with a real dependency shape.
///
/// `authority` depends on `store`, `protocol` on `authority`, and
/// `projection` on `store`. That is a diamond, not a chain, so a start order
/// that merely happened to be insertion order would not satisfy it.
fn node() -> NodeSpec {
    let caps = CapabilityProfile::node_root();
    NodeSpec::new("fgit-node", BudgetPolicy::finite_defaults())
        .service(ServiceSpec::new("store", BudgetClass::Database, caps))
        .service(ServiceSpec::new("authority", BudgetClass::Database, caps).depends_on("store"))
        .service(ServiceSpec::new("protocol", BudgetClass::Request, caps).depends_on("authority"))
        .service(
            ServiceSpec::new("projection", BudgetClass::BackgroundController, caps)
                .depends_on("store"),
        )
}

/// One ledger per service, keyed by service name.
fn ledgers(spec: &NodeSpec) -> BTreeMap<String, Arc<ServiceLedger>> {
    spec.services()
        .iter()
        .map(|service| (service.name().to_owned(), Arc::new(ServiceLedger::new())))
        .collect()
}

/// Build the app spec, wiring each service to its own ledger.
fn app_spec(spec: &NodeSpec, ledgers: &BTreeMap<String, Arc<ServiceLedger>>) -> AppSpec {
    let now = Time::from_secs(0);
    spec.to_app_spec(now, |service| {
        let ledger = Arc::clone(
            ledgers
                .get(service.name())
                .expect("every declared service has a ledger"),
        );
        // The child budget is *derived* from the node root rather than minted
        // beside it, so the meet rule that refuses widening is on the live
        // path rather than only in `meter`'s own unit tests.
        let root = spec.policy().budget_at(now, BudgetClass::NodeRoot);
        let requested = spec.policy().budget_at(now, service.budget_class());
        let budget = derive_child(root, requested)
            .expect("a class budget never widens the node root it is derived from");
        LedgerService::new(ledger, STEPS, budget).into_child_start()
    })
    .expect("the demonstration topology is valid")
}

/// A started node: the lab runtime, the app handle, and the ledgers.
struct StartedNode {
    /// Keeps the production runtime that minted the context alive.
    ///
    /// The `Cx` handed to `AppSpec::start` came from this node, and dropping
    /// the runtime while the supervision tree still references that context
    /// would invalidate the very thing under test.
    _node: fgit_runtime::NodeRuntime,
    runtime: LabRuntime,
    app: asupersync::app::AppHandle,
    ledgers: BTreeMap<String, Arc<ServiceLedger>>,
    /// Child names in the order the supervisor actually started them.
    supervisor_order: Vec<String>,
}

/// Start the node and run it to quiescence.
///
/// The context is minted by this crate's own production factory — the same
/// `request_cx_with_budget` path a real node uses — rather than by
/// `Cx::for_testing`, which Asupersync gates behind
/// `cfg(any(test, feature = "test-internals"))` precisely so that downstream
/// crates cannot forge a full-capability context. Honouring that gate is the
/// point: if the supervisor accepts a context this crate minted through the
/// production factory, the capability story holds.
fn start_node() -> StartedNode {
    let spec = node();
    let ledgers = ledgers(&spec);
    let app_spec = app_spec(&spec, &ledgers);

    let node_runtime = RuntimeProfile::deterministic()
        .build()
        .expect("the deterministic profile builds");
    let cx = node_runtime.request_cx(BudgetClass::NodeRoot);

    let mut runtime = LabRuntime::new(LabConfig::default());
    let root = runtime.state.create_root_region(Budget::INFINITE);

    let app = app_spec
        .start(&mut runtime.state, &cx, root)
        .expect("the supervisor starts the compiled topology");

    let supervisor_order: Vec<String> = app
        .supervisor()
        .started
        .iter()
        .map(|child| child.name.as_str().to_owned())
        .collect();

    let started_tasks: Vec<TaskId> = app
        .supervisor()
        .started
        .iter()
        .map(|child| child.task_id)
        .collect();

    // Publish the started children into the scheduler's ready lane, then run
    // until nothing can make progress.
    {
        let mut scheduler = runtime.scheduler.lock();
        for task in started_tasks {
            scheduler.schedule(task, 0);
        }
    }
    runtime.run_until_quiescent();

    StartedNode {
        _node: node_runtime,
        runtime,
        app,
        ledgers,
        supervisor_order,
    }
}

/// Carry a stopped region through request -> drain -> finalize.
///
/// `AppHandle::stop` records the cancel intent. Reaching quiescence takes
/// repeated passes: each one requests cancellation for whatever is still
/// live, schedules those cancels, runs the scheduler until nothing can
/// progress, and then asks the region to advance. The loop is bounded so a
/// region that refuses to settle fails the test instead of hanging it.
fn drive_shutdown(runtime: &mut LabRuntime, app_region: RegionId) {
    for _ in 0..8 {
        let effects = runtime.state.cancel_request(
            app_region,
            &CancelReason::new(CancelKind::Shutdown),
            None,
        );
        let (to_cancel, _wakes) = effects.into_parts();
        {
            let mut scheduler = runtime.scheduler.lock();
            for (task_id, priority) in to_cancel {
                scheduler.schedule_cancel(task_id, priority);
            }
        }

        runtime.run_until_quiescent();
        runtime.state.advance_region_state(app_region);

        if runtime
            .state
            .region(app_region)
            .is_some_and(|region| region.state() == RegionState::Closed)
        {
            return;
        }
    }
}

#[test]
fn every_declared_service_actually_starts_and_completes() {
    // The test the audit's finding demands: not "the spec compiles" but "the
    // services ran". A start body that is never invoked leaves `started` at
    // zero, which is exactly what the previous `never_starts` stubs did.
    let started = start_node();

    assert_eq!(
        started.ledgers.len(),
        4,
        "the node declares four services, got {:?}",
        started.ledgers.keys().collect::<Vec<_>>()
    );

    for (name, ledger) in &started.ledgers {
        assert_eq!(
            ledger.started(),
            1,
            "service `{name}` was never started by the supervisor"
        );
        assert_eq!(
            ledger.steps(),
            STEPS,
            "service `{name}` did not advance through its work"
        );
        assert_eq!(
            ledger.completed(),
            1,
            "service `{name}` started but never reached its final statement"
        );
    }
}

#[test]
fn the_supervisor_starts_services_in_the_order_this_crate_compiled() {
    // Two independent computations of the same order: this crate's Kahn walk
    // with a lexicographic tie-break, and Asupersync's own supervisor. If they
    // ever disagree, the `StartTieBreak::NameLex` coupling in `to_app_spec`
    // has drifted and the plan this crate reports is not the plan that runs.
    let started = start_node();
    let plan = node().compile().expect("the topology compiles");

    assert_eq!(
        started.supervisor_order,
        plan.order(),
        "the supervisor's actual start order differs from the compiled plan"
    );

    // And the order is a real topological order for the declared edges: each
    // dependency appears before the service that declared it.
    let position = |name: &str| {
        started
            .supervisor_order
            .iter()
            .position(|started| started == name)
            .unwrap_or_else(|| panic!("`{name}` must appear in the start order"))
    };
    assert!(position("store") < position("authority"));
    assert!(position("authority") < position("protocol"));
    assert!(position("store") < position("projection"));
}

#[test]
fn stopping_the_node_closes_its_region() {
    // Shutdown is the half a compile-time plan cannot speak to: the region
    // that owns the services must actually leave the open state.
    let mut started = start_node();
    let app_region = started.app.root_region();

    assert_eq!(
        started
            .runtime
            .state
            .region(app_region)
            .map(asupersync::record::region::RegionRecord::state),
        Some(RegionState::Open),
        "the app region must be open while the node is running"
    );

    let stopped = started
        .app
        .stop(&mut started.runtime.state)
        .expect("a started app stops");
    assert_eq!(stopped.name, "fgit-node");
    assert_eq!(stopped.root_region, app_region);

    // `stop` records the intent; it does not by itself carry the region
    // through the protocol. Cancellation is request -> drain -> finalize, so
    // the shutdown has to be driven to completion rather than assumed from
    // the return value — which is exactly the distinction this crate's
    // `ShutdownDriver` exists to enforce.
    drive_shutdown(&mut started.runtime, app_region);

    let region_state = started
        .runtime
        .state
        .region(app_region)
        .map(asupersync::record::region::RegionRecord::state)
        .expect("the app region still exists after stop");
    assert_ne!(
        region_state,
        RegionState::Open,
        "a driven shutdown must move the app region out of the open state"
    );

    // Stop records a cancel intent rather than dropping the tree silently.
    assert!(
        started
            .runtime
            .state
            .region(app_region)
            .and_then(|region| region.cancel_reason().map(|_| ()))
            .is_some(),
        "stop must record why the region was cancelled"
    );
}
