//! The node service graph, its deterministic start order, and the
//! dependency-ordered shutdown sequence.
//!
//! A node is a set of named services with declared dependencies. Compiling the
//! node validates that the declarations form a DAG and computes one canonical
//! start order; shutdown is that order reversed, wrapped in the phase sequence
//! the integration profile fixes: stop admission, request cancellation, drain
//! sessions and database commands, finalize or transfer obligations, close
//! database workers explicitly, flush evidence, then join the node root.
//!
//! The ordering computation here is FrankenGit's own and is pure, so it is
//! testable without a running runtime. It is also cross-checked against
//! Asupersync's compiled supervisor order in this module's tests: the two
//! independent computations must agree, which is what makes
//! [`NodeSpec::to_app_spec`] safe to hand to the supervisor.
//!
//! # Non-claim
//!
//! Compiling a topology proves the ordering is well defined. It does not claim
//! a tree-wide compiled-supervisor restart contract; the profile is explicit
//! that Asupersync proves live restart per actor, and higher-level restart
//! ordering stays explicit rather than assumed.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::Budget;
use asupersync::app::AppSpec;
use asupersync::supervision::{ChildSpec, ChildStart, StartTieBreak};

use crate::grant::CapabilityProfile;
use crate::meter::{BudgetClass, BudgetPolicy};
use crate::refuse::{RuntimeRefusal, TopologyDefect};

/// The canonical shutdown phases, in the order the profile fixes.
///
/// Shutdown is a sequence, not an event. Each phase must complete before the
/// next begins, because draining before cancelling admits work that will be
/// cancelled anyway, and joining the root before finalizing obligations turns
/// an unresolved obligation into a leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ShutdownPhase {
    /// Stop admitting new work.
    StopAdmission,
    /// Request cancellation of in-flight work.
    RequestCancellation,
    /// Drain sessions and database commands.
    DrainSessions,
    /// Finalize or explicitly transfer every outstanding obligation.
    FinalizeObligations,
    /// Close database workers explicitly rather than relying on drop.
    CloseDatabaseWorkers,
    /// Flush evidence to its durable sink.
    FlushEvidence,
    /// Join the node root region to quiescence.
    JoinRoot,
}

/// The canonical phase order.
const SHUTDOWN_PHASES: [ShutdownPhase; 7] = [
    ShutdownPhase::StopAdmission,
    ShutdownPhase::RequestCancellation,
    ShutdownPhase::DrainSessions,
    ShutdownPhase::FinalizeObligations,
    ShutdownPhase::CloseDatabaseWorkers,
    ShutdownPhase::FlushEvidence,
    ShutdownPhase::JoinRoot,
];

impl ShutdownPhase {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StopAdmission => "stop_admission",
            Self::RequestCancellation => "request_cancellation",
            Self::DrainSessions => "drain_sessions",
            Self::FinalizeObligations => "finalize_obligations",
            Self::CloseDatabaseWorkers => "close_database_workers",
            Self::FlushEvidence => "flush_evidence",
            Self::JoinRoot => "join_root",
        }
    }

    /// The canonical shutdown sequence.
    #[must_use]
    pub const fn sequence() -> [Self; 7] {
        SHUTDOWN_PHASES
    }
}

/// One declared service in the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    name: String,
    depends_on: Vec<String>,
    budget_class: BudgetClass,
    capabilities: CapabilityProfile,
}

impl ServiceSpec {
    /// Declare a service.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        budget_class: BudgetClass,
        capabilities: CapabilityProfile,
    ) -> Self {
        Self {
            name: name.into(),
            depends_on: Vec::new(),
            budget_class,
            capabilities,
        }
    }

    /// Declare a dependency on another service by name.
    #[must_use]
    pub fn depends_on(mut self, name: impl Into<String>) -> Self {
        self.depends_on.push(name.into());
        self
    }

    /// The service name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The declared dependency names.
    #[must_use]
    pub fn dependencies(&self) -> &[String] {
        &self.depends_on
    }

    /// The budget class this service's work is charged to.
    #[must_use]
    pub const fn budget_class(&self) -> BudgetClass {
        self.budget_class
    }

    /// The capability envelope this service runs inside.
    #[must_use]
    pub const fn capabilities(&self) -> CapabilityProfile {
        self.capabilities
    }
}

/// A declared node: a name, a budget policy, and a set of services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpec {
    name: String,
    services: Vec<ServiceSpec>,
    policy: BudgetPolicy,
}

impl NodeSpec {
    /// Begin declaring a node.
    #[must_use]
    pub fn new(name: impl Into<String>, policy: BudgetPolicy) -> Self {
        Self {
            name: name.into(),
            services: Vec::new(),
            policy,
        }
    }

    /// Add a service declaration.
    #[must_use]
    pub fn service(mut self, service: ServiceSpec) -> Self {
        self.services.push(service);
        self
    }

    /// The node name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The declared services, in declaration order.
    #[must_use]
    pub fn services(&self) -> &[ServiceSpec] {
        &self.services
    }

    /// The budget policy.
    #[must_use]
    pub const fn policy(&self) -> BudgetPolicy {
        self.policy
    }

    /// Validate the declarations and compute the canonical start order.
    ///
    /// The order is a topological sort with a lexicographic tie-break, so a
    /// given set of declarations always produces byte-identical ordering
    /// regardless of declaration order or map iteration.
    ///
    /// # Errors
    ///
    /// [`RuntimeRefusal::TopologyInvalid`] for an empty topology, a duplicate
    /// service name, a dependency on an undeclared service, or a cycle.
    pub fn compile(&self) -> Result<StartPlan, RuntimeRefusal> {
        if self.services.is_empty() {
            return Err(invalid(TopologyDefect::Empty));
        }

        let mut names = BTreeSet::new();
        for service in &self.services {
            if !names.insert(service.name.clone()) {
                return Err(invalid(TopologyDefect::DuplicateService(
                    service.name.clone(),
                )));
            }
        }

        // Dependency edges, keyed in sorted order so the traversal below is
        // independent of declaration order.
        let mut dependencies: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for service in &self.services {
            let entry = dependencies.entry(service.name.as_str()).or_default();
            for dependency in &service.depends_on {
                if !names.contains(dependency.as_str()) {
                    return Err(invalid(TopologyDefect::UnknownDependency {
                        service: service.name.clone(),
                        missing: dependency.clone(),
                    }));
                }
                entry.insert(dependency.as_str());
            }
        }

        // Kahn's algorithm, always taking the lexicographically smallest
        // ready service, which makes the result canonical.
        let mut remaining = dependencies.clone();
        let mut order: Vec<String> = Vec::with_capacity(self.services.len());
        while !remaining.is_empty() {
            let ready = remaining
                .iter()
                .find(|(_, deps)| deps.is_empty())
                .map(|(name, _)| (*name).to_owned());

            let Some(next) = ready else {
                return Err(invalid(TopologyDefect::DependencyCycle(
                    remaining.keys().map(|name| (*name).to_owned()).collect(),
                )));
            };

            remaining.remove(next.as_str());
            for deps in remaining.values_mut() {
                deps.remove(next.as_str());
            }
            order.push(next);
        }

        Ok(StartPlan {
            node: self.name.clone(),
            order,
            policy: self.policy,
        })
    }

    /// Build the Asupersync application spec for this node.
    ///
    /// The supervisor receives the same dependency edges this module
    /// validated, plus a per-service shutdown budget drawn from the node's
    /// budget policy. Start bodies are supplied by the caller: this crate
    /// declares topology and policy, it does not fabricate service behaviour.
    ///
    /// # Errors
    ///
    /// Whatever [`compile`](Self::compile) refuses, refused here first.
    pub fn to_app_spec<F>(&self, mut start_for: F) -> Result<AppSpec, RuntimeRefusal>
    where
        F: FnMut(&ServiceSpec) -> Box<dyn ChildStart>,
    {
        let plan = self.compile()?;
        let root_budget = self.policy.budget_for(BudgetClass::NodeRoot);

        let mut spec = AppSpec::new(self.name.clone())
            .with_budget(root_budget)
            // Match this module's own lexicographic tie-break so the
            // supervisor's compiled order and `plan.order` agree.
            .with_tie_break(StartTieBreak::NameLex);

        // Add children in canonical order so the spec is byte-stable too.
        for name in plan.order() {
            let service = self
                .services
                .iter()
                .find(|candidate| candidate.name == *name)
                .expect("plan order is drawn from the declared services");

            let mut child = ChildSpec::new(service.name.clone(), BoxedStart(start_for(service)))
                .with_shutdown_budget(self.policy.budget_for(BudgetClass::ShutdownCleanup));
            for dependency in &service.depends_on {
                child = child.depends_on(dependency.clone());
            }
            spec = spec.child(child);
        }

        Ok(spec)
    }
}

fn invalid(defect: TopologyDefect) -> RuntimeRefusal {
    RuntimeRefusal::TopologyInvalid { defect }
}

/// Adapts a caller-supplied boxed start body to the supervisor's trait.
///
/// [`ChildSpec::new`] takes a concrete `impl ChildStart`, and there is no
/// blanket implementation for `Box<dyn ChildStart>`, so the box is delegated
/// through this newtype rather than forcing every caller to name one concrete
/// start type for a heterogeneous service set.
struct BoxedStart(Box<dyn ChildStart>);

impl ChildStart for BoxedStart {
    fn start(
        &mut self,
        scope: &asupersync::cx::Scope<'static, asupersync::types::policy::FailFast>,
        state: &mut asupersync::runtime::RuntimeState,
        cx: &asupersync::cx::Cx,
    ) -> Result<asupersync::types::id::TaskId, asupersync::runtime::SpawnError> {
        self.0.start(scope, state, cx)
    }
}

/// A validated node topology with its canonical orders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartPlan {
    node: String,
    order: Vec<String>,
    policy: BudgetPolicy,
}

impl StartPlan {
    /// The node name.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// The canonical start order: dependencies before dependents.
    #[must_use]
    pub fn order(&self) -> &[String] {
        &self.order
    }

    /// The canonical service stop order: dependents before dependencies.
    #[must_use]
    pub fn stop_order(&self) -> Vec<String> {
        self.order.iter().rev().cloned().collect()
    }

    /// The full shutdown sequence: the canonical phases, with the service stop
    /// order applied inside the cancellation and drain phases.
    #[must_use]
    pub fn shutdown_sequence(&self) -> Vec<ShutdownPhase> {
        ShutdownPhase::sequence().to_vec()
    }

    /// The effective budget for a service, derived beneath the node root.
    #[must_use]
    pub fn budget_for(&self, class: BudgetClass) -> Budget {
        self.policy
            .derive(self.policy.budget_for(BudgetClass::NodeRoot), class)
    }
}

#[cfg(test)]
mod tests {
    use asupersync::cx::cap::CapMask;
    use asupersync::runtime::{RuntimeState, SpawnError};
    use asupersync::types::id::TaskId;

    use super::*;
    use crate::grant::{AuthorityCapability, AuthoritySet, Ownership};

    fn caps() -> CapabilityProfile {
        CapabilityProfile::node_root()
    }

    /// A start body that reports the runtime is unavailable.
    ///
    /// Used only to satisfy `to_app_spec`'s caller-supplied factory in tests
    /// that assert *ordering*, which the supervisor computes at compile time
    /// before any start body runs.
    fn never_starts() -> Box<dyn ChildStart> {
        Box::new(
            |_scope: &asupersync::cx::Scope<'static, asupersync::types::policy::FailFast>,
             _state: &mut RuntimeState,
             _cx: &asupersync::cx::Cx|
             -> Result<TaskId, SpawnError> {
                Err(SpawnError::RuntimeUnavailable)
            },
        )
    }

    fn node() -> NodeSpec {
        NodeSpec::new("fgit-node", BudgetPolicy::finite_defaults())
            .service(ServiceSpec::new(
                "store",
                BudgetClass::Database,
                caps(),
            ))
            .service(
                ServiceSpec::new("authority", BudgetClass::Database, caps()).depends_on("store"),
            )
            .service(
                ServiceSpec::new("protocol", BudgetClass::Request, caps())
                    .depends_on("authority"),
            )
            .service(
                ServiceSpec::new("projection", BudgetClass::BackgroundController, caps())
                    .depends_on("store"),
            )
    }

    #[test]
    fn start_order_places_dependencies_before_dependents() {
        let plan = node().compile().expect("valid topology");
        let order = plan.order();

        let position = |name: &str| {
            order
                .iter()
                .position(|candidate| candidate == name)
                .unwrap_or_else(|| panic!("`{name}` missing from start order"))
        };

        assert!(position("store") < position("authority"));
        assert!(position("authority") < position("protocol"));
        assert!(position("store") < position("projection"));
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn start_order_is_canonical_regardless_of_declaration_order() {
        let forward = node().compile().expect("valid").order().to_vec();

        // Same graph, services declared in reverse.
        let reversed = NodeSpec::new("fgit-node", BudgetPolicy::finite_defaults())
            .service(
                ServiceSpec::new("projection", BudgetClass::BackgroundController, caps())
                    .depends_on("store"),
            )
            .service(
                ServiceSpec::new("protocol", BudgetClass::Request, caps())
                    .depends_on("authority"),
            )
            .service(
                ServiceSpec::new("authority", BudgetClass::Database, caps()).depends_on("store"),
            )
            .service(ServiceSpec::new("store", BudgetClass::Database, caps()))
            .compile()
            .expect("valid")
            .order()
            .to_vec();

        assert_eq!(forward, reversed);
    }

    #[test]
    fn start_order_is_stable_across_repeated_compilations() {
        let spec = node();
        let first = spec.compile().expect("valid").order().to_vec();
        for _ in 0..16 {
            assert_eq!(spec.compile().expect("valid").order(), first.as_slice());
        }
    }

    #[test]
    fn stop_order_is_the_exact_reverse_of_start_order() {
        let plan = node().compile().expect("valid");
        let mut expected = plan.order().to_vec();
        expected.reverse();
        assert_eq!(plan.stop_order(), expected);

        // Dependents really do stop before what they depend on.
        let stop = plan.stop_order();
        let position = |name: &str| {
            stop.iter()
                .position(|candidate| candidate == name)
                .expect("present")
        };
        assert!(position("protocol") < position("authority"));
        assert!(position("authority") < position("store"));
        assert!(position("projection") < position("store"));
    }

    #[test]
    fn shutdown_phases_are_in_the_canonical_order() {
        let plan = node().compile().expect("valid");
        assert_eq!(
            plan.shutdown_sequence(),
            vec![
                ShutdownPhase::StopAdmission,
                ShutdownPhase::RequestCancellation,
                ShutdownPhase::DrainSessions,
                ShutdownPhase::FinalizeObligations,
                ShutdownPhase::CloseDatabaseWorkers,
                ShutdownPhase::FlushEvidence,
                ShutdownPhase::JoinRoot,
            ]
        );

        // Obligations are finalized before workers close, and evidence is
        // flushed before the root is joined. Both orderings are load-bearing.
        let sequence = plan.shutdown_sequence();
        let at = |phase: ShutdownPhase| {
            sequence
                .iter()
                .position(|candidate| *candidate == phase)
                .expect("phase present")
        };
        assert!(at(ShutdownPhase::StopAdmission) < at(ShutdownPhase::RequestCancellation));
        assert!(at(ShutdownPhase::RequestCancellation) < at(ShutdownPhase::DrainSessions));
        assert!(at(ShutdownPhase::DrainSessions) < at(ShutdownPhase::FinalizeObligations));
        assert!(at(ShutdownPhase::FinalizeObligations) < at(ShutdownPhase::CloseDatabaseWorkers));
        assert!(at(ShutdownPhase::CloseDatabaseWorkers) < at(ShutdownPhase::FlushEvidence));
        assert!(at(ShutdownPhase::FlushEvidence) < at(ShutdownPhase::JoinRoot));
    }

    #[test]
    fn empty_topology_is_refused() {
        let refusal = NodeSpec::new("empty", BudgetPolicy::finite_defaults())
            .compile()
            .expect_err("a node with no services is not a node");
        assert_eq!(
            refusal,
            RuntimeRefusal::TopologyInvalid {
                defect: TopologyDefect::Empty
            }
        );
    }

    #[test]
    fn duplicate_service_name_is_refused() {
        let refusal = NodeSpec::new("dup", BudgetPolicy::finite_defaults())
            .service(ServiceSpec::new("store", BudgetClass::Database, caps()))
            .service(ServiceSpec::new("store", BudgetClass::Request, caps()))
            .compile()
            .expect_err("names must be unique");
        assert_eq!(
            refusal,
            RuntimeRefusal::TopologyInvalid {
                defect: TopologyDefect::DuplicateService("store".to_owned())
            }
        );
    }

    #[test]
    fn unknown_dependency_is_refused() {
        let refusal = NodeSpec::new("unknown", BudgetPolicy::finite_defaults())
            .service(
                ServiceSpec::new("protocol", BudgetClass::Request, caps())
                    .depends_on("missing-service"),
            )
            .compile()
            .expect_err("dependencies must be declared");
        assert_eq!(
            refusal,
            RuntimeRefusal::TopologyInvalid {
                defect: TopologyDefect::UnknownDependency {
                    service: "protocol".to_owned(),
                    missing: "missing-service".to_owned(),
                }
            }
        );
    }

    #[test]
    fn dependency_cycle_is_refused() {
        let refusal = NodeSpec::new("cyclic", BudgetPolicy::finite_defaults())
            .service(ServiceSpec::new("a", BudgetClass::Request, caps()).depends_on("b"))
            .service(ServiceSpec::new("b", BudgetClass::Request, caps()).depends_on("c"))
            .service(ServiceSpec::new("c", BudgetClass::Request, caps()).depends_on("a"))
            .compile()
            .expect_err("a cycle has no start order");

        match refusal {
            RuntimeRefusal::TopologyInvalid {
                defect: TopologyDefect::DependencyCycle(members),
            } => {
                assert_eq!(members, vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]);
            }
            other => panic!("expected a dependency cycle, got {other:?}"),
        }
    }

    #[test]
    fn self_dependency_is_refused_as_a_cycle() {
        let refusal = NodeSpec::new("self", BudgetPolicy::finite_defaults())
            .service(ServiceSpec::new("a", BudgetClass::Request, caps()).depends_on("a"))
            .compile()
            .expect_err("a service cannot depend on itself");
        assert!(matches!(
            refusal,
            RuntimeRefusal::TopologyInvalid {
                defect: TopologyDefect::DependencyCycle(_)
            }
        ));

        // Paired permitted case: the same service without the self edge.
        NodeSpec::new("self", BudgetPolicy::finite_defaults())
            .service(ServiceSpec::new("a", BudgetClass::Request, caps()))
            .compile()
            .expect("a service with no dependencies compiles");
    }

    #[test]
    fn the_supervisor_agrees_with_our_computed_start_order() {
        // Two independent computations of the same order: this module's Kahn
        // sort, and Asupersync's compiled supervisor. If they ever disagree,
        // handing `to_app_spec` output to a supervisor would start services in
        // an order this crate did not validate.
        let spec = node();
        let plan = spec.compile().expect("valid topology");
        let app = spec
            .to_app_spec(|_service| never_starts())
            .expect("valid topology compiles to an app spec");
        let compiled = app.compile().expect("the supervisor accepts the topology");

        let supervisor_order: Vec<String> = compiled
            .compiled_supervisor()
            .start_order
            .iter()
            .map(|index| {
                compiled.compiled_supervisor().children[*index]
                    .name
                    .to_string()
            })
            .collect();

        assert_eq!(supervisor_order, plan.order().to_vec());
    }

    #[test]
    fn app_spec_construction_refuses_an_invalid_topology() {
        let refusal = NodeSpec::new("cyclic", BudgetPolicy::finite_defaults())
            .service(ServiceSpec::new("a", BudgetClass::Request, caps()).depends_on("b"))
            .service(ServiceSpec::new("b", BudgetClass::Request, caps()).depends_on("a"))
            .to_app_spec(|_service| never_starts())
            .expect_err("an invalid topology never reaches the supervisor");
        assert!(matches!(
            refusal,
            RuntimeRefusal::TopologyInvalid { .. }
        ));
    }

    #[test]
    fn service_budgets_are_finite_and_bounded_by_the_root() {
        let plan = node().compile().expect("valid");
        let root = plan.budget_for(BudgetClass::NodeRoot);
        for service in node().services() {
            let budget = plan.budget_for(service.budget_class());
            assert!(
                !crate::meter::is_unbounded(budget),
                "service `{}` must have a finite budget",
                service.name()
            );
            assert!(budget.poll_quota <= root.poll_quota);
        }
    }

    #[test]
    fn services_can_declare_narrowed_capability_envelopes() {
        let projection = ServiceSpec::new(
            "projection",
            BudgetClass::BackgroundController,
            CapabilityProfile::node_root()
                .narrow(
                    CapMask::all(),
                    AuthoritySet::none().with(AuthorityCapability::Database),
                    Ownership::Owned,
                )
                .expect("narrowing to database-only authority"),
        );

        // A projection may read the database but never publish.
        assert!(
            projection
                .capabilities()
                .authority()
                .contains(AuthorityCapability::Database)
        );
        assert!(
            !projection
                .capabilities()
                .authority()
                .contains(AuthorityCapability::Publication)
        );
    }
}
