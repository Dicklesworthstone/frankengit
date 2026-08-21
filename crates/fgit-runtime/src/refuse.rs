//! Stable refusal and exhaustion vocabulary for the `FrankenGit` node runtime.
//!
//! Every way the runtime profile can decline to proceed is one variant here
//! with one stable machine code. The codes are part of the observable contract:
//! evidence, receipts, and operator tooling match on [`RuntimeRefusal::code`],
//! never on the human message. Adding a variant is a protocol change.
//!
//! A refusal is not an error return that happens to be typed. It carries the
//! reason a *permitted* path was not taken, so the caller can distinguish
//! "policy said no" from "the work failed".

use core::fmt;

/// Which budget dimension ran out.
///
/// These mirror the runtime's own exhaustion causes
/// ([`asupersync::types::cancel::CancelKind::Deadline`],
/// [`PollQuota`](asupersync::types::cancel::CancelKind::PollQuota),
/// [`CostBudget`](asupersync::types::cancel::CancelKind::CostBudget)) so a
/// refusal raised by `FrankenGit` policy and a cancellation raised by the
/// scheduler describe the same dimension with the same word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exhaustion {
    /// The wall-clock/logical deadline dimension is empty.
    Deadline,
    /// The poll quota dimension is empty.
    PollQuota,
    /// The abstract cost quota dimension is empty.
    CostQuota,
}

impl Exhaustion {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::PollQuota => "poll_quota",
            Self::CostQuota => "cost_quota",
        }
    }

    /// The cancellation cause the runtime raises for this same dimension.
    #[must_use]
    pub const fn cancel_kind(self) -> asupersync::CancelKind {
        match self {
            Self::Deadline => asupersync::CancelKind::Deadline,
            Self::PollQuota => asupersync::CancelKind::PollQuota,
            Self::CostQuota => asupersync::CancelKind::CostBudget,
        }
    }
}

impl fmt::Display for Exhaustion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Every dimension of an [`asupersync::Budget`] that a child can try to widen.
///
/// This is a superset of [`Exhaustion`]: priority is an inherited scheduling
/// constraint that a child must not relax, but it is not a quota that can run
/// out, so it has no exhaustion cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetDimension {
    /// Absolute completion deadline.
    Deadline,
    /// Poll quota.
    PollQuota,
    /// Abstract cost quota.
    CostQuota,
    /// Scheduling priority. In the runtime's lattice a *higher* priority value
    /// is the tighter constraint, so relaxing means requesting a lower value.
    Priority,
}

impl BudgetDimension {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::PollQuota => "poll_quota",
            Self::CostQuota => "cost_quota",
            Self::Priority => "priority",
        }
    }

    /// The exhaustion cause for this dimension, when it is a quota at all.
    #[must_use]
    pub const fn exhaustion(self) -> Option<Exhaustion> {
        match self {
            Self::Deadline => Some(Exhaustion::Deadline),
            Self::PollQuota => Some(Exhaustion::PollQuota),
            Self::CostQuota => Some(Exhaustion::CostQuota),
            Self::Priority => None,
        }
    }
}

impl fmt::Display for BudgetDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Every typed refusal the node runtime profile can raise.
///
/// The variants are deliberately specific: a caller that sees
/// [`ChildBudgetWidening`](Self::ChildBudgetWidening) knows a subsystem tried
/// to hand itself more budget than its parent granted, which is a construction
/// defect, not a transient condition to retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeRefusal {
    /// A child requested a budget looser than its parent's along some
    /// dimension. Budgets meet; they never join.
    ChildBudgetWidening {
        /// The dimension that would have been widened.
        dimension: BudgetDimension,
    },
    /// A subsystem requested a capability its parent context does not hold.
    CapabilityWidening {
        /// The runtime capability bits that were requested but not held.
        missing: &'static str,
    },
    /// A detached/background work unit was configured to retain an authority
    /// capability. Detached work never holds publication, object, network,
    /// database, secret, runner, or billing authority.
    DetachedAuthorityRetained {
        /// The authority capability that was wrongly retained.
        capability: &'static str,
    },
    /// A service class was configured with an unbounded budget. Only a named
    /// node-root/service-root policy may hold [`asupersync::Budget::INFINITE`].
    UnboundedServiceBudget {
        /// The service/budget class that requested it.
        class: &'static str,
    },
    /// An obligation-leak policy that cannot satisfy region closure was
    /// selected. `Silent` is forbidden outright; `Log` alone cannot close.
    LeakPolicyInsufficient {
        /// The rejected policy name.
        policy: &'static str,
    },
    /// `Recover` was selected without the controls that make it admissible.
    LeakRecoveryUncontrolled {
        /// Which required control was missing.
        missing: &'static str,
    },
    /// A budget dimension was already empty when the work was requested.
    BudgetExhausted {
        /// The empty dimension.
        dimension: Exhaustion,
    },
    /// The node topology is not a valid dependency DAG.
    TopologyInvalid {
        /// Stable sub-code describing the defect.
        defect: TopologyDefect,
    },
    /// Bounded fan-out admission refused further work.
    AdmissionRefused {
        /// The configured bound that was reached.
        limit: usize,
    },
    /// The owning runtime is gone, so no production context can be minted.
    RuntimeUnavailable,
    /// A shutdown phase was run out of the canonical order.
    ShutdownOutOfOrder {
        /// The phase the sequence expected next.
        expected: &'static str,
        /// The phase the caller tried to run.
        actual: &'static str,
    },
    /// Shutdown was finished before every phase had run.
    ShutdownIncomplete {
        /// The first phase that never ran.
        missing: &'static str,
    },
    /// A region closed without reaching obligation quiescence.
    ///
    /// The counts are split rather than summed because they call for
    /// different responses: an *escalated* effect is owned by a named
    /// principal and a human is already on it, a *leaked* effect means the
    /// program dropped work on the floor, and an *accounting fault* is worse
    /// than either — the ledger itself could not complete a move, so the
    /// numbers beside it are not trustworthy. Folding them into one
    /// "unresolved" total would erase exactly the distinction an operator
    /// needs. Shape agreed with `fgit-resource` (fg012a); the fields are
    /// plain scalars so this can carry a
    /// `RegionCloseOutcome::ContainmentFailure` across the crate boundary
    /// before `fgit-runtime` depends on that crate.
    RegionCloseContainmentFailure {
        /// The region that failed to close cleanly.
        region: u64,
        /// Obligations neither settled nor escalated.
        unsettled: u32,
        /// Obligations handed to a named principal.
        escalated: u32,
        /// Obligations whose responsibility was dropped.
        leaked: u32,
        /// Accounting moves the ledger could not complete.
        accounting_faults: u32,
    },
}

/// Why a node topology failed to compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyDefect {
    /// Two services share one name.
    DuplicateService(String),
    /// A service depends on a name that is not in the topology.
    UnknownDependency {
        /// The service declaring the dependency.
        service: String,
        /// The missing dependency name.
        missing: String,
    },
    /// The dependency edges contain a cycle.
    DependencyCycle(Vec<String>),
    /// The topology declares no services at all.
    Empty,
}

impl TopologyDefect {
    /// Stable machine code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::DuplicateService(_) => "duplicate_service",
            Self::UnknownDependency { .. } => "unknown_dependency",
            Self::DependencyCycle(_) => "dependency_cycle",
            Self::Empty => "empty_topology",
        }
    }
}

impl fmt::Display for TopologyDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateService(name) => write!(f, "duplicate service `{name}`"),
            Self::UnknownDependency { service, missing } => {
                write!(f, "service `{service}` depends on unknown `{missing}`")
            }
            Self::DependencyCycle(cycle) => {
                write!(f, "dependency cycle: {}", cycle.join(" -> "))
            }
            Self::Empty => f.write_str("topology declares no services"),
        }
    }
}

impl RuntimeRefusal {
    /// Stable machine code for evidence and operator tooling.
    ///
    /// This is the field downstream systems match on. It never changes for an
    /// existing variant.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ChildBudgetWidening { .. } => "runtime.budget.child_widening",
            Self::CapabilityWidening { .. } => "runtime.capability.widening",
            Self::DetachedAuthorityRetained { .. } => "runtime.capability.detached_authority",
            Self::UnboundedServiceBudget { .. } => "runtime.budget.unbounded_service",
            Self::LeakPolicyInsufficient { .. } => "runtime.obligation.leak_policy_insufficient",
            Self::LeakRecoveryUncontrolled { .. } => "runtime.obligation.recovery_uncontrolled",
            Self::BudgetExhausted { .. } => "runtime.budget.exhausted",
            Self::TopologyInvalid { .. } => "runtime.topology.invalid",
            Self::AdmissionRefused { .. } => "runtime.admission.refused",
            Self::RuntimeUnavailable => "runtime.unavailable",
            Self::ShutdownOutOfOrder { .. } => "runtime.shutdown.out_of_order",
            Self::ShutdownIncomplete { .. } => "runtime.shutdown.incomplete",
            Self::RegionCloseContainmentFailure { .. } => {
                "runtime.obligation.region_close_containment_failure"
            }
        }
    }

    /// Whether retrying the identical request could succeed.
    ///
    /// Construction defects (widening, invalid topology, insufficient leak
    /// policy) are never retryable: the same request will be refused forever.
    /// Only admission pressure is.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::AdmissionRefused { .. })
    }
}

impl fmt::Display for RuntimeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChildBudgetWidening { dimension } => write!(
                f,
                "child budget would widen the parent `{dimension}` limit; budgets meet, never join"
            ),
            Self::CapabilityWidening { missing } => write!(
                f,
                "requested capability `{missing}` is not held by the parent context"
            ),
            Self::DetachedAuthorityRetained { capability } => write!(
                f,
                "detached work may not retain the `{capability}` authority capability"
            ),
            Self::UnboundedServiceBudget { class } => write!(
                f,
                "service class `{class}` requested an unbounded budget; only the node root may be infinite"
            ),
            Self::LeakPolicyInsufficient { policy } => write!(
                f,
                "obligation leak policy `{policy}` cannot satisfy region closure"
            ),
            Self::LeakRecoveryUncontrolled { missing } => {
                write!(f, "obligation leak policy `Recover` requires `{missing}`")
            }
            Self::BudgetExhausted { dimension } => {
                write!(f, "budget dimension `{dimension}` is already exhausted")
            }
            Self::TopologyInvalid { defect } => write!(f, "invalid node topology: {defect}"),
            Self::AdmissionRefused { limit } => {
                write!(f, "admission refused at bounded limit {limit}")
            }
            Self::RuntimeUnavailable => {
                f.write_str("owning runtime is unavailable; no production context can be minted")
            }
            Self::ShutdownOutOfOrder { expected, actual } => write!(
                f,
                "shutdown phase `{actual}` ran out of order; the sequence expected `{expected}`"
            ),
            Self::ShutdownIncomplete { missing } => write!(
                f,
                "shutdown finished before phase `{missing}` ran; the node is not quiescent"
            ),
            Self::RegionCloseContainmentFailure {
                region,
                unsettled,
                escalated,
                leaked,
                accounting_faults,
            } => write!(
                f,
                "region {region} closed with containment failure: {unsettled} unsettled, \
                 {escalated} escalated, {leaked} leaked, {accounting_faults} accounting fault(s)"
            ),
        }
    }
}

impl std::error::Error for RuntimeRefusal {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_codes_are_unique_and_stable() {
        let refusals = [
            RuntimeRefusal::ChildBudgetWidening {
                dimension: BudgetDimension::Deadline,
            },
            RuntimeRefusal::CapabilityWidening { missing: "io" },
            RuntimeRefusal::DetachedAuthorityRetained {
                capability: "publication",
            },
            RuntimeRefusal::UnboundedServiceBudget { class: "request" },
            RuntimeRefusal::LeakPolicyInsufficient { policy: "Silent" },
            RuntimeRefusal::LeakRecoveryUncontrolled {
                missing: "escalation",
            },
            RuntimeRefusal::BudgetExhausted {
                dimension: Exhaustion::PollQuota,
            },
            RuntimeRefusal::TopologyInvalid {
                defect: TopologyDefect::Empty,
            },
            RuntimeRefusal::AdmissionRefused { limit: 8 },
            RuntimeRefusal::RuntimeUnavailable,
            RuntimeRefusal::ShutdownOutOfOrder {
                expected: "stop_admission",
                actual: "join_root",
            },
            RuntimeRefusal::ShutdownIncomplete {
                missing: "flush_evidence",
            },
            RuntimeRefusal::RegionCloseContainmentFailure {
                region: 3,
                unsettled: 1,
                escalated: 0,
                leaked: 2,
                accounting_faults: 0,
            },
        ];

        let mut codes: Vec<&str> = refusals.iter().map(RuntimeRefusal::code).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "refusal codes must be unique");

        // Codes are a namespaced contract, not free text.
        for code in &codes {
            assert!(
                code.starts_with("runtime."),
                "refusal code `{code}` must be namespaced under `runtime.`"
            );
        }
    }

    #[test]
    fn a_containment_failure_keeps_its_counts_separate() {
        // The counts must not be summed: each one calls for a different
        // response, and an accounting fault means the others are suspect.
        let refusal = RuntimeRefusal::RegionCloseContainmentFailure {
            region: 7,
            unsettled: 0,
            escalated: 1,
            leaked: 0,
            accounting_faults: 0,
        };
        assert_eq!(
            refusal.code(),
            "runtime.obligation.region_close_containment_failure"
        );
        assert!(!refusal.is_retryable());

        let rendered = refusal.to_string();
        assert!(rendered.contains("region 7"));
        assert!(rendered.contains("0 unsettled"));
        assert!(rendered.contains("1 escalated"));
        assert!(rendered.contains("0 leaked"));
        assert!(rendered.contains("0 accounting fault"));

        // A human-owned escalation and a dropped effect are distinguishable,
        // which is the whole reason the counts are split.
        let dropped = RuntimeRefusal::RegionCloseContainmentFailure {
            region: 7,
            unsettled: 0,
            escalated: 0,
            leaked: 1,
            accounting_faults: 0,
        };
        assert_ne!(refusal, dropped);
        assert_ne!(refusal.to_string(), dropped.to_string());
    }

    #[test]
    fn construction_defects_are_not_retryable() {
        assert!(
            !RuntimeRefusal::ChildBudgetWidening {
                dimension: BudgetDimension::Deadline
            }
            .is_retryable()
        );
        assert!(!RuntimeRefusal::CapabilityWidening { missing: "io" }.is_retryable());
        assert!(!RuntimeRefusal::LeakPolicyInsufficient { policy: "Log" }.is_retryable());
        // Paired permitted case: admission pressure is the one retryable class.
        assert!(RuntimeRefusal::AdmissionRefused { limit: 4 }.is_retryable());
    }

    #[test]
    fn exhaustion_maps_to_the_runtime_cancel_cause() {
        assert_eq!(
            Exhaustion::Deadline.cancel_kind(),
            asupersync::CancelKind::Deadline
        );
        assert_eq!(
            Exhaustion::PollQuota.cancel_kind(),
            asupersync::CancelKind::PollQuota
        );
        assert_eq!(
            Exhaustion::CostQuota.cancel_kind(),
            asupersync::CancelKind::CostBudget
        );
    }

    #[test]
    fn topology_defect_codes_are_stable() {
        assert_eq!(
            TopologyDefect::DuplicateService("a".to_owned()).code(),
            "duplicate_service"
        );
        assert_eq!(
            TopologyDefect::UnknownDependency {
                service: "a".to_owned(),
                missing: "b".to_owned()
            }
            .code(),
            "unknown_dependency"
        );
        assert_eq!(
            TopologyDefect::DependencyCycle(vec!["a".to_owned()]).code(),
            "dependency_cycle"
        );
        assert_eq!(TopologyDefect::Empty.code(), "empty_topology");
    }
}
