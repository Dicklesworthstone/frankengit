//! Budget classes, finite defaults, and the child-derivation rule.
//!
//! The integration profile is explicit that budgets are semantic, not
//! decorative: a child budget is the *meet* of parent and requested limits,
//! [`asupersync::Budget::INFINITE`] belongs only to a named node-root policy,
//! and everything else — requests, parsers, transfers, repairs, projection
//! work, database commands, shutdown cleanup — receives a finite,
//! profile-owned budget.
//!
//! This module owns the FrankenGit half of that contract. The lattice itself
//! is the runtime's ([`asupersync::Budget::meet`]); what lives here is the
//! classification, the finite defaults, and the refusal that fires when code
//! tries to hand itself more than it inherited.
//!
//! # Timeouts, not deadlines
//!
//! [`Budget::deadline`] is an *absolute* [`Time`], so a policy cannot store
//! one: a node that started yesterday would hand every request a deadline
//! that passed yesterday. Class defaults are therefore [`ClassLimits`] holding
//! a timeout, and the absolute deadline is computed at mint time against the
//! runtime's clock via [`BudgetPolicy::budget_at`].

use std::time::Duration;

use asupersync::Budget;
use asupersync::types::id::Time;

use crate::refuse::{BudgetDimension, Exhaustion, RuntimeRefusal};

/// The work classes the node runtime budgets separately.
///
/// Every variant except [`NodeRoot`](Self::NodeRoot) is finite by
/// construction. `NodeRoot` is the single named root policy the profile
/// permits to be unbounded, and even it is only unbounded when the operator
/// explicitly selects an unbounded root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetClass {
    /// The node root region. The one class allowed to be unbounded.
    NodeRoot,
    /// An inbound protocol request.
    Request,
    /// Parsing untrusted bytes (objects, packs, pkt-line, documents).
    Parser,
    /// Object/pack transfer work.
    Transfer,
    /// A database command or transaction against the embedded store.
    Database,
    /// A long-lived background controller (GC, repair, projection rebuild).
    BackgroundController,
    /// Cleanup performed while the node is shutting down.
    ShutdownCleanup,
}

/// Every non-root class, for exhaustive policy checks.
const FINITE_CLASSES: [BudgetClass; 6] = [
    BudgetClass::Request,
    BudgetClass::Parser,
    BudgetClass::Transfer,
    BudgetClass::Database,
    BudgetClass::BackgroundController,
    BudgetClass::ShutdownCleanup,
];

impl BudgetClass {
    /// Stable machine name used in refusals and evidence.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NodeRoot => "node_root",
            Self::Request => "request",
            Self::Parser => "parser",
            Self::Transfer => "transfer",
            Self::Database => "database",
            Self::BackgroundController => "background_controller",
            Self::ShutdownCleanup => "shutdown_cleanup",
        }
    }

    /// Whether this class may legitimately carry an unbounded budget.
    #[must_use]
    pub const fn may_be_unbounded(self) -> bool {
        matches!(self, Self::NodeRoot)
    }

    /// Every class that must be finite.
    #[must_use]
    pub const fn finite_classes() -> [Self; 6] {
        FINITE_CLASSES
    }
}

/// A class's limits, expressed relative to the moment work starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassLimits {
    /// How long work of this class may take. `None` means no time limit.
    pub timeout: Option<Duration>,
    /// Poll quota.
    pub poll_quota: u32,
    /// Cost quota. `None` means no cost limit.
    pub cost_quota: Option<u64>,
    /// Scheduling priority; higher is tighter in the runtime's lattice.
    pub priority: u8,
}

impl ClassLimits {
    /// Finite limits.
    #[must_use]
    pub const fn finite(timeout: Duration, poll_quota: u32, cost_quota: u64) -> Self {
        Self {
            timeout: Some(timeout),
            poll_quota,
            cost_quota: Some(cost_quota),
            priority: 0,
        }
    }

    /// The unbounded limits. Admissible only for the node root.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            timeout: None,
            poll_quota: u32::MAX,
            cost_quota: None,
            priority: 0,
        }
    }

    /// Whether these limits leave every dimension unbounded.
    #[must_use]
    pub const fn is_unbounded(self) -> bool {
        self.timeout.is_none() && self.cost_quota.is_none() && self.poll_quota == u32::MAX
    }

    /// Resolve to an absolute budget starting at `now`.
    #[must_use]
    pub fn at(self, now: Time) -> Budget {
        let mut budget = Budget::new()
            .with_poll_quota(self.poll_quota)
            .with_priority(self.priority);
        if let Some(cost) = self.cost_quota {
            budget = budget.with_cost_quota(cost);
        } else {
            budget.cost_quota = None;
        }
        match self.timeout {
            Some(timeout) => budget.tightened_by_timeout(now, timeout),
            None => {
                budget.deadline = None;
                budget
            }
        }
    }
}

/// Whether a budget leaves every dimension unbounded.
///
/// A budget is unbounded when it has no deadline, no cost quota, and the
/// saturating poll quota. That is exactly [`Budget::INFINITE`]'s shape, but
/// this checks the shape rather than comparing to the constant so a budget
/// assembled field-by-field cannot smuggle an infinite default past the gate.
#[must_use]
pub const fn is_unbounded(budget: Budget) -> bool {
    budget.deadline.is_none() && budget.cost_quota.is_none() && budget.poll_quota == u32::MAX
}

/// The finite default limits the node hands to each work class.
///
/// These are profile inputs, not magic numbers scattered through call sites:
/// the whole point is that a reviewer can read one table and see that no work
/// class inherits an accidental infinite budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetPolicy {
    root: ClassLimits,
    unbounded_root: bool,
    request: ClassLimits,
    parser: ClassLimits,
    transfer: ClassLimits,
    database: ClassLimits,
    background: ClassLimits,
    shutdown: ClassLimits,
}

impl BudgetPolicy {
    /// The default finite policy.
    ///
    /// Every class is bounded on time, polls, and cost — including the root:
    /// the default node root is *not* infinite. An operator who wants an
    /// unbounded root must ask for it by name through
    /// [`with_unbounded_root`](Self::with_unbounded_root), which is the
    /// "named node-root policy" the profile requires.
    #[must_use]
    pub const fn finite_defaults() -> Self {
        Self {
            root: ClassLimits::finite(Duration::from_secs(86_400), u32::MAX - 1, u64::MAX / 2),
            unbounded_root: false,
            request: ClassLimits::finite(Duration::from_secs(30), 100_000, 1_000_000),
            parser: ClassLimits::finite(Duration::from_secs(10), 50_000, 500_000),
            transfer: ClassLimits::finite(Duration::from_secs(300), 1_000_000, 50_000_000),
            database: ClassLimits::finite(Duration::from_secs(15), 50_000, 1_000_000),
            background: ClassLimits::finite(Duration::from_secs(3_600), 10_000_000, 100_000_000),
            shutdown: ClassLimits::finite(Duration::from_secs(30), 100_000, 1_000_000),
        }
    }

    /// Select the named unbounded node-root policy.
    ///
    /// This is the only supported way to obtain unbounded limits anywhere in
    /// the node, and it applies to the root region alone. Child classes stay
    /// finite and still meet against the root.
    #[must_use]
    pub const fn with_unbounded_root(mut self) -> Self {
        self.root = ClassLimits::unbounded();
        self.unbounded_root = true;
        self
    }

    /// Override one class's limits.
    ///
    /// # Errors
    ///
    /// [`RuntimeRefusal::UnboundedServiceBudget`] when the supplied limits are
    /// unbounded and the class is not permitted to be.
    pub const fn with_class_limits(
        mut self,
        class: BudgetClass,
        limits: ClassLimits,
    ) -> Result<Self, RuntimeRefusal> {
        if limits.is_unbounded() && !class.may_be_unbounded() {
            return Err(RuntimeRefusal::UnboundedServiceBudget {
                class: class.code(),
            });
        }
        match class {
            BudgetClass::NodeRoot => {
                self.unbounded_root = limits.is_unbounded();
                self.root = limits;
            }
            BudgetClass::Request => self.request = limits,
            BudgetClass::Parser => self.parser = limits,
            BudgetClass::Transfer => self.transfer = limits,
            BudgetClass::Database => self.database = limits,
            BudgetClass::BackgroundController => self.background = limits,
            BudgetClass::ShutdownCleanup => self.shutdown = limits,
        }
        Ok(self)
    }

    /// The limits for a class, before meeting with any parent.
    #[must_use]
    pub const fn limits_for(&self, class: BudgetClass) -> ClassLimits {
        match class {
            BudgetClass::NodeRoot => self.root,
            BudgetClass::Request => self.request,
            BudgetClass::Parser => self.parser,
            BudgetClass::Transfer => self.transfer,
            BudgetClass::Database => self.database,
            BudgetClass::BackgroundController => self.background,
            BudgetClass::ShutdownCleanup => self.shutdown,
        }
    }

    /// The absolute budget for a class, for work starting at `now`.
    #[must_use]
    pub fn budget_at(&self, now: Time, class: BudgetClass) -> Budget {
        self.limits_for(class).at(now)
    }

    /// The absolute budget for a class, met against the node root.
    ///
    /// This is the shape every non-root class actually receives: its own
    /// limits, tightened by whatever the root allows.
    #[must_use]
    pub fn derived_budget_at(&self, now: Time, class: BudgetClass) -> Budget {
        if class == BudgetClass::NodeRoot {
            return self.budget_at(now, class);
        }
        self.budget_at(now, BudgetClass::NodeRoot)
            .meet(self.budget_at(now, class))
    }

    /// Whether the operator selected an unbounded node root.
    #[must_use]
    pub const fn has_unbounded_root(&self) -> bool {
        self.unbounded_root
    }

    /// Verify that no class that must be finite carries unbounded limits.
    ///
    /// This is the invariant behind the acceptance line "no request, parser,
    /// transfer, database, or background controller inherits an accidental
    /// infinite budget". It is checked when a profile is built, so unbounded
    /// service limits cannot reach a running node.
    pub fn verify_finite(&self) -> Result<(), RuntimeRefusal> {
        for class in BudgetClass::finite_classes() {
            let limits = self.limits_for(class);
            if limits.is_unbounded() || limits.timeout.is_none() || limits.cost_quota.is_none() {
                return Err(RuntimeRefusal::UnboundedServiceBudget {
                    class: class.code(),
                });
            }
        }
        Ok(())
    }
}

impl Default for BudgetPolicy {
    fn default() -> Self {
        Self::finite_defaults()
    }
}

/// Compute a child budget from an explicit request, refusing any widening.
///
/// [`asupersync::Budget::meet`] would silently clamp a widening request to the
/// parent's value. Silent clamping hides a construction defect: code that asks
/// for a looser deadline than its caller granted is wrong, and shipping it
/// clamped means the bug survives until the deadline matters. So this refuses
/// first and meets second.
///
/// # Errors
///
/// [`RuntimeRefusal::ChildBudgetWidening`] naming the first dimension, in
/// declaration order, that the request would have relaxed.
pub fn derive_child(parent: Budget, requested: Budget) -> Result<Budget, RuntimeRefusal> {
    if let Some(dimension) = widened_dimension(parent, requested) {
        return Err(RuntimeRefusal::ChildBudgetWidening { dimension });
    }
    Ok(parent.meet(requested))
}

/// The first dimension along which `requested` is looser than `parent`.
///
/// `None` on a dimension means "unconstrained", which is the loosest possible
/// value, so a `None` request under a `Some` parent is a widening.
#[must_use]
pub fn widened_dimension(parent: Budget, requested: Budget) -> Option<BudgetDimension> {
    match (parent.deadline, requested.deadline) {
        (Some(_), None) => return Some(BudgetDimension::Deadline),
        (Some(p), Some(r)) if r > p => return Some(BudgetDimension::Deadline),
        _ => {}
    }
    if requested.poll_quota > parent.poll_quota {
        return Some(BudgetDimension::PollQuota);
    }
    match (parent.cost_quota, requested.cost_quota) {
        (Some(_), None) => return Some(BudgetDimension::CostQuota),
        (Some(p), Some(r)) if r > p => return Some(BudgetDimension::CostQuota),
        _ => {}
    }
    // Higher priority value is the tighter constraint in the runtime lattice,
    // so a lower requested priority is an attempt to escape it.
    if requested.priority < parent.priority {
        return Some(BudgetDimension::Priority);
    }
    None
}

/// Refuse work whose budget is already empty on some dimension.
///
/// # Errors
///
/// [`RuntimeRefusal::BudgetExhausted`] naming the empty dimension.
pub fn ensure_headroom(budget: Budget, now: Time) -> Result<(), RuntimeRefusal> {
    let remaining = budget.remaining(now);
    if budget.deadline.is_some() && remaining.deadline.is_none_or(|left| left == Duration::ZERO) {
        return Err(RuntimeRefusal::BudgetExhausted {
            dimension: Exhaustion::Deadline,
        });
    }
    if remaining.polls == Some(0) {
        return Err(RuntimeRefusal::BudgetExhausted {
            dimension: Exhaustion::PollQuota,
        });
    }
    if remaining.cost == Some(0) {
        return Err(RuntimeRefusal::BudgetExhausted {
            dimension: Exhaustion::CostQuota,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Time = Time::from_secs(1_000);

    fn parent() -> Budget {
        Budget::new()
            .with_deadline(Time::from_secs(1_030))
            .with_poll_quota(1_000)
            .with_cost_quota(10_000)
            .with_priority(10)
    }

    #[test]
    fn class_limits_resolve_relative_to_the_supplied_clock() {
        // The bug this shape exists to prevent: a policy that stores an
        // absolute deadline hands out an already-expired budget on a node
        // that has been up for a while.
        let policy = BudgetPolicy::finite_defaults();

        for now in [Time::from_secs(0), Time::from_secs(1_000_000)] {
            let budget = policy.budget_at(now, BudgetClass::Request);
            let deadline = budget.deadline.expect("requests are time-bounded");
            assert!(
                deadline > now,
                "a request minted at {now:?} must not already be expired ({deadline:?})"
            );
            ensure_headroom(budget, now).expect("a freshly minted request has headroom");
        }
    }

    #[test]
    fn request_timeout_is_exactly_the_configured_duration() {
        let policy = BudgetPolicy::finite_defaults();
        let budget = policy.budget_at(NOW, BudgetClass::Request);
        assert_eq!(budget.deadline, Some(Time::from_secs(1_030)));
    }

    #[test]
    fn no_finite_class_defaults_to_an_infinite_budget() {
        let policy = BudgetPolicy::finite_defaults();
        for class in BudgetClass::finite_classes() {
            let limits = policy.limits_for(class);
            assert!(
                !limits.is_unbounded(),
                "class `{}` must not default to unbounded limits",
                class.code()
            );
            assert!(
                limits.timeout.is_some(),
                "class `{}` must carry a timeout",
                class.code()
            );
            assert!(
                limits.cost_quota.is_some(),
                "class `{}` must carry a cost quota",
                class.code()
            );
            assert!(limits.poll_quota < u32::MAX);

            let budget = policy.budget_at(NOW, class);
            assert!(!is_unbounded(budget));
            assert!(budget.deadline.is_some());
        }
        policy.verify_finite().expect("defaults are finite");
    }

    #[test]
    fn default_node_root_is_finite_and_unbounded_root_is_opt_in() {
        let policy = BudgetPolicy::finite_defaults();
        assert!(!policy.has_unbounded_root());
        assert!(!policy.limits_for(BudgetClass::NodeRoot).is_unbounded());

        // Paired permitted case: the named root policy may be unbounded.
        let named = BudgetPolicy::finite_defaults().with_unbounded_root();
        assert!(named.has_unbounded_root());
        assert!(named.limits_for(BudgetClass::NodeRoot).is_unbounded());
        assert!(is_unbounded(named.budget_at(NOW, BudgetClass::NodeRoot)));
        // ...and selecting it does not loosen any child class.
        named.verify_finite().expect("child classes stay finite");
        assert!(!is_unbounded(
            named.derived_budget_at(NOW, BudgetClass::Request)
        ));
    }

    #[test]
    fn unbounded_limits_for_a_finite_class_are_refused() {
        let refusal = BudgetPolicy::finite_defaults()
            .with_class_limits(BudgetClass::Request, ClassLimits::unbounded())
            .expect_err("an infinite request budget must be refused");
        assert_eq!(
            refusal,
            RuntimeRefusal::UnboundedServiceBudget { class: "request" }
        );

        // Paired permitted case: finite limits for the same class proceed.
        let policy = BudgetPolicy::finite_defaults()
            .with_class_limits(
                BudgetClass::Request,
                ClassLimits::finite(Duration::from_secs(5), 10, 10),
            )
            .expect("finite request limits are permitted");
        assert_eq!(policy.limits_for(BudgetClass::Request).poll_quota, 10);
    }

    #[test]
    fn every_finite_class_is_covered_by_verify_finite() {
        // Planted negative per class, so a future variant silently dropped
        // from the check fails here.
        for class in BudgetClass::finite_classes() {
            let mut policy = BudgetPolicy::finite_defaults();
            match class {
                BudgetClass::Request => policy.request = ClassLimits::unbounded(),
                BudgetClass::Parser => policy.parser = ClassLimits::unbounded(),
                BudgetClass::Transfer => policy.transfer = ClassLimits::unbounded(),
                BudgetClass::Database => policy.database = ClassLimits::unbounded(),
                BudgetClass::BackgroundController => policy.background = ClassLimits::unbounded(),
                BudgetClass::ShutdownCleanup => policy.shutdown = ClassLimits::unbounded(),
                BudgetClass::NodeRoot => unreachable!("not a finite class"),
            }
            assert_eq!(
                policy
                    .verify_finite()
                    .expect_err("unbounded finite class must be refused"),
                RuntimeRefusal::UnboundedServiceBudget {
                    class: class.code()
                }
            );
        }
    }

    #[test]
    fn a_class_missing_only_its_timeout_is_still_refused() {
        // Partial unboundedness is the easy miss: cost and polls are set, so
        // `is_unbounded` is false, but the work can still run forever.
        let mut policy = BudgetPolicy::finite_defaults();
        policy.transfer = ClassLimits {
            timeout: None,
            poll_quota: 1_000,
            cost_quota: Some(1_000),
            priority: 0,
        };
        assert_eq!(
            policy
                .verify_finite()
                .expect_err("no timeout is unbounded time"),
            RuntimeRefusal::UnboundedServiceBudget { class: "transfer" }
        );
    }

    #[test]
    fn child_budget_widening_is_refused_on_every_dimension() {
        let parent = parent();
        let cases = [
            (
                Budget::new()
                    .with_deadline(Time::from_secs(1_060))
                    .with_poll_quota(1_000)
                    .with_cost_quota(10_000)
                    .with_priority(10),
                BudgetDimension::Deadline,
            ),
            (
                Budget::new()
                    .with_poll_quota(1_000)
                    .with_cost_quota(10_000)
                    .with_priority(10),
                BudgetDimension::Deadline,
            ),
            (
                Budget::new()
                    .with_deadline(Time::from_secs(1_030))
                    .with_poll_quota(2_000)
                    .with_cost_quota(10_000)
                    .with_priority(10),
                BudgetDimension::PollQuota,
            ),
            (
                Budget::new()
                    .with_deadline(Time::from_secs(1_030))
                    .with_poll_quota(1_000)
                    .with_cost_quota(20_000)
                    .with_priority(10),
                BudgetDimension::CostQuota,
            ),
            (
                Budget::new()
                    .with_deadline(Time::from_secs(1_030))
                    .with_poll_quota(1_000)
                    .with_priority(10),
                BudgetDimension::CostQuota,
            ),
            (
                Budget::new()
                    .with_deadline(Time::from_secs(1_030))
                    .with_poll_quota(1_000)
                    .with_cost_quota(10_000)
                    .with_priority(1),
                BudgetDimension::Priority,
            ),
        ];

        for (requested, expected) in cases {
            let refusal = derive_child(parent, requested)
                .expect_err("a widening child budget must be refused");
            assert_eq!(
                refusal,
                RuntimeRefusal::ChildBudgetWidening {
                    dimension: expected
                },
                "wrong dimension reported for {requested:?}"
            );
            assert!(!refusal.is_retryable());
        }
    }

    #[test]
    fn child_budget_tightening_is_permitted_and_meets() {
        let parent = parent();
        // Near-identical to the refused cases above, but tighter everywhere.
        let requested = Budget::new()
            .with_deadline(Time::from_secs(1_005))
            .with_poll_quota(100)
            .with_cost_quota(1_000)
            .with_priority(20);

        let child = derive_child(parent, requested).expect("tightening is permitted");
        assert_eq!(child.deadline, Some(Time::from_secs(1_005)));
        assert_eq!(child.poll_quota, 100);
        assert_eq!(child.cost_quota, Some(1_000));
        assert_eq!(child.priority, 20);
    }

    #[test]
    fn equal_child_budget_is_permitted() {
        let parent = parent();
        let child = derive_child(parent, parent).expect("an equal budget is not a widening");
        assert_eq!(child, parent);
    }

    #[test]
    fn derivation_is_transitive_and_monotone() {
        let root = parent();
        let mid = derive_child(
            root,
            Budget::new()
                .with_deadline(Time::from_secs(1_020))
                .with_poll_quota(500)
                .with_cost_quota(5_000)
                .with_priority(10),
        )
        .expect("tighter");
        let leaf = derive_child(
            mid,
            Budget::new()
                .with_deadline(Time::from_secs(1_010))
                .with_poll_quota(250)
                .with_cost_quota(2_500)
                .with_priority(10),
        )
        .expect("tighter still");

        assert!(leaf.deadline <= root.deadline);
        assert!(leaf.poll_quota <= root.poll_quota);
        assert!(leaf.cost_quota <= root.cost_quota);
        assert!(leaf.priority >= root.priority);

        // And the middle budget cannot be re-widened back toward the root.
        assert!(derive_child(leaf, mid).is_err());
    }

    #[test]
    fn derived_class_budgets_never_exceed_the_root() {
        let policy = BudgetPolicy::finite_defaults();
        for class in BudgetClass::finite_classes() {
            let root = policy.budget_at(NOW, BudgetClass::NodeRoot);
            let derived = policy.derived_budget_at(NOW, class);
            assert!(derived.poll_quota <= root.poll_quota, "{}", class.code());
            assert!(derived.deadline <= root.deadline, "{}", class.code());
            assert!(derived.cost_quota <= root.cost_quota, "{}", class.code());
            assert!(!is_unbounded(derived));
        }
    }

    #[test]
    fn a_class_looser_than_the_root_is_clamped_by_derivation() {
        // The background controller's hour is longer than a five-minute root.
        let policy = BudgetPolicy::finite_defaults()
            .with_class_limits(
                BudgetClass::NodeRoot,
                ClassLimits::finite(Duration::from_secs(300), 1_000, 1_000),
            )
            .expect("a finite root is permitted");

        let derived = policy.derived_budget_at(NOW, BudgetClass::BackgroundController);
        assert_eq!(derived.deadline, Some(Time::from_secs(1_300)));
        assert_eq!(derived.poll_quota, 1_000);
        assert_eq!(derived.cost_quota, Some(1_000));
    }

    #[test]
    fn exhausted_dimensions_are_refused_and_headroom_proceeds() {
        let now = Time::from_secs(1_000);

        let no_polls = Budget::new()
            .with_deadline(Time::from_secs(1_030))
            .with_poll_quota(0)
            .with_cost_quota(10);
        assert_eq!(
            ensure_headroom(no_polls, now).expect_err("no polls left"),
            RuntimeRefusal::BudgetExhausted {
                dimension: Exhaustion::PollQuota
            }
        );

        let no_cost = Budget::new()
            .with_deadline(Time::from_secs(1_030))
            .with_poll_quota(10)
            .with_cost_quota(0);
        assert_eq!(
            ensure_headroom(no_cost, now).expect_err("no cost left"),
            RuntimeRefusal::BudgetExhausted {
                dimension: Exhaustion::CostQuota
            }
        );

        let past_deadline = Budget::new()
            .with_deadline(Time::from_secs(999))
            .with_poll_quota(10)
            .with_cost_quota(10);
        assert_eq!(
            ensure_headroom(past_deadline, now).expect_err("deadline passed"),
            RuntimeRefusal::BudgetExhausted {
                dimension: Exhaustion::Deadline
            }
        );

        // Paired permitted case: headroom on every dimension.
        let healthy = Budget::new()
            .with_deadline(Time::from_secs(1_030))
            .with_poll_quota(10)
            .with_cost_quota(10);
        ensure_headroom(healthy, now).expect("headroom on every dimension");
    }

    #[test]
    fn unbounded_shape_is_detected_without_comparing_to_the_constant() {
        assert!(is_unbounded(Budget::INFINITE));
        let assembled = Budget {
            deadline: None,
            poll_quota: u32::MAX,
            cost_quota: None,
            priority: 3,
        };
        assert!(is_unbounded(assembled));
        assert!(!is_unbounded(
            Budget::INFINITE.with_poll_quota(u32::MAX - 1)
        ));
    }
}
