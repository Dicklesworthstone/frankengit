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

/// Whether a budget leaves any dimension unbounded.
///
/// A budget is unbounded when it has no deadline, no cost quota, and the
/// saturating poll quota. That is exactly [`Budget::INFINITE`]'s shape, but
/// this checks the shape rather than comparing to the constant so a budget
/// assembled field-by-field cannot smuggle an infinite default past the gate.
#[must_use]
pub fn is_unbounded(budget: Budget) -> bool {
    budget.deadline.is_none() && budget.cost_quota.is_none() && budget.poll_quota == u32::MAX
}

/// The finite default budgets the node hands to each work class.
///
/// These are profile inputs, not magic numbers scattered through call sites:
/// the whole point is that a reviewer can read one table and see that no work
/// class inherits an accidental infinite budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetPolicy {
    /// Root budget. May be unbounded only when `unbounded_root` is set.
    root: Budget,
    /// Whether the operator explicitly selected an unbounded node root.
    unbounded_root: bool,
    request: Budget,
    parser: Budget,
    transfer: Budget,
    database: Budget,
    background: Budget,
    shutdown: Budget,
}

impl BudgetPolicy {
    /// The default finite policy.
    ///
    /// Every class is bounded on at least the deadline and poll dimensions,
    /// including the root: the default node root is *not* infinite. An
    /// operator who wants an unbounded root must ask for it by name through
    /// [`with_unbounded_root`](Self::with_unbounded_root), which is the
    /// "named node-root policy" the profile requires.
    #[must_use]
    pub fn finite_defaults() -> Self {
        Self {
            root: Budget::new()
                .with_deadline(Time::from_secs(86_400))
                .with_poll_quota(u32::MAX - 1)
                .with_cost_quota(u64::MAX / 2),
            unbounded_root: false,
            request: Budget::new()
                .with_deadline(Time::from_secs(30))
                .with_poll_quota(100_000)
                .with_cost_quota(1_000_000),
            parser: Budget::new()
                .with_deadline(Time::from_secs(10))
                .with_poll_quota(50_000)
                .with_cost_quota(500_000),
            transfer: Budget::new()
                .with_deadline(Time::from_secs(300))
                .with_poll_quota(1_000_000)
                .with_cost_quota(50_000_000),
            database: Budget::new()
                .with_deadline(Time::from_secs(15))
                .with_poll_quota(50_000)
                .with_cost_quota(1_000_000),
            background: Budget::new()
                .with_deadline(Time::from_secs(3_600))
                .with_poll_quota(10_000_000)
                .with_cost_quota(100_000_000),
            shutdown: Budget::new()
                .with_deadline(Time::from_secs(30))
                .with_poll_quota(100_000)
                .with_cost_quota(1_000_000),
        }
    }

    /// Select the named unbounded node-root policy.
    ///
    /// This is the only supported way to obtain [`Budget::INFINITE`] anywhere
    /// in the node, and it applies to the root region alone. Child classes
    /// stay finite and still meet against the root.
    #[must_use]
    pub const fn with_unbounded_root(mut self) -> Self {
        self.root = Budget::INFINITE;
        self.unbounded_root = true;
        self
    }

    /// Override one finite class budget.
    ///
    /// Returns [`RuntimeRefusal::UnboundedServiceBudget`] when the supplied
    /// budget is unbounded and the class is not permitted to be.
    pub fn with_class_budget(
        mut self,
        class: BudgetClass,
        budget: Budget,
    ) -> Result<Self, RuntimeRefusal> {
        if is_unbounded(budget) && !class.may_be_unbounded() {
            return Err(RuntimeRefusal::UnboundedServiceBudget { class: class.code() });
        }
        match class {
            BudgetClass::NodeRoot => {
                self.unbounded_root = is_unbounded(budget);
                self.root = budget;
            }
            BudgetClass::Request => self.request = budget,
            BudgetClass::Parser => self.parser = budget,
            BudgetClass::Transfer => self.transfer = budget,
            BudgetClass::Database => self.database = budget,
            BudgetClass::BackgroundController => self.background = budget,
            BudgetClass::ShutdownCleanup => self.shutdown = budget,
        }
        Ok(self)
    }

    /// The budget for a class, before meeting with any parent.
    #[must_use]
    pub const fn budget_for(&self, class: BudgetClass) -> Budget {
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

    /// Whether the operator selected an unbounded node root.
    #[must_use]
    pub const fn has_unbounded_root(&self) -> bool {
        self.unbounded_root
    }

    /// Verify that no class that must be finite carries an unbounded budget.
    ///
    /// This is the invariant behind the acceptance line "no request, parser,
    /// transfer, database, or background controller inherits an accidental
    /// infinite budget". It is checked when a profile is built, so an
    /// unbounded service budget cannot reach a running node.
    pub fn verify_finite(&self) -> Result<(), RuntimeRefusal> {
        for class in BudgetClass::finite_classes() {
            if is_unbounded(self.budget_for(class)) {
                return Err(RuntimeRefusal::UnboundedServiceBudget { class: class.code() });
            }
        }
        Ok(())
    }

    /// Derive the effective budget for a class beneath a parent budget.
    ///
    /// The class default is met against the parent, so a child can only ever
    /// be tighter. This never refuses: the class defaults are authored to be
    /// tighter than any legitimate root, and meeting is total.
    #[must_use]
    pub fn derive(&self, parent: Budget, class: BudgetClass) -> Budget {
        parent.meet(self.budget_for(class))
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
    if remaining.deadline.is_some_and(|left| left.is_zero()) {
        return Err(RuntimeRefusal::BudgetExhausted {
            dimension: Exhaustion::Deadline,
        });
    }
    if budget.deadline.is_some() && remaining.deadline.is_none() {
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

    fn parent() -> Budget {
        Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(1_000)
            .with_cost_quota(10_000)
            .with_priority(10)
    }

    #[test]
    fn no_finite_class_defaults_to_an_infinite_budget() {
        let policy = BudgetPolicy::finite_defaults();
        // The acceptance line, checked exhaustively over every finite class.
        for class in BudgetClass::finite_classes() {
            let budget = policy.budget_for(class);
            assert!(
                !is_unbounded(budget),
                "class `{}` must not default to an unbounded budget",
                class.code()
            );
            assert!(
                budget.deadline.is_some(),
                "class `{}` must carry a deadline",
                class.code()
            );
            assert!(
                budget.cost_quota.is_some(),
                "class `{}` must carry a cost quota",
                class.code()
            );
            assert!(budget.poll_quota < u32::MAX);
        }
        policy.verify_finite().expect("defaults are finite");
    }

    #[test]
    fn default_node_root_is_finite_and_unbounded_root_is_opt_in() {
        let policy = BudgetPolicy::finite_defaults();
        assert!(!policy.has_unbounded_root());
        assert!(!is_unbounded(policy.budget_for(BudgetClass::NodeRoot)));

        // Paired permitted case: the named root policy may be unbounded.
        let named = BudgetPolicy::finite_defaults().with_unbounded_root();
        assert!(named.has_unbounded_root());
        assert!(is_unbounded(named.budget_for(BudgetClass::NodeRoot)));
        // ...and selecting it does not loosen any child class.
        named.verify_finite().expect("child classes stay finite");
    }

    #[test]
    fn unbounded_budget_for_a_finite_class_is_refused() {
        let refusal = BudgetPolicy::finite_defaults()
            .with_class_budget(BudgetClass::Request, Budget::INFINITE)
            .expect_err("an infinite request budget must be refused");
        assert_eq!(
            refusal,
            RuntimeRefusal::UnboundedServiceBudget { class: "request" }
        );

        // Paired permitted case: a finite override of the same class proceeds.
        let policy = BudgetPolicy::finite_defaults()
            .with_class_budget(
                BudgetClass::Request,
                Budget::new()
                    .with_deadline(Time::from_secs(5))
                    .with_poll_quota(10)
                    .with_cost_quota(10),
            )
            .expect("a finite request budget is permitted");
        assert_eq!(policy.budget_for(BudgetClass::Request).poll_quota, 10);
    }

    #[test]
    fn every_finite_class_is_covered_by_verify_finite() {
        // Planted negative for each class individually, so a future variant
        // that is silently dropped from the check fails this test.
        for class in BudgetClass::finite_classes() {
            let mut policy = BudgetPolicy::finite_defaults();
            match class {
                BudgetClass::Request => policy.request = Budget::INFINITE,
                BudgetClass::Parser => policy.parser = Budget::INFINITE,
                BudgetClass::Transfer => policy.transfer = Budget::INFINITE,
                BudgetClass::Database => policy.database = Budget::INFINITE,
                BudgetClass::BackgroundController => policy.background = Budget::INFINITE,
                BudgetClass::ShutdownCleanup => policy.shutdown = Budget::INFINITE,
                BudgetClass::NodeRoot => unreachable!("not a finite class"),
            }
            let refusal = policy
                .verify_finite()
                .expect_err("an unbounded finite class must be refused");
            assert_eq!(
                refusal,
                RuntimeRefusal::UnboundedServiceBudget { class: class.code() }
            );
        }
    }

    #[test]
    fn child_budget_widening_is_refused_on_every_dimension() {
        let parent = parent();

        let cases = [
            (
                Budget::new()
                    .with_deadline(Time::from_secs(60))
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
                    .with_deadline(Time::from_secs(30))
                    .with_poll_quota(2_000)
                    .with_cost_quota(10_000)
                    .with_priority(10),
                BudgetDimension::PollQuota,
            ),
            (
                Budget::new()
                    .with_deadline(Time::from_secs(30))
                    .with_poll_quota(1_000)
                    .with_cost_quota(20_000)
                    .with_priority(10),
                BudgetDimension::CostQuota,
            ),
            (
                Budget::new()
                    .with_deadline(Time::from_secs(30))
                    .with_poll_quota(1_000)
                    .with_priority(10),
                BudgetDimension::CostQuota,
            ),
            (
                Budget::new()
                    .with_deadline(Time::from_secs(30))
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
        // Near-identical to the refused cases above, but tighter on every
        // dimension, so it must proceed.
        let requested = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(100)
            .with_cost_quota(1_000)
            .with_priority(20);

        let child = derive_child(parent, requested).expect("tightening is permitted");
        assert_eq!(child.deadline, Some(Time::from_secs(5)));
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
                .with_deadline(Time::from_secs(20))
                .with_poll_quota(500)
                .with_cost_quota(5_000)
                .with_priority(10),
        )
        .expect("tighter");
        let leaf = derive_child(
            mid,
            Budget::new()
                .with_deadline(Time::from_secs(10))
                .with_poll_quota(250)
                .with_cost_quota(2_500)
                .with_priority(10),
        )
        .expect("tighter still");

        // A grandchild can never exceed the root on any dimension.
        assert!(leaf.deadline <= root.deadline);
        assert!(leaf.poll_quota <= root.poll_quota);
        assert!(leaf.cost_quota <= root.cost_quota);
        assert!(leaf.priority >= root.priority);

        // And the middle budget cannot be re-widened back toward the root.
        assert!(derive_child(leaf, mid).is_err());
    }

    #[test]
    fn class_derivation_meets_against_the_parent() {
        let policy = BudgetPolicy::finite_defaults();
        let tight_parent = Budget::new()
            .with_deadline(Time::from_secs(1))
            .with_poll_quota(7)
            .with_cost_quota(9);

        for class in BudgetClass::finite_classes() {
            let derived = policy.derive(tight_parent, class);
            assert!(derived.poll_quota <= 7, "class {} exceeded parent", class.code());
            assert!(derived.deadline <= Some(Time::from_secs(1)));
            assert!(derived.cost_quota <= Some(9));
        }
    }

    #[test]
    fn exhausted_dimensions_are_refused_and_headroom_proceeds() {
        let now = Time::from_secs(10);

        let no_polls = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(0)
            .with_cost_quota(10);
        assert_eq!(
            ensure_headroom(no_polls, now).expect_err("no polls left"),
            RuntimeRefusal::BudgetExhausted {
                dimension: Exhaustion::PollQuota
            }
        );

        let no_cost = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(10)
            .with_cost_quota(0);
        assert_eq!(
            ensure_headroom(no_cost, now).expect_err("no cost left"),
            RuntimeRefusal::BudgetExhausted {
                dimension: Exhaustion::CostQuota
            }
        );

        let past_deadline = Budget::new()
            .with_deadline(Time::from_secs(1))
            .with_poll_quota(10)
            .with_cost_quota(10);
        assert_eq!(
            ensure_headroom(past_deadline, now).expect_err("deadline passed"),
            RuntimeRefusal::BudgetExhausted {
                dimension: Exhaustion::Deadline
            }
        );

        // Paired permitted case: a budget with headroom on every dimension.
        let healthy = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(10)
            .with_cost_quota(10);
        ensure_headroom(healthy, now).expect("headroom on every dimension");
    }

    #[test]
    fn unbounded_shape_is_detected_without_comparing_to_the_constant() {
        assert!(is_unbounded(Budget::INFINITE));
        // Assembled field-by-field rather than via the constant.
        let assembled = Budget {
            deadline: None,
            poll_quota: u32::MAX,
            cost_quota: None,
            priority: 3,
        };
        assert!(is_unbounded(assembled));
        // One bounded dimension is enough to be bounded.
        assert!(!is_unbounded(Budget::INFINITE.with_poll_quota(u32::MAX - 1)));
    }
}
