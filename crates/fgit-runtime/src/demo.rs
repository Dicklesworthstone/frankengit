//! One real service exercising the whole profile.
//!
//! The ownership chooser the integration profile describes is: request fan-out
//! uses a child [`Scope`](asupersync::Scope); dynamic homogeneous work uses a
//! bounded [`JoinSet`]; stateful protocols use actors; resource-specific
//! cleanup uses RAII plus an obligation. This service is the second shape — a
//! batch of independent, homogeneous lookups — so it uses a bounded `JoinSet`
//! inside a child scope, and nothing else. Picking a shape by ownership rather
//! than convenience is the point.
//!
//! It is a demonstration in the sense that it is small, not in the sense that
//! it is fake: the resolver is supplied by the caller, the fan-out is really
//! bounded, the work really runs on the node's scheduler, and every member's
//! outcome keeps its own arm.

use asupersync::cx::Cx;

use crate::adapter::ServiceOutcome;
use crate::refuse::RuntimeRefusal;

/// A resolved reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The reference name that was resolved.
    pub name: String,
    /// The target the reference pointed at.
    pub target: String,
}

/// Why one reference failed to resolve.
///
/// This is a domain refusal, distinct from cancellation and from a contained
/// panic. Keeping it a separate type is what lets the batch report "three
/// resolved, one unknown, one cancelled" instead of "four failed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// No such reference.
    Unknown(String),
    /// The reference name is not well formed.
    Malformed {
        /// The offending name.
        name: String,
        /// Why it was rejected.
        reason: &'static str,
    },
}

impl core::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown(name) => write!(f, "unknown reference `{name}`"),
            Self::Malformed { name, reason } => {
                write!(f, "malformed reference `{name}`: {reason}")
            }
        }
    }
}

impl std::error::Error for ResolveError {}

/// The outcome of one batch member.
pub type MemberOutcome = ServiceOutcome<Resolved, ResolveError>;

/// Resolve a batch of reference names with bounded concurrency.
///
/// Each name is resolved by `resolve` on the node's scheduler inside a child
/// scope, so the whole batch is one quiescence point: when this returns, every
/// member has finished or been cancelled, and nothing is still running.
///
/// Admission is bounded *before* any work is spawned. Refusing up front is the
/// difference between a bounded service and one that queues an unbounded batch
/// and discovers the problem under load.
///
/// # Errors
///
/// - [`RuntimeRefusal::AdmissionRefused`] when the batch exceeds `limit`.
/// - [`RuntimeRefusal::RuntimeUnavailable`] when the context carries no spawn
///   gateway for the child region.
pub async fn resolve_batch<R, Fut>(
    cx: &Cx,
    limit: usize,
    names: Vec<String>,
    resolve: R,
) -> Result<Vec<MemberOutcome>, RuntimeRefusal>
where
    R: Fn(String) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<Resolved, ResolveError>> + Send + 'static,
{
    if names.len() > limit {
        return Err(RuntimeRefusal::AdmissionRefused { limit });
    }
    if names.is_empty() {
        return Ok(Vec::new());
    }

    let scope = cx.scope();
    let mut set: asupersync::combinator::JoinSet<
        '_,
        Resolved,
        ResolveError,
        asupersync::types::policy::FailFast,
    > = asupersync::combinator::JoinSet::new(&scope);

    for name in names {
        let resolve = resolve.clone();
        set.spawn(cx, move |_member_cx: Cx| async move { resolve(name).await })
            .map_err(|_| RuntimeRefusal::RuntimeUnavailable)?;
    }

    // `join_all` yields one four-valued Outcome per member. Lifting each one
    // separately is what keeps a cancelled member distinguishable from a
    // member that returned a domain error.
    Ok(set
        .join_all(cx)
        .await
        .into_iter()
        .map(ServiceOutcome::from_outcome)
        .collect())
}

/// Classify a batch result into counts per outcome arm.
///
/// Reporting a batch as a single success/failure bit is the collapse this
/// crate exists to prevent, so the summary keeps the arms apart too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BatchSummary {
    /// Members that produced a value.
    pub succeeded: usize,
    /// Members that reached a typed domain refusal.
    pub refused: usize,
    /// Members that were cancelled.
    pub cancelled: usize,
    /// Members whose panic was contained.
    pub panicked: usize,
}

impl BatchSummary {
    /// Summarize a batch result.
    #[must_use]
    pub fn of(outcomes: &[MemberOutcome]) -> Self {
        let mut summary = Self::default();
        for outcome in outcomes {
            match outcome.classify() {
                crate::adapter::OutcomeClass::Success => summary.succeeded += 1,
                crate::adapter::OutcomeClass::Refusal => summary.refused += 1,
                crate::adapter::OutcomeClass::Cancelled => summary.cancelled += 1,
                crate::adapter::OutcomeClass::Panicked => summary.panicked += 1,
            }
        }
        summary
    }

    /// Total members accounted for.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.succeeded + self.refused + self.cancelled + self.panicked
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::adapter::OutcomeClass;
    use crate::boot::{ProfileClass, RuntimeProfile};
    use crate::meter::BudgetClass;

    /// A real resolver over a fixed reference table.
    ///
    /// Concrete inputs and concrete answers: `main` and `dev` exist, `gone`
    /// does not, and a name with a space is malformed.
    async fn table_resolver(name: String) -> Result<Resolved, ResolveError> {
        if name.contains(' ') {
            return Err(ResolveError::Malformed {
                name,
                reason: "reference names may not contain spaces",
            });
        }
        match name.as_str() {
            "refs/heads/main" => Ok(Resolved {
                name,
                target: "0f1e2d3c4b5a69788796a5b4c3d2e1f009182736".to_owned(),
            }),
            "refs/heads/dev" => Ok(Resolved {
                name,
                target: "1122334455667788990011223344556677889900".to_owned(),
            }),
            _ => Err(ResolveError::Unknown(name)),
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn batch_resolution_preserves_each_member_arm() {
        let node = RuntimeProfile::deterministic().build().expect("builds");
        let cx = node.request_cx(BudgetClass::Request);

        let outcomes = node
            .block_on(async {
                resolve_batch(
                    &cx,
                    8,
                    names(&["refs/heads/main", "refs/heads/gone", "bad name"]),
                    table_resolver,
                )
                .await
            })
            .expect("the batch is within the admission bound");

        assert_eq!(outcomes.len(), 3);

        let summary = BatchSummary::of(&outcomes);
        assert_eq!(summary.total(), 3);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.refused, 2);
        assert_eq!(summary.panicked, 0);

        // The successful member really carries its resolved target.
        let resolved = outcomes
            .iter()
            .find(|outcome| outcome.classify() == OutcomeClass::Success)
            .cloned()
            .and_then(ServiceOutcome::success)
            .expect("one member resolved");
        assert_eq!(resolved.name, "refs/heads/main");
        assert_eq!(resolved.target, "0f1e2d3c4b5a69788796a5b4c3d2e1f009182736");

        // And the two refusals kept their distinct domain reasons.
        let mut reasons: Vec<String> = outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                ServiceOutcome::Refusal(error) => Some(error.to_string()),
                _ => None,
            })
            .collect();
        reasons.sort();
        assert_eq!(
            reasons,
            vec![
                "malformed reference `bad name`: reference names may not contain spaces".to_owned(),
                "unknown reference `refs/heads/gone`".to_owned(),
            ]
        );

        drop(cx);
        assert!(node.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn batch_admission_is_bounded_before_any_work_is_spawned() {
        let node = RuntimeProfile::deterministic().build().expect("builds");
        let cx = node.request_cx(BudgetClass::Request);

        let refusal = node
            .block_on(async {
                resolve_batch(
                    &cx,
                    2,
                    names(&["refs/heads/main", "refs/heads/dev", "refs/heads/gone"]),
                    table_resolver,
                )
                .await
            })
            .expect_err("three members exceed a bound of two");
        assert_eq!(refusal, RuntimeRefusal::AdmissionRefused { limit: 2 });
        assert!(refusal.is_retryable());

        // Paired permitted case: the same batch exactly at the bound.
        let outcomes = node
            .block_on(async {
                resolve_batch(
                    &cx,
                    2,
                    names(&["refs/heads/main", "refs/heads/dev"]),
                    table_resolver,
                )
                .await
            })
            .expect("a batch at the bound is admitted");
        assert_eq!(BatchSummary::of(&outcomes).succeeded, 2);

        drop(cx);
        assert!(node.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn an_empty_batch_is_a_no_op() {
        let node = RuntimeProfile::deterministic().build().expect("builds");
        let cx = node.request_cx(BudgetClass::Request);
        let outcomes = node
            .block_on(async { resolve_batch(&cx, 4, Vec::new(), table_resolver).await })
            .expect("an empty batch is admitted");
        assert!(outcomes.is_empty());
        assert_eq!(BatchSummary::of(&outcomes).total(), 0);
        drop(cx);
        assert!(node.join_root(Duration::from_secs(5)));
    }

    #[test]
    fn the_same_protocol_yields_the_same_outcomes_under_two_profiles() {
        // The acceptance line: one demo protocol, two profiles, identical
        // typed outcomes. Production uses several workers with parking on;
        // the deterministic profile pins one worker with parking off.
        let batch = names(&[
            "refs/heads/main",
            "refs/heads/dev",
            "refs/heads/gone",
            "bad name",
        ]);

        let run = |profile: RuntimeProfile| {
            let class = profile.class();
            let node = profile.build().expect("profile builds");
            let cx = node.request_cx(BudgetClass::Request);
            let outcomes = node
                .block_on({
                    let batch = batch.clone();
                    async move { resolve_batch(&cx, 8, batch, table_resolver).await }
                })
                .expect("within the admission bound");

            let mut classes: Vec<&'static str> = outcomes
                .iter()
                .map(|outcome| outcome.classify().code())
                .collect();
            classes.sort_unstable();

            let summary = BatchSummary::of(&outcomes);
            assert!(node.join_root(Duration::from_secs(5)));
            (class, classes, summary)
        };

        let (production_class, production_classes, production_summary) =
            run(RuntimeProfile::production(4));
        let (deterministic_class, deterministic_classes, deterministic_summary) =
            run(RuntimeProfile::deterministic());

        assert_eq!(production_class, ProfileClass::Production);
        assert_eq!(deterministic_class, ProfileClass::Deterministic);
        assert_eq!(production_classes, deterministic_classes);
        assert_eq!(production_summary, deterministic_summary);
        assert_eq!(production_summary.succeeded, 2);
        assert_eq!(production_summary.refused, 2);
        assert_eq!(production_summary.cancelled, 0);
        assert_eq!(production_summary.panicked, 0);
    }

    #[test]
    fn batch_members_run_under_a_bounded_request_budget() {
        let node = RuntimeProfile::deterministic().build().expect("builds");
        let cx = node.request_cx(BudgetClass::Request);

        // The request context is bounded on every dimension before the batch
        // is even admitted.
        assert!(!crate::meter::is_unbounded(cx.budget()));
        assert!(cx.budget().deadline.is_some());

        let outcomes = node
            .block_on(async {
                resolve_batch(&cx, 4, names(&["refs/heads/main"]), table_resolver).await
            })
            .expect("admitted");
        assert_eq!(BatchSummary::of(&outcomes).succeeded, 1);
        drop(cx);
        assert!(node.join_root(Duration::from_secs(5)));
    }
}
