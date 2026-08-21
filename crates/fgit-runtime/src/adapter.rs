//! The service boundary that keeps all four outcome arms distinct.
//!
//! Asupersync's [`Outcome`] is four-valued: success, domain error, cancelled,
//! panicked. The integration profile requires that distinction to *survive
//! through service internals* — the usual failure mode is an adapter that
//! does `outcome.into_result()` somewhere in the middle, after which a
//! cancelled request and a failed request are the same thing and a contained
//! panic looks like a domain error.
//!
//! So this crate's service boundary carries a [`ServiceOutcome`], which is the
//! four arms plus one thing Asupersync cannot know: whether an externally
//! observed effect might already have happened when the cancellation landed.
//! The profile is explicit that after a possible head CAS or other externally
//! observed effect, a caller must resolve the immutable outcome rather than
//! report "not committed". [`CommitAmbiguity`] is how that requirement is
//! carried instead of assumed.

use asupersync::types::PanicPayload;
use asupersync::{CancelReason, Outcome};

/// The four-way classification, with no collapsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OutcomeClass {
    /// The operation produced its value.
    Success,
    /// The operation reached a typed domain error or refusal.
    Refusal,
    /// The operation was cancelled.
    Cancelled,
    /// The operation panicked and the panic was contained.
    Panicked,
}

impl OutcomeClass {
    /// Stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Refusal => "refusal",
            Self::Cancelled => "cancelled",
            Self::Panicked => "panicked",
        }
    }

    /// Every class, for exhaustive checks.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::Success,
            Self::Refusal,
            Self::Cancelled,
            Self::Panicked,
        ]
    }
}

/// Whether an externally observed effect may already have taken place.
///
/// This is the difference between "the client disconnected, nothing happened"
/// and "the client disconnected, and a ref may or may not have moved". The
/// second is not reportable as failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitAmbiguity {
    /// No externally observed effect had been attempted. Cancellation here
    /// genuinely proves nothing was published.
    None,
    /// An externally observed effect was in flight. The immutable outcome must
    /// be resolved by looking up this idempotency key; the caller may not
    /// assume either direction.
    Possible {
        /// The idempotency key under which the effect can be resolved.
        idempotency_key: String,
    },
}

impl CommitAmbiguity {
    /// Whether the caller must resolve the outcome before reporting.
    #[must_use]
    pub const fn must_resolve(&self) -> bool {
        matches!(self, Self::Possible { .. })
    }

    /// The idempotency key, when resolution is required.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        match self {
            Self::None => None,
            Self::Possible { idempotency_key } => Some(idempotency_key),
        }
    }
}

/// A service result that preserves every arm.
///
/// There is deliberately no `into_result`, no `unwrap_or_default`, and no
/// `ok()` that folds cancellation or panic into the error arm. Converting to
/// a two-valued type is a decision a caller must make explicitly and
/// visibly, which is what [`ServiceOutcome::classify`] plus a `match` is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceOutcome<T, E> {
    /// Success.
    Success(T),
    /// A typed domain error or refusal.
    Refusal(E),
    /// Cancellation, with its cause and commit-ambiguity metadata.
    Cancelled {
        /// Why the work was cancelled.
        reason: CancelReason,
        /// Whether an externally observed effect may already have landed.
        ambiguity: CommitAmbiguity,
    },
    /// A contained panic. This is a containment event, not a domain error.
    Panicked(PanicPayload),
}

impl<T, E> ServiceOutcome<T, E> {
    /// Lift a runtime [`Outcome`] with no externally observed effect in
    /// flight.
    ///
    /// Use this for pure work. If the operation could have published anything
    /// observable, use [`from_outcome_after_effect`](Self::from_outcome_after_effect)
    /// so the ambiguity is carried instead of silently lost.
    #[must_use]
    pub fn from_outcome(outcome: Outcome<T, E>) -> Self {
        Self::lift(outcome, CommitAmbiguity::None)
    }

    /// Lift a runtime [`Outcome`] for work that had an externally observed
    /// effect in flight.
    ///
    /// A cancellation becomes [`CommitAmbiguity::Possible`], so the caller
    /// cannot report "not committed" without resolving the key first.
    #[must_use]
    pub fn from_outcome_after_effect(
        outcome: Outcome<T, E>,
        idempotency_key: impl Into<String>,
    ) -> Self {
        Self::lift(
            outcome,
            CommitAmbiguity::Possible {
                idempotency_key: idempotency_key.into(),
            },
        )
    }

    fn lift(outcome: Outcome<T, E>, ambiguity: CommitAmbiguity) -> Self {
        match outcome {
            Outcome::Ok(value) => Self::Success(value),
            Outcome::Err(error) => Self::Refusal(error),
            Outcome::Cancelled(reason) => Self::Cancelled { reason, ambiguity },
            Outcome::Panicked(payload) => Self::Panicked(payload),
        }
    }

    /// The four-way classification.
    #[must_use]
    pub const fn classify(&self) -> OutcomeClass {
        match self {
            Self::Success(_) => OutcomeClass::Success,
            Self::Refusal(_) => OutcomeClass::Refusal,
            Self::Cancelled { .. } => OutcomeClass::Cancelled,
            Self::Panicked(_) => OutcomeClass::Panicked,
        }
    }

    /// The commit-ambiguity metadata, when this is a cancellation.
    #[must_use]
    pub const fn ambiguity(&self) -> Option<&CommitAmbiguity> {
        match self {
            Self::Cancelled { ambiguity, .. } => Some(ambiguity),
            _ => None,
        }
    }

    /// Whether the caller must resolve an immutable outcome before reporting.
    #[must_use]
    pub const fn must_resolve_commit(&self) -> bool {
        match self {
            Self::Cancelled { ambiguity, .. } => ambiguity.must_resolve(),
            _ => false,
        }
    }

    /// Transform the success value, leaving every other arm untouched.
    ///
    /// This is the shape every combinator in this crate takes: the non-success
    /// arms pass through structurally, so no transformation step can quietly
    /// reclassify a cancellation.
    #[must_use]
    pub fn map_success<U, F: FnOnce(T) -> U>(self, f: F) -> ServiceOutcome<U, E> {
        match self {
            Self::Success(value) => ServiceOutcome::Success(f(value)),
            Self::Refusal(error) => ServiceOutcome::Refusal(error),
            Self::Cancelled { reason, ambiguity } => {
                ServiceOutcome::Cancelled { reason, ambiguity }
            }
            Self::Panicked(payload) => ServiceOutcome::Panicked(payload),
        }
    }

    /// Transform the refusal value, leaving every other arm untouched.
    #[must_use]
    pub fn map_refusal<F2, F: FnOnce(E) -> F2>(self, f: F) -> ServiceOutcome<T, F2> {
        match self {
            Self::Success(value) => ServiceOutcome::Success(value),
            Self::Refusal(error) => ServiceOutcome::Refusal(f(error)),
            Self::Cancelled { reason, ambiguity } => {
                ServiceOutcome::Cancelled { reason, ambiguity }
            }
            Self::Panicked(payload) => ServiceOutcome::Panicked(payload),
        }
    }

    /// Attach commit ambiguity to an already-lifted cancellation.
    ///
    /// Used when the effect is issued after the outcome was produced upstream,
    /// e.g. a head CAS attempted inside a service whose caller lifted the
    /// outcome earlier.
    #[must_use]
    pub fn with_effect_ambiguity(self, idempotency_key: impl Into<String>) -> Self {
        match self {
            Self::Cancelled { reason, .. } => Self::Cancelled {
                reason,
                ambiguity: CommitAmbiguity::Possible {
                    idempotency_key: idempotency_key.into(),
                },
            },
            other => other,
        }
    }

    /// Convert back to a runtime [`Outcome`].
    ///
    /// Lossless on the four arms. Commit-ambiguity metadata does not exist in
    /// the runtime type, so this is only appropriate where no effect was in
    /// flight; [`must_resolve_commit`](Self::must_resolve_commit) tells the
    /// caller when it is not.
    #[must_use]
    pub fn into_outcome(self) -> Outcome<T, E> {
        match self {
            Self::Success(value) => Outcome::Ok(value),
            Self::Refusal(error) => Outcome::Err(error),
            Self::Cancelled { reason, .. } => Outcome::Cancelled(reason),
            Self::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// The success value, if this succeeded.
    #[must_use]
    pub fn success(self) -> Option<T> {
        match self {
            Self::Success(value) => Some(value),
            _ => None,
        }
    }
}

/// Lift the `Result` a spawned task body returns into a service outcome.
///
/// Asupersync task bodies return `Result<T, E>`; the runtime supplies the
/// cancelled and panicked arms when the task is joined. This is the seam where
/// a service's own two-valued result meets the runtime's four-valued one, and
/// it exists so the mapping is written once rather than at every call site.
#[must_use]
pub fn lift_task_result<T, E>(result: Result<T, E>) -> ServiceOutcome<T, E> {
    match result {
        Ok(value) => ServiceOutcome::Success(value),
        Err(error) => ServiceOutcome::Refusal(error),
    }
}

#[cfg(test)]
mod tests {
    use asupersync::CancelKind;

    use super::*;

    fn cancelled_outcome() -> Outcome<u32, &'static str> {
        Outcome::Cancelled(CancelReason::new(CancelKind::Shutdown))
    }

    #[test]
    fn all_four_arms_survive_the_service_boundary() {
        let cases: [(Outcome<u32, &'static str>, OutcomeClass); 4] = [
            (Outcome::Ok(7), OutcomeClass::Success),
            (Outcome::Err("refused"), OutcomeClass::Refusal),
            (cancelled_outcome(), OutcomeClass::Cancelled),
            (
                Outcome::Panicked(PanicPayload::new("boom")),
                OutcomeClass::Panicked,
            ),
        ];

        for (outcome, expected) in cases {
            let lifted = ServiceOutcome::from_outcome(outcome);
            assert_eq!(lifted.classify(), expected);
        }
    }

    #[test]
    fn cancellation_is_not_collapsed_into_refusal() {
        let lifted = ServiceOutcome::<u32, &str>::from_outcome(cancelled_outcome());
        assert_eq!(lifted.classify(), OutcomeClass::Cancelled);
        assert_ne!(lifted.classify(), OutcomeClass::Refusal);
        assert!(lifted.success().is_none());
    }

    #[test]
    fn panic_is_not_collapsed_into_refusal() {
        let lifted =
            ServiceOutcome::<u32, &str>::from_outcome(Outcome::Panicked(PanicPayload::new("boom")));
        assert_eq!(lifted.classify(), OutcomeClass::Panicked);
        assert_ne!(lifted.classify(), OutcomeClass::Refusal);
    }

    #[test]
    fn mapping_success_preserves_every_other_arm() {
        // The classic collapse site: a map step in the middle of a service.
        for outcome in [
            Outcome::<u32, &str>::Err("refused"),
            cancelled_outcome(),
            Outcome::Panicked(PanicPayload::new("boom")),
        ] {
            let before = ServiceOutcome::from_outcome(outcome);
            let class = before.classify();
            let after = before.map_success(|value| value + 1);
            assert_eq!(after.classify(), class, "map_success changed the arm");
        }

        // Paired permitted case: the success arm does transform.
        let mapped = ServiceOutcome::<u32, &str>::from_outcome(Outcome::Ok(7))
            .map_success(|value| value + 1);
        assert_eq!(mapped.success(), Some(8));
    }

    #[test]
    fn mapping_refusal_preserves_every_other_arm() {
        for outcome in [
            Outcome::<u32, &str>::Ok(1),
            cancelled_outcome(),
            Outcome::Panicked(PanicPayload::new("boom")),
        ] {
            let before = ServiceOutcome::from_outcome(outcome);
            let class = before.classify();
            let after = before.map_refusal(|error| format!("wrapped: {error}"));
            assert_eq!(after.classify(), class);
        }

        let mapped = ServiceOutcome::<u32, &str>::from_outcome(Outcome::Err("refused"))
            .map_refusal(|error| format!("wrapped: {error}"));
        assert!(matches!(mapped, ServiceOutcome::Refusal(ref m) if m == "wrapped: refused"));
    }

    #[test]
    fn cancellation_without_an_effect_needs_no_resolution() {
        let lifted = ServiceOutcome::<u32, &str>::from_outcome(cancelled_outcome());
        assert!(!lifted.must_resolve_commit());
        assert_eq!(lifted.ambiguity(), Some(&CommitAmbiguity::None));
    }

    #[test]
    fn cancellation_after_an_observed_effect_is_ambiguous() {
        let lifted =
            ServiceOutcome::<u32, &str>::from_outcome_after_effect(cancelled_outcome(), "rcr-8f21");
        assert!(lifted.must_resolve_commit());
        assert_eq!(
            lifted
                .ambiguity()
                .and_then(CommitAmbiguity::idempotency_key),
            Some("rcr-8f21")
        );
    }

    #[test]
    fn commit_ambiguity_survives_a_mapping_pipeline() {
        // The whole point: ambiguity must not be lost by intermediate steps.
        let lifted =
            ServiceOutcome::<u32, &str>::from_outcome_after_effect(cancelled_outcome(), "rcr-8f21")
                .map_success(|value| value + 1)
                .map_refusal(|error| format!("wrapped: {error}"));

        assert!(lifted.must_resolve_commit());
        assert_eq!(
            lifted
                .ambiguity()
                .and_then(CommitAmbiguity::idempotency_key),
            Some("rcr-8f21")
        );
    }

    #[test]
    fn success_and_refusal_are_never_ambiguous() {
        // Ambiguity is a property of cancellation only: a completed operation
        // has an answer, so marking it ambiguous must be a no-op.
        let success =
            ServiceOutcome::<u32, &str>::from_outcome_after_effect(Outcome::Ok(1), "rcr-1");
        assert!(!success.must_resolve_commit());
        assert_eq!(success.ambiguity(), None);

        let refusal = ServiceOutcome::<u32, &str>::from_outcome(Outcome::Err("no"))
            .with_effect_ambiguity("rcr-2");
        assert!(!refusal.must_resolve_commit());
    }

    #[test]
    fn round_trip_through_the_runtime_outcome_preserves_the_arm() {
        for outcome in [
            Outcome::<u32, &str>::Ok(3),
            Outcome::Err("refused"),
            cancelled_outcome(),
            Outcome::Panicked(PanicPayload::new("boom")),
        ] {
            let class = ServiceOutcome::from_outcome(outcome.clone()).classify();
            let restored = ServiceOutcome::<u32, &str>::from_outcome(
                ServiceOutcome::from_outcome(outcome).into_outcome(),
            );
            assert_eq!(restored.classify(), class);
        }
    }

    #[test]
    fn task_results_lift_into_the_success_and_refusal_arms_only() {
        assert_eq!(
            lift_task_result::<u32, &str>(Ok(1)).classify(),
            OutcomeClass::Success
        );
        assert_eq!(
            lift_task_result::<u32, &str>(Err("no")).classify(),
            OutcomeClass::Refusal
        );
    }

    #[test]
    fn outcome_class_codes_are_distinct() {
        let mut codes: Vec<&str> = OutcomeClass::all().iter().map(|c| c.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 4);
    }
}
