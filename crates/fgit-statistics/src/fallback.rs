//! Deterministic-fallback selection: §33's fail-closed rule, enforced by shape.
//!
//! §33 requires that **any** evidence gap, support failure, regime alarm,
//! numeric-bound violation or stale window select the pinned deterministic
//! fallback. That is a disjunction over conditions, and disjunctions written as
//! `if a { .. } else if b { .. }` chains rot: a sixth condition gets added to the
//! struct and forgotten in the chain, and the controller keeps using its adaptive
//! candidate under a condition that was supposed to disqualify it. The failure is
//! silent, because the candidate still produces answers.
//!
//! So the conditions are a closed set, and [`PolicyGate::select`] is written as a
//! *scan over that set* rather than a hand-maintained chain. Adding a variant to
//! [`FallbackTrigger`] without extending [`PolicyGate`] is a compile error, and
//! the exhaustiveness test below pins that the scan visits every variant.
//!
//! # Why the candidate is the residue, not the default
//!
//! [`PolicySelection::Candidate`] is returned only after every trigger has been
//! checked and none fired. Written the other way round — default to candidate,
//! override on a trigger — an unchecked condition silently *permits* adaptation.
//! Written this way, an unchecked condition is a variant with no arm, which does
//! not compile.

/// Why the pinned deterministic fallback was selected.
///
/// A closed set: §33 names these five and this type does not admit a sixth
/// without a matching arm in [`PolicyGate::select`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FallbackTrigger {
    /// The evidence stream is missing observations it declared it would have.
    EvidenceGap,
    /// An input fell outside the support the mechanism can act on — for example
    /// an off-policy propensity outside its declared range.
    SupportFailure,
    /// A regime detector alarmed, so the stream is no longer the one the
    /// candidate policy was calibrated against.
    RegimeAlarm,
    /// A computed value violated a declared numeric bound, including an
    /// accumulator that saturated and therefore lost magnitude.
    NumericBoundViolation,
    /// The evidence window no longer covers the decision being made.
    StaleWindow,
}

impl FallbackTrigger {
    /// Every trigger, in a fixed order.
    ///
    /// The order is fixed so that a run with two simultaneous conditions reports
    /// the same one every time. A gate that reported whichever condition it
    /// happened to check first would make the decision path unreplayable, which
    /// §8 forbids for anything affecting a decision.
    pub const ALL: [Self; 5] = [
        Self::EvidenceGap,
        Self::SupportFailure,
        Self::RegimeAlarm,
        Self::NumericBoundViolation,
        Self::StaleWindow,
    ];
}

/// What a controller may use for one decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicySelection {
    /// No trigger fired: the adaptive candidate is admissible.
    Candidate,
    /// A trigger fired: the pinned deterministic fallback is required, and the
    /// reason is carried so the decision path can be replayed.
    Fallback(FallbackTrigger),
}

impl PolicySelection {
    /// Whether the adaptive candidate may be used.
    #[must_use]
    pub const fn admits_candidate(self) -> bool {
        matches!(self, Self::Candidate)
    }

    /// The trigger, when the fallback was selected.
    #[must_use]
    pub const fn trigger(self) -> Option<FallbackTrigger> {
        match self {
            Self::Candidate => None,
            Self::Fallback(trigger) => Some(trigger),
        }
    }
}

/// The observed state of every §33 disqualifying condition.
///
/// One field per [`FallbackTrigger`] variant. Constructing this requires the
/// caller to have an answer for each condition — there is no `Default`, because
/// defaulting an unknown condition to "fine" is exactly the silent permission
/// this module exists to prevent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyGate {
    /// Observations are missing from the declared stream.
    pub evidence_gap: bool,
    /// An input fell outside the mechanism's declared support.
    pub support_failure: bool,
    /// A regime detector alarmed.
    pub regime_alarm: bool,
    /// A declared numeric bound was violated, or an accumulator saturated.
    pub numeric_bound_violation: bool,
    /// The evidence window does not cover this decision.
    pub stale_window: bool,
}

impl PolicyGate {
    /// A gate with no condition observed.
    ///
    /// Deliberately **not** `Default`: a caller writing `PolicyGate::default()`
    /// reads as "nothing to declare", whereas this name states that the caller
    /// has affirmatively observed all five conditions to be clear.
    #[must_use]
    pub const fn all_clear() -> Self {
        Self {
            evidence_gap: false,
            support_failure: false,
            regime_alarm: false,
            numeric_bound_violation: false,
            stale_window: false,
        }
    }

    /// Whether one specific condition is set.
    #[must_use]
    pub const fn is_set(&self, trigger: FallbackTrigger) -> bool {
        match trigger {
            FallbackTrigger::EvidenceGap => self.evidence_gap,
            FallbackTrigger::SupportFailure => self.support_failure,
            FallbackTrigger::RegimeAlarm => self.regime_alarm,
            FallbackTrigger::NumericBoundViolation => self.numeric_bound_violation,
            FallbackTrigger::StaleWindow => self.stale_window,
        }
    }

    /// Selects the candidate only if **every** condition is clear.
    ///
    /// Scans [`FallbackTrigger::ALL`] in its fixed order and returns the first
    /// condition that is set, so two simultaneous conditions always report the
    /// same one and the decision path replays identically.
    #[must_use]
    pub fn select(&self) -> PolicySelection {
        for trigger in FallbackTrigger::ALL {
            if self.is_set(trigger) {
                return PolicySelection::Fallback(trigger);
            }
        }
        PolicySelection::Candidate
    }
}
