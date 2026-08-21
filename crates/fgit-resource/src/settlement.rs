//! Reconciliation of committed-but-unacknowledged external effects.
//!
//! An effect that is canonically owned but not yet observed sits in the one
//! window where "retry" and "duplicate" are the same action seen from two
//! sides. This module is the state machine that walks that window without ever
//! choosing duplication: it dispatches, and when an acknowledgement is lost it
//! *probes* before it resends. What it may conclude depends on what the
//! downstream promises.
//!
//! # Worked example: an outbox effect with weak downstream idempotency
//!
//! A webhook receiver that suppresses duplicates only within a bounded window
//! has [`DownstreamIdempotency::Weak`]. Reconciling one delivery against it
//! runs like this:
//!
//! 1. `Pending` — dispatch attempt 1 with the reservation's idempotency key.
//! 2. The receiver accepts it, but the acknowledgement is lost in transit, so
//!    the channel reports [`DeliveryVerdict::AmbiguousTimeout`] and the plan
//!    moves to `Probing`.
//! 3. If the probe lands while the key is still inside the receiver's window,
//!    it answers [`ProbeVerdict::Delivered`], the plan reaches `Delivered`, and
//!    the obligation acknowledges. The receiver saw the effect exactly once.
//! 4. If the probe lands after the window evicted the key, it answers
//!    [`ProbeVerdict::Unknown`] — which for a weak downstream is genuinely
//!    undecidable between "delivered and forgotten" and "never delivered".
//!    Resending here would risk a duplicate canonical effect, so the plan
//!    reaches `Indeterminate` and the obligation escalates to a named owner.
//!    Region close then reports a containment failure, which is the correct
//!    outcome: automation stopped and a human owns it.
//!
//! The near-identical permitted case is the same sequence against a
//! [`DownstreamIdempotency::Strong`] receiver, whose probe is always definite:
//! `NotDelivered` sends the plan back to `Pending`, it redelivers under the
//! same key, the receiver suppresses or accepts exactly once, and the
//! obligation acknowledges with no human in the loop.

use crate::ids::{BoundIdentity, IdempotencyKey};
use crate::twophase::{
    EscalationReason, EscalationReceipt, ObligationKind, SettledObligation,
    TerminalFailureReason, UnacknowledgedEffect,
};
use core::fmt;
use core::num::NonZeroU32;

/// What a downstream promises about duplicate suppression.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DownstreamIdempotency {
    /// Duplicate suppression is durable: a probe is always definite.
    Strong,
    /// Duplicate suppression is bounded: a probe may answer `Unknown`, and a
    /// resend after that could duplicate the effect.
    Weak,
}

/// What a dispatch attempt observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeliveryVerdict {
    /// The downstream took the effect for the first time.
    Accepted,
    /// The downstream recognized the key and suppressed a duplicate.
    DuplicateSuppressed,
    /// The attempt failed in a way that may succeed later.
    TransientFailure,
    /// The downstream rejected the effect permanently.
    PermanentRejection,
    /// The attempt may or may not have landed.
    AmbiguousTimeout,
}

/// What a probe observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeVerdict {
    /// The downstream holds the effect.
    Delivered,
    /// The downstream definitely never took the effect.
    NotDelivered,
    /// The downstream cannot say.
    Unknown,
}

/// The downstream a reconciler talks to.
///
/// Implementations are transport adapters. This crate performs no I/O and owns
/// no transport; it owns the decision of what to do with what a transport
/// reports.
pub trait DownstreamChannel {
    /// Sends the effect under its stable idempotency key.
    fn deliver(&mut self, key: &IdempotencyKey, attempt: u32) -> DeliveryVerdict;

    /// Asks whether the effect under this key already landed.
    fn probe(&mut self, key: &IdempotencyKey) -> ProbeVerdict;
}

/// Bounds on how hard a reconciler may try.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcilePolicy {
    max_attempts: NonZeroU32,
}

impl ReconcilePolicy {
    /// Builds a policy with a bounded attempt count.
    #[must_use]
    pub const fn new(max_attempts: NonZeroU32) -> Self {
        Self { max_attempts }
    }

    /// The attempt ceiling.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts.get()
    }
}

/// Where reconciliation currently stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReconcileState {
    /// The next action is a dispatch of `attempt`.
    Pending {
        /// One-based attempt ordinal about to be sent.
        attempt: u32,
    },
    /// The next action is a probe about `attempt`.
    Probing {
        /// One-based attempt ordinal whose fate is unknown.
        attempt: u32,
    },
    /// The downstream holds the effect exactly once.
    Delivered {
        /// The attempt that landed.
        attempt: u32,
    },
    /// The effect will never be delivered.
    Undeliverable {
        /// Why delivery stopped for good.
        reason: TerminalFailureReason,
    },
    /// Automation cannot decide the outcome.
    Indeterminate {
        /// Why a human must decide.
        reason: EscalationReason,
    },
}

impl ReconcileState {
    /// Whether no further action is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Delivered { .. } | Self::Undeliverable { .. } | Self::Indeterminate { .. }
        )
    }
}

impl fmt::Display for ReconcileState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Pending { attempt } => write!(f, "pending(attempt {attempt})"),
            Self::Probing { attempt } => write!(f, "probing(attempt {attempt})"),
            Self::Delivered { attempt } => write!(f, "delivered(attempt {attempt})"),
            Self::Undeliverable { reason } => write!(f, "undeliverable({reason:?})"),
            Self::Indeterminate { reason } => write!(f, "indeterminate({reason:?})"),
        }
    }
}

/// What a reconciler observed during one step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Observation {
    /// A dispatch verdict.
    Delivery(DeliveryVerdict),
    /// A probe verdict.
    Probe(ProbeVerdict),
}

/// One recorded step of a reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileTransition {
    from: ReconcileState,
    observation: Observation,
    to: ReconcileState,
}

impl ReconcileTransition {
    /// The state the step started in.
    #[must_use]
    pub const fn from(&self) -> ReconcileState {
        self.from
    }

    /// What the downstream reported.
    #[must_use]
    pub const fn observation(&self) -> Observation {
        self.observation
    }

    /// The state the step ended in.
    #[must_use]
    pub const fn to(&self) -> ReconcileState {
        self.to
    }
}

/// The reconciliation state machine for one external effect.
///
/// The plan is pure with respect to the obligation: it carries no ownership,
/// performs no I/O, and can be replayed from its transition list. Tying it to
/// an owned [`UnacknowledgedEffect`] is the job of [`reconcile`].
#[derive(Clone, Debug)]
pub struct ReconcilePlan {
    key: IdempotencyKey,
    idempotency: DownstreamIdempotency,
    policy: ReconcilePolicy,
    state: ReconcileState,
    transitions: Vec<ReconcileTransition>,
}

impl ReconcilePlan {
    /// Starts a plan for one idempotency key.
    #[must_use]
    pub fn new(
        key: IdempotencyKey,
        idempotency: DownstreamIdempotency,
        policy: ReconcilePolicy,
    ) -> Self {
        Self {
            key,
            idempotency,
            policy,
            state: ReconcileState::Pending { attempt: 1 },
            transitions: Vec::new(),
        }
    }

    /// The idempotency key every attempt reuses.
    #[must_use]
    pub const fn key(&self) -> IdempotencyKey {
        self.key
    }

    /// What the downstream promises.
    #[must_use]
    pub const fn idempotency(&self) -> DownstreamIdempotency {
        self.idempotency
    }

    /// Where reconciliation stands.
    #[must_use]
    pub const fn state(&self) -> ReconcileState {
        self.state
    }

    /// Every step taken so far, in order.
    #[must_use]
    pub fn transitions(&self) -> &[ReconcileTransition] {
        &self.transitions
    }

    /// Takes one step, if the plan is not already terminal.
    pub fn step(&mut self, channel: &mut impl DownstreamChannel) -> ReconcileState {
        let from = self.state;
        let (observation, to) = match from {
            ReconcileState::Pending { attempt } => {
                let verdict = channel.deliver(&self.key, attempt);
                (
                    Observation::Delivery(verdict),
                    self.after_delivery(attempt, verdict),
                )
            }
            ReconcileState::Probing { attempt } => {
                let verdict = channel.probe(&self.key);
                (Observation::Probe(verdict), self.after_probe(attempt, verdict))
            }
            terminal => return terminal,
        };
        self.transitions.push(ReconcileTransition {
            from,
            observation,
            to,
        });
        self.state = to;
        to
    }

    /// Steps until the plan is terminal.
    ///
    /// The loop is bounded by the policy's attempt ceiling, so a downstream
    /// that answers inconsistently cannot spin this forever.
    pub fn run(&mut self, channel: &mut impl DownstreamChannel) -> ReconcileState {
        let ceiling = self
            .policy
            .max_attempts()
            .saturating_mul(2)
            .saturating_add(2);
        for _ in 0..ceiling {
            if self.state.is_terminal() {
                break;
            }
            self.step(channel);
        }
        if !self.state.is_terminal() {
            self.state = ReconcileState::Indeterminate {
                reason: EscalationReason::RetryBudgetExhausted,
            };
        }
        self.state
    }

    fn after_delivery(&self, attempt: u32, verdict: DeliveryVerdict) -> ReconcileState {
        match verdict {
            DeliveryVerdict::Accepted | DeliveryVerdict::DuplicateSuppressed => {
                ReconcileState::Delivered { attempt }
            }
            DeliveryVerdict::PermanentRejection => ReconcileState::Undeliverable {
                reason: TerminalFailureReason::PermanentDownstreamRejection,
            },
            DeliveryVerdict::AmbiguousTimeout => ReconcileState::Probing { attempt },
            DeliveryVerdict::TransientFailure => self.next_attempt(attempt),
        }
    }

    fn after_probe(&self, attempt: u32, verdict: ProbeVerdict) -> ReconcileState {
        match verdict {
            ProbeVerdict::Delivered => ReconcileState::Delivered { attempt },
            ProbeVerdict::NotDelivered => self.next_attempt(attempt),
            // A weak downstream that has forgotten the key cannot distinguish
            // "delivered and evicted" from "never delivered". Resending would
            // risk duplicating a canonical effect, so automation stops here.
            // A strong downstream answering `Unknown` has broken its declared
            // contract, which is a different escalation, not a licence to
            // resend.
            ProbeVerdict::Unknown => ReconcileState::Indeterminate {
                reason: match self.idempotency {
                    DownstreamIdempotency::Weak => EscalationReason::IndeterminateDelivery,
                    DownstreamIdempotency::Strong => EscalationReason::ProbeContractViolation,
                },
            },
        }
    }

    fn next_attempt(&self, attempt: u32) -> ReconcileState {
        let next = attempt.saturating_add(1);
        if next > self.policy.max_attempts() {
            ReconcileState::Indeterminate {
                reason: EscalationReason::RetryBudgetExhausted,
            }
        } else {
            ReconcileState::Pending { attempt: next }
        }
    }
}

/// How reconciliation ended for an owned obligation.
#[must_use]
#[derive(Debug)]
pub enum ReconcileOutcome<K: ObligationKind> {
    /// The downstream observed the effect; the obligation is settled.
    Acknowledged(SettledObligation<K>),
    /// The effect will never be delivered; the obligation is settled.
    TerminallyFailed(SettledObligation<K>),
    /// Automation stopped; a named owner holds the obligation and the region
    /// will report a containment failure at close.
    Escalated(EscalationReceipt<K>),
}

/// Drives a plan to a conclusion and settles the obligation accordingly.
///
/// `evidence` builds the acknowledgement payload from the attempt that landed;
/// it is only called on the delivered path, so a caller cannot accidentally
/// manufacture acknowledgement evidence for an effect nobody observed.
pub fn reconcile<K, C, E>(
    effect: UnacknowledgedEffect<K>,
    plan: &mut ReconcilePlan,
    channel: &mut C,
    owner: BoundIdentity,
    evidence: E,
) -> ReconcileOutcome<K>
where
    K: ObligationKind,
    C: DownstreamChannel,
    E: FnOnce(u32) -> K::AckEvidence,
{
    match plan.run(channel) {
        ReconcileState::Delivered { attempt } => {
            ReconcileOutcome::Acknowledged(effect.acknowledge(evidence(attempt)))
        }
        ReconcileState::Undeliverable { reason } => {
            ReconcileOutcome::TerminallyFailed(effect.fail_terminally(reason))
        }
        ReconcileState::Indeterminate { reason } => {
            ReconcileOutcome::Escalated(effect.escalate(owner, reason))
        }
        // `run` never returns a non-terminal state; escalate rather than
        // inventing an outcome if that invariant were ever broken.
        ReconcileState::Pending { .. } | ReconcileState::Probing { .. } => {
            ReconcileOutcome::Escalated(
                effect.escalate(owner, EscalationReason::RetryBudgetExhausted),
            )
        }
    }
}
