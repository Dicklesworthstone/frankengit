//! The two-phase obligation lifecycle as owned type-state.
//!
//! `Reserved -> Committed -> Acknowledged` and `Reserved -> Aborted` are three
//! distinct owned types, not one type with a state field. Each transition
//! consumes the value it starts from, so the planted negatives are not "tested
//! and rejected" but *unrepresentable*: after `commit(self, ..)` there is no
//! reserved value left to commit again, and after `abort(self, ..)` there is
//! nothing left to commit at all. The mirrored runtime state machine lives in
//! [`crate::custody::ObligationState::apply`] for the paths where the value is
//! a record rather than a possession — journal replay, crash recovery, and the
//! heterogeneous set a region must settle before claiming quiescence.
//!
//! Every owned type here is `#[must_use]` and carries a drop guard, so the one
//! failure mode type-state cannot prevent — dropping a live obligation on the
//! floor — becomes a typed [`crate::custody::LeakRecord`] rather than silence.

use crate::algebra::{Grade, ResourceVector};
use crate::custody::{
    LeakClass, LeakGuard, LedgerHandle, LifecycleError, LifecycleEvent, ObligationState,
};
use crate::ids::{BoundIdentity, ObligationId};
use core::fmt;

/// Whether an effect has an external observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObservationMode {
    /// No external recipient exists; acknowledgement is trivial at commit.
    Internal,
    /// An external recipient must be observed before the effect is settled.
    ExternallyObserved,
}

/// The eleven concrete obligation classes.
///
/// The list is closed and matches `docs/CALM_AND_OBLIGATIONS.md` section 7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObligationClass {
    /// Admission of one immutable object into the store.
    ObjectAdmissionPermit,
    /// One preparation-lane combiner slot.
    PreparedTxnSlot,
    /// One authority head compare-and-set attempt.
    HeadCasAttempt,
    /// One external effect delivery.
    OutboxEffectPermit,
    /// One secret made reachable to one consumer.
    SecretLease,
    /// One workspace overlay and its outputs.
    WorkspaceLease,
    /// One sandbox allocation for hostile compute.
    RunnerSlot,
    /// One retention hold protecting canonical objects.
    RetentionPin,
    /// One repair decode, verification, and placement.
    RepairPermit,
    /// One context packet's budget and authorization scope.
    ContextBudgetPermit,
    /// One bounded charge against an external account.
    BillingReservation,
}

impl ObligationClass {
    /// Every class, in specification order.
    pub const ALL: [Self; 11] = [
        Self::ObjectAdmissionPermit,
        Self::PreparedTxnSlot,
        Self::HeadCasAttempt,
        Self::OutboxEffectPermit,
        Self::SecretLease,
        Self::WorkspaceLease,
        Self::RunnerSlot,
        Self::RetentionPin,
        Self::RepairPermit,
        Self::ContextBudgetPermit,
        Self::BillingReservation,
    ];

    /// Whether the class has an external observer.
    #[must_use]
    pub const fn observation(self) -> ObservationMode {
        match self {
            Self::OutboxEffectPermit
            | Self::SecretLease
            | Self::RunnerSlot
            | Self::BillingReservation => ObservationMode::ExternallyObserved,
            Self::ObjectAdmissionPermit
            | Self::PreparedTxnSlot
            | Self::HeadCasAttempt
            | Self::WorkspaceLease
            | Self::RetentionPin
            | Self::RepairPermit
            | Self::ContextBudgetPermit => ObservationMode::Internal,
        }
    }

    /// Stable lowercase name for receipts and refusals.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectAdmissionPermit => "object_admission_permit",
            Self::PreparedTxnSlot => "prepared_txn_slot",
            Self::HeadCasAttempt => "head_cas_attempt",
            Self::OutboxEffectPermit => "outbox_effect_permit",
            Self::SecretLease => "secret_lease",
            Self::WorkspaceLease => "workspace_lease",
            Self::RunnerSlot => "runner_slot",
            Self::RetentionPin => "retention_pin",
            Self::RepairPermit => "repair_permit",
            Self::ContextBudgetPermit => "context_budget_permit",
            Self::BillingReservation => "billing_reservation",
        }
    }
}

impl fmt::Display for ObligationClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Acknowledgement evidence for an effect nobody outside the node observes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrivialAck;

/// One obligation class and the payloads its lifecycle carries.
pub trait ObligationKind: Sized + 'static {
    /// Which of the eleven classes this kind is.
    const CLASS: ObligationClass;
    /// Whether an external recipient must be observed.
    const OBSERVATION: ObservationMode;
    /// Grades a reservation of this class must hold a non-zero amount of.
    const REQUIRED_GRADES: &'static [Grade];

    /// What the reserve phase records.
    type Reservation: fmt::Debug;
    /// What the commit phase records.
    type CommitReceipt: fmt::Debug;
    /// What the abort phase records.
    type AbortReceipt: fmt::Debug;
    /// What external observation records.
    type AckEvidence: fmt::Debug;
}

/// An obligation with no external observer.
///
/// Implementing this marker is what makes the trivial-acknowledgement path
/// available: an internal effect settles in one call at commit, with no
/// acknowledgement ceremony and no committed-but-unacknowledged window.
pub trait InternalEffect: ObligationKind<AckEvidence = TrivialAck> {}

/// An obligation whose recipient lives outside the node.
///
/// These stay [`ObligationState::Committed`] until acknowledgement evidence
/// arrives, and may leave their region only as an explicit
/// [`UnacknowledgedEffect`] record.
pub trait ExternallyObserved: ObligationKind {}

/// Why a committed effect left its region without acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeferralReason {
    /// The region is closing and the recipient has not answered yet.
    RegionClosing,
    /// The recipient is unreachable right now.
    DownstreamUnavailable,
    /// Delivery is in flight and observation is expected later.
    AwaitingObservation,
    /// Cancellation arrived after the effect was already committed.
    CancelledAfterCommit,
}

/// Why reconciliation handed an effect to a human owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EscalationReason {
    /// The downstream could not say whether the effect landed.
    IndeterminateDelivery,
    /// The retry budget ran out before a definite answer.
    RetryBudgetExhausted,
    /// The downstream broke its declared idempotency contract.
    ProbeContractViolation,
    /// Policy requires a human decision for this effect class.
    PolicyRequiresHuman,
}

/// Why an effect will never be delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TerminalFailureReason {
    /// The recipient rejected the effect permanently.
    PermanentDownstreamRejection,
    /// The effect's retention or validity window expired.
    ValidityWindowExpired,
    /// An operator decided to stop retrying.
    OperatorDecision,
}

/// The evidence a settled obligation ends with.
///
/// A terminal state is never a bare enum tag here: it carries the exact
/// receipt the phase produced, so a settled obligation can be audited without
/// consulting a second store.
#[derive(Debug)]
pub enum TerminalEvidence<K: ObligationKind> {
    /// Reserved then abandoned; no external effect occurred.
    Aborted(K::AbortReceipt),
    /// Committed and observed.
    Acknowledged(K::CommitReceipt, K::AckEvidence),
    /// Committed and declared permanently undeliverable.
    TerminallyFailed(K::CommitReceipt, TerminalFailureReason),
}

/// A non-generic summary of a settled obligation.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SettlementSummary {
    id: ObligationId,
    class: ObligationClass,
    state: ObligationState,
}

impl SettlementSummary {
    /// Which obligation settled.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.id
    }

    /// Its class.
    #[must_use]
    pub const fn class(&self) -> ObligationClass {
        self.class
    }

    /// The terminal state the ledger recorded.
    #[must_use]
    pub const fn state(&self) -> ObligationState {
        self.state
    }
}

/// A terminal obligation receipt.
#[must_use]
#[derive(Debug)]
pub struct SettledObligation<K: ObligationKind> {
    summary: SettlementSummary,
    evidence: TerminalEvidence<K>,
}

impl<K: ObligationKind> SettledObligation<K> {
    /// The non-generic summary.
    #[must_use]
    pub const fn summary(&self) -> SettlementSummary {
        self.summary
    }

    /// Which obligation settled.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.summary.id
    }

    /// Its class.
    #[must_use]
    pub const fn class(&self) -> ObligationClass {
        self.summary.class
    }

    /// The terminal state the ledger recorded.
    #[must_use]
    pub const fn state(&self) -> ObligationState {
        self.summary.state
    }

    /// The evidence the terminal phase produced.
    #[must_use]
    pub const fn evidence(&self) -> &TerminalEvidence<K> {
        &self.evidence
    }

    /// Consumes the receipt and yields its evidence.
    #[must_use]
    pub fn into_evidence(self) -> TerminalEvidence<K> {
        self.evidence
    }
}

/// Evidence that an unresolved effect was handed to a named owner.
#[must_use]
#[derive(Debug)]
pub struct EscalationReceipt<K: ObligationKind> {
    id: ObligationId,
    owner: BoundIdentity,
    reason: EscalationReason,
    receipt: K::CommitReceipt,
}

impl<K: ObligationKind> EscalationReceipt<K> {
    /// Which obligation was escalated.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.id
    }

    /// Its class.
    #[must_use]
    pub const fn class(&self) -> ObligationClass {
        K::CLASS
    }

    /// The owner now responsible for it.
    #[must_use]
    pub const fn owner(&self) -> BoundIdentity {
        self.owner
    }

    /// Why reconciliation could not finish.
    #[must_use]
    pub const fn reason(&self) -> EscalationReason {
        self.reason
    }

    /// What the commit phase recorded, handed on to the owner.
    #[must_use]
    pub const fn commit_receipt(&self) -> &K::CommitReceipt {
        &self.receipt
    }
}

/// Applies a ledger event and reports the state the ledger actually holds.
///
/// The owned two-phase values are the ledger's only writer, so the event can
/// only be refused if the ledger were already corrupt. Reading the state back
/// on that path keeps the receipt truthful instead of asserting a transition
/// that did not happen.
fn advance(handle: &LedgerHandle, id: ObligationId, event: LifecycleEvent) -> ObligationState {
    handle
        .mark(id, event)
        .unwrap_or_else(|_| handle.state_of(id).unwrap_or(ObligationState::Leaked))
}

/// A reservation that has not yet committed or aborted.
///
/// The reserve phase is cancellation-safe: no externally committed effect
/// exists while this value is alive.
#[must_use = "a reserved obligation must be committed, aborted, or explicitly transferred; dropping it is a leak"]
pub struct ReservedObligation<K: ObligationKind> {
    id: ObligationId,
    reservation: K::Reservation,
    guard: LeakGuard,
}

impl<K: ObligationKind> fmt::Debug for ReservedObligation<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReservedObligation")
            .field("id", &self.id)
            .field("class", &K::CLASS)
            .field("reservation", &self.reservation)
            .finish_non_exhaustive()
    }
}

impl<K: ObligationKind> ReservedObligation<K> {
    pub(crate) const fn from_parts(
        id: ObligationId,
        reservation: K::Reservation,
        guard: LeakGuard,
    ) -> Self {
        Self {
            id,
            reservation,
            guard,
        }
    }

    /// The obligation identifier.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.id
    }

    /// The obligation class.
    #[must_use]
    pub const fn class(&self) -> ObligationClass {
        K::CLASS
    }

    /// What the reserve phase recorded.
    #[must_use]
    pub const fn reservation(&self) -> &K::Reservation {
        &self.reservation
    }

    /// A handle to the owning region's ledger.
    #[must_use]
    pub fn ledger(&self) -> LedgerHandle {
        self.guard.handle()
    }

    /// Budget this reservation still holds.
    #[must_use]
    pub fn reserved(&self) -> ResourceVector {
        self.ledger()
            .reserved_for(self.id)
            .unwrap_or(ResourceVector::ZERO)
    }

    /// Whether settling with `actual` would be accepted.
    ///
    /// Callers that cannot afford to rebuild a receipt should pre-flight with
    /// this, because a refused settlement drops the receipt it was handed.
    pub fn can_settle(&self, actual: &ResourceVector) -> Result<(), LifecycleError> {
        self.reserved()
            .first_deficit(actual)
            .map_or(Ok(()), |error| {
                Err(LifecycleError::ChargeExceedsReservation(error))
            })
    }

    /// Commits the effect, binding the resources actually used.
    ///
    /// `actual` must not exceed the reservation in any grade; consumable
    /// grades are charged and everything else returns to the pool. On refusal
    /// the reservation is handed back so that a rejected settlement cannot
    /// leak; the commit receipt passed to the refused call is dropped.
    pub fn commit(
        self,
        receipt: K::CommitReceipt,
        actual: &ResourceVector,
    ) -> Result<CommittedObligation<K>, SettlementRefused<K>> {
        let handle = self.guard.handle();
        if let Err(error) = handle.commit_reservation(self.id, actual) {
            return Err(SettlementRefused {
                obligation: self,
                error,
            });
        }
        let Self {
            id,
            reservation: _,
            mut guard,
        } = self;
        guard.rearm_as(LeakClass::CommittedObligationDropped);
        Ok(CommittedObligation { id, receipt, guard })
    }

    /// Abandons the reservation, binding the resources spent before abandoning.
    ///
    /// No externally committed effect exists on this path. `spent` covers work
    /// already done, such as processor time burned by a lost race; everything
    /// else returns to the pool.
    pub fn abort(
        self,
        receipt: K::AbortReceipt,
        spent: &ResourceVector,
    ) -> Result<SettledObligation<K>, SettlementRefused<K>> {
        let handle = self.guard.handle();
        let state = match handle.abort_reservation(self.id, spent) {
            Ok(state) => state,
            Err(error) => {
                return Err(SettlementRefused {
                    obligation: self,
                    error,
                });
            }
        };
        let Self {
            id,
            reservation: _,
            mut guard,
        } = self;
        guard.disarm();
        Ok(SettledObligation {
            summary: SettlementSummary {
                id,
                class: K::CLASS,
                state,
            },
            evidence: TerminalEvidence::Aborted(receipt),
        })
    }

    /// Abandons the reservation having spent nothing.
    ///
    /// This is the common cancellation path and cannot be refused, because
    /// releasing the whole reservation can never mint budget.
    pub fn abort_unused(self, receipt: K::AbortReceipt) -> SettledObligation<K> {
        let handle = self.guard.handle();
        let state = handle
            .abort_reservation(self.id, &ResourceVector::ZERO)
            .unwrap_or_else(|_| {
                handle
                    .state_of(self.id)
                    .unwrap_or(ObligationState::Aborted)
            });
        let Self {
            id,
            reservation: _,
            mut guard,
        } = self;
        guard.disarm();
        SettledObligation {
            summary: SettlementSummary {
                id,
                class: K::CLASS,
                state,
            },
            evidence: TerminalEvidence::Aborted(receipt),
        }
    }
}

impl<K: InternalEffect> ReservedObligation<K> {
    /// Commits an internal effect and settles it in the same step.
    ///
    /// This is the trivial-acknowledgement path: an effect with no external
    /// observer has nothing to wait for, so there is no committed-but-
    /// unacknowledged window and no acknowledgement ceremony.
    pub fn commit_internal(
        self,
        receipt: K::CommitReceipt,
        actual: &ResourceVector,
    ) -> Result<SettledObligation<K>, SettlementRefused<K>> {
        let committed = self.commit(receipt, actual)?;
        Ok(committed.acknowledge(TrivialAck))
    }
}

/// A refused settlement that still owns its reservation.
#[must_use = "a refused settlement still owns a live reservation; resolve it or it leaks"]
pub struct SettlementRefused<K: ObligationKind> {
    obligation: ReservedObligation<K>,
    error: LifecycleError,
}

impl<K: ObligationKind> fmt::Debug for SettlementRefused<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SettlementRefused")
            .field("class", &K::CLASS)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<K: ObligationKind> fmt::Display for SettlementRefused<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} settlement refused: {}", K::CLASS, self.error)
    }
}

impl<K: ObligationKind> SettlementRefused<K> {
    /// Why the settlement was refused.
    #[must_use]
    pub const fn error(&self) -> LifecycleError {
        self.error
    }

    /// Takes the reservation back so the caller can retry or abort it.
    #[must_use]
    pub fn into_obligation(self) -> ReservedObligation<K> {
        self.obligation
    }
}

/// A committed effect awaiting external observation.
///
/// The effect is canonically owned. Cancellation from here may never report
/// "not committed": the caller resolves the outcome by identity lookup.
#[must_use = "a committed obligation must be acknowledged or explicitly deferred; dropping it is a leak"]
pub struct CommittedObligation<K: ObligationKind> {
    id: ObligationId,
    receipt: K::CommitReceipt,
    guard: LeakGuard,
}

impl<K: ObligationKind> fmt::Debug for CommittedObligation<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommittedObligation")
            .field("id", &self.id)
            .field("class", &K::CLASS)
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

impl<K: ObligationKind> CommittedObligation<K> {
    /// The obligation identifier.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.id
    }

    /// The obligation class.
    #[must_use]
    pub const fn class(&self) -> ObligationClass {
        K::CLASS
    }

    /// What the commit phase recorded.
    #[must_use]
    pub const fn receipt(&self) -> &K::CommitReceipt {
        &self.receipt
    }

    /// A handle to the owning region's ledger.
    #[must_use]
    pub fn ledger(&self) -> LedgerHandle {
        self.guard.handle()
    }

    /// Records that the external recipient observed the effect.
    pub fn acknowledge(self, evidence: K::AckEvidence) -> SettledObligation<K> {
        let Self {
            id,
            receipt,
            mut guard,
        } = self;
        let handle = guard.handle();
        guard.disarm();
        let state = advance(&handle, id, LifecycleEvent::Acknowledge);
        SettledObligation {
            summary: SettlementSummary {
                id,
                class: K::CLASS,
                state,
            },
            evidence: TerminalEvidence::Acknowledged(receipt, evidence),
        }
    }

    /// Moves the effect out of its region as an explicit record.
    ///
    /// This is the only sanctioned way for a committed effect to outlive its
    /// region. The region still reports it at close, and the record itself is
    /// leak-guarded, so deferral relocates ownership without dissolving it.
    pub fn defer_acknowledgement(self, reason: DeferralReason) -> UnacknowledgedEffect<K> {
        let Self {
            id,
            receipt,
            mut guard,
        } = self;
        let handle = guard.handle();
        let state = advance(&handle, id, LifecycleEvent::Defer);
        debug_assert_eq!(state, ObligationState::DeferredExternally);
        guard.rearm_as(LeakClass::UnacknowledgedRecordDropped);
        UnacknowledgedEffect {
            id,
            receipt,
            reason,
            guard,
        }
    }
}

/// A committed effect whose acknowledgement is owed outside its region.
///
/// This is the value a reconciler drives. It is leak-guarded, so an effect
/// that nobody reconciles is reported rather than forgotten.
#[must_use = "an unacknowledged effect must be reconciled, escalated, or terminally failed; dropping it is a leak"]
pub struct UnacknowledgedEffect<K: ObligationKind> {
    id: ObligationId,
    receipt: K::CommitReceipt,
    reason: DeferralReason,
    guard: LeakGuard,
}

impl<K: ObligationKind> fmt::Debug for UnacknowledgedEffect<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnacknowledgedEffect")
            .field("id", &self.id)
            .field("class", &K::CLASS)
            .field("reason", &self.reason)
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

impl<K: ObligationKind> UnacknowledgedEffect<K> {
    /// The obligation identifier.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.id
    }

    /// The obligation class.
    #[must_use]
    pub const fn class(&self) -> ObligationClass {
        K::CLASS
    }

    /// What the commit phase recorded.
    #[must_use]
    pub const fn receipt(&self) -> &K::CommitReceipt {
        &self.receipt
    }

    /// Why the effect left its region unacknowledged.
    #[must_use]
    pub const fn deferral_reason(&self) -> DeferralReason {
        self.reason
    }

    /// A handle to the owning region's ledger.
    #[must_use]
    pub fn ledger(&self) -> LedgerHandle {
        self.guard.handle()
    }

    /// Records that the external recipient observed the effect after all.
    pub fn acknowledge(self, evidence: K::AckEvidence) -> SettledObligation<K> {
        let Self {
            id,
            receipt,
            reason: _,
            mut guard,
        } = self;
        let handle = guard.handle();
        guard.disarm();
        let state = advance(&handle, id, LifecycleEvent::Acknowledge);
        SettledObligation {
            summary: SettlementSummary {
                id,
                class: K::CLASS,
                state,
            },
            evidence: TerminalEvidence::Acknowledged(receipt, evidence),
        }
    }

    /// Hands the effect to a named owner because its outcome is undecidable.
    ///
    /// The ledger keeps the obligation outstanding, so region close still
    /// reports a containment failure naming this owner. Escalation is an
    /// admission that automation stopped, never a settlement.
    pub fn escalate(self, owner: BoundIdentity, reason: EscalationReason) -> EscalationReceipt<K> {
        let Self {
            id,
            receipt,
            reason: _,
            mut guard,
        } = self;
        let handle = guard.handle();
        guard.disarm();
        let state = advance(&handle, id, LifecycleEvent::Escalate);
        debug_assert_eq!(state, ObligationState::Escalated);
        EscalationReceipt {
            id,
            owner,
            reason,
            receipt,
        }
    }

    /// Records that the effect will never be delivered.
    pub fn fail_terminally(self, reason: TerminalFailureReason) -> SettledObligation<K> {
        let Self {
            id,
            receipt,
            reason: _,
            mut guard,
        } = self;
        let handle = guard.handle();
        guard.disarm();
        let state = advance(&handle, id, LifecycleEvent::FailTerminally);
        SettledObligation {
            summary: SettlementSummary {
                id,
                class: K::CLASS,
                state,
            },
            evidence: TerminalEvidence::TerminallyFailed(receipt, reason),
        }
    }
}
