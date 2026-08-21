//! Region custody: the obligation ledger, leak detection, and region close.
//!
//! The ledger is the *runtime-state* half of this crate. The type-state half
//! (see [`crate::twophase`]) makes double-commit and commit-after-abort
//! unrepresentable for a value you own; the ledger makes the same rules
//! checkable for values you only have a record of — a replayed journal, a
//! crash-recovered outbox row, or a heterogeneous set of live obligations
//! that a region must settle before it can claim quiescence.

use crate::algebra::{
    BudgetGrant, Grade, GradeDisposition, ResourceError, ResourceVector,
};
use crate::ids::{GrantId, ObligationId, RegionId};
use crate::twophase::{ObligationClass, ObligationKind, ReservedObligation};
use core::fmt;
use core::num::NonZeroU32;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

/// What a region does when an obligation or grant is dropped unresolved.
///
/// There is deliberately no `Silent` and no log-only variant. The integration
/// profile forbids a silent leak outright and states that logging alone cannot
/// satisfy region closure, so neither is representable here: both surviving
/// variants leave a durable [`LeakRecord`] in the ledger and both make region
/// close report a [`ContainmentFailure`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeakPolicy {
    /// Fail fast. Verification and release profiles use this.
    ///
    /// The panic is raised after the ledger lock is released and is suppressed
    /// while the thread is already unwinding, so a leak discovered during
    /// another failure's cleanup degrades to a durable record instead of
    /// aborting the process and destroying the original diagnosis.
    Panic,
    /// Record, degrade, and escalate. Availability-oriented services may use
    /// this only with a durable leak record and a bounded escalation
    /// threshold, both of which this variant requires.
    Recover {
        /// Leak count at which the region must be escalated by its operator.
        escalation_threshold: NonZeroU32,
    },
}

/// The kind of value that was dropped without resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeakClass {
    /// A budget grant was dropped instead of being reserved, split, combined,
    /// or released. The amount returns to the pool; the drop is still a leak.
    BudgetGrantDropped,
    /// A reserved obligation was dropped without commit, abort, or transfer.
    ReservedObligationDropped,
    /// A committed obligation was dropped without acknowledgement and without
    /// an explicit unacknowledged-effect record.
    CommittedObligationDropped,
    /// An unacknowledged-effect record was dropped without reconciliation.
    UnacknowledgedRecordDropped,
    /// A ledger was dropped without an explicit region close.
    LedgerDroppedWithoutClose,
}

impl LeakClass {
    /// Stable lowercase name for receipts and refusals.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BudgetGrantDropped => "budget_grant_dropped",
            Self::ReservedObligationDropped => "reserved_obligation_dropped",
            Self::CommittedObligationDropped => "committed_obligation_dropped",
            Self::UnacknowledgedRecordDropped => "unacknowledged_record_dropped",
            Self::LedgerDroppedWithoutClose => "ledger_dropped_without_close",
        }
    }
}

impl fmt::Display for LeakClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a leak record is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeakSubject {
    /// A budget grant.
    Grant(GrantId),
    /// An obligation.
    Obligation(ObligationId),
    /// The region itself.
    Region(RegionId),
}

impl fmt::Display for LeakSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Grant(id) => fmt::Display::fmt(&id, f),
            Self::Obligation(id) => fmt::Display::fmt(&id, f),
            Self::Region(id) => fmt::Display::fmt(&id, f),
        }
    }
}

/// The durable record left behind by every leak, under every policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeakRecord {
    subject: LeakSubject,
    class: LeakClass,
    obligation: Option<ObligationClass>,
    reclaimed: ResourceVector,
    ordinal: u64,
}

impl LeakRecord {
    /// What leaked.
    #[must_use]
    pub const fn subject(&self) -> LeakSubject {
        self.subject
    }

    /// How it leaked.
    #[must_use]
    pub const fn class(&self) -> LeakClass {
        self.class
    }

    /// The obligation class, when the subject was an obligation.
    #[must_use]
    pub const fn obligation_class(&self) -> Option<ObligationClass> {
        self.obligation
    }

    /// Budget the ledger reclaimed while recording the leak.
    ///
    /// Reclaiming keeps the accounting identity true even in the presence of
    /// leaks: a leak is a lifecycle failure, never an accounting hole.
    #[must_use]
    pub const fn reclaimed(&self) -> ResourceVector {
        self.reclaimed
    }

    /// Per-region ordinal, starting at one.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }
}

impl fmt::Display for LeakRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "leak#{} {} {}", self.ordinal, self.class, self.subject)
    }
}

/// Runtime lifecycle state of one obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObligationState {
    /// Two-phase reservation taken; no externally committed effect exists.
    Reserved,
    /// The effect is canonically owned. External observation may be pending.
    Committed,
    /// Committed, and ownership was explicitly moved out of the region as an
    /// unacknowledged-effect record.
    DeferredExternally,
    /// Reconciliation could not decide the outcome and handed it to an owner.
    Escalated,
    /// The external recipient's observation is recorded.
    Acknowledged,
    /// Reserved then abandoned; no external effect occurred.
    Aborted,
    /// Policy declared the effect permanently undeliverable.
    TerminallyFailed,
    /// Dropped without resolution.
    Leaked,
}

/// An event applied to [`ObligationState`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifecycleEvent {
    /// The effect becomes canonically owned.
    Commit,
    /// The reservation is released without effect.
    Abort,
    /// External observation evidence arrived.
    Acknowledge,
    /// Ownership moves out of the region as an explicit record.
    Defer,
    /// Reconciliation handed the outcome to a named owner.
    Escalate,
    /// Policy declared permanent failure.
    FailTerminally,
    /// The value was dropped unresolved.
    Leak,
}

impl ObligationState {
    /// Whether no further lifecycle event is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Acknowledged | Self::Aborted | Self::TerminallyFailed | Self::Leaked
        )
    }

    /// Whether the region still owes work for this obligation.
    #[must_use]
    pub const fn is_outstanding(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Committed | Self::DeferredExternally | Self::Escalated
        )
    }

    /// Whether an external effect may already exist.
    ///
    /// Cancellation must never report "not committed" for a state where this
    /// is true; the caller resolves the outcome by identity lookup instead.
    #[must_use]
    pub const fn effect_may_exist(self) -> bool {
        !matches!(self, Self::Reserved | Self::Aborted)
    }

    /// The total state machine.
    ///
    /// Every illegal pair is a typed [`LifecycleError::IllegalTransition`],
    /// including the planted negatives: committing twice, committing after an
    /// abort, and acknowledging something never committed.
    pub fn apply(self, event: LifecycleEvent) -> Result<Self, LifecycleError> {
        let next = match (self, event) {
            (Self::Reserved, LifecycleEvent::Commit) => Self::Committed,
            (Self::Reserved, LifecycleEvent::Abort) => Self::Aborted,
            (Self::Committed, LifecycleEvent::Acknowledge)
            | (Self::DeferredExternally, LifecycleEvent::Acknowledge)
            | (Self::Escalated, LifecycleEvent::Acknowledge) => Self::Acknowledged,
            (Self::Committed, LifecycleEvent::Defer) => Self::DeferredExternally,
            (Self::DeferredExternally, LifecycleEvent::Escalate) => Self::Escalated,
            (Self::DeferredExternally, LifecycleEvent::FailTerminally)
            | (Self::Escalated, LifecycleEvent::FailTerminally) => Self::TerminallyFailed,
            (
                Self::Reserved | Self::Committed | Self::DeferredExternally | Self::Escalated,
                LifecycleEvent::Leak,
            ) => Self::Leaked,
            (from, event) => return Err(LifecycleError::IllegalTransition { from, event }),
        };
        Ok(next)
    }
}

impl fmt::Display for ObligationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match *self {
            Self::Reserved => "reserved",
            Self::Committed => "committed",
            Self::DeferredExternally => "deferred_externally",
            Self::Escalated => "escalated",
            Self::Acknowledged => "acknowledged",
            Self::Aborted => "aborted",
            Self::TerminallyFailed => "terminally_failed",
            Self::Leaked => "leaked",
        };
        f.write_str(text)
    }
}

/// A refusal from the obligation lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    /// The state machine has no edge for this pair.
    IllegalTransition {
        /// State the obligation was in.
        from: ObligationState,
        /// Event that was rejected.
        event: LifecycleEvent,
    },
    /// The ledger has no entry for the obligation.
    UnknownObligation(ObligationId),
    /// Settling would have charged more than was reserved.
    ChargeExceedsReservation(ResourceError),
    /// The region was already closed.
    RegionClosed(RegionId),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::IllegalTransition { from, event } => {
                write!(f, "obligation in state {from} refuses event {event:?}")
            }
            Self::UnknownObligation(id) => write!(f, "no ledger entry for {id}"),
            Self::ChargeExceedsReservation(error) => {
                write!(f, "settlement would mint budget: {error}")
            }
            Self::RegionClosed(region) => write!(f, "{region} is already closed"),
        }
    }
}

impl std::error::Error for LifecycleError {}

/// A refusal from [`ObligationLedger::reserve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveError {
    /// The grant held nothing in a grade this obligation class requires.
    ///
    /// The grant is released back to the pool before this refusal returns.
    MissingGrade {
        /// The obligation class that was refused.
        class: ObligationClass,
        /// The grade the class requires.
        grade: Grade,
    },
    /// The region was closed.
    RegionClosed(RegionId),
}

impl fmt::Display for ReserveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MissingGrade { class, grade } => write!(
                f,
                "{} requires a non-zero {grade} reservation",
                class.as_str()
            ),
            Self::RegionClosed(region) => write!(f, "{region} is already closed"),
        }
    }
}

impl std::error::Error for ReserveError {}

/// Accounting state of one region's budget pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolSnapshot {
    capacity: ResourceVector,
    available: ResourceVector,
    granted: ResourceVector,
    reserved: ResourceVector,
    consumed: ResourceVector,
    delegated: ResourceVector,
}

impl PoolSnapshot {
    /// Total budget the region was created with.
    #[must_use]
    pub const fn capacity(&self) -> ResourceVector {
        self.capacity
    }

    /// Budget nobody holds.
    #[must_use]
    pub const fn available(&self) -> ResourceVector {
        self.available
    }

    /// Budget held by live [`BudgetGrant`] values.
    #[must_use]
    pub const fn granted(&self) -> ResourceVector {
        self.granted
    }

    /// Budget held by obligations that have not settled.
    #[must_use]
    pub const fn reserved(&self) -> ResourceVector {
        self.reserved
    }

    /// Budget spent on consumable grades.
    #[must_use]
    pub const fn consumed(&self) -> ResourceVector {
        self.consumed
    }

    /// Capacity handed to open child regions.
    #[must_use]
    pub const fn delegated(&self) -> ResourceVector {
        self.delegated
    }

    /// The sum of every account.
    ///
    /// The region's accounting identity is `accounted() == capacity()`. It is
    /// maintained through split, combine, reserve, settle, abort, delegation
    /// to child regions, and leak reclamation, which is what "a split never
    /// mints budget" means operationally.
    pub fn accounted(&self) -> Result<ResourceVector, ResourceError> {
        self.available
            .combine(&self.granted)?
            .combine(&self.reserved)?
            .combine(&self.consumed)?
            .combine(&self.delegated)
    }

    /// Whether the accounting identity holds right now.
    #[must_use]
    pub fn is_conserved(&self) -> bool {
        self.accounted() == Ok(self.capacity)
    }
}

/// One obligation the region still owes work for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutstandingObligation {
    id: ObligationId,
    class: ObligationClass,
    state: ObligationState,
    reserved: ResourceVector,
}

impl OutstandingObligation {
    /// Which obligation.
    #[must_use]
    pub const fn id(&self) -> ObligationId {
        self.id
    }

    /// Its class.
    #[must_use]
    pub const fn class(&self) -> ObligationClass {
        self.class
    }

    /// Its runtime state.
    #[must_use]
    pub const fn state(&self) -> ObligationState {
        self.state
    }

    /// Budget it still holds.
    #[must_use]
    pub const fn reserved(&self) -> ResourceVector {
        self.reserved
    }
}

/// Evidence that a region reached quiescence.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuiescenceReceipt {
    region: RegionId,
    settled: u64,
    consumed: ResourceVector,
    returned: ResourceVector,
}

impl QuiescenceReceipt {
    /// The region that closed.
    #[must_use]
    pub const fn region(&self) -> RegionId {
        self.region
    }

    /// How many obligations reached a terminal state.
    #[must_use]
    pub const fn settled(&self) -> u64 {
        self.settled
    }

    /// Consumable budget actually spent.
    #[must_use]
    pub const fn consumed(&self) -> ResourceVector {
        self.consumed
    }

    /// Budget returned to the pool (or to a parent region).
    #[must_use]
    pub const fn returned(&self) -> ResourceVector {
        self.returned
    }
}

/// Evidence that a region could not reach quiescence.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainmentFailure {
    region: RegionId,
    unsettled: Vec<OutstandingObligation>,
    escalated: Vec<OutstandingObligation>,
    leaks: Vec<LeakRecord>,
    consumed: ResourceVector,
}

impl ContainmentFailure {
    /// The region that failed to close cleanly.
    #[must_use]
    pub const fn region(&self) -> RegionId {
        self.region
    }

    /// Obligations still reserved or committed at close.
    #[must_use]
    pub fn unsettled(&self) -> &[OutstandingObligation] {
        &self.unsettled
    }

    /// Obligations handed to a named owner by reconciliation.
    #[must_use]
    pub fn escalated(&self) -> &[OutstandingObligation] {
        &self.escalated
    }

    /// Every leak recorded in the region's lifetime.
    #[must_use]
    pub fn leaks(&self) -> &[LeakRecord] {
        &self.leaks
    }

    /// Consumable budget actually spent.
    #[must_use]
    pub const fn consumed(&self) -> ResourceVector {
        self.consumed
    }
}

impl fmt::Display for ContainmentFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} containment failure: {} unsettled, {} escalated, {} leaked",
            self.region,
            self.unsettled.len(),
            self.escalated.len(),
            self.leaks.len()
        )
    }
}

/// The result of closing a region.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegionCloseOutcome {
    /// Every obligation settled and no leak was recorded.
    Quiescent(QuiescenceReceipt),
    /// Something outlived the region; the failure names owners and evidence.
    ContainmentFailure(ContainmentFailure),
}

impl RegionCloseOutcome {
    /// Whether the region reached quiescence.
    #[must_use]
    pub const fn is_quiescent(&self) -> bool {
        matches!(*self, Self::Quiescent(_))
    }
}

