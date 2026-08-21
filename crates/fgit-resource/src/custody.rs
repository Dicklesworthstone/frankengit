//! Region custody: the obligation ledger, leak detection, and region close.
//!
//! The ledger is the *runtime-state* half of this crate. The type-state half
//! (see [`crate::twophase`]) makes double-commit and commit-after-abort
//! unrepresentable for a value you own; the ledger makes the same rules
//! checkable for values you only have a record of — a replayed journal, a
//! crash-recovered outbox row, or a heterogeneous set of live obligations
//! that a region must settle before it can claim quiescence.

use crate::algebra::{BudgetGrant, Grade, GradeDisposition, ResourceError, ResourceVector};
use crate::ids::{GrantId, ObligationId, RegionId};
use crate::twophase::{ObligationClass, ObligationKind, ReservedObligation};
use core::fmt;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

/// What a ledger does at the moment a value is dropped unresolved.
///
/// This is the *recording* half of leak handling, and it is deliberately
/// narrow. Both variants leave a durable [`LeakRecord`] and both make region
/// close report a [`ContainmentFailure`], so there is no silent and no
/// log-only choice to make here.
///
/// The *profile* half — the bounded cleanup budget, escalation threshold,
/// durable leak sink, and health-degradation signal that the integration
/// profile requires before a service may run in a recovering mode — belongs to
/// `fgit-runtime`, which configures the runtime's obligation table and refuses
/// an uncontrolled recovering profile. `fgit-resource` cannot certify those
/// controls and does not pretend to: selecting
/// [`LeakDisposition::RecordAndContinue`] is only admissible underneath a
/// runtime profile that supplies them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeakDisposition {
    /// Record the leak and raise immediately.
    ///
    /// Verification and release profiles use this. The panic is raised after
    /// the ledger lock is released and is suppressed while the thread is
    /// already unwinding, so a leak discovered during another failure's
    /// cleanup degrades to a durable record instead of aborting the process
    /// and destroying the original diagnosis.
    FailFast,
    /// Record the leak and let the region keep running.
    ///
    /// The record still blocks quiescence at region close; escalation is the
    /// runtime profile's decision, not the ledger's.
    RecordAndContinue,
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
    pub const fn apply(self, event: LifecycleEvent) -> Result<Self, LifecycleError> {
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
    accounting_faults: u32,
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

    /// How many times the ledger could not complete an accounting move.
    ///
    /// A well-formed ledger never records one: every live amount was carved
    /// out of `capacity`, so no sum can overflow and no subtraction can
    /// underflow. The counter exists so that a ledger which somehow did reach
    /// that state says so, instead of quietly keeping a stale number. A
    /// non-zero count makes the region close as a containment failure.
    #[must_use]
    pub const fn accounting_faults(&self) -> u32 {
        self.accounting_faults
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
        self.accounting_faults == 0 && self.accounted() == Ok(self.capacity)
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
    accounting_faults: u32,
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

    /// Accounting moves the ledger could not complete.
    #[must_use]
    pub const fn accounting_faults(&self) -> u32 {
        self.accounting_faults
    }
}

impl fmt::Display for ContainmentFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} containment failure: {} unsettled, {} escalated, {} leaked, {} accounting faults",
            self.region,
            self.unsettled.len(),
            self.escalated.len(),
            self.leaks.len(),
            self.accounting_faults
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

#[derive(Clone, Copy, Debug)]
struct LedgerEntry {
    class: ObligationClass,
    state: ObligationState,
    reserved: ResourceVector,
    charged: ResourceVector,
}

#[derive(Debug)]
struct LedgerState {
    region: RegionId,
    capacity: ResourceVector,
    available: ResourceVector,
    consumed: ResourceVector,
    delegated: ResourceVector,
    grants: BTreeMap<GrantId, ResourceVector>,
    entries: BTreeMap<ObligationId, LedgerEntry>,
    leaks: Vec<LeakRecord>,
    next_grant: u64,
    next_obligation: u64,
    leak_ordinal: u64,
    accounting_faults: u32,
    closed: bool,
}

/// Folds a sequence of amounts held by a ledger.
///
/// Overflow cannot occur for a well-formed ledger because every live amount was
/// carved out of `capacity`. If it somehow did, the fold drops the offending
/// term rather than panicking inside a lock, and the resulting shortfall is
/// reported by [`PoolSnapshot::is_conserved`].
fn sum_amounts<'a>(amounts: impl Iterator<Item = &'a ResourceVector>) -> ResourceVector {
    amounts.fold(ResourceVector::ZERO, |total, amount| {
        total.combine(amount).unwrap_or(total)
    })
}

impl LedgerState {
    fn granted(&self) -> ResourceVector {
        sum_amounts(self.grants.values())
    }

    fn reserved(&self) -> ResourceVector {
        sum_amounts(self.entries.values().map(|entry| &entry.reserved))
    }

    fn snapshot(&self) -> PoolSnapshot {
        PoolSnapshot {
            capacity: self.capacity,
            available: self.available,
            granted: self.granted(),
            reserved: self.reserved(),
            consumed: self.consumed,
            delegated: self.delegated,
            accounting_faults: self.accounting_faults,
        }
    }

    /// Records that an accounting move could not be completed.
    ///
    /// Reaching this is a ledger defect, not an ordinary outcome. It is
    /// counted rather than panicked because the caller is inside the ledger
    /// lock, and it is surfaced by [`PoolSnapshot::accounting_faults`] and by
    /// region close so that it can never pass as a clean settlement.
    const fn note_fault(&mut self) {
        self.accounting_faults = self.accounting_faults.saturating_add(1);
    }

    fn add_available(&mut self, amount: &ResourceVector) {
        match self.available.combine(amount) {
            Ok(total) => self.available = total,
            Err(_) => self.note_fault(),
        }
    }

    fn add_consumed(&mut self, amount: &ResourceVector) {
        match self.consumed.combine(amount) {
            Ok(total) => self.consumed = total,
            Err(_) => self.note_fault(),
        }
    }

    fn add_delegated(&mut self, amount: &ResourceVector) {
        match self.delegated.combine(amount) {
            Ok(total) => self.delegated = total,
            Err(_) => self.note_fault(),
        }
    }

    fn drop_delegated(&mut self, amount: &ResourceVector) {
        match self.delegated.split(amount) {
            Ok((_, rest)) => self.delegated = rest,
            Err(_) => self.note_fault(),
        }
    }

    fn allocate_grant_id(&mut self) -> GrantId {
        self.next_grant = self.next_grant.saturating_add(1);
        GrantId::new(self.region, self.next_grant)
    }

    fn allocate_obligation_id(&mut self) -> ObligationId {
        self.next_obligation = self.next_obligation.saturating_add(1);
        ObligationId::new(self.region, self.next_obligation)
    }

    /// Moves `amount` out of the available pool into a fresh grant.
    fn carve(&mut self, amount: ResourceVector) -> Result<GrantId, ResourceError> {
        let (_, rest) = self.available.split(&amount)?;
        self.available = rest;
        let id = self.allocate_grant_id();
        self.grants.insert(id, amount);
        Ok(id)
    }

    /// Retires a grant and returns the amount it held.
    fn retire(&mut self, id: GrantId) -> ResourceVector {
        match self.grants.remove(&id) {
            Some(amount) => amount,
            None => {
                self.note_fault();
                ResourceVector::ZERO
            }
        }
    }

    fn give_back(&mut self, amount: ResourceVector) {
        self.add_available(&amount);
    }

    fn record_leak(&mut self, subject: LeakSubject, class: LeakClass) -> LeakRecord {
        self.leak_ordinal = self.leak_ordinal.saturating_add(1);
        let mut reclaimed = ResourceVector::ZERO;
        let mut obligation = None;
        let mut faulted = false;
        match subject {
            LeakSubject::Grant(id) => {
                reclaimed = self.retire(id);
                self.give_back(reclaimed);
            }
            LeakSubject::Obligation(id) => {
                if let Some(entry) = self.entries.get_mut(&id) {
                    obligation = Some(entry.class);
                    reclaimed = entry.reserved;
                    entry.reserved = ResourceVector::ZERO;
                    match entry.state.apply(LifecycleEvent::Leak) {
                        Ok(next) => entry.state = next,
                        Err(_) => faulted = true,
                    }
                }
                self.give_back(reclaimed);
            }
            LeakSubject::Region(_) => {}
        }
        if faulted {
            self.note_fault();
        }
        let record = LeakRecord {
            subject,
            class,
            obligation,
            reclaimed,
            ordinal: self.leak_ordinal,
        };
        self.leaks.push(record);
        record
    }

    fn fresh(region: RegionId, capacity: ResourceVector) -> Self {
        Self {
            region,
            capacity,
            available: capacity,
            consumed: ResourceVector::ZERO,
            delegated: ResourceVector::ZERO,
            grants: BTreeMap::new(),
            entries: BTreeMap::new(),
            leaks: Vec::new(),
            next_grant: 0,
            next_obligation: 0,
            leak_ordinal: 0,
            accounting_faults: 0,
            closed: false,
        }
    }
}

#[derive(Debug)]
struct LedgerInner {
    region: RegionId,
    disposition: LeakDisposition,
    parent: Option<LedgerHandle>,
    state: Mutex<LedgerState>,
}

/// A cloneable reference to one region's ledger.
///
/// Obligations and grants hold a handle so that dropping one can never be
/// silent. A handle grants no authority: it records settlement and reads
/// accounting, but it cannot create budget.
#[derive(Clone, Debug)]
pub struct LedgerHandle(Arc<LedgerInner>);

impl LedgerHandle {
    fn with_state<R>(&self, action: impl FnOnce(&mut LedgerState) -> R) -> R {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        action(&mut state)
    }

    /// The region this handle belongs to.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.0.region
    }

    /// How this region records a dropped value.
    #[must_use]
    pub fn disposition(&self) -> LeakDisposition {
        self.0.disposition
    }

    /// Current accounting.
    #[must_use]
    pub fn snapshot(&self) -> PoolSnapshot {
        self.with_state(|state| state.snapshot())
    }

    /// Runtime state of one obligation, if the region knows it.
    #[must_use]
    pub fn state_of(&self, id: ObligationId) -> Option<ObligationState> {
        self.with_state(|state| state.entries.get(&id).map(|entry| entry.state))
    }

    /// Consumable budget charged to one obligation at settlement.
    #[must_use]
    pub fn charged_to(&self, id: ObligationId) -> Option<ResourceVector> {
        self.with_state(|state| state.entries.get(&id).map(|entry| entry.charged))
    }

    /// Every leak recorded so far, in order.
    #[must_use]
    pub fn leaks(&self) -> Vec<LeakRecord> {
        self.with_state(|state| state.leaks.clone())
    }

    /// Obligations the region still owes work for.
    #[must_use]
    pub fn outstanding(&self) -> Vec<OutstandingObligation> {
        self.with_state(|state| collect_outstanding(state, ObligationState::is_outstanding))
    }

    fn new_guard(&self, subject: LeakSubject, class: LeakClass) -> LeakGuard {
        LeakGuard {
            handle: self.clone(),
            subject,
            class,
            armed: true,
        }
    }

    pub(crate) fn grant_from(&self, id: GrantId, amount: ResourceVector) -> BudgetGrant {
        BudgetGrant::from_parts(
            id,
            amount,
            self.new_guard(LeakSubject::Grant(id), LeakClass::BudgetGrantDropped),
        )
    }

    /// Rewrites `old` to `rest` and registers `part` as a fresh grant.
    pub(crate) fn divide_grant(
        &self,
        old: GrantId,
        part: ResourceVector,
        rest: ResourceVector,
    ) -> BudgetGrant {
        let carved = self.with_state(|state| {
            state.grants.insert(old, rest);
            let carved = state.allocate_grant_id();
            state.grants.insert(carved, part);
            carved
        });
        self.grant_from(carved, part)
    }

    /// Retires `source` and rewrites `target` to hold `total`.
    pub(crate) fn absorb_grant(&self, target: GrantId, source: GrantId, total: ResourceVector) {
        self.with_state(|state| {
            state.retire(source);
            state.grants.insert(target, total);
        });
    }

    pub(crate) fn release_grant(&self, id: GrantId) {
        self.with_state(|state| {
            let amount = state.retire(id);
            state.give_back(amount);
        });
    }

    /// Budget one obligation still holds, if the region knows it.
    #[must_use]
    pub fn reserved_for(&self, id: ObligationId) -> Option<ResourceVector> {
        self.with_state(|state| state.entries.get(&id).map(|entry| entry.reserved))
    }

    pub(crate) fn commit_reservation(
        &self,
        id: ObligationId,
        actual: &ResourceVector,
    ) -> Result<ObligationState, LifecycleError> {
        self.settle(id, LifecycleEvent::Commit, actual)
    }

    pub(crate) fn abort_reservation(
        &self,
        id: ObligationId,
        spent: &ResourceVector,
    ) -> Result<ObligationState, LifecycleError> {
        self.settle(id, LifecycleEvent::Abort, spent)
    }

    fn settle(
        &self,
        id: ObligationId,
        event: LifecycleEvent,
        spent: &ResourceVector,
    ) -> Result<ObligationState, LifecycleError> {
        self.with_state(|state| {
            let entry = *state
                .entries
                .get(&id)
                .ok_or(LifecycleError::UnknownObligation(id))?;
            let next = entry.state.apply(event)?;
            let charged = spent.mask(GradeDisposition::Consumable);
            let (_, returned) = entry
                .reserved
                .split(spent)
                .and_then(|_| entry.reserved.split(&charged))
                .map_err(LifecycleError::ChargeExceedsReservation)?;
            state.add_consumed(&charged);
            state.give_back(returned);
            if let Some(slot) = state.entries.get_mut(&id) {
                slot.state = next;
                slot.charged = charged;
                slot.reserved = ResourceVector::ZERO;
            }
            Ok(next)
        })
    }

    /// Applies a lifecycle event that moves no budget.
    ///
    /// Crate-private on purpose: the owned two-phase values in
    /// [`crate::twophase`] are the ledger's only writer, so an external caller
    /// cannot desynchronize the runtime state from the type state. Journal
    /// replay and other reconstruction paths use the pure, public
    /// [`ObligationState::apply`] instead.
    pub(crate) fn mark(
        &self,
        id: ObligationId,
        event: LifecycleEvent,
    ) -> Result<ObligationState, LifecycleError> {
        self.with_state(|state| {
            let entry = state
                .entries
                .get_mut(&id)
                .ok_or(LifecycleError::UnknownObligation(id))?;
            let next = entry.state.apply(event)?;
            entry.state = next;
            Ok(next)
        })
    }

    fn record_leak(&self, subject: LeakSubject, class: LeakClass) {
        let record = self.with_state(|state| state.record_leak(subject, class));
        if self.0.disposition == LeakDisposition::FailFast && !std::thread::panicking() {
            panic!("obligation leak under the fail-fast disposition: {record}");
        }
    }
}

fn collect_outstanding(
    state: &LedgerState,
    predicate: fn(ObligationState) -> bool,
) -> Vec<OutstandingObligation> {
    state
        .entries
        .iter()
        .filter(|(_, entry)| predicate(entry.state))
        .map(|(id, entry)| OutstandingObligation {
            id: *id,
            class: entry.class,
            state: entry.state,
            reserved: entry.reserved,
        })
        .collect()
}

/// Drop-time leak detector attached to every value that owns responsibility.
#[derive(Debug)]
pub(crate) struct LeakGuard {
    handle: LedgerHandle,
    subject: LeakSubject,
    class: LeakClass,
    armed: bool,
}

impl LeakGuard {
    pub(crate) fn handle(&self) -> LedgerHandle {
        self.handle.clone()
    }

    pub(crate) const fn disarm(&mut self) {
        self.armed = false;
    }

    pub(crate) const fn rearm_as(&mut self, class: LeakClass) {
        self.class = class;
        self.armed = true;
    }
}

impl Drop for LeakGuard {
    fn drop(&mut self) {
        if self.armed {
            self.handle.record_leak(self.subject, self.class);
        }
    }
}

/// The owner of one region's obligations and budget.
///
/// A ledger is created with an explicit capacity and leak disposition, hands out
/// [`BudgetGrant`] values, converts grants into obligations, and must be closed
/// explicitly. Dropping it without [`ObligationLedger::close`] is itself a leak.
#[must_use = "a region ledger must be closed explicitly so that quiescence is proved, not assumed"]
#[derive(Debug)]
pub struct ObligationLedger {
    handle: LedgerHandle,
    guard: LeakGuard,
}

impl ObligationLedger {
    /// Creates a root region with an explicit capacity.
    ///
    /// A root capacity is the declared boundary of the algebra: it is the one
    /// place an amount comes from nowhere, and it is a named profile input
    /// rather than an ambient default.
    pub fn root(region: RegionId, disposition: LeakDisposition, capacity: ResourceVector) -> Self {
        Self::from_inner(LedgerInner {
            region,
            disposition,
            parent: None,
            state: Mutex::new(LedgerState::fresh(region, capacity)),
        })
    }

    fn from_inner(inner: LedgerInner) -> Self {
        let region = inner.region;
        let handle = LedgerHandle(Arc::new(inner));
        let guard = handle.new_guard(
            LeakSubject::Region(region),
            LeakClass::LedgerDroppedWithoutClose,
        );
        Self { handle, guard }
    }

    /// Creates a child region funded entirely by `grant`.
    ///
    /// This is the only constructor for a non-root region, which is how "a
    /// child region cannot mint authority or budget from nothing" is enforced:
    /// the child's capacity is exactly the parent budget handed to it, and the
    /// parent records that amount as delegated until the child closes.
    pub fn child(
        &self,
        region: RegionId,
        disposition: LeakDisposition,
        grant: BudgetGrant,
    ) -> Self {
        let capacity = grant.amount();
        let (id, _, parent) = grant.into_parts();
        parent.with_state(|state| {
            state.retire(id);
            state.add_delegated(&capacity);
        });
        Self::from_inner(LedgerInner {
            region,
            disposition,
            parent: Some(parent),
            state: Mutex::new(LedgerState::fresh(region, capacity)),
        })
    }

    /// A cloneable handle to this region's ledger.
    #[must_use]
    pub fn handle(&self) -> LedgerHandle {
        self.handle.clone()
    }

    /// The region identifier.
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.handle.region()
    }

    /// Current accounting.
    #[must_use]
    pub fn snapshot(&self) -> PoolSnapshot {
        self.handle.snapshot()
    }

    /// Every leak recorded so far.
    #[must_use]
    pub fn leaks(&self) -> Vec<LeakRecord> {
        self.handle.leaks()
    }

    /// Obligations the region still owes work for.
    #[must_use]
    pub fn outstanding(&self) -> Vec<OutstandingObligation> {
        self.handle.outstanding()
    }

    /// Removes `amount` from the available pool and hands back a grant.
    pub fn grant(&self, amount: ResourceVector) -> Result<BudgetGrant, ResourceError> {
        let id = self.handle.with_state(|state| state.carve(amount))?;
        Ok(self.handle.grant_from(id, amount))
    }

    /// Converts a grant into a reserved obligation of kind `K`.
    ///
    /// The grant must be non-zero in every grade the class declares required;
    /// on refusal the grant is released back to the pool, so a refusal never
    /// destroys budget.
    pub fn reserve<K: ObligationKind>(
        &self,
        reservation: K::Reservation,
        grant: BudgetGrant,
    ) -> Result<ReservedObligation<K>, ReserveError> {
        let amount = grant.amount();
        if self.handle.with_state(|state| state.closed) {
            let _released = grant.release();
            return Err(ReserveError::RegionClosed(self.handle.region()));
        }
        let missing = K::REQUIRED_GRADES
            .iter()
            .copied()
            .find(|grade| amount.get(*grade) == 0);
        if let Some(grade) = missing {
            let _released = grant.release();
            return Err(ReserveError::MissingGrade {
                class: K::CLASS,
                grade,
            });
        }
        let (grant_id, _, handle) = grant.into_parts();
        let id = handle.with_state(|state| {
            state.retire(grant_id);
            let id = state.allocate_obligation_id();
            state.entries.insert(
                id,
                LedgerEntry {
                    class: K::CLASS,
                    state: ObligationState::Reserved,
                    reserved: amount,
                    charged: ResourceVector::ZERO,
                },
            );
            id
        });
        let guard = handle.new_guard(
            LeakSubject::Obligation(id),
            LeakClass::ReservedObligationDropped,
        );
        Ok(ReservedObligation::from_parts(id, reservation, guard))
    }

    /// Closes the region and reports quiescence or a typed containment failure.
    ///
    /// Closing observes; it does not cancel. Cancellation is request, then
    /// drain, then finalize, and the caller performs those steps before
    /// closing. A region that closes with live obligations reports them rather
    /// than pretending they settled.
    pub fn close(self) -> RegionCloseOutcome {
        let Self { handle, mut guard } = self;
        guard.disarm();
        let report = handle.with_state(|state| {
            state.closed = true;
            let granted_now = state.granted();
            let returned = match state.available.combine(&granted_now) {
                Ok(total) => total,
                Err(_) => {
                    state.note_fault();
                    state.available
                }
            };
            CloseReport {
                unsettled: collect_outstanding(state, |value| {
                    matches!(
                        value,
                        ObligationState::Reserved
                            | ObligationState::Committed
                            | ObligationState::DeferredExternally
                    )
                }),
                escalated: collect_outstanding(state, |value| value == ObligationState::Escalated),
                leaks: state.leaks.clone(),
                consumed: state.consumed,
                returned,
                settled: u64::try_from(
                    state
                        .entries
                        .values()
                        .filter(|entry| entry.state.is_terminal())
                        .count(),
                )
                .unwrap_or(u64::MAX),
                capacity: state.capacity,
                accounting_faults: state.accounting_faults,
            }
        });
        if let Some(parent) = handle.0.parent.clone() {
            settle_child_into_parent(&parent, report.capacity, report.consumed);
        }
        if report.unsettled.is_empty()
            && report.escalated.is_empty()
            && report.leaks.is_empty()
            && report.accounting_faults == 0
        {
            RegionCloseOutcome::Quiescent(QuiescenceReceipt {
                region: handle.region(),
                settled: report.settled,
                consumed: report.consumed,
                returned: report.returned,
            })
        } else {
            RegionCloseOutcome::ContainmentFailure(ContainmentFailure {
                region: handle.region(),
                unsettled: report.unsettled,
                escalated: report.escalated,
                leaks: report.leaks,
                consumed: report.consumed,
                accounting_faults: report.accounting_faults,
            })
        }
    }
}

#[derive(Debug)]
struct CloseReport {
    unsettled: Vec<OutstandingObligation>,
    escalated: Vec<OutstandingObligation>,
    leaks: Vec<LeakRecord>,
    consumed: ResourceVector,
    returned: ResourceVector,
    settled: u64,
    capacity: ResourceVector,
    accounting_faults: u32,
}

/// Returns a closed child's unspent capacity to its parent.
///
/// The parent's accounting identity is restored exactly: the delegated amount
/// is cleared, the child's consumption is adopted, and the difference returns
/// to the parent's available pool. A child that leaked still returns its
/// budget, because a leak is a lifecycle failure and not an accounting hole.
fn settle_child_into_parent(
    parent: &LedgerHandle,
    capacity: ResourceVector,
    consumed: ResourceVector,
) {
    parent.with_state(|state| {
        state.drop_delegated(&capacity);
        state.add_consumed(&consumed);
        match capacity.split(&consumed) {
            Ok((_, unspent)) => state.give_back(unspent),
            Err(_) => state.note_fault(),
        }
    });
}
