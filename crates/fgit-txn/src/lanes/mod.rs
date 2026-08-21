//! Per-core preparation lanes and owned ready slots.
//!
//! A lane is deliberately a type-state machine rather than a mutable status
//! flag. A prepared capsule can enter a [`SealedLane`] only with the matching
//! [`PreparedTxnSlot`] obligation, and that obligation remains owned until a
//! combiner hands it to a decision-batch attempt or cancellation aborts it.

use std::collections::BTreeSet;

use fgit_resource::kinds::{NoCandidateReason, PreparedTxnSlot, SlotAbandoned};
use fgit_resource::{ReservedObligation, SettledObligation};
use fgit_types::identity::{PreparedTxnCapsuleId, TxId};
use fgit_types::numeric::DecisionSequence;

/// The largest witness key accepted by one prepared capsule.
pub const MAX_WITNESS_KEY_BYTES: usize = 256;

/// The largest number of conservative conflict witnesses on one capsule.
pub const MAX_CONFLICT_WITNESSES: usize = 256;

/// The largest canonical prepared-capsule body this lane implementation holds.
pub const MAX_PREPARED_CAPSULE_BYTES: usize = 1024 * 1024;

/// Stable identity of one preparation lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaneId(u16);

impl LaneId {
    /// Creates a stable lane identity.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the stable lane identity.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// The lifecycle position of a preparation lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LaneState {
    /// New capsules may be appended.
    Writable,
    /// Every capsule owns a reserved [`PreparedTxnSlot`].
    Sealed,
    /// A combiner exclusively owns the sealed capsules.
    Combining,
    /// All owned slots were handed off or settled, ready for reuse.
    Retired,
}

/// Transaction priority in the version-one combiner policy.
///
/// Smaller variants win the priority portion of the tie-break. The sealed
/// decision sequence still dominates this class, so priority never changes a
/// pre-existing sealed order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PriorityClass {
    /// An operator-initiated safety or recovery transaction.
    Critical,
    /// An interactive client transaction.
    Interactive,
    /// An ordinary admitted transaction.
    Normal,
    /// Deferred maintenance work.
    Background,
}

impl PriorityClass {
    /// Stable code carried in a decision-path hash.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::Interactive => 1,
            Self::Normal => 2,
            Self::Background => 3,
        }
    }
}

/// The authority-adjacent domain a conservative conflict witness protects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WitnessDomain {
    /// The authority-head basis.
    RepositoryHead,
    /// One exact reference or namespace family.
    Reference,
    /// One forge aggregate or stream.
    Forge,
    /// Protection, review, or policy input.
    Policy,
    /// Quota, retention, or legal-hold state.
    QuotaOrRetention,
    /// Object-closure assumptions.
    ObjectClosure,
    /// A graph or search generation read by policy.
    GraphGeneration,
}

impl WitnessDomain {
    /// Stable code carried in a decision-path hash.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::RepositoryHead => 0,
            Self::Reference => 1,
            Self::Forge => 2,
            Self::Policy => 3,
            Self::QuotaOrRetention => 4,
            Self::ObjectClosure => 5,
            Self::GraphGeneration => 6,
        }
    }
}

/// One conservative read or write witness carried by a prepared capsule.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConflictWitness {
    domain: WitnessDomain,
    key: Vec<u8>,
}

impl ConflictWitness {
    /// Creates a bounded witness key.
    pub fn try_new(domain: WitnessDomain, key: Vec<u8>) -> Result<Self, LaneRefusal> {
        if key.is_empty() {
            return Err(LaneRefusal::EmptyWitnessKey);
        }
        if key.len() > MAX_WITNESS_KEY_BYTES {
            return Err(LaneRefusal::WitnessKeyTooLarge {
                observed: key.len(),
                maximum: MAX_WITNESS_KEY_BYTES,
            });
        }
        Ok(Self { domain, key })
    }

    /// The domain this witness protects.
    #[must_use]
    pub const fn domain(&self) -> WitnessDomain {
        self.domain
    }

    /// The canonical witness key bytes.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

/// One capsule ready for a combiner once its slot is reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedCapsule {
    capsule_id: PreparedTxnCapsuleId,
    transaction_id: TxId,
    sealed_sequence: DecisionSequence,
    priority: PriorityClass,
    ready_at_tick: u64,
    canonical_bytes: Vec<u8>,
    witnesses: BTreeSet<ConflictWitness>,
}

impl PreparedCapsule {
    /// Creates a bounded, immutable prepared capsule descriptor.
    pub fn try_new(
        capsule_id: PreparedTxnCapsuleId,
        transaction_id: TxId,
        sealed_sequence: DecisionSequence,
        priority: PriorityClass,
        ready_at_tick: u64,
        canonical_bytes: Vec<u8>,
        witnesses: BTreeSet<ConflictWitness>,
    ) -> Result<Self, LaneRefusal> {
        if canonical_bytes.len() > MAX_PREPARED_CAPSULE_BYTES {
            return Err(LaneRefusal::CapsuleTooLarge {
                observed: canonical_bytes.len(),
                maximum: MAX_PREPARED_CAPSULE_BYTES,
            });
        }
        if witnesses.len() > MAX_CONFLICT_WITNESSES {
            return Err(LaneRefusal::TooManyWitnesses {
                observed: witnesses.len(),
                maximum: MAX_CONFLICT_WITNESSES,
            });
        }
        Ok(Self {
            capsule_id,
            transaction_id,
            sealed_sequence,
            priority,
            ready_at_tick,
            canonical_bytes,
            witnesses,
        })
    }

    /// Immutable prepared-capsule identity.
    #[must_use]
    pub const fn capsule_id(&self) -> PreparedTxnCapsuleId {
        self.capsule_id
    }

    /// Stable identity of the sealed logical transaction.
    #[must_use]
    pub const fn transaction_id(&self) -> TxId {
        self.transaction_id
    }

    /// The sealed decision sequence used by the deterministic combiner policy.
    #[must_use]
    pub const fn sealed_sequence(&self) -> DecisionSequence {
        self.sealed_sequence
    }

    /// The user-visible priority class.
    #[must_use]
    pub const fn priority(&self) -> PriorityClass {
        self.priority
    }

    /// Logical lane tick at which the prepared capsule became ready.
    ///
    /// This is supplied by the owning runtime receipt rather than by a wall
    /// clock, keeping the bounded batch cut replayable.
    #[must_use]
    pub const fn ready_at_tick(&self) -> u64 {
        self.ready_at_tick
    }

    /// Exact canonical prepared-capsule bytes already validated by preparation.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Conservative witnesses in canonical sorted order.
    #[must_use]
    pub const fn witnesses(&self) -> &BTreeSet<ConflictWitness> {
        &self.witnesses
    }

    /// Canonical byte cost used by a microbatch cut.
    #[must_use]
    pub const fn canonical_len(&self) -> usize {
        self.canonical_bytes.len()
    }
}

/// Hard capacity of one append-only lane buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneCapacity {
    max_capsules: usize,
    max_canonical_bytes: usize,
}

impl LaneCapacity {
    /// Creates a non-empty bounded lane capacity.
    pub fn try_new(max_capsules: usize, max_canonical_bytes: usize) -> Result<Self, LaneRefusal> {
        if max_capsules == 0 {
            return Err(LaneRefusal::ZeroCapsuleCapacity);
        }
        if max_canonical_bytes == 0 {
            return Err(LaneRefusal::ZeroByteCapacity);
        }
        Ok(Self {
            max_capsules,
            max_canonical_bytes,
        })
    }

    /// Maximum capsule count before explicit overflow is required.
    #[must_use]
    pub const fn max_capsules(self) -> usize {
        self.max_capsules
    }

    /// Maximum canonical bytes before explicit overflow is required.
    #[must_use]
    pub const fn max_canonical_bytes(self) -> usize {
        self.max_canonical_bytes
    }
}

/// Refusal for a lane operation that cannot preserve its invariants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneRefusal {
    /// A witness key was empty and therefore had no stable scope.
    EmptyWitnessKey,
    /// A witness key exceeded the bounded preparation surface.
    WitnessKeyTooLarge {
        /// Observed key bytes.
        observed: usize,
        /// Maximum key bytes.
        maximum: usize,
    },
    /// A capsule body exceeded the bounded preparation surface.
    CapsuleTooLarge {
        /// Observed canonical body bytes.
        observed: usize,
        /// Maximum body bytes.
        maximum: usize,
    },
    /// A capsule's conflict surface exceeded the bounded graph input.
    TooManyWitnesses {
        /// Observed witness count.
        observed: usize,
        /// Maximum witnesses per capsule.
        maximum: usize,
    },
    /// A lane could not accept even one capsule.
    ZeroCapsuleCapacity,
    /// A lane could not accept any canonical bytes.
    ZeroByteCapacity,
    /// Two prepared capsules named the same sealed transaction.
    DuplicateTransaction,
    /// The supplied slots did not exactly cover the sealed capsules.
    SlotCountMismatch {
        /// Capsules waiting for slots.
        capsules: usize,
        /// Supplied slot obligations.
        slots: usize,
    },
    /// A slot was reserved for another lane.
    SlotLaneMismatch {
        /// Lane that owns the buffer.
        expected: LaneId,
        /// Lane named by the slot reservation.
        observed: LaneId,
    },
    /// A slot named a transaction absent from this sealed buffer.
    SlotTransactionMismatch,
    /// More than one slot named the same transaction.
    DuplicateSlotTransaction,
}

/// One capsule the lane could not append without exceeding its fixed bound.
#[must_use]
#[derive(Debug)]
pub struct OverflowedCapsule {
    capsule: PreparedCapsule,
}

impl OverflowedCapsule {
    /// The capsule requiring a secondary lane or direct-attempt bypass.
    #[must_use]
    pub fn capsule(&self) -> &PreparedCapsule {
        &self.capsule
    }

    /// Consumes the explicit overflow result and returns its capsule.
    #[must_use]
    pub fn into_capsule(self) -> PreparedCapsule {
        self.capsule
    }
}

/// A non-overflow append refusal retaining the caller's capsule.
#[must_use]
#[derive(Debug)]
pub struct AppendRefusal {
    capsule: PreparedCapsule,
    refusal: LaneRefusal,
}

impl AppendRefusal {
    /// The invariant that rejected the append.
    #[must_use]
    pub const fn refusal(&self) -> LaneRefusal {
        self.refusal
    }

    /// Returns the capsule without creating a ready-slot obligation.
    #[must_use]
    pub fn into_capsule(self) -> PreparedCapsule {
        self.capsule
    }
}

/// The caller-visible outcome of appending one prepared capsule.
#[must_use]
#[derive(Debug)]
pub enum AppendFailure {
    /// The capsule must use a secondary lane or direct-attempt bypass.
    Overflow(OverflowedCapsule),
    /// The capsule violated a lane invariant and cannot bypass it.
    Refused(AppendRefusal),
}

/// A writable lane that has not yet attached ready-slot obligations.
#[must_use]
#[derive(Debug)]
pub struct WritableLane {
    id: LaneId,
    capacity: LaneCapacity,
    pending: Vec<PreparedCapsule>,
    canonical_bytes: usize,
}

impl WritableLane {
    /// Creates an empty append-only lane.
    #[must_use]
    pub const fn new(id: LaneId, capacity: LaneCapacity) -> Self {
        Self {
            id,
            capacity,
            pending: Vec::new(),
            canonical_bytes: 0,
        }
    }

    /// The lane identity retained for the transaction lifetime.
    #[must_use]
    pub const fn id(&self) -> LaneId {
        self.id
    }

    /// This typed value is writable.
    #[must_use]
    pub const fn state(&self) -> LaneState {
        LaneState::Writable
    }

    /// Number of prepared capsules awaiting slots.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no capsule has been appended.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Appends one prepared capsule or returns it on the explicit overflow path.
    pub fn append(&mut self, capsule: PreparedCapsule) -> Result<(), AppendFailure> {
        let next_bytes = self.canonical_bytes.saturating_add(capsule.canonical_len());
        if self.pending.len() == self.capacity.max_capsules
            || next_bytes > self.capacity.max_canonical_bytes
        {
            return Err(AppendFailure::Overflow(OverflowedCapsule { capsule }));
        }
        if self
            .pending
            .iter()
            .any(|existing| existing.transaction_id == capsule.transaction_id)
        {
            return Err(AppendFailure::Refused(AppendRefusal {
                capsule,
                refusal: LaneRefusal::DuplicateTransaction,
            }));
        }
        self.canonical_bytes = next_bytes;
        self.pending.push(capsule);
        Ok(())
    }

    /// Cancels preparation before any ready-slot obligation was reserved.
    #[must_use]
    pub fn cancel(self) -> RetiredLane {
        RetiredLane {
            id: self.id,
            capacity: self.capacity,
        }
    }

    /// Attaches exactly one reserved slot to every capsule and seals the lane.
    pub fn seal(self, slots: Vec<ReservedPreparedSlot>) -> Result<SealedLane, SealFailure> {
        let Self {
            id,
            capacity,
            mut pending,
            canonical_bytes,
        } = self;
        let capsule_count = pending.len();
        let slot_count = slots.len();
        if capsule_count != slot_count {
            return Err(SealFailure {
                lane: Self {
                    id,
                    capacity,
                    pending,
                    canonical_bytes,
                },
                slots,
                refusal: LaneRefusal::SlotCountMismatch {
                    capsules: capsule_count,
                    slots: slot_count,
                },
            });
        }

        let mut slots = slots;
        slots.sort_by_key(|slot| slot.reservation().transaction);
        for pair in slots.windows(2) {
            if pair[0].reservation().transaction == pair[1].reservation().transaction {
                return Err(SealFailure {
                    lane: Self {
                        id,
                        capacity,
                        pending,
                        canonical_bytes,
                    },
                    slots,
                    refusal: LaneRefusal::DuplicateSlotTransaction,
                });
            }
        }

        pending.sort_by_key(PreparedCapsule::transaction_id);
        for pair in pending.windows(2) {
            if pair[0].transaction_id == pair[1].transaction_id {
                return Err(SealFailure {
                    lane: Self {
                        id,
                        capacity,
                        canonical_bytes,
                        pending,
                    },
                    slots,
                    refusal: LaneRefusal::DuplicateTransaction,
                });
            }
        }

        for slot in &slots {
            let reservation = slot.reservation();
            let observed_lane = LaneId::new(reservation.lane);
            if observed_lane != id {
                return Err(SealFailure {
                    lane: Self {
                        id,
                        capacity,
                        pending,
                        canonical_bytes,
                    },
                    slots,
                    refusal: LaneRefusal::SlotLaneMismatch {
                        expected: id,
                        observed: observed_lane,
                    },
                });
            }
        }
        if pending
            .iter()
            .zip(&slots)
            .any(|(capsule, slot)| slot.reservation().transaction != capsule.transaction_id)
        {
            return Err(SealFailure {
                lane: Self {
                    id,
                    capacity,
                    pending,
                    canonical_bytes,
                },
                slots,
                refusal: LaneRefusal::SlotTransactionMismatch,
            });
        }

        let mut entries = Vec::with_capacity(pending.len());
        for (capsule, slot) in pending.into_iter().zip(slots) {
            entries.push(PreparedEntry { capsule, slot });
        }
        Ok(SealedLane {
            id,
            capacity,
            entries,
        })
    }
}

/// Concrete ownership of a ready preparation slot.
pub type ReservedPreparedSlot = ReservedObligation<PreparedTxnSlot>;

/// A sealing refusal that retains all live slot obligations for explicit abort.
#[must_use]
#[derive(Debug)]
pub struct SealFailure {
    lane: WritableLane,
    slots: Vec<ReservedPreparedSlot>,
    refusal: LaneRefusal,
}

impl SealFailure {
    /// The refusal that prevented a safe sealed lane.
    #[must_use]
    pub const fn refusal(&self) -> LaneRefusal {
        self.refusal
    }

    /// Aborts every retained slot and returns the still-writable lane.
    #[must_use]
    pub fn abort_cancelled(self) -> WritableLane {
        for slot in self.slots {
            let _settled = slot.abort_unused(SlotAbandoned {
                reason: NoCandidateReason::Cancelled,
            });
        }
        self.lane
    }
}

/// A lane whose ready capsules each own one preparation slot.
#[must_use]
#[derive(Debug)]
pub struct SealedLane {
    id: LaneId,
    capacity: LaneCapacity,
    entries: Vec<PreparedEntry>,
}

impl SealedLane {
    /// Lane identity.
    #[must_use]
    pub const fn id(&self) -> LaneId {
        self.id
    }

    /// This typed value is sealed.
    #[must_use]
    pub const fn state(&self) -> LaneState {
        LaneState::Sealed
    }

    /// Ready capsules in transaction-ID order, independent of caller map order.
    #[must_use]
    pub fn capsules(&self) -> impl ExactSizeIterator<Item = &PreparedCapsule> {
        self.entries.iter().map(|entry| &entry.capsule)
    }

    /// Transfers exclusive ownership of the ready buffer to a combiner.
    #[must_use]
    pub fn begin_combining(self) -> CombiningLane {
        CombiningLane {
            id: self.id,
            capacity: self.capacity,
            entries: self.entries,
        }
    }

    /// Cancellation before combining abandons every ready slot.
    #[must_use]
    pub fn cancel(self) -> RetiredLane {
        abort_entries(self.entries, NoCandidateReason::Cancelled);
        RetiredLane {
            id: self.id,
            capacity: self.capacity,
        }
    }
}

/// A lane exclusively owned by a combiner.
#[must_use]
#[derive(Debug)]
pub struct CombiningLane {
    pub(crate) id: LaneId,
    pub(crate) capacity: LaneCapacity,
    pub(crate) entries: Vec<PreparedEntry>,
}

impl CombiningLane {
    /// Lane identity.
    #[must_use]
    pub const fn id(&self) -> LaneId {
        self.id
    }

    /// This typed value is combining.
    #[must_use]
    pub const fn state(&self) -> LaneState {
        LaneState::Combining
    }

    /// Cancellation during combining abandons every still-owned slot.
    #[must_use]
    pub fn cancel(self) -> RetiredLane {
        abort_entries(self.entries, NoCandidateReason::Cancelled);
        RetiredLane {
            id: self.id,
            capacity: self.capacity,
        }
    }
}

/// A lane with no live slot ownership, ready to become writable again.
#[must_use]
#[derive(Debug)]
pub struct RetiredLane {
    id: LaneId,
    capacity: LaneCapacity,
}

impl RetiredLane {
    /// Creates a retired lane after a combiner transferred every entry.
    #[must_use]
    pub(crate) const fn from_combiner(id: LaneId, capacity: LaneCapacity) -> Self {
        Self { id, capacity }
    }

    /// Lane identity.
    #[must_use]
    pub const fn id(&self) -> LaneId {
        self.id
    }

    /// This typed value is retired.
    #[must_use]
    pub const fn state(&self) -> LaneState {
        LaneState::Retired
    }

    /// Cancellation after retirement preserves the quiescent reusable state.
    #[must_use]
    pub const fn cancel(self) -> Self {
        self
    }

    /// Reopens a quiescent lane with its original fixed capacity.
    #[must_use]
    pub const fn reopen(self) -> WritableLane {
        WritableLane::new(self.id, self.capacity)
    }
}

/// A concrete direct-attempt bypass that still owns its ready slot.
#[must_use]
#[derive(Debug)]
pub struct DirectAttempt {
    pub(crate) entry: PreparedEntry,
}

impl DirectAttempt {
    /// Creates a direct attempt when a slot exactly matches an overflowed capsule.
    pub fn try_new(
        lane: LaneId,
        capsule: PreparedCapsule,
        slot: ReservedPreparedSlot,
    ) -> Result<Self, DirectAttemptRefusal> {
        let reservation = slot.reservation();
        let observed_lane = LaneId::new(reservation.lane);
        if observed_lane != lane {
            return Err(DirectAttemptRefusal {
                capsule,
                slot,
                refusal: LaneRefusal::SlotLaneMismatch {
                    expected: lane,
                    observed: observed_lane,
                },
            });
        }
        if reservation.transaction != capsule.transaction_id {
            return Err(DirectAttemptRefusal {
                capsule,
                slot,
                refusal: LaneRefusal::SlotTransactionMismatch,
            });
        }
        Ok(Self {
            entry: PreparedEntry { capsule, slot },
        })
    }

    /// The direct-attempt capsule.
    #[must_use]
    pub fn capsule(&self) -> &PreparedCapsule {
        &self.entry.capsule
    }

    /// Cancellation abandons the slot instead of dropping it.
    #[must_use]
    pub fn cancel(self) -> SettledObligation<PreparedTxnSlot> {
        self.entry.slot.abort_unused(SlotAbandoned {
            reason: NoCandidateReason::Cancelled,
        })
    }
}

/// A direct-attempt refusal retaining the capsule and live slot.
#[must_use]
#[derive(Debug)]
pub struct DirectAttemptRefusal {
    capsule: PreparedCapsule,
    slot: ReservedPreparedSlot,
    refusal: LaneRefusal,
}

impl DirectAttemptRefusal {
    /// The refusal that prevented a direct attempt.
    #[must_use]
    pub const fn refusal(&self) -> LaneRefusal {
        self.refusal
    }

    /// Cancels the retained slot and returns its capsule for a secondary lane.
    #[must_use]
    pub fn abort_cancelled(self) -> PreparedCapsule {
        let _settled = self.slot.abort_unused(SlotAbandoned {
            reason: NoCandidateReason::Cancelled,
        });
        self.capsule
    }
}

/// Internal pairing of an immutable capsule with its owned ready slot.
#[derive(Debug)]
pub(crate) struct PreparedEntry {
    pub(crate) capsule: PreparedCapsule,
    pub(crate) slot: ReservedPreparedSlot,
}

pub(crate) fn abort_entries(
    entries: Vec<PreparedEntry>,
    reason: NoCandidateReason,
) -> Vec<SettledObligation<PreparedTxnSlot>> {
    entries
        .into_iter()
        .map(|entry| entry.slot.abort_unused(SlotAbandoned { reason }))
        .collect()
}
