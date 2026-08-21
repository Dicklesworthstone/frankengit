//! Deterministic flat combining over sealed preparation lanes.
//!
//! The combiner is a healthy-path optimization, never an authority lease. It
//! selects a bounded healthy-path work shape; publication remains a later
//! exact-predecessor head compare-and-set. Time is an explicit logical tick
//! from the owning runtime receipt, so a recorded lane can be replayed without
//! consulting a wall clock.

use std::collections::BTreeSet;

use fgit_resource::SettledObligation;
use fgit_resource::kinds::{NoCandidateReason, PreparedTxnSlot, SlotHandedOff};
use fgit_types::identity::{RepositoryDecisionBatchId, TxId};

use crate::lanes::{
    CombiningLane, DirectAttempt, PreparedCapsule, PreparedEntry, RetiredLane, abort_entries,
};

/// The closed, derived scheduling hint used internally by this flat combiner.
///
/// This only selects the healthy-path combined versus bypass work shape. It
/// is not an authority order, is not encoded in publication material, and is
/// not recoverable from published state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScheduleOrder {
    /// Priority class, then transaction identity.
    PriorityClassThenTxIdV1,
}

/// Fixed bounds for one deterministic flat-combiner invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchBounds {
    decision_limit: u32,
    byte_ceiling: u64,
    oldest_tick: u64,
}

impl BatchBounds {
    /// Creates non-zero decision and byte limits for a bounded microbatch.
    pub const fn try_new(
        decision_limit: u32,
        byte_ceiling: u64,
        oldest_tick: u64,
    ) -> Result<Self, BatchBoundsRefusal> {
        if decision_limit == 0 {
            return Err(BatchBoundsRefusal::ZeroDecisionLimit);
        }
        if byte_ceiling == 0 {
            return Err(BatchBoundsRefusal::ZeroByteLimit);
        }
        Ok(Self {
            decision_limit,
            byte_ceiling,
            oldest_tick,
        })
    }

    /// Maximum decisions admitted to one batch.
    #[must_use]
    pub const fn max_decisions(self) -> u32 {
        self.decision_limit
    }

    /// Maximum canonical prepared-capsule bytes admitted to one batch.
    #[must_use]
    pub const fn max_canonical_bytes(self) -> u64 {
        self.byte_ceiling
    }

    /// Largest logical ready age before an explicit direct-attempt bypass.
    #[must_use]
    pub const fn max_ready_age_ticks(self) -> u64 {
        self.oldest_tick
    }
}

/// Refusal while constructing a bounded batch policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchBoundsRefusal {
    /// A batch must admit at least one decision.
    ZeroDecisionLimit,
    /// A batch must admit at least one canonical byte.
    ZeroByteLimit,
}

/// Why a ready capsule bypassed the combined path without losing its slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BypassReason {
    /// The deterministic decision-count cut had already been reached.
    DecisionLimit,
    /// The deterministic canonical-byte cut would have been exceeded.
    ByteLimit,
    /// The capsule has waited beyond the recorded logical age bound.
    ReadyAgeLimit,
    /// The runtime supplied a tick before the capsule became ready.
    FutureReadyTick,
}

/// A direct attempt paired with the deterministic reason it bypassed batching.
#[must_use]
#[derive(Debug)]
pub struct BypassedAttempt {
    reason: BypassReason,
    attempt: DirectAttempt,
}

impl BypassedAttempt {
    /// The explicit, deterministic bypass reason.
    #[must_use]
    pub const fn reason(&self) -> BypassReason {
        self.reason
    }

    /// The owned direct attempt, still holding its preparation slot.
    #[must_use]
    pub const fn attempt(&self) -> &DirectAttempt {
        &self.attempt
    }

    /// Consumes the wrapper and returns the ready direct attempt.
    pub fn into_attempt(self) -> DirectAttempt {
        self.attempt
    }
}

/// A non-commutativity relation between two prepared transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConflictEdge {
    first: TxId,
    second: TxId,
}

impl ConflictEdge {
    fn new(left: TxId, right: TxId) -> Self {
        if left <= right {
            Self {
                first: left,
                second: right,
            }
        } else {
            Self {
                first: right,
                second: left,
            }
        }
    }

    /// First transaction identity in canonical transaction-ID order.
    #[must_use]
    pub const fn first(self) -> TxId {
        self.first
    }

    /// Second transaction identity in canonical transaction-ID order.
    #[must_use]
    pub const fn second(self) -> TxId {
        self.second
    }
}

/// A connected non-commuting component processed sequentially in scratch state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictComponent {
    transaction_ids: Vec<TxId>,
}

impl ConflictComponent {
    /// Transaction IDs in canonical transaction-ID order.
    #[must_use]
    pub fn transaction_ids(&self) -> &[TxId] {
        &self.transaction_ids
    }
}

/// Canonically represented conflict graph over the combined portion of one lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictGraph {
    ordered_transaction_ids: Vec<TxId>,
    edges: Vec<ConflictEdge>,
    components: Vec<ConflictComponent>,
}

impl ConflictGraph {
    fn from_entries(entries: &[&PreparedEntry]) -> Self {
        let mut ordered_transaction_ids = entries
            .iter()
            .map(|entry| entry.capsule.transaction_id())
            .collect::<Vec<_>>();
        ordered_transaction_ids.sort_unstable();
        let mut edges = Vec::new();
        for (offset, left) in entries.iter().enumerate() {
            for right in &entries[offset + 1..] {
                if !left
                    .capsule
                    .witnesses()
                    .is_disjoint(right.capsule.witnesses())
                {
                    edges.push(ConflictEdge::new(
                        left.capsule.transaction_id(),
                        right.capsule.transaction_id(),
                    ));
                }
            }
        }
        edges.sort_unstable();
        let components = components_for(&ordered_transaction_ids, &edges);
        Self {
            ordered_transaction_ids,
            edges,
            components,
        }
    }

    /// Transactions in canonical transaction-ID order.
    #[must_use]
    pub fn ordered_transaction_ids(&self) -> &[TxId] {
        &self.ordered_transaction_ids
    }

    /// Canonically ordered non-commutativity edges.
    #[must_use]
    pub fn edges(&self) -> &[ConflictEdge] {
        &self.edges
    }

    /// Components whose members must execute sequentially against scratch state.
    #[must_use]
    pub fn components(&self) -> &[ConflictComponent] {
        &self.components
    }
}

fn components_for(nodes: &[TxId], edges: &[ConflictEdge]) -> Vec<ConflictComponent> {
    let mut visited = BTreeSet::<TxId>::new();
    let mut components = Vec::new();
    for &root in nodes {
        if visited.contains(&root) {
            continue;
        }
        let mut reachable = BTreeSet::<TxId>::new();
        let mut frontier = vec![root];
        while let Some(current) = frontier.pop() {
            if !reachable.insert(current) {
                continue;
            }
            for edge in edges {
                if edge.first == current && !reachable.contains(&edge.second) {
                    frontier.push(edge.second);
                }
                if edge.second == current && !reachable.contains(&edge.first) {
                    frontier.push(edge.first);
                }
            }
        }
        visited.extend(&reachable);
        let transaction_ids = nodes
            .iter()
            .copied()
            .filter(|node| reachable.contains(node))
            .collect();
        components.push(ConflictComponent { transaction_ids });
    }
    components
}

/// Stateless deterministic flat combiner configuration.
///
/// The pre-combiner schedule is a derived scheduling hint only: it is not
/// recoverable from published state and carries no semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlatCombiner {
    bounds: BatchBounds,
    schedule_order: ScheduleOrder,
}

impl FlatCombiner {
    /// Creates the version-one combiner with its closed derived schedule.
    #[must_use]
    pub const fn new(bounds: BatchBounds) -> Self {
        Self {
            bounds,
            schedule_order: ScheduleOrder::PriorityClassThenTxIdV1,
        }
    }

    /// The hard batch cut applied by this combiner.
    #[must_use]
    pub const fn bounds(self) -> BatchBounds {
        self.bounds
    }

    /// Cuts and orders a sealed lane using only its stable capsule fields.
    ///
    /// The result retains every preparation slot: selected entries are owned by
    /// the combined batch and all other entries are owned by direct attempts.
    pub fn combine(
        &self,
        lane: CombiningLane,
        logical_now_tick: u64,
    ) -> Result<Combination, CombineFailure> {
        let CombiningLane {
            id,
            capacity,
            mut entries,
        } = lane;
        entries.sort_by_key(|entry| entry_order_key(self.schedule_order, entry));
        let dispositions = match plan_cut(&entries, self.bounds, logical_now_tick) {
            Ok(dispositions) => dispositions,
            Err(refusal) => {
                return Err(CombineFailure::new(
                    CombiningLane {
                        id,
                        capacity,
                        entries,
                    },
                    refusal,
                ));
            }
        };
        let selected_entries = entries
            .iter()
            .zip(&dispositions)
            .filter_map(|(entry, disposition)| {
                matches!(disposition, EntryDisposition::Selected).then_some(entry)
            })
            .collect::<Vec<_>>();
        let graph = ConflictGraph::from_entries(&selected_entries);
        let mut combined_entries = Vec::with_capacity(selected_entries.len());
        let mut bypasses = Vec::with_capacity(entries.len() - selected_entries.len());
        for (entry, disposition) in entries.into_iter().zip(dispositions) {
            match disposition {
                EntryDisposition::Selected => combined_entries.push(entry),
                EntryDisposition::Bypassed(reason) => bypasses.push(BypassedAttempt {
                    reason,
                    attempt: DirectAttempt { entry },
                }),
            }
        }
        combined_entries.sort_by_key(|entry| entry.capsule.transaction_id());
        bypasses.sort_by_key(|attempt| attempt.attempt.capsule().transaction_id());
        let retired = RetiredLane::from_combiner(id, capacity);
        let batch = (!combined_entries.is_empty()).then_some(CombinedBatch {
            entries: combined_entries,
            graph,
        });
        Ok(Combination {
            batch,
            bypasses,
            retired,
        })
    }
}

const fn entry_order_key(schedule_order: ScheduleOrder, entry: &PreparedEntry) -> (u8, TxId) {
    match schedule_order {
        ScheduleOrder::PriorityClassThenTxIdV1 => (
            entry.capsule.priority().code(),
            entry.capsule.transaction_id(),
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryDisposition {
    Selected,
    Bypassed(BypassReason),
}

fn plan_cut(
    entries: &[PreparedEntry],
    bounds: BatchBounds,
    logical_now_tick: u64,
) -> Result<Vec<EntryDisposition>, CombineRefusal> {
    let mut selected_count = 0_u32;
    let mut selected_bytes = 0_u64;
    let mut dispositions = Vec::with_capacity(entries.len());
    for entry in entries {
        let capsule = &entry.capsule;
        let disposition = if let Some(age) = logical_now_tick.checked_sub(capsule.ready_at_tick()) {
            if age > bounds.oldest_tick {
                EntryDisposition::Bypassed(BypassReason::ReadyAgeLimit)
            } else if selected_count == bounds.decision_limit {
                EntryDisposition::Bypassed(BypassReason::DecisionLimit)
            } else {
                let next_bytes = selected_bytes
                    .checked_add(canonical_len_u64(capsule)?)
                    .ok_or(CombineRefusal::CanonicalByteCountOverflow)?;
                if next_bytes > bounds.byte_ceiling {
                    EntryDisposition::Bypassed(BypassReason::ByteLimit)
                } else {
                    selected_count = selected_count
                        .checked_add(1)
                        .ok_or(CombineRefusal::DecisionCountOverflow)?;
                    selected_bytes = next_bytes;
                    EntryDisposition::Selected
                }
            }
        } else {
            EntryDisposition::Bypassed(BypassReason::FutureReadyTick)
        };
        dispositions.push(disposition);
    }
    Ok(dispositions)
}

fn canonical_len_u64(capsule: &PreparedCapsule) -> Result<u64, CombineRefusal> {
    u64::try_from(capsule.canonical_len()).map_err(|_| CombineRefusal::CanonicalByteCountOverflow)
}

/// A ready batch that owns every selected preparation-slot obligation.
#[must_use]
#[derive(Debug)]
pub struct CombinedBatch {
    entries: Vec<PreparedEntry>,
    graph: ConflictGraph,
}

impl CombinedBatch {
    /// Capsules in canonical transaction-ID order.
    ///
    /// The private pre-combiner schedule is intentionally not observable here.
    pub fn capsules(&self) -> impl ExactSizeIterator<Item = &PreparedCapsule> {
        self.entries.iter().map(|entry| &entry.capsule)
    }

    /// Conflict graph over exactly the selected batch members.
    #[must_use]
    pub const fn conflict_graph(&self) -> &ConflictGraph {
        &self.graph
    }

    /// Immutable prepared outcomes selected for the combined path.
    ///
    /// These are pre-publication outcomes only. Final `Committed` or
    /// `Refused` decisions remain owned by the authority decision stream.
    #[must_use]
    pub fn canonical_attempt_outcomes(&self) -> Vec<crate::lanes::PreparedAttemptOutcome> {
        self.entries
            .iter()
            .map(|entry| entry.capsule.canonical_attempt_outcome())
            .collect()
    }

    /// Cancels every still-owned slot before any decision batch is attempted.
    #[must_use]
    pub fn cancel(self) -> Vec<SettledObligation<PreparedTxnSlot>> {
        abort_entries(self.entries, NoCandidateReason::Cancelled)
    }

    /// Transfers all selected slots to a named decision-batch attempt.
    ///
    /// A settlement refusal is retained with every untransferred slot; already
    /// handed-off slots are reported separately and never misrepresented as
    /// cancelled or unpublished.
    pub fn hand_off(
        self,
        batch_attempt: RepositoryDecisionBatchId,
    ) -> Result<HandedOffBatch, Box<BatchHandoffFailure>> {
        let mut settled = Vec::with_capacity(self.entries.len());
        let mut remaining = self.entries.into_iter();
        while let Some(entry) = remaining.next() {
            let PreparedEntry { capsule, slot } = entry;
            let actual = slot.reserved();
            match slot.commit_internal(SlotHandedOff { batch_attempt }, &actual) {
                Ok(settled_slot) => settled.push(settled_slot),
                Err(refusal) => {
                    return Err(Box::new(BatchHandoffFailure {
                        batch_attempt,
                        handed_off: settled,
                        remaining: std::iter::once(PreparedEntry {
                            capsule,
                            slot: refusal.into_obligation(),
                        })
                        .chain(remaining)
                        .collect(),
                    }));
                }
            }
        }
        Ok(HandedOffBatch {
            batch_attempt,
            settled_slots: settled,
        })
    }
}

/// Terminal evidence that every selected slot joined a batch attempt.
#[must_use]
#[derive(Debug)]
pub struct HandedOffBatch {
    batch_attempt: RepositoryDecisionBatchId,
    settled_slots: Vec<SettledObligation<PreparedTxnSlot>>,
}

impl HandedOffBatch {
    /// Identity of the decision-batch attempt that accepted the slots.
    #[must_use]
    pub const fn batch_attempt(&self) -> RepositoryDecisionBatchId {
        self.batch_attempt
    }

    /// Settlement evidence for every accepted slot.
    #[must_use]
    pub fn settled_slots(&self) -> &[SettledObligation<PreparedTxnSlot>] {
        &self.settled_slots
    }
}

/// A partial handoff whose live obligations must still be resolved.
#[must_use]
#[derive(Debug)]
pub struct BatchHandoffFailure {
    batch_attempt: RepositoryDecisionBatchId,
    handed_off: Vec<SettledObligation<PreparedTxnSlot>>,
    remaining: Vec<PreparedEntry>,
}

impl BatchHandoffFailure {
    /// Attempt identity associated with already handed-off slots.
    #[must_use]
    pub const fn batch_attempt(&self) -> RepositoryDecisionBatchId {
        self.batch_attempt
    }

    /// Slots already handed off and therefore never safe to report cancelled.
    #[must_use]
    pub fn handed_off(&self) -> &[SettledObligation<PreparedTxnSlot>] {
        &self.handed_off
    }

    /// Cancels only the slots that remained live after the refusal.
    #[must_use]
    pub fn cancel_remaining(self) -> Vec<SettledObligation<PreparedTxnSlot>> {
        abort_entries(self.remaining, NoCandidateReason::Cancelled)
    }
}

/// The result of one deterministic combination attempt.
#[must_use]
#[derive(Debug)]
pub struct Combination {
    batch: Option<CombinedBatch>,
    bypasses: Vec<BypassedAttempt>,
    retired: RetiredLane,
}

impl Combination {
    /// The selected combined batch, if the bounded cut admitted any capsule.
    #[must_use]
    pub const fn batch(&self) -> Option<&CombinedBatch> {
        self.batch.as_ref()
    }

    /// Explicit direct-attempt bypasses in the same deterministic order.
    #[must_use]
    pub fn bypasses(&self) -> &[BypassedAttempt] {
        &self.bypasses
    }

    /// The lane is retired once it has transferred all entries to outputs.
    #[must_use]
    pub const fn retired(&self) -> &RetiredLane {
        &self.retired
    }

    /// Cancels all output owners and returns the quiescent lane for reuse.
    pub fn cancel(self) -> CombinationCancellation {
        let mut settled_slots = self.batch.map_or_else(Vec::new, CombinedBatch::cancel);
        settled_slots.extend(
            self.bypasses
                .into_iter()
                .map(BypassedAttempt::into_attempt)
                .map(DirectAttempt::cancel),
        );
        CombinationCancellation {
            retired: self.retired,
            settled_slots,
        }
    }

    /// Splits the result into independently-owned batch, bypass, and lane paths.
    pub fn into_parts(self) -> CombinationParts {
        CombinationParts {
            batch: self.batch,
            bypasses: self.bypasses,
            retired: self.retired,
        }
    }
}

/// Independently-owned outputs of a combination operation.
#[must_use]
#[derive(Debug)]
pub struct CombinationParts {
    /// Selected batch which must be handed off or cancelled.
    pub batch: Option<CombinedBatch>,
    /// Direct attempts which must be handed off or cancelled.
    pub bypasses: Vec<BypassedAttempt>,
    /// Quiescent lane which can be reopened after its output paths settle.
    pub retired: RetiredLane,
}

impl CombinationParts {
    /// Cancels every output still owned by this result.
    pub fn cancel(self) -> CombinationCancellation {
        Combination {
            batch: self.batch,
            bypasses: self.bypasses,
            retired: self.retired,
        }
        .cancel()
    }
}

/// Cancellation evidence and the reusable retired lane.
#[must_use]
#[derive(Debug)]
pub struct CombinationCancellation {
    retired: RetiredLane,
    settled_slots: Vec<SettledObligation<PreparedTxnSlot>>,
}

impl CombinationCancellation {
    /// Settlement evidence for every cancelled output slot.
    #[must_use]
    pub fn settled_slots(&self) -> &[SettledObligation<PreparedTxnSlot>] {
        &self.settled_slots
    }

    /// Returns the lane after every owned output was settled.
    pub fn into_retired(self) -> RetiredLane {
        self.retired
    }
}

/// A combination refusal that retains the live lane for cancellation or retry.
#[must_use]
#[derive(Debug)]
pub struct CombineFailure {
    lane: CombiningLane,
    refusal: CombineRefusal,
}

impl CombineFailure {
    const fn new(lane: CombiningLane, refusal: CombineRefusal) -> Self {
        Self { lane, refusal }
    }

    /// The exact condition that prevented a replayable combined attempt.
    #[must_use]
    pub const fn refusal(&self) -> CombineRefusal {
        self.refusal
    }

    /// Cancels every retained slot and returns the quiescent lane.
    pub fn cancel(self) -> RetiredLane {
        self.lane.cancel()
    }
}

/// Refusal that prevents a canonical combine operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CombineRefusal {
    /// The platform could not represent a canonical prepared-capsule length.
    CanonicalByteCountOverflow,
    /// Selected decision count overflowed despite the bounded policy.
    DecisionCountOverflow,
}

/// A direct-attempt handoff refusal retaining the live slot.
#[must_use]
#[derive(Debug)]
pub struct DirectHandoffFailure {
    attempt: DirectAttempt,
}

impl DirectHandoffFailure {
    /// Cancels the retained direct attempt without leaking its slot.
    pub fn cancel(self) -> SettledObligation<PreparedTxnSlot> {
        self.attempt.cancel()
    }
}

impl DirectAttempt {
    /// Transfers this direct bypass to a named single-decision batch attempt.
    pub fn hand_off(
        self,
        batch_attempt: RepositoryDecisionBatchId,
    ) -> Result<SettledObligation<PreparedTxnSlot>, Box<DirectHandoffFailure>> {
        let PreparedEntry { capsule, slot } = self.entry;
        let actual = slot.reserved();
        match slot.commit_internal(SlotHandedOff { batch_attempt }, &actual) {
            Ok(settled) => Ok(settled),
            Err(refusal) => Err(Box::new(DirectHandoffFailure {
                attempt: Self {
                    entry: PreparedEntry {
                        capsule,
                        slot: refusal.into_obligation(),
                    },
                },
            })),
        }
    }
}
