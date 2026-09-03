//! Pure merge delivery transition over canonical forge and outbox state.
//!
//! This is the semantic bridge between a canonical merge event batch and the
//! two authenticated state roots that must advance with the merged ref. It is a
//! pure function: no store, time source, randomness, worker, or authority-head
//! mutation is consulted.
//!
//! Stable delivery identity is derived by `fgit-codec` from immutable semantic
//! inputs. The transition refuses a caller-selected duplicate key rather than
//! overwriting an existing obligation, and it never derives identity from the
//! winning head generation.

use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxState, CanonicalOutboxStateEntry, CodecRefusal,
    ForgePositionStateEntry, OutboxDeliveryIdentityInput, derive_outbox_delivery_key,
};
use fgit_types::{AsciiSlug, Digest, RepositoryCommitId, RepositoryId, TxId};

use crate::intent::{ForgeStreamId, ForgeStreamPosition, OutboxDeliveryKey};

/// Immutable semantic input for one merge delivery transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeDeliveryInput {
    repository_id: RepositoryId,
    stream: ForgeStreamId,
    expected_position: ForgeStreamPosition,
    event_count: u32,
    event_batch_root: Digest,
    effect_class: AsciiSlug,
    destination: AsciiSlug,
    payload_root: Digest,
    tx_id: TxId,
    predecessor_rcr_id: Option<RepositoryCommitId>,
    initial_effect_state_root: Digest,
}

impl MergeDeliveryInput {
    /// Creates one complete transition input.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        repository_id: RepositoryId,
        stream: ForgeStreamId,
        expected_position: ForgeStreamPosition,
        event_count: u32,
        event_batch_root: Digest,
        effect_class: AsciiSlug,
        destination: AsciiSlug,
        payload_root: Digest,
        tx_id: TxId,
        predecessor_rcr_id: Option<RepositoryCommitId>,
        initial_effect_state_root: Digest,
    ) -> Self {
        Self {
            repository_id,
            stream,
            expected_position,
            event_count,
            event_batch_root,
            effect_class,
            destination,
            payload_root,
            tx_id,
            predecessor_rcr_id,
            initial_effect_state_root,
        }
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Forge stream advanced by the event batch.
    #[must_use]
    pub const fn stream(self) -> ForgeStreamId {
        self.stream
    }

    /// Exact predecessor stream position.
    #[must_use]
    pub const fn expected_position(self) -> ForgeStreamPosition {
        self.expected_position
    }

    /// Number of ordered events in the batch.
    #[must_use]
    pub const fn event_count(self) -> u32 {
        self.event_count
    }

    /// Immutable event-batch commitment.
    #[must_use]
    pub const fn event_batch_root(self) -> Digest {
        self.event_batch_root
    }

    /// Stable delivery effect class.
    #[must_use]
    pub const fn effect_class(self) -> AsciiSlug {
        self.effect_class
    }

    /// Stable delivery destination or audience.
    #[must_use]
    pub const fn destination(self) -> AsciiSlug {
        self.destination
    }

    /// Immutable delivery payload commitment.
    #[must_use]
    pub const fn payload_root(self) -> Digest {
        self.payload_root
    }

    /// Sealed transaction whose semantics produced the merge.
    #[must_use]
    pub const fn tx_id(self) -> TxId {
        self.tx_id
    }

    /// Previously committed RCR at the transition basis.
    #[must_use]
    pub const fn predecessor_rcr_id(self) -> Option<RepositoryCommitId> {
        self.predecessor_rcr_id
    }

    /// Initial canonical effect/obligation-state commitment.
    #[must_use]
    pub const fn initial_effect_state_root(self) -> Digest {
        self.initial_effect_state_root
    }
}

/// Complete pure successor state for one merge delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeDeliveryTransition {
    forge_positions: CanonicalForgePositionState,
    outbox: CanonicalOutboxState,
    forge_position_root: Digest,
    outbox_root: Digest,
    delivery_key: OutboxDeliveryKey,
}

impl MergeDeliveryTransition {
    /// Successor canonical forge-position state.
    #[must_use]
    pub const fn forge_positions(&self) -> &CanonicalForgePositionState {
        &self.forge_positions
    }

    /// Successor canonical outbox state.
    #[must_use]
    pub const fn outbox(&self) -> &CanonicalOutboxState {
        &self.outbox
    }

    /// Root to bind as the successor `forge_position_root`.
    #[must_use]
    pub const fn forge_position_root(&self) -> Digest {
        self.forge_position_root
    }

    /// Root to bind as the successor `outbox_root`.
    #[must_use]
    pub const fn outbox_root(&self) -> Digest {
        self.outbox_root
    }

    /// Stable delivery key derived from immutable merge semantics.
    #[must_use]
    pub const fn delivery_key(&self) -> OutboxDeliveryKey {
        self.delivery_key
    }
}

/// Applies one merge event batch and its delivery obligation to canonical
/// predecessor state.
///
/// # Errors
///
/// Refuses repository mismatch, stale stream position, a stable delivery key
/// already present in the predecessor, malformed position arithmetic, map
/// bounds, and canonical-root framing failure.
pub fn apply_merge_delivery_transition(
    forge_basis: &CanonicalForgePositionState,
    outbox_basis: &CanonicalOutboxState,
    input: MergeDeliveryInput,
) -> Result<MergeDeliveryTransition, MergeDeliveryTransitionRefusal> {
    if forge_basis.repository_id() != input.repository_id
        || outbox_basis.repository_id() != input.repository_id
    {
        return Err(MergeDeliveryTransitionRefusal::RepositoryMismatch {
            expected: input.repository_id,
            forge_observed: forge_basis.repository_id(),
            outbox_observed: outbox_basis.repository_id(),
        });
    }

    let stream = input.stream.label();
    let observed_position = forge_basis
        .entry(stream)
        .map_or(ForgeStreamPosition::GENESIS, |entry| {
            ForgeStreamPosition::new(entry.successor_position())
        });
    if observed_position != input.expected_position {
        return Err(MergeDeliveryTransitionRefusal::ForgePositionMismatch {
            stream: input.stream,
            expected: input.expected_position,
            observed: observed_position,
        });
    }

    let identity_input = OutboxDeliveryIdentityInput::new(
        input.repository_id,
        input.effect_class,
        input.destination,
        input.payload_root,
        input.tx_id,
        input.predecessor_rcr_id,
    );
    let delivery_label = derive_outbox_delivery_key(identity_input)?;
    let delivery_key = OutboxDeliveryKey::new(delivery_label);
    if outbox_basis.entry(delivery_label).is_some() {
        return Err(MergeDeliveryTransitionRefusal::DeliveryKeyAlreadyPresent { delivery_key });
    }

    let next_forge_entry = ForgePositionStateEntry::try_new(
        stream,
        input.expected_position.get(),
        input.event_count,
        input.event_batch_root,
    )?;
    let mut forge_entries = forge_basis.entries().to_vec();
    if let Some(index) = forge_entries
        .iter()
        .position(|entry| entry.stream() == stream)
    {
        forge_entries[index] = next_forge_entry;
    } else {
        forge_entries.push(next_forge_entry);
    }
    let forge_positions = CanonicalForgePositionState::try_new(input.repository_id, forge_entries)?;

    let mut outbox_entries = outbox_basis.entries().to_vec();
    outbox_entries.push(CanonicalOutboxStateEntry::new(
        delivery_label,
        input.effect_class,
        input.destination,
        input.payload_root,
        input.tx_id,
        input.predecessor_rcr_id,
        input.initial_effect_state_root,
        None,
    ));
    let outbox = CanonicalOutboxState::try_new(input.repository_id, outbox_entries)?;
    let forge_position_root = forge_positions.root()?;
    let outbox_root = outbox.root()?;

    Ok(MergeDeliveryTransition {
        forge_positions,
        outbox,
        forge_position_root,
        outbox_root,
        delivery_key,
    })
}

/// Why a pure merge delivery transition failed closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeDeliveryTransitionRefusal {
    /// The two predecessor states do not belong to the requested repository.
    RepositoryMismatch {
        /// Requested repository.
        expected: RepositoryId,
        /// Repository retained by forge state.
        forge_observed: RepositoryId,
        /// Repository retained by outbox state.
        outbox_observed: RepositoryId,
    },
    /// The stream was not at the exact expected predecessor position.
    ForgePositionMismatch {
        /// Stream whose precondition failed.
        stream: ForgeStreamId,
        /// Caller-declared exact predecessor.
        expected: ForgeStreamPosition,
        /// Canonical predecessor state.
        observed: ForgeStreamPosition,
    },
    /// The stable semantic delivery identity is already present.
    DeliveryKeyAlreadyPresent {
        /// Colliding stable key.
        delivery_key: OutboxDeliveryKey,
    },
    /// Canonical state construction or identity failed.
    Codec(CodecRefusal),
}

impl core::fmt::Display for MergeDeliveryTransitionRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "merge delivery transition refused: {self:?}")
    }
}

impl core::error::Error for MergeDeliveryTransitionRefusal {}

impl From<CodecRefusal> for MergeDeliveryTransitionRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}
