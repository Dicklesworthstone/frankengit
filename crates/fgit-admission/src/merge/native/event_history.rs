//! Complete aggregate history independent of active delivery responsibility.
//!
//! The authenticated frontier and active outbox are useful event sources, but
//! terminal delivery may remove any outbox entry. Missing versions come from
//! the same selected head's verified predecessor chain. A visitor retains only
//! the payloads its read model needs; this collector keeps bounded identities.

use std::collections::{BTreeMap, BTreeSet};

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{HistoryStep, PublicationBasis, read_history_step_async};
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch};
use fgit_types::{Digest, HeadGeneration, RefusalCode, RepositoryId};

use super::{delivery, storage, unavailable};
use crate::AdmissionError;

const MAX_HISTORY_STEPS: usize = 4096;
const MAX_HISTORY_DECISIONS: usize = 65_536;

/// Callers may narrow, but cannot increase, the established replay profile.
#[derive(Clone, Copy, Debug)]
pub(super) struct HistoryReadLimits {
    pub events: usize,
    pub scan_bytes: usize,
}

impl HistoryReadLimits {
    pub const DEFAULT: Self = Self {
        events: 65_536,
        scan_bytes: 128 * 1024 * 1024,
    };

    const fn validate(self) -> Result<(), AdmissionError> {
        if self.events == 0
            || self.events > Self::DEFAULT.events
            || self.scan_bytes == 0
            || self.scan_bytes > Self::DEFAULT.scan_bytes
        {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HistoryReadSummary {
    pub scanned_events: usize,
    pub scanned_bytes: usize,
}

/// Visit each selected `(aggregate, version)` once, with its encoded byte size.
///
/// The caller supplies maps already authenticated by `delivery::read_roots_in`
/// and exact entries from that forge map. A successful return proves complete
/// versions `1..=frontier` and the exact frontier batch for every selected
/// aggregate. Root identity, duplicate consistency, scanning and predecessor
/// bounds are checked here. The visitor owns its existing retained-byte bound.
///
/// Arrival order is unspecified: reducers that need causal order must retain
/// version-keyed events and fold after this operation succeeds. Visitors must
/// not publish or disclose intermediate results; a later dependency may refuse.
/// Complete active histories never require unrelated older authority history.
pub(super) async fn visit_selected_at<S, C, F>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    forge: &CanonicalForgePositionState,
    outbox: &CanonicalOutboxState,
    selected: &BTreeMap<AggregateId, ForgePositionStateEntry>,
    limits: HistoryReadLimits,
    visitor: &mut F,
    cancelled: &C,
) -> Result<HistoryReadSummary, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
    F: FnMut(&ForgeEvent, usize) -> Result<(), AdmissionError> + Send,
{
    limits.validate()?;
    checkpoint(cancelled)?;
    let repository = basis.body().repository_id;
    if fgit_authority::authority_head_identity(basis.body())
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
        != basis.id()
        || forge.repository_id() != repository
        || outbox.repository_id() != repository
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let mut frontier_roots = BTreeMap::<Digest, Vec<&ForgePositionStateEntry>>::new();
    for (aggregate, position) in selected {
        checkpoint(cancelled)?;
        let label = storage::aggregate_label(*aggregate)?;
        if position.stream() != label || forge.entry(label) != Some(position) {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        frontier_roots
            .entry(position.event_batch_root())
            .or_default()
            .push(position);
    }
    let mut replay = ReplayEvents::new(forge, selected, limits, visitor);
    if selected.is_empty() {
        return Ok(replay.summary());
    }
    // A shared frontier batch is read and charged once, then every selected
    // range is authenticated before its version becomes a completeness bound.
    for (root, positions) in frontier_roots {
        let batch = replay
            .read_root(store, cx, repository, root, false, cancelled)
            .await?
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let mut ranges = positions
            .into_iter()
            .map(|position| (position.stream(), (position, 0_u32)))
            .collect();
        if !delivery::validate_position_ranges(&mut ranges, &batch, cancelled)?.is_empty() {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    let expected_events = selected.values().try_fold(0usize, |total, frontier| {
        let version = usize::try_from(frontier.successor_position())
            .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        charge(total, version, limits.events)
    })?;
    for entry in outbox.entries() {
        replay
            .read_root(
                store,
                cx,
                repository,
                entry.payload_root(),
                false,
                cancelled,
            )
            .await?;
    }

    // Every retained identity is unique, nonzero and no newer than its own
    // frontier. Equality therefore proves contiguous coverage without walking
    // attacker-selected integer ranges. Outbox absence never proves retention.
    let mut successor = basis.body().clone();
    let (mut steps, mut decisions) = (0usize, 0usize);
    while replay.events.len() != expected_events {
        checkpoint(cancelled)?;
        match read_history_step_async(
            store,
            cx,
            &successor,
            &mut steps,
            MAX_HISTORY_STEPS,
            cancelled,
        )
        .await
        .map_err(storage::history_step_refusal)?
        {
            HistoryStep::Genesis => {
                // Preserve supported seeded state only at the actual genesis
                // reached through this authenticated predecessor chain.
                if successor.repository_id != repository
                    || successor.generation != HeadGeneration::FIRST
                    || successor.predecessor_head_id.is_some()
                    || successor.decision_tail_id.is_some()
                    || successor.latest_committed_rcr_id.is_some()
                    || successor.latest_repository_sequence.is_some()
                    || successor.latest_decision_sequence.is_some()
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                let genesis = PublicationBasis::new(
                    fgit_authority::authority_head_identity(&successor)
                        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?,
                    successor,
                );
                let initial = delivery::read_roots_in(store, cx, &genesis, cancelled).await?;
                let mut initial_roots = BTreeMap::<Digest, Vec<&ForgePositionStateEntry>>::new();
                for aggregate in selected.keys() {
                    checkpoint(cancelled)?;
                    if let Some(position) =
                        initial.forge.entry(storage::aggregate_label(*aggregate)?)
                        && !replay.batches.contains(&position.event_batch_root())
                    {
                        initial_roots
                            .entry(position.event_batch_root())
                            .or_default()
                            .push(position);
                    }
                }
                for (root, positions) in initial_roots {
                    let batch = replay
                        .read_root(store, cx, repository, root, false, cancelled)
                        .await?
                        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
                    let mut ranges = positions
                        .into_iter()
                        .map(|position| (position.stream(), (position, 0_u32)))
                        .collect();
                    if !delivery::validate_position_ranges(&mut ranges, &batch, cancelled)?
                        .is_empty()
                    {
                        return Err(unavailable(RefusalCode::EvidenceInvalid));
                    }
                }
                for entry in initial.outbox.entries() {
                    replay
                        .read_root(
                            store,
                            cx,
                            repository,
                            entry.payload_root(),
                            false,
                            cancelled,
                        )
                        .await?;
                }
                if replay.events.len() != expected_events {
                    return Err(unavailable(RefusalCode::EvidenceMissing));
                }
                break;
            }
            HistoryStep::Checkpoint { predecessor, .. } => {
                successor = predecessor.body().clone();
            }
            HistoryStep::Decision { predecessor, batch } => {
                // Refusals and unrelated commits consume the same history
                // budget. Ref-only/settlement RCRs may name verified empty
                // event batches, which are never valid outbox payloads.
                decisions = charge(decisions, batch.decisions.len(), MAX_HISTORY_DECISIONS)?;
                replay.charge_scan_bytes(
                    fgit_codec::encode_body(&batch)
                        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
                        .len(),
                )?;
                for record in batch.committed_rcrs.iter().rev() {
                    checkpoint(cancelled)?;
                    if record.repository_id != repository {
                        return Err(unavailable(RefusalCode::EvidenceInvalid));
                    }
                    replay
                        .read_root(
                            store,
                            cx,
                            repository,
                            record.forge_event_batch_root,
                            true,
                            cancelled,
                        )
                        .await?;
                }
                successor = predecessor.body().clone();
            }
        }
    }
    checkpoint(cancelled)?;
    Ok(replay.summary())
}

struct ReplayEvents<'a, F> {
    forge: &'a CanonicalForgePositionState,
    selected: &'a BTreeMap<AggregateId, ForgePositionStateEntry>,
    limits: HistoryReadLimits,
    visitor: &'a mut F,
    events: BTreeMap<(AggregateId, AggregateVersion), Digest>,
    batches: BTreeSet<Digest>,
    empty_batches: BTreeSet<Digest>,
    scanned_events: usize,
    scanned_bytes: usize,
}

impl<'a, F: FnMut(&ForgeEvent, usize) -> Result<(), AdmissionError> + Send> ReplayEvents<'a, F> {
    const fn new(
        forge: &'a CanonicalForgePositionState,
        selected: &'a BTreeMap<AggregateId, ForgePositionStateEntry>,
        limits: HistoryReadLimits,
        visitor: &'a mut F,
    ) -> Self {
        Self {
            forge,
            selected,
            limits,
            visitor,
            events: BTreeMap::new(),
            batches: BTreeSet::new(),
            empty_batches: BTreeSet::new(),
            scanned_events: 0,
            scanned_bytes: 0,
        }
    }

    const fn summary(&self) -> HistoryReadSummary {
        HistoryReadSummary {
            scanned_events: self.scanned_events,
            scanned_bytes: self.scanned_bytes,
        }
    }

    fn charge_scan_bytes(&mut self, bytes: usize) -> Result<(), AdmissionError> {
        self.scanned_bytes = charge(self.scanned_bytes, bytes, self.limits.scan_bytes)?;
        Ok(())
    }

    async fn read_root<S, C>(
        &mut self,
        store: &S,
        cx: &S::Context,
        repository: RepositoryId,
        root: Digest,
        allow_empty: bool,
        cancelled: &C,
    ) -> Result<Option<ForgeEventBatch>, AdmissionError>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
    {
        checkpoint(cancelled)?;
        if !self.batches.insert(root) {
            if !allow_empty && self.empty_batches.contains(&root) {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            return Ok(None);
        }
        let (batch, size) = storage::read_events_with_size(store, cx, repository, root).await?;
        checkpoint(cancelled)?;
        self.charge_scan_bytes(size)?;
        self.scanned_events = charge(self.scanned_events, batch.events.len(), self.limits.events)?;
        if !allow_empty || !batch.events.is_empty() {
            delivery::validate_payload_positions(self.forge, &batch)?;
        }
        if batch.events.is_empty() {
            self.empty_batches.insert(root);
        }
        for event in &batch.events {
            checkpoint(cancelled)?;
            if !self.selected.contains_key(&event.aggregate) {
                continue;
            }
            let key = (event.aggregate, event.version);
            let digest = storage::root(event)?;
            if let Some(previous) = self.events.get(&key) {
                if *previous != digest {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                continue;
            }
            let size = fgit_codec::encode_body(event)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
                .len();
            (self.visitor)(event, size)?;
            self.events.insert(key, digest);
        }
        Ok(Some(batch))
    }
}

const fn charge(total: usize, amount: usize, maximum: usize) -> Result<usize, AdmissionError> {
    match total.checked_add(amount) {
        Some(value) if value <= maximum => Ok(value),
        _ => Err(unavailable(RefusalCode::ResourceBudgetExceeded)),
    }
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), AdmissionError> {
    if cancelled() {
        Err(unavailable(RefusalCode::CancellationInProgress))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
