//! Disposable aggregate/version coordinates from one complete selected replay.

use std::mem::size_of;

use fgit_authority::{AsyncAuthorityStore, StoreInstanceId};
use fgit_chronicle::PublicationBasis;
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId};

use super::{
    AdmissionError, AggregateId, AggregateVersion, BTreeMap, Digest, ForgeEvent,
    ForgePositionStateEntry, RefusalCode, ReplayEvents, RepositoryId,
    checkpoint, unavailable,
};

#[derive(Clone, Copy, Debug)]
struct EventCoordinate {
    aggregate: AggregateId,
    version: AggregateVersion,
    batch_root: Digest,
    event_digest: Digest,
}

/// Verified coordinates for selected aggregate histories at one exact head.
///
/// This contains no event text and is never authority or an authorization
/// decision. Private construction requires a complete ordinary selected replay,
/// including conflicting-version detection across every active outbox payload.
/// The same index can serve a subset of its verified aggregate frontiers. Each
/// read still verifies all selected payloads and the caller's current grants.
///
/// Hosts must additionally bind custody to their storage root, tenant,
/// repository incarnation and object format. Store instance identifiers alone
/// do not distinguish independently opened host configurations. The index is
/// disposable, process-local metadata and does not accelerate a changed head.
#[derive(Debug)]
pub struct VerifiedAggregateHistory {
    source_head: RepositoryAuthorityHeadId,
    source_generation: HeadGeneration,
    repository: RepositoryId,
    store_instance: StoreInstanceId,
    positions: Vec<(AggregateId, ForgePositionStateEntry)>,
    events: Vec<EventCoordinate>,
}

impl VerifiedAggregateHistory {
    /// Exact canonical head supplying all retained coordinates.
    #[must_use]
    pub const fn source_head(&self) -> RepositoryAuthorityHeadId {
        self.source_head
    }

    /// Generation of that exact source head; it does not prove ancestry.
    #[must_use]
    pub const fn source_generation(&self) -> HeadGeneration {
        self.source_generation
    }

    /// Inline metadata plus both actual vector allocations, without payloads.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        // Construction verifies the same arithmetic and the profile ceilings.
        size_of::<Self>()
            + self.positions.capacity() * size_of::<(AggregateId, ForgePositionStateEntry)>()
            + self.events.capacity() * size_of::<EventCoordinate>()
    }

    pub(super) fn covers<S: AsyncAuthorityStore + ?Sized>(
        &self,
        store: &S,
        basis: &PublicationBasis,
        selected: &BTreeMap<AggregateId, ForgePositionStateEntry>,
    ) -> bool {
        self.source_head == basis.id()
            && self.repository == basis.body().repository_id
            && self.store_instance == store.instance_id()
            && selected.iter().all(|(aggregate, position)| {
                self.positions
                    .binary_search_by_key(aggregate, |(id, _)| *id)
                    .is_ok_and(|index| self.positions[index].1 == *position)
            })
    }

    fn coordinates(&self, aggregate: AggregateId) -> &[EventCoordinate] {
        let start = self
            .events
            .partition_point(|event| event.aggregate < aggregate);
        let end = self
            .events
            .partition_point(|event| event.aggregate <= aggregate);
        &self.events[start..end]
    }

    pub(super) async fn visit_remaining<S, C, F>(
        &self,
        store: &S,
        cx: &S::Context,
        repository: RepositoryId,
        replay: &mut ReplayEvents<'_, F>,
        expected_events: usize,
        cancelled: &C,
    ) -> Result<(), AdmissionError>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
        F: FnMut(&ForgeEvent, usize) -> Result<(), AdmissionError> + Send,
    {
        checkpoint(cancelled)?;
        // Binary ranges select only the requested aggregates. This temporary
        // root list is bounded by the already checked selected event ceiling.
        let mut roots = Vec::new();
        roots
            .try_reserve_exact(expected_events)
            .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for aggregate in replay.selected.keys() {
            for event in self.coordinates(*aggregate) {
                checkpoint(cancelled)?;
                if roots.len() == expected_events {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                roots.push(event.batch_root);
            }
        }
        if roots.len() != expected_events {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        roots.sort_unstable();
        roots.dedup();
        checkpoint(cancelled)?;
        for root in roots {
            replay
                .read_root(store, cx, repository, root, false, cancelled)
                .await?;
        }
        if replay.events.len() != expected_events {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        for aggregate in replay.selected.keys() {
            for event in self.coordinates(*aggregate) {
                checkpoint(cancelled)?;
                if replay.events.get(&(event.aggregate, event.version))
                    != Some(&event.event_digest)
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
            }
        }
        checkpoint(cancelled)
    }
}

/// Optional capture accompanies, and cannot replace, the canonical verifier.
pub(super) struct Builder {
    index: VerifiedAggregateHistory,
    expected_events: usize,
}

impl Builder {
    pub(super) fn new<S, C>(
        store: &S,
        basis: &PublicationBasis,
        selected: &BTreeMap<AggregateId, ForgePositionStateEntry>,
        max_events: usize,
        maximum: usize,
        cancelled: &C,
    ) -> Result<Option<Self>, AdmissionError>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
    {
        if maximum == 0 || selected.is_empty() {
            return Ok(None);
        }
        checkpoint(cancelled)?;
        let mut expected_events = 0usize;
        for position in selected.values() {
            checkpoint(cancelled)?;
            let Some(total) = usize::try_from(position.successor_position())
                .ok()
                .and_then(|count| expected_events.checked_add(count))
                .filter(|count| *count <= max_events)
            else {
                // Normal replay owns its existing evidence/resource refusal.
                return Ok(None);
            };
            expected_events = total;
        }
        if !retained_bytes(selected.len(), expected_events)
            .is_some_and(|bytes| bytes <= maximum)
        {
            return Ok(None);
        }
        let mut index = VerifiedAggregateHistory {
            source_head: basis.id(),
            source_generation: basis.body().generation,
            repository: basis.body().repository_id,
            store_instance: store.instance_id(),
            positions: Vec::new(),
            events: Vec::new(),
        };
        if index.positions.try_reserve_exact(selected.len()).is_err()
            || index.events.try_reserve_exact(expected_events).is_err()
            || !retained_bytes(index.positions.capacity(), index.events.capacity())
                .is_some_and(|bytes| bytes <= maximum)
        {
            return Ok(None);
        }
        for (aggregate, position) in selected {
            checkpoint(cancelled)?;
            index.positions.push((*aggregate, *position));
        }
        Ok(Some(Self {
            index,
            expected_events,
        }))
    }

    pub(super) fn push(
        &mut self,
        event: &ForgeEvent,
        batch_root: Digest,
        event_digest: Digest,
    ) -> Result<(), AdmissionError> {
        if self.index.events.len() >= self.expected_events {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        self.index.events.push(EventCoordinate {
            aggregate: event.aggregate,
            version: event.version,
            batch_root,
            event_digest,
        });
        Ok(())
    }

    pub(super) fn finish<C: Fn() -> bool + Sync>(
        mut self,
        expected_events: usize,
        cancelled: &C,
    ) -> Result<VerifiedAggregateHistory, AdmissionError> {
        checkpoint(cancelled)?;
        if self.expected_events != expected_events || self.index.events.len() != expected_events {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        self.index
            .events
            .sort_unstable_by_key(|event| (event.aggregate, event.version));
        checkpoint(cancelled)?;
        Ok(self.index)
    }
}

fn retained_bytes(positions: usize, events: usize) -> Option<usize> {
    positions
        .checked_mul(size_of::<(AggregateId, ForgePositionStateEntry)>())
        .and_then(|bytes| bytes.checked_add(size_of::<VerifiedAggregateHistory>()))
        .and_then(|bytes| {
            events
                .checked_mul(size_of::<EventCoordinate>())
                .and_then(|events| bytes.checked_add(events))
        })
}

#[cfg(test)]
#[path = "tests_index.rs"]
mod tests;
