//! Bounded authority-selected replay; no mutable queue database is authoritative.
use super::{
    AdmissionError, AsyncAuthorityStore, ForgeEvent, ForgeEventPayload, PublicationBasis, delivery,
    storage, unavailable,
};
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry};
use fgit_forge::aggregate::{AggregateId, AggregateVersion, QueueNumber};
use fgit_forge::merge_queue::MergeQueueSnapshot;
use fgit_types::{RefName, RefusalCode, RepositoryAuthorityHeadId, RepositoryId};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PAGE: u16 = 100;
const MAX_EVENTS: usize = 65_536;
const MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuePage {
    pub source_head: RepositoryAuthorityHeadId,
    pub queues: Vec<MergeQueueSnapshot>,
    /// Last returned queue number when another visible queue remains.
    pub next_after: Option<u64>,
}

pub async fn read_page_at<S, V, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    after: u64,
    limit: u16,
    visible: &V,
    cancelled: &C,
) -> Result<QueuePage, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    V: Fn(&RefName) -> bool + Sync,
    C: Fn() -> bool + Sync,
{
    if limit == 0 || limit > MAX_PAGE {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    checkpoint(cancelled)?;
    let state = delivery::read_roots_in(store, cx, basis, cancelled).await?;
    let wanted: BTreeSet<_> = frontiers(&state.forge, cancelled)?
        .into_keys()
        .filter(|number| number.get() > after)
        .collect();
    let queues = replay_selected(
        store,
        cx,
        basis.body().repository_id,
        &state.forge,
        &state.outbox,
        &wanted,
        cancelled,
    )
    .await?;
    let mut visible = queues
        .into_values()
        .filter(|queue| visible_queue(queue, visible));
    let queues: Vec<_> = visible.by_ref().take(usize::from(limit)).collect();
    let next_after = if visible.next().is_some() {
        queues.last().map(|queue| queue.queue_number.get())
    } else {
        None
    };
    checkpoint(cancelled)?;
    Ok(QueuePage {
        source_head: basis.id(),
        queues,
        next_after,
    })
}

pub async fn read_queue_at<S, V, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    number: QueueNumber,
    visible: &V,
    cancelled: &C,
) -> Result<Option<MergeQueueSnapshot>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    V: Fn(&RefName) -> bool + Sync,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let state = delivery::read_roots_in(store, cx, basis, cancelled).await?;
    let queue = replay_selected(
        store,
        cx,
        basis.body().repository_id,
        &state.forge,
        &state.outbox,
        &BTreeSet::from([number]),
        cancelled,
    )
    .await?
    .remove(&number)
    .filter(|queue| visible_queue(queue, visible));
    checkpoint(cancelled)?;
    Ok(queue)
}

fn visible_queue(queue: &MergeQueueSnapshot, visible: &impl Fn(&RefName) -> bool) -> bool {
    visible(&queue.target_ref) && queue.entries.iter().all(|entry| visible(&entry.source_ref))
}

pub(super) async fn replay_selected<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    forge: &CanonicalForgePositionState,
    outbox: &CanonicalOutboxState,
    wanted: &BTreeSet<QueueNumber>,
    cancelled: &C,
) -> Result<BTreeMap<QueueNumber, MergeQueueSnapshot>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let frontiers = frontiers(forge, cancelled)?;
    if !frontiers.keys().any(|number| wanted.contains(number)) {
        return Ok(BTreeMap::new());
    }
    let mut events = BTreeMap::<(QueueNumber, AggregateVersion), ForgeEvent>::new();
    let mut batches = BTreeSet::new();
    let (mut scanned_events, mut scanned_bytes, mut retained_bytes) = (0usize, 0usize, 0usize);
    for entry in outbox.entries() {
        checkpoint(cancelled)?;
        if !batches.insert(entry.payload_root()) {
            continue;
        }
        let (batch, size) =
            storage::read_events_with_size(store, cx, repository, entry.payload_root()).await?;
        delivery::validate_payload_positions(forge, &batch)?;
        scanned_events = scanned_events
            .checked_add(batch.events.len())
            .filter(|count| *count <= MAX_EVENTS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        scanned_bytes = scanned_bytes
            .checked_add(size)
            .filter(|count| *count <= MAX_SCAN_BYTES)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for event in batch.events {
            checkpoint(cancelled)?;
            let AggregateId::MergeQueue(number) = event.aggregate else {
                continue;
            };
            if !wanted.contains(&number) {
                continue;
            }
            let key = (number, event.version);
            if let Some(previous) = events.get(&key) {
                if previous != &event {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                continue;
            }
            let bytes = fgit_codec::encode_body(&event)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
                .len();
            retained_bytes = retained_bytes
                .checked_add(bytes)
                .filter(|count| *count <= MAX_RETAINED_BYTES)
                .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            events.insert(key, event);
        }
    }
    let mut queues = BTreeMap::<QueueNumber, MergeQueueSnapshot>::new();
    let mut latest = BTreeMap::new();
    for ((number, _), event) in events {
        checkpoint(cancelled)?;
        let ForgeEventPayload::MergeQueueChangedNative(change) = &event.payload else {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        };
        let queue = queues
            .entry(number)
            .or_insert_with(|| MergeQueueSnapshot::new(number, change.target_ref.clone()));
        queue
            .apply_event(&event)
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        latest.insert(number, event);
    }
    for (number, frontier) in frontiers {
        checkpoint(cancelled)?;
        if !wanted.contains(&number) {
            continue;
        }
        let queue = queues
            .get(&number)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
        if queue.version.get() != frontier.successor_position() {
            return Err(unavailable(RefusalCode::EvidenceMissing));
        }
        let batch =
            storage::read_events(store, cx, repository, frontier.event_batch_root()).await?;
        delivery::validate_position_batch(&frontier, &batch)?;
        let selected = batch
            .events
            .iter()
            .rev()
            .find(|event| event.aggregate == AggregateId::MergeQueue(number));
        if selected != latest.get(&number) {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    checkpoint(cancelled)?;
    Ok(queues)
}

fn frontiers<C: Fn() -> bool + Sync>(
    forge: &CanonicalForgePositionState,
    cancelled: &C,
) -> Result<BTreeMap<QueueNumber, ForgePositionStateEntry>, AdmissionError> {
    let mut frontiers = BTreeMap::new();
    for entry in forge.entries() {
        checkpoint(cancelled)?;
        let label = entry.stream();
        let Some(text) = label.as_str().strip_prefix("queue/") else {
            continue;
        };
        let number = text
            .parse::<u64>()
            .ok()
            .and_then(QueueNumber::try_new)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if storage::aggregate_label(AggregateId::MergeQueue(number))? != label {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        frontiers.insert(number, *entry);
    }
    Ok(frontiers)
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), AdmissionError> {
    if cancelled() {
        Err(unavailable(RefusalCode::CancellationInProgress))
    } else {
        Ok(())
    }
}
