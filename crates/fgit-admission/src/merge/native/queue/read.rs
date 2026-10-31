//! Bounded authority-selected replay; no mutable queue database is authoritative.
use super::{
    AdmissionError, AsyncAuthorityStore, ForgeEvent, ForgeEventPayload, PublicationBasis, delivery,
    storage, unavailable,
};
use fgit_chronicle::{HistoryStep, read_history_step_async};
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry};
use fgit_forge::ForgeEventBatch;
use fgit_forge::aggregate::{AggregateId, AggregateVersion, QueueNumber};
use fgit_forge::merge_queue::MergeQueueSnapshot;
use fgit_types::{
    Digest, HeadGeneration, RefName, RefusalCode, RepositoryAuthorityHeadId, RepositoryId,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PAGE: u16 = 100;
const MAX_EVENTS: usize = 65_536;
const MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 32 * 1024 * 1024;
const MAX_HISTORY_STEPS: usize = 4096;
const MAX_HISTORY_DECISIONS: usize = 65_536;

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
        basis,
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
        basis,
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
    basis: &PublicationBasis,
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
    let repository = basis.body().repository_id;
    // A public PublicationBasis must bind its asserted ID even when no queue
    // exists. Callers have authenticated the maps, including legacy bootstrap.
    if fgit_authority::authority_head_identity(basis.body())
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
        != basis.id()
        || forge.repository_id() != repository
        || outbox.repository_id() != repository
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let selected_frontiers = frontiers(forge, cancelled)?;
    if !selected_frontiers
        .keys()
        .any(|number| wanted.contains(number))
    {
        return Ok(BTreeMap::new());
    }

    // Authenticate every selected frontier before using its version as a
    // completeness bound. Group shared batches so reads and byte accounting do
    // not multiply when one publication advances several queues.
    let mut frontier_roots =
        BTreeMap::<Digest, Vec<(QueueNumber, &ForgePositionStateEntry)>>::new();
    for (number, frontier) in &selected_frontiers {
        checkpoint(cancelled)?;
        if wanted.contains(number) {
            frontier_roots
                .entry(frontier.event_batch_root())
                .or_default()
                .push((*number, frontier));
        }
    }
    let mut replay = ReplayEvents::new(forge, wanted);
    let mut selected = BTreeMap::new();
    for (root, positions) in frontier_roots {
        let batch = replay
            .read_root(store, cx, repository, root, false, cancelled)
            .await?
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        for (number, position) in positions {
            checkpoint(cancelled)?;
            delivery::validate_position_batch(position, &batch)?;
            let event = batch
                .events
                .iter()
                .rev()
                .find(|event| event.aggregate == AggregateId::MergeQueue(number))
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            selected.insert(number, event.clone());
        }
    }
    let expected_events = selected_frontiers
        .iter()
        .filter(|(number, _)| wanted.contains(*number))
        .try_fold(0usize, |total, (_, frontier)| {
            let version = usize::try_from(frontier.successor_position())
                .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            total
                .checked_add(version)
                .filter(|count| *count <= MAX_EVENTS)
                .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))
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

    // Terminal delivery removes entries from the active outbox. Missing queue
    // deltas therefore come from the selected authority's verified RCR chain,
    // never from scanning immutable object presence or a mutable side index.
    // Every retained event is unique, nonzero and no newer than its frontier,
    // so this cardinality check proves 1..=frontier without iterating u64 ranges.
    if replay.events.len() != expected_events {
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
                    // Preserve supported genesis-seeded state only through the
                    // actual genesis reached by authenticated predecessor links.
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
                    let mut initial_roots = BTreeMap::<Digest, Vec<ForgePositionStateEntry>>::new();
                    for (number, position) in frontiers(&initial.forge, cancelled)? {
                        checkpoint(cancelled)?;
                        if wanted.contains(&number)
                            && !replay.batches.contains(&position.event_batch_root())
                        {
                            initial_roots
                                .entry(position.event_batch_root())
                                .or_default()
                                .push(position);
                        }
                    }
                    // A seeded first queue event may be committed directly by
                    // the genesis frontier even when its outbox is empty. Roots
                    // already consumed through canonical evidence contribute no
                    // additional deltas and need no second immutable read.
                    for (root, positions) in initial_roots {
                        let batch = replay
                            .read_root(store, cx, repository, root, false, cancelled)
                            .await?
                            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
                        for position in positions {
                            checkpoint(cancelled)?;
                            delivery::validate_position_batch(&position, &batch)?;
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
                HistoryStep::Checkpoint { predecessor } => {
                    successor = predecessor.body().clone();
                }
                HistoryStep::Decision { predecessor, batch } => {
                    // Include unrelated commits and refused decisions in the
                    // work bound. Refusal-only and checkpoint edges also consume
                    // MAX_HISTORY_STEPS inside the shared authenticated walker.
                    decisions = decisions
                        .checked_add(batch.decisions.len())
                        .filter(|count| *count <= MAX_HISTORY_DECISIONS)
                        .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
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
                        // Ref-only/settlement commits may name a verified empty
                        // event batch. Charge it, without treating it as an
                        // invalid delivery payload or a queue event.
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
    }
    let mut queues = BTreeMap::<QueueNumber, MergeQueueSnapshot>::new();
    let mut latest = BTreeMap::new();
    for ((number, _), event) in replay.events {
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
    for (number, frontier) in selected_frontiers {
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
        if selected.get(&number) != latest.get(&number) {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    checkpoint(cancelled)?;
    Ok(queues)
}

struct ReplayEvents<'a> {
    forge: &'a CanonicalForgePositionState,
    wanted: &'a BTreeSet<QueueNumber>,
    events: BTreeMap<(QueueNumber, AggregateVersion), ForgeEvent>,
    batches: BTreeSet<Digest>,
    empty_batches: BTreeSet<Digest>,
    scanned_events: usize,
    scanned_bytes: usize,
    retained_bytes: usize,
}

impl<'a> ReplayEvents<'a> {
    fn new(forge: &'a CanonicalForgePositionState, wanted: &'a BTreeSet<QueueNumber>) -> Self {
        Self {
            forge,
            wanted,
            events: BTreeMap::new(),
            batches: BTreeSet::new(),
            empty_batches: BTreeSet::new(),
            scanned_events: 0,
            scanned_bytes: 0,
            retained_bytes: 0,
        }
    }

    fn charge_scan_bytes(&mut self, bytes: usize) -> Result<(), AdmissionError> {
        self.scanned_bytes = self
            .scanned_bytes
            .checked_add(bytes)
            .filter(|count| *count <= MAX_SCAN_BYTES)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
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
        self.scanned_events = self
            .scanned_events
            .checked_add(batch.events.len())
            .filter(|count| *count <= MAX_EVENTS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        if !allow_empty || !batch.events.is_empty() {
            delivery::validate_payload_positions(self.forge, &batch)?;
        }
        if batch.events.is_empty() {
            self.empty_batches.insert(root);
        }
        for event in &batch.events {
            checkpoint(cancelled)?;
            let AggregateId::MergeQueue(number) = event.aggregate else {
                continue;
            };
            if !self.wanted.contains(&number) {
                continue;
            }
            let key = (number, event.version);
            if let Some(previous) = self.events.get(&key) {
                if previous != event {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                continue;
            }
            let bytes = fgit_codec::encode_body(event)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
                .len();
            self.retained_bytes = self
                .retained_bytes
                .checked_add(bytes)
                .filter(|count| *count <= MAX_RETAINED_BYTES)
                .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            self.events.insert(key, event.clone());
        }
        Ok(Some(batch))
    }
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
