//! Gap-free, bounded replay of the existing canonical queue event format.
use super::{
    AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload, ForgeRefusal, MergeQueueSnapshot,
    QueueAction, QueueBatchId, QueueEntry, invalid_queue,
};
use crate::ExpectedVersion;
use crate::event::queue::MAX_QUEUE_ENTRIES;
use std::collections::BTreeSet;

impl MergeQueueSnapshot {
    pub(super) fn apply_checked_event(&mut self, event: &ForgeEvent) -> Result<(), ForgeRefusal> {
        let ForgeEventPayload::MergeQueueChangedNative(change) = &event.payload else {
            return Err(invalid_queue("queue.payload"));
        };
        change
            .validate()
            .map_err(|cause| ForgeRefusal::BodyUnrepresentable {
                cause: Box::new(cause),
            })?;
        if event.aggregate != AggregateId::MergeQueue(self.queue_number)
            || change.queue_number != self.queue_number
            || change.target_ref != self.target_ref
        {
            return Err(invalid_queue("queue.binding"));
        }
        let expected = if self.initialized {
            self.version.next()?
        } else {
            AggregateVersion::FIRST
        };
        if event.version != expected {
            return Err(ForgeRefusal::VersionConflict {
                expected: if event.version == AggregateVersion::FIRST {
                    ExpectedVersion::NewStream
                } else {
                    ExpectedVersion::Exactly(
                        AggregateVersion::try_new(event.version.get() - 1)
                            .ok_or_else(|| invalid_queue("queue.version"))?,
                    )
                },
                observed: self.initialized.then_some(self.version),
            });
        }
        if !self.initialized && !matches!(change.action, QueueAction::Enqueue { .. }) {
            return Err(invalid_queue("queue.first_action"));
        }
        match &change.action {
            QueueAction::Enqueue {
                pull_request,
                source_ref,
                head_tip,
                enqueued_by,
                priority,
            } => {
                self.require_idle()?;
                if source_ref == &self.target_ref
                    || !source_ref.as_bytes().starts_with(b"refs/heads/")
                    || self
                        .entries
                        .iter()
                        .any(|entry| entry.head_tip.algorithm() != head_tip.algorithm())
                {
                    return Err(invalid_queue("queue.enqueue.coordinates"));
                }
                // Explicit re-enqueue replaces coordinates, actor and FIFO age.
                self.entries
                    .retain(|entry| entry.pull_request != *pull_request);
                if self.entries.len() >= MAX_QUEUE_ENTRIES {
                    return Err(invalid_queue("queue.capacity"));
                }
                let entry = QueueEntry {
                    pull_request: *pull_request,
                    source_ref: source_ref.clone(),
                    head_tip: *head_tip,
                    enqueued_by: *enqueued_by,
                    priority: *priority,
                    enqueued_version: event.version,
                };
                let position = self
                    .entries
                    .iter()
                    .position(|held| {
                        held.priority < entry.priority
                            || (held.priority == entry.priority
                                && (held.enqueued_version, held.pull_request)
                                    > (entry.enqueued_version, entry.pull_request))
                    })
                    .unwrap_or(self.entries.len());
                self.entries.insert(position, entry);
            }
            QueueAction::Dequeue { pull_request, .. } => {
                self.require_idle()?;
                if self.find_entry(*pull_request).is_none() {
                    return Err(invalid_queue("queue.dequeue.absent"));
                }
                self.entries
                    .retain(|entry| entry.pull_request != *pull_request);
            }
            QueueAction::Reorder { order, .. } => {
                self.require_idle()?;
                let selected: BTreeSet<_> = order.iter().copied().collect();
                if selected.len() != order.len()
                    || order
                        .iter()
                        .any(|number| self.find_entry(*number).is_none())
                {
                    return Err(invalid_queue("queue.reorder.entries"));
                }
                let mut reordered = Vec::with_capacity(self.entries.len());
                for number in order {
                    reordered.push(
                        self.find_entry(*number)
                            .ok_or_else(|| invalid_queue("queue.reorder.absent"))?
                            .clone(),
                    );
                }
                reordered.extend(
                    self.entries
                        .iter()
                        .filter(|entry| !selected.contains(&entry.pull_request))
                        .cloned(),
                );
                self.entries = reordered;
            }
            QueueAction::BatchFormed { batch_id, entries } => {
                self.require_idle()?;
                let order = self.deterministic_order();
                if entries.len() > order.len() || entries.as_slice() != &order[..entries.len()] {
                    return Err(invalid_queue("queue.batch.entries"));
                }
                self.active_batch = Some(QueueBatchId::from_digest(*batch_id));
                self.active_batch_entries.clone_from(entries);
            }
            QueueAction::BatchLanded {
                batch_id,
                entries,
                target_tip,
            } => {
                if self.active_batch != Some(QueueBatchId::from_digest(*batch_id))
                    || entries != &self.active_batch_entries
                    || self
                        .entries
                        .iter()
                        .any(|entry| entry.head_tip.algorithm() != target_tip.algorithm())
                {
                    return Err(invalid_queue("queue.batch.landing"));
                }
                let selected: BTreeSet<_> = entries.iter().copied().collect();
                self.entries
                    .retain(|entry| !selected.contains(&entry.pull_request));
                self.active_batch = None;
                self.active_batch_entries.clear();
            }
            QueueAction::BatchRejected { batch_id, .. } => {
                if self.active_batch != Some(QueueBatchId::from_digest(*batch_id)) {
                    return Err(invalid_queue("queue.batch.rejection"));
                }
                self.active_batch = None;
                self.active_batch_entries.clear();
            }
        }
        self.version = event.version;
        self.initialized = true;
        Ok(())
    }
    fn require_idle(&self) -> Result<(), ForgeRefusal> {
        if self.active_batch.is_some() {
            Err(invalid_queue("queue.batch.active"))
        } else {
            Ok(())
        }
    }
}
#[cfg(test)]
mod tests;
