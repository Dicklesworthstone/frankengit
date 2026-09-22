//! Canonical merge queue lifecycle events.
//!
//! Queue operations (enqueue, dequeue, reorder, batch formation, landing)
//! are canonical forge events with aggregate versions. Writers must name
//! the expected aggregate version, ensuring no concurrent operations race
//! silently without detection.

use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{Digest, GitOid, PrincipalId, RefName};

use super::{counter, invalid_native};
use crate::aggregate::{PullRequestNumber, QueueNumber};

pub const MAX_QUEUE_ENTRIES: usize = 1024;

/// The reason a candidate PR was removed from the merge queue or a batch was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DequeueReason {
    Withdrawn = 1,
    Conflict = 2,
    CheckFailed = 3,
    BaseMoved = 4,
    Evicted = 5,
    AdminOverride = 6,
}

impl DequeueReason {
    #[must_use]
    pub const fn wire_value(self) -> u32 {
        self as u32
    }

    pub fn from_wire_value(value: u32) -> Result<Self, CodecRefusal> {
        match value {
            1 => Ok(Self::Withdrawn),
            2 => Ok(Self::Conflict),
            3 => Ok(Self::CheckFailed),
            4 => Ok(Self::BaseMoved),
            5 => Ok(Self::Evicted),
            6 => Ok(Self::AdminOverride),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "queue.dequeue_reason",
                observed,
                offset: 0,
            }),
        }
    }
}

/// Action applied to the merge queue aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueueAction {
    /// Enqueue a candidate pull request with priority.
    Enqueue {
        pull_request: PullRequestNumber,
        source_ref: RefName,
        head_tip: GitOid,
        enqueued_by: PrincipalId,
        priority: u32,
    },
    /// Dequeue a pull request candidate with an explicit reason.
    Dequeue {
        pull_request: PullRequestNumber,
        dequeued_by: PrincipalId,
        reason: DequeueReason,
    },
    /// Reorder the active queue entries.
    Reorder {
        order: Vec<PullRequestNumber>,
        reordered_by: PrincipalId,
    },
    /// A speculative batch of candidate PRs is formed.
    BatchFormed {
        batch_id: Digest,
        entries: Vec<PullRequestNumber>,
    },
    /// A speculative batch was successfully landed to the target branch.
    BatchLanded {
        batch_id: Digest,
        entries: Vec<PullRequestNumber>,
        target_tip: GitOid,
    },
    /// A speculative batch was rejected or aborted.
    BatchRejected {
        batch_id: Digest,
        reason: DequeueReason,
    },
}

impl QueueAction {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        match self {
            Self::Enqueue {
                source_ref,
                head_tip,
                ..
            } => {
                if !source_ref.as_bytes().starts_with(b"refs/") {
                    return Err(invalid_native("queue.enqueue.source_ref"));
                }
                if head_tip.is_zero() {
                    return Err(invalid_native("queue.enqueue.head_tip"));
                }
                Ok(())
            }
            Self::Dequeue { .. } => Ok(()),
            Self::Reorder { order, .. } => {
                if order.len() > MAX_QUEUE_ENTRIES {
                    return Err(invalid_native("queue.reorder.max_entries"));
                }
                // Check for duplicates
                for i in 0..order.len() {
                    for j in (i + 1)..order.len() {
                        if order[i] == order[j] {
                            return Err(invalid_native("queue.reorder.duplicate"));
                        }
                    }
                }
                Ok(())
            }
            Self::BatchFormed { entries, .. } => {
                if entries.is_empty() || entries.len() > MAX_QUEUE_ENTRIES {
                    return Err(invalid_native("queue.batch_formed.entries"));
                }
                for i in 0..entries.len() {
                    for j in (i + 1)..entries.len() {
                        if entries[i] == entries[j] {
                            return Err(invalid_native("queue.batch_formed.duplicate"));
                        }
                    }
                }
                Ok(())
            }
            Self::BatchLanded {
                entries,
                target_tip,
                ..
            } => {
                if entries.is_empty() || entries.len() > MAX_QUEUE_ENTRIES {
                    return Err(invalid_native("queue.batch_landed.entries"));
                }
                if target_tip.is_zero() {
                    return Err(invalid_native("queue.batch_landed.target_tip"));
                }
                Ok(())
            }
            Self::BatchRejected { .. } => Ok(()),
        }
    }

    #[must_use]
    pub const fn action_kind(&self) -> u32 {
        match self {
            Self::Enqueue { .. } => 1,
            Self::Dequeue { .. } => 2,
            Self::Reorder { .. } => 3,
            Self::BatchFormed { .. } => 4,
            Self::BatchLanded { .. } => 5,
            Self::BatchRejected { .. } => 6,
        }
    }
}

/// A canonical merge queue event on wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeQueueEvent {
    pub queue_number: QueueNumber,
    pub target_ref: RefName,
    pub action: QueueAction,
}

impl NativeQueueEvent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if !self.target_ref.as_bytes().starts_with(b"refs/heads/") {
            return Err(invalid_native("queue.target_ref"));
        }
        self.action.validate()
    }

    pub fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_scalar(self.queue_number.get());
        out.write_bytes("queue.target_ref", self.target_ref.as_bytes())?;
        out.write_scalar(self.action.action_kind());
        match &self.action {
            QueueAction::Enqueue {
                pull_request,
                source_ref,
                head_tip,
                enqueued_by,
                priority,
            } => {
                out.write_scalar(pull_request.get());
                out.write_bytes("queue.enqueue.source_ref", source_ref.as_bytes())?;
                out.write_git_oid(head_tip);
                out.write_opaque_id(enqueued_by.as_bytes());
                out.write_scalar(*priority);
            }
            QueueAction::Dequeue {
                pull_request,
                dequeued_by,
                reason,
            } => {
                out.write_scalar(pull_request.get());
                out.write_opaque_id(dequeued_by.as_bytes());
                out.write_scalar(reason.wire_value());
            }
            QueueAction::Reorder {
                order,
                reordered_by,
            } => {
                out.write_opaque_id(reordered_by.as_bytes());
                out.write_sequence("queue.reorder.order", order, |out, pr| {
                    out.write_scalar(pr.get());
                    Ok(())
                })?;
            }
            QueueAction::BatchFormed { batch_id, entries } => {
                out.write_digest(batch_id)?;
                out.write_sequence("queue.batch_formed.entries", entries, |out, pr| {
                    out.write_scalar(pr.get());
                    Ok(())
                })?;
            }
            QueueAction::BatchLanded {
                batch_id,
                entries,
                target_tip,
            } => {
                out.write_digest(batch_id)?;
                out.write_sequence("queue.batch_landed.entries", entries, |out, pr| {
                    out.write_scalar(pr.get());
                    Ok(())
                })?;
                out.write_git_oid(target_tip);
            }
            QueueAction::BatchRejected { batch_id, reason } => {
                out.write_digest(batch_id)?;
                out.write_scalar(reason.wire_value());
            }
        }
        Ok(())
    }

    pub fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let queue_num_raw = input.read_scalar::<u64>("queue.queue_number")?;
        let queue_number = counter("queue.queue_number", queue_num_raw)?;
        let target_ref_bytes = input.read_bytes("queue.target_ref")?;
        let target_ref = RefName::try_new(target_ref_bytes).map_err(CodecRefusal::from)?;

        let action_offset = input.offset();
        let kind = input.read_scalar::<u32>("queue.action_kind")?;
        let action = match kind {
            1 => {
                let pr_raw = input.read_scalar::<u64>("queue.enqueue.pull_request")?;
                let pull_request = counter("queue.enqueue.pull_request", pr_raw)?;
                let source_ref_bytes = input.read_bytes("queue.enqueue.source_ref")?;
                let source_ref = RefName::try_new(source_ref_bytes).map_err(CodecRefusal::from)?;
                let head_tip = input.read_git_oid()?;
                let enqueued_by =
                    PrincipalId::from_bytes(input.read_opaque_id("queue.enqueue.enqueued_by")?);
                let priority = input.read_scalar::<u32>("queue.enqueue.priority")?;
                QueueAction::Enqueue {
                    pull_request,
                    source_ref,
                    head_tip,
                    enqueued_by,
                    priority,
                }
            }
            2 => {
                let pr_raw = input.read_scalar::<u64>("queue.dequeue.pull_request")?;
                let pull_request = counter("queue.dequeue.pull_request", pr_raw)?;
                let dequeued_by =
                    PrincipalId::from_bytes(input.read_opaque_id("queue.dequeue.dequeued_by")?);
                let reason_raw = input.read_scalar::<u32>("queue.dequeue.reason")?;
                let reason = DequeueReason::from_wire_value(reason_raw)?;
                QueueAction::Dequeue {
                    pull_request,
                    dequeued_by,
                    reason,
                }
            }
            3 => {
                let reordered_by =
                    PrincipalId::from_bytes(input.read_opaque_id("queue.reorder.reordered_by")?);
                let mut count = 0usize;
                let order = input.read_sequence("queue.reorder.order", |input| {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| invalid_native("queue.reorder.order"))?;
                    if count > MAX_QUEUE_ENTRIES {
                        return Err(invalid_native("queue.reorder.order"));
                    }
                    let pr_raw = input.read_scalar::<u64>("queue.reorder.pr")?;
                    counter("queue.reorder.pr", pr_raw)
                })?;
                QueueAction::Reorder {
                    order,
                    reordered_by,
                }
            }
            4 => {
                let batch_id = input.read_digest()?;
                let mut count = 0usize;
                let entries = input.read_sequence("queue.batch_formed.entries", |input| {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| invalid_native("queue.batch_formed.entries"))?;
                    if count > MAX_QUEUE_ENTRIES {
                        return Err(invalid_native("queue.batch_formed.entries"));
                    }
                    let pr_raw = input.read_scalar::<u64>("queue.batch_formed.pr")?;
                    counter("queue.batch_formed.pr", pr_raw)
                })?;
                QueueAction::BatchFormed { batch_id, entries }
            }
            5 => {
                let batch_id = input.read_digest()?;
                let mut count = 0usize;
                let entries = input.read_sequence("queue.batch_landed.entries", |input| {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| invalid_native("queue.batch_landed.entries"))?;
                    if count > MAX_QUEUE_ENTRIES {
                        return Err(invalid_native("queue.batch_landed.entries"));
                    }
                    let pr_raw = input.read_scalar::<u64>("queue.batch_landed.pr")?;
                    counter("queue.batch_landed.pr", pr_raw)
                })?;
                let target_tip = input.read_git_oid()?;
                QueueAction::BatchLanded {
                    batch_id,
                    entries,
                    target_tip,
                }
            }
            6 => {
                let batch_id = input.read_digest()?;
                let reason_raw = input.read_scalar::<u32>("queue.batch_rejected.reason")?;
                let reason = DequeueReason::from_wire_value(reason_raw)?;
                QueueAction::BatchRejected { batch_id, reason }
            }
            observed => {
                return Err(CodecRefusal::VariantUnknown {
                    field: "queue.action_kind",
                    observed,
                    offset: action_offset,
                });
            }
        };

        let event = Self {
            queue_number,
            target_ref,
            action,
        };
        event.validate()?;
        Ok(event)
    }
}
