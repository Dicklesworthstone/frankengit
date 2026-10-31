//! Actor-free queue management intents. Speculative batch events require the
//! separate atomic merge publication path and have no metadata command here.
use super::{NativeQueueEvent, QueueAction};
use crate::aggregate::{
    AggregateId, AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber,
};
use crate::event::{ForgeEvent, ForgeEventPayload};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RefusalCode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueueCommandAction {
    Enqueue {
        pull_request: PullRequestNumber,
        expected_pull_request_version: AggregateVersion,
        source_ref: RefName,
        head_tip: GitOid,
        expected_target_tip: GitOid,
        priority: u32,
    },
    Dequeue {
        pull_request: PullRequestNumber,
        reason: super::DequeueReason,
    },
    /// An exact permutation of every existing entry. Admission refuses omitted,
    /// duplicated or absent IDs instead of choosing an implicit remainder.
    Reorder { order: Vec<PullRequestNumber> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueCommand {
    pub number: QueueNumber,
    pub target_ref: RefName,
    pub expected_version: ExpectedVersion,
    pub action: QueueCommandAction,
}

impl QueueCommand {
    /// Freeze semantics using the authenticated actor. Admission additionally
    /// seals PR-version and target-tip guards without changing event wire bytes.
    pub fn proposed_event(
        &self,
        actor: PrincipalId,
        format: GitHashAlgorithm,
    ) -> Result<ForgeEvent, RefusalCode> {
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(previous) => previous
                .next()
                .map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        if self.expected_version == ExpectedVersion::NewStream
            && !matches!(self.action, QueueCommandAction::Enqueue { .. })
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let action = match &self.action {
            QueueCommandAction::Enqueue {
                pull_request,
                source_ref,
                head_tip,
                expected_target_tip,
                priority,
                ..
            } => {
                if source_ref == &self.target_ref
                    || !source_ref.as_bytes().starts_with(b"refs/heads/")
                    || head_tip.algorithm() != format
                    || expected_target_tip.algorithm() != format
                    || head_tip.is_zero()
                    || expected_target_tip.is_zero()
                {
                    return Err(RefusalCode::EvidenceInvalid);
                }
                QueueAction::Enqueue {
                    pull_request: *pull_request,
                    source_ref: source_ref.clone(),
                    head_tip: *head_tip,
                    enqueued_by: actor,
                    priority: *priority,
                }
            }
            QueueCommandAction::Dequeue {
                pull_request,
                reason,
            } => QueueAction::Dequeue {
                pull_request: *pull_request,
                dequeued_by: actor,
                reason: *reason,
            },
            QueueCommandAction::Reorder { order } => QueueAction::Reorder {
                order: order.clone(),
                reordered_by: actor,
            },
        };
        let change = NativeQueueEvent {
            queue_number: self.number,
            target_ref: self.target_ref.clone(),
            action,
        };
        change
            .validate()
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        Ok(ForgeEvent {
            aggregate: AggregateId::MergeQueue(self.number),
            version,
            payload: ForgeEventPayload::MergeQueueChangedNative(change),
        })
    }
}
