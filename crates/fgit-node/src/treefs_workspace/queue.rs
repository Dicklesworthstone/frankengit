//! Canonical merge-queue management on the same authority as refs and PRs.
//!
//! Management records queue intent; guarded landing moves an existing candidate
//! through ordinary protected merge admission and one atomic queue/PR decision.

use super::issues::snapshots;
use super::native_merge::NodeNativeMergeProjection;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use fgit_admission::merge::native::{objects::MergeObjectLimits, queue};
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::QueueNumber;
use fgit_forge::merge_queue::{MergeQueueSnapshot, QueueCommand};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{RefName, RefusalCode, RepositoryAuthorityHeadId, TxId};
use fgit_wire::visibility::RefVisibility;

/// One queue selected from an authenticated current or retained repository head.
/// An unavailable or hidden queue is deliberately indistinguishable from absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueRead {
    pub source_head: RepositoryAuthorityHeadId,
    pub queue: Option<MergeQueueSnapshot>,
}

#[derive(Debug)]
pub enum QueueReadRefusal {
    InvalidLimit,
    SnapshotRequired,
    SnapshotMoved,
    Cell(CellRefusal),
    Selection(Box<super::events::ForgeEventReadRefusal>),
    Admission(Box<AdmissionError>),
}

impl QueueReadRefusal {
    #[must_use]
    pub const fn is_snapshot_unavailable(&self) -> bool {
        matches!(self, Self::SnapshotMoved)
    }
}

impl From<snapshots::SnapshotReadRefusal> for QueueReadRefusal {
    fn from(error: snapshots::SnapshotReadRefusal) -> Self {
        match error {
            snapshots::SnapshotReadRefusal::Unavailable => Self::SnapshotMoved,
            snapshots::SnapshotReadRefusal::Admission(error) => Self::Admission(error),
        }
    }
}

impl core::fmt::Display for QueueReadRefusal {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(out, "native merge-queue read refused: {self:?}")
    }
}

impl core::error::Error for QueueReadRefusal {}

#[derive(Clone, Copy)]
enum QueuePublication<'a> {
    Management(&'a QueueCommand),
    Landing(&'a queue::QueueLandingCommand),
}

impl OneNode {
    /// Submit enqueue, dequeue or reorder through ordinary metadata admission.
    /// The authenticated session supplies the actor. Enqueue guards and queue
    /// versions belong to the immutable request, so retry cannot silently pick
    /// up a newer candidate or reinterpret an earlier action.
    pub async fn admit_queue_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &QueueCommand,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        Box::pin(self.publish_queue_in(
            request,
            session,
            QueuePublication::Management(command),
            limits,
        ))
        .await
    }

    /// Land exactly the first queued PR using the existing fast-forward merge
    /// profile. Target movement, PR merge and queue completion share one RCR.
    /// Review/check protection remains mandatory; no caller-supplied batch
    /// success or derived merge object is accepted by this profile.
    pub async fn land_queue_head_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &queue::QueueLandingCommand,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        Box::pin(self.publish_queue_in(
            request,
            session,
            QueuePublication::Landing(command),
            limits,
        ))
        .await
    }

    async fn publish_queue_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        publication: QueuePublication<'_>,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let error = |source| NodeReceiveTransportRefusal::Admission(Box::new(source));
        let attempt = match publication {
            QueuePublication::Management(command) => {
                queue::proposal(&context, command).map_err(error)?.1
            }
            QueuePublication::Landing(command) => {
                queue::landing_proposal(&context, command).map_err(error)?.1
            }
        };
        let tx = attempt
            .derive()
            .map_err(|_| {
                error(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        // Resolve the original outcome before new-work gates. Seal revalidation
        // still rejects key reuse with other bytes after subsequent queue edits.
        if let OutcomeLookup::Decided(terminal) = self
            .resolve_outcome_checkpointed_in(request, tx)
            .await
            .map_err(|source| error(source.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|source| error(source.into()))?;
            return Ok((tx, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self
                .durable_admission_projection(&context)
                .map_err(error)?
                .with_authentication(authenticated.authentication()),
            object_limits: MergeObjectLimits::default(),
            staging: None,
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        let terminal = match publication {
            QueuePublication::Management(command) => {
                Box::pin(queue::admit_queue_async(
                    &self.authority,
                    request.authority(),
                    &context,
                    command,
                    limits,
                    &projection,
                ))
                .await
            }
            QueuePublication::Landing(command) => {
                Box::pin(queue::admit_landing_async(
                    &self.authority,
                    request.authority(),
                    &context,
                    command,
                    limits,
                    &projection,
                ))
                .await
            }
        }
        .map_err(error)?;
        Ok((tx, terminal))
    }

    /// Read complete queues in numeric order at one exact repository head.
    /// Continuations require the first page's head. Current canonical and caller
    /// visibility both apply, including when reading an older retained head.
    pub async fn read_queues_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        after: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<queue::QueuePage, QueueReadRefusal> {
        if limit == 0 || limit > 100 {
            return Err(QueueReadRefusal::InvalidLimit);
        }
        if after != 0 && expected_head.is_none() {
            return Err(QueueReadRefusal::SnapshotRequired);
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(QueueReadRefusal::Cell)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|source| QueueReadRefusal::Selection(Box::new(source)))?;
        let selected = snapshots::select(
            &self.authority,
            request.authority(),
            &current.basis,
            expected_head,
            &|| !super::workspace_request_live(request),
        )
        .await?;
        let visible = |reference: &RefName| {
            !visibility.hides(reference.as_bytes())
                && !current.hidden_refs.hides(reference.as_bytes())
        };
        queue::read_page_at(
            &self.authority,
            request.authority(),
            &selected,
            after,
            limit,
            &visible,
            &|| !super::workspace_request_live(request),
        )
        .await
        .map_err(|source| QueueReadRefusal::Admission(Box::new(source)))
    }

    /// Read one complete queue. Hidden targets or entries suppress the whole
    /// queue; a partial replay must never masquerade as its canonical state.
    pub async fn read_queue_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        number: QueueNumber,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<QueueRead, QueueReadRefusal> {
        admits_read(self.cell_state(), ReadMode::Current).map_err(QueueReadRefusal::Cell)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|source| QueueReadRefusal::Selection(Box::new(source)))?;
        let selected = snapshots::select(
            &self.authority,
            request.authority(),
            &current.basis,
            expected_head,
            &|| !super::workspace_request_live(request),
        )
        .await?;
        let visible = |reference: &RefName| {
            !visibility.hides(reference.as_bytes())
                && !current.hidden_refs.hides(reference.as_bytes())
        };
        let queue = queue::read_queue_at(
            &self.authority,
            request.authority(),
            &selected,
            number,
            &visible,
            &|| !super::workspace_request_live(request),
        )
        .await
        .map_err(|source| QueueReadRefusal::Admission(Box::new(source)))?;
        Ok(QueueRead {
            source_head: selected.id(),
            queue,
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod landing_tests;
