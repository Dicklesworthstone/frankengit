//! Durable repository milestones on the same authority as issues. Progress is
//! derived from issue membership at the selected head; no counters are stored.

use super::{issues::snapshots, native_merge::NodeNativeMergeProjection};
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use fgit_admission::merge::native::{milestones, objects::MergeObjectLimits};
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::{MilestoneNumber, event::milestone::MilestoneCommand};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{RefusalCode, RepositoryAuthorityHeadId, TxId};

impl OneNode {
    /// Publish a milestone command through the sealed metadata owner. The
    /// authenticated session supplies actor and idempotency identity; milestone
    /// text and dates cannot supply authorization or change any Git reference.
    pub async fn admit_milestone_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &MilestoneCommand,
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
        let (_, attempt) = milestones::proposal(&context, command).map_err(error)?;
        let tx = attempt
            .derive()
            .map_err(|_| {
                error(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        // Historical terminal recovery precedes current intake, quota and
        // lifecycle validation. Recheck the entire immutable seal, not just a
        // known key, so a retry cannot silently change the original action.
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
                .with_authenticated_session(authenticated),
            object_limits: MergeObjectLimits::default(),
            staging: None,
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        let terminal = Box::pin(milestones::admit_milestone_async(
            &self.authority,
            request.authority(),
            &context,
            command,
            limits,
            &projection,
        ))
        .await
        .map_err(error)?;
        Ok((tx, terminal))
    }

    /// Read a numeric milestone page and issue progress from one authenticated
    /// current or retained head. Remote adapters must authenticate repository
    /// metadata access before entering this trusted-local surface.
    pub async fn read_milestones_in(
        &self,
        request: &NodeRequestContext,
        after: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<milestones::MilestonePage, MilestoneReadRefusal> {
        validate_page(after, limit, expected_head)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(MilestoneReadRefusal::Cell)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|source| MilestoneReadRefusal::Selection(Box::new(source)))?;
        let selected = snapshots::select(
            &self.authority,
            request.authority(),
            &current.basis,
            expected_head,
            &|| !super::workspace_request_live(request),
        )
        .await?;
        milestones::read_page_at(
            &self.authority,
            request.authority(),
            &selected,
            after,
            limit,
            &|| !super::workspace_request_live(request),
        )
        .await
        .map_err(|source| MilestoneReadRefusal::Admission(Box::new(source)))
    }

    /// Read exact milestone history, metadata and membership progress at the
    /// same retained head. A continuation always requires that head token;
    /// concurrent issue or milestone writes never change a pinned response.
    pub async fn read_milestone_history_in(
        &self,
        request: &NodeRequestContext,
        number: MilestoneNumber,
        after_version: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<milestones::MilestoneHistoryPage, MilestoneReadRefusal> {
        validate_page(after_version, limit, expected_head)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(MilestoneReadRefusal::Cell)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|source| MilestoneReadRefusal::Selection(Box::new(source)))?;
        let selected = snapshots::select(
            &self.authority,
            request.authority(),
            &current.basis,
            expected_head,
            &|| !super::workspace_request_live(request),
        )
        .await?;
        milestones::read_history_at(
            &self.authority,
            request.authority(),
            &selected,
            number,
            after_version,
            limit,
            &|| !super::workspace_request_live(request),
        )
        .await
        .map_err(|source| MilestoneReadRefusal::Admission(Box::new(source)))
    }
}

const fn validate_page(
    after: u64,
    limit: u16,
    expected: Option<RepositoryAuthorityHeadId>,
) -> Result<(), MilestoneReadRefusal> {
    if limit == 0 || limit > 100 {
        return Err(MilestoneReadRefusal::InvalidLimit);
    }
    if after != 0 && expected.is_none() {
        return Err(MilestoneReadRefusal::SnapshotRequired);
    }
    Ok(())
}

#[derive(Debug)]
pub enum MilestoneReadRefusal {
    InvalidLimit,
    SnapshotRequired,
    SnapshotMoved,
    Cell(CellRefusal),
    Selection(Box<super::events::ForgeEventReadRefusal>),
    Admission(Box<AdmissionError>),
}
impl From<snapshots::SnapshotReadRefusal> for MilestoneReadRefusal {
    fn from(error: snapshots::SnapshotReadRefusal) -> Self {
        match error {
            snapshots::SnapshotReadRefusal::Unavailable => Self::SnapshotMoved,
            snapshots::SnapshotReadRefusal::Admission(error) => Self::Admission(error),
        }
    }
}
impl std::fmt::Display for MilestoneReadRefusal {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "native milestone read refused: {self:?}")
    }
}
impl std::error::Error for MilestoneReadRefusal {}
