//! Durable native discussions through the repository's sealed metadata owner.
//! Independent aggregate identities preserve issues and native Git state.

use super::{issues::snapshots, native_merge::NodeNativeMergeProjection};
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use fgit_admission::merge::native::{discussions, objects::MergeObjectLimits};
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::{
    DiscussionNumber,
    event::discussion::{DiscussionCommand, DiscussionCommentIntent},
};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{RefusalCode, RepositoryAuthorityHeadId, TxId};

#[derive(Clone, Copy)]
enum DiscussionSubmission<'a> {
    Exact(&'a DiscussionCommand),
    AppendComment(&'a DiscussionCommentIntent),
}

impl OneNode {
    /// Publish the exact comment body without selecting a mutable discussion
    /// predecessor. Every attempt revalidates the current discussion and lock
    /// before assigning its next version. The actor, text and retry identity
    /// stay fixed; a known terminal is recovered before new intake or quota.
    pub async fn admit_discussion_comment_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        intent: &DiscussionCommentIntent,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        self.admit_discussion_submission_in(
            request,
            session,
            DiscussionSubmission::AppendComment(intent),
            limits,
        )
        .await
    }

    /// Publish a discussion command through the sealed metadata owner. The
    /// authenticated session supplies actor and idempotency identity; discussion
    /// text cannot supply authorization or change any Git reference.
    pub async fn admit_discussion_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &DiscussionCommand,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        self.admit_discussion_submission_in(
            request,
            session,
            DiscussionSubmission::Exact(command),
            limits,
        )
        .await
    }

    async fn admit_discussion_submission_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        submission: DiscussionSubmission<'_>,
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
        let (_, attempt) = match submission {
            DiscussionSubmission::Exact(command) => discussions::proposal(&context, command),
            DiscussionSubmission::AppendComment(intent) => {
                discussions::append_proposal(&context, intent)
            }
        }
        .map_err(error)?;
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
        let terminal = match submission {
            DiscussionSubmission::Exact(command) => {
                Box::pin(discussions::admit_discussion_async(
                    &self.authority,
                    request.authority(),
                    &context,
                    command,
                    limits,
                    &projection,
                ))
                .await
            }
            DiscussionSubmission::AppendComment(intent) => {
                Box::pin(discussions::admit_discussion_comment_async(
                    &self.authority,
                    request.authority(),
                    &context,
                    intent,
                    limits,
                    &projection,
                ))
                .await
            }
        }
        .map_err(error)?;
        Ok((tx, terminal))
    }

    /// Read a numeric discussion page from one authenticated
    /// current or retained head. Remote adapters must authenticate repository
    /// metadata access before entering this trusted-local surface.
    pub async fn read_discussions_in(
        &self,
        request: &NodeRequestContext,
        after: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<discussions::DiscussionPage, DiscussionReadRefusal> {
        validate_page(after, limit, expected_head)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(DiscussionReadRefusal::Cell)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|source| DiscussionReadRefusal::Selection(Box::new(source)))?;
        let selected = snapshots::select(
            &self.authority,
            request.authority(),
            &current.basis,
            expected_head,
            &|| !super::workspace_request_live(request),
        )
        .await?;
        discussions::read_page_at(
            &self.authority,
            request.authority(),
            &selected,
            after,
            limit,
            &|| !super::workspace_request_live(request),
        )
        .await
        .map_err(|source| DiscussionReadRefusal::Admission(Box::new(source)))
    }

    /// Read exact discussion history and current discussion metadata at the
    /// same retained head. A continuation always requires that head token;
    /// concurrent forge writes never change a pinned response.
    pub async fn read_discussion_history_in(
        &self,
        request: &NodeRequestContext,
        number: DiscussionNumber,
        after_version: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<discussions::DiscussionHistoryPage, DiscussionReadRefusal> {
        validate_page(after_version, limit, expected_head)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(DiscussionReadRefusal::Cell)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|source| DiscussionReadRefusal::Selection(Box::new(source)))?;
        let selected = snapshots::select(
            &self.authority,
            request.authority(),
            &current.basis,
            expected_head,
            &|| !super::workspace_request_live(request),
        )
        .await?;
        discussions::read_history_at(
            &self.authority,
            request.authority(),
            &selected,
            number,
            after_version,
            limit,
            &|| !super::workspace_request_live(request),
        )
        .await
        .map_err(|source| DiscussionReadRefusal::Admission(Box::new(source)))
    }
}

const fn validate_page(
    after: u64,
    limit: u16,
    expected: Option<RepositoryAuthorityHeadId>,
) -> Result<(), DiscussionReadRefusal> {
    if limit == 0 || limit > 100 {
        return Err(DiscussionReadRefusal::InvalidLimit);
    }
    if after != 0 && expected.is_none() {
        return Err(DiscussionReadRefusal::SnapshotRequired);
    }
    Ok(())
}

#[derive(Debug)]
pub enum DiscussionReadRefusal {
    InvalidLimit,
    SnapshotRequired,
    SnapshotMoved,
    Cell(CellRefusal),
    Selection(Box<super::events::ForgeEventReadRefusal>),
    Admission(Box<AdmissionError>),
}
impl From<snapshots::SnapshotReadRefusal> for DiscussionReadRefusal {
    fn from(error: snapshots::SnapshotReadRefusal) -> Self {
        match error {
            snapshots::SnapshotReadRefusal::Unavailable => Self::SnapshotMoved,
            snapshots::SnapshotReadRefusal::Admission(error) => Self::Admission(error),
        }
    }
}
impl std::fmt::Display for DiscussionReadRefusal {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "native discussion read refused: {self:?}")
    }
}
impl std::error::Error for DiscussionReadRefusal {}
