//! One canonical discussion stream per native PR. Comments retain their own
//! sequence, so conversation cannot advance PR metadata or review versions.

use fgit_admission::merge::native::objects::MergeObjectLimits;
use fgit_admission::merge::native::pull_request::comments;
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::pull_request_comment::PullRequestCommentCommand;
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{RefusalCode, RepositoryAuthorityHeadId, TxId};
use fgit_wire::visibility::RefVisibility;

use super::snapshots;
use crate::treefs_workspace::native_merge::NodeNativeMergeProjection;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};

pub use comments::{PullRequestCommentView, PullRequestCommentsPage};

impl OneNode {
    /// Append one exact-version comment and its delivery obligation in the
    /// same native repository transaction. The authenticated session supplies
    /// the actor; comment text grants no approval or publication permission.
    /// Closed and merged native PRs retain their conversation streams.
    pub async fn admit_pull_request_comment_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &PullRequestCommentCommand,
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
        let map = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let (_, attempt) = comments::proposal(&context, command).map_err(map)?;
        let tx = attempt
            .derive()
            .map_err(|_| {
                map(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        // Historical results precede current intake, quotas, and PR state.
        // Re-sealing still refuses semantic reuse of the original key.
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            self.tenant_id,
            self.repository_id,
            tx,
        )
        .await
        .map_err(|error| map(error.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|error| map(error.into()))?;
            return Ok((tx, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self.durable_admission_projection(&context).map_err(map)?,
            object_limits: MergeObjectLimits::default(),
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        let terminal = comments::admit_async(
            &self.authority,
            request.authority(),
            &context,
            command,
            limits,
            &projection,
        )
        .await
        .map_err(map)?;
        Ok((tx, terminal))
    }

    /// Read one bounded contiguous discussion window at one authenticated
    /// current or retained head. Current disclosure policy still gates both
    /// of the PR's references, including when a historical head is selected.
    /// An absent/hidden native PR is None; unavailable evidence is an error.
    pub async fn read_pull_request_comments_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        number: PullRequestNumber,
        after: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<Option<PullRequestCommentsPage>, PullRequestCommentsReadRefusal> {
        if !(1..=100).contains(&limit) {
            return Err(PullRequestCommentsReadRefusal::InvalidLimit);
        }
        if after != 0 && expected_head.is_none() {
            return Err(PullRequestCommentsReadRefusal::UnpinnedContinuation);
        }
        admits_read(self.cell_state(), ReadMode::Current)
            .map_err(PullRequestCommentsReadRefusal::Cell)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|error| PullRequestCommentsReadRefusal::Selection(Box::new(error)))?;
        let selected = snapshots::select(
            &self.authority,
            request.authority(),
            &current.basis,
            expected_head,
            &|| !super::super::workspace_request_live(request),
        )
        .await
        .map_err(|error| match error {
            snapshots::SnapshotReadRefusal::Unavailable => {
                PullRequestCommentsReadRefusal::SnapshotMoved
            }
            snapshots::SnapshotReadRefusal::Admission(error) => {
                PullRequestCommentsReadRefusal::Admission(error)
            }
        })?;
        let visible = |source: &fgit_types::RefName, target: &fgit_types::RefName| {
            [source, target].iter().all(|name| {
                !visibility.hides(name.as_bytes()) && !current.hidden_refs.hides(name.as_bytes())
            })
        };
        let result = comments::read_page_at(
            &self.authority,
            request.authority(),
            &selected,
            number,
            after,
            limit,
            &visible,
            &|| !super::super::workspace_request_live(request),
        )
        .await
        .map_err(|error| PullRequestCommentsReadRefusal::Admission(Box::new(error)))?;
        if let Some(page) = &result {
            if page.number != number || page.source_head != selected.id() {
                return Err(PullRequestCommentsReadRefusal::Admission(Box::new(
                    AdmissionError::AsyncProjectionUnavailable(RefusalCode::EvidenceInvalid),
                )));
            }
            page.validate_window(after, limit).map_err(|code| {
                PullRequestCommentsReadRefusal::Admission(Box::new(
                    AdmissionError::AsyncProjectionUnavailable(code),
                ))
            })?;
        }
        Ok(result)
    }
}

#[derive(Debug)]
pub enum PullRequestCommentsReadRefusal {
    InvalidLimit,
    UnpinnedContinuation,
    SnapshotMoved,
    Cell(CellRefusal),
    Selection(Box<super::super::events::ForgeEventReadRefusal>),
    Admission(Box<AdmissionError>),
}
impl PullRequestCommentsReadRefusal {
    #[must_use]
    pub const fn is_snapshot_unavailable(&self) -> bool {
        matches!(self, Self::SnapshotMoved)
    }
}
impl std::fmt::Display for PullRequestCommentsReadRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "pull-request comments read refused: {self:?}")
    }
}
impl std::error::Error for PullRequestCommentsReadRefusal {}
