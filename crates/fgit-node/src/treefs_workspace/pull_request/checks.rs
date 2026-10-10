//! Current-visibility gate for authority-selected workflow observations.

use fgit_admission::AdmissionError;
use fgit_admission::merge::native::workflow_checks;
use fgit_forge::aggregate::PullRequestNumber;
use fgit_forge::event::workflow_check::WorkflowCheckId;
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{RefusalCode, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;

use super::snapshots;
use crate::{AdmissionMaterializationRefusal, NodeRequestContext, OneNode};
pub use workflow_checks::{PullRequestChecksPage, WorkflowCheckSummary};

impl OneNode {
    /// Bounded workflow observations for the PR's exact recorded source. A
    /// changed/deleted source at the selected head yields `source_current=false`
    /// and no checks. Historical pages keep their PR and source coordinates;
    /// CURRENT caller visibility and hidden-ref policy still gate both branches.
    ///
    /// Continuations require the first page's authority head. The existing
    /// authenticated ancestor walk refuses configuration/policy/compaction
    /// boundaries. A retained observation never establishes permission to merge.
    pub async fn read_pull_request_checks_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        number: PullRequestNumber,
        after: Option<WorkflowCheckId>,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<Option<PullRequestChecksPage>, PullRequestChecksReadRefusal> {
        if limit == 0 || limit > 100 {
            return Err(PullRequestChecksReadRefusal::InvalidLimit);
        }
        if after.is_some() && expected_head.is_none() {
            return Err(PullRequestChecksReadRefusal::UnpinnedContinuation);
        }
        admits_read(self.cell_state(), ReadMode::Current)
            .map_err(PullRequestChecksReadRefusal::Cell)?;
        let current = self
            .event_read_basis_in(request, None)
            .await
            .map_err(|error| PullRequestChecksReadRefusal::Selection(Box::new(error)))?;
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
                PullRequestChecksReadRefusal::SnapshotMoved
            }
            snapshots::SnapshotReadRefusal::Admission(error) => {
                PullRequestChecksReadRefusal::Admission(error)
            }
        })?;
        let ref_state = crate::read_historical_ref_state_in(
            &self.authority,
            request.authority(),
            self.repository_id,
            selected.body(),
        )
        .await
        .map_err(|error| PullRequestChecksReadRefusal::Authority(Box::new(error)))?;
        if !super::super::workspace_request_live(request) {
            return Err(PullRequestChecksReadRefusal::Admission(Box::new(
                AdmissionError::AsyncProjectionUnavailable(RefusalCode::CancellationInProgress),
            )));
        }
        let refs = ref_state.refs();
        let visible = |source: &fgit_types::RefName, target: &fgit_types::RefName| {
            [source, target].iter().all(|name| {
                !visibility.hides(name.as_bytes()) && !current.hidden_refs.hides(name.as_bytes())
            })
        };
        workflow_checks::read_pull_request_page_at(
            &self.authority,
            request.authority(),
            &selected,
            number,
            refs,
            after,
            limit,
            &visible,
            &|| !super::super::workspace_request_live(request),
        )
        .await
        .map_err(|error| PullRequestChecksReadRefusal::Admission(Box::new(error)))
    }
}

#[derive(Debug)]
pub enum PullRequestChecksReadRefusal {
    InvalidLimit,
    UnpinnedContinuation,
    SnapshotMoved,
    Cell(CellRefusal),
    Selection(Box<super::super::events::ForgeEventReadRefusal>),
    Authority(Box<AdmissionMaterializationRefusal>),
    Admission(Box<AdmissionError>),
}
impl PullRequestChecksReadRefusal {
    /// Only an unavailable ancestor allows a transport to suggest restarting
    /// pagination. Corruption, cancellation and missing evidence remain errors.
    #[must_use]
    pub const fn is_snapshot_unavailable(&self) -> bool {
        matches!(self, Self::SnapshotMoved)
    }
}
impl std::fmt::Display for PullRequestChecksReadRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "pull-request checks read refused: {self:?}")
    }
}
impl std::error::Error for PullRequestChecksReadRefusal {}
