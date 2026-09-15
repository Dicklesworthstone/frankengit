//! Repository-wide canonical forge event feed for local integrations.
use super::workspace_request_live;
use crate::{AdmissionMaterializationRefusal, NodeRequestContext, OneNode};
use fgit_admission::merge::native::feed::{self, ForgeEventCursor, ForgeEventPage};
use fgit_types::RepositoryAuthorityHeadId;
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};

#[derive(Debug)]
pub enum ForgeEventReadRefusal {
    InvalidLimit,
    SnapshotMoved,
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    Admission(Box<fgit_admission::AdmissionError>),
}
impl std::fmt::Display for ForgeEventReadRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "forge event feed refused: {self:?}")
    }
}
impl std::error::Error for ForgeEventReadRefusal {}

impl OneNode {
    /// Read committed forge events in repository order from canonical authority
    /// history. A cursor remains valid when the repository advances; supplying
    /// `expected_head` instead freezes pagination to one exact authority head.
    /// This trusted-local read grants no mutation authority and maintains no
    /// second event database or process-local cursor state.
    pub async fn read_forge_events_in(
        &self,
        request: &NodeRequestContext,
        after: Option<ForgeEventCursor>,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<ForgeEventPage, ForgeEventReadRefusal> {
        if limit == 0 || limit > 100 {
            return Err(ForgeEventReadRefusal::InvalidLimit);
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(ForgeEventReadRefusal::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| ForgeEventReadRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(ForgeEventReadRefusal::SnapshotMoved);
        }
        feed::read_page_at(
            &self.authority,
            request.authority(),
            selected.basis(),
            after,
            limit,
            &|| !workspace_request_live(request),
        )
        .await
        .map_err(|error| ForgeEventReadRefusal::Admission(Box::new(error)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refusal_vocabulary_distinguishes_input_and_snapshot_movement() {
        assert!(
            ForgeEventReadRefusal::InvalidLimit
                .to_string()
                .contains("InvalidLimit")
        );
        assert!(
            ForgeEventReadRefusal::SnapshotMoved
                .to_string()
                .contains("SnapshotMoved")
        );
    }
}
