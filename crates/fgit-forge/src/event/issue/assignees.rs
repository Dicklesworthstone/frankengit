//! Stable additive assignee intent, separate from exact-version issue commands.
use super::{IssueAction, IssueCommand, invalid_native, validate_assignees};
use crate::{AggregateVersion, ExpectedVersion, ForgeEvent, IssueNumber};
use fgit_codec::CodecRefusal;
use fgit_types::{PrincipalId, RefusalCode};

/// Add these principals to an existing issue's assignee set once. The set is
/// sorted, unique, nonempty and bounded. Existing assignees remain assigned;
/// admission checks the resulting union against the current issue's limit.
/// The authenticated actor and idempotency key are bound by a distinct seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueAssigneesIntent {
    pub number: IssueNumber,
    pub assignees: Vec<PrincipalId>,
}
impl IssueAssigneesIntent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if self.assignees.is_empty() {
            return Err(invalid_native("issue.empty_assignees"));
        }
        validate_assignees(&self.assignees)
    }

    /// Canonical commitment template for the add-assignees-v1 seal profile.
    ///
    /// Version 2 is a fixed encoding coordinate, never an expected predecessor
    /// or a publication position. Reusing the historical Assign event keeps its
    /// canonical bytes and union semantics intact. Admission seals this template
    /// under the distinct profile and plans its actual successor from the
    /// authenticated current issue frontier.
    pub fn commitment_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        self.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        IssueCommand {
            number: self.number,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: IssueAction::Assign {
                assignees: self.assignees.clone(),
            },
        }
        .proposed_event(actor)
    }
}

#[cfg(test)]
mod tests;
