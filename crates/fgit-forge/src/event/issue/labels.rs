//! Stable label-addition intent, separate from exact-version label replacement.
use super::{IssueAction, IssueCommand, invalid_native, validate_labels};
use crate::{AggregateVersion, ExpectedVersion, ForgeEvent, IssueNumber};
use fgit_codec::CodecRefusal;
use fgit_types::{PrincipalId, RefusalCode};

/// Add a sorted, distinct, nonempty label set to the selected issue. Admission
/// checks its union with the current labels on every attempt. This request has
/// no predecessor and never replaces labels, removes them, or changes metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueLabelsIntent {
    pub number: IssueNumber,
    pub labels: Vec<String>,
}
impl IssueLabelsIntent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if self.labels.is_empty() {
            return Err(invalid_native("issue.empty_labels"));
        }
        validate_labels(&self.labels)
    }

    /// Version 2 is an identity template, never an expected predecessor or an
    /// assigned publication position. The separate issue.add-labels.v1 seal
    /// binds this event; admission obtains its actual position from authority.
    pub fn commitment_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        self.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        IssueCommand {
            number: self.number,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: IssueAction::AddLabels {
                labels: self.labels.clone(),
            },
        }
        .proposed_event(actor)
    }
}

#[cfg(test)]
mod tests;
