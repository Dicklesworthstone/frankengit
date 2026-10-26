//! Stable additive comment intent, separate from exact-version issue commands.
use super::{IssueAction, IssueCommand, validate_comment_body};
use crate::{AggregateVersion, ExpectedVersion, ForgeEvent, IssueNumber};
use fgit_codec::CodecRefusal;
use fgit_types::{PrincipalId, RefusalCode};

/// Append this exact comment once to an existing issue. No issue version, title,
/// lifecycle state or labels are part of the intent. The authenticated actor and
/// idempotency key are supplied by admission and bound by the distinct seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueCommentIntent {
    pub number: IssueNumber,
    pub body: String,
}
impl IssueCommentIntent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        validate_comment_body(&self.body)
    }

    /// Canonical commitment template for the append-comment-v1 seal profile.
    ///
    /// Version 2 is a fixed encoding coordinate, never an expected predecessor
    /// or a publication position. It permits reuse of the existing canonical
    /// Comment encoding (version 1 is reserved for Open) without changing any
    /// historical event bytes. Admission must use the distinct append scope and
    /// plan the actual successor from the authenticated current issue frontier.
    pub fn commitment_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        IssueCommand {
            number: self.number,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: IssueAction::Comment {
                body: self.body.clone(),
            },
        }
        .proposed_event(actor)
    }
}

#[cfg(test)]
mod tests;
