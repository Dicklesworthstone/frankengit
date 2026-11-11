//! Stable comment intent, distinct from exact-version discussion commands.
use super::{DiscussionAction, DiscussionCommand, validate_comment_body};
use crate::{AggregateVersion, DiscussionNumber, ExpectedVersion, ForgeEvent};
use fgit_codec::CodecRefusal;
use fgit_types::{PrincipalId, RefusalCode};

/// Add this exact comment once to an existing, currently unlocked discussion.
/// Admission supplies the authenticated actor and idempotency key. The intent
/// selects no predecessor, title, lifecycle state or lock state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscussionCommentIntent {
    pub number: DiscussionNumber,
    pub body: String,
}

impl DiscussionCommentIntent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        validate_comment_body(&self.body)
    }

    /// Canonical template for the separate `discussion.append-comment.v1` seal.
    /// Version 2 is only an identity coordinate: version 1 remains reserved for
    /// Open. The actual successor is selected from authenticated current state;
    /// no historical event or exact-version request encoding changes.
    pub fn commitment_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        DiscussionCommand {
            number: self.number,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: DiscussionAction::Comment {
                body: self.body.clone(),
            },
        }
        .proposed_event(actor)
    }
}

#[cfg(test)]
mod tests;
