//! Stable additive PR comment intent, separate from exact conversation versions.

use super::{PullRequestCommentCommand, SourceCommentAnchor, validate_body};
use crate::{ExpectedVersion, ForgeEvent, PullRequestNumber};
use fgit_codec::CodecRefusal;
use fgit_types::{PrincipalId, RefusalCode};

/// Append this exact comment once to an existing native pull request. The
/// conversation predecessor is selected during admission, not submitted here.
/// The actor and idempotency key are supplied by admission and bound by a
/// distinct seal profile. An optional source anchor retains all its original
/// coordinates, including the exact PR metadata version; replanning the
/// conversation position never refreshes or remaps those coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestAppendCommentCommand {
    pub number: PullRequestNumber,
    pub body: String,
    pub anchor: Option<SourceCommentAnchor>,
}

impl PullRequestAppendCommentCommand {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        validate_body(&self.body)?;
        if let Some(anchor) = &self.anchor {
            anchor.validate()?;
        }
        Ok(())
    }

    /// Canonical commitment template for the append-comment-v1 seal profile.
    ///
    /// Version 1 is a fixed encoding coordinate, never an expected predecessor
    /// or a publication position. Reusing the historical kind-12/kind-15 event
    /// encoding changes no existing bytes. Admission must use the distinct
    /// append scope, independently verify the complete seal, and plan the real
    /// successor from the authenticated current conversation frontier.
    pub fn commitment_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        // Bound caller-owned text and anchor fields before cloning them into
        // the historical command representation.
        self.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        PullRequestCommentCommand {
            number: self.number,
            expected_version: ExpectedVersion::NewStream,
            body: self.body.clone(),
            anchor: self.anchor.clone(),
        }
        .proposed_event(actor)
    }
}

#[cfg(test)]
mod tests;
