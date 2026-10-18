//! Append-only conversation comments in a stream independent of PR metadata.
//! A comment is untrusted text, never an approval or a source-line anchor.

use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use crate::{AggregateId, AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PrincipalId, RefusalCode};

pub const MAX_COMMENT_BYTES: usize = 65_536;

/// Exact submitted text and its authenticated author. No clock, current PR
/// version, mutable branch tip or rendering result enters the event identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePullRequestComment {
    pub actor: PrincipalId,
    pub body: String,
}

impl NativePullRequestComment {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        validate_body(&self.body)
    }

    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_bytes("actor", self.actor.as_bytes())?;
        out.write_bytes("body", self.body.as_bytes())
    }

    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let actor: [u8; 16] = input
            .read_bytes("actor")?
            .try_into()
            .map_err(|_| invalid_native("pull_request_comment.actor"))?;
        let bytes = input.read_bytes("body")?;
        if bytes.len() > MAX_COMMENT_BYTES {
            return Err(invalid_native("pull_request_comment.body_limit"));
        }
        let body =
            std::str::from_utf8(bytes).map_err(|_| invalid_native("pull_request_comment.utf8"))?;
        validate_body(body)?;
        Ok(Self {
            actor: PrincipalId::from_bytes(actor),
            body: body.to_owned(),
        })
    }
}

pub fn validate_body(body: &str) -> Result<(), CodecRefusal> {
    if body.len() > MAX_COMMENT_BYTES || body.trim().is_empty() || body.contains('\0') {
        return Err(invalid_native("pull_request_comment.body"));
    }
    Ok(())
}

/// `expected_version` names the conversation stream, not PR metadata. Its
/// first comment requires NewStream; subsequent appends name an exact version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestCommentCommand {
    pub number: PullRequestNumber,
    pub expected_version: ExpectedVersion,
    pub body: String,
}

impl PullRequestCommentCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        validate_body(&self.body).map_err(|_| RefusalCode::EvidenceInvalid)?;
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(previous) => previous
                .next()
                .map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        Ok(ForgeEvent {
            aggregate: AggregateId::PullRequestConversation(self.number),
            version,
            payload: ForgeEventPayload::PullRequestCommentedNative(NativePullRequestComment {
                actor,
                body: self.body.clone(),
            }),
        })
    }
}

pub(super) fn validate_event(event: &ForgeEvent) -> Result<(), CodecRefusal> {
    if matches!(event.aggregate, AggregateId::PullRequestConversation(_))
        != matches!(
            event.payload,
            ForgeEventPayload::PullRequestCommentedNative(_)
        )
    {
        return Err(invalid_native("pull_request_comment.aggregate_kind"));
    }
    if let ForgeEventPayload::PullRequestCommentedNative(comment) = &event.payload {
        comment.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
