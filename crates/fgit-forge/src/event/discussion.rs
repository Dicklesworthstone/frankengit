//! Canonical repository discussions with exact-version lifecycle and comments.
//! The stream is independent of issues, pull requests and their read grants.
use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use crate::aggregate::{AggregateId, AggregateVersion, DiscussionNumber, ExpectedVersion};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PrincipalId, RefusalCode};

pub use super::issue::{MAX_BODY_BYTES, MAX_TITLE_BYTES};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscussionState {
    Open,
    Closed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscussionEdit {
    pub title: Option<String>,
    pub body: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscussionAction {
    Open { title: String, body: String },
    Edit(DiscussionEdit),
    Comment { body: String },
    Close,
    Reopen,
    Lock,
    Unlock,
}

impl DiscussionAction {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        match self {
            Self::Open { title, body } => {
                validate_title(title)?;
                validate_body(body)
            }
            Self::Edit(edit) => {
                if edit.title.is_none() && edit.body.is_none() {
                    return Err(invalid_native("discussion.empty_edit"));
                }
                if let Some(title) = &edit.title {
                    validate_title(title)?;
                }
                if let Some(body) = &edit.body {
                    validate_body(body)?;
                }
                Ok(())
            }
            Self::Comment { body } => {
                validate_body(body)?;
                if body.trim().is_empty() {
                    return Err(invalid_native("discussion.comment"));
                }
                Ok(())
            }
            Self::Close | Self::Reopen | Self::Lock | Self::Unlock => Ok(()),
        }
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Edit(_) => "edit",
            Self::Comment { .. } => "comment",
            Self::Close => "close",
            Self::Reopen => "reopen",
            Self::Lock => "lock",
            Self::Unlock => "unlock",
        }
    }

    fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_scalar(match self {
            Self::Open { .. } => 1u32,
            Self::Edit(_) => 2,
            Self::Close => 3,
            Self::Reopen => 4,
            Self::Comment { .. } => 5,
            Self::Lock => 6,
            Self::Unlock => 7,
        });
        match self {
            Self::Open { title, body } => {
                out.write_bytes("discussion.title", title.as_bytes())?;
                out.write_bytes("discussion.body", body.as_bytes())?;
            }
            Self::Edit(edit) => {
                for (field, value) in [
                    ("discussion.title", &edit.title),
                    ("discussion.body", &edit.body),
                ] {
                    out.write_bool(value.is_some());
                    if let Some(value) = value {
                        out.write_bytes(field, value.as_bytes())?;
                    }
                }
            }
            Self::Comment { body } => out.write_bytes("discussion.comment", body.as_bytes())?,
            Self::Close | Self::Reopen | Self::Lock | Self::Unlock => {}
        }
        Ok(())
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        let action = match input.read_scalar::<u32>("discussion.action")? {
            1 => Self::Open {
                title: text(input, "discussion.title", MAX_TITLE_BYTES)?,
                body: text(input, "discussion.body", MAX_BODY_BYTES)?,
            },
            2 => Self::Edit(DiscussionEdit {
                title: if input.read_bool("discussion.has_title")? {
                    Some(text(input, "discussion.title", MAX_TITLE_BYTES)?)
                } else {
                    None
                },
                body: if input.read_bool("discussion.has_body")? {
                    Some(text(input, "discussion.body", MAX_BODY_BYTES)?)
                } else {
                    None
                },
            }),
            3 => Self::Close,
            4 => Self::Reopen,
            5 => Self::Comment {
                body: text(input, "discussion.comment", MAX_BODY_BYTES)?,
            },
            6 => Self::Lock,
            7 => Self::Unlock,
            observed => {
                return Err(CodecRefusal::VariantUnknown {
                    field: "discussion.action",
                    observed,
                    offset,
                });
            }
        };
        action.validate()?;
        Ok(action)
    }
}

fn validate_title(title: &str) -> Result<(), CodecRefusal> {
    if title.trim().is_empty()
        || title.len() > MAX_TITLE_BYTES
        || title.chars().any(char::is_control)
    {
        return Err(invalid_native("discussion.title"));
    }
    Ok(())
}

fn validate_body(body: &str) -> Result<(), CodecRefusal> {
    if body.len() > MAX_BODY_BYTES || body.contains('\0') {
        return Err(invalid_native("discussion.body"));
    }
    Ok(())
}

fn text(
    input: &mut Decoder<'_>,
    field: &'static str,
    limit: usize,
) -> Result<String, CodecRefusal> {
    let bytes = input.read_bytes(field)?;
    if bytes.len() > limit {
        return Err(invalid_native(field));
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| invalid_native(field))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDiscussionEvent {
    pub actor: PrincipalId,
    pub action: DiscussionAction,
}

impl NativeDiscussionEvent {
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.actor.as_bytes());
        self.action.write(out)
    }

    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self {
            actor: PrincipalId::from_bytes(input.read_opaque_id("discussion.actor")?),
            action: DiscussionAction::read(input)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscussionCommand {
    pub number: DiscussionNumber,
    pub expected_version: ExpectedVersion,
    pub action: DiscussionAction,
}

impl DiscussionCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        self.action
            .validate()
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        if matches!(self.action, DiscussionAction::Open { .. })
            != (self.expected_version == ExpectedVersion::NewStream)
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(version) => version
                .next()
                .map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        Ok(ForgeEvent {
            aggregate: AggregateId::Discussion(self.number),
            version,
            payload: ForgeEventPayload::DiscussionChangedNative(NativeDiscussionEvent {
                actor,
                action: self.action.clone(),
            }),
        })
    }
}

/// A gap-free canonical stream fold. Comment bodies remain in event history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscussionSnapshot {
    pub number: DiscussionNumber,
    pub version: AggregateVersion,
    pub title: String,
    pub body: String,
    pub state: DiscussionState,
    pub opened_by: PrincipalId,
    pub last_actor: PrincipalId,
    pub comments: u64,
    pub locked: bool,
}

pub(super) fn validate_event(event: &ForgeEvent) -> Result<(), CodecRefusal> {
    if matches!(event.aggregate, AggregateId::Discussion(_))
        != matches!(event.payload, ForgeEventPayload::DiscussionChangedNative(_))
    {
        return Err(invalid_native("discussion.aggregate_kind"));
    }
    if let ForgeEventPayload::DiscussionChangedNative(change) = &event.payload {
        change.action.validate()?;
        if matches!(change.action, DiscussionAction::Open { .. })
            != (event.version == AggregateVersion::FIRST)
        {
            return Err(invalid_native("discussion.aggregate_version"));
        }
    }
    Ok(())
}

pub fn apply_event(
    previous: Option<&DiscussionSnapshot>,
    event: &ForgeEvent,
) -> Result<DiscussionSnapshot, RefusalCode> {
    validate_event(event).map_err(|_| RefusalCode::EvidenceInvalid)?;
    let (AggregateId::Discussion(number), ForgeEventPayload::DiscussionChangedNative(change)) =
        (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let Some(previous) = previous else {
        let DiscussionAction::Open { title, body } = &change.action else {
            return Err(RefusalCode::EvidenceStale);
        };
        return Ok(DiscussionSnapshot {
            number,
            version: event.version,
            title: title.clone(),
            body: body.clone(),
            state: DiscussionState::Open,
            opened_by: change.actor,
            last_actor: change.actor,
            comments: 0,
            locked: false,
        });
    };
    if previous.number != number || !previous.version.is_immediate_predecessor_of(event.version) {
        return Err(RefusalCode::EvidenceStale);
    }
    validate_title(&previous.title)
        .and_then(|()| validate_body(&previous.body))
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let mut next = previous.clone();
    match &change.action {
        DiscussionAction::Edit(edit) => {
            if let Some(title) = &edit.title {
                next.title.clone_from(title);
            }
            if let Some(body) = &edit.body {
                next.body.clone_from(body);
            }
        }
        DiscussionAction::Comment { .. } if !previous.locked => {
            next.comments = previous
                .comments
                .checked_add(1)
                .ok_or(RefusalCode::ResourceBudgetExceeded)?;
        }
        DiscussionAction::Close if previous.state == DiscussionState::Open => {
            next.state = DiscussionState::Closed
        }
        DiscussionAction::Reopen if previous.state == DiscussionState::Closed => {
            next.state = DiscussionState::Open
        }
        DiscussionAction::Lock if !previous.locked => next.locked = true,
        DiscussionAction::Unlock if previous.locked => next.locked = false,
        _ => return Err(RefusalCode::ProtectedRefTransitionDenied),
    }
    next.version = event.version;
    next.last_actor = change.actor;
    Ok(next)
}

#[cfg(test)]
mod tests;
