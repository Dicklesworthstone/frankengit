//! Canonical repository milestones. Membership belongs to issue events;
//! lifecycle and dates here never mutate issues, Git refs or access policy.
use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use crate::aggregate::{AggregateId, AggregateVersion, ExpectedVersion, MilestoneNumber};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PrincipalId, RefusalCode};

pub use super::issue::{MAX_BODY_BYTES, MAX_TITLE_BYTES};
/// Latest supported UTC timestamp: 9999-12-31 23:59:59. Dates are metadata;
/// neither the clock nor a due date authorizes an automatic transition.
pub const MAX_DUE_AT: u64 = 253_402_300_799;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MilestoneState {
    Open,
    Closed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MilestoneEdit {
    pub title: Option<String>,
    pub body: Option<String>,
    /// None preserves the date, Some(None) clears it, Some(Some(n)) replaces it.
    pub due_at: Option<Option<u64>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MilestoneAction {
    Open {
        title: String,
        body: String,
        due_at: Option<u64>,
    },
    Edit(MilestoneEdit),
    Close,
    Reopen,
}
impl MilestoneAction {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        match self {
            Self::Open {
                title,
                body,
                due_at,
            } => {
                validate_title(title)?;
                validate_body(body)?;
                validate_due_at(*due_at)
            }
            Self::Edit(edit) => {
                if edit.title.is_none() && edit.body.is_none() && edit.due_at.is_none() {
                    return Err(invalid_native("milestone.empty_edit"));
                }
                if let Some(title) = &edit.title {
                    validate_title(title)?;
                }
                if let Some(body) = &edit.body {
                    validate_body(body)?;
                }
                if let Some(due_at) = edit.due_at {
                    validate_due_at(due_at)?;
                }
                Ok(())
            }
            Self::Close | Self::Reopen => Ok(()),
        }
    }
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Edit(_) => "edit",
            Self::Close => "close",
            Self::Reopen => "reopen",
        }
    }
    fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_scalar(match self {
            Self::Open { .. } => 1u32,
            Self::Edit(_) => 2,
            Self::Close => 3,
            Self::Reopen => 4,
        });
        match self {
            Self::Open {
                title,
                body,
                due_at,
            } => {
                out.write_bytes("milestone.title", title.as_bytes())?;
                out.write_bytes("milestone.body", body.as_bytes())?;
                write_due_at(out, *due_at);
            }
            Self::Edit(edit) => {
                for (field, value) in [
                    ("milestone.title", &edit.title),
                    ("milestone.body", &edit.body),
                ] {
                    out.write_bool(value.is_some());
                    if let Some(value) = value {
                        out.write_bytes(field, value.as_bytes())?;
                    }
                }
                out.write_bool(edit.due_at.is_some());
                if let Some(due_at) = edit.due_at {
                    write_due_at(out, due_at);
                }
            }
            Self::Close | Self::Reopen => {}
        }
        Ok(())
    }
    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        let action = match input.read_scalar::<u32>("milestone.action")? {
            1 => Self::Open {
                title: text(input, "milestone.title", MAX_TITLE_BYTES)?,
                body: text(input, "milestone.body", MAX_BODY_BYTES)?,
                due_at: read_due_at(input)?,
            },
            2 => Self::Edit(MilestoneEdit {
                title: if input.read_bool("milestone.has_title")? {
                    Some(text(input, "milestone.title", MAX_TITLE_BYTES)?)
                } else {
                    None
                },
                body: if input.read_bool("milestone.has_body")? {
                    Some(text(input, "milestone.body", MAX_BODY_BYTES)?)
                } else {
                    None
                },
                due_at: if input.read_bool("milestone.has_due_at_edit")? {
                    Some(read_due_at(input)?)
                } else {
                    None
                },
            }),
            3 => Self::Close,
            4 => Self::Reopen,
            observed => {
                return Err(CodecRefusal::VariantUnknown {
                    field: "milestone.action",
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
        return Err(invalid_native("milestone.title"));
    }
    Ok(())
}
fn validate_body(body: &str) -> Result<(), CodecRefusal> {
    if body.len() > MAX_BODY_BYTES || body.contains('\0') {
        return Err(invalid_native("milestone.body"));
    }
    Ok(())
}
fn validate_due_at(due_at: Option<u64>) -> Result<(), CodecRefusal> {
    if due_at.is_some_and(|value| value > MAX_DUE_AT) {
        return Err(invalid_native("milestone.due_at"));
    }
    Ok(())
}
fn write_due_at(out: &mut Encoder, due_at: Option<u64>) {
    out.write_bool(due_at.is_some());
    if let Some(due_at) = due_at {
        out.write_scalar(due_at);
    }
}
fn read_due_at(input: &mut Decoder<'_>) -> Result<Option<u64>, CodecRefusal> {
    if input.read_bool("milestone.has_due_at")? {
        Ok(Some(input.read_scalar::<u64>("milestone.due_at")?))
    } else {
        Ok(None)
    }
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
pub struct NativeMilestoneEvent {
    pub actor: PrincipalId,
    pub action: MilestoneAction,
}
impl NativeMilestoneEvent {
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.actor.as_bytes());
        self.action.write(out)
    }
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self {
            actor: PrincipalId::from_bytes(input.read_opaque_id("milestone.actor")?),
            action: MilestoneAction::read(input)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneCommand {
    pub number: MilestoneNumber,
    pub expected_version: ExpectedVersion,
    pub action: MilestoneAction,
}
impl MilestoneCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        self.action
            .validate()
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        if matches!(self.action, MilestoneAction::Open { .. })
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
            aggregate: AggregateId::Milestone(self.number),
            version,
            payload: ForgeEventPayload::MilestoneChangedNative(NativeMilestoneEvent {
                actor,
                action: self.action.clone(),
            }),
        })
    }
}

/// A fold of one canonical stream. Issue counts are derived independently at
/// the same selected head; storing them here would create competing authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneSnapshot {
    pub number: MilestoneNumber,
    pub version: AggregateVersion,
    pub title: String,
    pub body: String,
    pub due_at: Option<u64>,
    pub state: MilestoneState,
    pub opened_by: PrincipalId,
    pub last_actor: PrincipalId,
}

pub(super) fn validate_event(event: &ForgeEvent) -> Result<(), CodecRefusal> {
    if matches!(event.aggregate, AggregateId::Milestone(_))
        != matches!(event.payload, ForgeEventPayload::MilestoneChangedNative(_))
    {
        return Err(invalid_native("milestone.aggregate_kind"));
    }
    if let ForgeEventPayload::MilestoneChangedNative(change) = &event.payload {
        change.action.validate()?;
        if matches!(change.action, MilestoneAction::Open { .. })
            != (event.version == AggregateVersion::FIRST)
        {
            return Err(invalid_native("milestone.aggregate_version"));
        }
    }
    Ok(())
}

pub fn apply_event(
    previous: Option<&MilestoneSnapshot>,
    event: &ForgeEvent,
) -> Result<MilestoneSnapshot, RefusalCode> {
    validate_event(event).map_err(|_| RefusalCode::EvidenceInvalid)?;
    let (AggregateId::Milestone(number), ForgeEventPayload::MilestoneChangedNative(change)) =
        (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let Some(previous) = previous else {
        let MilestoneAction::Open {
            title,
            body,
            due_at,
        } = &change.action
        else {
            return Err(RefusalCode::EvidenceStale);
        };
        return Ok(MilestoneSnapshot {
            number,
            version: event.version,
            title: title.clone(),
            body: body.clone(),
            due_at: *due_at,
            state: MilestoneState::Open,
            opened_by: change.actor,
            last_actor: change.actor,
        });
    };
    if previous.number != number || !previous.version.is_immediate_predecessor_of(event.version) {
        return Err(RefusalCode::EvidenceStale);
    }
    validate_title(&previous.title)
        .and_then(|()| validate_body(&previous.body))
        .and_then(|()| validate_due_at(previous.due_at))
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let mut next = previous.clone();
    match &change.action {
        MilestoneAction::Edit(edit) => {
            if let Some(title) = &edit.title {
                next.title.clone_from(title);
            }
            if let Some(body) = &edit.body {
                next.body.clone_from(body);
            }
            if let Some(due_at) = edit.due_at {
                next.due_at = due_at;
            }
        }
        MilestoneAction::Close if previous.state == MilestoneState::Open => {
            next.state = MilestoneState::Closed
        }
        MilestoneAction::Reopen if previous.state == MilestoneState::Closed => {
            next.state = MilestoneState::Open
        }
        _ => return Err(RefusalCode::ProtectedRefTransitionDenied),
    }
    next.version = event.version;
    next.last_actor = change.actor;
    Ok(next)
}

#[cfg(test)]
mod tests;
