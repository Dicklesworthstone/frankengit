//! Versioned issue commands and canonical events. Text is data, never authority.
//! Events retain explicit changes, so a retry never depends on a latest-state
//! lookup. Admission evaluates the exact expected predecessor before publication.
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PrincipalId, RefusalCode};
use crate::aggregate::{AggregateId, AggregateVersion, ExpectedVersion, IssueNumber};
use super::{ForgeEvent, ForgeEventPayload, invalid_native};

pub const MAX_TITLE_BYTES: usize = 256;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_LABELS: usize = 32;
pub const MAX_LABEL_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueState { Open, Closed }

/// A replacement applies only to the explicitly supplied fields. Labels are a
/// bounded canonical set; None preserves them and Some(empty) clears them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IssueEdit {
    pub title: Option<String>,
    pub body: Option<String>,
    pub labels: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssueAction {
    Open { title: String, body: String, labels: Vec<String> },
    Edit(IssueEdit),
    Close,
    Reopen,
    Comment { body: String },
}
impl IssueAction {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        match self {
            Self::Open { title, body, labels } => {
                validate_title(title)?; validate_body(body)?; validate_labels(labels)
            }
            Self::Edit(edit) => {
                if edit.title.is_none() && edit.body.is_none() && edit.labels.is_none() {
                    return Err(invalid_native("issue.empty_edit"));
                }
                if let Some(title) = &edit.title { validate_title(title)?; }
                if let Some(body) = &edit.body { validate_body(body)?; }
                if let Some(labels) = &edit.labels { validate_labels(labels)?; }
                Ok(())
            }
            Self::Comment { body } => {
                validate_body(body)?;
                if body.trim().is_empty() { return Err(invalid_native("issue.empty_comment")); }
                Ok(())
            }
            Self::Close | Self::Reopen => Ok(()),
        }
    }
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self { Self::Open { .. } => "open", Self::Edit(_) => "edit",
            Self::Close => "close", Self::Reopen => "reopen", Self::Comment { .. } => "comment" }
    }
    fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_scalar(match self { Self::Open { .. } => 1u32, Self::Edit(_) => 2,
            Self::Close => 3, Self::Reopen => 4, Self::Comment { .. } => 5 });
        match self {
            Self::Open { title, body, labels } => {
                out.write_bytes("issue.title", title.as_bytes())?;
                out.write_bytes("issue.body", body.as_bytes())?;
                write_labels(out, labels)?;
            }
            Self::Edit(edit) => {
                for (field, value) in [("issue.title", &edit.title), ("issue.body", &edit.body)] {
                    out.write_bool(value.is_some());
                    if let Some(text) = value { out.write_bytes(field, text.as_bytes())?; }
                }
                out.write_bool(edit.labels.is_some());
                if let Some(labels) = &edit.labels { write_labels(out, labels)?; }
            }
            Self::Comment { body } => out.write_bytes("issue.comment", body.as_bytes())?,
            Self::Close | Self::Reopen => {}
        }
        Ok(())
    }
    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        let action = match input.read_scalar::<u32>("issue.action")? {
            1 => Self::Open { title: text(input, "issue.title", MAX_TITLE_BYTES)?,
                body: text(input, "issue.body", MAX_BODY_BYTES)?, labels: read_labels(input)? },
            2 => Self::Edit(IssueEdit {
                title: if input.read_bool("issue.has_title")? { Some(text(input, "issue.title", MAX_TITLE_BYTES)?) } else { None },
                body: if input.read_bool("issue.has_body")? { Some(text(input, "issue.body", MAX_BODY_BYTES)?) } else { None },
                labels: if input.read_bool("issue.has_labels")? { Some(read_labels(input)?) } else { None },
            }),
            3 => Self::Close,
            4 => Self::Reopen,
            5 => Self::Comment { body: text(input, "issue.comment", MAX_BODY_BYTES)? },
            observed => return Err(CodecRefusal::VariantUnknown { field: "issue.action", observed, offset }),
        };
        action.validate()?;
        Ok(action)
    }
}
fn validate_title(title: &str) -> Result<(), CodecRefusal> {
    if title.trim().is_empty() || title.len() > MAX_TITLE_BYTES || title.chars().any(char::is_control) {
        return Err(invalid_native("issue.title"));
    }
    Ok(())
}
fn validate_body(body: &str) -> Result<(), CodecRefusal> {
    if body.len() > MAX_BODY_BYTES || body.contains('\0') { return Err(invalid_native("issue.body")); }
    Ok(())
}
fn validate_labels(labels: &[String]) -> Result<(), CodecRefusal> {
    if labels.len() > MAX_LABELS || labels.windows(2).any(|pair| pair[0] >= pair[1])
        || labels.iter().any(|label| label.trim().is_empty() || label.len() > MAX_LABEL_BYTES
            || label.chars().any(char::is_control))
    { return Err(invalid_native("issue.labels")); }
    Ok(())
}
fn text(input: &mut Decoder<'_>, field: &'static str, limit: usize) -> Result<String, CodecRefusal> {
    let bytes = input.read_bytes(field)?;
    if bytes.len() > limit { return Err(invalid_native(field)); }
    let value = std::str::from_utf8(bytes).map_err(|_| invalid_native(field))?;
    Ok(value.to_owned())
}
fn write_labels(out: &mut Encoder, labels: &[String]) -> Result<(), CodecRefusal> {
    validate_labels(labels)?;
    out.write_sequence("issue.labels", labels, |out, label| out.write_bytes("issue.label", label.as_bytes()))
}
fn read_labels(input: &mut Decoder<'_>) -> Result<Vec<String>, CodecRefusal> {
    // The codec's sequence bound is checked before allocation; the issue bound
    // is applied as each element is read, before retaining another label.
    let mut count = 0usize;
    let labels = input.read_sequence("issue.labels", |input| {
        count = count.checked_add(1).ok_or_else(|| invalid_native("issue.labels"))?;
        if count > MAX_LABELS { return Err(invalid_native("issue.labels")); }
        text(input, "issue.label", MAX_LABEL_BYTES)
    })?;
    validate_labels(&labels)?;
    Ok(labels)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeIssueEvent { pub actor: PrincipalId, pub action: IssueAction }
impl NativeIssueEvent {
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.actor.as_bytes());
        self.action.write(out)
    }
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self { actor: PrincipalId::from_bytes(input.read_opaque_id("issue.actor")?),
            action: IssueAction::read(input)? })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueCommand {
    pub number: IssueNumber,
    pub expected_version: ExpectedVersion,
    pub action: IssueAction,
}
impl IssueCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        self.action.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        if matches!(self.action, IssueAction::Open { .. }) != (self.expected_version == ExpectedVersion::NewStream) {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(version) => version.next().map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        Ok(ForgeEvent { aggregate: AggregateId::Issue(self.number), version,
            payload: ForgeEventPayload::IssueChangedNative(NativeIssueEvent { actor, action: self.action.clone() }) })
    }
}

/// Rebuildable state, not storage or authority. Comments remain in the exact
/// versioned event timeline; this small projection never duplicates their text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueSnapshot {
    pub number: IssueNumber,
    pub version: AggregateVersion,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub state: IssueState,
    pub opened_by: PrincipalId,
    pub last_actor: PrincipalId,
    pub comments: u64,
}

/// Replay one event against its exact predecessor. No latest-version refresh,
/// implicit reopening, duplicate creation or lost-update overwrite is possible.
pub fn apply_event(previous: Option<&IssueSnapshot>, event: &ForgeEvent) -> Result<IssueSnapshot, RefusalCode> {
    let (AggregateId::Issue(number), ForgeEventPayload::IssueChangedNative(change)) = (event.aggregate, &event.payload) else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    change.action.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
    let Some(previous) = previous else {
        let IssueAction::Open { title, body, labels } = &change.action else { return Err(RefusalCode::EvidenceStale); };
        if event.version != AggregateVersion::FIRST { return Err(RefusalCode::EvidenceStale); }
        return Ok(IssueSnapshot { number, version: event.version, title: title.clone(), body: body.clone(),
            labels: labels.clone(), state: IssueState::Open, opened_by: change.actor,
            last_actor: change.actor, comments: 0 });
    };
    if previous.number != number || !previous.version.is_immediate_predecessor_of(event.version) {
        return Err(RefusalCode::EvidenceStale);
    }
    let mut next = previous.clone();
    match &change.action {
        IssueAction::Open { .. } => return Err(RefusalCode::ProtectedRefTransitionDenied),
        IssueAction::Edit(edit) => {
            if let Some(title) = &edit.title { next.title.clone_from(title); }
            if let Some(body) = &edit.body { next.body.clone_from(body); }
            if let Some(labels) = &edit.labels { next.labels.clone_from(labels); }
        }
        IssueAction::Close if previous.state == IssueState::Open => next.state = IssueState::Closed,
        IssueAction::Reopen if previous.state == IssueState::Closed => next.state = IssueState::Open,
        IssueAction::Close | IssueAction::Reopen => return Err(RefusalCode::ProtectedRefTransitionDenied),
        IssueAction::Comment { .. } => next.comments = next.comments.checked_add(1).ok_or(RefusalCode::ResourceBudgetExceeded)?,
    }
    next.version = event.version;
    next.last_actor = change.actor;
    Ok(next)
}

#[cfg(test)]
mod tests;
