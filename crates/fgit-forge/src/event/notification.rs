//! Canonical self-owned issue subscription, mute and read-prefix commands.
//! Defaults and inbox membership are derived; only explicit preferences persist.
use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use crate::{AggregateId, AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PrincipalId, RefusalCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationMode {
    Participating,
    Subscribed,
    Muted,
}
impl NotificationMode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Participating => "participating",
            Self::Subscribed => "subscribed",
            Self::Muted => "muted",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationAction {
    SetMode(NotificationMode),
    /// Acknowledges only an explicitly observed issue prefix. None clears it.
    SetReadThrough(Option<AggregateVersion>),
}
impl NotificationAction {
    pub const fn name(self) -> &'static str {
        match self {
            Self::SetMode(_) => "set_mode",
            Self::SetReadThrough(_) => "set_read_through",
        }
    }
    fn write(self, out: &mut Encoder) {
        match self {
            Self::SetMode(mode) => {
                out.write_scalar(1u32);
                out.write_scalar(match mode {
                    NotificationMode::Participating => 1u32,
                    NotificationMode::Subscribed => 2,
                    NotificationMode::Muted => 3,
                });
            }
            Self::SetReadThrough(through) => {
                out.write_scalar(2u32);
                out.write_bool(through.is_some());
                if let Some(through) = through {
                    out.write_scalar(through.get());
                }
            }
        }
    }
    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        match input.read_scalar::<u32>("notification.action")? {
            1 => {
                let offset = input.offset();
                Ok(Self::SetMode(
                    match input.read_scalar::<u32>("notification.mode")? {
                        1 => NotificationMode::Participating,
                        2 => NotificationMode::Subscribed,
                        3 => NotificationMode::Muted,
                        observed => {
                            return Err(CodecRefusal::VariantUnknown {
                                field: "notification.mode",
                                observed,
                                offset,
                            });
                        }
                    },
                ))
            }
            2 => Ok(Self::SetReadThrough(
                if input.read_bool("notification.has_read_through")? {
                    Some(
                        AggregateVersion::try_new(
                            input.read_scalar::<u64>("notification.read_through")?,
                        )
                        .ok_or_else(|| invalid_native("notification.read_through"))?,
                    )
                } else {
                    None
                },
            )),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "notification.action",
                observed,
                offset,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeNotificationEvent {
    pub actor: PrincipalId,
    pub action: NotificationAction,
}
impl NativeNotificationEvent {
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.actor.as_bytes());
        self.action.write(out);
        Ok(())
    }
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self {
            actor: PrincipalId::from_bytes(input.read_opaque_id("notification.actor")?),
            action: NotificationAction::read(input)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationCommand {
    pub number: IssueNumber,
    pub expected_version: ExpectedVersion,
    pub action: NotificationAction,
}
impl NotificationCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(before) => before
                .next()
                .map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        Ok(ForgeEvent {
            aggregate: AggregateId::NotificationPreference {
                principal: actor,
                issue: self.number,
            },
            version,
            payload: ForgeEventPayload::NotificationPreferenceChangedNative(
                NativeNotificationEvent {
                    actor,
                    action: self.action,
                },
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationPreferenceSnapshot {
    pub principal: PrincipalId,
    pub number: IssueNumber,
    pub version: AggregateVersion,
    pub mode: NotificationMode,
    pub read_through: Option<AggregateVersion>,
}

pub(super) fn validate_event(event: &ForgeEvent) -> Result<(), CodecRefusal> {
    if matches!(event.aggregate, AggregateId::NotificationPreference { .. })
        != matches!(
            event.payload,
            ForgeEventPayload::NotificationPreferenceChangedNative(_)
        )
    {
        return Err(invalid_native("notification.aggregate_kind"));
    }
    if let (
        AggregateId::NotificationPreference { principal, .. },
        ForgeEventPayload::NotificationPreferenceChangedNative(change),
    ) = (event.aggregate, &event.payload)
    {
        if principal != change.actor {
            return Err(invalid_native("notification.actor"));
        }
    }
    Ok(())
}

pub fn apply_event(
    previous: Option<&NotificationPreferenceSnapshot>,
    event: &ForgeEvent,
) -> Result<NotificationPreferenceSnapshot, RefusalCode> {
    validate_event(event).map_err(|_| RefusalCode::EvidenceInvalid)?;
    let (
        AggregateId::NotificationPreference { principal, issue },
        ForgeEventPayload::NotificationPreferenceChangedNative(change),
    ) = (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let mut next = match previous {
        Some(previous) => {
            if previous.principal != principal
                || previous.number != issue
                || !previous.version.is_immediate_predecessor_of(event.version)
            {
                return Err(RefusalCode::EvidenceStale);
            }
            previous.clone()
        }
        None => {
            if event.version != AggregateVersion::FIRST {
                return Err(RefusalCode::EvidenceStale);
            }
            NotificationPreferenceSnapshot {
                principal,
                number: issue,
                version: event.version,
                mode: NotificationMode::Participating,
                read_through: None,
            }
        }
    };
    match change.action {
        NotificationAction::SetMode(mode) => next.mode = mode,
        NotificationAction::SetReadThrough(through) => next.read_through = through,
    }
    next.version = event.version;
    Ok(next)
}

#[cfg(test)]
mod tests;
