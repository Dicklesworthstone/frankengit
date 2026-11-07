//! Canonical self-owned thread subscription, mute and read-prefix commands.
//! Defaults and inbox membership are derived; only explicit preferences persist.
use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use crate::{
    AggregateId, AggregateVersion, DiscussionNumber, ExpectedVersion, IssueNumber,
    PullRequestNumber,
};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PrincipalId, RefusalCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum NotificationTargetKind {
    Issue,
    Discussion,
    PullRequest,
}
impl NotificationTargetKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::Discussion => "discussion",
            Self::PullRequest => "pull_request",
        }
    }
}

/// The subject kind is identity material, including when numbers coincide.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum NotificationTarget {
    Issue(IssueNumber),
    Discussion(DiscussionNumber),
    PullRequest(PullRequestNumber),
}
impl NotificationTarget {
    pub const fn kind(self) -> NotificationTargetKind {
        match self {
            Self::Issue(_) => NotificationTargetKind::Issue,
            Self::Discussion(_) => NotificationTargetKind::Discussion,
            Self::PullRequest(_) => NotificationTargetKind::PullRequest,
        }
    }
    pub const fn number(self) -> u64 {
        match self {
            Self::Issue(number) => number.get(),
            Self::Discussion(number) => number.get(),
            Self::PullRequest(number) => number.get(),
        }
    }
    pub const fn aggregate(self) -> AggregateId {
        match self {
            Self::Issue(number) => AggregateId::Issue(number),
            Self::Discussion(number) => AggregateId::Discussion(number),
            Self::PullRequest(number) => AggregateId::PullRequest(number),
        }
    }
    pub const fn preference_aggregate(self, principal: PrincipalId) -> AggregateId {
        match self {
            Self::Issue(issue) => AggregateId::NotificationPreference { principal, issue },
            Self::Discussion(discussion) => AggregateId::DiscussionNotificationPreference {
                principal,
                discussion,
            },
            Self::PullRequest(pull_request) => AggregateId::PullRequestNotificationPreference {
                principal,
                pull_request,
            },
        }
    }
    pub const fn from_preference_aggregate(aggregate: AggregateId) -> Option<(PrincipalId, Self)> {
        match aggregate {
            AggregateId::NotificationPreference { principal, issue } => {
                Some((principal, Self::Issue(issue)))
            }
            AggregateId::DiscussionNotificationPreference {
                principal,
                discussion,
            } => Some((principal, Self::Discussion(discussion))),
            AggregateId::PullRequestNotificationPreference {
                principal,
                pull_request,
            } => Some((principal, Self::PullRequest(pull_request))),
            _ => None,
        }
    }
}

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
    /// Acknowledges only an explicitly observed subject prefix. None clears it.
    /// Issues/discussions use their aggregate version. PRs use the derived
    /// activity ordinal of lifecycle, conversation and review events in exact
    /// repository-record/event order, never a lifecycle or reviewer version.
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
    pub target: NotificationTarget,
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
            aggregate: self.target.preference_aggregate(actor),
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
    pub target: NotificationTarget,
    pub version: AggregateVersion,
    pub mode: NotificationMode,
    pub read_through: Option<AggregateVersion>,
}

pub(super) fn validate_event(event: &ForgeEvent) -> Result<(), CodecRefusal> {
    if NotificationTarget::from_preference_aggregate(event.aggregate).is_some()
        != matches!(
            event.payload,
            ForgeEventPayload::NotificationPreferenceChangedNative(_)
        )
    {
        return Err(invalid_native("notification.aggregate_kind"));
    }
    if let (Some((principal, _)), ForgeEventPayload::NotificationPreferenceChangedNative(change)) = (
        NotificationTarget::from_preference_aggregate(event.aggregate),
        &event.payload,
    ) {
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
    let (Some((principal, target)), ForgeEventPayload::NotificationPreferenceChangedNative(change)) = (
        NotificationTarget::from_preference_aggregate(event.aggregate),
        &event.payload,
    ) else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let mut next = match previous {
        Some(previous) => {
            if previous.principal != principal
                || previous.target != target
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
                target,
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
