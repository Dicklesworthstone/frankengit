//! Kind-preserving subject state for notification participation and rendering.
use fgit_forge::event::discussion::{DiscussionAction, DiscussionSnapshot, DiscussionState};
use fgit_forge::event::issue::{IssueAction, IssueSnapshot, IssueState};
use fgit_forge::event::notification::NotificationTarget;
use fgit_forge::{AggregateVersion, ForgeEvent, ForgeEventPayload};
use fgit_types::{PrincipalId, RefusalCode};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotificationSubjectSnapshot {
    Issue(IssueSnapshot),
    Discussion(DiscussionSnapshot),
}

impl NotificationSubjectSnapshot {
    pub fn target(&self) -> NotificationTarget {
        match self {
            Self::Issue(issue) => NotificationTarget::Issue(issue.number),
            Self::Discussion(discussion) => NotificationTarget::Discussion(discussion.number),
        }
    }
    pub fn version(&self) -> AggregateVersion {
        match self {
            Self::Issue(issue) => issue.version,
            Self::Discussion(discussion) => discussion.version,
        }
    }
    pub fn title(&self) -> &str {
        match self {
            Self::Issue(issue) => &issue.title,
            Self::Discussion(discussion) => &discussion.title,
        }
    }
    pub fn is_closed(&self) -> bool {
        match self {
            Self::Issue(issue) => issue.state == IssueState::Closed,
            Self::Discussion(discussion) => discussion.state == DiscussionState::Closed,
        }
    }
    pub fn opened_by(&self) -> PrincipalId {
        match self {
            Self::Issue(issue) => issue.opened_by,
            Self::Discussion(discussion) => discussion.opened_by,
        }
    }
    pub fn assigned_to(&self, principal: PrincipalId) -> bool {
        match self {
            Self::Issue(issue) => issue.assignees.contains(&principal),
            Self::Discussion(_) => false,
        }
    }

    pub(super) fn apply_event(
        previous: Option<&Self>,
        event: &ForgeEvent,
    ) -> Result<(Self, PrincipalId, bool), RefusalCode> {
        match &event.payload {
            ForgeEventPayload::IssueChangedNative(change) => {
                let previous = match previous {
                    None => None,
                    Some(Self::Issue(issue)) => Some(issue),
                    Some(Self::Discussion(_)) => return Err(RefusalCode::EvidenceInvalid),
                };
                let issue = fgit_forge::event::issue::apply_event(previous, event)?;
                Ok((
                    Self::Issue(issue),
                    change.actor,
                    matches!(
                        change.action,
                        IssueAction::Open { .. } | IssueAction::Comment { .. }
                    ),
                ))
            }
            ForgeEventPayload::DiscussionChangedNative(change) => {
                let previous = match previous {
                    None => None,
                    Some(Self::Discussion(discussion)) => Some(discussion),
                    Some(Self::Issue(_)) => return Err(RefusalCode::EvidenceInvalid),
                };
                let discussion = fgit_forge::event::discussion::apply_event(previous, event)?;
                Ok((
                    Self::Discussion(discussion),
                    change.actor,
                    matches!(
                        change.action,
                        DiscussionAction::Open { .. } | DiscussionAction::Comment { .. }
                    ),
                ))
            }
            _ => Err(RefusalCode::EvidenceInvalid),
        }
    }
}
