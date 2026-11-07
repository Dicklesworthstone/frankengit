//! Kind-preserving subject state for notification participation and rendering.
use fgit_forge::event::discussion::{DiscussionAction, DiscussionSnapshot, DiscussionState};
use fgit_forge::event::issue::{IssueAction, IssueSnapshot, IssueState};
use fgit_forge::event::notification::NotificationTarget;
use fgit_forge::event::pull_request::{NativePullRequestEvent, PullRequestAction, PullRequestData};
use fgit_forge::{AggregateVersion, ForgeEvent, ForgeEventPayload};
use fgit_types::{PrincipalId, RefName, RefusalCode};

/// One native PR's state and append-stable activity prefix. The activity
/// counter is derived from canonical RCR/event order, not a writable stream
/// and not the independent lifecycle, conversation or reviewer version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestNotificationSnapshot {
    pub number: fgit_forge::PullRequestNumber,
    pub activity_version: AggregateVersion,
    pub lifecycle_version: AggregateVersion,
    pub data: PullRequestData,
    pub opened_by: PrincipalId,
    pub state: PullRequestNotificationState,
    pub(super) last_action: PullRequestAction,
    pub(super) last_metadata_actor: PrincipalId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PullRequestNotificationState {
    Open,
    Closed,
    Merged,
}

impl PullRequestNotificationSnapshot {
    pub(super) fn lifecycle_event(&self) -> ForgeEvent {
        ForgeEvent {
            aggregate: fgit_forge::AggregateId::PullRequest(self.number),
            version: self.lifecycle_version,
            payload: ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent {
                action: self.last_action,
                actor: self.last_metadata_actor,
                data: self.data.clone(),
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotificationSubjectSnapshot {
    Issue(IssueSnapshot),
    Discussion(DiscussionSnapshot),
    PullRequest(PullRequestNotificationSnapshot),
}

impl NotificationSubjectSnapshot {
    pub fn target(&self) -> NotificationTarget {
        match self {
            Self::Issue(issue) => NotificationTarget::Issue(issue.number),
            Self::Discussion(discussion) => NotificationTarget::Discussion(discussion.number),
            Self::PullRequest(pull) => NotificationTarget::PullRequest(pull.number),
        }
    }
    pub fn version(&self) -> AggregateVersion {
        match self {
            Self::Issue(issue) => issue.version,
            Self::Discussion(discussion) => discussion.version,
            Self::PullRequest(pull) => pull.activity_version,
        }
    }
    pub fn title(&self) -> &str {
        match self {
            Self::Issue(issue) => &issue.title,
            Self::Discussion(discussion) => &discussion.title,
            Self::PullRequest(pull) => &pull.data.title,
        }
    }
    pub fn is_closed(&self) -> bool {
        match self {
            Self::Issue(issue) => issue.state == IssueState::Closed,
            Self::Discussion(discussion) => discussion.state == DiscussionState::Closed,
            Self::PullRequest(pull) => pull.state != PullRequestNotificationState::Open,
        }
    }
    pub fn is_merged(&self) -> bool {
        matches!(
            self,
            Self::PullRequest(pull) if pull.state == PullRequestNotificationState::Merged
        )
    }
    /// Current disclosure policy must permit BOTH refs before a PR thread is
    /// returned or its preferences are mutated. These names are never grants.
    pub fn pull_request_refs(&self) -> Option<(&RefName, &RefName)> {
        match self {
            Self::PullRequest(pull) => Some((&pull.data.source_ref, &pull.data.target_ref)),
            _ => None,
        }
    }
    pub fn opened_by(&self) -> PrincipalId {
        match self {
            Self::Issue(issue) => issue.opened_by,
            Self::Discussion(discussion) => discussion.opened_by,
            Self::PullRequest(pull) => pull.opened_by,
        }
    }
    pub fn assigned_to(&self, principal: PrincipalId) -> bool {
        match self {
            Self::Issue(issue) => issue.assignees.contains(&principal),
            Self::Discussion(_) => false,
            Self::PullRequest(_) => false,
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
                    Some(Self::Discussion(_) | Self::PullRequest(_)) => {
                        return Err(RefusalCode::EvidenceInvalid);
                    }
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
                    Some(Self::Issue(_) | Self::PullRequest(_)) => {
                        return Err(RefusalCode::EvidenceInvalid);
                    }
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
