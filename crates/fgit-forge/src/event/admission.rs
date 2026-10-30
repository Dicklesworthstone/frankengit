//! Map a submitted forge command profile to its canonical admission rule.
//! Classification controls planning only; seal verification and the current
//! lifecycle, authorization and resource predicates still decide admission.

use super::{ForgeEvent, ForgeEventPayload, issue::IssueAction};
use fgit_calm::forge_admission_rule;
pub use fgit_calm::{ForgeAdmissionRule, ForgeOperation, ForgeReplanPolicy};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForgeCommandProfile {
    ExactVersion,
    AppendIssueCommentV1,
    AppendPullRequestCommentV1,
    /// Unrecognized semantics never gain append eligibility.
    Unknown,
}

#[must_use]
pub const fn classify_event(
    event: &ForgeEvent,
    profile: ForgeCommandProfile,
) -> ForgeAdmissionRule {
    let operation = match profile {
        ForgeCommandProfile::AppendIssueCommentV1 => match &event.payload {
            ForgeEventPayload::IssueChangedNative(change)
                if matches!(change.action, IssueAction::Comment { .. }) =>
            {
                ForgeOperation::IssueAppendComment
            }
            _ => ForgeOperation::Unknown,
        },
        ForgeCommandProfile::AppendPullRequestCommentV1 => {
            match (&event.aggregate, &event.payload) {
                (
                    crate::AggregateId::PullRequestConversation(_),
                    ForgeEventPayload::PullRequestCommentedNative(_),
                ) => ForgeOperation::PullRequestAppendComment,
                _ => ForgeOperation::Unknown,
            }
        }
        ForgeCommandProfile::Unknown => ForgeOperation::Unknown,
        ForgeCommandProfile::ExactVersion => match &event.payload {
            ForgeEventPayload::PullRequestOpened { .. } => ForgeOperation::PullRequestOpen,
            ForgeEventPayload::PullRequestHeadAdvanced { .. } => {
                ForgeOperation::PullRequestHeadAdvance
            }
            ForgeEventPayload::MergeCommitted { .. } => ForgeOperation::PullRequestMerge,
            ForgeEventPayload::PullRequestClosed { .. } => ForgeOperation::PullRequestClose,
            ForgeEventPayload::MergeCommittedNative(_) => ForgeOperation::NativeMerge,
            ForgeEventPayload::PullRequestChangedNative(_) => {
                ForgeOperation::NativePullRequestChange
            }
            ForgeEventPayload::PullRequestReviewedNative(_) => ForgeOperation::ReviewDecision,
            ForgeEventPayload::IssueChangedNative(change) => match &change.action {
                IssueAction::Open { .. } => ForgeOperation::IssueOpen,
                IssueAction::Edit(_) => ForgeOperation::IssueEdit,
                IssueAction::Close => ForgeOperation::IssueClose,
                IssueAction::Reopen => ForgeOperation::IssueReopen,
                IssueAction::Comment { .. } => ForgeOperation::IssueExactComment,
                IssueAction::Assign { .. } => ForgeOperation::IssueAssign,
                IssueAction::Unassign { .. } => ForgeOperation::IssueUnassign,
            },
            ForgeEventPayload::ReviewProtectionChanged(_) => ForgeOperation::ReviewProtection,
            ForgeEventPayload::MergeQueueChangedNative(_) => ForgeOperation::MergeQueueChange,
            ForgeEventPayload::WorkflowCheckObservedNative(_) => ForgeOperation::WorkflowCheck,
            ForgeEventPayload::PullRequestCommentedNative(_) => ForgeOperation::PullRequestComment,
        },
    };
    forge_admission_rule(operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::issue::{IssueCommand, IssueEdit};
    use crate::{AggregateVersion, ExpectedVersion, IssueNumber};
    use fgit_types::PrincipalId;

    #[test]
    fn only_an_explicit_comment_profile_can_replan_a_changed_event_position() {
        for action in [
            IssueAction::Open {
                title: "issue".into(),
                body: String::new(),
                labels: vec![],
            },
            IssueAction::Edit(IssueEdit {
                title: Some("new title".into()),
                ..Default::default()
            }),
            IssueAction::Close,
            IssueAction::Reopen,
            IssueAction::Comment {
                body: "append text".into(),
            },
            IssueAction::Assign {
                assignees: vec![PrincipalId::from_bytes([2; 16])],
            },
            IssueAction::Unassign {
                assignees: vec![PrincipalId::from_bytes([2; 16])],
            },
        ] {
            let is_comment = matches!(action, IssueAction::Comment { .. });
            let expected_version = if matches!(action, IssueAction::Open { .. }) {
                ExpectedVersion::NewStream
            } else {
                ExpectedVersion::Exactly(AggregateVersion::FIRST)
            };
            let event = IssueCommand {
                number: IssueNumber::try_new(1).unwrap(),
                expected_version,
                action,
            }
            .proposed_event(PrincipalId::from_bytes([1; 16]))
            .unwrap();
            for profile in [
                ForgeCommandProfile::ExactVersion,
                ForgeCommandProfile::Unknown,
                ForgeCommandProfile::AppendPullRequestCommentV1,
            ] {
                assert_eq!(
                    classify_event(&event, profile).replan,
                    ForgeReplanPolicy::PreservePreconditions
                );
            }
            assert_eq!(
                classify_event(&event, ForgeCommandProfile::AppendIssueCommentV1).replan,
                if is_comment {
                    ForgeReplanPolicy::RevalidateAppend
                } else {
                    ForgeReplanPolicy::PreservePreconditions
                }
            );
        }
    }

    #[test]
    fn pr_append_eligibility_requires_its_own_profile_and_conversation_aggregate() {
        use crate::event::pull_request_comment::PullRequestAppendCommentCommand;
        use crate::{AggregateId, PullRequestNumber};
        use fgit_calm::CoordinationClass;

        let event = PullRequestAppendCommentCommand {
            number: PullRequestNumber::FIRST,
            body: "Independent contribution".into(),
            anchor: None,
        }
        .commitment_event(PrincipalId::from_bytes([7; 16]))
        .unwrap();
        let rule = classify_event(&event, ForgeCommandProfile::AppendPullRequestCommentV1);
        assert_eq!(rule.replan, ForgeReplanPolicy::RevalidateAppend);
        assert_eq!(rule.coordination, CoordinationClass::HeadCasRequired);
        for profile in [
            ForgeCommandProfile::ExactVersion,
            ForgeCommandProfile::Unknown,
            ForgeCommandProfile::AppendIssueCommentV1,
        ] {
            assert_eq!(
                classify_event(&event, profile).replan,
                ForgeReplanPolicy::PreservePreconditions
            );
        }
        for aggregate in [
            AggregateId::PullRequest(PullRequestNumber::FIRST),
            AggregateId::Issue(IssueNumber::FIRST),
            AggregateId::ReviewProtection,
        ] {
            let mut wrong = event.clone();
            wrong.aggregate = aggregate;
            assert_eq!(
                classify_event(&wrong, ForgeCommandProfile::AppendPullRequestCommentV1).replan,
                ForgeReplanPolicy::PreservePreconditions
            );
        }
    }
}
