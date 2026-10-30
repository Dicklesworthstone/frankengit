//! Canonical forge publication and bounded revalidation policy.
//!
//! Appending content keyed by a sealed transaction can preserve its meaning
//! across a changed issue or PR conversation frontier. Canonical sequencing,
//! current permissions, resource limits and terminal outcomes still require
//! the repository head CAS.
//! Retry eligibility never grants authority or turns the head into a CRDT.

use crate::CoordinationClass;

/// Semantic operations, distinguished before canonical events are prepared.
/// An exact-version comment and an append intent deliberately differ here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForgeOperation {
    PullRequestOpen,
    PullRequestHeadAdvance,
    PullRequestMerge,
    PullRequestClose,
    NativeMerge,
    NativePullRequestChange,
    ReviewDecision,
    IssueOpen,
    IssueEdit,
    IssueClose,
    IssueReopen,
    IssueExactComment,
    IssueAppendComment,
    IssueAssign,
    IssueUnassign,
    ReviewProtection,
    MergeQueueChange,
    WorkflowCheck,
    PullRequestComment,
    PullRequestAppendComment,
    Unknown,
}

/// Which parts of a request may be planned again after observing a new basis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForgeReplanPolicy {
    /// The caller's original predecessor and other preconditions remain exact.
    PreservePreconditions,
    /// Re-evaluate current state and stamp an append's new canonical position.
    /// The subject, actor, content, source anchor, profile and transaction
    /// identity remain fixed.
    RevalidateAppend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgeAdmissionRule {
    pub coordination: CoordinationClass,
    pub replan: ForgeReplanPolicy,
}

/// The single semantic table for canonical forge replan eligibility.
///
/// Only explicit issue and PR comment append profiles have version-independent
/// conversation intents. A PR source anchor retains its exact metadata basis.
/// Legacy comments, replacement sets, edits, reviews and unknown operations
/// preserve their submitted preconditions. Every row retains head-CAS authority,
/// including append comments (CALM-013's sequencing/permission boundary).
#[must_use]
pub const fn forge_admission_rule(operation: ForgeOperation) -> ForgeAdmissionRule {
    let replan = match operation {
        ForgeOperation::IssueAppendComment | ForgeOperation::PullRequestAppendComment => {
            ForgeReplanPolicy::RevalidateAppend
        }
        ForgeOperation::PullRequestOpen
        | ForgeOperation::PullRequestHeadAdvance
        | ForgeOperation::PullRequestMerge
        | ForgeOperation::PullRequestClose
        | ForgeOperation::NativeMerge
        | ForgeOperation::NativePullRequestChange
        | ForgeOperation::ReviewDecision
        | ForgeOperation::IssueOpen
        | ForgeOperation::IssueEdit
        | ForgeOperation::IssueClose
        | ForgeOperation::IssueReopen
        | ForgeOperation::IssueExactComment
        | ForgeOperation::IssueAssign
        | ForgeOperation::IssueUnassign
        | ForgeOperation::ReviewProtection
        | ForgeOperation::MergeQueueChange
        | ForgeOperation::WorkflowCheck
        | ForgeOperation::PullRequestComment
        | ForgeOperation::Unknown => ForgeReplanPolicy::PreservePreconditions,
    };
    ForgeAdmissionRule {
        coordination: CoordinationClass::HeadCasRequired,
        replan,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_strict_and_unknown_operation_preserves_its_original_preconditions() {
        for operation in [
            ForgeOperation::PullRequestOpen,
            ForgeOperation::PullRequestHeadAdvance,
            ForgeOperation::PullRequestMerge,
            ForgeOperation::PullRequestClose,
            ForgeOperation::NativeMerge,
            ForgeOperation::NativePullRequestChange,
            ForgeOperation::ReviewDecision,
            ForgeOperation::IssueOpen,
            ForgeOperation::IssueEdit,
            ForgeOperation::IssueClose,
            ForgeOperation::IssueReopen,
            ForgeOperation::IssueExactComment,
            ForgeOperation::IssueAssign,
            ForgeOperation::IssueUnassign,
            ForgeOperation::ReviewProtection,
            ForgeOperation::MergeQueueChange,
            ForgeOperation::WorkflowCheck,
            ForgeOperation::PullRequestComment,
            ForgeOperation::Unknown,
        ] {
            let rule = forge_admission_rule(operation);
            assert_eq!(
                rule.replan,
                ForgeReplanPolicy::PreservePreconditions,
                "{operation:?}"
            );
            assert_eq!(rule.coordination, CoordinationClass::HeadCasRequired);
        }
    }

    #[test]
    fn additive_intent_may_replan_but_never_publish_without_authority() {
        for operation in [
            ForgeOperation::IssueAppendComment,
            ForgeOperation::PullRequestAppendComment,
        ] {
            let rule = forge_admission_rule(operation);
            assert_eq!(rule.replan, ForgeReplanPolicy::RevalidateAppend);
            assert_eq!(rule.coordination, CoordinationClass::HeadCasRequired);
            assert!(!rule.coordination.is_coordination_free());
        }
    }
}
