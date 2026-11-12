//! Pure matching of authority-selected observations in reverse publication
//! order. The history reader, never this matcher or a caller, supplies authority.

use fgit_forge::ForgeEventPayload;
use fgit_forge::event::protection::{RequiredCandidateWorkflowCheck, RequiredWorkflowCheck};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
use fgit_types::RefusalCode;

#[derive(Clone)]
pub(super) struct ExactChecks<'a> {
    subject: ReviewSubject,
    candidate: CandidateBinding,
    branch_unresolved: Vec<&'a RequiredWorkflowCheck>,
    candidate_unresolved: Vec<&'a RequiredCandidateWorkflowCheck>,
}

impl<'a> ExactChecks<'a> {
    pub(super) fn new(
        subject: ReviewSubject,
        candidate: CandidateBinding,
        ordinary: &'a [RequiredWorkflowCheck],
        required: &'a [RequiredCandidateWorkflowCheck],
    ) -> Self {
        Self {
            subject,
            candidate,
            branch_unresolved: ordinary.iter().collect(),
            candidate_unresolved: required.iter().collect(),
        }
    }

    /// A non-success LAST matching record refuses immediately. After a selector
    /// is resolved, older records cannot change it while other selectors resolve.
    pub(super) fn observe(&mut self, payload: &ForgeEventPayload) -> Result<bool, RefusalCode> {
        match payload {
            ForgeEventPayload::WorkflowCheckObservedNative(observation) => {
                let check = &observation.record;
                if check.source_commit == self.candidate.commit
                    && let Some(index) = self.branch_unresolved.iter().position(|requirement| {
                        requirement.source_ref == check.source_ref
                            && requirement.publisher == observation.actor
                            && requirement.graph_root == check.graph_root
                            && requirement.job == check.job
                    })
                {
                    if check.conclusion != WorkflowCheckConclusion::Success {
                        return Err(RefusalCode::ProtectedRefTransitionDenied);
                    }
                    self.branch_unresolved.remove(index);
                }
            }
            ForgeEventPayload::CandidateWorkflowCheckObservedNative(observation) => {
                let record = &observation.record;
                if record.subject == self.subject
                    && record.candidate == self.candidate
                    && let Some(index) = self.candidate_unresolved.iter().position(|requirement| {
                        requirement.publisher == observation.actor
                            && requirement.graph_root == record.check.graph_root
                            && requirement.job == record.check.job
                    })
                {
                    if record.check.conclusion != WorkflowCheckConclusion::Success {
                        return Err(RefusalCode::ProtectedRefTransitionDenied);
                    }
                    self.candidate_unresolved.remove(index);
                }
            }
            _ => {}
        }
        Ok(self.branch_unresolved.is_empty() && self.candidate_unresolved.is_empty())
    }
}

#[cfg(test)]
mod tests;
