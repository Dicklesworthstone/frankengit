//! Exact candidate observations retain the canonical PR subject independently
//! of execution. The target branch is an anchor, never a claim that the branch
//! currently names the candidate. Admission verifies the original bundle and
//! completed job before this immutable statement can become canonical.

use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{GitHashAlgorithm, PolicyEpoch, PrincipalId, RefName, RefusalCode};

use super::{WorkflowCheckId, WorkflowCheckRecord};
use crate::event::review::{CandidateBinding, ReviewSubject};
use crate::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload, PullRequestNumber};

pub const CANDIDATE_WORKFLOW_CHECK_PROFILE: &str = "exact-unpublished-candidate-v1";

/// Immutable original PR coordinates, actual candidate and exact bundle bytes
/// associated with one completed workflow job. No current head, publication
/// time or mutable CI-ref lease enters this record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateWorkflowCheckRecord {
    pub subject: ReviewSubject,
    pub candidate: CandidateBinding,
    pub bundle_sha256: [u8; 32],
    pub check: WorkflowCheckRecord,
}

impl CandidateWorkflowCheckRecord {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        self.subject.validate()?;
        self.candidate.validate(&self.subject)?;
        self.check.validate()?;
        if self.check.source_ref != self.subject.target_ref
            || self.check.source_commit != self.candidate.commit
        {
            return Err(super::super::invalid_native(
                "candidate_workflow_check.coordinates",
            ));
        }
        Ok(())
    }

    /// Authentication supplies the reporter. Reuse the existing full execution
    /// identity so changing a job's evidence profile cannot mint a second result.
    pub fn proposed_event(
        &self,
        actor: PrincipalId,
        format: GitHashAlgorithm,
    ) -> Result<ForgeEvent, RefusalCode> {
        self.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        if self.candidate.commit.algorithm() != format {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let change = NativeCandidateWorkflowCheck {
            actor,
            record: self.clone(),
        };
        Ok(ForgeEvent {
            aggregate: AggregateId::WorkflowCheck(change.id()),
            version: AggregateVersion::FIRST,
            payload: ForgeEventPayload::CandidateWorkflowCheckObservedNative(change),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCandidateWorkflowCheck {
    pub actor: PrincipalId,
    pub record: CandidateWorkflowCheckRecord,
}

impl NativeCandidateWorkflowCheck {
    #[must_use]
    pub fn id(&self) -> WorkflowCheckId {
        super::execution_id(self.actor, &self.record.check)
    }

    pub(in crate::event) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.record.validate()?;
        out.write_opaque_id(self.actor.as_bytes());
        let subject = &self.record.subject;
        out.write_scalar(subject.pull_request.get());
        out.write_scalar(subject.pull_request_version.get());
        out.write_ref_name(&subject.source_ref)?;
        out.write_ref_name(&subject.target_ref)?;
        out.write_git_oid(&subject.source_tip);
        out.write_git_oid(&subject.target_tip);
        out.write_scalar(subject.policy_epoch.get());
        out.write_git_oid(&self.record.candidate.merge_base);
        out.write_git_oid(&self.record.candidate.commit);
        out.write_raw(&self.record.bundle_sha256);
        self.record.check.write(out)
    }

    pub(in crate::event) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let actor =
            PrincipalId::from_bytes(input.read_opaque_id("candidate_workflow_check.actor")?);
        let pull_request = PullRequestNumber::try_new(
            input.read_scalar::<u64>("candidate_workflow_check.pull_request")?,
        )
        .ok_or_else(|| super::super::invalid_native("candidate_workflow_check.pull_request"))?;
        let pull_request_version = AggregateVersion::try_new(
            input.read_scalar::<u64>("candidate_workflow_check.pull_request_version")?,
        )
        .ok_or_else(|| {
            super::super::invalid_native("candidate_workflow_check.pull_request_version")
        })?;
        let source_ref: RefName = input.read_ref_name()?;
        let target_ref: RefName = input.read_ref_name()?;
        let source_tip = input.read_git_oid()?;
        let target_tip = input.read_git_oid()?;
        let policy_epoch = PolicyEpoch::try_new(
            input.read_scalar::<u64>("candidate_workflow_check.policy_epoch")?,
        )?;
        let candidate = CandidateBinding {
            merge_base: input.read_git_oid()?,
            commit: input.read_git_oid()?,
        };
        let mut bundle_sha256 = [0; 32];
        bundle_sha256.copy_from_slice(input.take("candidate_workflow_check.bundle_sha256", 32)?);
        let value = Self {
            actor,
            record: CandidateWorkflowCheckRecord {
                subject: ReviewSubject {
                    pull_request,
                    pull_request_version,
                    source_ref,
                    target_ref,
                    source_tip,
                    target_tip,
                    policy_epoch,
                },
                candidate,
                bundle_sha256,
                check: WorkflowCheckRecord::read(input)?,
            },
        };
        value.record.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
