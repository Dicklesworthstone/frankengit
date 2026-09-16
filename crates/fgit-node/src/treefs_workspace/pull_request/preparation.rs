//! Read-only preparation of an explicitly selected, current native PR.
//! PR metadata, policy and refs must describe the SAME authenticated head as
//! native construction. A concurrent publication refuses the attempt instead
//! of returning a candidate for a silently refreshed subject.

use fgit_admission::{AdmissionError, ProjectionFailure};
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::{MergeMetadata, MergePreparation, PreparationLimits};
use fgit_forge::ForgeEventPayload;
use fgit_types::{RefusalCode, RepositoryAuthorityHeadId};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_wire::visibility::RefVisibility;

use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode};

/// An artifact for inspection, not a seal, publication receipt or approval.
/// Candidate objects are owned only by `bundle` and the pure planner's result.
#[derive(Debug)]
pub struct PreparedPullRequestBundle {
    pub source_head: RepositoryAuthorityHeadId,
    pub subject: ReviewSubject,
    pub outcome: MergePreparation,
    pub bundle: Option<Vec<u8>>,
}

impl OneNode {
    /// Construct an exact-candidate review artifact from an existing open PR.
    /// Caller/canonical visibility applies before disclosure. No principal,
    /// key, seal or publication is required for this read-only operation.
    ///
    /// The existing native constructor owns object selection, validation and
    /// packing. Its independently selected head MUST equal the PR head before
    /// any artifact returns. Harmless concurrent publications can therefore
    /// refuse an attempt, but never mix PR metadata with a different source.
    pub async fn prepare_pull_request_bundle_in(
        &self,
        request: &NodeRequestContext,
        subject: &ReviewSubject,
        visibility: &RefVisibility,
        metadata: &MergeMetadata,
        limits: PreparationLimits,
    ) -> Result<PreparedPullRequestBundle, NodeWorkspaceRefusal> {
        metadata.validate().map_err(NodeWorkspaceRefusal::MergePreparation)?;
        limits.validate().map_err(NodeWorkspaceRefusal::MergePreparation)?;
        let head = self.validate_pull_request_preparation_in(request, subject, visibility).await?;
        let prepared = self.prepare_merge_bundle_in(request, &subject.target_ref,
            &subject.source_ref, visibility, metadata, limits).await?;
        if prepared.source_head != head {
            return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
        }
        if !super::super::workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        Ok(PreparedPullRequestBundle {
            source_head: prepared.source_head, subject: subject.clone(),
            outcome: prepared.outcome, bundle: prepared.bundle,
        })
    }

    /// Shared exact-PR selection for automatic and explicitly resolved reads.
    /// This is not a publication capability. Every caller must still pin its
    /// subsequent native construction to the returned authenticated head.
    pub(in crate::treefs_workspace) async fn validate_pull_request_preparation_in(
        &self, request: &NodeRequestContext, subject: &ReviewSubject,
        visibility: &RefVisibility,
    ) -> Result<RepositoryAuthorityHeadId, NodeWorkspaceRefusal> {
        subject.validate().map_err(|_| NodeWorkspaceRefusal::InvalidWorkspaceCandidate("invalid preparation subject"))?;
        if subject.source_tip.algorithm() != self.object_format {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if visibility.hides(subject.source_ref.as_bytes()) || visibility.hides(subject.target_ref.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let current = self.materialize_admission_in(request).await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        let visible = |source: &fgit_types::RefName, target: &fgit_types::RefName| {
            [source, target].iter().all(|name| !visibility.hides(name.as_bytes())
                && !current.snapshot().hidden_refs.hides(name.as_bytes()))
        };
        if !visible(&subject.source_ref, &subject.target_ref) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let mut page = fgit_admission::merge::native::pull_request::read_page_at(
            &self.authority, request.authority(), current.basis(),
            subject.pull_request.get() - 1, 1, &visible,
            &|| !super::super::workspace_request_live(request),
        ).await.map_err(|error| NodeWorkspaceRefusal::MergeValidation(ProjectionFailure::Unavailable(
            match error {
                AdmissionError::AsyncProjectionUnavailable(code) => code,
                _ => RefusalCode::EvidenceInvalid,
            },
        )))?;
        let pr = page.pull_requests.pop().filter(|pr| pr.number == subject.pull_request)
            .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let ForgeEventPayload::PullRequestChangedNative(change) = &pr.event.payload else {
            return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
        };
        if change.action == PullRequestAction::Close
            || pr.event.version != subject.pull_request_version
            || change.data.source_ref != subject.source_ref
            || change.data.target_ref != subject.target_ref
            || change.data.source_tip != subject.source_tip
            || change.data.target_tip != subject.target_tip
            || current.basis().body().policy_epoch != subject.policy_epoch
            || current.snapshot().refs.get(&subject.source_ref) != Some(&subject.source_tip)
            || current.snapshot().refs.get(&subject.target_ref) != Some(&subject.target_tip)
        {
            return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
        }
        if !super::super::workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        Ok(current.basis().id())
    }
}
