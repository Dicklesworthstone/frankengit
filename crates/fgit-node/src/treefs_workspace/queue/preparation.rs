//! Read-only native construction for one exact, idle queue head. Queue and PR
//! observations must belong to the same authenticated authority predecessor.

use fgit_admission::merge::native::queue;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::{
    MergeCommitStyle, MergeMetadata, MergePreparation, MergeProfile, PreparationLimits,
};
use fgit_forge::{AggregateVersion, QueueNumber};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{RefName, RefusalCode, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;

use crate::treefs_workspace::workspace_request_live;
use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode};

/// An exact queue-head artifact for inspection and execution. Neither these
/// bytes nor a successful local workflow authorize publication. The candidate
/// is unpublished and its objects remain owned by `bundle` and `outcome`.
#[derive(Debug)]
pub struct PreparedQueueHeadBundle {
    pub number: QueueNumber,
    pub expected_version: AggregateVersion,
    pub source_head: RepositoryAuthorityHeadId,
    pub subject: ReviewSubject,
    pub outcome: MergePreparation,
    pub bundle: Option<Vec<u8>>,
}

impl OneNode {
    /// Prepare a deterministic two-parent merge for the exact first queued PR.
    /// An unrelated concurrent authority publication may refuse this read;
    /// preparation never mixes queue selection with a newer PR or source view.
    pub async fn prepare_queue_head_bundle_in(
        &self,
        request: &NodeRequestContext,
        number: QueueNumber,
        expected_version: AggregateVersion,
        subject: &ReviewSubject,
        visibility: &RefVisibility,
        metadata: &MergeMetadata,
        limits: PreparationLimits,
    ) -> Result<PreparedQueueHeadBundle, NodeWorkspaceRefusal> {
        self.prepare_queue_head_bundle_with_profile_in(
            request,
            number,
            expected_version,
            subject,
            visibility,
            metadata,
            limits,
            MergeProfile::PathMergeV1,
        )
        .await
    }

    /// Select deterministic path or exact-rename construction. Commit style is
    /// fixed to two-parent; conflicts return the native preparation outcome,
    /// and no queue event, ref, object placement, seal or decision is published.
    pub async fn prepare_queue_head_bundle_with_profile_in(
        &self,
        request: &NodeRequestContext,
        number: QueueNumber,
        expected_version: AggregateVersion,
        subject: &ReviewSubject,
        visibility: &RefVisibility,
        metadata: &MergeMetadata,
        limits: PreparationLimits,
        profile: MergeProfile,
    ) -> Result<PreparedQueueHeadBundle, NodeWorkspaceRefusal> {
        metadata
            .validate()
            .map_err(NodeWorkspaceRefusal::MergePreparation)?;
        limits
            .validate()
            .map_err(NodeWorkspaceRefusal::MergePreparation)?;
        subject.validate().map_err(|_| {
            NodeWorkspaceRefusal::InvalidWorkspaceCandidate("invalid queue preparation subject")
        })?;
        if subject.source_tip.algorithm() != self.object_format {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        let visible = |name: &RefName| {
            !visibility.hides(name.as_bytes())
                && !selected.snapshot().hidden_refs.hides(name.as_bytes())
        };
        if !visible(&subject.source_ref) || !visible(&subject.target_ref) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let queue = queue::read_queue_at(
            &self.authority,
            request.authority(),
            selected.basis(),
            number,
            &visible,
            &|| !workspace_request_live(request),
        )
        .await
        .map_err(|error| {
            NodeWorkspaceRefusal::MergeValidation(
                error.into_projection_unavailable(RefusalCode::EvidenceInvalid),
            )
        })?
        .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        if queue.version != expected_version
            || queue.target_ref != subject.target_ref
            || queue.active_batch.is_some()
            || queue.entries.first().is_none_or(|entry| {
                entry.pull_request != subject.pull_request
                    || entry.source_ref != subject.source_ref
                    || entry.head_tip != subject.source_tip
            })
        {
            return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
        }
        // The existing PR preparation owns canonical open-PR/version/policy
        // checks, exact live branch tips, all object reads and native packing.
        let prepared = Box::pin(self.prepare_pull_request_bundle_with_options_in(
            request,
            subject,
            visibility,
            metadata,
            limits,
            profile,
            MergeCommitStyle::TwoParent,
        ))
        .await?;
        if prepared.source_head != selected.basis().id() {
            return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
        }
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        Ok(PreparedQueueHeadBundle {
            number,
            expected_version,
            source_head: prepared.source_head,
            subject: prepared.subject,
            outcome: prepared.outcome,
            bundle: prepared.bundle,
        })
    }
}
