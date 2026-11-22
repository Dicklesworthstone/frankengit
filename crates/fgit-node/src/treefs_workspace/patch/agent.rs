//! Sponsored candidate construction retains the verified request boundary.
//! Repository text determines edits, never the authority for executing them.

use super::*;
use crate::agent_credentials::SourceCandidateRequest;

impl OneNode {
    /// Prepare an ephemeral candidate under independently granted source
    /// disclosure. Unlike the trusted-owner adapter, this entrypoint requires
    /// an opaque proof borrowed from the original authenticated agent request.
    /// Its native context cannot outlive that request or cross repositories.
    ///
    /// Complete root disclosure preserves untouched siblings. The generated
    /// TreeFS capability grants writes only to both sides of declared edits,
    /// retains the original expiry and shares finite read-byte/object budgets.
    /// No staging, ref authority, host workspace or process is created.
    pub async fn prepare_agent_source_patch_in(
        &self,
        candidate_request: &SourceCandidateRequest<'_>,
        reference: &RefName,
        expected_commit: GitOid,
        patch_bytes: &[u8],
        metadata: &MergeMetadata,
        binary_refactor: bool,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        let context = candidate_request.context(self)?;
        self.prepare_agent_source_patch_with_context_in(
            &context,
            candidate_request,
            reference,
            expected_commit,
            patch_bytes,
            metadata,
            binary_refactor,
        )
        .await
    }

    /// Explicitly opt into inert Git symlink edits under the original sponsored
    /// candidate request. Link targets are blob bytes, never host paths. This
    /// adds no source publication, checkout or process authority, and the
    /// regular-file entrypoint continues to refuse symlink edits.
    pub async fn prepare_agent_source_symlink_patch_in(
        &self,
        candidate_request: &SourceCandidateRequest<'_>,
        reference: &RefName,
        expected_commit: GitOid,
        patch_bytes: &[u8],
        metadata: &MergeMetadata,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        let context = candidate_request.context(self)?;
        self.prepare_agent_source_symlink_patch_with_context_in(
            &context,
            candidate_request,
            reference,
            expected_commit,
            patch_bytes,
            metadata,
        )
        .await
    }

    /// Opt into opaque gitlink pointer patches under the original verified
    /// sponsored request. Parent source disclosure grants no submodule access.
    pub async fn prepare_agent_source_gitlink_patch_in(
        &self,
        candidate_request: &SourceCandidateRequest<'_>,
        reference: &RefName,
        expected_commit: GitOid,
        patch_bytes: &[u8],
        metadata: &MergeMetadata,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        let context = candidate_request.context(self)?;
        self.prepare_agent_source_gitlink_patch_with_context_in(
            &context,
            candidate_request,
            reference,
            expected_commit,
            patch_bytes,
            metadata,
        )
        .await
    }

    /// Continue under the exact context already owned and driven by HTTP.
    /// Its caller binds this context to the authenticated transport deadline;
    /// this adapter retains its cancellation/poll/cost ledger rather than
    /// deriving a sibling context with a renewed phase budget.
    pub(crate) async fn prepare_agent_source_patch_with_context_in(
        &self,
        context: &NodeRequestContext,
        candidate_request: &SourceCandidateRequest<'_>,
        reference: &RefName,
        expected_commit: GitOid,
        patch_bytes: &[u8],
        metadata: &MergeMetadata,
        binary_refactor: bool,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        self.prepare_agent_source_patch_profile_with_context_in(
            context,
            candidate_request,
            reference,
            expected_commit,
            patch_bytes,
            metadata,
            if binary_refactor {
                PatchProfile::BinaryRefactor
            } else {
                PatchProfile::Regular
            },
        )
        .await
    }

    pub(crate) async fn prepare_agent_source_symlink_patch_with_context_in(
        &self,
        context: &NodeRequestContext,
        candidate_request: &SourceCandidateRequest<'_>,
        reference: &RefName,
        expected_commit: GitOid,
        patch_bytes: &[u8],
        metadata: &MergeMetadata,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        self.prepare_agent_source_patch_profile_with_context_in(
            context,
            candidate_request,
            reference,
            expected_commit,
            patch_bytes,
            metadata,
            PatchProfile::Symlinks,
        )
        .await
    }

    pub(crate) async fn prepare_agent_source_gitlink_patch_with_context_in(
        &self,
        context: &NodeRequestContext,
        candidate_request: &SourceCandidateRequest<'_>,
        reference: &RefName,
        expected_commit: GitOid,
        patch_bytes: &[u8],
        metadata: &MergeMetadata,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        self.prepare_agent_source_patch_profile_with_context_in(
            context,
            candidate_request,
            reference,
            expected_commit,
            patch_bytes,
            metadata,
            PatchProfile::Gitlinks,
        )
        .await
    }

    async fn prepare_agent_source_patch_profile_with_context_in(
        &self,
        context: &NodeRequestContext,
        candidate_request: &SourceCandidateRequest<'_>,
        reference: &RefName,
        expected_commit: GitOid,
        patch_bytes: &[u8],
        metadata: &MergeMetadata,
        profile: PatchProfile,
    ) -> Result<WorkspacePatchCandidate, NodeWorkspaceRefusal> {
        candidate_request.check_context(self, context)?;
        candidate_request.check_input(patch_bytes.len())?;
        let candidate = self
            .prepare_repository_patch_profile_in(
                context,
                reference,
                expected_commit,
                candidate_request.workspace_id(),
                patch_bytes,
                metadata,
                PatchLimits::default(),
                profile,
                candidate_request.authenticated_at(),
                Some(candidate_request.expires_at()),
            )
            .await?;
        candidate_request.check_context(self, context)?;
        Ok(candidate)
    }
}
