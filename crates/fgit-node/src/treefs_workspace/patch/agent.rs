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
        candidate_request.check_input(patch_bytes.len())?;
        let candidate = self
            .prepare_repository_patch_profile_in(
                &context,
                reference,
                expected_commit,
                candidate_request.workspace_id(),
                patch_bytes,
                metadata,
                PatchLimits::default(),
                if binary_refactor {
                    PatchProfile::BinaryRefactor
                } else {
                    PatchProfile::Regular
                },
                candidate_request.authenticated_at(),
                Some(candidate_request.expires_at()),
            )
            .await?;
        candidate_request.check()?;
        Ok(candidate)
    }
}
