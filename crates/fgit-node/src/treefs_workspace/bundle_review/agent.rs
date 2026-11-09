//! Candidate disclosure retains the original sponsored request's authority.
use super::*;
use crate::agent_credentials::SourceCandidateRequest;

impl OneNode {
    /// Inspect an ephemeral single-parent candidate under an independently
    /// granted, request-borrowed source-candidate capability. Neither the bundle
    /// nor its metadata can select an operator or refresh the request deadline.
    /// The supplied visibility can only narrow canonical source disclosure.
    /// Original objects must be reachable from the selected visible parent;
    /// inspection grants no object import, approval or publication authority.
    pub async fn inspect_agent_source_bundle_in(
        &self,
        candidate_request: &SourceCandidateRequest<'_>,
        reference: &RefName,
        expected_base: GitOid,
        expected_candidate: GitOid,
        input: &[u8],
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        options: &ReviewOptions,
    ) -> Result<BundleInspection, BundleInspectionRefusal> {
        let request = candidate_request
            .context(self)
            .map_err(|error| BundleInspectionRefusal::Envelope(Box::new(error)))?;
        candidate_request
            .check_input(input.len())
            .map_err(|error| BundleInspectionRefusal::Envelope(Box::new(error)))?;
        let inspected = self
            .inspect_workspace_bundle_in(
                &request,
                reference,
                expected_base,
                expected_candidate,
                input,
                visibility,
                expected_head,
                options,
            )
            .await?;
        candidate_request
            .check()
            .map_err(|error| BundleInspectionRefusal::Envelope(Box::new(error)))?;
        Ok(inspected)
    }
}
