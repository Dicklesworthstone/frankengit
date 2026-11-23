//! Sponsored task branches use the ordinary branch quarantine and admission.

use super::*;
use crate::agent_credentials::SourceBranchCreationRequest;

impl OneNode {
    /// Create one absent branch at an exact currently visible branch tip under
    /// its independently granted canonical ref ceiling. The complete native
    /// commit and visible closure are verified by ordinary branch quarantine;
    /// current visibility, credential and protection are checked again at each
    /// publication basis. No objects are imported and no source files change.
    ///
    /// Principal, sponsor, key and lifetime come from the borrowed request.
    /// Exact retries recover the original terminal result before reevaluating
    /// mutable ref/scope state. Publication remains one sealed atomic decision.
    pub async fn create_agent_branch_in(
        &self,
        request: &NodeRequestContext,
        creation: &SourceBranchCreationRequest<'_>,
        reference: &RefName,
        target: GitOid,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        creation.check_context(self, request)?;
        creation.check_input(reference.as_bytes().len() + target.algorithm().digest_len())?;
        let command = RefCommand {
            name: reference.clone(),
            expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(target),
            force: false,
        };
        let commands = [command];
        let semantic = branch_request(self.object_format, &commands)?;
        let session = creation.session();
        let proof = creation.bind_branch(reference, target);
        creation
            .drive_in(
                self,
                request,
                self.admit_branch_commands_durable_in(
                    request,
                    &session,
                    &commands,
                    semantic,
                    limits,
                    Some(&proof),
                ),
            )
            .await
    }
}
