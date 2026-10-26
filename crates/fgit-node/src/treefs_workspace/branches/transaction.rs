#![forbid(unsafe_code)]
//! Multi-branch transactions reuse the ordinary receive admission and exact
//! terminal identity, never a loop of independently published branch writes.
use super::*;

impl OneNode {
    /// Hard limit for a single local branch transaction before cloning commands.
    pub const MAX_BRANCH_TRANSACTION_COMMANDS: usize = fgit_authority::MAX_REF_COMMANDS;

    /// Publish up to [`Self::MAX_BRANCH_TRANSACTION_COMMANDS`] distinct branch
    /// changes in one sealed, atomic transaction.
    /// Every command requires an exact old tip or absence, and new tips remain
    /// visible, verified commits. Force, duplicate targets, mixed hash domains,
    /// hidden refs and default-branch deletion are not admitted. All ordinary
    /// branch-protection and fast-forward checks remain in the shared path.
    ///
    /// Command ordering is canonicalized by SemanticRequest. Identical retries
    /// recover the original terminal decision before checking current objects
    /// or quota. An error after admission never proves non-commit.
    pub async fn admit_branch_transaction_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        commands: &[RefCommand],
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        session
            .authenticated_session()
            .ok_or_else(|| receive_error(NodeReceiveTransportRefusal::Unauthenticated))?;
        if commands.is_empty() || commands.len() > Self::MAX_BRANCH_TRANSACTION_COMMANDS {
            return Err(invalid(
                "branch transaction command count is outside the authority request bound",
            ));
        }
        let semantic = branch_commands_request(self.object_format, commands)?;
        self.admit_branch_commands_durable_in(request, session, commands, semantic, limits)
            .await
    }
}
