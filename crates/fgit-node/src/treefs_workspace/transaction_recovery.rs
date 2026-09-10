//! Recover terminal knowledge without requiring a workspace or candidate bundle.
use fgit_authority::key_recovery::{RecoveryFailure, RecoveryScope, RequestRecovery, recover_request_async};
use fgit_types::RefusalCode;
use crate::{LoopbackReceiveSession, NodeRequestContext, OneNode, PackContextCheckpoint, checkpoint_pack_context};

impl OneNode {
    /// Recover this authenticated principal's original sealed request by key.
    ///
    /// This reads authority metadata only: no command is reconstructed, no
    /// candidate bytes are required, and no Git object is read or staged. It
    /// deliberately does not apply new-publication, push-quota, or current-PR
    /// gates. A stopped cell cannot erase a previously committed/refused
    /// decision. The existing runtime/store must still be live and readable.
    ///
    /// The local/gateway caller authenticates the supplied session. Knowledge
    /// of a key or transaction ID is not an additional capability. This is not
    /// a remote identity service and does not widen repository visibility.
    pub async fn recover_transaction_in(
        &self, request: &NodeRequestContext, session: &LoopbackReceiveSession,
    ) -> Result<RequestRecovery, RecoveryFailure> {
        let authenticated = session.authenticated_session().ok_or(RecoveryFailure::AuthenticationRequired)?;
        let scope = RecoveryScope { tenant_id: self.tenant_id, repository_id: self.repository_id,
            principal_id: authenticated.principal_id() };
        recover_request_async(&self.authority, request.authority(), &self.head_key, scope,
            authenticated.client_idempotency_key(), &|| match checkpoint_pack_context(request.authority()) {
                PackContextCheckpoint::Live => Ok(()),
                PackContextCheckpoint::Stopped { budget_exhaustion: Some(_) } => Err(RefusalCode::ResourceBudgetExceeded),
                PackContextCheckpoint::Stopped { budget_exhaustion: None } => Err(RefusalCode::CancellationInProgress),
            }).await
    }
}

#[cfg(test)]
mod tests;
