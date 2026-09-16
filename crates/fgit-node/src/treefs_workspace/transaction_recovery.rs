//! Recover terminal knowledge without requiring a workspace or candidate bundle.
use fgit_admission::AdmissionContext;
use fgit_admission::policy_bridge::receive_session::recovery::{
    SessionRecovery, SessionRecoveryFailure, recover,
};
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
            authenticated.client_idempotency_key(), &|| recovery_checkpoint(request)).await
    }

    /// Recover every command of a non-atomic push using only its original key.
    ///
    /// The admission-owned descriptor is revalidated against the whole request
    /// and all child bindings, then each child's seal and outcome is verified.
    /// The complete original wire order is returned, including commands that
    /// have not reached a terminal decision. No pack, publication, re-seal, or
    /// write permission is required. Callers authenticate this principal's
    /// recovery grant before invoking the method.
    ///
    /// Descriptors exist for pushes processed by the continuing coordinator
    /// after descriptor support was added. A missing/legacy descriptor is an
    /// observation, not an empty session or proof of rollback. Atomic pushes
    /// retain the single-transaction `recover_transaction_in` interface.
    pub async fn recover_receive_session_in(
        &self, request: &NodeRequestContext, session: &LoopbackReceiveSession,
    ) -> Result<SessionRecovery, SessionRecoveryFailure> {
        let authenticated = session.authenticated_session()
            .ok_or(RecoveryFailure::AuthenticationRequired)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(), tenant_id: self.tenant_id,
            repository_id: self.repository_id, principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        recover(&self.authority, request.authority(), &context,
            &|| recovery_checkpoint(request)).await
    }
}

fn recovery_checkpoint(request: &NodeRequestContext) -> Result<(), RefusalCode> {
    match checkpoint_pack_context(request.authority()) {
        PackContextCheckpoint::Live => Ok(()),
        PackContextCheckpoint::Stopped { budget_exhaustion: Some(_) } => Err(RefusalCode::ResourceBudgetExceeded),
        PackContextCheckpoint::Stopped { budget_exhaustion: None } => Err(RefusalCode::CancellationInProgress),
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod session_tests;
