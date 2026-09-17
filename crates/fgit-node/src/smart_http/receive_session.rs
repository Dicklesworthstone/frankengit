//! Shared node-owned receive admission and native byte intake.
//!
//! HTTP and embedding transports use the same exact-basis coordinator. The
//! historical `NodeSmartHttpRefusal` name is retained as the public error family;
//! its interrupted-session variant preserves canonical outcomes independently
//! of how the native receive bytes arrived. The legacy daemon is not redirected
//! by this module: callers must select the new session API explicitly.

mod bounded_intake;

use std::future::{Future, poll_fn};
use std::pin::pin;

use fgit_admission::policy_bridge::receive_session;
use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionResult, BasisBoundValidatedReceive,
};
use fgit_git_object::ParseLimits;
use fgit_types::{GitHashAlgorithm, RefusalCode};
use fgit_types::cell::admits_staging_intake;
use fgit_wire::GitObjectFormat;
use fgit_wire::receive::{ReceiveCancellation, ReceiveContext, ReceiveError, ReceivePack};

use super::NodeSmartHttpRefusal;
use crate::{
    LoopbackReceiveSession, MaterializedAdmission, NodeReceiveTransportRefusal,
    NodeRequestContext, OneNode, PackContextCheckpoint, checkpoint_pack_context,
};
use crate::quarantine_validator::ProductionReceiveQuarantineHandoff;

impl OneNode {
    /// Derive the key needed to recover one non-atomic receive command.
    ///
    /// The index is zero-based ORIGINAL wire order and must be below 64.
    /// This is a pure selector over the admission lowerer's existing identity
    /// rule, not a credential, new transaction, or storage operation. A local
    /// client can then call `recover_transaction_in` with this key under the
    /// original authenticated principal. Atomic pushes use the original key
    /// directly. No command-count or whole-session completion is inferred.
    pub fn receive_command_recovery_key(
        original: &fgit_authority::IdempotencyKey,
        index: usize,
    ) -> Result<fgit_authority::IdempotencyKey, fgit_admission::AdmissionError> {
        receive_session::non_atomic_command_key(original, index)
    }

    /// Admit an authenticated production receive through the continuing core.
    ///
    /// This boundary accepts only the private, basis-bound quarantine proof.
    /// The transport authenticates the principal and owns intake/quota checks;
    /// this method independently checks publication eligibility. StagingOnly
    /// may retain objects but cannot publish them here.
    ///
    /// Non-atomic sessions bind their complete request and all child retry keys
    /// before the first decision. Each command retains its validation witness;
    /// continuation permits only the session's verified preceding decision.
    /// Interrupted outcomes remain available in `ReceiveInterrupted`, including
    /// the wire-order prefix already returned by the authority resolver. No
    /// infrastructure error implies rollback of that prefix or the next command.
    pub async fn admit_receive_session_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        validated: &BasisBoundValidatedReceive,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeSmartHttpRefusal::UnauthenticatedReceive)?;
        self.receive_publication_admitted()?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let projection = self
            .durable_admission_projection(&context)
            .map_err(|error| NodeReceiveTransportRefusal::Admission(Box::new(error)))?;
        receive_session::admit(
            &self.authority,
            request.authority(),
            &context,
            validated,
            limits,
            &projection,
        )
        .await
        .map_err(|error| NodeSmartHttpRefusal::ReceiveInterrupted(Box::new(error)))
    }

    /// Receive one complete native receive-pack request without an HTTP envelope.
    ///
    /// The embedding supplies an authenticated session with a stable client key
    /// and the exact node-owned materialization authorizing external pack bases.
    /// Principal, retry key, policy and object-format authority are never inferred
    /// from PACK bytes or transport headers. The native machine enforces its
    /// immutable ReceiveContext limits; this method feeds at most 16 KiB between
    /// cancellation checkpoints and introduces no second whole-request copy.
    ///
    /// Authentication, quota, cell intake, format and cancellation checks precede
    /// untrusted-byte retention. Production quarantine validates and stages the
    /// complete request before `admit_receive_session_durable_in` publishes any
    /// command. Incomplete or corrupt input cannot create a session descriptor.
    /// The canonical result and descriptor are interoperable with HTTP when the
    /// original principal, key, semantics and wire command order are identical.
    ///
    /// Cancellation is forwarded into the authority context while its future is
    /// polled; the future is still driven to its actual result. A terminal result
    /// wins over late cancellation. The caller owns the future through completion
    /// and must not drop it to infer non-commit. This is a native API, not a change
    /// to the legacy TCP daemon's greeting, key derivation or report-status path.
    pub async fn receive_pack_session_durable_in<C>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        materialized: &MaterializedAdmission,
        receive_context: ReceiveContext,
        input: &[u8],
        parse_limits: ParseLimits,
        admission_limits: AdmissionLimits,
        cancellation: &mut C,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal>
    where
        C: ReceiveCancellation,
    {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeSmartHttpRefusal::UnauthenticatedReceive)?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        admits_staging_intake(self.cell_state())
            .map_err(NodeReceiveTransportRefusal::CellState)?;
        let expected_format = match self.object_format {
            GitHashAlgorithm::Sha1 => GitObjectFormat::Sha1,
            GitHashAlgorithm::Sha256 => GitObjectFormat::Sha256,
        };
        if receive_context.object_format != expected_format {
            return Err(ReceiveError::AuthoritativeRefusal(
                RefusalCode::HashAlgorithmDomainMismatch,
            ).into());
        }
        let mut live = || {
            let active = cancellation.checkpoint()
                && matches!(checkpoint_pack_context(request.authority()), PackContextCheckpoint::Live);
            if !active { request.authority().cancel(); }
            active
        };
        if !live() {
            return Err(ReceiveError::AuthoritativeRefusal(RefusalCode::CancellationInProgress).into());
        }
        let validator = self.production_quarantine_validator(
            materialized, receive_context.limits.pack.clone(), parse_limits,
        ).map_err(ReceiveError::AuthoritativeRefusal)?;
        let mut receive = ReceivePack::new(receive_context)?;
        bounded_intake::push(&mut receive, input, &mut live)?;
        let mut handoff = ProductionReceiveQuarantineHandoff::new(
            validator, materialized.basis().clone(),
        );
        receive.finish_with_handoff(&mut handoff, &mut live)?;
        let validated = handoff.into_validated_receive()?;
        drop(receive);
        if !live() {
            return Err(ReceiveError::AuthoritativeRefusal(RefusalCode::CancellationInProgress).into());
        }
        let mut admission = pin!(self.admit_receive_session_durable_in(
            request, session, &validated, admission_limits,
        ));
        poll_fn(|cx| {
            // Never return early here: the underlying future may already own
            // an in-flight head CAS, and only it can settle that responsibility.
            let _ = live();
            admission.as_mut().poll(cx)
        }).await
    }

    /// Compatibility shim: HTTP has no independent session admission rules.
    pub(super) async fn admit_continuing_http_receive_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        validated: &BasisBoundValidatedReceive,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
        self.admit_receive_session_durable_in(request, session, validated, limits).await
    }
}

#[cfg(test)]
#[path = "receive_session_tests.rs"]
mod tests;
