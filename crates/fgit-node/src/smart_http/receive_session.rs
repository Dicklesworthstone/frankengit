//! Shared node-owned receive admission and native byte intake.
//!
//! HTTP, guarded raw TCP and embedding transports share the exact-basis
//! coordinator. The historical `NodeSmartHttpRefusal` name is retained as the
//! public error family; interrupted outcomes do not depend on transport framing.
//! Older node compatibility methods remain distinct from the guarded service.

use crate::bounded_receive_intake as bounded_intake;
mod daemon;

use std::future::{Future, poll_fn};
use std::pin::pin;

use fgit_admission::policy_bridge::receive_session;
use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionResult, BasisBoundValidatedReceive,
};
use fgit_git_object::ParseLimits;
use fgit_types::cell::admits_staging_intake;
use fgit_types::{GitHashAlgorithm, RefusalCode};
use fgit_wire::GitObjectFormat;
use fgit_wire::receive::{ReceiveCancellation, ReceiveContext, ReceiveError, ReceivePack};

use super::NodeSmartHttpRefusal;
use crate::quarantine_validator::ProductionReceiveQuarantineHandoff;
use crate::{
    LoopbackReceiveSession, MaterializedAdmission, NodeReceiveTransportRefusal, NodeRequestContext,
    OneNode, PackContextCheckpoint, checkpoint_pack_context,
};

impl OneNode {
    /// Derive the key needed to recover one non-atomic receive command.
    ///
    /// The index is zero-based ORIGINAL wire order and must be below
    /// [`fgit_admission::MAX_RECEIVE_SESSION_COMMANDS`].
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
    /// cannot publish here; a receive whose objects are only staged
    /// (frankengit-tz5z) abandons them when it ends without a commit.
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
        Box::pin(
            self.admit_receive_session_publishing_in(request, session, validated, limits, None),
        )
        .await
    }

    /// [`Self::admit_receive_session_durable_in`] for a receive whose
    /// verified objects are staged but not yet published: they are published
    /// when admission stages a commit, before its head CAS (frankengit-tz5z).
    pub(crate) async fn admit_receive_session_publishing_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        validated: &BasisBoundValidatedReceive,
        limits: AdmissionLimits,
        staging: Option<&crate::receive_staging::ReceiveStaging>,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeSmartHttpRefusal::UnauthenticatedReceive)?;
        // Check the ORIGINAL complete command list before the admission driver
        // binds child keys or selects any non-atomic microbatch. A denied
        // sibling cannot leave a permitted prefix published.
        if validated
            .request()
            .commands
            .iter()
            .any(|command| !authenticated.permits_ref_write_bytes(&command.ref_name))
        {
            return Err(NodeSmartHttpRefusal::RefWriteScopeDenied);
        }
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
            .durable_admission_projection_publishing(&context, staging)
            .map_err(|error| NodeReceiveTransportRefusal::Admission(Box::new(error)))?
            .with_authentication(authenticated.authentication());
        let checkpoint = || match checkpoint_pack_context(request.authority()) {
            PackContextCheckpoint::Live => Ok(()),
            PackContextCheckpoint::Stopped { budget_exhaustion } => {
                Err(if budget_exhaustion.is_some() {
                    RefusalCode::ResourceBudgetExceeded
                } else {
                    RefusalCode::CancellationInProgress
                })
            }
        };
        Box::pin(receive_session::admit_with_checkpoint(
            &self.authority,
            request.authority(),
            &context,
            validated,
            limits,
            &projection,
            &checkpoint,
        ))
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
        admits_staging_intake(self.cell_state()).map_err(NodeReceiveTransportRefusal::CellState)?;
        let expected_format = match self.object_format {
            GitHashAlgorithm::Sha1 => GitObjectFormat::Sha1,
            GitHashAlgorithm::Sha256 => GitObjectFormat::Sha256,
        };
        if receive_context.object_format != expected_format {
            return Err(ReceiveError::AuthoritativeRefusal(
                RefusalCode::HashAlgorithmDomainMismatch,
            )
            .into());
        }
        let mut live = || {
            let active = cancellation.checkpoint()
                && matches!(
                    checkpoint_pack_context(request.authority()),
                    PackContextCheckpoint::Live
                );
            if !active {
                request.authority().cancel();
            }
            active
        };
        if !live() {
            return Err(
                ReceiveError::AuthoritativeRefusal(RefusalCode::CancellationInProgress).into(),
            );
        }
        // Verified objects are published only if admission commits
        // (frankengit-tz5z); every other exit drops `staging`, removing them.
        let staging = crate::receive_staging::ReceiveStaging::default();
        let validator = self
            .production_quarantine_validator(
                materialized,
                receive_context.limits.pack.clone(),
                parse_limits,
            )
            .map_err(ReceiveError::AuthoritativeRefusal)?
            .with_receive_staging(&staging);
        let wire_limits = receive_context.limits.wire.clone();
        let mut receive = ReceivePack::new(receive_context)?
            .with_pack_retention(self.received_pack_cache().capture_limit());
        bounded_intake::push(&mut receive, input, &wire_limits, &mut live)?;
        let mut handoff =
            ProductionReceiveQuarantineHandoff::new(validator, materialized.basis().clone());
        receive.finish_with_handoff(&mut handoff, &mut live)?;
        let validated = handoff.into_validated_receive()?;
        drop(receive);
        if !live() {
            return Err(
                ReceiveError::AuthoritativeRefusal(RefusalCode::CancellationInProgress).into(),
            );
        }
        let mut admission = pin!(self.admit_receive_session_publishing_in(
            request,
            session,
            &validated,
            admission_limits,
            Some(&staging),
        ));
        poll_fn(|cx| {
            // Never return early here: the underlying future may already own
            // an in-flight head CAS, and only it can settle that responsibility.
            let _ = live();
            admission.as_mut().poll(cx)
        })
        .await
    }

    /// Compatibility shim: HTTP has no independent session admission rules.
    pub(super) async fn admit_continuing_http_receive_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        validated: &BasisBoundValidatedReceive,
        limits: AdmissionLimits,
        staging: Option<&crate::receive_staging::ReceiveStaging>,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
        Box::pin(
            self.admit_receive_session_publishing_in(request, session, validated, limits, staging),
        )
        .await
    }
}

#[cfg(test)]
#[path = "receive_session_tests.rs"]
mod tests;
