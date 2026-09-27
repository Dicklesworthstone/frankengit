//! Receipt-bearing entry point for the existing native fast-forward method.
//! No new seal, ref-only update, object staging, or metadata lookup is introduced.

use fgit_admission::merge::native::NativeMergeIntent;
use fgit_admission::merge::native::objects::MergeObjectLimits;
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_authority::TerminalOutcome;
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_types::{GitOid, RefName, RefusalCode, TxId};

use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};

impl OneNode {
    /// Fast-forward an existing PR to its exact, already-admitted source tip.
    ///
    /// The caller supplies an authenticated session and all observed coordinates.
    /// This local composition boundary does not authenticate a remote request.
    /// It never reads current metadata to fill in missing expectations or turns
    /// a failed ancestry check into a force update or a different merge method.
    ///
    /// The existing native driver proves ancestry from verified commit bodies,
    /// checks the PR version and current mandatory review protection, and publishes
    /// the target ref, PR event and delivery obligation in one authority decision.
    /// It resolves an identical terminal retry before new-publication gates.
    /// Both admission and object budgets belong to the same request context;
    /// changing a budget does not change the canonical transaction identity.
    ///
    /// The returned ID is derived from the driver's existing semantic seal. It
    /// is not a new identity belonging to this API or to an invocation. A known
    /// terminal result is returned without a post-publication metadata query or
    /// cancellation check. A pending outbox obligation is not acknowledgement.
    ///
    /// # Errors
    /// Invalid coordinates or a missing authenticated session refuse before
    /// admission. Infrastructure/cancellation errors do not prove non-commit;
    /// retain the exact principal, key, PR version, branch bytes and native tips.
    pub async fn fast_forward_pull_request_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        pull_request: PullRequestNumber,
        expected_version: AggregateVersion,
        source_ref: &RefName,
        source_tip: GitOid,
        target_ref: &RefName,
        target_tip_before: GitOid,
        limits: AdmissionLimits,
        object_limits: MergeObjectLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let map_error = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let intent = NativeMergeIntent::fast_forward_only(
            pull_request,
            expected_version,
            source_ref.clone(),
            source_tip,
            target_ref.clone(),
            target_tip_before,
        )
        .map_err(map_error)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        // Pure derivation only. The existing driver below owns sealing,
        // recovery, quota, authorization, validation, and publication.
        let tx = intent
            .seal_attempt(&context)
            .map_err(map_error)?
            .derive()
            .map_err(|_| {
                map_error(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        let terminal = self
            .admit_native_merge_durable_in(request, session, &intent, limits, object_limits)
            .await?;
        Ok((tx, terminal))
    }
}
