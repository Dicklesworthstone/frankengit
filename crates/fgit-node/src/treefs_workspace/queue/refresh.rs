//! An explicitly authorized, target-only PR update for the current queue head.
//! This operation cannot move refs, replace FIFO entries or reuse review/check
//! evidence belonging to the previous PR version and target.

use super::*;
use fgit_admission::merge::native::queue::QueueHeadRefreshCommand;

impl OneNode {
    /// Refresh one exact idle queue head to the offered current target while
    /// preserving all other recorded PR data and the complete queue snapshot.
    /// The caller supplies its own authenticated metadata authority; neither a
    /// read session nor the identity of a queue enqueuer grants that authority.
    pub async fn refresh_queue_head_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &QueueHeadRefreshCommand,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let map_error = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let (_, attempt) =
            queue::queue_head_refresh_proposal(&context, command).map_err(map_error)?;
        let tx_id = attempt
            .derive()
            .map_err(|_| {
                map_error(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        // Recover the original immutable outcome before gates for new work.
        // Replaying a terminal result never rebuilds observations from current
        // queue/PR state, even after another landing or a node shutdown.
        if let OutcomeLookup::Decided(terminal) = self
            .resolve_outcome_checkpointed_in(request, tx_id)
            .await
            .map_err(|error| map_error(error.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|error| map_error(error.into()))?;
            return Ok((tx_id, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self
                .durable_admission_projection(&context)
                .map_err(map_error)?
                .with_authenticated_session(authenticated),
            object_limits: MergeObjectLimits::default(),
            staging: None,
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        let terminal = Box::pin(queue::admit_queue_head_refresh_async(
            &self.authority,
            request.authority(),
            &context,
            command,
            limits,
            &projection,
        ))
        .await
        .map_err(map_error)?;
        Ok((tx_id, terminal))
    }
}
