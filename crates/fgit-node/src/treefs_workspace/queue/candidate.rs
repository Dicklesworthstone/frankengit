//! Authenticated two-parent queue-head publication. Incoming candidate objects
//! remain privately quarantined until native admission prepares the complete
//! target/PR/queue transition against one exact authority predecessor.

use fgit_admission::merge::native::objects::MergeObjectLimits;
use fgit_admission::merge::native::queue::{
    QueueCandidateLandingCommand, admit_candidate_landing_async, candidate_landing_proposal,
};
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_types::{RefusalCode, TxId};

use crate::receive_staging::ReceiveStaging;
use crate::treefs_workspace::native_merge::NodeNativeMergeProjection;
use crate::treefs_workspace::publication::receive_error;
use crate::treefs_workspace::workspace_request_live;
use crate::{
    LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, NodeWorkspaceRefusal,
    OneNode,
};

impl OneNode {
    /// Land the exact first queued PR using an explicitly supplied two-parent
    /// candidate bundle. The native validator independently verifies ordered
    /// parents, common ancestry, closure and the current review/check policy.
    /// Only one authority CAS publishes the target move, PR merge and two queue
    /// events. The authenticated session, including its authentication method,
    /// is retained through policy evaluation; no actor comes from the command.
    ///
    /// An exact decided retry resolves before intake, quota, object quarantine
    /// or current policy checks. In particular, recovery does not require the
    /// original bundle bytes to remain available. Undecided malformed input
    /// never publishes the received ref-only proof or changes queue state.
    pub async fn land_queue_head_bundle_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &QueueCandidateLandingCommand,
        input: &[u8],
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or_else(|| receive_error(NodeReceiveTransportRefusal::Unauthenticated))?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let map_admission =
            |error| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(error)));
        let (_, attempt) = candidate_landing_proposal(&context, command).map_err(map_admission)?;
        let tx_id = attempt
            .derive()
            .map_err(|_| {
                map_admission(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        if let OutcomeLookup::Decided(terminal) = self
            .resolve_outcome_checkpointed_in(request, tx_id)
            .await
            .map_err(|error| map_admission(error.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|error| map_admission(error.into()))?;
            return Ok((tx_id, terminal));
        }
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota
            .evaluate(&authenticated.principal_id())
            .map_err(receive_error)?;
        let staging = ReceiveStaging::default();
        let (quarantined, _) = self
            .quarantine_reviewed_bundle_in(
                request,
                &command.merge.target_ref,
                command.merge.target_tip_before,
                command.merge.merge_commit,
                input,
                std::slice::from_ref(&command.merge.source_ref),
                Some(&staging),
            )
            .await?;
        // This proof is deliberately not admitted: it represents only a ref
        // command. The queue admission driver revalidates all coupled effects
        // against its own current authenticated predecessor using this staging.
        drop(quarantined);
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self
                .durable_admission_projection(&context)
                .map_err(map_admission)?
                .with_authentication(authenticated.authentication()),
            object_limits: MergeObjectLimits {
                max_reused_blob_bytes: self.reused_merge_blob_limit(),
                ..MergeObjectLimits::default()
            },
            staging: Some(&staging),
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        let terminal = Box::pin(admit_candidate_landing_async(
            &self.authority,
            request.authority(),
            &context,
            command,
            limits,
            &projection,
        ))
        .await
        .map_err(map_admission)?;
        Ok((tx_id, terminal))
    }
}
