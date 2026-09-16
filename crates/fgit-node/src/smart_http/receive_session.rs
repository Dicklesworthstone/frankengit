//! Node-owned authentication and publication gates for continuing HTTP pushes.

use fgit_admission::policy_bridge::receive_session;
use fgit_admission::{
    AdmissionContext, AdmissionLimits, AdmissionResult, BasisBoundValidatedReceive,
};

use super::NodeSmartHttpRefusal;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};

impl OneNode {
    /// Preserve the loopback receive boundary's authentication and cell policy
    /// while using the proof-preserving per-command session coordinator.
    pub(super) async fn admit_continuing_http_receive_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        validated: &BasisBoundValidatedReceive,
        limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeSmartHttpRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeSmartHttpRefusal::UnauthenticatedReceive)?;
        // Intake/quota and full quarantine validation already ran in the RPC
        // adapter. StagingOnly still retains staged work but cannot publish it.
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
}
