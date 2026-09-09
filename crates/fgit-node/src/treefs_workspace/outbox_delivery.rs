//! Local authenticated composition for bounded canonical forge delivery.

use fgit_admission::merge::native::settlement::{OutboxDestination, deliver_outbox_async};
use fgit_admission::{AdmissionContext, AdmissionLimits};
use fgit_codec::CanonicalOutboxEffectState;
use fgit_resource::ReconcilePolicy;
use fgit_runtime::BudgetClass;
use fgit_types::{AsciiSlug, RefusalCode};
use fsqlite_types::cx::Cx;

use crate::{
    LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode,
    PackContextCheckpoint, checkpoint_pack_context,
};

impl OneNode {
    /// Mints the operator's finite background-controller context for one outbox
    /// reconciliation invocation. A worker may publish several transactions
    /// and await a destination; it is not one database command. The same
    /// context stays attached throughout the invocation, including drain.
    /// This does not spawn work or renew an existing request's budget.
    #[must_use]
    pub fn outbox_delivery_context(&self) -> NodeRequestContext {
        let authority = Cx::new();
        authority.set_native_cx(self.runtime.request_cx(BudgetClass::BackgroundController));
        NodeRequestContext { authority }
    }

    /// Drives one retained forge delivery with an explicitly configured adapter.
    /// Repository text cannot select this capability or its endpoint. The local
    /// authenticated service owns the request context and finite retry policy.
    /// No worker is spawned; this request awaits transport drain and settlement.
    /// A background worker uses [`Self::outbox_delivery_context`]. Callers may
    /// instead supply a shorter request context; exhaustion keeps any published
    /// progress available for a later independently budgeted invocation.
    pub async fn deliver_forge_outbox_in<D: OutboxDestination<Cx>>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        key: AsciiSlug,
        destination: &mut D,
        policy: ReconcilePolicy,
        limits: AdmissionLimits,
    ) -> Result<CanonicalOutboxEffectState, NodeReceiveTransportRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
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
        let checkpoint = || match checkpoint_pack_context(request.authority()) {
            PackContextCheckpoint::Live => Ok(()),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: Some(_),
            } => Err(RefusalCode::ResourceBudgetExceeded),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: None,
            } => Err(RefusalCode::CancellationInProgress),
        };
        deliver_outbox_async(
            &self.authority,
            request.authority(),
            &context,
            key,
            &projection,
            destination,
            policy,
            limits,
            &checkpoint,
        )
        .await
        .map_err(|error| NodeReceiveTransportRefusal::Admission(Box::new(error)))
    }
}
