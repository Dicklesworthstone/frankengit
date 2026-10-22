//! Local authenticated composition for bounded canonical forge delivery.

mod receipt;
mod selection;
pub use receipt::RetiredForgeDeliveryReceipt;

use fgit_admission::merge::native::dispatch::{
    DispatchResult, DispatchTransport, dispatch_outbox_async,
};
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
    /// Run an explicitly owned, immutable set of Weak routes. Canonical markers
    /// precede transport I/O; every observed outcome and terminal removal uses
    /// the same authority-head publication as the original obligation.
    pub async fn dispatch_forge_outbox_in<T, N>(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        key: AsciiSlug,
        transport: &mut T,
        send_allowance: u32,
        limits: AdmissionLimits,
        now: &N,
    ) -> Result<DispatchResult, NodeReceiveTransportRefusal>
    where
        T: DispatchTransport<Cx>,
        N: Fn() -> Result<u64, RefusalCode>,
    {
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
            .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?;
        let checkpoint = || match checkpoint_pack_context(request.authority()) {
            PackContextCheckpoint::Live => Ok(()),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: Some(_),
            } => Err(RefusalCode::ResourceBudgetExceeded),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: None,
            } => Err(RefusalCode::CancellationInProgress),
        };
        dispatch_outbox_async(
            &self.authority,
            request.authority(),
            &context,
            key,
            &projection,
            transport,
            send_allowance,
            limits,
            &checkpoint,
            now,
        )
        .await
        .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))
    }

    /// Read canonical route ownership before selecting a local dispatcher plan.
    /// A journal observation cannot stand in for a missing canonical marker.
    pub async fn read_forge_dispatch_in(
        &self,
        request: &NodeRequestContext,
        key: AsciiSlug,
        expected_head: Option<fgit_types::RepositoryAuthorityHeadId>,
    ) -> Result<
        Option<fgit_admission::merge::native::dispatch::CanonicalDispatchProgress>,
        selection::ForgeDeliveryReadRefusal,
    > {
        use selection::{ForgeDeliveryReadRefusal as R, checkpoint};
        checkpoint(request)?;
        fgit_types::cell::admits_read(self.cell_state(), fgit_types::cell::ReadMode::Current)
            .map_err(R::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|e| R::Authority(Box::new(e)))?;
        if expected_head.is_some_and(|h| h != selected.basis().id()) {
            return Err(R::SnapshotMoved);
        }
        let state = fgit_admission::merge::native::delivery::read_in(
            &self.authority,
            request.authority(),
            selected.basis(),
            &|| checkpoint(request).is_err(),
        )
        .await
        .map_err(|e| R::Admission(Box::new(e)))?;
        let entry = state.outbox.entry(key).ok_or(R::MissingDelivery)?;
        let progress = fgit_admission::merge::native::dispatch::read_dispatch_progress(
            &self.authority,
            request.authority(),
            selected.basis(),
            entry,
            &|| checkpoint(request).is_err(),
        )
        .await
        .map_err(|e| R::Admission(Box::new(e)))?;
        checkpoint(request)?;
        Ok(progress)
    }
    /// Authenticate a failed/escalated source for an explicit new replay intent.
    /// Local dead-letter diagnostics alone never supply canonical provenance.
    pub async fn read_forge_replay_source_in(
        &self,
        request: &NodeRequestContext,
        key: AsciiSlug,
        destination: AsciiSlug,
        expected_head: Option<fgit_types::RepositoryAuthorityHeadId>,
    ) -> Result<
        (
            fgit_types::RepositoryAuthorityHeadId,
            CanonicalOutboxEffectState,
            fgit_forge::ForgeEventBatch,
        ),
        selection::ForgeDeliveryReadRefusal,
    > {
        use selection::{ForgeDeliveryReadRefusal as R, checkpoint};
        checkpoint(request)?;
        fgit_types::cell::admits_read(self.cell_state(), fgit_types::cell::ReadMode::Current)
            .map_err(R::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|e| R::Authority(Box::new(e)))?;
        if expected_head.is_some_and(|h| h != selected.basis().id()) {
            return Err(R::SnapshotMoved);
        }
        let source = fgit_admission::merge::native::dispatch::replay::read_source(
            &self.authority,
            request.authority(),
            selected.basis(),
            key,
            destination,
            &|| checkpoint(request).is_err(),
        )
        .await
        .map_err(|e| R::Admission(Box::new(e)))?;
        checkpoint(request)?;
        let events = crate::read_evidence_body_in(
            &self.authority,
            request.authority(),
            self.repository_id,
            crate::ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
            source.payload_root(),
            &|| checkpoint(request).is_err(),
        )
        .await
        .map_err(|e| R::Authority(Box::new(e)))?;
        checkpoint(request)?;
        Ok((selected.basis().id(), source, events))
    }

    /// Seal and publish a new one-send replay responsibility. This creates no
    /// forge event and never reopens or edits the source delivery's outcome.
    pub async fn enqueue_forge_replay_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        intent: &fgit_admission::merge::native::dispatch::replay::ReplayIntent,
        limits: AdmissionLimits,
    ) -> Result<AsciiSlug, NodeReceiveTransportRefusal> {
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
            .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?;
        let checkpoint = || match checkpoint_pack_context(request.authority()) {
            PackContextCheckpoint::Live => Ok(()),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: Some(_),
            } => Err(RefusalCode::ResourceBudgetExceeded),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: None,
            } => Err(RefusalCode::CancellationInProgress),
        };
        fgit_admission::merge::native::dispatch::replay::enqueue_replay_async(
            &self.authority,
            request.authority(),
            &context,
            intent,
            &projection,
            limits,
            &checkpoint,
        )
        .await
        .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))
    }
    /// Read the original canonical route plan for explicit replay eligibility,
    /// including retired sources, without constructing a transport capability.
    pub async fn read_forge_dispatch_plan_in(
        &self,
        request: &NodeRequestContext,
        key: AsciiSlug,
        destination: AsciiSlug,
        expected_head: Option<fgit_types::RepositoryAuthorityHeadId>,
    ) -> Result<
        Option<fgit_admission::merge::native::dispatch::CanonicalDispatchProgress>,
        selection::ForgeDeliveryReadRefusal,
    > {
        use selection::{ForgeDeliveryReadRefusal as R, checkpoint};
        checkpoint(request)?;
        fgit_types::cell::admits_read(self.cell_state(), fgit_types::cell::ReadMode::Current)
            .map_err(R::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|e| R::Authority(Box::new(e)))?;
        if expected_head.is_some_and(|h| h != selected.basis().id()) {
            return Err(R::SnapshotMoved);
        }
        let plan = fgit_admission::merge::native::dispatch::read_dispatch_plan(
            &self.authority,
            request.authority(),
            selected.basis(),
            key,
            destination,
            &|| checkpoint(request).is_err(),
        )
        .await
        .map_err(|e| R::Admission(Box::new(e)))?;
        checkpoint(request)?;
        Ok(plan)
    }
}
