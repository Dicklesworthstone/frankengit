//! Trusted-local administration of mandatory repository review protection.
//! All live publication routes enforce the selected policy without an opt-in.
use super::native_merge::NodeNativeMergeProjection;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use fgit_admission::merge::native::objects::MergeObjectLimits;
use fgit_admission::merge::native::protection::{self, ProtectionState};
use fgit_admission::{AdmissionContext, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::event::protection::ProtectionCommand;
use fgit_types::{RefusalCode, TxId};

impl OneNode {
    /// First installation requires an authorized repository operator. Later
    /// replacement/disable/ownership rotation is checked against CURRENT policy
    /// administrators at each exact CAS basis. This local API does not establish
    /// remote identity or confer repository-admin rights from a supplied ID.
    pub async fn admit_review_protection_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &ProtectionCommand,
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
        let (_, attempt) = protection::proposal(&context, command)
            .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?;
        let tx = attempt
            .derive()
            .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e.into())))?
            .0;
        checkpoint(request)?;
        if let OutcomeLookup::Decided(outcome) = fgit_authority::resolve_outcome_async(
            &self.authority,
            request.authority(),
            &context.head_key,
            context.tenant_id,
            context.repository_id,
            tx,
        )
        .await
        .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e.into())))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e.into())))?;
            return Ok((tx, outcome));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&context.principal_id)?;
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self
                .durable_admission_projection(&context)
                .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?,
            object_limits: MergeObjectLimits::default(),
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        let terminal = protection::admit_async(
            &self.authority,
            request.authority(),
            &context,
            command,
            limits,
            &projection,
        )
        .await
        .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?;
        Ok((tx, terminal))
    }
    /// Read one complete policy at one authenticated current repository head.
    /// An absent selected body is an error, not disabled protection.
    pub async fn read_review_protection_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<ProtectionState, NodeReceiveTransportRefusal> {
        checkpoint(request)?;
        fgit_types::cell::admits_read(self.cell_state(), fgit_types::cell::ReadMode::Current)
            .map_err(NodeReceiveTransportRefusal::CellState)?;
        let selected = self.materialize_admission_in(request).await.map_err(|e| {
            NodeReceiveTransportRefusal::Admission(Box::new(
                fgit_admission::AdmissionError::AsyncProjectionUnavailable(
                    match crate::async_projection_unavailable(e) {
                        fgit_admission::ProjectionFailure::Unavailable(code)
                        | fgit_admission::ProjectionFailure::Refuse(code) => code,
                    },
                ),
            ))
        })?;
        let value = protection::read_at(
            &self.authority,
            request.authority(),
            selected.basis(),
            &|| checkpoint(request).is_err(),
        )
        .await
        .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?;
        checkpoint(request)?;
        Ok(value)
    }
}

fn checkpoint(request: &NodeRequestContext) -> Result<(), NodeReceiveTransportRefusal> {
    let code = match crate::checkpoint_pack_context(request.authority()) {
        crate::PackContextCheckpoint::Live => return Ok(()),
        crate::PackContextCheckpoint::Stopped {
            budget_exhaustion: Some(_),
        } => RefusalCode::ResourceBudgetExceeded,
        crate::PackContextCheckpoint::Stopped {
            budget_exhaustion: None,
        } => RefusalCode::CancellationInProgress,
    };
    Err(NodeReceiveTransportRefusal::Admission(Box::new(
        fgit_admission::AdmissionError::AsyncProjectionUnavailable(code),
    )))
}
