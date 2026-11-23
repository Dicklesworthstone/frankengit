//! Exact PR-label publication uses the original session and request context.
//! Independent label versions preserve reviewed PR content across triage.

use fgit_admission::merge::native::pull_request::labels;
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::event::pull_request_labels::{PullRequestLabelsCommand, PullRequestLabelsIntent};
use fgit_types::{RefusalCode, TxId};

use crate::treefs_workspace::native_merge::NodeNativeMergeProjection;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};

impl OneNode {
    /// Add the sealed labels to the current set, revalidating every CAS basis.
    /// Overlapping additions are idempotent as sets, while the original key
    /// retains one terminal outcome even if a later replacement removes them.
    pub async fn admit_pull_request_add_labels_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        intent: &PullRequestLabelsIntent,
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
        let map = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let (_, attempt) = labels::addition_proposal(&context, intent).map_err(map)?;
        let tx = attempt
            .derive()
            .map_err(|_| {
                map(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        if let OutcomeLookup::Decided(terminal) = self
            .resolve_outcome_checkpointed_in(request, tx)
            .await
            .map_err(|error| map(error.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|error| map(error.into()))?;
            return Ok((tx, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection =
            NodeNativeMergeProjection::metadata(self, &context, authenticated).map_err(map)?;
        let terminal = Box::pin(labels::admit_addition_async(
            &self.authority,
            request.authority(),
            &context,
            intent,
            limits,
            &projection,
        ))
        .await
        .map_err(map)?;
        Ok((tx, terminal))
    }

    /// Replace a native PR's complete label set at an exact label version.
    /// The authenticated session supplies its actor; ordinary PR write grants
    /// do not imply a ref mutation, merge approval or an administrator role.
    /// Open, closed and merged native PRs remain valid subjects while current
    /// canonical visibility permits their unchanged source and target names.
    pub async fn admit_pull_request_labels_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &PullRequestLabelsCommand,
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
        let map = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let (_, attempt) = labels::proposal(&context, command).map_err(map)?;
        let tx = attempt
            .derive()
            .map_err(|_| {
                map(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        // Original outcomes precede current quota, cell-readiness and metadata
        // checks; resealing still refuses semantic reuse of the original key.
        if let OutcomeLookup::Decided(terminal) = self
            .resolve_outcome_checkpointed_in(request, tx)
            .await
            .map_err(|error| map(error.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|error| map(error.into()))?;
            return Ok((tx, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection =
            NodeNativeMergeProjection::metadata(self, &context, authenticated).map_err(map)?;
        let terminal = Box::pin(labels::admit_async(
            &self.authority,
            request.authority(),
            &context,
            command,
            limits,
            &projection,
        ))
        .await
        .map_err(map)?;
        Ok((tx, terminal))
    }
}
