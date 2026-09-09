//! Production composition for reviewed native merge publication.
//! The local authenticated caller supplies an intent. Native objects and all
//! predecessor state are resolved here, never accepted as caller-minted roots.

use std::cell::Cell;
use std::future::Future;

use fgit_admission::merge::native::objects::{MergeObjectLimits, validate_merge_objects};
use fgit_admission::merge::native::{
    NativeMergeIntent, NativeMergeProjection, admit_native_merge_async,
    admit_sealed_native_merge_async,
};
use fgit_admission::merge::{NativeMergeBasis, SealedMerge};
use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, AsyncAdmissionProjection,
    CommitMaterialization, ProjectionFailure, RefusalMaterialization, ValidatedClosure,
};
use fgit_authority::{AuthenticatedHead, TerminalOutcome};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_reference::intent::TransactionRequest;
use fgit_txn::TransactionFoldReport;
use fgit_types::{RefusalCode, TxId};
use fsqlite_types::cx::Cx;

use crate::{
    DurableAsyncAdmissionProjection, LoopbackReceiveSession, NodeReceiveTransportRefusal,
    NodeRequestContext, OneNode, PackContextCheckpoint, VerifiedFabricPackSource,
    async_projection_unavailable, checkpoint_pack_context,
};

impl OneNode {
    /// Native continuation of the original sealed-package node API. Preserve
    /// its request identity, but use the same native-object validation and
    /// coupled Ref + Forge + Outbox publication as the reviewed-intent API.
    /// Legacy internal-digest events are deliberately not adapted here.
    pub(crate) async fn admit_sealed_native_merge_durable_in(
        &self,
        request: &NodeRequestContext,
        context: &AdmissionContext,
        sealed: &SealedMerge<'_>,
        limits: AdmissionLimits,
    ) -> Result<TerminalOutcome, AdmissionError> {
        // Preserve the trusted local-context API. The node validates every
        // repository coordinate before constructing its native object source.
        let inner = self.durable_admission_projection(context)?;
        let projection = NodeNativeMergeProjection {
            node: self,
            inner,
            object_limits: MergeObjectLimits::default(),
        };
        admit_sealed_native_merge_async(
            &self.authority,
            request.authority(),
            context,
            sealed,
            limits,
            &projection,
        )
        .await
    }

    /// Publish a reviewed two-parent merge, its forge transition and pending
    /// delivery obligation in one RCR/head CAS on the embedded authority.
    ///
    /// Candidate objects are re-read, hashed and traversed before publication.
    /// Source, target and base must be authority-selected; ordered parents must
    /// be target-before and source. All preparation and staging uses the
    /// caller's request context. No Git process or alternative database is used.
    ///
    /// Authentication remains the caller's responsibility at this local
    /// composition boundary. An enqueued delivery is not a delivery receipt,
    /// PR approval or assertion that an external consumer has processed it.
    pub async fn admit_native_merge_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        intent: &NativeMergeIntent,
        limits: AdmissionLimits,
        object_limits: MergeObjectLimits,
    ) -> Result<TerminalOutcome, NodeReceiveTransportRefusal> {
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
        let inner = self
            .durable_admission_projection(&context)
            .map_err(|error| NodeReceiveTransportRefusal::Admission(Box::new(error)))?;
        let projection = NodeNativeMergeProjection { node: self, inner, object_limits };
        admit_native_merge_async(
            &self.authority, request.authority(), &context, intent, limits, &projection,
        )
        .await
        .map_err(|error| NodeReceiveTransportRefusal::Admission(Box::new(error)))
    }
}

struct NodeNativeMergeProjection<'node> {
    node: &'node OneNode,
    inner: DurableAsyncAdmissionProjection<'node>,
    object_limits: MergeObjectLimits,
}

impl AsyncAdmissionProjection<FsqliteAuthorityStore> for NodeNativeMergeProjection<'_> {
    fn snapshot_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        // The shared projection already retains symbolic HEAD and binds its
        // prepared ref state to this exact receipt; do not rebuild that state.
        self.inner.snapshot_async(authority, cx, basis, authenticated)
    }

    fn materialize_commit_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner.materialize_commit_async(authority, cx, basis, request, fold, closure)
    }

    fn materialize_refusal_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner.materialize_refusal_async(authority, cx, basis, tx_id, code)
    }
}

impl NativeMergeProjection<FsqliteAuthorityStore> for NodeNativeMergeProjection<'_> {
    fn merge_checkpoint(&self, cx: &Cx) -> Result<(), RefusalCode> {
        match checkpoint_pack_context(cx) {
            PackContextCheckpoint::Live => Ok(()),
            PackContextCheckpoint::Stopped { budget_exhaustion: Some(_) } => {
                Err(RefusalCode::ResourceBudgetExceeded)
            }
            PackContextCheckpoint::Stopped { budget_exhaustion: None } => {
                Err(RefusalCode::CancellationInProgress)
            }
        }
    }

    #[expect(clippy::manual_async_fn, reason = "explicit Send is the resolution contract")]
    fn resolve_merge_basis_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<NativeMergeBasis, ProjectionFailure>> + Send + 'a {
        async move {
            if authenticated
                .body()
                .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptInvalid))?
                != *basis.body()
            {
                return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale));
            }
            let prepared = self
                .inner
                .prepared
                .lock()
                .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::InternalInvariantBreach))?
                .take()
                .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
            if prepared.basis != *basis {
                return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale));
            }
            // Resolve exact root/repository bindings, payloads and effect
            // predecessor chains through the same reader used after reopen.
            let delivery = fgit_admission::merge::native::delivery::read_in(
                authority, cx, basis, &|| self.merge_checkpoint(cx).is_err(),
            )
            .await
            .map_err(|error| async_projection_unavailable(
                crate::AdmissionMaterializationRefusal::Delivery(Box::new(error)),
            ))?;
            self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
            Ok(NativeMergeBasis {
                refs: prepared.ref_state,
                root_layout: prepared.root_layout,
                forge: delivery.forge,
                outbox: delivery.outbox,
            })
        }
    }

    #[expect(clippy::manual_async_fn, reason = "explicit Send is the native validator's cross-thread contract")]
    fn validate_merge_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        async move {
            let selected = self.inner.materializer.materialize_exact_in(
                authority, cx, self.node.repository_id, basis, authenticated,
                &|| self.merge_checkpoint(cx).is_err(),
            )
            .await
            .map_err(async_projection_unavailable)?;
            let merge = intent.merge()
                .map_err(|_| ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
            if [merge.source_tip, merge.target_tip_before, merge.base_tip].iter()
                .any(|oid| !selected.selected_closure().closure().objects().contains(oid))
            {
                return Err(ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete));
            }
            let exhaustion = Cell::new(None);
            let source = VerifiedFabricPackSource {
                fabric: &self.node.fabric,
                object_format: self.node.object_format,
                maximum_object_bytes: self.object_limits.max_object_bytes
                    .min(usize::try_from(self.node.max_object_bytes).unwrap_or(usize::MAX)),
                database_context: cx,
                database_exhaustion: &exhaustion,
                session_is_live: None,
            };
            let mut live = || match checkpoint_pack_context(cx) {
                PackContextCheckpoint::Live => true,
                PackContextCheckpoint::Stopped { budget_exhaustion } => {
                    if let Some(dimension) = budget_exhaustion {
                        exhaustion.set(Some(dimension));
                    }
                    false
                }
            };
            let result = validate_merge_objects(&source, merge, self.object_limits, &mut live);
            if exhaustion.get().is_some() {
                return Err(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded));
            }
            result
        }
    }
}

#[cfg(test)]
mod sealed_tests;
