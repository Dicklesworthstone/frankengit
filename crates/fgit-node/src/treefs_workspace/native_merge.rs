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
use fgit_authority::{AuthenticatedHead, IdempotencyKey, TerminalOutcome};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_forge::aggregate::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::NativeMerge;
use fgit_reference::intent::TransactionRequest;
use fgit_txn::TransactionFoldReport;
use fgit_types::{PrincipalId, RefusalCode, TxId};
use fsqlite_types::cx::Cx;

use super::publication::receive_error;
use super::{NodeWorkspaceRefusal, workspace_request_live};
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
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
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

    /// Apply an independently reviewed merge artifact through native admission.
    ///
    /// The bundle must advertise exactly the reviewed target branch/candidate.
    /// Its prerequisite frontier must include target-before and may contain up
    /// to 64 unique commits, all verified against authority-selected history.
    /// This accommodates ordinary Git bundles listing target and base boundary
    /// commits. Unknown capabilities, partial-clone and multi-ref bundles remain
    /// unsupported; workspace apply separately retains its one-prerequisite
    /// profile. Both operations use the same bounded parser and quarantine.
    ///
    /// The caller supplies all review coordinates, PR identity/version and the
    /// authenticated local principal independently of the artifact. A version
    /// of NewStream records a merge receipt, not fabricated PR opening/approval.
    /// The reviewed tree is not recomputed or silently changed by this method.
    ///
    /// Production quarantine only stages verified native objects. Its ref-only
    /// proof is NEVER admitted: the native merge driver independently validates
    /// ordered parents, common ancestry and closure against its current basis,
    /// then publishes ref, forge position and outbox together. A race between
    /// quarantine and admission cannot authorize a stale merge. An identical
    /// retry resolves its original terminal result rather than moving the ref
    /// back or creating a second delivery. The returned TxId is that native seal.
    ///
    /// # Errors
    /// Envelope/review mismatch and unavailable intake refuse before admission.
    /// Canonical decisions are returned as terminal outcomes, not inferred from
    /// staged object existence. Infrastructure failures retain uncertainty;
    /// cancellation is never interpreted as evidence of non-commit.
    pub async fn apply_merge_bundle_durable_in(
        &self,
        request: &NodeRequestContext,
        principal: PrincipalId,
        idempotency_key: &[u8],
        pull_request: PullRequestNumber,
        expected_version: ExpectedVersion,
        merge: &NativeMerge,
        input: &[u8],
    ) -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal> {
        let map_admission = |error| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(error)));
        let key = IdempotencyKey::new(idempotency_key.to_vec())
            .map_err(|_| NodeWorkspaceRefusal::InvalidWorkspaceCandidate("invalid bounded idempotency key"))?;
        let intent = NativeMergeIntent::new(pull_request, expected_version, merge.clone())
            .map_err(map_admission)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: principal,
            idempotency_key: key,
            object_format: self.object_format,
        };
        let attempt = intent.seal_attempt(&context).map_err(map_admission)?;
        let tx_id = attempt.derive()
            .map_err(|_| NodeWorkspaceRefusal::InvalidWorkspaceCandidate("native merge identity derivation refused"))?.0;
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota.evaluate(&principal).map_err(receive_error)?;
        let (quarantined, _) = self.quarantine_reviewed_bundle_in(
            request,
            &merge.target_ref,
            merge.target_tip_before,
            merge.merge_commit,
            input,
            std::slice::from_ref(&merge.source_ref),
        ).await?;
        // A received ref command is not a merge decision. The native driver
        // re-reads the staged candidate and authenticates a fresh exact basis;
        // retaining or admitting this source-only proof would split the effect.
        drop(quarantined);
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self.durable_admission_projection(&context).map_err(map_admission)?,
            object_limits: MergeObjectLimits::default(),
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        let terminal = admit_native_merge_async(
            &self.authority, request.authority(), &context, &intent,
            AdmissionLimits::default(), &projection,
        ).await.map_err(map_admission)?;
        // Preserve known terminal results even if cancellation arrives now.
        Ok((tx_id, terminal))
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
        let projection = NodeNativeMergeProjection {
            node: self,
            inner,
            object_limits,
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        admit_native_merge_async(
            &self.authority, request.authority(), &context, intent, limits, &projection,
        )
        .await
        .map_err(|error| NodeReceiveTransportRefusal::Admission(Box::new(error)))
    }
}

/// The existing asynchronous projection plus real native-object validation.
/// This deliberately does not implement synchronous staging callbacks.
pub(super) struct NodeNativeMergeProjection<'node> {
    pub(super) node: &'node OneNode,
    pub(super) inner: DurableAsyncAdmissionProjection<'node>,
    pub(super) object_limits: MergeObjectLimits,
    /// Derived from the session whose exclusive guard spans this projection.
    pub(super) workspace: Option<([u8; 32], fgit_types::GitOid, fgit_types::GitOid)>,
    pub(super) workspace_capability: Option<fgit_treefs::TreeCapability>,
    pub(super) workspace_clock_floor: u64,
}

impl NodeNativeMergeProjection<'_> {
    fn workspace_live(&self) -> Result<(), RefusalCode> {
        if let Some(capability) = &self.workspace_capability {
            let now = self
                .workspace_clock_floor
                .max(self.node.runtime.now().as_nanos());
            capability
                .authorize_root(now)
                .map_err(|error| match error {
                    fgit_treefs::CapabilityRefusal::Expired { .. } => {
                        RefusalCode::CapabilityExpired
                    }
                    _ => RefusalCode::CapabilityScopeViolation,
                })?;
        }
        Ok(())
    }
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
    fn workspace_snapshot_digest(&self) -> Result<[u8; 32], ProjectionFailure> {
        self.workspace_live().map_err(ProjectionFailure::Refuse)?;
        self.workspace
            .map(|(digest, _, _)| digest)
            .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))
    }
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
    fn merge_publication_checkpoint(&self, cx: &Cx) -> Result<(), RefusalCode> {
        self.merge_checkpoint(cx)?;
        self.workspace_live()
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
            let closure = result?;
            if let Some((_, expected_tree, expected_base)) = self.workspace {
                if merge.target_tip_before != expected_base {
                    return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale));
                }
                use fgit_git_object::{
                    AcceptanceProfile, ObjectType, ParsedObject, parse_object_body,
                };
                let read = source.read_object(&merge.merge_commit);
                if exhaustion.get().is_some() {
                    return Err(ProjectionFailure::Unavailable(
                        RefusalCode::ResourceBudgetExceeded,
                    ));
                }
                self.merge_checkpoint(cx)
                    .map_err(ProjectionFailure::Unavailable)?;
                let (kind, body) =
                    read.map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
                let ParsedObject::Commit(commit) = parse_object_body(
                    ObjectType::Commit,
                    &body,
                    AcceptanceProfile::GitCompatibleImport,
                    &source.parse_limits(),
                )
                .map_err(|_| ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?
                else {
                    return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
                };
                let actual_tree = commit
                    .tree_reference()
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .and_then(|text| {
                        fgit_types::GitOid::from_hex(
                            self.node.object_format,
                            &text.to_ascii_lowercase(),
                        )
                        .ok()
                    });
                if kind != ObjectType::Commit || actual_tree != Some(expected_tree) {
                    return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale));
                }
            }
            Ok(closure)
        }
    }
}

#[cfg(test)]
mod sealed_tests;
