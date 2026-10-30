//! Production composition for reviewed native merge publication.
//! The local authenticated caller supplies an intent. Native objects and all
//! predecessor state are resolved here, never accepted as caller-minted roots.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::future::Future;

use fgit_admission::evidence::AdmissionAuthentication;
use fgit_admission::merge::native::objects::{
    CanonicalObjectHeader, FrontierObjectHeaders, MAX_REUSED_BLOB_BYTES, MergeObjectLimits,
    ObjectFrontier, validate_fast_forward_objects_above, validate_merge_objects_above,
    validate_squash_objects_above,
};
use fgit_admission::merge::native::{
    NativeMergeIntent, NativeMergeMethod, NativeMergeProjection, admit_native_merge_async,
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
use fgit_pack::{PackError, PackWriteError};
use fgit_reference::intent::TransactionRequest;
use fgit_txn::TransactionFoldReport;
use fgit_types::{GitOid, PrincipalId, RefusalCode, TxId};
use fsqlite_types::cx::Cx;

use super::publication::receive_error;
use super::{NodeWorkspaceRefusal, workspace_request_live};
use crate::receive_staging::ReceiveStaging;
use crate::{
    DurableAsyncAdmissionProjection, LoopbackReceiveSession, NodeReceiveTransportRefusal,
    NodeRequestContext, OneNode, PackContextCheckpoint, VerifiedFabricPackSource,
    async_projection_unavailable, checkpoint_pack_context,
};

impl OneNode {
    /// The configured selected-blob policy also bounds omitted admitted blobs.
    /// It never widens a native metadata/body parser or permits unselected reads.
    pub(crate) fn reused_merge_blob_limit(&self) -> usize {
        self.selected_pack_limits
            .max_object_bytes
            .min(
                self.service_config
                    .selected_pack_blob_limit
                    .unwrap_or_else(|| {
                        usize::try_from(self.max_object_bytes)
                            .unwrap_or(usize::MAX)
                            .min(MergeObjectLimits::default().max_reused_blob_bytes)
                    }),
            )
            .min(usize::try_from(MAX_REUSED_BLOB_BYTES).unwrap_or(usize::MAX))
    }
}

pub(super) fn read_frontier_header(
    source: &VerifiedFabricPackSource<'_>,
    id: &GitOid,
    maximum_blob_bytes: usize,
) -> Result<CanonicalObjectHeader, PackWriteError> {
    let metadata_limit = source.buffered_object_limit();
    let (object_type, body_bytes) =
        source.read_object_header_within(id, metadata_limit.max(maximum_blob_bytes))?;
    let limit = if object_type == fgit_git_object::ObjectType::Blob {
        maximum_blob_bytes
    } else {
        metadata_limit
    };
    if body_bytes > limit {
        return Err(PackError::ObjectSizeLimit {
            actual: body_bytes,
            limit,
        }
        .into());
    }
    Ok(CanonicalObjectHeader {
        id: *id,
        object_type,
        body_bytes,
    })
}

struct NativeFrontierHeaders<'source, 'selected, 'staging> {
    source: VerifiedFabricPackSource<'source>,
    selected: &'selected BTreeSet<GitOid>,
    staging: &'staging ReceiveStaging,
    maximum_blob_bytes: usize,
}
impl FrontierObjectHeaders for NativeFrontierHeaders<'_, '_, '_> {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError> {
        self.source.session_checkpoint()?;
        if !self.selected.contains(id) {
            return Err(PackWriteError::MissingCanonicalObject(*id));
        }
        if self.staging.contains(*id) {
            // Supplied bytes retain full verification, even when their native
            // identity is also present in the selected predecessor closure.
            return Ok(None);
        }
        read_frontier_header(&self.source, id, self.maximum_blob_bytes).map(Some)
    }
}

/// Preserve the legacy merge seal by default. A squash is an explicit PR
/// operation, and a fast-forward has its own existing-object publication path.
pub(in crate::treefs_workspace) fn bundle_merge_intent(
    number: PullRequestNumber,
    version: ExpectedVersion,
    merge: NativeMerge,
    method: NativeMergeMethod,
) -> Result<NativeMergeIntent, NodeWorkspaceRefusal> {
    let intent = match (method, version) {
        (NativeMergeMethod::MergeCommit, version) => NativeMergeIntent::new(number, version, merge),
        (NativeMergeMethod::Squash, ExpectedVersion::Exactly(version)) => {
            NativeMergeIntent::squash(number, version, merge)
        }
        (NativeMergeMethod::Squash, ExpectedVersion::NewStream) => {
            return Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate(
                "squash requires an existing pull request and exact positive version",
            ));
        }
        (NativeMergeMethod::FastForwardOnly, _) => {
            return Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate(
                "fast-forward uses the existing-object merge publication path",
            ));
        }
    };
    intent.map_err(|error| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(error))))
}

impl OneNode {
    /// Compute the original sealed-package API's exact evidence under the
    /// current canonical policy. This read-only preparation validates native
    /// objects and review/check gates but neither seals nor publishes a request.
    /// A later publication independently checks the same evidence; a policy or
    /// ref change can make it stale. The optional digest selects the existing
    /// workspace-bound seal profile; it does not claim workspace ownership.
    /// This context-only API retains operator-asserted authentication. Use the
    /// session-bound variant when a transport verified the caller's credential.
    pub async fn prepare_sealed_merge_evidence_in(
        &self,
        request: &NodeRequestContext,
        context: &AdmissionContext,
        sealed: &SealedMerge<'_>,
        workspace_snapshot: Option<[u8; 32]>,
    ) -> Result<
        fgit_admission::merge::native::policy_preparation::PreparedSealedMergeEvidence,
        AdmissionError,
    > {
        self.prepare_sealed_merge_evidence_with_authentication_in(
            request,
            context,
            sealed,
            workspace_snapshot,
            AdmissionAuthentication::OperatorAssertion,
        )
        .await
    }

    /// Prepare exact offered evidence using the identity, retry key, and
    /// authentication method retained by the publication session. The caller
    /// supplies the same session and workspace digest to later admission;
    /// credential provenance is never inferred from a principal ID.
    ///
    /// Like the context-only variant, this neither seals nor publishes a
    /// request and does not claim ownership of the optional workspace digest.
    /// Admission revalidates the offer against its actual publication basis.
    pub async fn prepare_sealed_merge_evidence_for_session_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        sealed: &SealedMerge<'_>,
        workspace_snapshot: Option<[u8; 32]>,
    ) -> Result<
        fgit_admission::merge::native::policy_preparation::PreparedSealedMergeEvidence,
        NodeWorkspaceRefusal,
    > {
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
        self.prepare_sealed_merge_evidence_with_authentication_in(
            request,
            &context,
            sealed,
            workspace_snapshot,
            authenticated.authentication(),
        )
        .await
        .map_err(|error| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(error))))
    }

    async fn prepare_sealed_merge_evidence_with_authentication_in(
        &self,
        request: &NodeRequestContext,
        context: &AdmissionContext,
        sealed: &SealedMerge<'_>,
        workspace_snapshot: Option<[u8; 32]>,
        authentication: AdmissionAuthentication,
    ) -> Result<
        fgit_admission::merge::native::policy_preparation::PreparedSealedMergeEvidence,
        AdmissionError,
    > {
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self
                .durable_admission_projection(context)?
                .with_authentication(authentication),
            object_limits: MergeObjectLimits {
                max_reused_blob_bytes: self.reused_merge_blob_limit(),
                ..MergeObjectLimits::default()
            },
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
            staging: None,
        };
        fgit_admission::merge::native::policy_preparation::prepare_sealed_native_merge_evidence_async(
            &self.authority, request.authority(), context, sealed, workspace_snapshot, &projection,
        ).await
    }

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
            object_limits: MergeObjectLimits {
                max_reused_blob_bytes: self.reused_merge_blob_limit(),
                ..MergeObjectLimits::default()
            },
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
            staging: None,
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
    /// Production quarantine retains verified native objects in private synced
    /// custody until native admission prepares a commit. Its ref-only
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
        self.apply_merge_bundle_with_method_durable_in(
            request,
            principal,
            idempotency_key,
            pull_request,
            expected_version,
            merge,
            input,
            NativeMergeMethod::MergeCommit,
        )
        .await
    }

    /// Publish an explicitly selected merge-commit or squash candidate. Squash
    /// requires an existing PR and exactly one target parent. Both methods
    /// authenticate source history and use the same atomic publication path.
    pub async fn apply_merge_bundle_with_method_durable_in(
        &self,
        request: &NodeRequestContext,
        principal: PrincipalId,
        idempotency_key: &[u8],
        pull_request: PullRequestNumber,
        expected_version: ExpectedVersion,
        merge: &NativeMerge,
        input: &[u8],
        method: NativeMergeMethod,
    ) -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal> {
        let map_admission =
            |error| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(error)));
        let key = IdempotencyKey::new(idempotency_key.to_vec()).map_err(|_| {
            NodeWorkspaceRefusal::InvalidWorkspaceCandidate("invalid bounded idempotency key")
        })?;
        let intent = bundle_merge_intent(pull_request, expected_version, merge.clone(), method)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: principal,
            idempotency_key: key,
            object_format: self.object_format,
        };
        let attempt = intent.seal_attempt(&context).map_err(map_admission)?;
        let tx_id = attempt
            .derive()
            .map_err(|_| {
                NodeWorkspaceRefusal::InvalidWorkspaceCandidate(
                    "native merge identity derivation refused",
                )
            })?
            .0;
        // Resolve an exact prior decision before quarantine or current policy
        // checks. A changed policy cannot rewrite a historical merge/refusal,
        // and a successful retry need not reconstruct the old candidate inputs.
        if let fgit_authority::OutcomeLookup::Decided(terminal) =
            fgit_authority::resolve_outcome_async(
                &self.authority,
                request.authority(),
                &self.head_key,
                self.tenant_id,
                self.repository_id,
                tx_id,
            )
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
            .evaluate(&principal)
            .map_err(receive_error)?;
        let staging = ReceiveStaging::default();
        let (quarantined, _) = self
            .quarantine_reviewed_bundle_in(
                request,
                &merge.target_ref,
                merge.target_tip_before,
                merge.merge_commit,
                input,
                std::slice::from_ref(&merge.source_ref),
                Some(&staging),
            )
            .await?;
        // A received ref command is not a merge decision. The native driver
        // re-reads the staged candidate and authenticates a fresh exact basis;
        // retaining or admitting this source-only proof would split the effect.
        drop(quarantined);
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self
                .durable_admission_projection(&context)
                .map_err(map_admission)?,
            object_limits: MergeObjectLimits {
                max_reused_blob_bytes: self.reused_merge_blob_limit(),
                ..MergeObjectLimits::default()
            },
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
            staging: Some(&staging),
        };
        let terminal = admit_native_merge_async(
            &self.authority,
            request.authority(),
            &context,
            &intent,
            AdmissionLimits::default(),
            &projection,
        )
        .await
        .map_err(map_admission)?;
        // Preserve known terminal results even if cancellation arrives now.
        Ok((tx_id, terminal))
    }

    /// Publish a reviewed merge-commit, squash or fast-forward merge, its
    /// forge transition and pending delivery in one RCR/head CAS.
    /// Fast-forward-only intents use existing admitted source objects, prove
    /// actual target ancestry, and enforce the same mandatory review protection.
    /// They never synthesize a commit or fall back to a different merge method.
    ///
    /// A fresh undecided request requires candidate bytes already available in
    /// the immutable object fabric: this entry receives no bundle or private
    /// staging owner. Use [`Self::apply_merge_bundle_with_method_durable_in`] to
    /// resupply a candidate discarded after refusal. An exact decided retry
    /// recovers its historical outcome without requiring those bytes.
    ///
    /// Candidate objects are re-read, hashed and traversed before publication.
    /// Source, target and base must be authority-selected; for MergeCommit,
    /// ordered parents must be target-before and source. All preparation and
    /// staging uses the caller's request context. No Git process or alternative
    /// database is used.
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
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        // A retry is an outcome read, not a new mutation admission. Recover
        // the same native seal used by bundle publication before service,
        // quota, policy, or candidate-object checks can hide its decision.
        // Authentication and semantic identity still precede this lookup.
        let map_admission = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let attempt = intent.seal_attempt(&context).map_err(map_admission)?;
        let tx_id = attempt
            .derive()
            .map_err(|_| {
                map_admission(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CanonicalFramingInvalid,
                ))
            })?
            .0;
        if let fgit_authority::OutcomeLookup::Decided(terminal) =
            fgit_authority::resolve_outcome_async(
                &self.authority,
                request.authority(),
                &self.head_key,
                self.tenant_id,
                self.repository_id,
                tx_id,
            )
            .await
            .map_err(|error| map_admission(error.into()))?
        {
            // Reconfirm the exact principal/key/request binding. This is not
            // permission to reuse a different request under the same key.
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|error| map_admission(error.into()))?;
            return Ok(terminal);
        }
        self.push_quota.evaluate(&authenticated.principal_id())?;
        self.receive_publication_admitted()?;
        let inner = self
            .durable_admission_projection(&context)
            .map_err(|error| NodeReceiveTransportRefusal::Admission(Box::new(error)))?
            .with_authentication(authenticated.authentication());
        let projection = NodeNativeMergeProjection {
            node: self,
            inner,
            object_limits,
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
            staging: None,
        };
        admit_native_merge_async(
            &self.authority,
            request.authority(),
            &context,
            intent,
            limits,
            &projection,
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
    /// Private candidate objects owned by this bundle operation, if any.
    pub(super) staging: Option<&'node ReceiveStaging>,
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
        self.inner
            .snapshot_async(authority, cx, basis, authenticated)
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
        self.inner
            .materialize_commit_async(authority, cx, basis, request, fold, closure)
    }

    fn materialize_refusal_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_refusal_async(authority, cx, basis, tx_id, code)
    }
}

impl NativeMergeProjection<FsqliteAuthorityStore> for NodeNativeMergeProjection<'_> {
    fn admission_authentication(&self) -> Option<AdmissionAuthentication> {
        self.inner.authentication
    }

    fn validate_comment_anchor_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        anchor: &'a fgit_forge::event::pull_request_comment::SourceCommentAnchor,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        self.validate_source_comment_anchor_in(authority, cx, basis, authenticated, anchor)
    }

    fn validate_squash_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        self.validate_merge_async(authority, cx, basis, authenticated, intent)
    }

    fn validate_fast_forward_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        // Reuse the exact-basis materializer, request budget and mandatory
        // policy check; only the independently verified object shape differs.
        self.validate_merge_async(authority, cx, basis, authenticated, intent)
    }

    fn workspace_snapshot_digest(&self) -> Result<[u8; 32], ProjectionFailure> {
        self.workspace_live().map_err(ProjectionFailure::Refuse)?;
        self.workspace
            .map(|(digest, _, _)| digest)
            .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))
    }
    fn merge_checkpoint(&self, cx: &Cx) -> Result<(), RefusalCode> {
        match checkpoint_pack_context(cx) {
            PackContextCheckpoint::Live => Ok(()),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: Some(_),
            } => Err(RefusalCode::ResourceBudgetExceeded),
            PackContextCheckpoint::Stopped {
                budget_exhaustion: None,
            } => Err(RefusalCode::CancellationInProgress),
        }
    }
    fn merge_publication_checkpoint(&self, cx: &Cx) -> Result<(), RefusalCode> {
        self.merge_checkpoint(cx)?;
        self.workspace_live()
    }

    fn publish_merge_objects(&self, cx: &Cx) -> Result<(), RefusalCode> {
        if let Some(staging) = self.staging {
            self.merge_publication_checkpoint(cx)?;
            let result = staging.publish(&self.node.fabric, &mut || {
                self.merge_publication_checkpoint(cx).is_ok()
            });
            // Preserve cancellation, resource exhaustion and workspace expiry
            // after synchronous storage work, including when storage refused.
            self.merge_publication_checkpoint(cx)?;
            result.map_err(crate::publication_refusal)?;
        }
        Ok(())
    }

    async fn resolve_merge_basis_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
    ) -> Result<NativeMergeBasis, ProjectionFailure> {
        if authenticated
            .body()
            .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptInvalid))?
            != *basis.body()
        {
            return Err(ProjectionFailure::Unavailable(
                RefusalCode::AuthorityReceiptStale,
            ));
        }
        let prepared = self
            .inner
            .prepared
            .lock()
            .map_err(|_| ProjectionFailure::Unavailable(RefusalCode::InternalInvariantBreach))?
            .take()
            .ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
        if prepared.basis != *basis {
            return Err(ProjectionFailure::Unavailable(
                RefusalCode::AuthorityReceiptStale,
            ));
        }
        let delivery =
            fgit_admission::merge::native::delivery::read_in(authority, cx, basis, &|| {
                self.merge_checkpoint(cx).is_err()
            })
            .await
            .map_err(|error| {
                async_projection_unavailable(crate::AdmissionMaterializationRefusal::Delivery(
                    Box::new(error),
                ))
            })?;
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        Ok(NativeMergeBasis {
            refs: prepared.ref_state,
            root_layout: prepared.root_layout,
            forge: delivery.forge,
            outbox: delivery.outbox,
        })
    }

    async fn validate_merge_async<'a>(
        &'a self,
        authority: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        let selected = self
            .inner
            .materializer
            .materialize_exact_in(
                authority,
                cx,
                self.node.repository_id,
                basis,
                authenticated,
                &|| self.merge_checkpoint(cx).is_err(),
            )
            .await
            .map_err(async_projection_unavailable)?;
        let merge = intent
            .merge()
            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
        if [merge.source_tip, merge.target_tip_before, merge.base_tip]
            .iter()
            .any(|oid| {
                !selected
                    .selected_closure()
                    .closure()
                    .objects()
                    .contains(oid)
            })
        {
            return Err(ProjectionFailure::Refuse(
                RefusalCode::ObjectClosureIncomplete,
            ));
        }
        // Finish all synchronous object reads before awaiting policy:
        // neither the reader nor its thread-local budget cell may cross
        // an asynchronous authority operation.
        let closure = {
            let exhaustion = Cell::new(None);
            let object_limits = MergeObjectLimits {
                max_object_bytes: self
                    .object_limits
                    .max_object_bytes
                    .min(usize::try_from(self.node.max_object_bytes).unwrap_or(usize::MAX)),
                max_reused_blob_bytes: self
                    .object_limits
                    .max_reused_blob_bytes
                    .min(self.node.reused_merge_blob_limit()),
                ..self.object_limits
            };
            let source = VerifiedFabricPackSource {
                fabric: &self.node.fabric,
                object_format: self.node.object_format,
                maximum_object_bytes: object_limits.max_object_bytes,
                database_context: cx,
                database_exhaustion: &exhaustion,
                session_is_live: None,
            };
            let parse_limits = source.parse_limits();
            let existing_only = ReceiveStaging::default();
            let staging = self.staging.unwrap_or(&existing_only);
            let objects = selected.selected_closure().closure().objects();
            let headers = NativeFrontierHeaders {
                source: VerifiedFabricPackSource { ..source },
                selected: objects,
                staging,
                maximum_blob_bytes: object_limits.max_reused_blob_bytes,
            };
            let source = source.with_staging(staging);
            let mut live = || match checkpoint_pack_context(cx) {
                PackContextCheckpoint::Live => true,
                PackContextCheckpoint::Stopped { budget_exhaustion } => {
                    if let Some(dimension) = budget_exhaustion {
                        exhaustion.set(Some(dimension));
                    }
                    false
                }
            };
            // Validate only what the candidate adds above the authority-selected
            // closure; the record then names those objects (frankengit-lh8z).
            let result = match intent.method() {
                NativeMergeMethod::MergeCommit => validate_merge_objects_above(
                    &source,
                    merge,
                    ObjectFrontier::with_headers(objects, &headers),
                    object_limits,
                    &mut live,
                ),
                NativeMergeMethod::FastForwardOnly => validate_fast_forward_objects_above(
                    &source,
                    merge,
                    ObjectFrontier::with_headers(objects, &headers),
                    object_limits,
                    &mut live,
                ),
                NativeMergeMethod::Squash => validate_squash_objects_above(
                    &source,
                    merge,
                    ObjectFrontier::with_headers(objects, &headers),
                    object_limits,
                    &mut live,
                ),
            };
            if exhaustion.get().is_some() {
                return Err(ProjectionFailure::Unavailable(
                    RefusalCode::ResourceBudgetExceeded,
                ));
            }
            let closure = result?;
            if intent.method() == NativeMergeMethod::FastForwardOnly
                && !closure
                    .objects
                    .is_subset(selected.selected_closure().closure().objects())
            {
                // A fast-forward cannot admit merely staged dependencies.
                return Err(ProjectionFailure::Refuse(
                    RefusalCode::ObjectClosureIncomplete,
                ));
            }
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
                    &parse_limits,
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
            closure
        };
        match self.inner.authentication {
            Some(authentication) => {
                fgit_admission::merge::native::protection::enforce_merge_with_authentication_at(
                    authority,
                    cx,
                    basis,
                    &selected.snapshot().refs,
                    intent,
                    self.inner.context.principal_id,
                    authentication,
                    &|| self.merge_checkpoint(cx).is_err(),
                )
                .await
            }
            None => {
                fgit_admission::merge::native::protection::enforce_merge_at(
                    authority,
                    cx,
                    basis,
                    &selected.snapshot().refs,
                    intent,
                    self.inner.context.principal_id,
                    &|| self.merge_checkpoint(cx).is_err(),
                )
                .await
            }
        }?;
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        Ok(closure)
    }
}

#[cfg(test)]
mod sealed_tests;
