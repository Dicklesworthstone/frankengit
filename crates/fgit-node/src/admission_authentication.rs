//! Host-verified authentication receipts at durable admission boundaries.
//!
//! Authentication describes the original decision attempt. It never changes a
//! sealed transaction or causes terminal recovery to reinterpret old evidence.

use fgit_admission::ProjectionFailure;
use fgit_admission::evidence::{AdmissionAuthentication, PrincipalSnapshotRecord};
use fgit_admission::merge::native::protection;

use super::{
    ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX, AdmissionContext, AdmissionError, AdmissionLimits,
    AdmissionMaterializationRefusal, AdmissionResult, AsyncAuthorityStore,
    BasisBoundValidatedReceive, CanonicalRefState, DURABLE_REFUSAL_EVIDENCE_DETAIL,
    DecisionEvidenceBodies, Digest, DurableAdmissionMaterializer, ImmutableRead,
    NodeRequestContext, OneNode, PublicationBasis, RefusalCode, RefusalEvidenceBodies,
    RefusalMaterialization, RepositoryId, RootLayoutVersion, TransactionFoldReport,
    TransactionRequest, TxId, admission_immutable_key, admit_basis_bound_validated_receive_async,
    ensure_materializer_catch_up_live, evidence_root, stage_evidence_body_in,
};

pub(super) async fn stage_principal_snapshot_in<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    body: &PrincipalSnapshotRecord,
    cancelled: &C,
) -> Result<(), AdmissionMaterializationRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    match body {
        PrincipalSnapshotRecord::Legacy(snapshot) => {
            stage_evidence_body_in(
                store,
                cx,
                repository,
                ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
                snapshot,
                cancelled,
            )
            .await
        }
        PrincipalSnapshotRecord::Authenticated(snapshot) => {
            stage_evidence_body_in(
                store,
                cx,
                repository,
                ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
                snapshot,
                cancelled,
            )
            .await
        }
    }
}

pub(super) async fn read_principal_snapshot_in<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    root: Digest,
    cancelled: &C,
) -> Result<PrincipalSnapshotRecord, AdmissionMaterializationRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    ensure_materializer_catch_up_live(cancelled)?;
    let key = admission_immutable_key(ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX, repository, root)
        .map_err(AdmissionMaterializationRefusal::Key)?;
    let ImmutableRead::Present(frame) = store
        .read_immutable(cx, &key)
        .await
        .map_err(AdmissionMaterializationRefusal::Authority)?
    else {
        return Err(AdmissionMaterializationRefusal::ImmutableAbsent(root));
    };
    ensure_materializer_catch_up_live(cancelled)?;
    let body = PrincipalSnapshotRecord::decode(&frame, fgit_codec::DecodeLimits::DEFAULT)
        .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
    let identity = body
        .id()
        .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
    let identity = identity.as_internal_object_id();
    if Digest::new(identity.algorithm(), *identity.digest()) != root
        || body.repository_id() != repository
    {
        return Err(AdmissionMaterializationRefusal::CanonicalRoot(
            RefusalCode::EvidenceInvalid,
        ));
    }
    ensure_materializer_catch_up_live(cancelled)?;
    Ok(body)
}

pub(super) async fn direct_decision_evidence_in<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    current: &CanonicalRefState,
    layout: RootLayoutVersion,
    request: &TransactionRequest,
    fold: &TransactionFoldReport,
    authentication: Option<AdmissionAuthentication>,
    cancelled: &C,
) -> Result<DecisionEvidenceBodies, ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    match authentication {
        Some(authentication) => {
            protection::direct_decision_evidence_with_authentication_at(
                store,
                cx,
                context,
                basis,
                current,
                layout,
                request,
                fold,
                authentication,
                cancelled,
            )
            .await
        }
        None => {
            protection::direct_decision_evidence_at(
                store, cx, context, basis, current, layout, request, fold, cancelled,
            )
            .await
        }
    }
}

pub(super) async fn attach_prepared_policy_in<S, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    basis: &PublicationBasis,
    resolved: &fgit_admission::merge::NativeMergeBasis,
    prepared: &mut fgit_admission::merge::PreparedNativeMerge,
    publication: fgit_admission::evidence::RefPolicyPublication,
    authentication: Option<AdmissionAuthentication>,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    match authentication {
        Some(authentication) => {
            protection::attach_prepared_policy_with_authentication_at(
                store,
                cx,
                context,
                basis,
                resolved,
                prepared,
                publication,
                authentication,
                cancelled,
            )
            .await
        }
        None => {
            protection::attach_prepared_policy_at(
                store,
                cx,
                context,
                basis,
                resolved,
                prepared,
                publication,
                cancelled,
            )
            .await
        }
    }
}

impl DurableAdmissionMaterializer {
    pub(super) async fn stage_refusal_evidence_with_authentication_in<S, C>(
        &self,
        store: &S,
        cx: &S::Context,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        tx_id: TxId,
        code: RefusalCode,
        authentication: Option<AdmissionAuthentication>,
        cancelled: &C,
    ) -> Result<RefusalMaterialization, AdmissionMaterializationRefusal>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
    {
        let Some(authentication) = authentication else {
            return self
                .stage_refusal_evidence_in(store, cx, context, basis, tx_id, code, cancelled)
                .await;
        };
        if context.repository_id != basis.body().repository_id {
            return Err(AdmissionMaterializationRefusal::RepositoryMismatch {
                expected: context.repository_id,
                observed: basis.body().repository_id,
            });
        }
        ensure_materializer_catch_up_live(cancelled)?;
        let bodies = RefusalEvidenceBodies::derive_with_authentication(
            context,
            basis,
            tx_id,
            code,
            authentication,
        )
        .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        self.stage_refusal_evidence_bodies_in(store, cx, &bodies, cancelled)
            .await?;
        ensure_materializer_catch_up_live(cancelled)?;
        Ok(RefusalMaterialization {
            policy_epoch: basis.body().policy_epoch,
            detail: DURABLE_REFUSAL_EVIDENCE_DETAIL.to_owned(),
            evidence_root: evidence_root(bodies.refusal_evidence())
                .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?,
        })
    }
}

impl OneNode {
    pub(crate) async fn admit_basis_bound_validated_receive_with_authentication_in(
        &self,
        request: &NodeRequestContext,
        context: &AdmissionContext,
        validated: &BasisBoundValidatedReceive,
        limits: AdmissionLimits,
        staging: Option<&super::receive_staging::ReceiveStaging>,
        authentication: AdmissionAuthentication,
    ) -> Result<AdmissionResult, AdmissionError> {
        let projection = self
            .durable_admission_projection_publishing(context, staging)?
            .with_authentication(authentication);
        admit_basis_bound_validated_receive_async(
            &self.authority,
            request.authority(),
            context,
            validated,
            limits,
            &projection,
        )
        .await
    }
}
