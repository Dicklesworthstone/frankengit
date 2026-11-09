//! Awaited immutable staging through the caller's original authority context.
//! This module cannot publish a head or turn placement into a terminal outcome.

use fgit_authority::{AsyncAuthorityStore, ImmutableKey, PutOutcome};
use fgit_codec::{CanonicalBody, encode_body};
use fgit_types::{Digest, RefusalCode, RepositoryId};

use super::{PreparedHeadChange, unavailable};
use crate::AdmissionError;
use crate::evidence::{PrincipalSnapshotRecord, evidence_root};
use crate::merge::native::NativeMergeProjection;

pub(super) const HEAD_DELTA: &[u8] = b"frankengit/admission/head-delta/v1/";
pub(super) const REF_STATE: &[u8] = b"frankengit/admission/ref-state/v1/";
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

pub(super) async fn stage_prepared<S, P>(
    store: &S,
    cx: &S::Context,
    prepared: &PreparedHeadChange,
    projection: &P,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let repository = prepared.materialization.record.repository_id;
    stage_at(
        store,
        cx,
        repository,
        REF_STATE,
        prepared.materialization.roots.ref_root,
        &prepared.refs,
        projection,
    )
    .await?;
    stage(
        store,
        cx,
        repository,
        HEAD_DELTA,
        &prepared.delta,
        projection,
    )
    .await?;
    stage(
        store,
        cx,
        repository,
        b"frankengit/admission/invariant-evidence/v1/",
        &prepared.delta,
        projection,
    )
    .await?;
    stage(
        store,
        cx,
        repository,
        b"frankengit/admission/object-closure/v1/",
        &prepared.closure,
        projection,
    )
    .await?;
    let PrincipalSnapshotRecord::Authenticated(principal) = &prepared.evidence.principal else {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    };
    stage(
        store,
        cx,
        repository,
        b"frankengit/admission/principal-snapshot/v1/",
        principal,
        projection,
    )
    .await?;
    stage(
        store,
        cx,
        repository,
        b"frankengit/admission/policy-decision/v1/",
        &prepared.evidence.policy,
        projection,
    )
    .await?;
    stage(
        store,
        cx,
        repository,
        b"frankengit/admission/forge-event-batch/v1/",
        &prepared.evidence.forge,
        projection,
    )
    .await?;
    stage(
        store,
        cx,
        repository,
        b"frankengit/admission/outbox-effect-batch/v1/",
        &prepared.evidence.outbox,
        projection,
    )
    .await?;
    stage(
        store,
        cx,
        repository,
        b"frankengit/admission/retention-delta/v1/",
        &prepared.evidence.retention,
        projection,
    )
    .await?;
    if let Some(witness) = &prepared.protection_witness {
        stage(
            store,
            cx,
            repository,
            b"frankengit/admission/forge-event-batch/v1/",
            witness,
            projection,
        )
        .await?;
    }
    Ok(())
}

async fn stage<S, P, B>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    prefix: &[u8],
    body: &B,
    projection: &P,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
    B: CanonicalBody + Sync,
{
    stage_at(
        store,
        cx,
        repository,
        prefix,
        evidence_root(body).map_err(unavailable)?,
        body,
        projection,
    )
    .await
}

async fn stage_at<S, P, B>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    prefix: &[u8],
    digest: Digest,
    body: &B,
    projection: &P,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
    B: CanonicalBody + Sync,
{
    projection.merge_checkpoint(cx).map_err(unavailable)?;
    let frame = encode_body(body).map_err(|_| unavailable(RefusalCode::CanonicalFramingInvalid))?;
    if frame.len() > MAX_FRAME_BYTES {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    let mut bytes = Vec::with_capacity(prefix.len() + 18 + digest.bytes().len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(repository.as_bytes());
    bytes.extend_from_slice(&digest.algorithm().code_point().to_be_bytes());
    bytes.extend_from_slice(digest.bytes().as_bytes());
    let key = ImmutableKey::new(bytes).map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    let result = store.put_if_absent(cx, &key, &frame).await;
    projection.merge_checkpoint(cx).map_err(unavailable)?;
    match result? {
        PutOutcome::Created | PutOutcome::IdenticalRetry => Ok(()),
        PutOutcome::Conflict => Err(unavailable(RefusalCode::EvidenceInvalid)),
    }
}
