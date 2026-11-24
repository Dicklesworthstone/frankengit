//! Bound physical evidence writes without changing their keys, bytes or authority.
//! An unpublished receive chunk may pack frames from consecutive RCRs. Large evidence
//! retains the single-body admission envelope: grouping never creates a new
//! size refusal. An interrupted group may have staged a prefix, and no group
//! result publishes repository state or proves that a failed call did nothing.

use super::{
    ADMISSION_CLOSURE_KEY_PREFIX, ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
    ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX, ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX,
    ADMISSION_POLICY_DECISION_KEY_PREFIX, ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
    ADMISSION_REF_STATE_KEY_PREFIX, ADMISSION_RETENTION_DELTA_KEY_PREFIX,
    AdmissionMaterializationRefusal, AsyncAuthorityStore, CanonicalBody, DecisionEvidenceBodies,
    Digest, ImmutableKey, PutOutcome, RefusalCode, RepositoryId, admission_immutable_key,
    encode_body, ensure_materializer_catch_up_live, evidence_root, stage_immutable_frame,
};
use fgit_admission::PreparedCanonicalCommit;
use fgit_authority::{MAX_IMMUTABLE_BATCH_BYTES, MAX_IMMUTABLE_BATCH_ITEMS};

pub(super) struct RefBatch<'a, 'm> {
    projection: &'a super::DurableAsyncAdmissionProjection<'m>,
    store: &'a super::FsqliteAuthorityStore,
    cx: &'a super::FsqliteCx,
    pending: PendingRefEvidence,
}

impl<'a, 'm> RefBatch<'a, 'm> {
    pub(super) fn new(
        projection: &'a super::DurableAsyncAdmissionProjection<'m>,
        store: &'a super::FsqliteAuthorityStore,
        cx: &'a super::FsqliteCx,
    ) -> Self {
        Self {
            projection,
            store,
            cx,
            pending: PendingRefEvidence::default(),
        }
    }
}

impl fgit_admission::microbatch::RefBatchStaging for RefBatch<'_, '_> {
    async fn prepare<'a>(
        &'a mut self,
        state: &'a fgit_admission::microbatch::BatchRefState,
        request: &'a super::TransactionRequest,
        fold: &'a super::TransactionFoldReport,
        closure: &'a super::ValidatedClosure,
    ) -> Result<super::CommitMaterialization, super::AsyncProjectionFailure> {
        // Source publication carries a separate request-owned proof. Keep its
        // original per-command publication and cancellation boundaries.
        let pending = self
            .projection
            .source_publication
            .is_none()
            .then_some(&mut self.pending);
        self.projection
            .prepare_ref_batch_commit(self.store, self.cx, state, request, fold, closure, pending)
            .await
    }

    async fn flush(&mut self) -> Result<(), RefusalCode> {
        if self.pending.entries.is_empty() {
            return Ok(());
        }
        let stage = self.cx.create_child();
        self.pending
            .flush(self.store, &stage, &|| stage.checkpoint().is_err())
            .await
            .map_err(|error| match super::async_projection_unavailable(error) {
                super::AsyncProjectionFailure::Unavailable(code)
                | super::AsyncProjectionFailure::Refuse(code) => code,
            })
    }
}

pub(super) async fn stage_decision_in<S, C>(
    store: &S,
    cx: &S::Context,
    bodies: &DecisionEvidenceBodies,
    cancelled: &C,
) -> Result<(), AdmissionMaterializationRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let mut batch = EvidenceBatch::new(store, cx, cancelled);
    batch.decision(bodies).await?;
    batch.flush().await
}

/// Stage one already validated ref commit's exact evidence and successor bodies.
/// The opaque preparation owns the root/body binding; callers cannot replace it
/// with a digest or an arbitrary frame. These are still independent immutable
/// puts, never a publication or a proof that a failed operation staged nothing.
/// Native object promotion and every semantic check precede this call; an RCR
/// and its authority head may be published only after it completes.
#[cfg(test)]
pub(super) async fn stage_commit_in<S, C>(
    store: &S,
    cx: &S::Context,
    bodies: &DecisionEvidenceBodies,
    prepared: &mut PreparedCanonicalCommit,
    cancelled: &C,
) -> Result<(), AdmissionMaterializationRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    prepare_commit_in(store, cx, bodies, prepared, cancelled, None).await
}

/// Hold only the immutable bytes of the current CAS attempt. Storage errors
/// discard the private attempt. Even a successful flush never decides a ref.
#[derive(Default)]
pub(super) struct PendingRefEvidence {
    entries: Vec<(ImmutableKey, Vec<u8>)>,
    bytes: usize,
}

impl PendingRefEvidence {
    pub(super) async fn flush<S, C>(
        &mut self,
        store: &S,
        cx: &S::Context,
        cancelled: &C,
    ) -> Result<(), AdmissionMaterializationRefusal>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
    {
        let mut batch = EvidenceBatch {
            store,
            cx,
            cancelled,
            pending: std::mem::take(self),
        };
        batch.flush().await
    }
}

pub(super) async fn prepare_commit_in<S, C>(
    store: &S,
    cx: &S::Context,
    bodies: &DecisionEvidenceBodies,
    prepared: &mut PreparedCanonicalCommit,
    cancelled: &C,
    mut pending: Option<&mut PendingRefEvidence>,
) -> Result<(), AdmissionMaterializationRefusal>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let repository = bodies.principal_snapshot().repository_id();
    let mut batch = EvidenceBatch {
        store,
        cx,
        cancelled,
        pending: pending
            .as_deref_mut()
            .map(std::mem::take)
            .unwrap_or_default(),
    };
    batch.decision(bodies).await?;
    batch.check()?;
    let frame = prepared
        .ref_state_frame()
        .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
    batch
        .push(
            repository,
            ADMISSION_REF_STATE_KEY_PREFIX,
            prepared.ref_root(),
            frame,
        )
        .await?;
    batch.check()?;
    let closure_root = prepared.object_closure_root();
    let closure_frame = prepared
        .object_closure_frame()
        .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
    batch
        .append_borrowed(
            repository,
            ADMISSION_CLOSURE_KEY_PREFIX,
            closure_root,
            closure_frame,
        )
        .await?;
    if let Some(pending) = pending {
        *pending = batch.pending;
        Ok(())
    } else {
        batch.flush().await
    }
}

pub(super) struct EvidenceBatch<'a, S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync> {
    store: &'a S,
    cx: &'a S::Context,
    cancelled: &'a C,
    pending: PendingRefEvidence,
}

impl<'a, S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync> EvidenceBatch<'a, S, C> {
    pub(super) fn new(store: &'a S, cx: &'a S::Context, cancelled: &'a C) -> Self {
        Self {
            store,
            cx,
            cancelled,
            pending: PendingRefEvidence::default(),
        }
    }

    async fn decision(
        &mut self,
        bodies: &DecisionEvidenceBodies,
    ) -> Result<(), AdmissionMaterializationRefusal> {
        let repository = bodies.principal_snapshot().repository_id();
        self.check()?;
        let principal = bodies
            .principal_snapshot()
            .id()
            .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        let identity = principal.as_internal_object_id();
        let root = Digest::new(identity.algorithm(), *identity.digest());
        let frame = bodies
            .principal_snapshot()
            .encode()
            .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
        self.push(
            repository,
            ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
            root,
            frame,
        )
        .await?;
        self.check()?;
        let root = bodies
            .policy_decision()
            .root()
            .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        let frame = bodies
            .policy_decision()
            .encode()
            .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
        self.push(
            repository,
            ADMISSION_POLICY_DECISION_KEY_PREFIX,
            root,
            frame,
        )
        .await?;
        self.body(
            repository,
            ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX,
            bodies.invariant_evidence(),
        )
        .await?;
        self.body(
            repository,
            ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
            bodies.forge_event_batch(),
        )
        .await?;
        self.body(
            repository,
            ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX,
            bodies.outbox_effect_batch(),
        )
        .await?;
        self.body(
            repository,
            ADMISSION_RETENTION_DELTA_KEY_PREFIX,
            bodies.retention_delta(),
        )
        .await?;
        Ok(())
    }

    fn check(&self) -> Result<(), AdmissionMaterializationRefusal> {
        ensure_materializer_catch_up_live(self.cancelled)
    }

    async fn body<B: CanonicalBody + Sync>(
        &mut self,
        repository: RepositoryId,
        namespace: &[u8],
        body: &B,
    ) -> Result<(), AdmissionMaterializationRefusal> {
        self.check()?;
        let root = evidence_root(body).map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
        let frame = encode_body(body).map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
        self.push(repository, namespace, root, frame).await
    }

    pub(super) async fn push(
        &mut self,
        repository: RepositoryId,
        namespace: &[u8],
        root: Digest,
        frame: Vec<u8>,
    ) -> Result<(), AdmissionMaterializationRefusal> {
        self.check()?;
        let key = admission_immutable_key(namespace, repository, root)
            .map_err(AdmissionMaterializationRefusal::Key)?;
        let bytes = key.as_bytes().len().saturating_add(frame.len());
        if self.pending.entries.len() == MAX_IMMUTABLE_BATCH_ITEMS
            || bytes > MAX_IMMUTABLE_BATCH_BYTES.saturating_sub(self.pending.bytes)
        {
            self.flush().await?;
        }
        // The batch allowance is smaller than the existing per-body envelope.
        // Preserve the latter, including its backend-specific typed refusal.
        if bytes > MAX_IMMUTABLE_BATCH_BYTES || frame.len() > self.store.limits().body_bytes {
            self.check()?;
            stage_immutable_frame(self.store, self.cx, &key, &frame).await?;
            return self.check();
        }
        self.pending.bytes += bytes;
        self.pending.entries.push((key, frame));
        Ok(())
    }

    /// Complete the pending group with an already encoded final body. Copy it
    /// only when it fits that group, whose total bytes remain at most 1 MiB.
    /// A larger or standalone closure keeps its borrowed, reusable encoding
    /// and the original single-body admission envelope instead.
    #[cfg(test)]
    pub(super) async fn finish_borrowed(
        &mut self,
        repository: RepositoryId,
        namespace: &[u8],
        root: Digest,
        frame: &[u8],
    ) -> Result<(), AdmissionMaterializationRefusal> {
        self.append_borrowed(repository, namespace, root, frame)
            .await?;
        self.flush().await
    }

    async fn append_borrowed(
        &mut self,
        repository: RepositoryId,
        namespace: &[u8],
        root: Digest,
        frame: &[u8],
    ) -> Result<(), AdmissionMaterializationRefusal> {
        self.check()?;
        let key = admission_immutable_key(namespace, repository, root)
            .map_err(AdmissionMaterializationRefusal::Key)?;
        let bytes = key.as_bytes().len().saturating_add(frame.len());
        if self.pending.entries.is_empty()
            || self.pending.entries.len() == MAX_IMMUTABLE_BATCH_ITEMS
            || bytes > MAX_IMMUTABLE_BATCH_BYTES.saturating_sub(self.pending.bytes)
            || frame.len() > self.store.limits().body_bytes
        {
            self.flush().await?;
            self.check()?;
            stage_immutable_frame(self.store, self.cx, &key, frame).await?;
            return self.check();
        }
        self.pending.bytes += bytes;
        self.pending.entries.push((key, frame.to_vec()));
        self.check()
    }

    pub(super) async fn flush(&mut self) -> Result<(), AdmissionMaterializationRefusal> {
        self.check()?;
        if self.pending.entries.is_empty() {
            return Ok(());
        }
        let entries = std::mem::take(&mut self.pending.entries);
        self.pending.bytes = 0;
        let outcomes = self
            .store
            .put_if_absent_batch(self.cx, &entries)
            .await
            .map_err(AdmissionMaterializationRefusal::ImmutableBatch)?;
        if outcomes.len() != entries.len() {
            return Err(AdmissionMaterializationRefusal::CanonicalRoot(
                RefusalCode::InternalInvariantBreach,
            ));
        }
        if outcomes
            .iter()
            .any(|outcome| *outcome == PutOutcome::Conflict)
        {
            return Err(AdmissionMaterializationRefusal::ImmutableConflict);
        }
        self.check()
    }
}
