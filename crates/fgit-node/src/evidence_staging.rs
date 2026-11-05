//! Bound physical evidence writes without changing their keys, bytes or authority.
//! Small decisions use one native immutable-write transaction. Large evidence
//! retains the single-body admission envelope: grouping never creates a new
//! size refusal. An interrupted group may have staged a prefix, and no group
//! result publishes repository state or proves that a failed call did nothing.

use super::{
    ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX, ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX,
    ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX, ADMISSION_POLICY_DECISION_KEY_PREFIX,
    ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX, ADMISSION_RETENTION_DELTA_KEY_PREFIX,
    AdmissionMaterializationRefusal, AsyncAuthorityStore, CanonicalBody, DecisionEvidenceBodies,
    Digest, ImmutableKey, PutOutcome, RefusalCode, RepositoryId, admission_immutable_key,
    encode_body, ensure_materializer_catch_up_live, evidence_root, stage_immutable_frame,
};
use fgit_authority::{MAX_IMMUTABLE_BATCH_BYTES, MAX_IMMUTABLE_BATCH_ITEMS};

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
    let repository = bodies.principal_snapshot().repository_id();
    let mut batch = EvidenceBatch::new(store, cx, cancelled);
    batch.check()?;
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
    batch
        .push(
            repository,
            ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
            root,
            frame,
        )
        .await?;
    batch.check()?;
    let root = bodies
        .policy_decision()
        .root()
        .map_err(AdmissionMaterializationRefusal::CanonicalRoot)?;
    let frame = bodies
        .policy_decision()
        .encode()
        .map_err(AdmissionMaterializationRefusal::CanonicalFrame)?;
    batch
        .push(
            repository,
            ADMISSION_POLICY_DECISION_KEY_PREFIX,
            root,
            frame,
        )
        .await?;
    batch
        .body(
            repository,
            ADMISSION_INVARIANT_EVIDENCE_KEY_PREFIX,
            bodies.invariant_evidence(),
        )
        .await?;
    batch
        .body(
            repository,
            ADMISSION_FORGE_EVENT_BATCH_KEY_PREFIX,
            bodies.forge_event_batch(),
        )
        .await?;
    batch
        .body(
            repository,
            ADMISSION_OUTBOX_EFFECT_BATCH_KEY_PREFIX,
            bodies.outbox_effect_batch(),
        )
        .await?;
    batch
        .body(
            repository,
            ADMISSION_RETENTION_DELTA_KEY_PREFIX,
            bodies.retention_delta(),
        )
        .await?;
    batch.flush().await
}

pub(super) struct EvidenceBatch<'a, S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync> {
    store: &'a S,
    cx: &'a S::Context,
    cancelled: &'a C,
    entries: Vec<(ImmutableKey, Vec<u8>)>,
    bytes: usize,
}

impl<'a, S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync> EvidenceBatch<'a, S, C> {
    pub(super) fn new(store: &'a S, cx: &'a S::Context, cancelled: &'a C) -> Self {
        Self {
            store,
            cx,
            cancelled,
            entries: Vec::new(),
            bytes: 0,
        }
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
        if self.entries.len() == MAX_IMMUTABLE_BATCH_ITEMS
            || bytes > MAX_IMMUTABLE_BATCH_BYTES.saturating_sub(self.bytes)
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
        self.bytes += bytes;
        self.entries.push((key, frame));
        Ok(())
    }

    pub(super) async fn flush(&mut self) -> Result<(), AdmissionMaterializationRefusal> {
        self.check()?;
        if self.entries.is_empty() {
            return Ok(());
        }
        let entries = std::mem::take(&mut self.entries);
        self.bytes = 0;
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
