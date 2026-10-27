//! Bounded grouping of the existing binding and seal protocol.
//!
//! Identity derivation, canonical bodies and outcome classifiers are shared
//! with the single-request path. Every binding is settled before any seal is
//! created, so a changed key never turns into a sealed competing request.

use super::{
    AsyncAuthorityStore, AuthorityStore, ImmutableKey, KeyBinding, SealAdmission, SealAttempt,
    SealFailure, TransactionSealId, TxId, classify_binding, classify_seal, encode_body,
    encode_tx_id, idempotency_binding_key, interpret_binding_conflict, seal_identity, seal_key,
};
use crate::{
    AuthorityLimits, ImmutableBatchFailure, ImmutableBatchRefusal, MAX_IMMUTABLE_BATCH_ITEMS,
    PutOutcome, validate_immutable_batch,
};

struct Prepared {
    identities: Vec<(TxId, TransactionSealId)>,
    bindings: Vec<(ImmutableKey, Vec<u8>)>,
    seals: Vec<(ImmutableKey, Vec<u8>)>,
}

impl Prepared {
    fn new(attempts: &[SealAttempt]) -> Result<Self, SealFailure> {
        // Refuse before deriving or retaining anything proportional to an
        // unbounded caller-supplied collection.
        if attempts.len() > MAX_IMMUTABLE_BATCH_ITEMS {
            return Err(
                ImmutableBatchFailure::Bounds(ImmutableBatchRefusal::TooManyItems {
                    observed: attempts.len(),
                    limit: MAX_IMMUTABLE_BATCH_ITEMS,
                })
                .into(),
            );
        }
        let mut prepared = Self {
            identities: Vec::with_capacity(attempts.len()),
            bindings: Vec::with_capacity(attempts.len()),
            seals: Vec::with_capacity(attempts.len()),
        };
        for attempt in attempts {
            let (tx_id, seal) = attempt.derive()?;
            prepared.identities.push((tx_id, seal_identity(&seal)?));
            prepared.bindings.push((
                idempotency_binding_key(
                    attempt.tenant_id,
                    attempt.repository_id,
                    attempt.authenticated_principal_id,
                    &attempt.idempotency_key,
                )?,
                encode_tx_id(tx_id)?,
            ));
            prepared.seals.push((
                seal_key(attempt.tenant_id, attempt.repository_id, tx_id)?,
                encode_body(&seal)?,
            ));
        }
        Ok(prepared)
    }

    fn preflight_seals(&self, limits: AuthorityLimits) -> Result<(), SealFailure> {
        validate_immutable_batch(&self.bindings, limits)?;
        validate_immutable_batch(&self.seals, limits)?;
        Ok(())
    }

    const fn check_count(&self, outcomes: &[PutOutcome]) -> Result<(), SealFailure> {
        if outcomes.len() != self.identities.len() {
            return Err(SealFailure::SlotContentUnexpected {
                slot: "immutable batch outcome count",
            });
        }
        Ok(())
    }

    fn bind<S: AuthorityStore + ?Sized>(&self, store: &S) -> Result<Vec<KeyBinding>, SealFailure> {
        // Also preflight here: a backend override may optimize storage but
        // cannot widen the canonical helper's finite input contract.
        validate_immutable_batch(&self.bindings, store.limits())?;
        let outcomes = store.put_if_absent_batch(&self.bindings)?;
        self.check_count(&outcomes)?;
        self.identities
            .iter()
            .zip(&self.bindings)
            .zip(outcomes)
            .map(
                |(((tx_id, _), (key, _)), outcome)| match classify_binding(outcome, *tx_id) {
                    Some(settled) => settled,
                    None => interpret_binding_conflict(store.read_immutable(key)?, *tx_id),
                },
            )
            .collect()
    }

    async fn bind_async<S: AsyncAuthorityStore + ?Sized>(
        &self,
        store: &S,
        cx: &S::Context,
    ) -> Result<Vec<KeyBinding>, SealFailure> {
        validate_immutable_batch(&self.bindings, store.limits())?;
        let outcomes = store.put_if_absent_batch(cx, &self.bindings).await?;
        self.check_count(&outcomes)?;
        let mut result = Vec::with_capacity(outcomes.len());
        for (((tx_id, _), (key, _)), outcome) in
            self.identities.iter().zip(&self.bindings).zip(outcomes)
        {
            result.push(match classify_binding(outcome, *tx_id) {
                Some(settled) => settled?,
                None => interpret_binding_conflict(store.read_immutable(cx, key).await?, *tx_id)?,
            });
        }
        Ok(result)
    }

    fn admit(&self, outcomes: Vec<PutOutcome>) -> Result<Vec<SealAdmission>, SealFailure> {
        self.check_count(&outcomes)?;
        self.identities
            .iter()
            .zip(outcomes)
            .map(|((tx_id, seal_id), outcome)| classify_seal(outcome, *seal_id, *tx_id))
            .collect()
    }
}

/// Bind a bounded group of independent idempotency keys in input order.
///
/// Every identity is derived by the same protocol as [`super::seal_request`].
/// This creates no seals. A conflicting key is the same typed rejection as on
/// the single-key path; other immutable bindings may already have been stored.
/// Retry the same complete request after interruption.
pub fn bind_idempotency_keys<S>(
    store: &S,
    attempts: &[SealAttempt],
) -> Result<Vec<KeyBinding>, SealFailure>
where
    S: AuthorityStore + ?Sized,
{
    Prepared::new(attempts)?.bind(store)
}

/// The asynchronous sibling of [`bind_idempotency_keys`].
///
/// The caller-owned context reaches the backend's complete bounded operation;
/// no detached context is created and no interruption proves non-publication.
pub async fn bind_idempotency_keys_async<S>(
    store: &S,
    cx: &S::Context,
    attempts: &[SealAttempt],
) -> Result<Vec<KeyBinding>, SealFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    Prepared::new(attempts)?.bind_async(store, cx).await
}

/// Bind and seal a bounded group without changing any logical identity.
///
/// All input/body bounds and derivations are checked before the first write.
/// All key bindings settle before any seal is written. A partial or ambiguous
/// storage failure returns no successful seal vector: each original identity
/// remains recoverable by the normal exact-key lookup or identical retry.
pub fn seal_requests<S>(
    store: &S,
    attempts: &[SealAttempt],
) -> Result<Vec<SealAdmission>, SealFailure>
where
    S: AuthorityStore + ?Sized,
{
    let prepared = Prepared::new(attempts)?;
    prepared.preflight_seals(store.limits())?;
    prepared.bind(store)?;
    prepared.admit(store.put_if_absent_batch(&prepared.seals)?)
}

/// The asynchronous sibling of [`seal_requests`], sharing every decision rule.
pub async fn seal_requests_async<S>(
    store: &S,
    cx: &S::Context,
    attempts: &[SealAttempt],
) -> Result<Vec<SealAdmission>, SealFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let prepared = Prepared::new(attempts)?;
    prepared.preflight_seals(store.limits())?;
    prepared.bind_async(store, cx).await?;
    prepared.admit(store.put_if_absent_batch(cx, &prepared.seals).await?)
}
