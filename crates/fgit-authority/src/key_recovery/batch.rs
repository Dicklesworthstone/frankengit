//! Many scoped keys, one authenticated replay of the immutable decision chain.

use std::collections::BTreeMap;

use crate::{AuthorityFailure, ImmutableRead};
use fgit_codec::{Encoder, RepositoryAuthorityHeadBody};

use super::{
    AsyncAuthorityStore, HeadKey, IdempotencyKey, LIMITS, OutcomeLookup, RecoveryFailure,
    RecoveryScope, RefusalCode, RequestRecovery, TransactionSealBody, TransactionSealId, TxId,
    binding_identity, check, check_head, checked_seal, decode_body, finish, head_receipt,
    idempotency_binding_key, integrity, seal_key,
};
#[cfg(test)]
use super::{
    AuthenticatedHead, AuthorityStore, CANONICAL_CODEC_VERSION, DecodeLimits, HeadRead,
    HeadReadReceipt, OutcomeFailure, PrincipalId, RepositoryId, encode_body, recover_request,
    recover_request_async,
};
use crate::{
    TerminalOutcome, indexed_outcome_async, next_batch_to_replay, read_authority_head_body_async,
    read_decision_batch_body_async, reconcile_outcome,
};

/// Maximum number of observations in one bounded recovery operation.
/// Duplicate keys count toward this bound and retain their input positions.
pub const MAX_RECOVERY_KEYS: usize = 16_384;

enum PendingRecovery {
    Observation(RequestRecovery),
    Sealed {
        seal: TransactionSealBody,
        seal_id: TransactionSealId,
        indexed: OutcomeLookup,
    },
}

/// Recover a bounded list of original keys without replaying history per key.
///
/// All key bindings and seals pass the same checks as [`super::recover_request_async`].
/// Accelerator hints are read BEFORE the authenticated head used for the shared
/// replay: a concurrent atomic publication therefore cannot leave a hint newer
/// than that snapshot. Each answer still passes [`reconcile_outcome`], so absent
/// hints do not hide commits and conflicting hints remain integrity failures.
///
/// This is read-only and preserves input order, including duplicate keys. An
/// empty list authenticates the repository and returns no observations; an
/// oversized list refuses before any reads. Missing bindings/seals and undecided
/// outcomes are observations, never proof that concurrent work cannot commit.
/// The several key/seal observations are not a single atomic snapshot.
///
/// Replay uses the existing identity-checking body readers and batch bound. It
/// keeps only queried identities in memory and stops when each sealed query is
/// found. A checkpoint runs at every I/O and decision boundary; once every
/// result is terminal, subsequent cancellation cannot erase those decisions.
pub async fn recover_requests_async<S, C>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    scope: RecoveryScope,
    keys: &[IdempotencyKey],
    checkpoint: &C,
) -> Result<Vec<RequestRecovery>, RecoveryFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    check_batch_scope(store, cx, head_key, scope, keys.len(), checkpoint).await?;
    recover_batch(
        store,
        cx,
        head_key,
        scope,
        keys.iter().map(|key| (key, None)),
        checkpoint,
    )
    .await
}

/// Failure verifying the identities required by a bound batch. Ordinary
/// key recovery retains its existing missing-key observations and errors.
#[derive(Debug)]
pub enum BoundRecoveryFailure {
    /// Another store or recovery error, including cancellation.
    Recovery(RecoveryFailure),
    /// The immutable store could not read a required key binding.
    BindingRead(AuthorityFailure),
    /// A required key binding was absent or contained different bytes.
    BindingMismatch,
}

impl std::fmt::Display for BoundRecoveryFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recovery(error) => std::fmt::Display::fmt(error, out),
            Self::BindingRead(error) => write!(out, "read expected request key binding: {error}"),
            Self::BindingMismatch => out.write_str("expected request key binding differs"),
        }
    }
}

impl std::error::Error for BoundRecoveryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recovery(error) => Some(error),
            Self::BindingRead(error) => Some(error),
            Self::BindingMismatch => None,
        }
    }
}

impl From<RecoveryFailure> for BoundRecoveryFailure {
    fn from(error: RecoveryFailure) -> Self {
        Self::Recovery(error)
    }
}

/// Recover keys whose immutable bindings must match independently reconstructed
/// identities, including children of a verified receive-session descriptor.
/// A missing or different binding is an integrity error even for an unsealed
/// child. A matching binding still requires the ordinary seal and outcome checks.
pub async fn recover_bound_requests_async<S, C>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    scope: RecoveryScope,
    keys: &[(IdempotencyKey, TxId)],
    checkpoint: &C,
) -> Result<Vec<RequestRecovery>, BoundRecoveryFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    check_batch_scope(store, cx, head_key, scope, keys.len(), checkpoint).await?;
    // A corrupt descriptor is refused before reading any seal or outcome.
    // The slots are immutable, so the shared replay can reuse these checks.
    for (key, identity) in keys {
        check(checkpoint)?;
        let slot = idempotency_binding_key(
            scope.tenant_id,
            scope.repository_id,
            scope.principal_id,
            key,
        )
        .map_err(RecoveryFailure::from)?;
        let mut encoded = Encoder::new();
        encoded
            .write_internal_object_id(identity.as_internal_object_id())
            .map_err(RecoveryFailure::from)?;
        let binding = store
            .read_immutable(cx, &slot)
            .await
            .map_err(BoundRecoveryFailure::BindingRead)?;
        if !matches!(binding, ImmutableRead::Present(bytes) if bytes == encoded.into_bytes()) {
            return Err(BoundRecoveryFailure::BindingMismatch);
        }
    }
    recover_batch(
        store,
        cx,
        head_key,
        scope,
        keys.iter().map(|(key, expected)| (key, Some(*expected))),
        checkpoint,
    )
    .await
    .map_err(BoundRecoveryFailure::Recovery)
}

async fn check_batch_scope<S, C>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    scope: RecoveryScope,
    count: usize,
    checkpoint: &C,
) -> Result<(), RecoveryFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    if count > MAX_RECOVERY_KEYS {
        return Err(RecoveryFailure::BoundExceeded {
            field: "request key count",
            limit: MAX_RECOVERY_KEYS,
            observed: count,
        });
    }
    // Scope authentication is required even if no key or seal is observed.
    authenticated_head(store, cx, head_key, scope, checkpoint).await?;
    Ok(())
}

async fn recover_batch<'key, S, C>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    scope: RecoveryScope,
    keys: impl ExactSizeIterator<Item = (&'key IdempotencyKey, Option<TxId>)> + Send,
    checkpoint: &C,
) -> Result<Vec<RequestRecovery>, RecoveryFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    let mut pending = Vec::with_capacity(keys.len());
    let mut outcomes: BTreeMap<TxId, Option<TerminalOutcome>> = BTreeMap::new();
    for (key, expected) in keys {
        check(checkpoint)?;
        let observed = if let Some(verified) = expected {
            Some(verified)
        } else {
            let slot = idempotency_binding_key(
                scope.tenant_id,
                scope.repository_id,
                scope.principal_id,
                key,
            )?;
            let binding = store.read_immutable(cx, &slot).await?;
            check(checkpoint)?;
            binding_identity(binding)?
        };
        let Some(tx_id) = observed else {
            pending.push(PendingRecovery::Observation(
                RequestRecovery::KeyNotObserved,
            ));
            continue;
        };
        let slot = seal_key(scope.tenant_id, scope.repository_id, tx_id)?;
        let stored = store.read_immutable(cx, &slot).await?;
        check(checkpoint)?;
        let Some((seal, seal_id)) = checked_seal(stored, scope, key, tx_id)? else {
            pending.push(PendingRecovery::Observation(
                RequestRecovery::SealNotObserved,
            ));
            continue;
        };
        check(checkpoint)?;
        let indexed =
            indexed_outcome_async(store, cx, scope.tenant_id, scope.repository_id, tx_id).await?;
        check(checkpoint)?;
        outcomes.entry(tx_id).or_insert(None);
        pending.push(PendingRecovery::Sealed {
            seal,
            seal_id,
            indexed,
        });
    }
    if !outcomes.is_empty() {
        // Every accelerator observation precedes this read. Only this exact
        // authenticated head and the immutable links it names supply outcomes.
        let mut head = authenticated_head(store, cx, head_key, scope, checkpoint).await?;
        let mut walked = 0;
        let mut remaining = outcomes.len();
        while remaining != 0 {
            check(checkpoint)?;
            let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? else {
                break;
            };
            let batch = read_decision_batch_body_async(store, cx, batch_id).await?;
            check(checkpoint)?;
            if batch.repository_id != scope.repository_id {
                return Err(integrity("decision batch repository"));
            }
            // The complete canonical batch, including unqueried decisions and
            // inline RCRs, has already been decoded and re-identified above.
            for decision in &batch.decisions {
                check(checkpoint)?;
                if let Some(found) = outcomes.get_mut(&decision.tx_id)
                    && found.is_none()
                {
                    *found = Some(TerminalOutcome {
                        decision_sequence: decision.decision_sequence,
                        outcome: decision.outcome,
                    });
                    remaining -= 1;
                    if remaining == 0 {
                        break;
                    }
                }
            }
            if remaining == 0 {
                break;
            }
            check(checkpoint)?;
            head = read_authority_head_body_async(store, cx, batch.predecessor_head_id).await?;
            check(checkpoint)?;
            if head.repository_id != scope.repository_id {
                return Err(integrity("predecessor head repository"));
            }
        }
    }
    let mut results = Vec::with_capacity(pending.len());
    for observation in pending {
        match observation {
            PendingRecovery::Observation(observation) => results.push(observation),
            PendingRecovery::Sealed {
                seal,
                seal_id,
                indexed,
            } => {
                let found = outcomes
                    .get(&seal.tx_id)
                    .ok_or_else(|| integrity("selected outcome missing"))?;
                let replayed = found.map_or(OutcomeLookup::Undecided, OutcomeLookup::Decided);
                results.push(finish(
                    seal,
                    seal_id,
                    reconcile_outcome(indexed, replayed)?,
                    checkpoint,
                )?);
            }
        }
    }
    // Like single-key recovery, no post-resolution probe can turn an already
    // authenticated terminal result into an interruption. Partial observations
    // still require a live request. This final bounded pass performs no I/O.
    if results.iter().any(|result| result.terminal().is_none()) {
        check(checkpoint)?;
    }
    Ok(results)
}

async fn authenticated_head<S, C>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    scope: RecoveryScope,
    checkpoint: &C,
) -> Result<RepositoryAuthorityHeadBody, RecoveryFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    check(checkpoint)?;
    let receipt = head_receipt(store.read_head(cx, head_key).await?)?;
    check(checkpoint)?;
    let authenticated = store.authenticate_head_receipt(cx, &receipt).await?;
    check_head(
        &receipt,
        &authenticated,
        store.instance_id(),
        head_key,
        scope,
    )?;
    check(checkpoint)?;
    Ok(decode_body(receipt.body(), LIMITS)?)
}

#[cfg(test)]
mod tests;
