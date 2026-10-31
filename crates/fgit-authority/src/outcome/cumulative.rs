//! Reuse of an exact authority-derived outcome set for resolution and publication.
//!
//! This is disposable process state. It neither changes the outcome commitment
//! nor permits a cache to authorize a different head. The ordinary replay APIs
//! remain the fallback when another writer wins or the retained set is lost.

use super::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityStore, AuthorityVersionToken,
    CumulativeOutcomes, DuplicateAbsenceWitness, DuplicateScan, HeadKey, HeadRead, HeadReadReceipt,
    OutcomeFailure, OutcomeLookup, PublicationOutcome, RepositoryAuthorityHeadBody,
    RepositoryDecisionBatchBody, RepositoryId, TenantId, TerminalOutcome, TxId,
    authority_head_identity, decision_batch_identity, fold_outcome_index, indexed_outcome,
    indexed_outcome_async, publish_decisions_impl, publish_decisions_impl_async, reconcile_outcome,
};

/// Publish using a complete outcome set already collected at `expected`.
///
/// The set replaces only the duplicate-history scan. A fresh authenticated
/// head must select its exact token and root, and the ordinary atomic
/// head/outcome replacement still checks that token. An accelerator miss never
/// establishes absence. Generic callers can continue using [`super::publish_decisions`].
pub fn publish_decisions_with_cumulative<S>(
    store: &S,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
    tenant_id: TenantId,
    cumulative: &CumulativeOutcomes,
) -> Result<PublicationOutcome, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    publish_decisions_impl(
        store,
        head_key,
        expected,
        batch,
        head,
        tenant_id,
        Some(cumulative),
    )
}

/// Asynchronous twin of [`publish_decisions_with_cumulative`].
pub async fn publish_decisions_with_cumulative_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
    tenant_id: TenantId,
    cumulative: &CumulativeOutcomes,
) -> Result<PublicationOutcome, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    publish_decisions_impl_async(
        store,
        cx,
        head_key,
        expected,
        batch,
        head,
        tenant_id,
        Some(cumulative),
    )
    .await
}

/// Resolve one terminal outcome from a complete set collected at `expected`.
///
/// A retained checkpoint or a prior authoritative collection can supply this
/// set; an accelerator alone cannot. Read the accelerator before selecting and
/// authenticating the current head, then require that head's exact token,
/// repository and outcome root to agree with the retained set. A concurrent
/// publication therefore cannot make a newer hint look like corruption of an
/// older witness. The ordinary [`super::reconcile_outcome`] rule still refuses
/// genuine conflicts and still resolves a missing hint from authority.
///
/// `None` means the head is absent or no longer matches `expected`: the caller
/// must collect a new witness and replan. It never establishes that the
/// transaction is undecided. Only `Some(OutcomeLookup::Undecided)` proves
/// absence at the authenticated head checked here. Later head movement remains
/// possible, so a publication must still condition on the same exact token.
///
/// This performs no decision-history reads or writes. It recomputes the root
/// over the already retained set and preserves the original empty-genesis
/// compatibility rule. A mismatched witness token, repository or root, invalid
/// head authentication, accelerator conflict, and store failures remain typed
/// errors rather than being treated as a cache miss.
pub fn resolve_outcome_with_cumulative<S>(
    store: &S,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_id: TxId,
    cumulative: &CumulativeOutcomes,
) -> Result<Option<OutcomeLookup>, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    check_token(cumulative, expected)?;
    let indexed = indexed_outcome(store, tenant_id, repository_id, tx_id)?;
    let HeadRead::Present(receipt) = store.read_head(head_key)? else {
        return Ok(None);
    };
    let authenticated = store.authenticate_head_receipt(&receipt)?;
    resolve_authenticated(
        cumulative,
        head_key,
        expected,
        repository_id,
        tx_id,
        indexed,
        &authenticated,
    )
}

/// Asynchronous twin of [`resolve_outcome_with_cumulative`].
///
/// Every accelerator, head and authentication operation uses the caller's
/// original context. Cancellation and ambiguous reads propagate without
/// creating a replacement context or manufacturing an undecided answer.
pub async fn resolve_outcome_with_cumulative_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_id: TxId,
    cumulative: &CumulativeOutcomes,
) -> Result<Option<OutcomeLookup>, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    check_token(cumulative, expected)?;
    let indexed = indexed_outcome_async(store, cx, tenant_id, repository_id, tx_id).await?;
    let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? else {
        return Ok(None);
    };
    let authenticated = store.authenticate_head_receipt(cx, &receipt).await?;
    resolve_authenticated(
        cumulative,
        head_key,
        expected,
        repository_id,
        tx_id,
        indexed,
        &authenticated,
    )
}

fn resolve_authenticated(
    cumulative: &CumulativeOutcomes,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    repository_id: RepositoryId,
    tx_id: TxId,
    indexed: OutcomeLookup,
    authenticated: &AuthenticatedHead,
) -> Result<Option<OutcomeLookup>, OutcomeFailure> {
    if authenticated.receipt().key() != head_key {
        return Err(mismatch("head slot"));
    }
    if authenticated.receipt().token() != expected {
        return Ok(None);
    }
    let head = authenticated.body()?;
    if head.repository_id != repository_id {
        return Err(mismatch("repository"));
    }
    check_root(cumulative, &head)?;
    let replayed = cumulative
        .decision_for(tx_id)
        .map_or(OutcomeLookup::Undecided, OutcomeLookup::Decided);
    reconcile_outcome(indexed, replayed).map(Some)
}

const fn mismatch(field: &'static str) -> OutcomeFailure {
    OutcomeFailure::CumulativePublicationMismatch { field }
}

fn check_token(
    cumulative: &CumulativeOutcomes,
    expected: AuthorityVersionToken,
) -> Result<(), OutcomeFailure> {
    if cumulative.observed != expected {
        return Err(OutcomeFailure::CumulativeIndexStale {
            observed: cumulative.observed,
            expected,
        });
    }
    Ok(())
}

fn check_root(
    cumulative: &CumulativeOutcomes,
    head: &RepositoryAuthorityHeadBody,
) -> Result<(), OutcomeFailure> {
    // The original genesis contract allowed a sentinel outcome root before
    // the first decision. Its absence of a decision position proves the empty
    // set. Preserve that compatibility only at this empty boundary; every
    // nonempty position and every published successor uses the canonical root.
    if cumulative.entries.is_empty()
        && head.decision_tail_id.is_none()
        && head.latest_decision_sequence.is_none()
    {
        return Ok(());
    }
    if fold_outcome_index(&cumulative.entries, &[])? != head.outcome_index_root {
        return Err(mismatch("predecessor outcome root"));
    }
    Ok(())
}

fn scan(cumulative: &CumulativeOutcomes, tx_ids: &[TxId]) -> DuplicateScan {
    let decided: Vec<_> = tx_ids
        .iter()
        .filter_map(|tx_id| {
            cumulative
                .decision_for(*tx_id)
                .map(|outcome| (*tx_id, outcome))
        })
        .collect();
    if decided.is_empty() {
        DuplicateScan::Absent(DuplicateAbsenceWitness::minted_against(cumulative.observed))
    } else {
        DuplicateScan::Found {
            observed: cumulative.observed,
            decided,
        }
    }
}

pub(super) fn scan_current<S>(
    store: &S,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    cumulative: &CumulativeOutcomes,
    tx_ids: &[TxId],
) -> Result<Option<DuplicateScan>, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    check_token(cumulative, expected)?;
    let HeadRead::Present(receipt) = store.read_head(head_key)? else {
        return Ok(None);
    };
    let authenticated = store.authenticate_head_receipt(&receipt)?;
    if authenticated.receipt().key() != head_key {
        return Err(mismatch("head slot"));
    }
    if authenticated.receipt().token() != expected {
        return Ok(None);
    }
    check_root(cumulative, &authenticated.body()?)?;
    Ok(Some(scan(cumulative, tx_ids)))
}

pub(super) async fn scan_current_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    cumulative: &CumulativeOutcomes,
    tx_ids: &[TxId],
) -> Result<Option<DuplicateScan>, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    check_token(cumulative, expected)?;
    let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? else {
        return Ok(None);
    };
    let authenticated = store.authenticate_head_receipt(cx, &receipt).await?;
    if authenticated.receipt().key() != head_key {
        return Err(mismatch("head slot"));
    }
    if authenticated.receipt().token() != expected {
        return Ok(None);
    }
    check_root(cumulative, &authenticated.body()?)?;
    Ok(Some(scan(cumulative, tx_ids)))
}

impl CumulativeOutcomes {
    /// Extend this exact prefix through an authenticated published successor.
    ///
    /// Both receipts are reauthenticated by `store`; publicly constructible
    /// receipts or `AuthenticatedHead` markers are not proof of publication.
    /// The successor must be the immediate child of the retained predecessor
    /// and must select these exact batch bytes and the complete resulting
    /// outcome root. Staged candidates, unrelated winners and changed roots
    /// cannot rebind the retained token. A later head movement is harmless:
    /// the returned set remains bound to this historical successor, and a
    /// caller must observe that exact token before reusing it for publication.
    pub fn extend_after_publication<S>(
        self,
        store: &S,
        predecessor: &HeadReadReceipt,
        successor: &HeadReadReceipt,
        batch: &RepositoryDecisionBatchBody,
    ) -> Result<Self, OutcomeFailure>
    where
        S: AuthorityStore + ?Sized,
    {
        check_token(&self, predecessor.token())?;
        let predecessor = store.authenticate_head_receipt(predecessor)?;
        let successor = store.authenticate_head_receipt(successor)?;
        self.extend_authenticated(&predecessor, &successor, batch)
    }

    /// Asynchronous twin of [`Self::extend_after_publication`].
    pub async fn extend_after_publication_async<S>(
        self,
        store: &S,
        cx: &S::Context,
        predecessor: &HeadReadReceipt,
        successor: &HeadReadReceipt,
        batch: &RepositoryDecisionBatchBody,
    ) -> Result<Self, OutcomeFailure>
    where
        S: AsyncAuthorityStore + ?Sized,
    {
        check_token(&self, predecessor.token())?;
        let predecessor = store.authenticate_head_receipt(cx, predecessor).await?;
        let successor = store.authenticate_head_receipt(cx, successor).await?;
        self.extend_authenticated(&predecessor, &successor, batch)
    }

    fn extend_authenticated(
        mut self,
        predecessor: &AuthenticatedHead,
        successor: &AuthenticatedHead,
        batch: &RepositoryDecisionBatchBody,
    ) -> Result<Self, OutcomeFailure> {
        if predecessor.verified_against() != successor.verified_against() {
            return Err(mismatch("store instance"));
        }
        if predecessor.receipt().key() != successor.receipt().key() {
            return Err(mismatch("head slot"));
        }
        let previous = predecessor.body()?;
        let next = successor.body()?;
        check_root(&self, &previous)?;
        if next.repository_id != previous.repository_id
            || batch.repository_id != previous.repository_id
        {
            return Err(mismatch("repository"));
        }
        let previous_id = authority_head_identity(&previous)?;
        if next.predecessor_head_id != Some(previous_id) || batch.predecessor_head_id != previous_id
        {
            return Err(mismatch("predecessor head"));
        }
        if next.generation.get().checked_sub(1) != Some(previous.generation.get())
            || batch.predecessor_head_generation != previous.generation
        {
            return Err(mismatch("head generation"));
        }
        if next.decision_tail_id != Some(decision_batch_identity(batch)?) {
            return Err(mismatch("selected decision batch"));
        }
        let first = previous
            .latest_decision_sequence
            .map_or(Some(1), |sequence| sequence.get().checked_add(1))
            .ok_or_else(|| mismatch("decision sequence"))?;
        if batch.decisions.is_empty() || batch.first_decision_sequence.get() != first {
            return Err(mismatch("first decision sequence"));
        }
        for (index, decision) in batch.decisions.iter().enumerate() {
            let index = u64::try_from(index).map_err(|_| mismatch("decision sequence"))?;
            if first.checked_add(index) != Some(decision.decision_sequence.get()) {
                return Err(mismatch("decision sequence"));
            }
        }
        if next.latest_decision_sequence
            != batch
                .decisions
                .last()
                .map(|decision| decision.decision_sequence)
        {
            return Err(mismatch("latest decision sequence"));
        }
        let stamped: Vec<_> = batch
            .decisions
            .iter()
            .map(|decision| {
                (
                    decision.tx_id,
                    TerminalOutcome {
                        decision_sequence: decision.decision_sequence,
                        outcome: decision.outcome,
                    },
                )
            })
            .collect();
        let root = self.fold_against(predecessor.receipt().token(), &stamped)?;
        if root != batch.resulting_outcome_index_root || root != next.outcome_index_root {
            return Err(mismatch("successor outcome root"));
        }
        self.entries.extend(stamped);
        self.observed = successor.receipt().token();
        Ok(self)
    }
}
