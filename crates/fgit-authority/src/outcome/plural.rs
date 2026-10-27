//! One authoritative decision-history walk for several transaction identities.

use super::{
    AsyncAuthorityStore, AuthorityStore, BTreeMap, HeadKey, HeadRead, OutcomeFailure,
    OutcomeLookup, RepositoryDecisionBatchBody, RepositoryId, TenantId, TerminalOutcome, TxId,
    head_body_of, indexed_outcome, indexed_outcome_async, next_batch_to_replay,
    read_decision_batch_body, read_decision_batch_body_async, read_predecessor,
    read_predecessor_async, reconcile_outcome,
};

#[derive(Clone, Copy)]
struct Observation {
    indexed: OutcomeLookup,
    replayed: OutcomeLookup,
}

fn observe_batch(
    observations: &mut BTreeMap<TxId, Observation>,
    remaining: &mut usize,
    batch: &RepositoryDecisionBatchBody,
) {
    for decision in &batch.decisions {
        if let Some(observation) = observations.get_mut(&decision.tx_id)
            && observation.replayed == OutcomeLookup::Undecided
        {
            observation.replayed = OutcomeLookup::Decided(TerminalOutcome {
                decision_sequence: decision.decision_sequence,
                outcome: decision.outcome,
            });
            *remaining -= 1;
            if *remaining == 0 {
                break;
            }
        }
    }
}

fn finish(
    observations: &BTreeMap<TxId, Observation>,
    tx_ids: &[TxId],
) -> Result<Vec<(TxId, OutcomeLookup)>, OutcomeFailure> {
    tx_ids
        .iter()
        .map(|tx_id| {
            let observation = observations
                .get(tx_id)
                .ok_or(OutcomeFailure::StreamBodyMissing {
                    link: "requested transaction lookup",
                })?;
            Ok((
                *tx_id,
                reconcile_outcome(observation.indexed, observation.replayed)?,
            ))
        })
        .collect()
}

/// Resolve several transactions from one fresh authenticated history snapshot.
///
/// All accelerator hints are read before selecting that head. A concurrent
/// atomic publication therefore cannot supply a hint newer than the selected
/// history. Hints never prove absence or replace replay, and each result uses
/// the same fail-closed reconciliation as [`super::resolve_outcome`].
///
/// Results preserve requested order, including duplicate identities. Duplicates
/// share one hint and one history observation. Empty input performs no I/O.
/// Memory for lookup state is proportional to the unique requested identities,
/// not the repository's history; the output is proportional to the input slice.
///
/// Replay reidentifies complete canonical batch and predecessor bodies with
/// the ordinary readers and retains [`super::MAX_REPLAY_BATCHES`]. It stops as soon
/// as every requested terminal is found, without reading older predecessors.
/// If any target remains undecided, the bounded walk must reach genesis. No
/// partial result is returned after a read, integrity, or resource failure.
pub fn resolve_outcomes<S>(
    store: &S,
    head_key: &HeadKey,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_ids: &[TxId],
) -> Result<Vec<(TxId, OutcomeLookup)>, OutcomeFailure>
where
    S: AuthorityStore + ?Sized,
{
    if tx_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut observations = BTreeMap::new();
    for tx_id in tx_ids {
        if let std::collections::btree_map::Entry::Vacant(entry) = observations.entry(*tx_id) {
            entry.insert(Observation {
                indexed: indexed_outcome(store, tenant_id, repository_id, *tx_id)?,
                replayed: OutcomeLookup::Undecided,
            });
        }
    }
    if let HeadRead::Present(receipt) = store.read_head(head_key)? {
        let authenticated = store.authenticate_head_receipt(&receipt)?;
        let mut head = head_body_of(authenticated.receipt())?;
        let mut remaining = observations.len();
        let mut walked = 0;
        while remaining != 0 {
            let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? else {
                break;
            };
            let batch = read_decision_batch_body(store, batch_id)?;
            observe_batch(&mut observations, &mut remaining, &batch);
            if remaining == 0 {
                break;
            }
            let Some(previous) = read_predecessor(store, batch.predecessor_head_id)? else {
                break;
            };
            head = previous;
        }
    }
    finish(&observations, tx_ids)
}

/// Asynchronous twin of [`resolve_outcomes`], using the caller's authority
/// context for every hint, head authentication, and immutable history read.
pub async fn resolve_outcomes_async<S>(
    store: &S,
    cx: &S::Context,
    head_key: &HeadKey,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tx_ids: &[TxId],
) -> Result<Vec<(TxId, OutcomeLookup)>, OutcomeFailure>
where
    S: AsyncAuthorityStore + ?Sized,
{
    if tx_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut observations = BTreeMap::new();
    for tx_id in tx_ids {
        if let std::collections::btree_map::Entry::Vacant(entry) = observations.entry(*tx_id) {
            entry.insert(Observation {
                indexed: indexed_outcome_async(store, cx, tenant_id, repository_id, *tx_id).await?,
                replayed: OutcomeLookup::Undecided,
            });
        }
    }
    if let HeadRead::Present(receipt) = store.read_head(cx, head_key).await? {
        let authenticated = store.authenticate_head_receipt(cx, &receipt).await?;
        let mut head = head_body_of(authenticated.receipt())?;
        let mut remaining = observations.len();
        let mut walked = 0;
        while remaining != 0 {
            let Some(batch_id) = next_batch_to_replay(&head, &mut walked)? else {
                break;
            };
            let batch = read_decision_batch_body_async(store, cx, batch_id).await?;
            observe_batch(&mut observations, &mut remaining, &batch);
            if remaining == 0 {
                break;
            }
            let Some(previous) =
                read_predecessor_async(store, cx, batch.predecessor_head_id).await?
            else {
                break;
            };
            head = previous;
        }
    }
    finish(&observations, tx_ids)
}
