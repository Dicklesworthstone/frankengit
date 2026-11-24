//! Reuse a verified prefix after several publications between client polls.
//! Generation distance only bounds the search; exact authenticated ancestry
//! establishes whether this prefix belongs to the newly selected head.

use super::*;
use fgit_chronicle::{HistoryStep, read_history_step_async};

/// Optional acceleration may verify at most this many unobserved head edges.
/// Longer gaps use ordinary replay with its existing request/work limits.
const MAX_CATCH_UP_EDGES: u64 = 64;

impl VerifiedEventIndex {
    /// Cheap eligibility check for a host's optional catch-up attempt. This is
    /// neither an ancestry proof nor authorization to disclose any event.
    #[must_use]
    pub fn can_catch_up_at(&self, basis: &PublicationBasis) -> bool {
        basis
            .body()
            .generation
            .get()
            .checked_sub(self.source_generation.get())
            .is_some_and(|distance| (1..=MAX_CATCH_UP_EDGES).contains(&distance))
    }

    /// Verify a bounded suffix and reuse this index only if its exact source
    /// head is the suffix's ancestor. Unlike `extend_at`, this permits several
    /// publications between reads, including refusals and checkpoints.
    ///
    /// Same/older heads, gaps over 64 edges, and an independently verified fork
    /// return `Ok(None)`. Missing/corrupt required evidence is an error, never a
    /// cache hit. Every new edge and sequence is checked by the ordinary history
    /// verifier. Complete-history, retained-byte, and cancellation limits still
    /// apply, and all errors leave the original index unchanged.
    ///
    /// Storage work is O(new edges), plus at most two canonical empty bodies;
    /// the immutable descriptor copy remains O(retained rows). Event payloads
    /// and current disclosure policy must still be verified by each page reader.
    pub async fn catch_up_at<S, C>(
        &self,
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        max_retained_bytes: usize,
        cancelled: &C,
    ) -> Result<Option<Self>, AdmissionError>
    where
        S: AsyncAuthorityStore + ?Sized,
        C: Fn() -> bool + Sync,
    {
        checkpoint(cancelled)?;
        self.check_binding(store, basis)?;
        if basis.body().generation <= self.source_generation {
            return Ok(None);
        }
        // Profile ceilings apply to the complete history even though only the
        // new suffix needs I/O. A generation difference is never ancestry proof.
        let total_edges = usize::try_from(basis.body().generation.get() - 1)
            .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        let total_records = basis
            .body()
            .latest_repository_sequence
            .map_or(0, |sequence| sequence.get());
        if total_edges > history::Limits::DEFAULT.batches
            || total_records > history::Limits::DEFAULT.records as u64
            || retained_bytes(self.records.len())? > max_retained_bytes
        {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        if !self.can_catch_up_at(basis) {
            return Ok(None);
        }
        let mut successor = basis.body().clone();
        let mut walked = 0;
        let mut reverse = Vec::new();
        loop {
            checkpoint(cancelled)?;
            let step = read_history_step_async(
                store,
                cx,
                &successor,
                &mut walked,
                MAX_CATCH_UP_EDGES as usize,
                cancelled,
            )
            .await
            .map_err(storage::history_step_refusal)?;
            let (predecessor, committed) = match step {
                HistoryStep::Genesis => return Err(unavailable(RefusalCode::EvidenceInvalid)),
                HistoryStep::Checkpoint { predecessor, .. } => (predecessor, Vec::new()),
                HistoryStep::Decision { predecessor, batch } => (predecessor, batch.committed_rcrs),
            };
            let previous_records = predecessor
                .body()
                .latest_repository_sequence
                .map_or(0, |sequence| sequence.get());
            let successor_records = successor
                .latest_repository_sequence
                .map_or(0, |sequence| sequence.get());
            if predecessor.body().repository_id != self.repository
                || previous_records.checked_add(committed.len() as u64) != Some(successor_records)
            {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            reverse
                .len()
                .checked_add(committed.len())
                .filter(|count| *count <= history::Limits::DEFAULT.records)
                .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            reverse
                .try_reserve(committed.len())
                .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            for record in committed.into_iter().rev() {
                checkpoint(cancelled)?;
                if record.repository_id != self.repository {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                reverse.push(Record {
                    sequence: record.repository_sequence.get(),
                    tx_id: record.tx_id,
                    policy_epoch: record.policy_epoch,
                    principal_snapshot_id: record.principal_snapshot_id,
                    event_root: record.forge_event_batch_root,
                });
            }
            if predecessor.body().generation <= self.source_generation {
                checkpoint(cancelled)?;
                if predecessor.id() != self.source_head {
                    return Ok(None);
                }
                if predecessor.body().generation != self.source_generation
                    || previous_records != self.repository_sequence
                    || self.repository_sequence.checked_add(reverse.len() as u64)
                        != Some(total_records)
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                break;
            }
            successor = predecessor.body().clone();
        }
        reverse.reverse();
        Self::retain_at(
            store,
            cx,
            basis,
            &self.records,
            reverse,
            max_retained_bytes,
            cancelled,
        )
        .await
        .map(Some)
    }
}
