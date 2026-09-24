//! Non-consuming, snapshot-pinned reads of accepted check proposal history.
//!
//! Delivery removes a batch from the pending queue, not from retained history.
//! This reader includes acknowledged batches without resubmitting, settling,
//! repairing or running anything. A verified proposal is still not a check.
use super::{
    BTreeMap, BTreeSet, Binding, CheckDeliveryAcknowledgement, CheckDeliveryBatch,
    CheckDeliveryRefusal, CheckDeliverySink, CheckJournalPin, CheckRunStatus, Commitment,
    CoordinatorExecutionProfile, FileCheckJournal, HEADER_BYTES, root,
};
use std::ops::Bound::{Excluded, Unbounded};

/// Typed local evidence readers. These do not authenticate check issuers.
pub use crate::coordinator::scoped_workflow::journaled::observations::{
    MAX_OBSERVATION_BYTES, ObservationRefusal, VerifiedLocalObservation,
    decode_trusted_observation, verify_trusted_job,
};

pub const MAX_HISTORY_BATCHES: usize = 128;
pub const MAX_HISTORY_BYTES: usize = 8 * 1024 * 1024;

/// Exact accepted bytes and, separately, the recorded downstream custody root.
/// The root is not a canonical forge publication or a successful check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckHistoryEntry {
    batch: CheckDeliveryBatch,
    delivered: Option<Commitment>,
}
impl CheckHistoryEntry {
    #[must_use]
    pub const fn batch(&self) -> &CheckDeliveryBatch {
        &self.batch
    }
    #[must_use]
    pub const fn delivery_receipt(&self) -> Option<Commitment> {
        self.delivered
    }
}

/// Bounded page in physical acceptance order, pinned to the complete journal.
/// Continue with BOTH `snapshot()` and `next_after()`. An appended acknowledgement
/// changes the snapshot and requires a new traversal; pages never mix versions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckHistoryPage {
    snapshot: CheckJournalPin,
    entries: Vec<CheckHistoryEntry>,
    next_after: Option<Commitment>,
}
impl CheckHistoryPage {
    #[must_use]
    pub const fn snapshot(&self) -> CheckJournalPin {
        self.snapshot
    }
    #[must_use]
    pub fn entries(&self) -> &[CheckHistoryEntry] {
        &self.entries
    }
    #[must_use]
    pub const fn next_after(&self) -> Option<Commitment> {
        self.next_after
    }
}

impl FileCheckJournal {
    /// Number of accepted batches, including acknowledged history. No evidence
    /// or execution-completeness claim follows from this count.
    #[must_use]
    pub fn retained_batches(&self) -> usize {
        self.batches.len()
    }

    /// Read one exact accepted batch even after it was delivered. Recheck its
    /// proposal and acknowledgement records. Referenced evidence remains a
    /// separate bounded `read_evidence` operation: listing metadata must not
    /// amplify one small request into repeated 64 MiB evidence-body reads.
    pub fn read_retained_batch(
        &mut self,
        id: Commitment,
    ) -> Result<CheckHistoryEntry, CheckDeliveryRefusal> {
        self.healthy()?;
        let stored = self
            .batches
            .get(&id)
            .ok_or(CheckDeliveryRefusal::StaleBatch)?;
        let frame = stored.frame;
        let delivered = stored.delivered;
        let payload = self.read_frame(frame)?;
        let batch = payload
            .get(1..)
            .filter(|_| payload.first() == Some(&1))
            .and_then(|bytes| CheckDeliveryBatch::decode(bytes).ok());
        let Some(batch) = batch.filter(|batch| {
            batch.id() == id
                && batch.tenant == self.scope.tenant
                && batch.repository == self.scope.repository
                && self.bindings.get(&batch.run) == Some(&Binding::of(batch))
        }) else {
            self.failed = true;
            return Err(CheckDeliveryRefusal::CorruptJournal);
        };
        if let Some((receipt, ack_frame)) = delivered {
            let payload = self.read_frame(ack_frame)?;
            let mut expected = vec![2];
            root(&mut expected, id);
            root(&mut expected, receipt);
            if payload != expected {
                self.failed = true;
                return Err(CheckDeliveryRefusal::CorruptJournal);
            }
        }
        Ok(CheckHistoryEntry {
            batch,
            delivered: delivered.map(|(receipt, _)| receipt),
        })
    }

    /// Decode one completed job's retained evidence at an exact journal snapshot.
    /// Selection is checked before reading evidence, including the body-size
    /// ceiling before allocating it. Delivered batches remain inspectable. No
    /// proposal is settled, forwarded or converted into a canonical check.
    /// The caller authorizes disclosure of the retained source and logs.
    pub fn read_trusted_job(
        &mut self,
        expected: CheckJournalPin,
        batch_id: Commitment,
        fact_index: usize,
        maximum_evidence_bytes: usize,
        live: &dyn Fn() -> bool,
    ) -> Result<VerifiedLocalObservation, ObservationRefusal> {
        self.healthy()?;
        if maximum_evidence_bytes == 0 || maximum_evidence_bytes > MAX_OBSERVATION_BYTES {
            return Err(ObservationRefusal::InvalidLimits);
        }
        if !live() {
            return Err(ObservationRefusal::Cancelled);
        }
        if expected != self.pin {
            return Err(CheckDeliveryRefusal::StaleBatch.into());
        }
        self.verify_checkpoint(expected)?;
        let retained = self.read_retained_batch(batch_id)?;
        if !matches!(
            retained.batch.execution_profile(),
            CoordinatorExecutionProfile::TrustedWorkflow { .. }
        ) {
            return Err(ObservationRefusal::UnsupportedProfile);
        }
        let fact = retained
            .batch
            .facts()
            .get(fact_index)
            .ok_or(ObservationRefusal::FactNotCompleted)?;
        if fact.status != CheckRunStatus::Completed {
            return Err(ObservationRefusal::FactNotCompleted);
        }
        let id = fact
            .receipt_commitment
            .ok_or(ObservationRefusal::EvidenceMissing)?;
        let stored = self
            .evidence
            .get(&id)
            .ok_or(ObservationRefusal::EvidenceMissing)?;
        let bytes = stored
            .length
            .checked_sub(33)
            .ok_or(CheckDeliveryRefusal::CorruptJournal)?;
        if bytes > maximum_evidence_bytes {
            return Err(ObservationRefusal::RecordTooLarge);
        }
        if !live() {
            return Err(ObservationRefusal::Cancelled);
        }
        let evidence = self.read_evidence(id)?;
        verify_trusted_job(
            &retained.batch,
            fact_index,
            &evidence,
            maximum_evidence_bytes,
            live,
        )
    }

    /// Page all accepted batches, including delivered batches, without changing
    /// pending custody. `maximum_bytes` bounds the sum of returned batch bodies
    /// plus 32 bytes for each delivery receipt, not their later JSON expansion.
    /// A first entry that cannot fit is a refusal, never a misleading empty page.
    ///
    /// `after` must name an accepted batch in this exact `expected` snapshot.
    /// Unknown cursors, missing snapshot pins and snapshots changed by append
    /// all refuse. A caller may keep a returned pin as a minimum on reopen;
    /// the page pin itself is a local observation, not an external trust witness.
    pub fn read_history(
        &mut self,
        expected: Option<CheckJournalPin>,
        after: Option<Commitment>,
        maximum_batches: usize,
        maximum_bytes: usize,
        live: &dyn Fn() -> bool,
    ) -> Result<CheckHistoryPage, CheckDeliveryRefusal> {
        self.healthy()?;
        if maximum_batches == 0
            || maximum_batches > MAX_HISTORY_BATCHES
            || maximum_bytes == 0
            || maximum_bytes > MAX_HISTORY_BYTES
        {
            return Err(CheckDeliveryRefusal::InvalidLimits);
        }
        if !live() {
            return Err(CheckDeliveryRefusal::Cancelled);
        }
        if expected.is_some_and(|pin| pin != self.pin) || (after.is_some() && expected.is_none()) {
            return Err(CheckDeliveryRefusal::StaleBatch);
        }
        // Also check an empty page. Cached indexes cannot make truncated files
        // look like a clean, empty journal, and the header stays scope-bound.
        self.verify_checkpoint(CheckJournalPin::new(
            HEADER_BYTES,
            Commitment::of_bytes(&self.scope.bytes()),
        ))?;
        let start = match after {
            Some(id) => {
                self.batches
                    .get(&id)
                    .ok_or(CheckDeliveryRefusal::StaleBatch)?
                    .frame
                    .offset
            }
            None => 0,
        };
        // Rebuilt with the other bounded indexes. Only max+1 IDs are copied;
        // paging does not collect/sort the entire history on each request.
        let candidates = self
            .batch_order
            .range((Excluded(start), Unbounded))
            .take(maximum_batches + 1)
            .map(|(_, id)| *id)
            .collect::<Vec<_>>();
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        let mut more = false;
        for id in candidates {
            if !live() {
                return Err(CheckDeliveryRefusal::Cancelled);
            }
            if entries.len() == maximum_batches {
                more = true;
                break;
            }
            let stored = self
                .batches
                .get(&id)
                .ok_or(CheckDeliveryRefusal::CorruptJournal)?;
            let size = stored
                .frame
                .length
                .checked_sub(1)
                .and_then(|n| n.checked_add(if stored.delivered.is_some() { 32 } else { 0 }))
                .ok_or(CheckDeliveryRefusal::CorruptJournal)?;
            if size > maximum_bytes - bytes {
                if entries.is_empty() {
                    return Err(CheckDeliveryRefusal::BatchTooLarge);
                }
                more = true;
                break;
            }
            entries.push(self.read_retained_batch(id)?);
            bytes += size;
        }
        if !live() {
            return Err(CheckDeliveryRefusal::Cancelled);
        }
        let next_after = if more {
            entries.last().map(|entry| entry.batch.id())
        } else {
            None
        };
        Ok(CheckHistoryPage {
            snapshot: self.pin,
            entries,
            next_after,
        })
    }

    /// Read evidence only when the selected retained batch actually references
    /// it. This prevents a recovery selector from disclosing unrelated evidence
    /// left by a failed submission in the same repository journal.
    pub fn read_batch_evidence(
        &mut self,
        batch: Commitment,
        evidence: Commitment,
    ) -> Result<Vec<u8>, CheckDeliveryRefusal> {
        let retained = self.read_retained_batch(batch)?;
        if !retained
            .batch
            .facts
            .iter()
            .any(|fact| fact.receipt_commitment == Some(evidence))
        {
            return Err(CheckDeliveryRefusal::EvidenceMissing);
        }
        self.read_evidence(evidence)
    }
}

#[cfg(test)]
mod tests;

mod exchange;
