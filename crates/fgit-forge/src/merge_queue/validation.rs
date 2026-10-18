//! Structural checks shared by speculative evaluation, landing and receipts.
//!
//! These checks do not grant admission. The caller must still observe tips and
//! aggregate positions at the exact authority predecessor it will replace.

use std::collections::BTreeSet;

use fgit_codec::CodecRefusal;
use fgit_types::{GitOid, RefName};

use super::{BatchStatus, QueueBatchEntry, QueueBatchId, QueueBatchReceipt, SpeculativeBatchPlan};
use crate::ForgeRefusal;
use crate::event::NativeMerge;
use crate::event::queue::MAX_QUEUE_ENTRIES;

pub(super) fn invalid_queue(field: &'static str) -> ForgeRefusal {
    ForgeRefusal::BodyUnrepresentable {
        cause: Box::new(CodecRefusal::ValueUnrepresentable {
            field,
            observed: 0,
            limit: 1,
        }),
    }
}

fn validate_batch_identity(
    batch_id: QueueBatchId,
    target_ref: &RefName,
    base_tip: GitOid,
    entries: &[QueueBatchEntry],
) -> Result<(), ForgeRefusal> {
    if entries.is_empty() || entries.len() > MAX_QUEUE_ENTRIES {
        return Err(invalid_queue("queue.batch.entries"));
    }
    if !target_ref.as_bytes().starts_with(b"refs/heads/") || base_tip.is_zero() {
        return Err(invalid_queue("queue.batch.target"));
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        if !seen.insert(entry.pull_request) {
            return Err(invalid_queue("queue.batch.duplicate_pull_request"));
        }
        if entry.source_ref == *target_ref
            || !entry.source_ref.as_bytes().starts_with(b"refs/heads/")
            || entry.head_tip.is_zero()
            || entry.head_tip.algorithm() != base_tip.algorithm()
        {
            return Err(invalid_queue("queue.batch.candidate"));
        }
    }
    if QueueBatchId::compute(target_ref, base_tip, entries)? != batch_id {
        return Err(invalid_queue("queue.batch.identity"));
    }
    Ok(())
}

impl SpeculativeBatchPlan {
    /// Verify the complete, bounded speculative chain before it can be used.
    ///
    /// An intact batch identity alone is insufficient: it binds the candidates,
    /// not the intermediate merge results. Every step must extend the previous
    /// result and the final step must produce the declared target tip. All
    /// steps belong to one workspace epoch and use the native branch profile.
    pub fn validate(&self) -> Result<(), ForgeRefusal> {
        if self.steps.is_empty() || self.steps.len() > MAX_QUEUE_ENTRIES {
            return Err(invalid_queue("speculative_plan.steps"));
        }
        let epoch = self.steps[0].workspace_epoch;
        let mut expected_base = self.initial_target_tip;
        let mut entries = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            if step.projected_base_tip != expected_base {
                return Err(invalid_queue("speculative_plan.chain"));
            }
            if step.workspace_epoch != epoch {
                return Err(invalid_queue("speculative_plan.workspace_epoch"));
            }
            NativeMerge {
                source_ref: step.candidate_source_ref.clone(),
                source_tip: step.candidate_tip,
                base_tip: step.merge_base_tip,
                target_ref: self.target_ref.clone(),
                target_tip_before: step.projected_base_tip,
                merge_commit: step.resulting_speculative_tip,
            }
            .validate()
            .map_err(|cause| ForgeRefusal::BodyUnrepresentable {
                cause: Box::new(cause),
            })?;
            entries.push(QueueBatchEntry {
                pull_request: step.pull_request,
                source_ref: step.candidate_source_ref.clone(),
                head_tip: step.candidate_tip,
            });
            expected_base = step.resulting_speculative_tip;
        }
        if expected_base != self.final_target_tip {
            return Err(invalid_queue("speculative_plan.final_target_tip"));
        }
        validate_batch_identity(
            self.batch_id,
            &self.target_ref,
            self.initial_target_tip,
            &entries,
        )
    }
}

impl QueueBatchReceipt {
    /// Check the receipt's claimed candidates against its batch commitment.
    ///
    /// The v1 receipt digest already commits to the batch ID. Recomputing that
    /// ID prevents substituted, omitted or reordered entries from retaining a
    /// valid attestation, without changing the bytes of valid v1 receipts.
    /// A receipt is evidence of a reported outcome, not permission to land it.
    pub fn validate(&self) -> Result<(), ForgeRefusal> {
        validate_batch_identity(self.batch_id, &self.target_ref, self.base_tip, &self.entries)?;
        if self.resulting_tip.algorithm() != self.base_tip.algorithm()
            || (matches!(self.status, BatchStatus::SpeculativePass | BatchStatus::Landed)
                && self.resulting_tip.is_zero())
        {
            return Err(invalid_queue("queue.receipt.resulting_tip"));
        }
        Ok(())
    }
}
