//! A verified history suffix, not a caller-supplied sequence offset.
//!
//! Starting at the authenticated head, each link verifies the predecessor body,
//! decision batch and successor together. Once the cursor's RCR is reached,
//! older history cannot affect the requested page. The cursor's event index is
//! still checked by the payload reader; reaching an RCR alone is not success.

use super::{AdmissionError, ForgeEventCursor, Record, checkpoint, unavailable};
use fgit_authority::{AsyncAuthorityStore, authority_head_identity};
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::{CryptoBodyIdentity, RepositoryAuthorityHeadBody};
use fgit_types::{HeadGeneration, RefusalCode, RepositoryId};

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) batches: usize,
    pub(super) records: usize,
}
impl Limits {
    pub(super) const DEFAULT: Self = Self {
        batches: 4096,
        records: 65_536,
    };

    fn validate(self) -> Result<(), AdmissionError> {
        if self.batches == 0 || self.batches > Self::DEFAULT.batches
            || self.records == 0 || self.records > Self::DEFAULT.records
        {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        Ok(())
    }
}

pub(super) async fn read_records<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    after: Option<ForgeEventCursor>,
    limits: Limits,
    cancelled: &C,
) -> Result<Vec<Record>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    limits.validate()?;
    checkpoint(cancelled)?;
    // PublicationBasis is a public value. Never label a different body's
    // results with an asserted head ID, including on an empty/stale fast path.
    if authority_head_identity(basis.body())
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))? != basis.id()
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    if let Some(cursor) = after {
        if cursor.repository_sequence == 0 {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        let latest = basis.body().latest_repository_sequence.map_or(0, |n| n.get());
        if cursor.repository_sequence > latest {
            return Err(unavailable(RefusalCode::EvidenceStale));
        }
    }
    let repository = basis.body().repository_id;
    let mut successor = basis.body().clone();
    let mut reverse = Vec::new();
    let mut batches = 0usize;
    let mut records = 0usize;
    let mut cursor_record_seen = false;
    while let Some(batch_id) = successor.decision_tail_id {
        checkpoint(cancelled)?;
        if batches >= limits.batches {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        batches += 1;
        let predecessor_id = successor.predecessor_head_id
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let predecessor = fgit_authority::read_authority_head_body_async(
            store, cx, predecessor_id,
        ).await?;
        checkpoint(cancelled)?;
        let batch = fgit_authority::read_decision_batch_body_async(store, cx, batch_id).await?;
        checkpoint(cancelled)?;
        verify_pair(
            &CryptoBodyIdentity,
            &PublicationBasis::new(predecessor_id, predecessor.clone()),
            &batch,
            &successor,
        ).map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        // Charge all examined records, even those before the cursor in its
        // own microbatch. Filtering is not permission to evade work bounds.
        records = records.checked_add(batch.committed_rcrs.len())
            .filter(|count| *count <= limits.records)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        reverse.try_reserve(batch.committed_rcrs.len())
            .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for record in batch.committed_rcrs.iter().rev() {
            checkpoint(cancelled)?;
            if record.repository_id != repository {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            let sequence = record.repository_sequence.get();
            if after.is_some_and(|cursor| sequence < cursor.repository_sequence) {
                continue;
            }
            reverse.push(Record {
                sequence,
                tx_id: record.tx_id,
                policy_epoch: record.policy_epoch,
                event_root: record.forge_event_batch_root,
            });
            cursor_record_seen |= after.is_some_and(|cursor| sequence == cursor.repository_sequence);
        }
        successor = predecessor;
        if cursor_record_seen {
            // This predecessor was read and commitment-checked, and the entire
            // boundary batch was verified. No trust is placed in a bare number.
            break;
        }
    }
    if !cursor_record_seen {
        verify_genesis(&successor, repository)?;
        if after.is_some() {
            return Err(unavailable(RefusalCode::EvidenceStale));
        }
    }
    reverse.reverse();
    checkpoint(cancelled)?;
    Ok(reverse)
}

fn verify_genesis(
    head: &RepositoryAuthorityHeadBody,
    repository: RepositoryId,
) -> Result<(), AdmissionError> {
    if head.repository_id != repository
        || head.generation != HeadGeneration::FIRST
        || head.predecessor_head_id.is_some()
        || head.decision_tail_id.is_some()
        || head.latest_committed_rcr_id.is_some()
        || head.latest_decision_sequence.is_some()
        || head.latest_repository_sequence.is_some()
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(())
}
