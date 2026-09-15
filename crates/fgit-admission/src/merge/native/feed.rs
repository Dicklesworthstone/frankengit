//! Canonical, resumable forge-event feed over authenticated repository history.
//! No mutable event table participates: cursors name committed RCR sequence and
//! event position, and every page is reconstructed from verified authority history.
use super::{storage, unavailable};
use crate::AdmissionError;
use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::CryptoBodyIdentity;
use fgit_forge::ForgeEvent;
use fgit_types::{Digest, PolicyEpoch, RefusalCode, RepositoryAuthorityHeadId, TxId};

const MAX_HISTORY_BATCHES: usize = 4096;
const MAX_HISTORY_RECORDS: usize = 65_536;
const MAX_PAGE: u16 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ForgeEventCursor {
    pub repository_sequence: u64,
    pub event_index: u32,
}
impl ForgeEventCursor {
    pub fn new(repository_sequence: u64, event_index: u32) -> Result<Self, RefusalCode> {
        if repository_sequence == 0 {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(Self {
            repository_sequence,
            event_index,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeEventEnvelope {
    pub cursor: ForgeEventCursor,
    pub tx_id: TxId,
    pub policy_epoch: PolicyEpoch,
    pub event: ForgeEvent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForgeEventPage {
    pub source_head: RepositoryAuthorityHeadId,
    pub events: Vec<ForgeEventEnvelope>,
    pub next_after: Option<ForgeEventCursor>,
}

#[derive(Clone, Copy)]
struct Record {
    sequence: u64,
    tx_id: TxId,
    policy_epoch: PolicyEpoch,
    event_root: Digest,
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), AdmissionError> {
    if cancelled() {
        Err(unavailable(RefusalCode::CancellationInProgress))
    } else {
        Ok(())
    }
}
fn page_limit(limit: u16) -> Result<usize, AdmissionError> {
    if limit == 0 || limit > MAX_PAGE {
        Err(unavailable(RefusalCode::ResourceBudgetExceeded))
    } else {
        Ok(usize::from(limit))
    }
}

/// Read forge events in canonical repository order. `after` is an append-stable
/// cursor: it may be resumed at a later descendant head because repository
/// sequence never rewinds. Callers that need one frozen page set separately pin
/// `source_head` at the node boundary. A cursor must name an event that exists in
/// the selected history; arbitrary sequence numbers are never treated as offsets.
pub async fn read_page_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    after: Option<ForgeEventCursor>,
    limit: u16,
    cancelled: &C,
) -> Result<ForgeEventPage, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let limit = page_limit(limit)?;
    checkpoint(cancelled)?;
    if after.is_some_and(|cursor| cursor.repository_sequence == 0) {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let repository = basis.body().repository_id;
    let mut successor = basis.body().clone();
    let mut reverse = Vec::<Record>::new();
    let mut batches = 0usize;
    let mut records = 0usize;
    while let Some(batch_id) = successor.decision_tail_id {
        checkpoint(cancelled)?;
        if batches >= MAX_HISTORY_BATCHES {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        batches += 1;
        let predecessor_id = successor
            .predecessor_head_id
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let predecessor =
            fgit_authority::read_authority_head_body_async(store, cx, predecessor_id).await?;
        checkpoint(cancelled)?;
        let batch = fgit_authority::read_decision_batch_body_async(store, cx, batch_id).await?;
        checkpoint(cancelled)?;
        verify_pair(
            &CryptoBodyIdentity,
            &PublicationBasis::new(predecessor_id, predecessor.clone()),
            &batch,
            &successor,
        )
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        records = records
            .checked_add(batch.committed_rcrs.len())
            .filter(|count| *count <= MAX_HISTORY_RECORDS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        reverse
            .try_reserve(batch.committed_rcrs.len())
            .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for record in batch.committed_rcrs.iter().rev() {
            if record.repository_id != repository {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            reverse.push(Record {
                sequence: record.repository_sequence.get(),
                tx_id: record.tx_id,
                policy_epoch: record.policy_epoch,
                event_root: record.forge_event_batch_root,
            });
        }
        successor = predecessor;
    }
    if successor.repository_id != repository
        || successor.generation != fgit_types::HeadGeneration::FIRST
        || successor.predecessor_head_id.is_some()
        || successor.latest_committed_rcr_id.is_some()
        || successor.latest_decision_sequence.is_some()
        || successor.latest_repository_sequence.is_some()
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    reverse.reverse();
    let mut cursor_seen = after.is_none();
    let mut output = Vec::with_capacity(limit);
    let mut has_more = false;
    'records: for record in reverse {
        checkpoint(cancelled)?;
        if after.is_some_and(|cursor| record.sequence < cursor.repository_sequence) {
            continue;
        }
        let batch = storage::read_events(store, cx, repository, record.event_root).await?;
        checkpoint(cancelled)?;
        let start = match after {
            Some(cursor) if record.sequence == cursor.repository_sequence => {
                let index = usize::try_from(cursor.event_index)
                    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
                if index >= batch.events.len() {
                    return Err(unavailable(RefusalCode::EvidenceStale));
                }
                cursor_seen = true;
                index + 1
            }
            Some(cursor) if record.sequence > cursor.repository_sequence => {
                if !cursor_seen {
                    return Err(unavailable(RefusalCode::EvidenceStale));
                }
                0
            }
            _ => 0,
        };
        for (index, event) in batch.events.into_iter().enumerate().skip(start) {
            checkpoint(cancelled)?;
            if output.len() == limit {
                has_more = true;
                break 'records;
            }
            let event_index = u32::try_from(index)
                .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            output.push(ForgeEventEnvelope {
                cursor: ForgeEventCursor {
                    repository_sequence: record.sequence,
                    event_index,
                },
                tx_id: record.tx_id,
                policy_epoch: record.policy_epoch,
                event,
            });
        }
    }
    if !cursor_seen {
        return Err(unavailable(RefusalCode::EvidenceStale));
    }
    let next_after = if has_more {
        output.last().map(|item| item.cursor)
    } else {
        None
    };
    checkpoint(cancelled)?;
    Ok(ForgeEventPage {
        source_head: basis.id(),
        events: output,
        next_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursors_refuse_zero_sequence_and_order_lexicographically() {
        assert_eq!(
            ForgeEventCursor::new(0, 0),
            Err(RefusalCode::EvidenceInvalid)
        );
        let a = ForgeEventCursor::new(1, 9).unwrap();
        let b = ForgeEventCursor::new(2, 0).unwrap();
        assert!(a < b);
        assert_eq!(
            ForgeEventCursor::new(7, 3).unwrap(),
            ForgeEventCursor {
                repository_sequence: 7,
                event_index: 3
            }
        );
    }
    #[test]
    fn feed_page_bounds_are_closed_and_zero_is_not_an_empty_success() {
        assert!(page_limit(0).is_err());
        assert_eq!(page_limit(1).unwrap(), 1);
        assert_eq!(page_limit(100).unwrap(), 100);
        assert!(page_limit(101).is_err());
    }
}
