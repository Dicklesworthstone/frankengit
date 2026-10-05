//! Canonical, resumable forge-event feed over authenticated repository history.
//! No mutable event table participates: cursors name committed RCR sequence and
//! event position, and every page is reconstructed from verified authority history.
use super::{storage, unavailable};
use crate::AdmissionError;
use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_codec::encode_body;
use fgit_forge::ForgeEvent;
use fgit_types::{Digest, PolicyEpoch, RefusalCode, RepositoryAuthorityHeadId, TxId};

mod history;

const MAX_PAGE: u16 = 100;
const MAX_PAGE_EVENT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ForgeEventCursor {
    pub repository_sequence: u64,
    pub event_index: u32,
}
impl ForgeEventCursor {
    pub const fn new(repository_sequence: u64, event_index: u32) -> Result<Self, RefusalCode> {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
const fn charge_page_bytes(total: &mut usize, next: usize) -> Result<bool, AdmissionError> {
    if next > MAX_PAGE_EVENT_BYTES {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    let Some(updated) = total.checked_add(next) else {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    };
    if updated > MAX_PAGE_EVENT_BYTES {
        return Ok(false);
    }
    *total = updated;
    Ok(true)
}

/// Read forge events in canonical repository order. `after` is an append-stable
/// cursor: it may be resumed at a later descendant head because repository
/// sequence never rewinds. Callers that need one frozen page set separately pin
/// `source_head` at the node boundary. A cursor must name an event that exists in
/// the selected history; arbitrary sequence numbers are never treated as offsets.
/// Cursor reads verify the linked suffix through the cursor's batch, not the
/// unrelated prefix before it. Initial reads still verify back to genesis.
/// This is not a repository integrity scan or an indexed random-access API.
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
    let records = history::read_records(
        store,
        cx,
        basis,
        after,
        history::Limits::DEFAULT,
        cancelled,
    )
    .await?;
    let mut cursor_seen = after.is_none();
    let mut output = Vec::with_capacity(limit);
    let mut page_bytes = 0usize;
    let mut has_more = false;
    'records: for record in records {
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
            let encoded_bytes = encode_body(&event)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
                .len();
            if !charge_page_bytes(&mut page_bytes, encoded_bytes)? {
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

        let mut bytes = 0;
        assert!(charge_page_bytes(&mut bytes, MAX_PAGE_EVENT_BYTES).unwrap());
        assert_eq!(bytes, MAX_PAGE_EVENT_BYTES);
        assert!(!charge_page_bytes(&mut bytes, 1).unwrap());
        assert!(charge_page_bytes(&mut 0, MAX_PAGE_EVENT_BYTES + 1).is_err());
    }
}

#[cfg(test)]
mod history_tests;
