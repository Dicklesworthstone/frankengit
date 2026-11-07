//! Complete bounded selection from one authenticated canonical history.
//! Notification activity ordinals need the exact RCR/event order. Repeated
//! paged reads would reverify the same suffix and could become quadratic;
//! this internal reader verifies the chain once and reads each RCR once.

use super::{ForgeEventCursor, checkpoint, history, storage, unavailable};
use crate::AdmissionError;
use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_codec::encode_body;
use fgit_forge::ForgeEvent;
use fgit_types::{Digest, PrincipalSnapshotId, RefusalCode};

#[derive(Clone, Copy, Debug)]
pub(in crate::merge::native) struct SelectedHistoryLimits {
    pub events: usize,
    pub scan_bytes: usize,
    pub retained_bytes: usize,
}
impl SelectedHistoryLimits {
    pub const DEFAULT: Self = Self {
        events: 65_536,
        scan_bytes: 128 * 1024 * 1024,
        retained_bytes: 32 * 1024 * 1024,
    };

    fn validate(self) -> Result<(), AdmissionError> {
        if self.events == 0
            || self.events > Self::DEFAULT.events
            || self.scan_bytes == 0
            || self.scan_bytes > Self::DEFAULT.scan_bytes
            || self.retained_bytes == 0
            || self.retained_bytes > Self::DEFAULT.retained_bytes
        {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        Ok(())
    }
}

pub(in crate::merge::native) struct SelectedForgeEvent {
    pub cursor: ForgeEventCursor,
    pub event_root: Digest,
    pub principal_snapshot_id: PrincipalSnapshotId,
    pub event: ForgeEvent,
}

pub(in crate::merge::native) struct SelectedHistory {
    pub events: Vec<SelectedForgeEvent>,
    pub scanned_bytes: usize,
}

pub(in crate::merge::native) async fn read_selected_at<S, C, F>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    limits: SelectedHistoryLimits,
    selected: &F,
    cancelled: &C,
) -> Result<SelectedHistory, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
    F: Fn(&ForgeEvent) -> bool + Sync,
{
    limits.validate()?;
    let records =
        history::read_records(store, cx, basis, None, history::Limits::DEFAULT, cancelled).await?;
    let mut events = Vec::new();
    let mut scanned_events = 0usize;
    let mut scanned_bytes = 0usize;
    let mut retained_bytes = 0usize;
    for record in records {
        checkpoint(cancelled)?;
        let (batch, bytes) = storage::read_events_with_size(
            store,
            cx,
            basis.body().repository_id,
            record.event_root,
        )
        .await?;
        checkpoint(cancelled)?;
        scanned_events = charge(scanned_events, batch.events.len(), limits.events)?;
        scanned_bytes = charge(scanned_bytes, bytes, limits.scan_bytes)?;
        for (index, event) in batch.events.into_iter().enumerate() {
            checkpoint(cancelled)?;
            if !selected(&event) {
                continue;
            }
            let bytes = encode_body(&event)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
                .len();
            retained_bytes = charge(retained_bytes, bytes, limits.retained_bytes)?;
            events
                .try_reserve(1)
                .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            events.push(SelectedForgeEvent {
                cursor: ForgeEventCursor {
                    repository_sequence: record.sequence,
                    event_index: u32::try_from(index)
                        .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))?,
                },
                event_root: record.event_root,
                principal_snapshot_id: record.principal_snapshot_id,
                event,
            });
        }
    }
    checkpoint(cancelled)?;
    Ok(SelectedHistory {
        events,
        scanned_bytes,
    })
}

fn charge(total: usize, amount: usize, maximum: usize) -> Result<usize, AdmissionError> {
    total
        .checked_add(amount)
        .filter(|value| *value <= maximum)
        .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))
}
