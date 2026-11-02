//! Bounded canonical event reconstruction at one exact authority basis.
//! Only this principal's preferences are retained. The inbox remains a derived view.
use super::super::{delivery, storage, unavailable};
use crate::AdmissionError;
use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry};
use fgit_forge::event::issue::{IssueAction, IssueSnapshot};
use fgit_forge::event::notification::NotificationPreferenceSnapshot;
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload, IssueNumber};
use fgit_types::{Digest, PrincipalId, RefusalCode, RepositoryAuthorityHeadId, RepositoryId};
use std::collections::{BTreeMap, BTreeSet};

const MAX_THREADS: usize = 16_384;
const MAX_EVENTS: usize = 65_536;
const MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationThread {
    pub issue: IssueSnapshot,
    pub preference: Option<NotificationPreferenceSnapshot>,
    pub latest_other_version: Option<AggregateVersion>,
    pub participated: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationSourceSnapshot {
    pub source_head: RepositoryAuthorityHeadId,
    pub source_generation: u64,
    pub forge_root: Digest,
    pub outbox_root: Digest,
    pub principal: PrincipalId,
    pub threads: Vec<NotificationThread>,
}

fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), AdmissionError> {
    if cancelled() {
        Err(unavailable(RefusalCode::CancellationInProgress))
    } else {
        Ok(())
    }
}

pub async fn read_source_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    principal: PrincipalId,
    cancelled: &C,
) -> Result<NotificationSourceSnapshot, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    if fgit_authority::authority_head_identity(basis.body())
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
        != basis.id()
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let roots = delivery::read_roots_in(store, cx, basis, cancelled).await?;
    let threads = replay(
        store,
        cx,
        basis.body().repository_id,
        &roots.forge,
        &roots.outbox,
        principal,
        cancelled,
    )
    .await?;
    checkpoint(cancelled)?;
    Ok(NotificationSourceSnapshot {
        source_head: basis.id(),
        source_generation: basis.generation().get(),
        forge_root: basis.body().forge_position_root,
        outbox_root: basis.body().outbox_root,
        principal,
        threads,
    })
}

fn frontiers<C: Fn() -> bool + Sync>(
    forge: &CanonicalForgePositionState,
    principal: PrincipalId,
    cancelled: &C,
) -> Result<BTreeMap<AggregateId, ForgePositionStateEntry>, AdmissionError> {
    let mut selected = BTreeMap::new();
    let mut issue_count = 0usize;
    let mut preference_count = 0usize;
    for entry in forge.entries() {
        checkpoint(cancelled)?;
        let label = entry.stream();
        let aggregate = if let Some(number) = label.as_str().strip_prefix("issue/") {
            let number = number
                .parse::<u64>()
                .ok()
                .and_then(IssueNumber::try_new)
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            issue_count += 1;
            AggregateId::Issue(number)
        } else if let Some(preference) = label.as_str().strip_prefix("notify/") {
            let (owner, number) = preference
                .split_once('/')
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            let owner = PrincipalId::from_hex(owner)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
            let number = number
                .parse::<u64>()
                .ok()
                .and_then(IssueNumber::try_new)
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            let aggregate = AggregateId::NotificationPreference {
                principal: owner,
                issue: number,
            };
            if storage::aggregate_label(aggregate)? != label {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            if owner != principal {
                continue;
            }
            preference_count += 1;
            aggregate
        } else {
            continue;
        };
        if issue_count > MAX_THREADS || preference_count > MAX_THREADS {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        if storage::aggregate_label(aggregate)? != label
            || selected.insert(aggregate, *entry).is_some()
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    Ok(selected)
}

async fn replay<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    forge: &CanonicalForgePositionState,
    outbox: &CanonicalOutboxState,
    principal: PrincipalId,
    cancelled: &C,
) -> Result<Vec<NotificationThread>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    if forge.repository_id() != repository || outbox.repository_id() != repository {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let frontiers = frontiers(forge, principal, cancelled)?;
    let mut selected_batches =
        BTreeMap::<Digest, Vec<(AggregateId, ForgePositionStateEntry)>>::new();
    for (aggregate, entry) in &frontiers {
        selected_batches
            .entry(entry.event_batch_root())
            .or_default()
            .push((*aggregate, *entry));
    }
    let mut selected_latest = BTreeMap::new();
    let mut batches = BTreeSet::new();
    let mut events = BTreeMap::<(AggregateId, AggregateVersion), ForgeEvent>::new();
    let (mut scanned, mut scanned_bytes, mut retained_bytes) = (0usize, 0usize, 0usize);
    for entry in outbox.entries() {
        checkpoint(cancelled)?;
        if !batches.insert(entry.payload_root()) {
            continue;
        }
        let (batch, frame_bytes) =
            storage::read_events_with_size(store, cx, repository, entry.payload_root()).await?;
        checkpoint(cancelled)?;
        scanned = scanned
            .checked_add(batch.events.len())
            .filter(|n| *n <= MAX_EVENTS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        scanned_bytes = scanned_bytes
            .checked_add(frame_bytes)
            .filter(|n| *n <= MAX_SCAN_BYTES)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        delivery::validate_payload_positions(forge, &batch)?;
        if let Some(positions) = selected_batches.remove(&entry.payload_root()) {
            let mut ranges = positions
                .iter()
                .map(|(_, position)| (position.stream(), (position, 0u32)))
                .collect();
            if !delivery::validate_position_ranges(&mut ranges, &batch, cancelled)?.is_empty() {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            let selected: BTreeSet<_> = positions
                .into_iter()
                .map(|(aggregate, _)| aggregate)
                .collect();
            for event in &batch.events {
                checkpoint(cancelled)?;
                if selected.contains(&event.aggregate) {
                    selected_latest.insert(event.aggregate, event.clone());
                }
            }
        }
        for event in batch.events {
            checkpoint(cancelled)?;
            let relevant = matches!(event.aggregate, AggregateId::Issue(_))
                || matches!(event.aggregate, AggregateId::NotificationPreference { principal: owner, .. } if owner == principal);
            if !relevant {
                continue;
            }
            let frontier = frontiers
                .get(&event.aggregate)
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            if event.version.get() > frontier.successor_position() {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            let key = (event.aggregate, event.version);
            if let Some(previous) = events.get(&key) {
                if *previous != event {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
            } else {
                let size = fgit_codec::encode_body(&event)
                    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
                    .len();
                retained_bytes = retained_bytes
                    .checked_add(size)
                    .filter(|n| *n <= MAX_RETAINED_BYTES)
                    .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
                events.insert(key, event);
            }
        }
    }
    if !selected_batches.is_empty() {
        return Err(unavailable(RefusalCode::EvidenceMissing));
    }
    let mut issues = BTreeMap::<IssueNumber, NotificationThread>::new();
    let mut preferences = BTreeMap::<IssueNumber, NotificationPreferenceSnapshot>::new();
    let mut latest = BTreeMap::new();
    for ((aggregate, _), event) in events {
        checkpoint(cancelled)?;
        match (aggregate, &event.payload) {
            (AggregateId::Issue(number), ForgeEventPayload::IssueChangedNative(change)) => {
                let previous = issues.get(&number);
                let issue = fgit_forge::event::issue::apply_event(
                    previous.map(|thread| &thread.issue),
                    &event,
                )
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
                let participated = previous.is_some_and(|thread| thread.participated)
                    || (change.actor == principal
                        && matches!(
                            change.action,
                            IssueAction::Open { .. } | IssueAction::Comment { .. }
                        ));
                let latest_other_version = if change.actor != principal {
                    Some(event.version)
                } else {
                    previous.and_then(|thread| thread.latest_other_version)
                };
                issues.insert(
                    number,
                    NotificationThread {
                        issue,
                        preference: None,
                        latest_other_version,
                        participated,
                    },
                );
            }
            (
                AggregateId::NotificationPreference {
                    principal: owner,
                    issue,
                },
                ForgeEventPayload::NotificationPreferenceChangedNative(_),
            ) if owner == principal => {
                let next =
                    fgit_forge::event::notification::apply_event(preferences.get(&issue), &event)
                        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
                preferences.insert(issue, next);
            }
            _ => return Err(unavailable(RefusalCode::EvidenceInvalid)),
        }
        latest.insert(aggregate, event);
    }
    for (aggregate, frontier) in frontiers {
        checkpoint(cancelled)?;
        let event = latest
            .get(&aggregate)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
        if event.version.get() != frontier.successor_position() {
            return Err(unavailable(RefusalCode::EvidenceMissing));
        }
        if selected_latest.get(&aggregate) != Some(event) {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    for (number, thread) in &mut issues {
        checkpoint(cancelled)?;
        thread.preference = preferences.remove(number);
        if thread
            .preference
            .as_ref()
            .and_then(|preference| preference.read_through)
            .is_some_and(|through| through > thread.issue.version)
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    if !preferences.is_empty() {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    checkpoint(cancelled)?;
    Ok(issues.into_values().collect())
}

#[cfg(test)]
mod tests;
