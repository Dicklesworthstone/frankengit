//! PR activity is the chronological union of independent canonical streams.
//! The ordinal is derived only: preferences acknowledge that exact prefix,
//! while lifecycle, conversation and reviewer aggregate versions stay intact.
use super::super::super::{feed, storage, unavailable};
use super::{
    MAX_EVENTS, MAX_SCAN_BYTES, MAX_THREADS, NotificationSubjectSnapshot, NotificationThread,
    PullRequestNotificationSnapshot, PullRequestNotificationState, checkpoint,
};
use crate::AdmissionError;
use crate::evidence::PrincipalSnapshotRecord;
use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_codec::{CanonicalForgePositionState, DecodeLimits, ForgePositionStateEntry};
use fgit_forge::event::notification::apply_event;
use fgit_forge::event::pull_request::{PullRequestAction, validate_transition};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEventPayload, PullRequestNumber};
use fgit_types::{Digest, PrincipalId, PrincipalSnapshotId, RefusalCode, RepositoryId};
use std::collections::{BTreeMap, BTreeSet};

const PRINCIPAL_NAMESPACE: &[u8] = b"frankengit/admission/principal-snapshot/v1/";
const MAX_PRINCIPAL_FRAME: usize = 64 * 1024;

#[derive(Clone, Copy)]
struct StreamTail {
    version: AggregateVersion,
    event_root: Digest,
    sequence: u64,
    predecessor_position: u64,
    event_count: u32,
}

fn relevant(aggregate: AggregateId, principal: PrincipalId) -> bool {
    match aggregate {
        AggregateId::PullRequest(_)
        | AggregateId::PullRequestConversation(_)
        | AggregateId::PullRequestReview { .. } => true,
        AggregateId::PullRequestNotificationPreference {
            principal: owner, ..
        } => owner == principal,
        _ => false,
    }
}

fn number(raw: &str) -> Result<PullRequestNumber, AdmissionError> {
    raw.parse::<u64>()
        .ok()
        .and_then(PullRequestNumber::try_new)
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))
}

fn frontiers(
    forge: &CanonicalForgePositionState,
    principal: PrincipalId,
    cancelled: &impl Fn() -> bool,
) -> Result<BTreeMap<AggregateId, ForgePositionStateEntry>, AdmissionError> {
    let mut selected = BTreeMap::new();
    let mut subjects = 0usize;
    for entry in forge.entries() {
        checkpoint(cancelled)?;
        let label = entry.stream();
        let aggregate = if let Some(raw) = label.as_str().strip_prefix("pull-request/") {
            subjects += 1;
            AggregateId::PullRequest(number(raw)?)
        } else if let Some(raw) = label.as_str().strip_prefix("conversation/") {
            AggregateId::PullRequestConversation(number(raw)?)
        } else if let Some(raw) = label.as_str().strip_prefix("review/") {
            let (raw_number, raw_principal) = raw
                .split_once('/')
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            AggregateId::PullRequestReview {
                pull_request: number(raw_number)?,
                reviewer: PrincipalId::from_hex(raw_principal)
                    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?,
            }
        } else if let Some(raw) = label.as_str().strip_prefix("pnotify/") {
            let (raw_principal, raw_number) = raw
                .split_once('/')
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            let owner = PrincipalId::from_hex(raw_principal)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
            let aggregate = AggregateId::PullRequestNotificationPreference {
                principal: owner,
                pull_request: number(raw_number)?,
            };
            if storage::aggregate_label(aggregate)? != label {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            if owner != principal {
                continue;
            }
            aggregate
        } else {
            continue;
        };
        if subjects > MAX_THREADS || selected.len() >= MAX_EVENTS {
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

pub(super) async fn read_threads<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    forge: &CanonicalForgePositionState,
    principal: PrincipalId,
    cancelled: &C,
) -> Result<Vec<NotificationThread>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    if forge.repository_id() != basis.body().repository_id {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let frontiers = frontiers(forge, principal, cancelled)?;
    let history = feed::read_selected_at(
        store,
        cx,
        basis,
        feed::SelectedHistoryLimits::DEFAULT,
        &|event| relevant(event.aggregate, principal),
        cancelled,
    )
    .await?;
    let mut scanned_bytes = history.scanned_bytes;
    let mut tails = BTreeMap::<AggregateId, StreamTail>::new();
    let mut threads = BTreeMap::<PullRequestNumber, NotificationThread>::new();
    // Legacy digest-only and standalone merge receipts have no native opener
    // or title. Keep them outside this explicit native notification profile.
    let mut legacy = BTreeSet::new();
    let mut last_cursor = None;
    for item in history.events {
        checkpoint(cancelled)?;
        if last_cursor.is_some_and(|previous| item.cursor <= previous) {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        last_cursor = Some(item.cursor);
        track_stream(&item, &frontiers, &mut tails)?;
        match (&item.event.aggregate, &item.event.payload) {
            (
                AggregateId::PullRequest(number),
                ForgeEventPayload::PullRequestChangedNative(change),
            ) => {
                if legacy.contains(number) {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                let previous = threads.get(number);
                let prior = previous.map(pull).transpose()?;
                if prior
                    .is_some_and(|subject| subject.state == PullRequestNotificationState::Merged)
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                let previous_event = prior.map(PullRequestNotificationSnapshot::lifecycle_event);
                validate_transition(previous_event.as_ref(), &item.event)
                    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
                let version = next_activity(prior)?;
                let subject = PullRequestNotificationSnapshot {
                    number: *number,
                    activity_version: version,
                    lifecycle_version: item.event.version,
                    data: change.data.clone(),
                    opened_by: prior.map_or(change.actor, |subject| subject.opened_by),
                    state: if change.action == PullRequestAction::Close {
                        PullRequestNotificationState::Closed
                    } else {
                        PullRequestNotificationState::Open
                    },
                    last_action: change.action,
                    last_metadata_actor: change.actor,
                };
                let preference = previous.and_then(|thread| thread.preference.clone());
                let participated = previous.is_some_and(|thread| thread.participated)
                    || (change.action == PullRequestAction::Open && change.actor == principal);
                let latest_other_version = if change.actor != principal {
                    Some(version)
                } else {
                    previous.and_then(|thread| thread.latest_other_version)
                };
                if previous.is_none() && threads.len() >= MAX_THREADS {
                    return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
                }
                threads.insert(
                    *number,
                    NotificationThread {
                        subject: NotificationSubjectSnapshot::PullRequest(subject),
                        preference,
                        latest_other_version,
                        participated,
                    },
                );
            }
            (AggregateId::PullRequest(number), ForgeEventPayload::MergeCommittedNative(merge)) => {
                let Some(thread) = threads.get_mut(number) else {
                    if item.event.version != AggregateVersion::FIRST && !legacy.contains(number) {
                        return Err(unavailable(RefusalCode::EvidenceMissing));
                    }
                    legacy.insert(*number);
                    continue;
                };
                let subject = pull(thread)?;
                if subject.state != PullRequestNotificationState::Open
                    || !subject
                        .lifecycle_version
                        .is_immediate_predecessor_of(item.event.version)
                    || !subject.data.matches_merge(merge)
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                let actor = merge_actor(
                    store,
                    cx,
                    basis.body().repository_id,
                    item.principal_snapshot_id,
                    &mut scanned_bytes,
                    cancelled,
                )
                .await?;
                activity(thread, actor, principal, false)?;
                let subject = pull_mut(thread)?;
                subject.lifecycle_version = item.event.version;
                subject.state = PullRequestNotificationState::Merged;
            }
            (AggregateId::PullRequest(number), _) => {
                if threads.contains_key(number) {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                legacy.insert(*number);
            }
            (
                AggregateId::PullRequestConversation(number),
                ForgeEventPayload::PullRequestCommentedNative(comment),
            ) => {
                let Some(thread) = threads.get_mut(number) else {
                    if legacy.contains(number) {
                        continue;
                    }
                    return Err(unavailable(RefusalCode::EvidenceMissing));
                };
                if let Some(anchor) = &comment.anchor {
                    let subject = pull(thread)?;
                    // Retained anchors carry disclosure coordinates of their
                    // own. Native PR branch identities are immutable, so an
                    // anchor naming either different ref cannot join this inbox.
                    if anchor.source_ref != subject.data.source_ref
                        || anchor.target_ref != subject.data.target_ref
                    {
                        return Err(unavailable(RefusalCode::EvidenceInvalid));
                    }
                }
                activity(thread, comment.actor, principal, true)?;
            }
            (
                AggregateId::PullRequestReview {
                    pull_request: number,
                    ..
                },
                ForgeEventPayload::PullRequestReviewedNative(review),
            ) => {
                let Some(thread) = threads.get_mut(number) else {
                    if legacy.contains(number) {
                        continue;
                    }
                    return Err(unavailable(RefusalCode::EvidenceMissing));
                };
                let subject = pull(thread)?;
                if review.subject.source_ref != subject.data.source_ref
                    || review.subject.target_ref != subject.data.target_ref
                    || review.subject.pull_request_version > subject.lifecycle_version
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                activity(thread, review.reviewer, principal, true)?;
            }
            (
                AggregateId::PullRequestNotificationPreference {
                    pull_request: number,
                    ..
                },
                ForgeEventPayload::NotificationPreferenceChangedNative(_),
            ) => {
                let thread = threads
                    .get_mut(number)
                    .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
                let preference = apply_event(thread.preference.as_ref(), &item.event)
                    .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
                // Check at the event's original position, not just at the final
                // head: future activity must never retroactively validate an ack.
                if preference
                    .read_through
                    .is_some_and(|through| through > thread.subject.version())
                {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                thread.preference = Some(preference);
            }
            _ => return Err(unavailable(RefusalCode::EvidenceInvalid)),
        }
    }
    for (aggregate, frontier) in frontiers {
        checkpoint(cancelled)?;
        let tail = tails
            .get(&aggregate)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
        if tail.version.get() != frontier.successor_position()
            || tail.event_root != frontier.event_batch_root()
            || tail.predecessor_position != frontier.predecessor_position()
            || tail.event_count != frontier.event_count()
        {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    checkpoint(cancelled)?;
    Ok(threads.into_values().collect())
}

fn track_stream(
    item: &feed::SelectedForgeEvent,
    frontiers: &BTreeMap<AggregateId, ForgePositionStateEntry>,
    tails: &mut BTreeMap<AggregateId, StreamTail>,
) -> Result<(), AdmissionError> {
    let frontier = frontiers
        .get(&item.event.aggregate)
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    let previous = tails.get(&item.event.aggregate);
    let before = previous.map_or(0, |tail| tail.version.get());
    if before.checked_add(1) != Some(item.event.version.get())
        || item.event.version.get() > frontier.successor_position()
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let (predecessor_position, event_count) = match previous {
        Some(tail) if tail.sequence == item.cursor.repository_sequence => {
            if tail.event_root != item.event_root {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            (
                tail.predecessor_position,
                tail.event_count
                    .checked_add(1)
                    .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?,
            )
        }
        _ => (before, 1),
    };
    tails.insert(
        item.event.aggregate,
        StreamTail {
            version: item.event.version,
            event_root: item.event_root,
            sequence: item.cursor.repository_sequence,
            predecessor_position,
            event_count,
        },
    );
    Ok(())
}

fn pull(thread: &NotificationThread) -> Result<&PullRequestNotificationSnapshot, AdmissionError> {
    match &thread.subject {
        NotificationSubjectSnapshot::PullRequest(subject) => Ok(subject),
        _ => Err(unavailable(RefusalCode::EvidenceInvalid)),
    }
}
fn pull_mut(
    thread: &mut NotificationThread,
) -> Result<&mut PullRequestNotificationSnapshot, AdmissionError> {
    match &mut thread.subject {
        NotificationSubjectSnapshot::PullRequest(subject) => Ok(subject),
        _ => Err(unavailable(RefusalCode::EvidenceInvalid)),
    }
}
fn next_activity(
    previous: Option<&PullRequestNotificationSnapshot>,
) -> Result<AggregateVersion, AdmissionError> {
    previous.map_or(Ok(AggregateVersion::FIRST), |subject| {
        subject
            .activity_version
            .next()
            .map_err(|_| unavailable(RefusalCode::ResourceBudgetExceeded))
    })
}
fn activity(
    thread: &mut NotificationThread,
    actor: PrincipalId,
    principal: PrincipalId,
    participates: bool,
) -> Result<(), AdmissionError> {
    let subject = pull_mut(thread)?;
    subject.activity_version = next_activity(Some(subject))?;
    let version = subject.activity_version;
    thread.participated |= participates && actor == principal;
    if actor != principal {
        thread.latest_other_version = Some(version);
    }
    Ok(())
}

async fn merge_actor<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    expected: PrincipalSnapshotId,
    scanned_bytes: &mut usize,
    cancelled: &C,
) -> Result<PrincipalId, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    let id = expected.as_internal_object_id();
    let root = Digest::new(id.algorithm(), *id.digest());
    let frame = storage::read_frame(store, cx, repository, PRINCIPAL_NAMESPACE, root)
        .await?
        .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
    checkpoint(cancelled)?;
    if frame.len() > MAX_PRINCIPAL_FRAME {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    *scanned_bytes = scanned_bytes
        .checked_add(frame.len())
        .filter(|count| *count <= MAX_SCAN_BYTES)
        .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
    let snapshot = PrincipalSnapshotRecord::decode(&frame, DecodeLimits::DEFAULT)
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
    if snapshot.id().map_err(unavailable)? != expected || snapshot.repository_id() != repository {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    checkpoint(cancelled)?;
    Ok(snapshot.principal_id())
}

#[cfg(test)]
mod tests;
