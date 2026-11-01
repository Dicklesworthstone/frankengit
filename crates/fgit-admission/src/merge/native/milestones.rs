//! Repository milestones over the existing sealed metadata publication owner.
//! Counts are a bounded same-head fold of issue membership, never stored authority.
use super::super::NativeMergeBasis;
use super::{
    NativeMergeProjection, PreparationFailure, delivery, issues, metadata, storage, unavailable,
};
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, PermittedObjectClosure,
    ProjectionFailure, ValidatedClosure,
};
use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState};
use fgit_forge::event::milestone::{MilestoneCommand, MilestoneSnapshot, apply_event};
use fgit_forge::{
    AggregateId, AggregateVersion, ExpectedVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload,
    MilestoneNumber,
};
use fgit_types::{AsciiSlug, RefusalCode, RepositoryAuthorityHeadId, RepositoryId};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PAGE: u16 = 100;
const MAX_EVENTS: usize = 65_536;
const MAX_SCAN_EVENTS: usize = 65_536;
const MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;
const MAX_BYTES: usize = 32 * 1024 * 1024;

pub fn proposal(
    context: &AdmissionContext,
    command: &MilestoneCommand,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = command
        .proposed_event(context.principal_id)
        .map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format,
        true,
        Vec::new(),
        Vec::new(),
        vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static("milestone.event-batch-root.v1"),
            root.bytes().as_bytes(),
        )?],
    )?;
    Ok((
        event,
        SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(),
            request,
        },
    ))
}

/// The preparation boundary independently checks the full original request,
/// including actor, number, exact predecessor, action and every selected date.
pub(in crate::merge) fn verify_event_seal(
    context: &AdmissionContext,
    event: &ForgeEvent,
    attempt: &SealAttempt,
) -> Result<(), RefusalCode> {
    let (AggregateId::Milestone(number), ForgeEventPayload::MilestoneChangedNative(change)) =
        (event.aggregate, &event.payload)
    else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    let expected_version = if event.version == AggregateVersion::FIRST {
        ExpectedVersion::NewStream
    } else {
        ExpectedVersion::Exactly(
            AggregateVersion::try_new(event.version.get() - 1)
                .ok_or(RefusalCode::EvidenceInvalid)?,
        )
    };
    let command = MilestoneCommand {
        number,
        expected_version,
        action: change.action.clone(),
    };
    let (expected_event, expected_attempt) =
        proposal(context, &command).map_err(|_| RefusalCode::EvidenceInvalid)?;
    if expected_event != *event || expected_attempt != *attempt {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(())
}

pub async fn admit_milestone_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &MilestoneCommand,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    let (event, attempt) = proposal(context, command)?;
    metadata::admit_metadata_async(
        store,
        cx,
        context,
        event,
        attempt,
        limits,
        projection,
        &MilestoneValidation,
    )
    .await
}
struct MilestoneValidation;
impl<S, P> metadata::MetadataValidation<S, P> for MilestoneValidation
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    fn precheck(&self, _: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        Ok(())
    }
    async fn validate(
        &self,
        store: &S,
        cx: &S::Context,
        basis: &PublicationBasis,
        _: &AuthenticatedHead,
        _: &AdmissionSnapshot,
        resolved: &NativeMergeBasis,
        event: &ForgeEvent,
        projection: &P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        let AggregateId::Milestone(number) = event.aggregate else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        let previous = read_snapshot_from_roots(
            store,
            cx,
            basis.body().repository_id,
            &resolved.forge,
            &resolved.outbox,
            number,
            &|| projection.merge_checkpoint(cx).is_err(),
        )
        .await?;
        apply_event(previous.as_ref(), event).map_err(ProjectionFailure::Refuse)?;
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let closure = PermittedObjectClosure::default();
        Ok(ValidatedClosure {
            object_closure_root: crate::permitted_object_closure_root(&closure)
                .map_err(ProjectionFailure::Unavailable)?,
            objects: BTreeSet::new(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneSummary {
    pub milestone: MilestoneSnapshot,
    pub open_issues: u64,
    pub closed_issues: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestonePage {
    pub source_head: RepositoryAuthorityHeadId,
    pub milestones: Vec<MilestoneSummary>,
    pub next_after: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneHistoryPage {
    pub source_head: RepositoryAuthorityHeadId,
    pub milestone: Option<MilestoneSummary>,
    pub events: Vec<ForgeEvent>,
    pub next_after: Option<u64>,
}
struct Timeline {
    milestone: MilestoneSnapshot,
    events: Vec<ForgeEvent>,
    latest_event: ForgeEvent,
}
fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), AdmissionError> {
    if cancelled() {
        Err(unavailable(RefusalCode::CancellationInProgress))
    } else {
        Ok(())
    }
}
const fn limit(limit: u16) -> Result<(), AdmissionError> {
    if limit == 0 || limit > MAX_PAGE {
        Err(unavailable(RefusalCode::ResourceBudgetExceeded))
    } else {
        Ok(())
    }
}

/// Exact canonical metadata for admission, without progress scans. This reads
/// only the roots already authenticated by the caller's publication basis.
pub(super) async fn read_snapshot_from_roots<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    forge: &CanonicalForgePositionState,
    outbox: &CanonicalOutboxState,
    number: MilestoneNumber,
    cancelled: &C,
) -> Result<Option<MilestoneSnapshot>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    Ok(replay_selected(
        store,
        cx,
        repository,
        forge,
        outbox,
        &BTreeSet::from([number]),
        None,
        cancelled,
    )
    .await?
    .remove(&number)
    .map(|timeline| timeline.milestone))
}

pub async fn read_page_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    after: u64,
    page_limit: u16,
    cancelled: &C,
) -> Result<MilestonePage, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    limit(page_limit)?;
    let state = delivery::read_roots_in(store, cx, basis, cancelled).await?;
    let (wanted, more) = page_numbers(&state.forge, after, page_limit, cancelled)?;
    let timelines = replay_selected(
        store,
        cx,
        basis.body().repository_id,
        &state.forge,
        &state.outbox,
        &wanted,
        None,
        cancelled,
    )
    .await?;
    let counts = issues::milestone_counts_at_roots(
        store,
        cx,
        basis.body().repository_id,
        &state.forge,
        &state.outbox,
        &wanted,
        cancelled,
    )
    .await?;
    let milestones: Vec<_> = timelines
        .into_iter()
        .map(|(number, timeline)| {
            let (open_issues, closed_issues) = counts.get(&number).copied().unwrap_or_default();
            MilestoneSummary {
                milestone: timeline.milestone,
                open_issues,
                closed_issues,
            }
        })
        .collect();
    let next_after = if more {
        milestones.last().map(|row| row.milestone.number.get())
    } else {
        None
    };
    checkpoint(cancelled)?;
    Ok(MilestonePage {
        source_head: basis.id(),
        milestones,
        next_after,
    })
}

pub async fn read_history_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    number: MilestoneNumber,
    after: u64,
    page_limit: u16,
    cancelled: &C,
) -> Result<MilestoneHistoryPage, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    limit(page_limit)?;
    let state = delivery::read_roots_in(store, cx, basis, cancelled).await?;
    let wanted = BTreeSet::from([number]);
    let mut timelines = replay_selected(
        store,
        cx,
        basis.body().repository_id,
        &state.forge,
        &state.outbox,
        &wanted,
        Some((after, page_limit)),
        cancelled,
    )
    .await?;
    let Some(timeline) = timelines.remove(&number) else {
        checkpoint(cancelled)?;
        return Ok(MilestoneHistoryPage {
            source_head: basis.id(),
            milestone: None,
            events: Vec::new(),
            next_after: None,
        });
    };
    let counts = issues::milestone_counts_at_roots(
        store,
        cx,
        basis.body().repository_id,
        &state.forge,
        &state.outbox,
        &wanted,
        cancelled,
    )
    .await?;
    let (open_issues, closed_issues) = counts.get(&number).copied().unwrap_or_default();
    let mut events = timeline.events;
    let more = events.len() > usize::from(page_limit);
    events.truncate(usize::from(page_limit));
    let next_after = if more {
        events.last().map(|event| event.version.get())
    } else {
        None
    };
    checkpoint(cancelled)?;
    Ok(MilestoneHistoryPage {
        source_head: basis.id(),
        milestone: Some(MilestoneSummary {
            milestone: timeline.milestone,
            open_issues,
            closed_issues,
        }),
        events,
        next_after,
    })
}

async fn replay_selected<S, C>(
    store: &S,
    cx: &S::Context,
    repository: RepositoryId,
    forge: &CanonicalForgePositionState,
    outbox: &CanonicalOutboxState,
    wanted: &BTreeSet<MilestoneNumber>,
    history_window: Option<(u64, u16)>,
    cancelled: &C,
) -> Result<BTreeMap<MilestoneNumber, Timeline>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    if forge.repository_id() != repository || outbox.repository_id() != repository {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let frontiers = milestone_frontiers(forge, cancelled)?;
    if wanted.iter().all(|number| !frontiers.contains_key(number)) {
        // Callers already authenticated the delivery state. A new or missing
        // aggregate has no prior timeline to replay; object presence alone is
        // never used to invent one.
        checkpoint(cancelled)?;
        return Ok(BTreeMap::new());
    }
    let mut events = BTreeMap::<(MilestoneNumber, AggregateVersion), ForgeEvent>::new();
    let mut batches = BTreeSet::new();
    let (mut count, mut scanned_bytes, mut retained_bytes) = (0usize, 0usize, 0usize);
    for entry in outbox.entries() {
        checkpoint(cancelled)?;
        if !batches.insert(entry.payload_root()) {
            continue;
        }
        let batch = storage::read_events(store, cx, repository, entry.payload_root()).await?;
        checkpoint(cancelled)?;
        delivery::validate_payload_positions(forge, &batch)?;
        count = count
            .checked_add(batch.events.len())
            .filter(|n| *n <= MAX_SCAN_EVENTS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for event in batch.events {
            checkpoint(cancelled)?;
            let size = fgit_codec::encode_body(&event)
                .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?
                .len();
            scanned_bytes = scanned_bytes
                .checked_add(size)
                .filter(|n| *n <= MAX_SCAN_BYTES)
                .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            let AggregateId::Milestone(number) = event.aggregate else {
                continue;
            };
            let frontier = frontiers
                .get(&number)
                .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            if event.version.get() > frontier.successor_position() {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            if !wanted.contains(&number) {
                continue;
            }
            let key = (number, event.version);
            if let Some(previous) = events.get(&key) {
                if *previous != event {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
            } else {
                // Duplicate references do not consume memory twice, but a
                // conflicting event at the same version still fails closed.
                if events.len() >= MAX_EVENTS {
                    return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
                }
                retained_bytes = retained_bytes
                    .checked_add(size)
                    .filter(|total| *total <= MAX_BYTES)
                    .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
                events.insert(key, event);
            }
        }
    }
    let mut timelines = BTreeMap::<MilestoneNumber, Timeline>::new();
    for ((number, _), event) in events {
        checkpoint(cancelled)?;
        let state = apply_event(
            timelines.get(&number).map(|timeline| &timeline.milestone),
            &event,
        )
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        let timeline = timelines.entry(number).or_insert_with(|| Timeline {
            milestone: state.clone(),
            events: Vec::new(),
            latest_event: event.clone(),
        });
        timeline.milestone = state;
        if history_window.is_some_and(|(after, limit)| {
            event.version.get() > after && timeline.events.len() <= usize::from(limit)
        }) {
            timeline.events.push(event.clone());
        }
        timeline.latest_event = event;
    }
    for (number, frontier) in frontiers {
        checkpoint(cancelled)?;
        if !wanted.contains(&number) {
            continue;
        }
        let timeline = timelines
            .get(&number)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
        if timeline.milestone.version.get() != frontier.successor_position() {
            return Err(unavailable(RefusalCode::EvidenceMissing));
        }
        let batch =
            storage::read_events(store, cx, repository, frontier.event_batch_root()).await?;
        delivery::validate_position_batch(&frontier, &batch)?;
        let selected = batch
            .events
            .iter()
            .rev()
            .find(|event| event.aggregate == AggregateId::Milestone(number));
        if selected != Some(&timeline.latest_event) {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    checkpoint(cancelled)?;
    Ok(timelines)
}

/// Parse the canonical labels once, retaining numeric (not lexical) order.
fn milestone_frontiers<C: Fn() -> bool + Sync>(
    forge: &CanonicalForgePositionState,
    cancelled: &C,
) -> Result<BTreeMap<MilestoneNumber, fgit_codec::ForgePositionStateEntry>, AdmissionError> {
    let mut frontiers = BTreeMap::new();
    for entry in forge.entries() {
        checkpoint(cancelled)?;
        let label = entry.stream();
        let Some(text) = label.as_str().strip_prefix("milestone/") else {
            continue;
        };
        let number = text
            .parse::<u64>()
            .ok()
            .and_then(MilestoneNumber::try_new)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if storage::aggregate_label(AggregateId::Milestone(number))? != label {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        frontiers.insert(number, *entry);
    }
    Ok(frontiers)
}

fn page_numbers<C: Fn() -> bool + Sync>(
    forge: &CanonicalForgePositionState,
    after: u64,
    limit: u16,
    cancelled: &C,
) -> Result<(BTreeSet<MilestoneNumber>, bool), AdmissionError> {
    let mut numbers = BTreeSet::new();
    let mut more = false;
    for number in milestone_frontiers(forge, cancelled)?.into_keys() {
        checkpoint(cancelled)?;
        if number.get() <= after {
            continue;
        }
        if numbers.len() == usize::from(limit) {
            more = true;
            break;
        }
        numbers.insert(number);
    }
    Ok((numbers, more))
}

#[cfg(test)]
mod replay_tests;
#[cfg(test)]
mod seal_tests;
