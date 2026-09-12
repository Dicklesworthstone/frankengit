//! Repository issues selected by the existing canonical forge/outbox roots.
//! Reads rebuild from immutable accepted events; no issue table or cursor cache
//! is authoritative. A missing history or exceeded replay budget is a refusal.
use std::collections::{BTreeMap, BTreeSet};
use fgit_authority::{AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome};
use fgit_chronicle::PublicationBasis;
use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, IssueNumber};
use fgit_forge::event::issue::{IssueCommand, IssueSnapshot, apply_event};
use fgit_types::{AsciiSlug, RefusalCode, RepositoryAuthorityHeadId, RepositoryId};
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, PermittedObjectClosure, ProjectionFailure, ValidatedClosure};
use super::{NativeMergeProjection, PreparationFailure, delivery, metadata, storage, unavailable};
use super::super::NativeMergeBasis;

const MAX_PAGE: u16 = 100;
const MAX_EVENTS: usize = 4096;
const MAX_BYTES: usize = 32 * 1024 * 1024;

/// The seal contains only the submitted versioned command and authenticated
/// actor. Closing/commenting does not copy mutable title/body into its identity.
pub fn proposal(context: &AdmissionContext, command: &IssueCommand) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = command.proposed_event(context.principal_id).map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format, true, Vec::new(), Vec::new(), vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"), AsciiSlug::from_static("issue.event-batch-root"), root.bytes().as_bytes(),
        )?])?;
    Ok((event, SealAttempt { tenant_id: context.tenant_id, repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id, idempotency_key: context.idempotency_key.clone(), request }))
}

pub async fn admit_issue_async<S, P>(store: &S, cx: &S::Context, context: &AdmissionContext,
    command: &IssueCommand, limits: AdmissionLimits, projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: NativeMergeProjection<S> + ?Sized,
{
    let (event, attempt) = proposal(context, command)?;
    metadata::admit_metadata_async(store, cx, context, event, attempt, limits, projection, &IssueValidation).await
}
struct IssueValidation;
impl<S, P> metadata::MetadataValidation<S, P> for IssueValidation
where S: AsyncAuthorityStore + ?Sized, P: NativeMergeProjection<S> + ?Sized,
{
    fn precheck(&self, _: &AdmissionSnapshot) -> Result<(), ProjectionFailure> { Ok(()) }
    async fn validate(&self, store: &S, cx: &S::Context, basis: &PublicationBasis,
        _: &AuthenticatedHead, _: &AdmissionSnapshot, resolved: &NativeMergeBasis,
        event: &ForgeEvent, projection: &P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        let AggregateId::Issue(number) = event.aggregate else { return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into()); };
        let timelines = replay_selected(store, cx, basis.body().repository_id,
            &resolved.forge, &resolved.outbox, Some(number), &|| projection.merge_checkpoint(cx).is_err()).await?;
        let previous = timelines.get(&number).map(|timeline| &timeline.issue);
        apply_event(previous, event).map_err(ProjectionFailure::Refuse)?;
        projection.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
        // Issues introduce no native objects. Empty per-record closure cannot
        // erase the repository's independently verified cumulative retention.
        let closure = PermittedObjectClosure::default();
        Ok(ValidatedClosure { object_closure_root: crate::permitted_object_closure_root(&closure)
            .map_err(ProjectionFailure::Unavailable)?, objects: BTreeSet::new() })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuePage {
    pub source_head: RepositoryAuthorityHeadId,
    pub issues: Vec<IssueSnapshot>,
    pub next_after: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueHistoryPage {
    pub source_head: RepositoryAuthorityHeadId,
    pub issue: Option<IssueSnapshot>,
    pub events: Vec<ForgeEvent>,
    pub next_after: Option<u64>,
}
struct Timeline { issue: IssueSnapshot, events: Vec<ForgeEvent> }
fn checkpoint(cancelled: &impl Fn() -> bool) -> Result<(), AdmissionError> {
    if cancelled() { Err(unavailable(RefusalCode::CancellationInProgress)) } else { Ok(()) }
}
fn limit(limit: u16) -> Result<(), AdmissionError> {
    if limit == 0 || limit > MAX_PAGE { Err(unavailable(RefusalCode::ResourceBudgetExceeded)) } else { Ok(()) }
}

/// Current issue rows in numeric order, pinned to one authenticated head.
pub async fn read_page_at<S, C>(store: &S, cx: &S::Context, basis: &PublicationBasis,
    after: u64, page_limit: u16, cancelled: &C,
) -> Result<IssuePage, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync,
{
    limit(page_limit)?;
    let state = delivery::read_in(store, cx, basis, cancelled).await?;
    let all = replay_selected(store, cx, basis.body().repository_id, &state.forge, &state.outbox, None, cancelled).await?;
    let mut issues = Vec::new(); let mut more = false;
    for (number, timeline) in all {
        checkpoint(cancelled)?;
        if number.get() <= after { continue; }
        if issues.len() == usize::from(page_limit) { more = true; break; }
        issues.push(timeline.issue);
    }
    let next_after = if more { issues.last().map(|issue| issue.number.get()) } else { None };
    checkpoint(cancelled)?;
    Ok(IssuePage { source_head: basis.id(), issues, next_after })
}

/// Complete versioned action/comment history, paged by event version. The
/// accompanying issue state is the current state at this same exact snapshot.
pub async fn read_history_at<S, C>(store: &S, cx: &S::Context, basis: &PublicationBasis,
    number: IssueNumber, after: u64, page_limit: u16, cancelled: &C,
) -> Result<IssueHistoryPage, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync,
{
    limit(page_limit)?;
    let state = delivery::read_in(store, cx, basis, cancelled).await?;
    let mut timelines = replay_selected(store, cx, basis.body().repository_id, &state.forge, &state.outbox, Some(number), cancelled).await?;
    let Some(timeline) = timelines.remove(&number) else {
        return Ok(IssueHistoryPage { source_head: basis.id(), issue: None, events: Vec::new(), next_after: None });
    };
    let mut events = Vec::new(); let mut more = false;
    for event in timeline.events {
        checkpoint(cancelled)?;
        if event.version.get() <= after { continue; }
        if events.len() == usize::from(page_limit) { more = true; break; }
        events.push(event);
    }
    let next_after = if more { events.last().map(|event| event.version.get()) } else { None };
    checkpoint(cancelled)?;
    Ok(IssueHistoryPage { source_head: basis.id(), issue: Some(timeline.issue), events, next_after })
}

async fn replay_selected<S, C>(store: &S, cx: &S::Context, repository: RepositoryId,
    forge: &CanonicalForgePositionState, outbox: &CanonicalOutboxState,
    only: Option<IssueNumber>, cancelled: &C,
) -> Result<BTreeMap<IssueNumber, Timeline>, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    if forge.repository_id() != repository || outbox.repository_id() != repository {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    if forge.entries().len() > MAX_EVENTS || outbox.entries().len() > MAX_EVENTS {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    let mut frontiers = BTreeMap::new();
    for entry in forge.entries() {
        checkpoint(cancelled)?;
        let label = entry.stream();
        let Some(text) = label.as_str().strip_prefix("issue/") else { continue; };
        let number = text.parse::<u64>().ok().and_then(IssueNumber::try_new)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if storage::aggregate_label(AggregateId::Issue(number))? != entry.stream() {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        frontiers.insert(number, entry);
    }
    let mut events = BTreeMap::<(IssueNumber, AggregateVersion), ForgeEvent>::new();
    let mut batches = BTreeSet::new();
    let (mut count, mut bytes) = (0usize, 0usize);
    for entry in outbox.entries() {
        checkpoint(cancelled)?;
        if !batches.insert(entry.payload_root()) { continue; }
        let batch = storage::read_events(store, cx, repository, entry.payload_root()).await?;
        checkpoint(cancelled)?;
        count = count.checked_add(batch.events.len()).filter(|n| *n <= MAX_EVENTS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for event in batch.events {
            checkpoint(cancelled)?;
            let size = fgit_codec::encode_body(&event).map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?.len();
            bytes = bytes.checked_add(size).filter(|n| *n <= MAX_BYTES)
                .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            let AggregateId::Issue(number) = event.aggregate else { continue; };
            let frontier = frontiers.get(&number).ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
            if event.version.get() > frontier.successor_position() { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
            if only.is_some_and(|wanted| wanted != number) { continue; }
            let key = (number, event.version);
            if let Some(previous) = events.get(&key) {
                if *previous != event { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
            } else { events.insert(key, event); }
        }
    }
    let mut timelines = BTreeMap::<IssueNumber, Timeline>::new();
    for ((number, _), event) in events {
        checkpoint(cancelled)?;
        let state = apply_event(timelines.get(&number).map(|timeline| &timeline.issue), &event)
            .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        let timeline = timelines.entry(number).or_insert_with(|| Timeline { issue: state.clone(), events: Vec::new() });
        timeline.issue = state; timeline.events.push(event);
    }
    for (number, frontier) in frontiers {
        checkpoint(cancelled)?;
        if only.is_some_and(|wanted| wanted != number) { continue; }
        let timeline = timelines.get(&number).ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
        if timeline.issue.version.get() != frontier.successor_position() { return Err(unavailable(RefusalCode::EvidenceMissing)); }
        let batch = storage::read_events(store, cx, repository, frontier.event_batch_root()).await?;
        let selected = batch.events.iter().rev().find(|event| event.aggregate == AggregateId::Issue(number));
        if selected != timeline.events.last() { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
    }
    checkpoint(cancelled)?;
    Ok(timelines)
}
