//! Repository issues selected by the existing canonical forge/outbox roots.
//! Reads rebuild from immutable accepted events; no issue table or cursor cache
//! is authoritative. A missing history or exceeded replay budget is a refusal.
use super::super::NativeMergeBasis;
use super::{NativeMergeProjection, PreparationFailure, delivery, metadata, storage, unavailable};
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
use fgit_forge::event::issue::{IssueCommand, IssueSnapshot, apply_event};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, IssueNumber};
use fgit_types::{AsciiSlug, RefusalCode, RepositoryAuthorityHeadId, RepositoryId};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PAGE: u16 = 100;
// Scan work and retained query state are different budgets. Unrelated streams
// must not consume the selected issue/page's replay-memory allowance. These are
// finite read-profile limits, not changes to either canonical map schema.
const MAX_EVENTS: usize = 65_536;
const MAX_SCAN_EVENTS: usize = 65_536;
const MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;
const MAX_BYTES: usize = 32 * 1024 * 1024;

/// The seal contains only the submitted versioned command and authenticated
/// actor. Closing/commenting does not copy mutable title/body into its identity.
pub fn proposal(
    context: &AdmissionContext,
    command: &IssueCommand,
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
            AsciiSlug::from_static("issue.event-batch-root"),
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

pub async fn admit_issue_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &IssueCommand,
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
        &IssueValidation,
    )
    .await
}
struct IssueValidation;
impl<S, P> metadata::MetadataValidation<S, P> for IssueValidation
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
        let AggregateId::Issue(number) = event.aggregate else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        let timelines = replay_selected(
            store,
            cx,
            basis.body().repository_id,
            &resolved.forge,
            &resolved.outbox,
            &BTreeSet::from([number]),
            None,
            &|| projection.merge_checkpoint(cx).is_err(),
        )
        .await?;
        let previous = timelines.get(&number).map(|timeline| &timeline.issue);
        apply_event(previous, event).map_err(ProjectionFailure::Refuse)?;
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        // Issues introduce no native objects. Empty per-record closure cannot
        // erase the repository's independently verified cumulative retention.
        let closure = PermittedObjectClosure::default();
        Ok(ValidatedClosure {
            object_closure_root: crate::permitted_object_closure_root(&closure)
                .map_err(ProjectionFailure::Unavailable)?,
            objects: BTreeSet::new(),
        })
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
struct Timeline {
    issue: IssueSnapshot,
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

/// Current issue rows in numeric order, pinned to one authenticated head.
pub async fn read_page_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    after: u64,
    page_limit: u16,
    cancelled: &C,
) -> Result<IssuePage, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    limit(page_limit)?;
    let state = delivery::read_in(store, cx, basis, cancelled).await?;
    // Select numeric page keys before retaining or folding any issue history.
    // The lookahead key determines the cursor but does not consume replay state.
    let (wanted, more) = page_numbers(&state.forge, after, page_limit, cancelled)?;
    let all = replay_selected(
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
    let issues: Vec<_> = all.into_values().map(|timeline| timeline.issue).collect();
    let next_after = if more {
        issues.last().map(|issue| issue.number.get())
    } else {
        None
    };
    checkpoint(cancelled)?;
    Ok(IssuePage {
        source_head: basis.id(),
        issues,
        next_after,
    })
}

/// Complete versioned action/comment history, paged by event version. The
/// accompanying issue state is the current state at this same exact snapshot.
pub async fn read_history_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    number: IssueNumber,
    after: u64,
    page_limit: u16,
    cancelled: &C,
) -> Result<IssueHistoryPage, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    limit(page_limit)?;
    let state = delivery::read_in(store, cx, basis, cancelled).await?;
    let mut timelines = replay_selected(
        store,
        cx,
        basis.body().repository_id,
        &state.forge,
        &state.outbox,
        &BTreeSet::from([number]),
        Some((after, page_limit)),
        cancelled,
    )
    .await?;
    let Some(timeline) = timelines.remove(&number) else {
        return Ok(IssueHistoryPage {
            source_head: basis.id(),
            issue: None,
            events: Vec::new(),
            next_after: None,
        });
    };
    let mut events = Vec::new();
    let mut more = false;
    for event in timeline.events {
        checkpoint(cancelled)?;
        if event.version.get() <= after {
            continue;
        }
        if events.len() == usize::from(page_limit) {
            more = true;
            break;
        }
        events.push(event);
    }
    let next_after = if more {
        events.last().map(|event| event.version.get())
    } else {
        None
    };
    checkpoint(cancelled)?;
    Ok(IssueHistoryPage {
        source_head: basis.id(),
        issue: Some(timeline.issue),
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
    wanted: &BTreeSet<IssueNumber>,
    history_window: Option<(u64, u16)>,
    cancelled: &C,
) -> Result<BTreeMap<IssueNumber, Timeline>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    checkpoint(cancelled)?;
    if forge.repository_id() != repository || outbox.repository_id() != repository {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    let frontiers = issue_frontiers(forge, cancelled)?;
    if wanted.iter().all(|number| !frontiers.contains_key(number)) {
        // Callers already authenticated the delivery state. A new or missing
        // aggregate has no prior timeline to replay; object presence alone is
        // never used to invent one.
        checkpoint(cancelled)?;
        return Ok(BTreeMap::new());
    }
    let mut events = BTreeMap::<(IssueNumber, AggregateVersion), ForgeEvent>::new();
    let mut batches = BTreeSet::new();
    let (mut count, mut scanned_bytes, mut retained_bytes) = (0usize, 0usize, 0usize);
    for entry in outbox.entries() {
        checkpoint(cancelled)?;
        if !batches.insert(entry.payload_root()) {
            continue;
        }
        let batch = storage::read_events(store, cx, repository, entry.payload_root()).await?;
        checkpoint(cancelled)?;
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
            let AggregateId::Issue(number) = event.aggregate else {
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
    let mut timelines = BTreeMap::<IssueNumber, Timeline>::new();
    for ((number, _), event) in events {
        checkpoint(cancelled)?;
        let state = apply_event(
            timelines.get(&number).map(|timeline| &timeline.issue),
            &event,
        )
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        let timeline = timelines.entry(number).or_insert_with(|| Timeline {
            issue: state.clone(),
            events: Vec::new(),
            latest_event: event.clone(),
        });
        timeline.issue = state;
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
        if timeline.issue.version.get() != frontier.successor_position() {
            return Err(unavailable(RefusalCode::EvidenceMissing));
        }
        let batch =
            storage::read_events(store, cx, repository, frontier.event_batch_root()).await?;
        let selected = batch
            .events
            .iter()
            .rev()
            .find(|event| event.aggregate == AggregateId::Issue(number));
        if selected != Some(&timeline.latest_event) {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
    }
    checkpoint(cancelled)?;
    Ok(timelines)
}

/// Parse the canonical labels once, retaining numeric (not lexical) order.
fn issue_frontiers<C: Fn() -> bool + Sync>(
    forge: &CanonicalForgePositionState,
    cancelled: &C,
) -> Result<BTreeMap<IssueNumber, fgit_codec::ForgePositionStateEntry>, AdmissionError> {
    let mut frontiers = BTreeMap::new();
    for entry in forge.entries() {
        checkpoint(cancelled)?;
        let label = entry.stream();
        let Some(text) = label.as_str().strip_prefix("issue/") else {
            continue;
        };
        let number = text
            .parse::<u64>()
            .ok()
            .and_then(IssueNumber::try_new)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if storage::aggregate_label(AggregateId::Issue(number))? != label {
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
) -> Result<(BTreeSet<IssueNumber>, bool), AdmissionError> {
    let mut numbers = BTreeSet::new();
    let mut more = false;
    for number in issue_frontiers(forge, cancelled)?.into_keys() {
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
#[path = "issues/replay_tests.rs"]
mod replay_tests;
