//! Canonical PR conversations, with independent versions and bounded replay.
//! Comments never modify PR metadata, review votes, Git refs or policy epochs.

use std::collections::{BTreeMap, BTreeSet};

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest,
    TerminalOutcome,
};
use fgit_chronicle::PublicationBasis;
use fgit_codec::CanonicalForgePositionState;
use fgit_forge::event::pull_request_comment::{PullRequestCommentCommand, validate_body};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_types::{AsciiSlug, PrincipalId, RefName, RefusalCode, RepositoryAuthorityHeadId};

use super::super::{
    NativeMergeProjection, PreparationFailure, delivery, metadata, storage, unavailable,
};
use super::{PullRequestNumber, PullRequestView};
use crate::merge::NativeMergeBasis;
use crate::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, PermittedObjectClosure,
    ProjectionFailure, ValidatedClosure,
};

const MAX_PAGE: u16 = 100;
const MAX_SCAN_EVENTS: usize = 65_536;
const MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;

/// Freeze the exact discussion version, text, PR number and authenticated
/// actor. PR metadata changes do not change this original retry identity.
pub fn proposal(
    context: &AdmissionContext,
    command: &PullRequestCommentCommand,
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
            AsciiSlug::from_static("pull-request-comment.event-batch-root.v1"),
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

pub async fn admit_async<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    command: &PullRequestCommentCommand,
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
        &Validation,
    )
    .await
}

struct Validation;
impl<S, P> metadata::MetadataValidation<S, P> for Validation
where
    S: AsyncAuthorityStore + ?Sized,
    P: NativeMergeProjection<S> + ?Sized,
{
    fn precheck(&self, _: &AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        Ok(())
    }

    async fn validate<'a>(
        &'a self,
        store: &'a S,
        cx: &'a S::Context,
        basis: &'a PublicationBasis,
        _: &'a AuthenticatedHead,
        snapshot: &'a AdmissionSnapshot,
        resolved: &'a NativeMergeBasis,
        event: &'a ForgeEvent,
        projection: &'a P,
    ) -> Result<ValidatedClosure, PreparationFailure> {
        let AggregateId::PullRequestConversation(number) = event.aggregate else {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid).into());
        };
        let cancelled = || projection.merge_checkpoint(cx).is_err();
        let selected = native_pr_at(store, cx, basis, number, &|_, _| true, &cancelled)
            .await?
            .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))?;
        let data = selected
            .data
            .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
        if snapshot.hidden_refs.hides(data.source_ref.as_bytes())
            || snapshot.hidden_refs.hides(data.target_ref.as_bytes())
        {
            return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into());
        }
        // Closed/merged PRs retain their native conversation. Current tip
        // equality is irrelevant because commenting introduces no Git object.
        let previous = frontier(store, cx, &resolved.forge, number).await?;
        if previous.as_ref().map_or(0, |event| event.version.get()) != event.version.get() - 1 {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale).into());
        }
        projection
            .merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let objects = PermittedObjectClosure::default();
        Ok(ValidatedClosure {
            object_closure_root: crate::permitted_object_closure_root(&objects)
                .map_err(ProjectionFailure::Unavailable)?,
            objects: BTreeSet::new(),
        })
    }
}

/// One exact authored comment. A version is its stable position in this PR's
/// conversation; no rendering or mutable author record replaces original text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestCommentView {
    pub version: AggregateVersion,
    pub actor: PrincipalId,
    pub body: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestCommentsPage {
    pub number: PullRequestNumber,
    pub source_head: RepositoryAuthorityHeadId,
    pub discussion_version: Option<AggregateVersion>,
    pub comments: Vec<PullRequestCommentView>,
    pub next_after: Option<u64>,
}

impl PullRequestCommentsPage {
    /// Validate an exact contiguous window and its continuation before a
    /// transport discloses it. This does not authenticate a caller-minted page.
    pub fn validate_window(&self, after: u64, limit: u16) -> Result<(), RefusalCode> {
        if limit == 0 || limit > MAX_PAGE || self.comments.len() > usize::from(limit) {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        let latest = self.discussion_version.map_or(0, AggregateVersion::get);
        let length = latest.saturating_sub(after).min(u64::from(limit));
        if self.comments.len() as u64 != length {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let mut previous = after;
        for comment in &self.comments {
            if previous.checked_add(1) != Some(comment.version.get())
                || comment.version.get() > latest
                || validate_body(&comment.body).is_err()
            {
                return Err(RefusalCode::EvidenceInvalid);
            }
            previous = comment.version.get();
        }
        let expected_cursor = (previous < latest).then_some(previous);
        if self.next_after != expected_cursor {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }
}

/// Read one native PR's append-only conversation at a caller-authenticated
/// basis. `visible` must apply current caller and canonical hidden-ref policy
/// to BOTH branches, including when `basis` is a retained historical snapshot.
/// Absent, hidden and legacy-only PRs return None. Missing accepted bodies,
/// equivocation, gaps and cancellation fail closed rather than returning a
/// partial timeline. Reads retain at most one requested page of comment text.
pub async fn read_page_at<S, V, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    number: PullRequestNumber,
    after: u64,
    limit: u16,
    visible: &V,
    cancelled: &C,
) -> Result<Option<PullRequestCommentsPage>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    V: Fn(&RefName, &RefName) -> bool + Sync,
    C: Fn() -> bool + Sync,
{
    if limit == 0 || limit > MAX_PAGE {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    super::checkpoint(cancelled)?;
    if native_pr_at(store, cx, basis, number, visible, cancelled)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let state = delivery::read_roots_in(store, cx, basis, cancelled).await?;
    let mut page = PullRequestCommentsPage {
        number,
        source_head: basis.id(),
        discussion_version: None,
        comments: Vec::new(),
        next_after: None,
    };
    let Some(latest) = frontier(store, cx, &state.forge, number).await? else {
        super::checkpoint(cancelled)?;
        return Ok(Some(page));
    };
    page.discussion_version = Some(latest.version);
    let latest_digest = storage::root(&latest)?;
    let end = after.saturating_add(u64::from(limit));
    let mut seen = BTreeMap::new();
    let mut selected = BTreeMap::new();
    let mut batches = BTreeSet::new();
    let mut scanned_events = 0usize;
    let mut scanned_bytes = 0usize;
    for entry in state.outbox.entries() {
        super::checkpoint(cancelled)?;
        if !batches.insert(entry.payload_root()) {
            continue;
        }
        let batch =
            storage::read_events(store, cx, basis.body().repository_id, entry.payload_root())
                .await?;
        delivery::validate_payload_positions(&state.forge, &batch)?;
        scanned_events = scanned_events
            .checked_add(batch.events.len())
            .filter(|count| *count <= MAX_SCAN_EVENTS)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        for event in batch.events {
            super::checkpoint(cancelled)?;
            scanned_bytes = scanned_bytes
                .checked_add(super::event_size(&event)?)
                .filter(|count| *count <= MAX_SCAN_BYTES)
                .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            if event.aggregate != latest.aggregate {
                continue;
            }
            if event.version > latest.version {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            }
            let digest = storage::root(&event)?;
            if let Some(previous) = seen.insert(event.version, digest) {
                if previous != digest {
                    return Err(unavailable(RefusalCode::EvidenceInvalid));
                }
                continue;
            }
            let ForgeEventPayload::PullRequestCommentedNative(comment) = event.payload else {
                return Err(unavailable(RefusalCode::EvidenceInvalid));
            };
            if event.version.get() > after && event.version.get() <= end {
                selected.insert(
                    event.version,
                    PullRequestCommentView {
                        version: event.version,
                        actor: comment.actor,
                        body: comment.body,
                    },
                );
            }
        }
    }
    // Every unique positive version is <= latest, so the exact cardinality
    // proves no predecessor was silently omitted. The frontier body must also
    // occur byte-identically in the authority-selected history.
    if seen.len() as u64 != latest.version.get()
        || seen.get(&latest.version) != Some(&latest_digest)
    {
        return Err(unavailable(RefusalCode::EvidenceMissing));
    }
    page.comments = selected.into_values().collect();
    if let Some(last) = page.comments.last()
        && last.version < latest.version
    {
        page.next_after = Some(last.version.get());
    }
    page.validate_window(after, limit).map_err(unavailable)?;
    super::checkpoint(cancelled)?;
    Ok(Some(page))
}

async fn native_pr_at<S, V, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    number: PullRequestNumber,
    visible: &V,
    cancelled: &C,
) -> Result<Option<PullRequestView>, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    V: Fn(&RefName, &RefName) -> bool + Sync,
    C: Fn() -> bool + Sync,
{
    let page =
        super::read_page_at(store, cx, basis, number.get() - 1, 1, visible, cancelled).await?;
    Ok(page
        .pull_requests
        .into_iter()
        .find(|view| view.number == number && view.data.is_some()))
}

async fn frontier<S: AsyncAuthorityStore + ?Sized>(
    store: &S,
    cx: &S::Context,
    positions: &CanonicalForgePositionState,
    number: PullRequestNumber,
) -> Result<Option<ForgeEvent>, AdmissionError> {
    let aggregate = AggregateId::PullRequestConversation(number);
    let Some(entry) = positions.entry(storage::aggregate_label(aggregate)?) else {
        return Ok(None);
    };
    let batch = storage::read_events(
        store,
        cx,
        positions.repository_id(),
        entry.event_batch_root(),
    )
    .await?;
    delivery::validate_position_batch(entry, &batch)?;
    let event = batch
        .events
        .into_iter()
        .rev()
        .find(|event| event.aggregate == aggregate)
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    if event.version.get() != entry.successor_position()
        || !matches!(
            event.payload,
            ForgeEventPayload::PullRequestCommentedNative(_)
        )
    {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(Some(event))
}

#[cfg(test)]
mod tests;
