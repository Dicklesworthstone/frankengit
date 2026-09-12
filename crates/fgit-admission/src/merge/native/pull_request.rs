//! Native PR commands, canonical publication and bounded frontier reads.
//! This owns no mutable PR table: event bodies, forge positions and deliveries
//! are selected together by the same repository authority head as Git refs.

#[path = "reviews.rs"]
pub mod reviews;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use fgit_authority::{AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome};
use fgit_chronicle::PublicationBasis;
use fgit_codec::CanonicalForgePositionState;
use fgit_forge::aggregate::{AggregateId, AggregateVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_forge::event::pull_request::{NativePullRequestEvent, PullRequestAction, PullRequestCommand, PullRequestData, validate_transition};
use fgit_types::{AsciiSlug, PrincipalId, RefName, RefusalCode, RepositoryAuthorityHeadId};

use super::{NativeMergeProjection, PreparationFailure, delivery, storage, unavailable};
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, ProjectionFailure, ValidatedClosure};

/// The node supplies independently verified, already authority-selected
/// commit dependencies. Metadata commands may not introduce new Git objects.
pub trait PullRequestProjection<S>: NativeMergeProjection<S>
where S: AsyncAuthorityStore + ?Sized,
{
    fn validate_pull_request_async<'a>(
        &'a self, store: &'a S, cx: &'a S::Context,
        basis: &'a PublicationBasis, authenticated: &'a AuthenticatedHead,
        command: &'a PullRequestCommand,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a;
}

/// Freeze the submitted command and authenticated actor. The event commitment
/// binds action, version, branch names, exact tips and all text. No selected
/// head, clock, transport encoding or retry counter enters semantic identity.
pub fn proposal(
    context: &AdmissionContext, command: &PullRequestCommand,
) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let event = command.proposed_event(context.principal_id, context.object_format).map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(
        fgit_authority::RECEIVE_ADMISSION_SCHEMA, context.object_format, true,
        Vec::new(), Vec::new(), vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"),
            AsciiSlug::from_static("pull-request.event-batch-root"),
            root.bytes().as_bytes(),
        )?],
    )?;
    Ok((event, SealAttempt {
        tenant_id: context.tenant_id, repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id,
        idempotency_key: context.idempotency_key.clone(), request,
    }))
}

/// One exact-version PR transition and its delivery, without a ref movement.
/// Recovery precedes current-state checks. A CAS loser revalidates the SAME
/// immutable request; missing/corrupt storage and cancellation never become
/// successful empty reads or fabricated permanent lifecycle decisions.
pub async fn admit_pull_request_async<S, P>(
    store: &S, cx: &S::Context, context: &AdmissionContext,
    command: &PullRequestCommand, limits: AdmissionLimits, projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: PullRequestProjection<S> + ?Sized,
{
    limits.validate()?;
    let (event, attempt) = proposal(context, command)?;
    super::metadata::admit_metadata_async(store, cx, context, event, attempt,
        limits, projection, &PullRequestValidation(command)).await
}
struct PullRequestValidation<'a>(&'a PullRequestCommand);
impl<S, P> super::metadata::MetadataValidation<S, P> for PullRequestValidation<'_>
where S: AsyncAuthorityStore + ?Sized, P: PullRequestProjection<S> + ?Sized,
{
    fn precheck(&self, snapshot: &crate::AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        if snapshot.hidden_refs.hides(self.0.data.source_ref.as_bytes())
            || snapshot.hidden_refs.hides(self.0.data.target_ref.as_bytes())
        { return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized)); }
        Ok(())
    }
    fn validate<'a>(&'a self, store: &'a S, cx: &'a S::Context,
        basis: &'a PublicationBasis, authenticated: &'a AuthenticatedHead,
        snapshot: &'a crate::AdmissionSnapshot, resolved: &'a super::super::NativeMergeBasis,
        event: &'a ForgeEvent, projection: &'a P,
    ) -> impl Future<Output = Result<ValidatedClosure, PreparationFailure>> + Send + 'a {
        async move {
            let command = self.0;
            let previous = frontier_event(store, cx, &resolved.forge, command.number).await?;
            validate_transition(previous.as_ref(), event).map_err(ProjectionFailure::Refuse)?;
            if command.action != PullRequestAction::Close
                && (snapshot.refs.get(&command.data.source_ref) != Some(&command.data.source_tip)
                    || snapshot.refs.get(&command.data.target_ref) != Some(&command.data.target_tip))
            { return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into()); }
            Ok(projection.validate_pull_request_async(store, cx, basis, authenticated, command).await?)
        }
    }
}

/// Read the exact event selected for one aggregate. Both callers first resolve
/// the full delivery state, whose shared reader validates the batch's entire
/// range. The repeat read here verifies the same immutable event commitment;
/// no private duplicate of that reader's range validator is maintained.
async fn frontier_event<S: AsyncAuthorityStore + ?Sized>(
    store: &S, cx: &S::Context, positions: &CanonicalForgePositionState, number: PullRequestNumber,
) -> Result<Option<ForgeEvent>, AdmissionError> {
    let aggregate = AggregateId::PullRequest(number);
    let label = storage::aggregate_label(aggregate)?;
    let Some(entry) = positions.entry(label) else { return Ok(None); };
    let events = storage::read_events(store, cx, positions.repository_id(), entry.event_batch_root()).await?;
    let event = events.events.into_iter().rev().find(|event| event.aggregate == aggregate)
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    if event.version.get() != entry.successor_position() {
        return Err(unavailable(RefusalCode::EvidenceInvalid));
    }
    Ok(Some(event))
}

/// One native PR or explicit merge-only receipt at an authenticated frontier.
/// A merge-only receipt has no invented title, opener or prior review history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestView {
    pub number: PullRequestNumber,
    pub event: ForgeEvent,
    pub data: Option<PullRequestData>,
    pub opened_by: Option<PrincipalId>,
    /// Actor of the most recent metadata transition, not the merge principal.
    pub last_metadata_actor: Option<PrincipalId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestPage {
    pub source_head: RepositoryAuthorityHeadId,
    pub pull_requests: Vec<PullRequestView>,
    pub next_after: Option<u64>,
}

const MAX_PAGE: u16 = 100;
const MAX_READ_EVENTS: usize = 4096;
const MAX_READ_BYTES: usize = 32 * 1024 * 1024;

/// Read native PRs in numeric order at one exact caller-authenticated basis.
/// Both source and target must pass `visible` before any row is disclosed.
/// Older metadata is recovered from authority-selected outbox payloads so a
/// subsequent merge does not discard title/body/opener in the read model.
/// Legacy Digest-only PR streams are outside this explicitly native view.
/// A caller serving multiple pages must pin/check `source_head` on every page.
pub async fn read_page_at<S, V, C>(
    store: &S, cx: &S::Context, basis: &PublicationBasis, after: u64, limit: u16,
    visible: &V, cancelled: &C,
) -> Result<PullRequestPage, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
    V: Fn(&RefName, &RefName) -> bool + Sync,
    C: Fn() -> bool + Sync,
{
    if limit == 0 || limit > MAX_PAGE { return Err(unavailable(RefusalCode::ResourceBudgetExceeded)); }
    checkpoint(cancelled)?;
    let state = delivery::read_in(store, cx, basis, cancelled).await?;
    if state.forge.entries().len() > MAX_READ_EVENTS || state.outbox.entries().len() > MAX_READ_EVENTS {
        return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
    }
    let mut numbers = BTreeSet::new();
    for entry in state.forge.entries() {
        let label = entry.stream();
        let Some(text) = label.as_str().strip_prefix("pull-request/") else { continue; };
        let number = text.parse::<u64>().ok().and_then(PullRequestNumber::try_new)
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        if storage::aggregate_label(AggregateId::PullRequest(number))? != label {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        if number.get() > after { numbers.insert(number); }
    }
    let mut selected = Vec::new();
    let mut more = false;
    let mut bytes = 0usize;
    for number in numbers {
        checkpoint(cancelled)?;
        let event = frontier_event(store, cx, &state.forge, number).await?
            .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
        let permitted = match &event.payload {
            ForgeEventPayload::PullRequestChangedNative(change) => visible(&change.data.source_ref, &change.data.target_ref),
            ForgeEventPayload::MergeCommittedNative(merge) => visible(&merge.source_ref, &merge.target_ref),
            _ => false,
        };
        if !permitted { continue; }
        if selected.len() == usize::from(limit) { more = true; break; }
        charge_event(&event, &mut bytes)?;
        let (data, actor) = match &event.payload {
            ForgeEventPayload::PullRequestChangedNative(change) => (Some(change.data.clone()), Some(change.actor)),
            _ => (None, None),
        };
        selected.push(PullRequestView { number, event, data, opened_by: None, last_metadata_actor: actor });
    }
    // Scan retained canonical outbox payloads once for the whole page. This is
    // bounded replay of derived metadata, not another persistence or authority.
    let positions: BTreeMap<_, _> = selected.iter().map(|view| (view.number, view.event.version)).collect();
    let mut metadata: BTreeMap<PullRequestNumber, (AggregateVersion, NativePullRequestEvent)> = BTreeMap::new();
    let mut openers = BTreeMap::new();
    let mut seen = BTreeMap::new();
    let mut events_read = 0usize;
    if !selected.is_empty() {
        for obligation in state.outbox.entries() {
            checkpoint(cancelled)?;
            let batch = storage::read_events(store, cx, basis.body().repository_id, obligation.payload_root()).await?;
            events_read = events_read.checked_add(batch.events.len()).filter(|count| *count <= MAX_READ_EVENTS)
                .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
            for event in batch.events {
                charge_event(&event, &mut bytes)?;
                let AggregateId::PullRequest(number) = event.aggregate else { continue; };
                let Some(version) = positions.get(&number) else { continue; };
                if event.version > *version { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
                let digest = storage::root(&event)?;
                if let Some(previous) = seen.insert((number, event.version), digest)
                    && previous != digest
                { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
                let ForgeEventPayload::PullRequestChangedNative(change) = event.payload else { continue; };
                if change.action == PullRequestAction::Open {
                    if let Some(previous) = openers.insert(number, change.actor)
                        && previous != change.actor
                    { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
                }
                if metadata.get(&number).is_none_or(|(held, _)| *held < event.version) {
                    metadata.insert(number, (event.version, change));
                }
            }
        }
    }
    for view in &mut selected {
        if let Some((version, change)) = metadata.remove(&view.number) {
            match &view.event.payload {
                ForgeEventPayload::PullRequestChangedNative(latest) => {
                    if version != view.event.version || change != *latest {
                        return Err(unavailable(RefusalCode::EvidenceInvalid));
                    }
                }
                ForgeEventPayload::MergeCommittedNative(merge) => {
                    if !version.is_immediate_predecessor_of(view.event.version)
                        || change.action == PullRequestAction::Close || !change.data.matches_merge(merge)
                    { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
                }
                _ => return Err(unavailable(RefusalCode::EvidenceInvalid)),
            }
            view.opened_by = openers.get(&view.number).copied();
            if view.opened_by.is_none() { return Err(unavailable(RefusalCode::EvidenceMissing)); }
            view.data = Some(change.data);
            view.last_metadata_actor = Some(change.actor);
        } else if matches!(view.event.payload, ForgeEventPayload::PullRequestChangedNative(_)) {
            return Err(unavailable(RefusalCode::EvidenceMissing));
        }
    }
    checkpoint(cancelled)?;
    let next_after = if more { selected.last().map(|view| view.number.get()) } else { None };
    Ok(PullRequestPage { source_head: basis.id(), pull_requests: selected, next_after })
}

fn charge_event(event: &ForgeEvent, bytes: &mut usize) -> Result<(), AdmissionError> {
    let size = fgit_codec::encode_body(event)
        .map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?.len();
    *bytes = bytes.checked_add(size).filter(|total| *total <= MAX_READ_BYTES)
        .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
    Ok(())
}
fn checkpoint<C: Fn() -> bool + Sync>(cancelled: &C) -> Result<(), AdmissionError> {
    if cancelled() { Err(unavailable(RefusalCode::CancellationInProgress)) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId, TenantId};
    fn inputs() -> (AdmissionContext, PullRequestCommand) {
        let context = AdmissionContext {
            head_key: fgit_authority::HeadKey::new(b"pr-test/head".to_vec()).unwrap(),
            tenant_id: TenantId::from_bytes([1; 16]), repository_id: RepositoryId::from_bytes([2; 16]),
            principal_id: PrincipalId::from_bytes([3; 16]),
            idempotency_key: fgit_authority::IdempotencyKey::new(b"pr-test".to_vec()).unwrap(),
            object_format: GitHashAlgorithm::Sha1,
        };
        let command = PullRequestCommand {
            number: PullRequestNumber::FIRST, expected_version: fgit_forge::ExpectedVersion::NewStream,
            action: PullRequestAction::Open, data: PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"a".repeat(40)).unwrap(),
                target_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"b".repeat(40)).unwrap(),
                title: "Original request".into(), body: "x".repeat(64 * 1024),
            },
        };
        (context, command)
    }
    #[test]
    fn metadata_only_seal_is_stable_and_binds_the_complete_event() {
        let (context, command) = inputs();
        let (event, seal) = proposal(&context, &command).unwrap();
        assert!(seal.request.ref_commands().is_empty());
        assert!(seal.request.atomic());
        assert_eq!(proposal(&context, &command).unwrap(), (event, seal.clone()));
        let mut changed = command.clone(); changed.data.body.replace_range(0..1, "y");
        assert_ne!(proposal(&context, &changed).unwrap().1.derive().unwrap().0, seal.derive().unwrap().0);
        let mut actor = context.clone(); actor.principal_id = PrincipalId::from_bytes([4; 16]);
        assert_ne!(proposal(&actor, &command).unwrap().1.derive().unwrap().0, seal.derive().unwrap().0);
    }
    #[test]
    fn expected_version_and_action_are_not_rebuilt_from_current_state() {
        let (context, mut command) = inputs();
        let original = proposal(&context, &command).unwrap().1.derive().unwrap().0;
        command.action = PullRequestAction::Update;
        command.expected_version = fgit_forge::ExpectedVersion::Exactly(AggregateVersion::FIRST);
        let update = proposal(&context, &command).unwrap().1.derive().unwrap().0;
        command.action = PullRequestAction::Close;
        let close = proposal(&context, &command).unwrap().1.derive().unwrap().0;
        assert_ne!(original, update); assert_ne!(update, close);
        command.expected_version = fgit_forge::ExpectedVersion::NewStream;
        assert!(proposal(&context, &command).is_err());
    }
}
