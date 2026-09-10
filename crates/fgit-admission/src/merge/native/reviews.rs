//! Durable reviewer streams share the existing PR frontier, forge/outbox fold
//! and authority CAS. An approval is not a cached boolean or a second database.
#[path = "review_gate.rs"]
pub mod gate;

use std::collections::BTreeSet;
use std::future::Future;
use fgit_authority::{AsyncAuthorityStore, AuthenticatedHead, OutcomeLookup, ScopedEntry,
    SealAttempt, SemanticRequest, TerminalOutcome};
use fgit_chronicle::{PublicationBasis, PublicationPlan};
use fgit_codec::{CanonicalForgePositionState, CryptoBodyIdentity};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload, PullRequestNumber};
use fgit_forge::event::review::{CandidateBinding, CandidateReviewCommand, NativeReviewEvent,
    ReviewCommand, ReviewDecision, ReviewFreshness, review_freshness, validate_review_transition};
use fgit_types::{AsciiSlug, PolicyEpoch, PrincipalId, RefName, RefusalCode, RepositoryAuthorityHeadId};
use super::super::{NativeMergeProjection, PreparationFailure, delivery, prepare_event,
    stage_prepared, storage, unavailable};
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, ProjectionFailure, ValidatedClosure};

/// The owner validates native dependencies at the exact basis. Candidate
/// approvals additionally inspect the actual bundle without staging its objects.
pub trait ReviewProjection<S>: NativeMergeProjection<S>
where S: AsyncAuthorityStore + ?Sized,
{
    fn validate_review_async<'a>(
        &'a self, store: &'a S, cx: &'a S::Context, basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead, command: &'a ReviewCommand,
        candidate: Option<CandidateBinding>,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a;
}

pub fn proposal(context: &AdmissionContext, command: &ReviewCommand)
    -> Result<(ForgeEvent, SealAttempt), AdmissionError>
{
    seal_event(context, command.proposed_event(context.principal_id, context.object_format).map_err(unavailable)?)
}

pub fn candidate_proposal(context: &AdmissionContext, command: &CandidateReviewCommand)
    -> Result<(ForgeEvent, SealAttempt), AdmissionError>
{
    seal_event(context, command.proposed_event(context.principal_id, context.object_format).map_err(unavailable)?)
}

fn seal_event(context: &AdmissionContext, event: ForgeEvent) -> Result<(ForgeEvent, SealAttempt), AdmissionError> {
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format, true, Vec::new(), Vec::new(), vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"), AsciiSlug::from_static("pull-request-review.event-batch-root"),
            root.bytes().as_bytes(),
        )?])?;
    Ok((event, SealAttempt { tenant_id: context.tenant_id, repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id, idempotency_key: context.idempotency_key.clone(), request }))
}

pub async fn admit_review_async<S, P>(
    store: &S, cx: &S::Context, context: &AdmissionContext,
    command: &ReviewCommand, limits: AdmissionLimits, projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: ReviewProjection<S> + ?Sized,
{
    let (event, attempt) = proposal(context, command)?;
    admit_event(store, cx, context, command, event, attempt, limits, projection).await
}

pub async fn admit_candidate_review_async<S, P>(
    store: &S, cx: &S::Context, context: &AdmissionContext,
    command: &CandidateReviewCommand, limits: AdmissionLimits, projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: ReviewProjection<S> + ?Sized,
{
    let (event, attempt) = candidate_proposal(context, command)?;
    admit_event(store, cx, context, &command.review, event, attempt, limits, projection).await
}

/// The single review driver handles both profiles. Replanning retains the exact
/// event, including candidate identity; a stale vote cannot silently refresh.
async fn admit_event<S, P>(
    store: &S, cx: &S::Context, context: &AdmissionContext, command: &ReviewCommand,
    event: ForgeEvent, attempt: SealAttempt, limits: AdmissionLimits, projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: ReviewProjection<S> + ?Sized,
{
    limits.validate()?;
    projection.merge_checkpoint(cx).map_err(unavailable)?;
    let admission = fgit_authority::seal_request_async(store, cx, &attempt).await?;
    let tx_id = admission.tx_id();
    let ForgeEventPayload::PullRequestReviewedNative(review) = &event.payload else {
        return Err(unavailable(RefusalCode::InternalInvariantBreach));
    };
    for _ in 0..limits.max_cas_replans {
        projection.merge_checkpoint(cx).map_err(unavailable)?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            store, cx, &context.head_key, context.tenant_id, context.repository_id, tx_id,
        ).await? { return Ok(terminal); }
        let (basis, receipt, authenticated) = crate::read_basis_async(store, cx, &context.head_key).await?;
        let cumulative = fgit_authority::collect_cumulative_outcomes_async(store, cx, &context.head_key).await?;
        if cumulative.observed() != receipt.token() { continue; }
        let preparation: Result<_, PreparationFailure> = async {
            let snapshot = projection.snapshot_async(store, cx, &basis, &authenticated).await?;
            let subject = &command.subject;
            if snapshot.hidden_refs.hides(subject.source_ref.as_bytes())
                || snapshot.hidden_refs.hides(subject.target_ref.as_bytes())
            { return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized).into()); }
            let resolved = projection.resolve_merge_basis_async(store, cx, &basis, &authenticated).await?;
            if resolved.refs.refs() != &snapshot.refs
                || resolved.refs.head_target() != snapshot.head_target.as_ref()
                || storage::load_forge_positions(store, cx, &basis).await? != resolved.forge
            { return Err(ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale).into()); }
            projection.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
            let previous = review_frontier(store, cx, &resolved.forge, event.aggregate).await?;
            validate_review_transition(previous.as_ref(), &event).map_err(ProjectionFailure::Refuse)?;
            let pr = super::frontier_event(store, cx, &resolved.forge, subject.pull_request).await?;
            if command.decision != ReviewDecision::Withdraw {
                let freshness = review_freshness(review, pr.as_ref(), basis.body().policy_epoch,
                    snapshot.refs.get(&subject.source_ref).copied(), snapshot.refs.get(&subject.target_ref).copied());
                if freshness != ReviewFreshness::Current {
                    return Err(ProjectionFailure::Refuse(match freshness {
                        ReviewFreshness::PullRequestUnavailable => RefusalCode::ForgeTransitionInvalid,
                        ReviewFreshness::PullRequestClosed => RefusalCode::ProtectedRefTransitionDenied,
                        ReviewFreshness::SourceMoved | ReviewFreshness::TargetMoved => RefusalCode::TargetRefMoved,
                        _ => RefusalCode::EvidenceStale,
                    }).into());
                }
            }
            let closure = projection.validate_review_async(store, cx, &basis, &authenticated, command, review.candidate).await?;
            let prepared = prepare_event(context, &event, &closure, tx_id, &attempt, &basis, &resolved)
                .map_err(ProjectionFailure::Refuse)?;
            let pr_label = storage::aggregate_label(AggregateId::PullRequest(subject.pull_request))?;
            if prepared.refs != resolved.refs || prepared.materialization.roots.ref_root != basis.body().ref_root
                || prepared.materialization.roots.retention_root != basis.body().retention_root
                || prepared.forge.entry(pr_label) != resolved.forge.entry(pr_label)
                || !prepared.fold.effects().is_some_and(|effects| effects.refs.is_empty() && effects.retention.is_empty())
            { return Err(ProjectionFailure::Unavailable(RefusalCode::InternalInvariantBreach).into()); }
            Ok(prepared)
        }.await;
        let prepared = match preparation {
            Ok(prepared) => prepared,
            Err(PreparationFailure::Admission(error)) => return Err(*error),
            Err(PreparationFailure::Projection(ProjectionFailure::Unavailable(code))) => return Err(unavailable(code)),
            Err(PreparationFailure::Projection(ProjectionFailure::Refuse(code))) => {
                projection.merge_publication_checkpoint(cx).map_err(unavailable)?;
                if let Some(terminal) = crate::publish_refusal_async(store, cx, context, &basis,
                    receipt.token(), admission.seal_id(), tx_id, code, projection, &cumulative,
                ).await? { return Ok(terminal); }
                continue;
            }
        };
        stage_prepared(store, cx, &prepared).await?;
        projection.merge_publication_checkpoint(cx).map_err(unavailable)?;
        let mut plan = PublicationPlan::open(basis.clone())?;
        plan.commit(prepared.materialization.record);
        let publication = plan.seal(&CryptoBodyIdentity, prepared.materialization.roots, &cumulative, receipt.token())?;
        projection.merge_publication_checkpoint(cx).map_err(unavailable)?;
        if let Some(terminal) = crate::outcome_after_publish_async(store, cx, context, receipt.token(), &publication).await? {
            return Ok(terminal);
        }
    }
    Err(AdmissionError::CasReplanLimitExceeded { limit: limits.max_cas_replans })
}

async fn review_frontier<S: AsyncAuthorityStore + ?Sized>(
    store: &S, cx: &S::Context, positions: &CanonicalForgePositionState, aggregate: AggregateId,
) -> Result<Option<ForgeEvent>, AdmissionError> {
    let Some(position) = positions.entry(storage::aggregate_label(aggregate)?) else { return Ok(None); };
    let batch = storage::read_events(store, cx, positions.repository_id(), position.event_batch_root()).await?;
    let event = batch.events.into_iter().rev().find(|event| event.aggregate == aggregate)
        .ok_or_else(|| unavailable(RefusalCode::EvidenceInvalid))?;
    if event.version.get() != position.successor_position()
        || !matches!(&event.payload, ForgeEventPayload::PullRequestReviewedNative(review) if review.aggregate() == aggregate)
    { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
    Ok(Some(event))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewView {
    pub version: AggregateVersion,
    pub event: NativeReviewEvent,
    pub freshness: ReviewFreshness,
    pub reviewer_is_opener: Option<bool>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewPage {
    pub source_head: RepositoryAuthorityHeadId,
    pub pull_request: PullRequestNumber,
    pub pull_request_version: AggregateVersion,
    pub policy_epoch: PolicyEpoch,
    pub reviews: Vec<ReviewView>,
    pub next_after: Option<PrincipalId>,
}

/// Latest decisions in reviewer-ID order; never an approval count over a partial
/// page. Source-only decisions remain distinct from exact candidate approvals.
pub async fn read_page_at<S, V, C>(
    store: &S, cx: &S::Context, basis: &PublicationBasis, number: PullRequestNumber,
    refs: &std::collections::BTreeMap<RefName, fgit_types::GitOid>,
    after: Option<PrincipalId>, limit: u16, visible: &V, cancelled: &C,
) -> Result<Option<ReviewPage>, AdmissionError>
where S: AsyncAuthorityStore + ?Sized,
    V: Fn(&RefName, &RefName) -> bool + Sync, C: Fn() -> bool + Sync,
{
    if limit == 0 || limit > 100 { return Err(unavailable(RefusalCode::ResourceBudgetExceeded)); }
    super::checkpoint(cancelled)?;
    let mut prs = super::read_page_at(store, cx, basis, number.get() - 1, 1, visible, cancelled).await?;
    let Some(pr) = prs.pull_requests.pop().filter(|pr| pr.number == number) else { return Ok(None); };
    let state = delivery::read_in(store, cx, basis, cancelled).await?;
    if state.forge.entries().len() > 4096 { return Err(unavailable(RefusalCode::ResourceBudgetExceeded)); }
    let prefix = format!("review/{number}/");
    let mut reviewers = BTreeSet::new();
    for position in state.forge.entries() {
        super::checkpoint(cancelled)?;
        let label = position.stream();
        let Some(text) = label.as_str().strip_prefix(&prefix) else { continue; };
        let reviewer = PrincipalId::from_hex(text).map_err(|_| unavailable(RefusalCode::EvidenceInvalid))?;
        let aggregate = AggregateId::PullRequestReview { pull_request: number, reviewer };
        if storage::aggregate_label(aggregate)? != label { return Err(unavailable(RefusalCode::EvidenceInvalid)); }
        if after.is_none_or(|last| reviewer > last) { reviewers.insert(reviewer); }
    }
    let mut reviews = Vec::new(); let mut next_after = None; let mut bytes = 0usize;
    for reviewer in reviewers {
        super::checkpoint(cancelled)?;
        let event = review_frontier(store, cx, &state.forge,
            AggregateId::PullRequestReview { pull_request: number, reviewer }).await?
            .ok_or_else(|| unavailable(RefusalCode::EvidenceMissing))?;
        let version = event.version;
        let ForgeEventPayload::PullRequestReviewedNative(review) = event.payload else {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        };
        if !visible(&review.subject.source_ref, &review.subject.target_ref) { continue; }
        if reviews.len() == usize::from(limit) {
            next_after = reviews.last().map(|last: &ReviewView| last.event.reviewer); break;
        }
        bytes = bytes.checked_add(review.reason.len() + review.subject.source_ref.as_bytes().len()
            + review.subject.target_ref.as_bytes().len() + 400)
            .filter(|bytes| *bytes <= 2 * 1024 * 1024)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        let freshness = review_freshness(&review, Some(&pr.event), basis.body().policy_epoch,
            refs.get(&review.subject.source_ref).copied(), refs.get(&review.subject.target_ref).copied());
        reviews.push(ReviewView { version, event: review, freshness,
            reviewer_is_opener: pr.opened_by.map(|opener| opener == reviewer) });
    }
    super::checkpoint(cancelled)?;
    Ok(Some(ReviewPage { source_head: basis.id(), pull_request: number,
        pull_request_version: pr.event.version, policy_epoch: basis.body().policy_epoch, reviews, next_after }))
}
