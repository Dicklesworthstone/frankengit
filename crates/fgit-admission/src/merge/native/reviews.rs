//! Durable exact-subject reviewer streams on the existing forge/outbox path.
//! This module is a child of pull_request so it reuses the authenticated PR
//! frontier reader. Neither votes nor query summaries grant merge authority.

use std::collections::BTreeSet;
use std::future::Future;
use fgit_authority::{AsyncAuthorityStore, AuthenticatedHead, OutcomeLookup, ScopedEntry,
    SealAttempt, SemanticRequest, TerminalOutcome};
use fgit_chronicle::{PublicationBasis, PublicationPlan};
use fgit_codec::{CanonicalForgePositionState, CryptoBodyIdentity};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload, PullRequestNumber};
use fgit_forge::event::review::{NativeReviewEvent, ReviewCommand, ReviewDecision,
    ReviewFreshness, review_freshness, validate_review_transition};
use fgit_types::{AsciiSlug, PolicyEpoch, PrincipalId, RefName, RefusalCode, RepositoryAuthorityHeadId};
use super::super::{NativeMergeProjection, PreparationFailure, delivery, prepare_event,
    stage_prepared, storage, unavailable};
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, ProjectionFailure, ValidatedClosure};

/// The node authenticates native dependencies at the exact publication basis.
/// A review command may reference existing commits but cannot upload objects.
pub trait ReviewProjection<S>: NativeMergeProjection<S>
where S: AsyncAuthorityStore + ?Sized,
{
    fn validate_review_async<'a>(
        &'a self, store: &'a S, cx: &'a S::Context, basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead, command: &'a ReviewCommand,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a;
}

/// The complete exact-subject vote and session actor define the immutable
/// semantic request. Head generations and retry counters are not re-sealed.
pub fn proposal(context: &AdmissionContext, command: &ReviewCommand)
    -> Result<(ForgeEvent, SealAttempt), AdmissionError>
{
    let event = command.proposed_event(context.principal_id, context.object_format).map_err(unavailable)?;
    let root = storage::root(&ForgeEventBatch::of_one(event.clone()))?;
    let request = SemanticRequest::build(fgit_authority::RECEIVE_ADMISSION_SCHEMA,
        context.object_format, true, Vec::new(), Vec::new(), vec![ScopedEntry::new(
            AsciiSlug::from_static("forge"), AsciiSlug::from_static("pull-request-review.event-batch-root"),
            root.bytes().as_bytes(),
        )?])?;
    Ok((event, SealAttempt { tenant_id: context.tenant_id, repository_id: context.repository_id,
        authenticated_principal_id: context.principal_id, idempotency_key: context.idempotency_key.clone(), request }))
}

/// Publish one reviewer-stream successor and one delivery obligation. Native
/// refs, the PR's metadata position and retention remain unchanged. Every CAS
/// retry validates the same request against the new authenticated predecessor.
/// An already terminal outcome is recovered before any current-code checks.
pub async fn admit_review_async<S, P>(
    store: &S, cx: &S::Context, context: &AdmissionContext,
    command: &ReviewCommand, limits: AdmissionLimits, projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: ReviewProjection<S> + ?Sized,
{
    limits.validate()?;
    let (event, attempt) = proposal(context, command)?;
    projection.merge_checkpoint(cx).map_err(unavailable)?;
    let admission = fgit_authority::seal_request_async(store, cx, &attempt).await?;
    let tx_id = admission.tx_id();
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
                let ForgeEventPayload::PullRequestReviewedNative(review) = &event.payload else {
                    return Err(ProjectionFailure::Unavailable(RefusalCode::InternalInvariantBreach).into());
                };
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
            // Withdrawal may invalidate an old vote after code/policy moved,
            // but still requires an existing, exact-version reviewer stream.
            let closure = projection.validate_review_async(store, cx, &basis, &authenticated, command).await?;
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
    /// Equality to a known opener, not a proof of reviewer independence. None
    /// means opener history is unavailable in the selected native PR profile.
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

/// Latest decisions in reviewer-ID order at one authenticated basis. Stale and
/// withdrawn decisions are retained with explicit applicability. There is no
/// aggregate approval count over a partial page and no authorization verdict.
/// None means the PR is absent or hidden, never a successful empty review set.
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
    let mut reviews = Vec::new();
    let mut next_after = None;
    let mut bytes = 0usize;
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
            next_after = reviews.last().map(|last: &ReviewView| last.event.reviewer);
            break;
        }
        bytes = bytes.checked_add(review.reason.len() + review.subject.source_ref.as_bytes().len()
            + review.subject.target_ref.as_bytes().len() + 256)
            .filter(|bytes| *bytes <= 2 * 1024 * 1024)
            .ok_or_else(|| unavailable(RefusalCode::ResourceBudgetExceeded))?;
        let freshness = review_freshness(&review, Some(&pr.event), basis.body().policy_epoch,
            refs.get(&review.subject.source_ref).copied(), refs.get(&review.subject.target_ref).copied());
        reviews.push(ReviewView { version, event: review, freshness,
            reviewer_is_opener: pr.opened_by.map(|opener| opener == reviewer) });
    }
    super::checkpoint(cancelled)?;
    Ok(Some(ReviewPage { source_head: basis.id(), pull_request: number,
        pull_request_version: pr.event.version, policy_epoch: basis.body().policy_epoch,
        reviews, next_after }))
}
