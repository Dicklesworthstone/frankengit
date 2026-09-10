//! Exact named-reviewer preconditions inside the native publication loop.
//! Requirements are immutable request semantics, not an approval boolean supplied
//! by the CLI. Repository-wide protected-ref policy remains a separate owner.
use std::future::Future;
use fgit_authority::{AsyncAuthorityStore, AuthenticatedHead, ScopedEntry, SealAttempt, SemanticRequest, TerminalOutcome};
use fgit_chronicle::PublicationBasis;
use fgit_forge::{AggregateId, ExpectedVersion, ForgeEventPayload};
use fgit_forge::event::review::{CandidateBinding, NativeReviewEvent, ReviewDecision, ReviewSubject};
use fgit_reference::intent::TransactionRequest;
use fgit_types::{AsciiSlug, PolicyEpoch, PrincipalId, RefusalCode, TxId};
use crate::{AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, AsyncAdmissionProjection,
    CommitMaterialization, ProjectionFailure, RefusalMaterialization, ValidatedClosure};
use crate::merge::NativeMergeBasis;
use super::super::super::{NativeMergeIntent, NativeMergeProjection, admit_merge_attempt_async, delivery, unavailable};

pub const MAX_REQUIRED_REVIEWERS: usize = 32;

/// Every named reviewer must currently approve the exact candidate. Names are
/// sorted once; duplicates, empty sets, submitter/opener votes never satisfy it.
/// The caller must be authorized to choose the requirements. This is not a
/// replacement for repository-wide protected-ref administration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewRequirements {
    policy_epoch: PolicyEpoch,
    reviewers: Vec<PrincipalId>,
}
impl ReviewRequirements {
    pub fn new(policy_epoch: PolicyEpoch, mut reviewers: Vec<PrincipalId>) -> Result<Self, AdmissionError> {
        if reviewers.is_empty() || reviewers.len() > MAX_REQUIRED_REVIEWERS {
            return Err(unavailable(RefusalCode::ResourceBudgetExceeded));
        }
        reviewers.sort();
        if reviewers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(unavailable(RefusalCode::EvidenceInvalid));
        }
        Ok(Self { policy_epoch, reviewers })
    }
    pub fn reviewers(&self) -> &[PrincipalId] { &self.reviewers }
    pub const fn policy_epoch(&self) -> PolicyEpoch { self.policy_epoch }
    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12 + self.reviewers.len() * 16);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&self.policy_epoch.get().to_be_bytes());
        bytes.extend_from_slice(&(self.reviewers.len() as u16).to_be_bytes());
        for reviewer in &self.reviewers { bytes.extend_from_slice(reviewer.as_bytes()); }
        bytes
    }
}

/// Preserve the original merge/workspace request and add one required canonical
/// entry. Omitting/changing reviewers is a DIFFERENT seal, never a retry.
pub fn reviewed_seal_attempt(
    context: &AdmissionContext, intent: &NativeMergeIntent, required: &ReviewRequirements,
) -> Result<SealAttempt, AdmissionError> {
    if !matches!(intent.expected_version(), ExpectedVersion::Exactly(_))
        || required.reviewers.contains(&context.principal_id)
    { return Err(unavailable(RefusalCode::ProtectedRefTransitionDenied)); }
    let mut attempt = intent.seal_attempt(context)?;
    let request = &attempt.request;
    let mut entries = request.scoped_entries().to_vec();
    entries.push(ScopedEntry::new(AsciiSlug::from_static("forge"),
        AsciiSlug::from_static("merge.required-candidate-reviewers.v1"), required.bytes())?);
    attempt.request = SemanticRequest::build(request.request_schema(), request.object_format(), request.atomic(),
        request.ref_commands().to_vec(), request.push_options().to_vec(), entries)?;
    Ok(attempt)
}

/// Same native commit driver, with review validation repeated at EVERY attempted
/// basis. A concurrent withdrawal/PR update wins the same CAS, so a losing merge
/// must revalidate. Historical terminal recovery precedes current requirements.
pub async fn admit_reviewed_merge_async<S, P>(
    store: &S, cx: &S::Context, context: &AdmissionContext, intent: &NativeMergeIntent,
    required: &ReviewRequirements, limits: AdmissionLimits, projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: NativeMergeProjection<S> + Sync + ?Sized,
{
    limits.validate()?;
    let attempt = reviewed_seal_attempt(context, intent, required)?;
    let guarded = GuardedProjection { inner: projection, context, required };
    admit_merge_attempt_async(store, cx, context, intent, &attempt, None, limits, &guarded).await
}

struct GuardedProjection<'a, P: ?Sized> {
    inner: &'a P,
    context: &'a AdmissionContext,
    required: &'a ReviewRequirements,
}
impl<S, P> AsyncAdmissionProjection<S> for GuardedProjection<'_, P>
where S: AsyncAuthorityStore + ?Sized, P: NativeMergeProjection<S> + Sync + ?Sized,
{
    fn snapshot_async<'a>(&'a self, store: &'a S, cx: &'a S::Context, basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead) -> impl Future<Output=Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        self.inner.snapshot_async(store, cx, basis, authenticated)
    }
    fn materialize_commit_async<'a>(&'a self, store: &'a S, cx: &'a S::Context, basis: &'a PublicationBasis,
        request: &'a TransactionRequest, fold: &'a fgit_txn::TransactionFoldReport, closure: &'a ValidatedClosure)
        -> impl Future<Output=Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner.materialize_commit_async(store, cx, basis, request, fold, closure)
    }
    fn materialize_refusal_async<'a>(&'a self, store: &'a S, cx: &'a S::Context, basis: &'a PublicationBasis,
        tx_id: TxId, code: RefusalCode) -> impl Future<Output=Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner.materialize_refusal_async(store, cx, basis, tx_id, code)
    }
}
impl<S, P> NativeMergeProjection<S> for GuardedProjection<'_, P>
where S: AsyncAuthorityStore + ?Sized, P: NativeMergeProjection<S> + Sync + ?Sized,
{
    fn merge_checkpoint(&self, cx: &S::Context) -> Result<(), RefusalCode> { self.inner.merge_checkpoint(cx) }
    fn merge_publication_checkpoint(&self, cx: &S::Context) -> Result<(), RefusalCode> { self.inner.merge_publication_checkpoint(cx) }
    fn workspace_snapshot_digest(&self) -> Result<[u8; 32], ProjectionFailure> { self.inner.workspace_snapshot_digest() }
    fn resolve_merge_basis_async<'a>(&'a self, store: &'a S, cx: &'a S::Context, basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead) -> impl Future<Output=Result<NativeMergeBasis, ProjectionFailure>> + Send + 'a {
        self.inner.resolve_merge_basis_async(store, cx, basis, authenticated)
    }
    fn validate_merge_async<'a>(&'a self, store: &'a S, cx: &'a S::Context, basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead, intent: &'a NativeMergeIntent)
        -> impl Future<Output=Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        async move {
            let closure = self.inner.validate_merge_async(store, cx, basis, authenticated, intent).await?;
            self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
            verify_at(store, cx, basis, intent, self.context.principal_id, self.required,
                &|| self.merge_checkpoint(cx).is_err()).await?;
            self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
            Ok(closure)
        }
    }
}

fn infrastructure(error: AdmissionError) -> ProjectionFailure {
    match error {
        AdmissionError::AsyncProjectionUnavailable(code) => ProjectionFailure::Unavailable(code),
        _ => ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptInvalid),
    }
}
async fn verify_at<S, C>(store: &S, cx: &S::Context, basis: &PublicationBasis,
    intent: &NativeMergeIntent, submitter: PrincipalId, required: &ReviewRequirements, cancelled: &C)
    -> Result<(), ProjectionFailure>
where S: AsyncAuthorityStore + ?Sized, C: Fn() -> bool + Sync,
{
    let ExpectedVersion::Exactly(version) = intent.expected_version() else {
        return Err(ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied));
    };
    if basis.body().policy_epoch != required.policy_epoch {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale));
    }
    let AggregateId::PullRequest(number) = intent.event().aggregate else {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
    };
    let merge = intent.merge().map_err(infrastructure)?;
    let subject = ReviewSubject { pull_request: number, pull_request_version: version,
        source_ref: merge.source_ref.clone(), target_ref: merge.target_ref.clone(),
        source_tip: merge.source_tip, target_tip: merge.target_tip_before, policy_epoch: required.policy_epoch };
    let candidate = CandidateBinding { merge_base: merge.base_tip, commit: merge.merge_commit };
    let mut page = super::super::read_page_at(store, cx, basis, number.get() - 1, 1,
        &|source, target| source == &subject.source_ref && target == &subject.target_ref, cancelled).await.map_err(infrastructure)?;
    let pr = page.pull_requests.pop().filter(|pr| pr.number == number)
        .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))?;
    let ForgeEventPayload::PullRequestChangedNative(change) = &pr.event.payload else {
        return Err(ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied));
    };
    if change.action == fgit_forge::event::pull_request::PullRequestAction::Close
        || pr.event.version != version || !change.data.matches_merge(merge)
    { return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale)); }
    let opener = pr.opened_by.ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
    if required.reviewers.iter().any(|reviewer| *reviewer == opener || *reviewer == submitter) {
        return Err(ProjectionFailure::Refuse(RefusalCode::ProtectedRefTransitionDenied));
    }
    let state = delivery::read_in(store, cx, basis, cancelled).await.map_err(infrastructure)?;
    for reviewer in &required.reviewers {
        super::super::checkpoint(cancelled).map_err(infrastructure)?;
        let event = super::review_frontier(store, cx, &state.forge,
            AggregateId::PullRequestReview { pull_request: number, reviewer: *reviewer }).await.map_err(infrastructure)?
            .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))?;
        let ForgeEventPayload::PullRequestReviewedNative(review) = event.payload else {
            return Err(ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid));
        };
        verify_vote(&review, *reviewer, &subject, candidate).map_err(ProjectionFailure::Refuse)?;
    }
    Ok(())
}

fn verify_vote(review: &NativeReviewEvent, reviewer: PrincipalId, subject: &ReviewSubject,
    candidate: CandidateBinding) -> Result<(), RefusalCode> {
    review.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
    if review.reviewer != reviewer || &review.subject != subject || review.candidate != Some(candidate) {
        return Err(RefusalCode::EvidenceStale);
    }
    if review.decision != ReviewDecision::Approve { return Err(RefusalCode::ProtectedRefTransitionDenied); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryId, TenantId};
    use fgit_forge::{AggregateVersion, PullRequestNumber};
    fn fixture() -> (AdmissionContext, NativeMergeIntent, ReviewRequirements, NativeReviewEvent) {
        let oid = |digit: &str| GitOid::from_hex(GitHashAlgorithm::Sha1, &digit.repeat(40)).unwrap();
        let reviewer = PrincipalId::from_bytes([9;16]);
        let context = AdmissionContext { head_key: fgit_authority::HeadKey::new(b"head".to_vec()).unwrap(),
            tenant_id: TenantId::from_bytes([1;16]), repository_id: RepositoryId::from_bytes([2;16]),
            principal_id: PrincipalId::from_bytes([3;16]), idempotency_key: fgit_authority::IdempotencyKey::new(b"key".to_vec()).unwrap(),
            object_format: GitHashAlgorithm::Sha1 };
        let subject = ReviewSubject { pull_request: PullRequestNumber::FIRST, pull_request_version: AggregateVersion::FIRST,
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(), target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: oid("a"), target_tip: oid("b"), policy_epoch: PolicyEpoch::FIRST };
        let binding = CandidateBinding { merge_base: oid("c"), commit: oid("d") };
        let intent = NativeMergeIntent::new(subject.pull_request, ExpectedVersion::Exactly(subject.pull_request_version), binding.merge(&subject)).unwrap();
        let review = NativeReviewEvent { reviewer, subject, decision: ReviewDecision::Approve, candidate: Some(binding), reason: String::new() };
        (context, intent, ReviewRequirements::new(PolicyEpoch::FIRST, vec![reviewer]).unwrap(), review)
    }
    #[test]
    fn gate_requirements_are_sealed_order_independent_and_cannot_be_dropped_on_retry() {
        let (context, intent, required, _) = fixture();
        let guarded = reviewed_seal_attempt(&context, &intent, &required).unwrap();
        assert_ne!(guarded.derive().unwrap().0, intent.seal_attempt(&context).unwrap().derive().unwrap().0);
        let other = PrincipalId::from_bytes([8;16]);
        let a = ReviewRequirements::new(PolicyEpoch::FIRST, vec![other, required.reviewers[0]]).unwrap();
        let b = ReviewRequirements::new(PolicyEpoch::FIRST, vec![required.reviewers[0], other]).unwrap();
        assert_eq!(a, b); assert_eq!(reviewed_seal_attempt(&context, &intent, &a).unwrap(), reviewed_seal_attempt(&context, &intent, &b).unwrap());
        assert_ne!(guarded.derive().unwrap().0, reviewed_seal_attempt(&context, &intent, &a).unwrap().derive().unwrap().0);
        assert!(ReviewRequirements::new(PolicyEpoch::FIRST, vec![]).is_err());
        assert!(ReviewRequirements::new(PolicyEpoch::FIRST, vec![other, other]).is_err());
        assert!(reviewed_seal_attempt(&context, &intent,
            &ReviewRequirements::new(PolicyEpoch::FIRST, vec![context.principal_id]).unwrap()).is_err());
    }
    #[test]
    fn only_exact_current_candidate_approvals_satisfy_the_gate() {
        let (_, _, _, valid) = fixture(); let candidate = valid.candidate.unwrap();
        verify_vote(&valid, valid.reviewer, &valid.subject, candidate).unwrap();
        for field in 0..7 {
            let mut wrong = valid.clone();
            match field {
                0 => wrong.candidate = None,
                1 => wrong.candidate.as_mut().unwrap().commit = GitOid::from_hex(GitHashAlgorithm::Sha1, &"e".repeat(40)).unwrap(),
                2 => wrong.subject.pull_request_version = wrong.subject.pull_request_version.next().unwrap(),
                3 => wrong.subject.policy_epoch = PolicyEpoch::try_new(2).unwrap(),
                4 => { wrong.decision = ReviewDecision::Withdraw; wrong.reason = "withdrawn".into(); },
                5 => { wrong.decision = ReviewDecision::RequestChanges; wrong.reason = "blocked".into(); },
                _ => wrong.reviewer = PrincipalId::from_bytes([8;16]),
            }
            assert!(verify_vote(&wrong, valid.reviewer, &valid.subject, candidate).is_err(), "field {field}");
        }
    }
}
