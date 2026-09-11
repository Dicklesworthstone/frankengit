//! Local authenticated review and review-gated publication composition.
//! The bundle is inspected in memory; voting never imports candidate objects.
use std::cell::Cell;
use std::future::Future;
use fgit_admission::merge::native::objects::MergeObjectLimits;
use fgit_admission::merge::native::pull_request::reviews::{self, ReviewPage, ReviewProjection};
use fgit_admission::merge::native::pull_request::reviews::gate::{self, ReviewRequirements};
use fgit_admission::merge::native::{NativeMergeIntent, NativeMergeProjection};
use fgit_admission::merge::NativeMergeBasis;
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, AsyncAdmissionProjection,
    CommitMaterialization, ProjectionFailure, RefusalMaterialization, ValidatedClosure};
use fgit_authority::{AuthenticatedHead, IdempotencyKey, OutcomeLookup, TerminalOutcome};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_forge::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::review::{CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision};
use fgit_forge::review::{ComparisonMode, ReviewOptions};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParsedObject, parse_object_body};
use fgit_reference::intent::TransactionRequest;
use fgit_types::{GitOid, PolicyEpoch, PrincipalId, RefusalCode, RepositoryAuthorityHeadId, TxId};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_wire::visibility::RefVisibility;
use fsqlite_types::cx::Cx;
use super::super::native_merge::NodeNativeMergeProjection;
use super::super::{NodeWorkspaceRefusal, workspace_request_live};
use super::super::publication::receive_error;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode,
    VerifiedFabricPackSource, async_projection_unavailable};

impl OneNode {
    /// Publish a review only after exact-subject and actual-candidate validation.
    /// The session owns reviewer identity. Withdrawal needs no bundle and can
    /// retract its exact old vote after branches/policy/PR state have changed.
    pub async fn admit_candidate_review_durable_in(
        &self, request: &NodeRequestContext, session: &LoopbackReceiveSession,
        command: &CandidateReviewCommand, bundle: Option<&[u8]>, limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session.authenticated_session().ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let context = AdmissionContext { head_key: self.head_key.clone(), tenant_id: self.tenant_id,
            repository_id: self.repository_id, principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(), object_format: self.object_format };
        let map_error = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let (_, attempt) = reviews::candidate_proposal(&context, command).map_err(map_error)?;
        let tx_id = attempt.derive().map_err(|_| map_error(AdmissionError::AsyncProjectionUnavailable(RefusalCode::CanonicalFramingInvalid)))?.0;
        // A historical result survives stopped service, exhausted quota and
        // missing local bundle files. Confirm the same seal/key before return.
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority, request.authority(), &self.head_key, self.tenant_id, self.repository_id, tx_id,
        ).await.map_err(|error| map_error(error.into()))? {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await.map_err(|error| map_error(error.into()))?;
            return Ok((tx_id, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let owner = ReviewOwner { inner: NodeNativeMergeProjection {
            node: self, inner: self.durable_admission_projection(&context).map_err(map_error)?,
            object_limits: MergeObjectLimits::default(), workspace: None, workspace_capability: None, workspace_clock_floor: 0,
        }, request, bundle };
        let terminal = reviews::admit_candidate_review_async(&self.authority, request.authority(),
            &context, command, limits, &owner).await.map_err(map_error)?;
        Ok((tx_id, terminal))
    }

    /// Latest reviewer decisions at one authenticated current head. Continuations
    /// require its exact identity. No approval count is derived from partial pages.
    pub async fn read_reviews_in(
        &self, request: &NodeRequestContext, visibility: &RefVisibility, number: PullRequestNumber,
        after: Option<PrincipalId>, limit: u16, expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<Option<ReviewPage>, ReviewReadRefusal> {
        if limit == 0 || limit > 100 { return Err(ReviewReadRefusal::InvalidLimit); }
        if after.is_some() && expected_head.is_none() { return Err(ReviewReadRefusal::UnpinnedContinuation); }
        admits_read(self.cell_state(), ReadMode::Current).map_err(|error| ReviewReadRefusal::Read(error.to_string()))?;
        let selected = self.materialize_admission_in(request).await.map_err(|error| ReviewReadRefusal::Read(error.to_string()))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) { return Err(ReviewReadRefusal::SnapshotMoved); }
        let visible = |source: &fgit_types::RefName, target: &fgit_types::RefName| {
            [source, target].iter().all(|name| !visibility.hides(name.as_bytes())
                && !selected.snapshot().hidden_refs.hides(name.as_bytes()))
        };
        reviews::read_page_at(&self.authority, request.authority(), selected.basis(), number,
            &selected.snapshot().refs, after, limit, &visible, &|| !workspace_request_live(request))
            .await.map_err(|error| ReviewReadRefusal::Admission(Box::new(error)))
    }

    /// Explicit review-gated publication. Requirements are sealed with the exact
    /// candidate, and checked by the SAME native CAS driver on every replan.
    /// This API does not replace repository-wide ref-protection administration.
    pub async fn apply_reviewed_merge_bundle_durable_in(
        &self, request: &NodeRequestContext, principal: PrincipalId, key_bytes: &[u8],
        number: PullRequestNumber, version: ExpectedVersion, merge: &NativeMerge, input: &[u8],
        policy_epoch: PolicyEpoch, required_reviewers: &[PrincipalId],
    ) -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal> {
        let map_error = |error| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(error)));
        if required_reviewers.len() > gate::MAX_REQUIRED_REVIEWERS {
            return Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate("too many required reviewers"));
        }
        let required = ReviewRequirements::new(policy_epoch, required_reviewers.to_vec()).map_err(map_error)?;
        let context = AdmissionContext { head_key: self.head_key.clone(), tenant_id: self.tenant_id,
            repository_id: self.repository_id, principal_id: principal,
            idempotency_key: IdempotencyKey::new(key_bytes.to_vec())
                .map_err(|_| NodeWorkspaceRefusal::InvalidWorkspaceCandidate("invalid bounded idempotency key"))?,
            object_format: self.object_format };
        let intent = NativeMergeIntent::new(number, version, merge.clone()).map_err(map_error)?;
        let attempt = gate::reviewed_seal_attempt(&context, &intent, &required).map_err(map_error)?;
        let tx_id = attempt.derive().map_err(|_| NodeWorkspaceRefusal::InvalidWorkspaceCandidate("reviewed merge seal refused"))?.0;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority, request.authority(), &self.head_key, self.tenant_id, self.repository_id, tx_id,
        ).await.map_err(|error| map_error(error.into()))? {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await.map_err(|error| map_error(error.into()))?;
            return Ok((tx_id, terminal));
        }
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota.evaluate(&principal).map_err(receive_error)?;
        let (quarantine, _) = self.quarantine_reviewed_bundle_in(request, &merge.target_ref,
            merge.target_tip_before, merge.merge_commit, input, std::slice::from_ref(&merge.source_ref)).await?;
        // Stage native bytes through production quarantine; NEVER admit its
        // ref-only request instead of the review-gated coupled transaction.
        drop(quarantine);
        if !workspace_request_live(request) { return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None }); }
        let projection = NodeNativeMergeProjection { node: self,
            inner: self.durable_admission_projection(&context).map_err(map_error)?,
            object_limits: MergeObjectLimits::default(), workspace: None, workspace_capability: None, workspace_clock_floor: 0 };
        let terminal = gate::admit_reviewed_merge_async(&self.authority, request.authority(), &context,
            &intent, &required, AdmissionLimits::default(), &projection).await.map_err(map_error)?;
        Ok((tx_id, terminal))
    }
}

#[derive(Debug)]
pub enum ReviewReadRefusal {
    InvalidLimit, UnpinnedContinuation, SnapshotMoved,
    Read(String), Admission(Box<AdmissionError>),
}
impl std::fmt::Display for ReviewReadRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(out, "review read refused: {self:?}") }
}
impl std::error::Error for ReviewReadRefusal {}

struct ReviewOwner<'a> {
    inner: NodeNativeMergeProjection<'a>, request: &'a NodeRequestContext, bundle: Option<&'a [u8]>,
}
impl AsyncAdmissionProjection<FsqliteAuthorityStore> for ReviewOwner<'_> {
    fn snapshot_async<'a>(&'a self, store: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, head: &'a AuthenticatedHead)
        -> impl Future<Output=Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        self.inner.snapshot_async(store, cx, basis, head)
    }
    fn materialize_commit_async<'a>(&'a self, store: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, request: &'a TransactionRequest, fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure) -> impl Future<Output=Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner.materialize_commit_async(store, cx, basis, request, fold, closure)
    }
    fn materialize_refusal_async<'a>(&'a self, store: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, tx: TxId, code: RefusalCode)
        -> impl Future<Output=Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner.materialize_refusal_async(store, cx, basis, tx, code)
    }
}
impl NativeMergeProjection<FsqliteAuthorityStore> for ReviewOwner<'_> {
    fn merge_checkpoint(&self, cx: &Cx) -> Result<(), RefusalCode> { self.inner.merge_checkpoint(cx) }
    fn merge_publication_checkpoint(&self, cx: &Cx) -> Result<(), RefusalCode> { self.inner.merge_publication_checkpoint(cx) }
    fn resolve_merge_basis_async<'a>(&'a self, store: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, head: &'a AuthenticatedHead)
        -> impl Future<Output=Result<NativeMergeBasis, ProjectionFailure>> + Send + 'a {
        self.inner.resolve_merge_basis_async(store, cx, basis, head)
    }
    fn validate_merge_async<'a>(&'a self, store: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, head: &'a AuthenticatedHead, intent: &'a NativeMergeIntent)
        -> impl Future<Output=Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        self.inner.validate_merge_async(store, cx, basis, head, intent)
    }
}
impl ReviewProjection<FsqliteAuthorityStore> for ReviewOwner<'_> {
    fn validate_review_async<'a>(&'a self, store: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, head: &'a AuthenticatedHead, command: &'a ReviewCommand,
        candidate: Option<CandidateBinding>) -> impl Future<Output=Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        async move {
            self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
            let selected = self.inner.inner.materializer.materialize_exact_in(store, cx,
                self.inner.node.repository_id, basis, head, &|| self.merge_checkpoint(cx).is_err())
                .await.map_err(async_projection_unavailable)?;
            let closure = selected.selected_closure().closure();
            if closure.objects().len() > self.inner.object_limits.max_objects {
                return Err(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded));
            }
            for tip in [command.subject.source_tip, command.subject.target_tip] {
                if !closure.objects().contains(&tip) { return Err(ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete)); }
            }
            // No database-bound source or Cell borrow spans the inspection await.
            if command.decision != ReviewDecision::Withdraw {
                {
                    let exhaustion = Cell::new(None);
                    let source = VerifiedFabricPackSource { fabric: &self.inner.node.fabric,
                        object_format: self.inner.node.object_format,
                        maximum_object_bytes: self.inner.object_limits.max_object_bytes.min(
                            usize::try_from(self.inner.node.max_object_bytes).unwrap_or(usize::MAX)),
                        database_context: cx, database_exhaustion: &exhaustion, session_is_live: None };
                    for tip in [command.subject.source_tip, command.subject.target_tip] {
                        let value = source.read_object(&tip);
                        self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
                        if exhaustion.get().is_some() { return Err(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)); }
                        let (kind, bytes) = value.map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
                        if kind != ObjectType::Commit { return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)); }
                        let ParsedObject::Commit(commit) = parse_object_body(kind, &bytes,
                            AcceptanceProfile::GitCompatibleImport, &source.parse_limits())
                            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?
                        else { return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)); };
                        let tree = commit.tree_reference().and_then(|value| std::str::from_utf8(value).ok())
                            .and_then(|value| GitOid::from_hex(self.inner.node.object_format, &value.to_ascii_lowercase()).ok())
                            .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
                        if !closure.objects().contains(&tree) { return Err(ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete)); }
                    }
                }
                if let Some(binding) = candidate {
                    let input = self.bundle.ok_or(ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
                    let options = ReviewOptions { mode: ComparisonMode::Direct, ..ReviewOptions::default() };
                    let result = self.inner.node.inspect_merge_bundle_in(self.request, &binding.merge(&command.subject),
                        input, &RefVisibility::new(), Some(basis.id()), &options).await;
                    self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
                    use super::super::publication::BundleInspectionRefusal as E;
                    result.map_err(|error| match error {
                        E::Validation(failure) => failure,
                        E::SnapshotMoved | E::ParentMoved => ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale),
                        E::InvalidCandidate(_) | E::Pack(_) | E::Envelope(_) => ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid),
                        E::BudgetExceeded => ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded),
                        _ => ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid),
                    })?;
                }
            }
            self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
            Ok(ValidatedClosure { object_closure_root: fgit_admission::permitted_object_closure_root(closure)
                .map_err(ProjectionFailure::Unavailable)?, objects: closure.objects().clone() })
        }
    }
}

#[cfg(test)]
#[path = "review_tests.rs"]
mod tests;
