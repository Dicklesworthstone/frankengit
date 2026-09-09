//! Native PR lifecycle on the real embedded authority. No PR database or
//! caller-minted object proof is introduced. Both code and metadata mutations
//! use the node's existing exact-basis projection and verified object fabric.

use std::cell::Cell;
use std::future::Future;

use fgit_admission::merge::native::objects::MergeObjectLimits;
use fgit_admission::merge::native::pull_request::{self, PullRequestPage, PullRequestProjection};
use fgit_admission::merge::native::NativeMergeProjection;
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits, ProjectionFailure, ValidatedClosure};
use fgit_authority::{AuthenticatedHead, OutcomeLookup, TerminalOutcome};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_forge::event::pull_request::PullRequestCommand;
use fgit_git_object::{AcceptanceProfile, ObjectType, ParsedObject, parse_object_body};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{GitOid, RefusalCode, RepositoryAuthorityHeadId, TxId};
use fgit_wire::visibility::RefVisibility;
use fsqlite_types::cx::Cx;

use super::native_merge::NodeNativeMergeProjection;
use crate::{AdmissionMaterializationRefusal, LoopbackReceiveSession, NodeReceiveTransportRefusal,
    NodeRequestContext, OneNode, VerifiedFabricPackSource, async_projection_unavailable};

impl OneNode {
    /// Publish an exact-version native PR command and delivery obligation in
    /// one canonical transaction. The local authentication boundary supplies
    /// the principal; this method does not infer it from repository text.
    /// Opening/updating compares both current branch tips. Closing preserves
    /// the recorded data and remains possible after a branch was deleted.
    /// No command here changes a Git ref or introduces a native Git object.
    pub async fn admit_pull_request_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &PullRequestCommand,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session.authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(), tenant_id: self.tenant_id,
            repository_id: self.repository_id, principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let map_error = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let (_, attempt) = pull_request::proposal(&context, command).map_err(map_error)?;
        let tx_id = attempt.derive().map_err(|_| map_error(
            AdmissionError::AsyncProjectionUnavailable(RefusalCode::CanonicalFramingInvalid),
        ))?.0;
        // Recover the exact immutable request before applying gates for new
        // publication. A stopped cell or exhausted push quota cannot erase an
        // authenticated terminal outcome. Preserve the core seal/key check.
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority, request.authority(), &self.head_key,
            self.tenant_id, self.repository_id, tx_id,
        ).await.map_err(|error| map_error(error.into()))? {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await.map_err(|error| map_error(error.into()))?;
            return Ok((tx_id, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection = NodeNativeMergeProjection {
            node: self, inner: self.durable_admission_projection(&context).map_err(map_error)?,
            object_limits: MergeObjectLimits::default(),
            workspace: None, workspace_capability: None, workspace_clock_floor: 0,
        };
        let terminal = pull_request::admit_pull_request_async(
            &self.authority, request.authority(), &context, command, limits, &projection,
        ).await.map_err(map_error)?;
        // Cancellation after this point cannot erase an authenticated result.
        Ok((tx_id, terminal))
    }

    /// Read native PRs and explicit merge-only receipts at one authenticated
    /// head. Caller visibility can only narrow canonical hidden-ref policy.
    /// A supplied head must equal the selected snapshot before any row returns;
    /// use the first page's head for every continuation. This is a local read
    /// boundary, not a remote credential verifier or historical-policy bypass.
    pub async fn read_pull_requests_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
        after: u64,
        limit: u16,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<PullRequestPage, PullRequestReadRefusal> {
        if limit == 0 || limit > 100 { return Err(PullRequestReadRefusal::InvalidLimit); }
        admits_read(self.cell_state(), ReadMode::Current).map_err(PullRequestReadRefusal::Cell)?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|error| PullRequestReadRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(PullRequestReadRefusal::SnapshotMoved);
        }
        let visible = |source: &fgit_types::RefName, target: &fgit_types::RefName| {
            [source, target].iter().all(|reference|
                !visibility.hides(reference.as_bytes())
                && !selected.snapshot().hidden_refs.hides(reference.as_bytes()))
        };
        pull_request::read_page_at(
            &self.authority, request.authority(), selected.basis(), after, limit,
            &visible, &|| !super::workspace_request_live(request),
        ).await.map_err(|error| PullRequestReadRefusal::Admission(Box::new(error)))
    }
}

#[derive(Debug)]
pub enum PullRequestReadRefusal {
    InvalidLimit,
    SnapshotMoved,
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    Admission(Box<AdmissionError>),
}
impl std::fmt::Display for PullRequestReadRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native pull-request read refused: {self:?}")
    }
}
impl std::error::Error for PullRequestReadRefusal {}

impl PullRequestProjection<FsqliteAuthorityStore> for NodeNativeMergeProjection<'_> {
    #[expect(clippy::manual_async_fn, reason = "explicit Send is the native projection contract")]
    fn validate_pull_request_async<'a>(
        &'a self, authority: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, authenticated: &'a AuthenticatedHead,
        command: &'a PullRequestCommand,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        async move {
            self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
            let selected = self.inner.materializer.materialize_exact_in(
                authority, cx, self.node.repository_id, basis, authenticated,
                &|| self.merge_checkpoint(cx).is_err(),
            ).await.map_err(async_projection_unavailable)?;
            let closure = selected.selected_closure().closure();
            if closure.objects().len() > self.object_limits.max_objects {
                return Err(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded));
            }
            let exhaustion = Cell::new(None);
            let source = VerifiedFabricPackSource {
                fabric: &self.node.fabric, object_format: self.node.object_format,
                maximum_object_bytes: self.object_limits.max_object_bytes
                    .min(usize::try_from(self.node.max_object_bytes).unwrap_or(usize::MAX)),
                database_context: cx, database_exhaustion: &exhaustion, session_is_live: None,
            };
            for tip in [command.data.source_tip, command.data.target_tip] {
                self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
                if tip.is_zero() || tip.algorithm() != self.node.object_format {
                    return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
                }
                if !closure.objects().contains(&tip) {
                    return Err(ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete));
                }
                let result = source.read_object(&tip);
                self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
                if exhaustion.get().is_some() {
                    return Err(ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded));
                }
                let (kind, body) = result.map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
                if kind != ObjectType::Commit { return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)); }
                let ParsedObject::Commit(commit) = parse_object_body(kind, &body,
                    AcceptanceProfile::GitCompatibleImport, &source.parse_limits())
                    .map_err(|_| ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?
                else { return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)); };
                let tree = commit.tree_reference().and_then(|value| std::str::from_utf8(value).ok())
                    .and_then(|value| GitOid::from_hex(self.node.object_format, &value.to_ascii_lowercase()).ok())
                    .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
                if !closure.objects().contains(&tree) {
                    return Err(ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete));
                }
            }
            self.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;
            Ok(ValidatedClosure {
                object_closure_root: fgit_admission::permitted_object_closure_root(closure)
                    .map_err(ProjectionFailure::Unavailable)?,
                objects: closure.objects().clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests;
