//! Trusted-local default-branch administration through the ordinary decision
//! stream. HEAD stays in canonical ref state; no transport-local default or
//! fake Git object identity represents its symbolic target.

use std::cell::Cell;

use fgit_admission::default_branch::{self, DefaultBranchCommand};
use fgit_admission::evidence::AdmissionAuthentication;
use fgit_admission::merge::native::NativeMergeProjection;
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits, ProjectionFailure};
use fgit_authority::{AuthenticatedHead, OutcomeLookup, TerminalOutcome};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_git_object::{AcceptanceProfile, ObjectType, ParsedObject, parse_object_body};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{GitOid, RefName, RefusalCode, RepositoryAuthorityHeadId, TxId};
use fgit_wire::visibility::RefVisibility;

use super::NodeWorkspaceRefusal;
use super::native_merge::NodeNativeMergeProjection;
use crate::{
    FsqliteCx, LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode,
    PackContextCheckpoint, VerifiedFabricPackSource, async_projection_unavailable,
    checkpoint_pack_context,
};

fn admission_error(error: AdmissionError) -> NodeReceiveTransportRefusal {
    NodeReceiveTransportRefusal::Admission(Box::new(error))
}

fn checkpoint(request: &NodeRequestContext) -> Result<(), NodeWorkspaceRefusal> {
    match checkpoint_pack_context(request.authority()) {
        PackContextCheckpoint::Live => Ok(()),
        PackContextCheckpoint::Stopped { budget_exhaustion } => {
            Err(NodeWorkspaceRefusal::Cancelled {
                exhaustion: budget_exhaustion,
            })
        }
    }
}

impl OneNode {
    /// Read the exact optional symbolic HEAD and its direct tip at one
    /// authenticated current head. An unborn target has no tip; absence stays
    /// absent. Canonical and caller visibility both apply to HEAD and its
    /// target before either name or object ID is disclosed.
    pub async fn read_default_branch_in(
        &self,
        request: &NodeRequestContext,
        visibility: &RefVisibility,
    ) -> Result<(RepositoryAuthorityHeadId, Option<RefName>, Option<GitOid>), NodeWorkspaceRefusal>
    {
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        checkpoint(request)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        checkpoint(request)?;
        let snapshot = selected.snapshot();
        let hidden = |name: &[u8]| visibility.hides(name) || snapshot.hidden_refs.hides(name);
        if hidden(b"HEAD")
            || snapshot
                .head_target
                .as_ref()
                .is_some_and(|target| hidden(target.as_bytes()))
        {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let tip = snapshot
            .head_target
            .as_ref()
            .and_then(|target| snapshot.refs.get(target))
            .copied();
        Ok((selected.basis().id(), snapshot.head_target.clone(), tip))
    }

    /// Change only the canonical symbolic HEAD after an independently
    /// authorized local operator supplies the exact old target and a verified
    /// existing branch's expected tip. The embedding host authenticates and
    /// authorizes the local operator; a supplied principal is not remote
    /// authentication. HTTP, SSH, agent credentials and narrowed ref-write
    /// sessions do not gain repository administration through this method.
    ///
    /// Current administrator policy, hidden refs, expected values and native
    /// Commit identity are checked against every actual publication basis.
    /// Direct refs, Git objects and all unrelated roots remain unchanged.
    /// Exact terminal retries precede current policy, quota and target reads;
    /// an infrastructure error never establishes that the change did not commit.
    pub async fn admit_default_branch_trusted_local_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &DefaultBranchCommand,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        if authenticated.authentication() != AdmissionAuthentication::OperatorAssertion
            || authenticated.ref_write_scope.is_some()
        {
            return Err(admission_error(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::CapabilityScopeViolation,
            )));
        }
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let attempt = default_branch::proposal(&context, command).map_err(admission_error)?;
        let tx_id = attempt
            .derive()
            .map_err(|error| admission_error(error.into()))?
            .0;
        let projection = NodeNativeMergeProjection::metadata(self, &context, authenticated)
            .map_err(admission_error)?;
        projection
            .merge_checkpoint(request.authority())
            .map_err(|code| admission_error(AdmissionError::AsyncProjectionUnavailable(code)))?;
        if let OutcomeLookup::Decided(terminal) = self
            .resolve_outcome_checkpointed_in(request, tx_id)
            .await
            .map_err(|error| admission_error(error.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|error| admission_error(error.into()))?;
            return Ok((tx_id, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&context.principal_id)?;
        let terminal = Box::pin(default_branch::admit_async(
            &self.authority,
            request.authority(),
            &context,
            command,
            limits,
            &projection,
        ))
        .await
        .map_err(admission_error)?;
        Ok((tx_id, terminal))
    }
}

/// Revalidated native-object ownership for each CAS preparation. Merely
/// finding a body in the object store, or trusting its declared kind, cannot
/// establish a branch target. This helper receives the original request's
/// database context and never creates a replacement deadline or budget.
pub(super) async fn validate_target_at(
    projection: &NodeNativeMergeProjection<'_>,
    authority: &FsqliteAuthorityStore,
    cx: &FsqliteCx,
    basis: &PublicationBasis,
    authenticated: &AuthenticatedHead,
    target: &RefName,
    expected_tip: GitOid,
) -> Result<(), ProjectionFailure> {
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)?;
    let selected = projection
        .inner
        .materializer
        .materialize_exact_in(
            authority,
            cx,
            projection.node.repository_id,
            basis,
            authenticated,
            &|| projection.merge_checkpoint(cx).is_err(),
        )
        .await
        .map_err(async_projection_unavailable)?;
    let snapshot = selected.snapshot();
    if snapshot.hidden_refs.hides(b"HEAD") || snapshot.hidden_refs.hides(target.as_bytes()) {
        return Err(ProjectionFailure::Refuse(
            RefusalCode::HiddenRefUnauthorized,
        ));
    }
    if snapshot.refs.get(target) != Some(&expected_tip) {
        return Err(ProjectionFailure::Refuse(
            RefusalCode::ExpectedOldRefMismatch,
        ));
    }
    if !selected
        .selected_closure()
        .closure()
        .objects()
        .contains(&expected_tip)
    {
        return Err(ProjectionFailure::Unavailable(
            RefusalCode::ObjectClosureIncomplete,
        ));
    }
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)?;
    let exhaustion = Cell::new(None);
    let source = VerifiedFabricPackSource {
        fabric: &projection.node.fabric,
        object_format: projection.node.object_format,
        maximum_object_bytes: projection
            .object_limits
            .max_object_bytes
            .min(usize::try_from(projection.node.max_object_bytes).unwrap_or(usize::MAX)),
        database_context: cx,
        database_exhaustion: &exhaustion,
        session_is_live: None,
    };
    let object = source.read_object(&expected_tip);
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)?;
    if exhaustion.get().is_some() {
        return Err(ProjectionFailure::Unavailable(
            RefusalCode::ResourceBudgetExceeded,
        ));
    }
    let (kind, body) =
        object.map_err(|_| ProjectionFailure::Unavailable(RefusalCode::ObjectClosureIncomplete))?;
    if kind != ObjectType::Commit {
        return Err(ProjectionFailure::Refuse(
            RefusalCode::ObjectClosureIncomplete,
        ));
    }
    if !matches!(
        parse_object_body(
            kind,
            &body,
            AcceptanceProfile::GitCompatibleImport,
            &source.parse_limits()
        ),
        Ok(ParsedObject::Commit(_))
    ) {
        return Err(ProjectionFailure::Unavailable(
            RefusalCode::ObjectClosureIncomplete,
        ));
    }
    projection
        .merge_checkpoint(cx)
        .map_err(ProjectionFailure::Unavailable)
}
