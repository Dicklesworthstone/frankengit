//! Durable repository issues on the node's real authority. Local authenticated
//! commands share metadata publication with PRs; reads never trust a cache.
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_admission::merge::native::{issues, objects::MergeObjectLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::{IssueNumber, event::issue::IssueCommand};
use fgit_types::{RefusalCode, RepositoryAuthorityHeadId, TxId};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use crate::{AdmissionMaterializationRefusal, LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use super::native_merge::NodeNativeMergeProjection;

impl OneNode {
    /// Publish a versioned issue command plus its existing outbox obligation.
    /// The session's principal is authenticated by the trusted local boundary;
    /// issue text does not supply identity, authorization or executable code.
    pub async fn admit_issue_durable_in(&self, request: &NodeRequestContext,
        session: &LoopbackReceiveSession, command: &IssueCommand, limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session.authenticated_session().ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let context = AdmissionContext { head_key: self.head_key.clone(), tenant_id: self.tenant_id,
            repository_id: self.repository_id, principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(), object_format: self.object_format };
        let error = |source| NodeReceiveTransportRefusal::Admission(Box::new(source));
        let (_, attempt) = issues::proposal(&context, command).map_err(error)?;
        let tx = attempt.derive().map_err(|_| error(AdmissionError::AsyncProjectionUnavailable(RefusalCode::CanonicalFramingInvalid)))?.0;
        // A canonical historical result precedes new-publication intake/quota.
        // Recheck the complete immutable seal/key, never just a key's presence.
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority, request.authority(), &self.head_key, self.tenant_id, self.repository_id, tx,
        ).await.map_err(|source| error(source.into()))? {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await.map_err(|source| error(source.into()))?;
            return Ok((tx, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection = NodeNativeMergeProjection { node: self,
            inner: self.durable_admission_projection(&context).map_err(error)?,
            object_limits: MergeObjectLimits::default(), workspace: None,
            workspace_capability: None, workspace_clock_floor: 0 };
        let terminal = issues::admit_issue_async(&self.authority, request.authority(), &context,
            command, limits, &projection).await.map_err(error)?;
        Ok((tx, terminal))
    }

    /// Repository-local canonical metadata read. Git hidden-ref policies are
    /// not an issue ACL; a future remote adapter must authenticate repository
    /// metadata access before calling this local-operator surface.
    pub async fn read_issues_in(&self, request: &NodeRequestContext, after: u64,
        limit: u16, expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<issues::IssuePage, IssueReadRefusal> {
        validate_page(after, limit, expected_head)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(IssueReadRefusal::Cell)?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|source| IssueReadRefusal::Authority(Box::new(source)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) { return Err(IssueReadRefusal::SnapshotMoved); }
        issues::read_page_at(&self.authority, request.authority(), selected.basis(), after, limit,
            &|| !super::workspace_request_live(request)).await.map_err(|source| IssueReadRefusal::Admission(Box::new(source)))
    }

    pub async fn read_issue_history_in(&self, request: &NodeRequestContext, number: IssueNumber,
        after_version: u64, limit: u16, expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<issues::IssueHistoryPage, IssueReadRefusal> {
        validate_page(after_version, limit, expected_head)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(IssueReadRefusal::Cell)?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|source| IssueReadRefusal::Authority(Box::new(source)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) { return Err(IssueReadRefusal::SnapshotMoved); }
        issues::read_history_at(&self.authority, request.authority(), selected.basis(), number,
            after_version, limit, &|| !super::workspace_request_live(request)).await
            .map_err(|source| IssueReadRefusal::Admission(Box::new(source)))
    }
}
fn validate_page(after: u64, limit: u16, expected: Option<RepositoryAuthorityHeadId>) -> Result<(), IssueReadRefusal> {
    if limit == 0 || limit > 100 { return Err(IssueReadRefusal::InvalidLimit); }
    if after != 0 && expected.is_none() { return Err(IssueReadRefusal::SnapshotRequired); }
    Ok(())
}
#[derive(Debug)]
pub enum IssueReadRefusal {
    InvalidLimit,
    SnapshotRequired,
    SnapshotMoved,
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    Admission(Box<AdmissionError>),
}
impl std::fmt::Display for IssueReadRefusal {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(output, "native issue read refused: {self:?}") }
}
impl std::error::Error for IssueReadRefusal {}
#[cfg(test)]
mod tests;
