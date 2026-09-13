//! Administrative activation and current reads on the repository authority.
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_admission::merge::native::{protection, objects::MergeObjectLimits};
use fgit_authority::{OutcomeLookup, TerminalOutcome};
use fgit_forge::event::protection::ProtectionCommand;
use fgit_types::{PolicyEpoch, RefusalCode, RepositoryAuthorityHeadId, TxId};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use crate::{AdmissionMaterializationRefusal, LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use super::native_merge::NodeNativeMergeProjection;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryProtectionView {
    pub source_head: RepositoryAuthorityHeadId,
    pub policy_epoch: PolicyEpoch,
    pub selected: Option<protection::SelectedProtection>,
}

impl OneNode {
    /// Bootstrap requires an authenticated trusted-local operator in the first
    /// administrator set. Later replacements require a current administrator,
    /// exact stream predecessor and exact policy epoch inside the CAS loop.
    /// Historical recovery remains available after removal of that administrator.
    pub async fn admit_repository_protection_durable_in(&self, request: &NodeRequestContext,
        session: &LoopbackReceiveSession, command: &ProtectionCommand, limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session.authenticated_session().ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let context = AdmissionContext { head_key: self.head_key.clone(), tenant_id: self.tenant_id,
            repository_id: self.repository_id, principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(), object_format: self.object_format };
        let error = |source| NodeReceiveTransportRefusal::Admission(Box::new(source));
        let (_, attempt) = protection::proposal(&context, command).map_err(error)?;
        let tx = attempt.derive().map_err(|_| error(AdmissionError::AsyncProjectionUnavailable(RefusalCode::CanonicalFramingInvalid)))?.0;
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
        let terminal = protection::admit_protection_async(&self.authority, request.authority(), &context,
            command, limits, &projection).await.map_err(error)?;
        Ok((tx, terminal))
    }

    /// Trusted-local repository metadata. No hidden-ref rule is repurposed as
    /// permission to administer or disclose policy to a remote principal.
    pub async fn read_repository_protection_in(&self, request: &NodeRequestContext,
        expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<RepositoryProtectionView, ProtectionReadRefusal> {
        admits_read(self.cell_state(), ReadMode::Current).map_err(ProtectionReadRefusal::Cell)?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|source| ProtectionReadRefusal::Authority(Box::new(source)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(ProtectionReadRefusal::SnapshotMoved);
        }
        let policy = protection::read_at(&self.authority, request.authority(), selected.basis(),
            &|| !super::workspace_request_live(request)).await
            .map_err(|source| ProtectionReadRefusal::Admission(Box::new(source)))?;
        Ok(RepositoryProtectionView { source_head: selected.basis().id(),
            policy_epoch: selected.basis().body().policy_epoch, selected: policy })
    }
}
#[derive(Debug)]
pub enum ProtectionReadRefusal {
    SnapshotMoved,
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    Admission(Box<AdmissionError>),
}
impl std::fmt::Display for ProtectionReadRefusal {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "repository protection read refused: {self:?}")
    }
}
impl std::error::Error for ProtectionReadRefusal {}
