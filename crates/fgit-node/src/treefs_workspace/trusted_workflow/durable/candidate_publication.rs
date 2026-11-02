//! Verified unpublished-candidate checks through the ordinary metadata seal and
//! authority-head CAS. A retained job observation never grants its own trust.

use std::future::Future;
use std::path::Path;

use fgit_admission::merge::NativeMergeBasis;
use fgit_admission::merge::native::objects::MergeObjectLimits;
use fgit_admission::merge::native::workflow_checks::candidate::{
    self, CandidateWorkflowCheckProjection,
};
use fgit_admission::merge::native::{NativeMergeIntent, NativeMergeProjection};
use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionLimits, AdmissionSnapshot, AsyncAdmissionProjection,
    CommitMaterialization, ProjectionFailure, RefusalMaterialization, ValidatedClosure,
};
use fgit_authority::{AuthenticatedHead, OutcomeLookup, TerminalOutcome};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_crypto::{Digest, DigestHasher, Sha256Hasher};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::event::workflow_check::WorkflowCheckId;
use fgit_forge::event::workflow_check::candidate::{
    CandidateWorkflowCheckRecord, NativeCandidateWorkflowCheck,
};
use fgit_reference::intent::TransactionRequest;
use fgit_runner::coordinator::delivery::CheckDeliveryBatch;
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{RefusalCode, RepositoryAuthorityHeadId, RepositoryId, TenantId, TxId};
use fgit_wire::visibility::RefVisibility;
use fsqlite_types::cx::Cx;

use crate::treefs_workspace::native_merge::NodeNativeMergeProjection;
use crate::treefs_workspace::workspace_request_live;
use crate::{
    LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, NodeWorkspaceRefusal,
    OneNode, TrustedWorkflowFailure, async_projection_unavailable,
};

const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;

fn invalid(code: RefusalCode) -> NodeReceiveTransportRefusal {
    NodeReceiveTransportRefusal::Admission(Box::new(AdmissionError::AsyncProjectionUnavailable(
        code,
    )))
}
fn context(
    node: &OneNode,
    session: &LoopbackReceiveSession,
) -> Result<AdmissionContext, NodeReceiveTransportRefusal> {
    let authenticated = session
        .authenticated_session()
        .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
    Ok(AdmissionContext {
        head_key: node.head_key.clone(),
        tenant_id: node.tenant_id,
        repository_id: node.repository_id,
        principal_id: authenticated.principal_id(),
        idempotency_key: authenticated.client_idempotency_key().clone(),
        object_format: node.object_format,
    })
}

impl OneNode {
    /// Build an explicit candidate profile from the same real retained job
    /// verifier as ordinary checks. The reporting ref is the original target
    /// anchor; it is not asserted to name the unpublished candidate.
    pub fn candidate_workflow_check_record_from_batch(
        subject: ReviewSubject,
        candidate: CandidateBinding,
        bundle_sha256: [u8; 32],
        batch: &CheckDeliveryBatch,
        fact_index: usize,
        evidence: &[u8],
        live: &dyn Fn() -> bool,
    ) -> Result<CandidateWorkflowCheckRecord, NodeReceiveTransportRefusal> {
        let check = Self::workflow_check_record_from_batch(
            subject.target_ref.clone(),
            batch,
            fact_index,
            evidence,
            live,
        )?;
        let record = CandidateWorkflowCheckRecord {
            subject,
            candidate,
            bundle_sha256,
            check,
        };
        record
            .validate()
            .map_err(|_| invalid(RefusalCode::EvidenceInvalid))?;
        Ok(record)
    }

    /// Select one exact completed job without needing report.json, running a
    /// command, acknowledging delivery, or reopening execution ownership.
    /// The independent bundle pin can survive loss of the local bundle file.
    pub fn trusted_candidate_workflow_check_record(
        directory: &Path,
        expected: (TenantId, RepositoryId, Digest),
        minimum: Option<(u64, Digest)>,
        batch: Digest,
        fact_index: usize,
        subject: ReviewSubject,
        candidate: CandidateBinding,
        bundle_sha256: [u8; 32],
        live: &dyn Fn() -> bool,
    ) -> Result<CandidateWorkflowCheckRecord, TrustedWorkflowFailure> {
        let check = Self::trusted_workflow_check_record(
            directory,
            expected,
            minimum,
            batch,
            fact_index,
            subject.target_ref.clone(),
            live,
        )?;
        let record = CandidateWorkflowCheckRecord {
            subject,
            candidate,
            bundle_sha256,
            check,
        };
        record.validate().map_err(|_| {
            TrustedWorkflowFailure::InvalidInput(
                "candidate workflow evidence does not match its exact subject",
            )
        })?;
        Ok(record)
    }

    /// Recover only an already-decided original request, before any fresh
    /// bundle access or current eligibility check. An undecided lookup creates
    /// no seal, event, refusal or candidate-object custody.
    pub async fn recover_trusted_candidate_workflow_check_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        record: &CandidateWorkflowCheckRecord,
    ) -> Result<Option<(TxId, TerminalOutcome)>, NodeReceiveTransportRefusal> {
        let context = context(self, session)?;
        let map = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let (_, attempt) = candidate::proposal(&context, record).map_err(map)?;
        let tx = attempt
            .derive()
            .map_err(|_| invalid(RefusalCode::EvidenceInvalid))?
            .0;
        match self
            .resolve_outcome_checkpointed_in(request, tx)
            .await
            .map_err(|error| map(error.into()))?
        {
            OutcomeLookup::Decided(terminal) => {
                fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                    .await
                    .map_err(|error| map(error.into()))?;
                Ok(Some((tx, terminal)))
            }
            OutcomeLookup::Undecided => Ok(None),
        }
    }

    /// Publish a verified exact-candidate job statement. The existing metadata
    /// owner seals, revalidates at each selected predecessor and publishes one
    /// observation plus outbox obligation. No ref or candidate object is staged.
    pub async fn admit_trusted_candidate_workflow_check_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        record: &CandidateWorkflowCheckRecord,
        bundle: &[u8],
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        if let Some(terminal) = self
            .recover_trusted_candidate_workflow_check_in(request, session, record)
            .await?
        {
            return Ok(terminal);
        }
        let context = context(self, session)?;
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let map = |error| NodeReceiveTransportRefusal::Admission(Box::new(error));
        let (_, attempt) = candidate::proposal(&context, record).map_err(map)?;
        let tx = attempt
            .derive()
            .map_err(|_| invalid(RefusalCode::EvidenceInvalid))?
            .0;
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection = CandidateCheckOwner {
            inner: NodeNativeMergeProjection {
                node: self,
                inner: self
                    .durable_admission_projection(&context)
                    .map_err(map)?
                    .with_authentication(authenticated.authentication()),
                object_limits: MergeObjectLimits::default(),
                staging: None,
                workspace: None,
                workspace_capability: None,
                workspace_clock_floor: 0,
            },
            request,
            bundle,
        };
        let terminal = Box::pin(candidate::admit_async(
            &self.authority,
            request.authority(),
            &context,
            record,
            limits,
            &projection,
        ))
        .await
        .map_err(map)?;
        Ok((tx, terminal))
    }

    /// Read one canonical candidate observation at the current selected head.
    /// The native serving caller owns execution-evidence disclosure permission;
    /// both original refs additionally obey current canonical/caller visibility.
    pub async fn read_candidate_workflow_check_in(
        &self,
        request: &NodeRequestContext,
        id: WorkflowCheckId,
        visibility: &RefVisibility,
    ) -> Result<
        Option<(RepositoryAuthorityHeadId, NativeCandidateWorkflowCheck)>,
        NodeWorkspaceRefusal,
    > {
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        let observation = candidate::read_at(
            &self.authority,
            request.authority(),
            selected.basis(),
            id,
            &|| !workspace_request_live(request),
        )
        .await
        .map_err(|error| {
            NodeWorkspaceRefusal::MergeValidation(
                error.into_projection_unavailable(RefusalCode::EvidenceInvalid),
            )
        })?;
        let Some(observation) = observation else {
            return Ok(None);
        };
        let subject = &observation.record.subject;
        if [&subject.source_ref, &subject.target_ref]
            .into_iter()
            .any(|reference| {
                visibility.hides(reference.as_bytes())
                    || selected.snapshot().hidden_refs.hides(reference.as_bytes())
            })
        {
            return Ok(None);
        }
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        Ok(Some((selected.basis().id(), observation)))
    }
}

struct CandidateCheckOwner<'a> {
    inner: NodeNativeMergeProjection<'a>,
    request: &'a NodeRequestContext,
    bundle: &'a [u8],
}
impl AsyncAdmissionProjection<FsqliteAuthorityStore> for CandidateCheckOwner<'_> {
    fn collect_cumulative_outcomes_async<'a>(
        &'a self,
        store: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        head_key: &'a fgit_authority::HeadKey,
        head: &'a AuthenticatedHead,
    ) -> impl Future<
        Output = Result<fgit_authority::CumulativeOutcomes, fgit_authority::OutcomeFailure>,
    > + Send
    + 'a {
        self.inner
            .collect_cumulative_outcomes_async(store, cx, head_key, head)
    }

    fn snapshot_async<'a>(
        &'a self,
        store: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        head: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<AdmissionSnapshot, ProjectionFailure>> + Send + 'a {
        self.inner.snapshot_async(store, cx, basis, head)
    }
    fn materialize_commit_async<'a>(
        &'a self,
        store: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        request: &'a TransactionRequest,
        fold: &'a fgit_txn::TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> impl Future<Output = Result<CommitMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_commit_async(store, cx, basis, request, fold, closure)
    }
    fn materialize_refusal_async<'a>(
        &'a self,
        store: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        tx: TxId,
        code: RefusalCode,
    ) -> impl Future<Output = Result<RefusalMaterialization, ProjectionFailure>> + Send + 'a {
        self.inner
            .materialize_refusal_async(store, cx, basis, tx, code)
    }
}
impl NativeMergeProjection<FsqliteAuthorityStore> for CandidateCheckOwner<'_> {
    fn admission_authentication(
        &self,
    ) -> Option<fgit_admission::evidence::AdmissionAuthentication> {
        self.inner.admission_authentication()
    }

    fn validate_squash_async<'a>(
        &'a self,
        store: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        head: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        self.inner
            .validate_squash_async(store, cx, basis, head, intent)
    }

    fn merge_checkpoint(&self, cx: &Cx) -> Result<(), RefusalCode> {
        self.inner.merge_checkpoint(cx)
    }
    fn merge_publication_checkpoint(&self, cx: &Cx) -> Result<(), RefusalCode> {
        self.inner.merge_publication_checkpoint(cx)
    }
    fn publish_merge_objects(&self, cx: &Cx) -> Result<(), RefusalCode> {
        self.inner.publish_merge_objects(cx)
    }
    fn resolve_merge_basis_async<'a>(
        &'a self,
        store: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        head: &'a AuthenticatedHead,
    ) -> impl Future<Output = Result<NativeMergeBasis, ProjectionFailure>> + Send + 'a {
        self.inner.resolve_merge_basis_async(store, cx, basis, head)
    }
    fn validate_merge_async<'a>(
        &'a self,
        store: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        head: &'a AuthenticatedHead,
        intent: &'a NativeMergeIntent,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        self.inner
            .validate_merge_async(store, cx, basis, head, intent)
    }
}

impl CandidateWorkflowCheckProjection<FsqliteAuthorityStore> for CandidateCheckOwner<'_> {
    async fn validate_candidate_workflow_check_async<'a>(
        &'a self,
        store: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        record: &'a CandidateWorkflowCheckRecord,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        record
            .validate()
            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
        super::publication::validate_record(
            &record.check,
            self.inner.node.tenant_id,
            self.inner.node.repository_id,
            &|| self.merge_checkpoint(cx).is_ok(),
        )
        .map_err(|code| {
            self.merge_checkpoint(cx).err().map_or(
                ProjectionFailure::Refuse(code),
                ProjectionFailure::Unavailable,
            )
        })?;
        if self.bundle.is_empty() || self.bundle.len() > MAX_BUNDLE_BYTES {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
        }
        let mut digest = Sha256Hasher::new();
        for bytes in self.bundle.chunks(16 * 1024) {
            self.merge_checkpoint(cx)
                .map_err(ProjectionFailure::Unavailable)?;
            digest.update(bytes);
        }
        if digest.finish() != record.bundle_sha256 {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
        }
        let selected = self
            .inner
            .inner
            .materializer
            .materialize_exact_in(
                store,
                cx,
                self.inner.node.repository_id,
                basis,
                authenticated,
                &|| self.merge_checkpoint(cx).is_err(),
            )
            .await
            .map_err(async_projection_unavailable)?;
        if selected.basis() != basis {
            return Err(ProjectionFailure::Unavailable(
                RefusalCode::AuthorityReceiptStale,
            ));
        }
        let subject = &record.subject;
        let closure = selected.selected_closure().closure();
        if [subject.source_tip, subject.target_tip]
            .iter()
            .any(|tip| !closure.objects().contains(tip))
        {
            return Err(ProjectionFailure::Refuse(
                RefusalCode::ObjectClosureIncomplete,
            ));
        }
        let result = self
            .inner
            .node
            .validate_merge_bundle_in(
                self.request,
                &record.candidate.merge(subject),
                self.bundle,
                &RefVisibility::new(),
                Some(basis.id()),
            )
            .await;
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        use crate::treefs_workspace::publication::BundleInspectionRefusal as E;
        result.map_err(|error| match error {
            E::Validation(failure) => failure,
            E::SnapshotMoved | E::ParentMoved => {
                ProjectionFailure::Unavailable(RefusalCode::AuthorityReceiptStale)
            }
            E::InvalidCandidate(_) | E::Pack(_) | E::Envelope(_) => {
                ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)
            }
            E::BudgetExceeded => {
                ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
            }
            _ => ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid),
        })?;
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        crate::named_object_closure(closure, &[subject.source_tip, subject.target_tip])
    }
}
