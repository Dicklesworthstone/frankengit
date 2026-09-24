//! Publish verified local observations through the existing canonical forge path.
//! The authenticated principal REPORTS a result; it is not a sandbox attestation
//! and cannot satisfy a required successful check. No journal is acknowledged here.
use std::cell::Cell;
use std::future::Future;

use fgit_admission::merge::native::objects::MergeObjectLimits;
use fgit_admission::merge::native::{NativeMergeProjection, workflow_checks};
use fgit_admission::{
    AdmissionContext, AdmissionError, AdmissionLimits, ProjectionFailure, ValidatedClosure,
};
use fgit_authority::{AuthenticatedHead, OutcomeLookup, TerminalOutcome};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_forge::event::workflow_check::{
    MAX_CHECK_EVIDENCE_BYTES, WorkflowCheckConclusion, WorkflowCheckRecord,
};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParsedObject, parse_object_body};
use fgit_runner::Commitment;
use fgit_runner::coordinator::delivery::CheckDeliveryBatch;
use fgit_runner::coordinator::delivery::journal::history::{
    decode_trusted_observation, verify_trusted_job,
};
use fgit_runner::workflow::JobOutcome;
use fgit_types::{GitOid, RefName, RefusalCode, RepositoryId, TenantId, TxId};
use fsqlite_types::cx::Cx;

use crate::treefs_workspace::native_merge::NodeNativeMergeProjection;
use crate::{
    LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode,
    VerifiedFabricPackSource,
};

impl OneNode {
    /// Lower one verified, completed local proposal to the existing native event
    /// profile. This does no I/O and grants no publication capability. The branch
    /// is the reporting subject: admission requires its current tip to match the
    /// evidence's executed native commit. It need not be the original run's ref.
    pub fn workflow_check_record_from_batch(
        source_ref: RefName,
        batch: &CheckDeliveryBatch,
        fact_index: usize,
        evidence: &[u8],
        live: &dyn Fn() -> bool,
    ) -> Result<WorkflowCheckRecord, NodeReceiveTransportRefusal> {
        if !live() {
            return Err(invalid(RefusalCode::CancellationInProgress));
        }
        let observed =
            verify_trusted_job(batch, fact_index, evidence, MAX_CHECK_EVIDENCE_BYTES, live)
                .map_err(|_| {
                    invalid(if live() {
                        RefusalCode::EvidenceInvalid
                    } else {
                        RefusalCode::CancellationInProgress
                    })
                })?;
        let job = &observed.report().jobs[0];
        let record = WorkflowCheckRecord {
            source_ref,
            source_commit: observed.source_commit(),
            run_id: bytes32(observed.run_id().commitment()).map_err(invalid)?,
            attempt_id: bytes32(observed.attempt_id().commitment()).map_err(invalid)?,
            graph_root: bytes32(observed.report().graph).map_err(invalid)?,
            job: job.id.clone(),
            conclusion: conclusion(job.outcome),
            evidence: evidence.to_vec(),
        };
        record
            .validate()
            .map_err(|_| invalid(RefusalCode::EvidenceInvalid))?;
        if !live() {
            return Err(invalid(RefusalCode::CancellationInProgress));
        }
        Ok(record)
    }

    /// Record one authenticated local publisher's immutable job observation and
    /// enqueue its forge delivery in the SAME repository transaction. Exact bytes
    /// enter the original seal; no ref is changed and no green check is granted.
    ///
    /// A historical terminal outcome is resolved before current source/policy
    /// checks. New decisions validate typed evidence and its exact run, attempt,
    /// job, graph, native source and repository against the selected authority
    /// basis. The current branch must exist, be visible and still name that commit.
    /// This local authenticated-session API is not an untrusted CI/HTTP endpoint.
    /// No workflow is executed, journal consumed, or downstream receipt fabricated.
    pub async fn admit_trusted_workflow_check_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        record: &WorkflowCheckRecord,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let map = |e| NodeReceiveTransportRefusal::Admission(Box::new(e));
        let (_, attempt) = workflow_checks::proposal(&context, record).map_err(map)?;
        let tx = attempt
            .derive()
            .map_err(|_| invalid(RefusalCode::EvidenceInvalid))?
            .0;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            self.tenant_id,
            self.repository_id,
            tx,
        )
        .await
        .map_err(|e| map(e.into()))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|e| map(e.into()))?;
            return Ok((tx, terminal));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&authenticated.principal_id())?;
        let projection = NodeNativeMergeProjection {
            node: self,
            inner: self.durable_admission_projection(&context).map_err(map)?,
            object_limits: MergeObjectLimits::default(),
            workspace: None,
            workspace_capability: None,
            workspace_clock_floor: 0,
        };
        let terminal = workflow_checks::admit_async(
            &self.authority,
            request.authority(),
            &context,
            record,
            limits,
            &projection,
        )
        .await
        .map_err(map)?;
        Ok((tx, terminal))
    }
}

impl workflow_checks::WorkflowCheckProjection<FsqliteAuthorityStore>
    for NodeNativeMergeProjection<'_>
{
    fn validate_workflow_check_async<'a>(
        &'a self,
        store: &'a FsqliteAuthorityStore,
        cx: &'a Cx,
        basis: &'a PublicationBasis,
        authenticated: &'a AuthenticatedHead,
        record: &'a WorkflowCheckRecord,
    ) -> impl Future<Output = Result<ValidatedClosure, ProjectionFailure>> + Send + 'a {
        async move {
            self.merge_checkpoint(cx)
                .map_err(ProjectionFailure::Unavailable)?;
            // A correct hash alone is not a matching observation. Use the one
            // bounded runner decoder, then match every submitted semantic field.
            validate_record(
                record,
                self.node.tenant_id,
                self.node.repository_id,
                &|| self.merge_checkpoint(cx).is_ok(),
            )
            .map_err(|code| {
                self.merge_checkpoint(cx).err().map_or(
                    ProjectionFailure::Refuse(code),
                    ProjectionFailure::Unavailable,
                )
            })?;
            let materialized = self
                .inner
                .materializer
                .materialize_exact_in(
                    store,
                    cx,
                    self.node.repository_id,
                    basis,
                    authenticated,
                    &|| self.merge_checkpoint(cx).is_err(),
                )
                .await
                .map_err(crate::async_projection_unavailable)?;
            // The exact materializer selects `basis`; a different basis means the
            // authenticated receipt and the publication basis no longer agree.
            if materialized.basis() != basis {
                return Err(ProjectionFailure::Unavailable(
                    RefusalCode::AuthorityReceiptStale,
                ));
            }
            if materialized.snapshot().refs.get(&record.source_ref) != Some(&record.source_commit) {
                return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved));
            }
            if record.source_commit.algorithm() != self.node.object_format {
                return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
            }
            let closure = materialized.selected_closure().closure();
            if closure.objects().len() > self.object_limits.max_objects {
                return Err(ProjectionFailure::Unavailable(
                    RefusalCode::ResourceBudgetExceeded,
                ));
            }
            if !closure.objects().contains(&record.source_commit) {
                return Err(ProjectionFailure::Refuse(
                    RefusalCode::ObjectClosureIncomplete,
                ));
            }
            let exhaustion = Cell::new(None);
            let source = VerifiedFabricPackSource {
                fabric: &self.node.fabric,
                object_format: self.node.object_format,
                maximum_object_bytes: self
                    .object_limits
                    .max_object_bytes
                    .min(usize::try_from(self.node.max_object_bytes).unwrap_or(usize::MAX)),
                database_context: cx,
                database_exhaustion: &exhaustion,
                session_is_live: None,
            };
            let result = source.read_object(&record.source_commit);
            self.merge_checkpoint(cx)
                .map_err(ProjectionFailure::Unavailable)?;
            if exhaustion.get().is_some() {
                return Err(ProjectionFailure::Unavailable(
                    RefusalCode::ResourceBudgetExceeded,
                ));
            }
            let (kind, body) =
                result.map_err(|_| ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing))?;
            if kind != ObjectType::Commit {
                return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
            }
            let ParsedObject::Commit(commit) = parse_object_body(
                kind,
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &source.parse_limits(),
            )
            .map_err(|_| ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?
            else {
                return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
            };
            let tree = commit
                .tree_reference()
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| {
                    GitOid::from_hex(self.node.object_format, &value.to_ascii_lowercase()).ok()
                })
                .ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid))?;
            if !closure.objects().contains(&tree) {
                return Err(ProjectionFailure::Refuse(
                    RefusalCode::ObjectClosureIncomplete,
                ));
            }
            self.merge_checkpoint(cx)
                .map_err(ProjectionFailure::Unavailable)?;
            Ok(ValidatedClosure {
                object_closure_root: fgit_admission::permitted_object_closure_root(closure)
                    .map_err(ProjectionFailure::Unavailable)?,
                objects: closure.objects().clone(),
            })
        }
    }
}

fn validate_record(
    record: &WorkflowCheckRecord,
    tenant: TenantId,
    repository: RepositoryId,
    live: &dyn Fn() -> bool,
) -> Result<(), RefusalCode> {
    record
        .validate()
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    // This digest establishes integrity only. The authenticated publisher owns
    // the statement; the decoded frame is never evidence of producer authority.
    let observed = decode_trusted_observation(
        &record.evidence,
        Commitment::of_bytes(&record.evidence),
        MAX_CHECK_EVIDENCE_BYTES,
        live,
    )
    .map_err(|_| RefusalCode::EvidenceInvalid)?;
    let report = observed.report();
    if observed.tenant() != tenant
        || observed.repository() != repository
        || observed.source_commit() != record.source_commit
        || bytes32(observed.run_id().commitment())? != record.run_id
        || bytes32(observed.attempt_id().commitment())? != record.attempt_id
        || bytes32(report.graph)? != record.graph_root
        || report.jobs.len() != 1
        || report.jobs[0].id != record.job
        || conclusion(report.jobs[0].outcome) != record.conclusion
    {
        return Err(RefusalCode::EvidenceInvalid);
    }
    Ok(())
}
fn bytes32(value: Commitment) -> Result<[u8; 32], RefusalCode> {
    value
        .digest()
        .bytes()
        .as_bytes()
        .try_into()
        .map_err(|_| RefusalCode::EvidenceInvalid)
}
const fn conclusion(value: JobOutcome) -> WorkflowCheckConclusion {
    match value {
        JobOutcome::Succeeded | JobOutcome::Skipped => WorkflowCheckConclusion::ActionRequired,
        JobOutcome::Failed | JobOutcome::Refused | JobOutcome::OutputLimit => {
            WorkflowCheckConclusion::Failure
        }
        JobOutcome::Cancelled => WorkflowCheckConclusion::Cancelled,
        JobOutcome::TimedOut => WorkflowCheckConclusion::TimedOut,
    }
}
fn invalid(code: RefusalCode) -> NodeReceiveTransportRefusal {
    NodeReceiveTransportRefusal::Admission(Box::new(AdmissionError::AsyncProjectionUnavailable(
        code,
    )))
}

#[cfg(test)]
mod tests;
