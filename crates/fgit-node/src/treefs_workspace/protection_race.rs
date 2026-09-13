//! A real policy publication between native validation and the losing merge CAS.
use super::*;
use fgit_admission::{AsyncAdmissionProjection, AdmissionContext, AdmissionSnapshot, CommitMaterialization,
    ProjectionFailure, RefusalMaterialization, ValidatedClosure};
use fgit_admission::merge::native::{NativeMergeIntent, NativeMergeProjection, admit_native_merge_async};
use fgit_authority::AuthenticatedHead;
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_reference::intent::TransactionRequest;
use fgit_txn::TransactionFoldReport;
use fsqlite_types::cx::Cx;
use crate::treefs_workspace::native_merge::NodeNativeMergeProjection;
use std::sync::atomic::{AtomicUsize, Ordering};

struct ActivateDuringMerge<'a> {
    inner: NodeNativeMergeProjection<'a>,
    request: &'a NodeRequestContext,
    command: ProtectionCommand,
    validations: AtomicUsize,
}
impl AsyncAdmissionProjection<FsqliteAuthorityStore> for ActivateDuringMerge<'_> {
    async fn snapshot_async<'a>(&'a self, authority: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, authenticated: &'a AuthenticatedHead,
    ) -> Result<AdmissionSnapshot, ProjectionFailure> {
        self.inner.snapshot_async(authority,cx,basis,authenticated).await
    }
    async fn materialize_commit_async<'a>(&'a self, authority: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, request: &'a TransactionRequest, fold: &'a TransactionFoldReport,
        closure: &'a ValidatedClosure,
    ) -> Result<CommitMaterialization, ProjectionFailure> {
        self.inner.materialize_commit_async(authority,cx,basis,request,fold,closure).await
    }
    async fn materialize_refusal_async<'a>(&'a self, authority: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, tx: TxId, code: RefusalCode,
    ) -> Result<RefusalMaterialization, ProjectionFailure> {
        self.inner.materialize_refusal_async(authority,cx,basis,tx,code).await
    }
}
impl NativeMergeProjection<FsqliteAuthorityStore> for ActivateDuringMerge<'_> {
    fn merge_checkpoint(&self, cx: &Cx) -> Result<(),RefusalCode> { self.inner.merge_checkpoint(cx) }
    async fn validate_merge_async<'a>(&'a self, authority: &'a FsqliteAuthorityStore, cx: &'a Cx,
        basis: &'a PublicationBasis, authenticated: &'a AuthenticatedHead, intent: &'a NativeMergeIntent,
    ) -> Result<ValidatedClosure,ProjectionFailure> {
        let closure=self.inner.validate_merge_async(authority,cx,basis,authenticated,intent).await?;
        if self.validations.fetch_add(1,Ordering::SeqCst)==0 {
            let result=self.inner.node.admit_repository_protection_durable_in(self.request,
                &session(9,"policy-during-merge"),&self.command,AdmissionLimits::default()).await.unwrap();
            assert!(matches!(result.1.outcome,DecisionOutcome::Committed { .. }),"the competing publication must really commit");
        }
        Ok(closure)
    }
}

#[test]
fn repository_protection_activation_wins_a_real_head_race_and_the_merge_revalidates() {
    for format in [GitHashAlgorithm::Sha1,GitHashAlgorithm::Sha256] {
        for protected in [false,true] {
            let scratch=Scratch::new();let f=fixture(&scratch,format);
            let request=f.node.request_context();
            let merge=f.command.candidate.merge(&f.command.review.subject);
            let proof=f.node.runtime().block_on(f.node.quarantine_reviewed_bundle_in(&request,
                &merge.target_ref,merge.target_tip_before,merge.merge_commit,&f.bundle,
                std::slice::from_ref(&merge.source_ref))).unwrap();
            drop(proof);
            let context=AdmissionContext { head_key:f.node.head_key.clone(),tenant_id:f.node.tenant_id,
                repository_id:f.node.repository_id,principal_id:actor(2),
                idempotency_key:IdempotencyKey::new(b"raced-ordinary-merge".to_vec()).unwrap(),object_format:format };
            let intent=NativeMergeIntent::new(f.command.review.subject.pull_request,
                ExpectedVersion::Exactly(f.command.review.subject.pull_request_version),merge).unwrap();
            let policy_request=f.node.request_context();
            let projection=ActivateDuringMerge {
                inner:NodeNativeMergeProjection { node:&f.node,
                    inner:f.node.durable_admission_projection(&context).unwrap(),object_limits:Default::default(),
                    workspace:None,workspace_capability:None,workspace_clock_floor:0 },
                request:&policy_request,command:policy(&f.node,0,if protected { &[3] } else { &[] }),
                validations:AtomicUsize::new(0),
            };
            let before=snapshot(&f.node);
            let result=f.node.runtime().block_on(admit_native_merge_async(&f.node.authority,request.authority(),
                &context,&intent,AdmissionLimits::default(),&projection)).unwrap();
            assert_eq!(projection.validations.load(Ordering::SeqCst),2,
                "the first merge basis must lose to a real publication and be validated again");
            assert_eq!(view(&f.node).selected.unwrap().version,AggregateVersion::FIRST);
            if protected {
                assert!(matches!(result.outcome,DecisionOutcome::Refused { code:RefusalCode::EvidenceMissing,.. }));
                code_unchanged(&before,&snapshot(&f.node));
            } else {
                assert!(matches!(result.outcome,DecisionOutcome::Committed { .. }),"an unrelated policy change must not block a valid replan");
                assert_eq!(snapshot(&f.node).snapshot().refs[&target()],f.command.candidate.commit);
            }
            drop(projection);
            f.node.shutdown().unwrap();
        }
    }
}
