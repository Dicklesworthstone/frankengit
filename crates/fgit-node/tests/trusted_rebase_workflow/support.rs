//! Real two-commit source histories, native rebase preparation and saved checks.
#[path = "../trusted_merge_workflow/support.rs"]
mod native;
pub use native::*;

use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::sha256_digest;
use fgit_forge::event::NativeMerge;
use fgit_forge::event::protection::{
    ProtectedBranch, ProtectionCommand, RequiredCandidateWorkflowCheck, ReviewProtection,
};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::event::workflow_check::candidate::CandidateWorkflowCheckRecord;
use fgit_forge::preparation::rebase::{
    EmptyCommitPolicy, PreparedRebase, RebaseCommitter, RebasePreparation,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{
    LoopbackReceiveSession, NativeMergeMethod, NodeReceiveTransportRefusal, NodeWorkspaceRefusal,
    OneNode, TrustedWorkflowArtifactConfig, TrustedWorkflowFailure, TrustedWorkflowRun,
};
use fgit_runner::coordinator::CheckRunStatus;
use fgit_runner::workflow::WorkflowLimits;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId, TxId};
use fgit_wire::visibility::RefVisibility;

pub const REVIEWER: PrincipalId = PrincipalId::from_bytes([0x74; 16]);
pub const MERGER: PrincipalId = PrincipalId::from_bytes([0x75; 16]);
pub type Published = (TxId, TerminalOutcome);

pub fn session(principal: PrincipalId, key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(principal, IdempotencyKey::new(key.to_vec()).unwrap())
}
pub fn committed(result: Published) -> Published {
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
    result
}

pub struct Case {
    pub f: Fixture,
    pub subject: ReviewSubject,
    pub binding: CandidateBinding,
    pub merge: NativeMerge,
    pub plan: PreparedRebase,
    pub bundle: Vec<u8>,
}
impl Case {
    pub fn new(format: GitHashAlgorithm) -> Self {
        let f = Fixture::new_rebase(format, WORKFLOW);
        let node = f.node();
        committed(
            node.runtime()
                .block_on(node.admit_pull_request_durable_in(
                    &node.request_context(),
                    &session(OWNER, b"rebase-check-open"),
                    &PullRequestCommand {
                        number: PullRequestNumber::FIRST,
                        expected_version: ExpectedVersion::NewStream,
                        action: PullRequestAction::Open,
                        data: PullRequestData {
                            source_ref: source_ref(),
                            target_ref: target_ref(),
                            source_tip: f.source,
                            target_tip: f.target,
                            title: "Test the exact rewritten series".into(),
                            body: String::new(),
                        },
                    },
                    Default::default(),
                ))
                .unwrap(),
        );
        let subject = ReviewSubject {
            pull_request: PullRequestNumber::FIRST,
            pull_request_version: AggregateVersion::FIRST,
            source_ref: source_ref(),
            target_ref: target_ref(),
            source_tip: f.source,
            target_tip: f.target,
            policy_epoch: node
                .runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .basis()
                .body()
                .policy_epoch,
        };
        let prepared = node
            .runtime()
            .block_on(node.prepare_pull_request_rebase_bundle_in(
                &node.request_context(),
                &subject,
                &RefVisibility::new(),
                f.base,
                &RebaseCommitter {
                    identity: "CI <ci@example.invalid>".into(),
                    timestamp: 17,
                },
                Default::default(),
                EmptyCommitPolicy::Stop,
            ))
            .unwrap();
        let RebasePreparation::Clean(plan) = prepared.preparation.outcome else {
            panic!("real disjoint native source changes must rebase cleanly");
        };
        assert_eq!(plan.steps.len(), 2);
        let binding = CandidateBinding {
            merge_base: f.base,
            commit: plan.commit,
        };
        let merge = binding.merge(&subject);
        Self {
            f,
            subject,
            binding,
            merge,
            plan,
            bundle: prepared.preparation.bundle.unwrap(),
        }
    }
    pub fn node(&self) -> &OneNode {
        self.f.node()
    }
    pub fn execute(
        &self,
        id: u8,
        limits: WorkflowLimits,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        let node = self.node();
        node.runtime().block_on(node.run_trusted_rebase_workflow_in(
            &node.request_context(),
            &self.merge,
            &self.bundle,
            b"workflow.yml",
            [id; 16],
            &self.f.parent(),
            &inputs(),
            None,
            limits,
            artifacts,
        ))
    }
    pub fn record(&self, run: &TrustedWorkflowRun) -> CandidateWorkflowCheckRecord {
        let scope = run.check_journal_scope();
        let mut journal = run.open_check_journal(None, &|| true).unwrap();
        let pin = journal.pin();
        let page = journal
            .read_history(None, None, 128, 1024 * 1024, &|| true)
            .unwrap();
        for entry in page.entries() {
            for (index, fact) in entry.batch().facts().iter().enumerate() {
                if fact.status == CheckRunStatus::Completed && fact.job_id == "a" {
                    let batch = entry.batch().id().digest();
                    drop(journal);
                    return OneNode::trusted_candidate_workflow_check_record(
                        &run.run_directory,
                        (TENANT, REPOSITORY, scope.journal_id.digest()),
                        Some((pin.byte_len(), pin.tail().digest())),
                        batch,
                        index,
                        self.subject.clone(),
                        self.binding.clone(),
                        sha256_digest(&self.bundle),
                        &|| true,
                    )
                    .unwrap();
                }
            }
        }
        panic!("real first job must retain one completed observation");
    }
    pub fn protect(&mut self, check: &CandidateWorkflowCheckRecord) {
        let node = self.node();
        let selected = node
            .runtime()
            .block_on(node.read_review_protection_in(&node.request_context()))
            .unwrap();
        let command = ProtectionCommand {
            expected_version: selected
                .version()
                .map(ExpectedVersion::Exactly)
                .unwrap_or(ExpectedVersion::NewStream),
            expected_epoch: selected.policy_epoch,
            protection: ReviewProtection {
                ref_policy: None,
                administrators: vec![OWNER],
                branches: vec![ProtectedBranch {
                    name: target_ref(),
                    reviewers: vec![REVIEWER],
                    required_approvals: 1,
                    require_merge_queue: false,
                    path_reviews: Vec::new(),
                    required_checks: Vec::new(),
                    required_candidate_checks: vec![RequiredCandidateWorkflowCheck {
                        publisher: OWNER,
                        graph_root: check.check.graph_root,
                        job: check.check.job.clone(),
                    }],
                }],
            },
        };
        committed(
            node.runtime()
                .block_on(node.admit_review_protection_durable_in(
                    &node.request_context(),
                    &session(OWNER, b"protect-rebase-candidate-check"),
                    &command,
                    Default::default(),
                ))
                .unwrap(),
        );
        self.subject.policy_epoch = command.expected_epoch.next().unwrap();
    }
    pub fn approve(&self) {
        let node = self.node();
        committed(
            node.runtime()
                .block_on(node.admit_rebase_candidate_review_durable_in(
                    &node.request_context(),
                    &session(REVIEWER, b"approve-rebase-check-series"),
                    &CandidateReviewCommand {
                        review: ReviewCommand {
                            expected_version: ExpectedVersion::NewStream,
                            subject: self.subject.clone(),
                            decision: ReviewDecision::Approve,
                            reason: "Reviewed every original and rewritten commit".into(),
                        },
                        candidate: self.binding.clone(),
                    },
                    Some(&self.bundle),
                    Default::default(),
                ))
                .unwrap(),
        );
    }
    pub fn publish(
        &self,
        record: &CandidateWorkflowCheckRecord,
        key: &[u8],
        bundle: &[u8],
    ) -> Result<Published, NodeReceiveTransportRefusal> {
        let node = self.node();
        node.runtime()
            .block_on(node.admit_trusted_rebase_candidate_workflow_check_in(
                &node.request_context(),
                &session(OWNER, key),
                record,
                bundle,
                Default::default(),
            ))
    }
    pub fn merge(&self, key: &[u8], bundle: &[u8]) -> Result<Published, NodeWorkspaceRefusal> {
        let node = self.node();
        node.runtime()
            .block_on(node.apply_reviewed_merge_bundle_with_method_durable_in(
                &node.request_context(),
                MERGER,
                key,
                self.subject.pull_request,
                ExpectedVersion::Exactly(self.subject.pull_request_version),
                &self.merge,
                bundle,
                self.subject.policy_epoch,
                &[REVIEWER],
                NativeMergeMethod::Rebase,
            ))
    }
}
