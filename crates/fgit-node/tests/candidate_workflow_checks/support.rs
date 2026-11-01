//! Real imported histories, saved runner journals and canonical queue operations.
//! Reuse the existing divergent-tree fixture; no model result stands in for admission.
#[path = "../trusted_merge_workflow/support.rs"]
mod native;
pub use native::*;

use fgit_admission::merge::native::queue::QueueCandidateLandingCommand;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{Digest, GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::protection::{
    ProtectedBranch, ProtectionCommand, RequiredCandidateWorkflowCheck, RequiredWorkflowCheck,
    ReviewProtection,
};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::event::workflow_check::candidate::CandidateWorkflowCheckRecord;
use fgit_forge::event::workflow_check::{WorkflowCheckId, WorkflowCheckRecord};
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::preparation::{MergeMetadata, MergePreparation};
use fgit_forge::{AggregateId, AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_node::{
    LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeWorkspaceRefusal, OneNode,
    TrustedWorkflowRun,
};
use fgit_pack::full_bundle::retarget::RetargetedBundle;
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_runner::coordinator::CheckRunStatus;
use fgit_runner::coordinator::delivery::CheckDeliveryBatch;
use fgit_runner::workflow::WorkflowLimits;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, TxId};
use fgit_wire::visibility::RefVisibility;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::path::PathBuf;

pub const REVIEWER: PrincipalId = PrincipalId::from_bytes([0x74; 16]);
pub const OTHER_PUBLISHER: PrincipalId = PrincipalId::from_bytes([0x75; 16]);
pub type Published = (TxId, TerminalOutcome);

pub fn session(actor: PrincipalId, key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor, IdempotencyKey::new(key.to_vec()).unwrap())
}

pub fn committed(result: Published) -> Published {
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
    result
}

pub fn refused<E: Debug>(result: Result<Published, E>) {
    match result {
        Ok((_, outcome)) => assert!(
            matches!(outcome.outcome, DecisionOutcome::Refused { .. }),
            "{outcome:?}"
        ),
        Err(_) => {}
    }
}

pub fn ci_ref() -> RefName {
    RefName::try_new(b"refs/heads/check-isolation").unwrap()
}

pub fn refs(node: &OneNode) -> BTreeMap<RefName, GitOid> {
    node.runtime()
        .block_on(node.materialize_admission())
        .unwrap()
        .snapshot()
        .refs
        .clone()
}

pub fn candidate_id(record: &CandidateWorkflowCheckRecord, actor: PrincipalId) -> WorkflowCheckId {
    let event = record
        .proposed_event(actor, record.candidate.commit.algorithm())
        .unwrap();
    let AggregateId::WorkflowCheck(id) = event.aggregate else {
        panic!("candidate check must use the immutable workflow-check aggregate");
    };
    id
}

pub fn ordinary_id(record: &WorkflowCheckRecord, actor: PrincipalId) -> WorkflowCheckId {
    let event = record
        .proposed_event(actor, record.source_commit.algorithm())
        .unwrap();
    let AggregateId::WorkflowCheck(id) = event.aggregate else {
        panic!("ordinary check must use the immutable workflow-check aggregate");
    };
    id
}

pub fn required(record: &CandidateWorkflowCheckRecord) -> RequiredCandidateWorkflowCheck {
    RequiredCandidateWorkflowCheck {
        publisher: OWNER,
        graph_root: record.check.graph_root,
        job: record.check.job.clone(),
    }
}

pub struct Saved {
    pub directory: PathBuf,
    pub journal: Digest,
    pub pin: (u64, Digest),
    pub batch: CheckDeliveryBatch,
    pub index: usize,
    pub evidence: Vec<u8>,
}

impl Saved {
    pub fn capture(run: TrustedWorkflowRun) -> Self {
        assert!(run.workspaces_closed);
        let scope = run.check_journal_scope();
        let mut journal = run.open_check_journal(None, &|| true).unwrap();
        let pin = (journal.pin().byte_len(), journal.pin().tail().digest());
        let page = journal
            .read_history(None, None, 128, 1024 * 1024, &|| true)
            .unwrap();
        for entry in page.entries() {
            let batch = entry.batch();
            for (index, fact) in batch.facts().iter().enumerate() {
                if fact.status == CheckRunStatus::Completed && fact.job_id == "a" {
                    let evidence = journal
                        .read_evidence(fact.receipt_commitment.unwrap())
                        .unwrap();
                    return Self {
                        directory: run.run_directory.clone(),
                        journal: scope.journal_id.digest(),
                        pin,
                        batch: batch.clone(),
                        index,
                        evidence,
                    };
                }
            }
        }
        panic!("native execution must retain the completed first job");
    }

    pub fn record(&self, case: &Case) -> CandidateWorkflowCheckRecord {
        self.record_for(
            case.subject.clone(),
            case.binding.clone(),
            sha256_digest(&case.bundle),
        )
    }

    pub fn record_for(
        &self,
        subject: ReviewSubject,
        candidate: CandidateBinding,
        bundle_sha256: [u8; 32],
    ) -> CandidateWorkflowCheckRecord {
        OneNode::trusted_candidate_workflow_check_record(
            &self.directory,
            (TENANT, REPOSITORY, self.journal),
            Some(self.pin),
            self.batch.id().digest(),
            self.index,
            subject,
            candidate,
            bundle_sha256,
            &|| true,
        )
        .unwrap()
    }

    pub fn ordinary(&self, reference: RefName) -> WorkflowCheckRecord {
        OneNode::trusted_workflow_check_record(
            &self.directory,
            (TENANT, REPOSITORY, self.journal),
            Some(self.pin),
            self.batch.id().digest(),
            self.index,
            reference,
            &|| true,
        )
        .unwrap()
    }
}

pub struct Case {
    pub f: Fixture,
    pub pull: PullRequestCommand,
    pub subject: ReviewSubject,
    pub binding: CandidateBinding,
    pub merge: NativeMerge,
    pub bundle: Vec<u8>,
}

impl Case {
    pub fn new(format: GitHashAlgorithm) -> Self {
        let f = Fixture::new(format, WORKFLOW);
        let node = f.node();
        let pull = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: source_ref(),
                target_ref: target_ref(),
                source_tip: f.source,
                target_tip: f.target,
                title: "Check the actual unpublished divergent merge".into(),
                body: String::new(),
            },
        };
        committed(
            node.runtime()
                .block_on(node.admit_pull_request_durable_in(
                    &node.request_context(),
                    &session(OWNER, b"candidate-check-open"),
                    &pull,
                    Default::default(),
                ))
                .unwrap(),
        );
        committed(
            node.runtime()
                .block_on(node.admit_queue_durable_in(
                    &node.request_context(),
                    &session(OWNER, b"candidate-check-enqueue"),
                    &QueueCommand {
                        number: QueueNumber::FIRST,
                        expected_version: ExpectedVersion::NewStream,
                        target_ref: target_ref(),
                        action: QueueCommandAction::Enqueue {
                            pull_request: pull.number,
                            expected_pull_request_version: AggregateVersion::FIRST,
                            source_ref: source_ref(),
                            head_tip: f.source,
                            expected_target_tip: f.target,
                            priority: 0,
                        },
                    },
                    Default::default(),
                ))
                .unwrap(),
        );
        let epoch = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap()
            .basis()
            .body()
            .policy_epoch;
        let subject = ReviewSubject {
            pull_request: pull.number,
            pull_request_version: AggregateVersion::FIRST,
            source_ref: source_ref(),
            target_ref: target_ref(),
            source_tip: f.source,
            target_tip: f.target,
            policy_epoch: epoch,
        };
        let prepared = node
            .runtime()
            .block_on(node.prepare_queue_head_bundle_in(
                &node.request_context(),
                QueueNumber::FIRST,
                AggregateVersion::FIRST,
                &subject,
                &RefVisibility::new(),
                &MergeMetadata {
                    author: "Checks <checks@example.invalid>".into(),
                    committer: "Checks <checks@example.invalid>".into(),
                    timestamp: 11,
                    message: b"Exact unpublished queue candidate\n".to_vec(),
                },
                Default::default(),
            ))
            .unwrap();
        let MergePreparation::Clean(plan) = prepared.outcome else {
            panic!("the real divergent-tree fixture must merge cleanly");
        };
        let binding = CandidateBinding {
            merge_base: plan.base,
            commit: plan.commit,
        };
        let merge = binding.merge(&subject);
        Self {
            f,
            pull,
            subject,
            binding,
            merge,
            bundle: prepared.bundle.unwrap(),
        }
    }

    pub fn node(&self) -> &OneNode {
        self.f.node()
    }

    pub fn execute(&self, nonce: u8, output_limit: usize) -> Saved {
        let node = self.node();
        let run = node
            .runtime()
            .block_on(node.run_trusted_merge_workflow_in(
                &node.request_context(),
                &self.merge,
                &self.bundle,
                b"workflow.yml",
                [nonce; 16],
                &self.f.parent(),
                &inputs(),
                None,
                WorkflowLimits {
                    stream_bytes: output_limit.min(4096),
                    total_output_bytes: output_limit,
                    ..Default::default()
                },
            ))
            .unwrap();
        assert_eq!(run.executed_commit(), self.binding.commit);
        assert_eq!(run.merge.as_ref(), Some(&self.merge));
        assert_eq!(
            run.candidate.as_ref().unwrap().bundle_sha256,
            sha256_digest(&self.bundle)
        );
        Saved::capture(run)
    }

    pub fn execute_ref(&self, reference: &RefName, tip: GitOid, nonce: u8) -> Saved {
        let node = self.node();
        Saved::capture(
            node.runtime()
                .block_on(node.run_trusted_workflow_in(
                    &node.request_context(),
                    reference,
                    b"workflow.yml",
                    [nonce; 16],
                    &self.f.parent(),
                    &inputs(),
                    (None, Some(tip)),
                    Default::default(),
                ))
                .unwrap(),
        )
    }

    pub fn protect(
        &mut self,
        candidate_checks: Vec<RequiredCandidateWorkflowCheck>,
        ordinary_checks: Vec<RequiredWorkflowCheck>,
        reviews: bool,
        key: &[u8],
    ) {
        self.protect_with_queue(candidate_checks, ordinary_checks, reviews, true, key);
    }

    pub fn protect_with_queue(
        &mut self,
        candidate_checks: Vec<RequiredCandidateWorkflowCheck>,
        ordinary_checks: Vec<RequiredWorkflowCheck>,
        reviews: bool,
        require_merge_queue: bool,
        key: &[u8],
    ) {
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
                    require_merge_queue,
                    required_approvals: u16::from(reviews),
                    reviewers: if reviews { vec![REVIEWER] } else { Vec::new() },
                    required_checks: ordinary_checks,
                    required_candidate_checks: candidate_checks,
                }],
            },
        };
        committed(
            node.runtime()
                .block_on(node.admit_review_protection_durable_in(
                    &node.request_context(),
                    &session(OWNER, key),
                    &command,
                    Default::default(),
                ))
                .unwrap(),
        );
        self.subject.policy_epoch = command.expected_epoch.next().unwrap();
    }

    pub fn approve(&self, key: &[u8]) {
        let node = self.node();
        let command = CandidateReviewCommand {
            review: ReviewCommand {
                expected_version: ExpectedVersion::NewStream,
                subject: self.subject.clone(),
                decision: ReviewDecision::Approve,
                reason: "Inspected both parents and the exact candidate bundle".into(),
            },
            candidate: self.binding.clone(),
        };
        committed(
            node.runtime()
                .block_on(node.admit_candidate_review_durable_in(
                    &node.request_context(),
                    &session(REVIEWER, key),
                    &command,
                    Some(&self.bundle),
                    Default::default(),
                ))
                .unwrap(),
        );
    }

    pub fn publish(
        &self,
        record: &CandidateWorkflowCheckRecord,
        actor: PrincipalId,
        key: &[u8],
        bundle: &[u8],
    ) -> Result<Published, NodeReceiveTransportRefusal> {
        let node = self.node();
        node.runtime()
            .block_on(node.admit_trusted_candidate_workflow_check_in(
                &node.request_context(),
                &session(actor, key),
                record,
                bundle,
                Default::default(),
            ))
    }

    pub fn publish_ordinary(
        &self,
        record: &WorkflowCheckRecord,
        key: &[u8],
    ) -> Result<Published, NodeReceiveTransportRefusal> {
        let node = self.node();
        node.runtime()
            .block_on(node.admit_trusted_workflow_check_in(
                &node.request_context(),
                &session(OWNER, key),
                record,
                Default::default(),
            ))
    }

    pub fn command(&self) -> QueueCandidateLandingCommand {
        QueueCandidateLandingCommand {
            number: QueueNumber::FIRST,
            expected_version: AggregateVersion::FIRST,
            expected_policy_epoch: self.subject.policy_epoch,
            pull_request: self.subject.pull_request,
            expected_pull_request_version: self.subject.pull_request_version,
            merge: self.merge.clone(),
        }
    }

    pub fn land(&self, key: &[u8], bundle: &[u8]) -> Result<Published, NodeWorkspaceRefusal> {
        let node = self.node();
        node.runtime()
            .block_on(node.land_queue_head_bundle_durable_in(
                &node.request_context(),
                &session(OWNER, key),
                &self.command(),
                bundle,
                Default::default(),
            ))
    }

    pub fn import_candidate(&self, reference: RefName, key: &[u8]) {
        let bytes = RetargetedBundle::parse(
            &self.bundle,
            &target_ref(),
            &reference,
            self.binding.commit,
            Default::default(),
            &mut || true,
        )
        .unwrap();
        let bytes = [bytes.header_bytes(), bytes.pack_bytes()].concat();
        let old = refs(self.node()).get(&reference).copied();
        let node = self.node();
        let imported = node
            .runtime()
            .block_on(node.import_incremental_git_bundle_durable_in(
                &node.request_context(),
                &session(OWNER, key),
                &bytes,
                &[(reference, old)],
                Default::default(),
            ))
            .unwrap();
        assert_eq!(imported.commands.len(), 1);
        assert!(
            matches!(
                imported.commands[0].terminal.outcome,
                DecisionOutcome::Committed { .. }
            ),
            "{:?}",
            imported.commands
        );
    }

    pub fn update_pull(&mut self) {
        let mut update = self.pull.clone();
        update.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        update.action = PullRequestAction::Update;
        update.data.title.push_str(" (review context updated)");
        let node = self.node();
        committed(
            node.runtime()
                .block_on(node.admit_pull_request_durable_in(
                    &node.request_context(),
                    &session(OWNER, b"candidate-check-update-pr"),
                    &update,
                    Default::default(),
                ))
                .unwrap(),
        );
        self.subject.pull_request_version = AggregateVersion::FIRST.next().unwrap();
        self.pull = update;
    }
}

struct CandidateObjects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);

impl CandidateObjects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let oid = git_object_id(format, kind, &body);
        self.0.insert(oid, (kind, body));
        oid
    }
}

impl CanonicalObjectSource for CandidateObjects {
    fn load(&self, oid: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self
            .0
            .get(oid)
            .ok_or(PackWriteError::MissingCanonicalObject(*oid))?;
        Ok(CanonicalPackObject::new(
            *oid,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}

impl Case {
    /// A real caller-prepared two-parent merge can add a large file while its
    /// selected workflow inputs remain small. The native closure still validates
    /// every uploaded object; this does not fabricate execution or admission.
    pub fn with_large_candidate_file(mut self, bytes: usize) -> Self {
        let format = self.f.target.algorithm();
        let mut objects = CandidateObjects(BTreeMap::new());
        let large = objects.put(format, GitObjectKind::Blob, vec![b'X'; bytes]);
        let left = git_object_id(format, GitObjectKind::Blob, b"target\n");
        let right = git_object_id(format, GitObjectKind::Blob, b"source\n");
        let tree = objects.put(
            format,
            GitObjectKind::Tree,
            [
                b"100644 large.bin\0".as_slice(),
                large.as_bytes(),
                b"100644 left\0",
                left.as_bytes(),
                b"100644 right\0",
                right.as_bytes(),
                b"100644 workflow.yml\0",
                self.f.workflow.as_bytes(),
            ]
            .concat(),
        );
        let candidate = objects.put(
            format,
            GitObjectKind::Commit,
            commit_bytes(
                tree,
                &[self.f.target, self.f.source],
                "Candidate with an independently bounded large artifact",
            ),
        );
        let limits = PackLimits::default();
        let plan = PackPlanner::new(
            format,
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
            limits.clone(),
        )
        .plan_selected(
            &objects,
            &objects.0.keys().copied().collect::<Vec<_>>(),
            &mut || true,
        )
        .unwrap();
        let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
        let mut bundle = match format {
            GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
            GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
        };
        bundle.extend_from_slice(
            format!(
                "-{} target\n-{} source\n{candidate} refs/heads/main\n\n",
                self.f.target, self.f.source
            )
            .as_bytes(),
        );
        bundle.extend_from_slice(&pack);
        self.binding.commit = candidate;
        self.merge = self.binding.merge(&self.subject);
        self.bundle = bundle;
        self
    }
}
