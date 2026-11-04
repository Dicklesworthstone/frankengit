//! Real canonical source, failed workflow evidence and PR state; no mocked reader.
use super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::ExpectedVersion;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::workflow_check::{NativeWorkflowCheck, WorkflowCheckRecord};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::LoopbackReceiveSession;
use fgit_runner::coordinator::CheckRunStatus;
use fgit_runner::workflow::WorkflowLimits;
use fgit_types::{DecisionOutcome, HeadGeneration, RepositoryId, TenantId};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const ACTOR: PrincipalId = PrincipalId::from_bytes([0x67; 16]);

pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) options: Options,
    pub(super) data: PullRequestData,
    pub(super) evidence: Vec<u8>,
}

fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        ACTOR,
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn metadata(timestamp: u64) -> MergeMetadata {
    MergeMetadata {
        author: "Evidence <evidence@example.invalid>".into(),
        committer: "Evidence <evidence@example.invalid>".into(),
        timestamp,
        message: b"check evidence fixture\n".to_vec(),
    }
}

impl Fixture {
    pub(super) fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-mcp-check-evidence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let artifact_root = root.join("artifacts");
        fs::DirBuilder::new().mode(0o700).create(&artifact_root).unwrap();
        let tenant = TenantId::from_bytes([0x65; 16]);
        let repository = RepositoryId::from_bytes([0x66; 16]);
        let config = NodeConfig::new(root.join("node"), tenant, repository)
            .with_object_format(format)
            .with_workflow_artifact_root(artifact_root.clone())
            .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let target_ref = RefName::try_new(b"refs/heads/main").unwrap();
        let source_ref = RefName::try_new(b"refs/heads/topic").unwrap();
        let initial_patch = b"diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+Evidence fixture\n";
        let (_, initial, bundle) = node.runtime().block_on(
            node.prepare_trusted_initial_patch_in(
                &node.request_context(), &target_ref, initial_patch, &metadata(1),
                Default::default(), None,
            )
        ).unwrap();
        let published = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &node.request_context(), &session("evidence-initial"), &target_ref,
            initial.commit, bundle.bytes(), Default::default(),
        )).unwrap();
        assert!(matches!(
            published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }
        ));
        let branch = RefCommand {
            name: source_ref.clone(),
            expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(initial.commit),
            force: false,
        };
        let published = node.runtime().block_on(node.admit_branch_updates_durable_in(
            &node.request_context(), &session("evidence-topic"), &[branch], Default::default(),
        )).unwrap();
        assert!(matches!(
            published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }
        ));
        let workflow = b"diff --git a/workflow.yml b/workflow.yml\nnew file mode 100644\n--- /dev/null\n+++ b/workflow.yml\n@@ -0,0 +1,7 @@\n+name: check-evidence\n+on: push\n+jobs:\n+  diagnose:\n+    runs-on: fgit-trusted-local\n+    steps:\n+      - run: printf MCP-CHECK-FAILED; printf MCP-CHECK-ERROR >&2; exit 7\n";
        let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(
            &node.request_context(), &source_ref, initial.commit, [1; 16], workflow,
            &metadata(2), Default::default(),
        )).unwrap();
        let published = node.runtime().block_on(node.apply_workspace_bundle_durable_in(
            &node.request_context(), ACTOR, b"evidence-workflow", &source_ref,
            initial.commit, candidate.candidate_commit, candidate.bundle_bytes(),
        )).unwrap();
        assert!(matches!(
            published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }
        ));
        let source_tip = candidate.candidate_commit;
        let runs = root.join("runs");
        fs::DirBuilder::new().mode(0o700).create(&runs).unwrap();
        let run = node.runtime().block_on(node.run_trusted_workflow_in(
            &node.request_context(), &source_ref, b"workflow.yml", [2; 16],
            &runs, &[b"workflow.yml".to_vec()], (None, Some(source_tip)),
            WorkflowLimits { total_output_bytes: 8192, ..Default::default() },
        )).unwrap();
        let mut journal = run.open_check_journal(None, &|| true).unwrap();
        let history = journal.read_history(None, None, 128, 1024 * 1024, &|| true).unwrap();
        let mut records: BTreeMap<WorkflowCheckId, WorkflowCheckRecord> = BTreeMap::new();
        for entry in history.entries() {
            for (index, fact) in entry.batch().facts().iter().enumerate() {
                if fact.status == CheckRunStatus::Completed {
                    let evidence = journal.read_evidence(fact.receipt_commitment.unwrap()).unwrap();
                    let record = OneNode::workflow_check_record_from_batch(
                        source_ref.clone(), entry.batch(), index, &evidence, &|| true,
                    ).unwrap();
                    let id = NativeWorkflowCheck { actor: ACTOR, record: record.clone() }.id();
                    records.insert(id, record);
                }
            }
        }
        assert_eq!(records.len(), 1);
        let (check, record) = records.into_iter().next().unwrap();
        assert_eq!(record.conclusion, WorkflowCheckConclusion::Failure);
        let (_, terminal) = node.runtime().block_on(node.admit_trusted_workflow_check_in(
            &node.request_context(), &session(&check.to_string()), &record, Default::default(),
        )).unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        let data = PullRequestData {
            source_ref,
            target_ref,
            source_tip,
            target_tip: initial.commit,
            title: "Diagnose a failed canonical check".into(),
            body: "The canonical observation is not an approval.".into(),
        };
        let command = PullRequestCommand {
            number: PullRequestNumber::try_new(7).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: data.clone(),
        };
        let (_, terminal) = node.runtime().block_on(node.admit_pull_request_durable_in(
            &node.request_context(), &session("evidence-pr"), &command, Default::default(),
        )).unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        let options = Options {
            storage: root.join("node"), tenant, repository, format,
            incarnation: Some(node.repository_incarnation_id()),
            issues: false, discussions: false, pulls: true, source: false,
            queues: Default::default(), agent_context: false,
            artifacts: true, artifact_root: Some(artifact_root), agent_token_file: None,
            writes: Default::default(), outcomes: false, principal: None,
            max_messages: 64, index_maintenance: None,
        };
        node.shutdown().unwrap();
        Self { root, options, data, evidence: record.evidence }
    }

    pub(super) fn advance_source(&self, backend: &NodeTools) {
        let patch = b"diff --git a/next b/next\nnew file mode 100644\n--- /dev/null\n+++ b/next\n@@ -0,0 +1 @@\n+source moved without refreshing the PR\n";
        let candidate = backend.node.runtime().block_on(backend.node.prepare_trusted_patch_in(
            &backend.node.request_context(), &self.data.source_ref, self.data.source_tip,
            [3; 16], patch, &metadata(3), Default::default(),
        )).unwrap();
        let published = backend.node.runtime().block_on(backend.node.apply_workspace_bundle_durable_in(
            &backend.node.request_context(), ACTOR, b"evidence-source-moved",
            &self.data.source_ref, self.data.source_tip,
            candidate.candidate_commit, candidate.bundle_bytes(),
        )).unwrap();
        assert!(matches!(
            published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }
        ));
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
