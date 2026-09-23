//! Real private-file custody and actual OneNode/source/workspace execution.
//! The injected executor cases test ordering/failure, not process isolation.
use super::*;
use crate::{NodeConfig, OneNode};
use fgit_crypto::{DigestAlgorithm, DigestBytes, GitObjectKind, git_object_id};
use fgit_runner::coordinator::delivery::{
    CheckDeliveryAcknowledgement, CheckDeliveryBatch, CheckDeliveryRefusal, CheckDeliverySink,
};
use fgit_runner::coordinator::delivery::journal::attempt::{
    WorkflowAttemptStatus,
};
use fgit_runner::coordinator::{CheckRunConclusion, CheckRunStatus};
use fgit_runner::workflow::{
    StepLimits, StepObservation, StepOutcome, WorkerFailure, WorkflowJob, WorkflowLimits,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, GitHashAlgorithm, GitOid, GitOidSha1,
    PrincipalId, RefName, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId,
    RepositoryIncarnationId, TenantId,
};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const SOURCE: &str = "name: custody\non: push\njobs:\n  first:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf one > generated; printf first\n      - run: test \"$(cat generated)\" = one; printf second\n  next:\n    runs-on: fgit-trusted-local\n    needs: first\n    steps:\n      - run: test ! -e generated; printf dependent\n";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "fg-node-workflow-custody-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create private test directory: {error}"),
            }
        }
    }
}
impl Drop for Temp {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn limits() -> WorkflowLimits {
    WorkflowLimits { total_output_bytes: 8192, ..WorkflowLimits::default() }
}

// Only control-flow unit tests use these fabricated coordinates. Actual source
// selection/publication is exercised independently by the OneNode test below.
fn report(temp: &Temp) -> TrustedWorkflowRun {
    let plan = WorkflowPlan::compile(SOURCE).unwrap();
    let digest = DigestBytes::try_new(&[9; 32]).unwrap();
    TrustedWorkflowRun {
        tenant: TenantId::from_bytes([1;16]), repository: RepositoryId::from_bytes([2;16]),
        incarnation: RepositoryIncarnationId::from_bytes([3;16]),
        source_head: RepositoryAuthorityHeadId::from_digest(DigestAlgorithm::Sha256.id(), CANONICAL_CODEC_VERSION, digest),
        source_rcr: RepositoryCommitId::from_digest(DigestAlgorithm::Sha256.id(), CANONICAL_CODEC_VERSION, digest),
        source_commit: GitOid::Sha1(GitOidSha1::from_bytes([4;20])),
        source_tree: GitOid::Sha1(GitOidSha1::from_bytes([5;20])),
        source_reference: b"refs/heads/main".to_vec(), candidate: None, merge: None,
        workflow_blob: GitOid::Sha1(GitOidSha1::from_bytes([6;20])),
        workflow_path: b"workflow.yml".to_vec(), read_prefixes: vec![b"workflow.yml".to_vec()],
        run_id: [7;16], run_directory: temp.0.clone(), workspaces_closed: false,
        request_interrupted: false,
        execution: WorkflowReport { source: plan.source_commitment(), graph: plan.graph_commitment(), limits: limits(), jobs: Vec::new() },
    }
}
fn prepare(report: &TrustedWorkflowRun) -> Prepared {
    Prepared::new(report, WorkflowPlan::compile(SOURCE).unwrap()).unwrap()
}

struct Executor {
    directory: PathBuf,
    started: Vec<String>, closed: usize, observed_lengths: Vec<u64>,
    corrupt_after_close: bool, retain: bool,
}
impl Executor {
    fn new(temp: &Temp) -> Self {
        Self { directory: temp.0.clone(), started: Vec::new(), closed: 0,
            observed_lengths: Vec::new(), corrupt_after_close: false, retain: false }
    }
}
impl WorkflowExecutor for Executor {
    fn begin_job(&mut self, _: usize, job: &WorkflowJob, _: &dyn Fn() -> bool) -> Result<(), WorkerFailure> {
        // Both the complete queue and the durable Started fence precede even
        // the FIRST scope. Every later scope sees additional persisted records.
        let bytes = fs::metadata(self.directory.join(JOURNAL_FILE)).unwrap().len();
        assert!(bytes > 72);
        assert!(fs::metadata(self.directory.join(OWNER_FILE)).unwrap().len() > 168);
        if let Some(previous) = self.observed_lengths.last() { assert!(bytes > *previous); }
        self.observed_lengths.push(bytes);
        self.started.push(job.id.clone());
        Ok(())
    }
    fn execute_step(&mut self, _: usize, script: &str, _: StepLimits, _: &dyn Fn() -> bool) -> Result<StepObservation, WorkerFailure> {
        Ok(StepObservation { outcome: StepOutcome::Succeeded, exit_code: Some(0),
            stdout: script.as_bytes().to_vec(), stderr: Vec::new(), elapsed_millis: 1,
            output_complete: true, retain_workspace: self.retain })
    }
    fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> {
        self.closed += 1;
        if self.corrupt_after_close {
            // An explicit local fault injection, not an acceptable producer.
            // The journal must reject the changed physical boundary before
            // accepting evidence or allowing the dependent to start.
            let mut file = OpenOptions::new().append(true).open(self.directory.join(JOURNAL_FILE)).unwrap();
            file.write_all(b"torn").unwrap(); file.sync_all().unwrap();
        }
        Ok(())
    }
}

// This sink actually retains exact bytes before acknowledgement. It is a
// local-custody fixture, never a simulated canonical check publisher.
struct DiskSink(PathBuf);
impl CheckDeliverySink for DiskSink {
    fn accept(&mut self, batch: &CheckDeliveryBatch) -> Result<CheckDeliveryAcknowledgement, CheckDeliveryRefusal> {
        let path = self.0.join(format!("batch-{}", batch.ordinal()));
        let mut file = OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        file.write_all(batch.body()).unwrap(); file.sync_all().unwrap();
        File::open(&self.0).unwrap().sync_all().unwrap();
        Ok(CheckDeliveryAcknowledgement::after_durable_acceptance(batch, Commitment::of_bytes(&fs::read(path).unwrap())))
    }
}

#[test]
fn node_adapter_journals_each_job_before_releasing_its_dependent() {
    let temp = Temp::new();
    let report = report(&temp); let prepared = prepare(&report);
    let binding = prepared.binding; let scope = prepared.scope;
    let mut executor = Executor::new(&temp);
    let completed = prepared.execute(&temp.0, &mut executor, &|| true).unwrap();
    assert!(completed.succeeded());
    assert_eq!(executor.started, ["first", "next"]); assert_eq!(executor.closed, 2);
    let mut owner = FileWorkflowAttempt::open(&temp.0.join(OWNER_FILE), binding, None, &|| true).unwrap();
    assert_eq!(owner.status(), WorkflowAttemptStatus::Completed);
    let receipt = owner.completed_receipt().unwrap().unwrap();
    assert!(!receipt.requires_containment());
    let mut journal = FileCheckJournal::open(&temp.0.join(JOURNAL_FILE), scope, Default::default(), Some(receipt.journal_pin()), &|| true).unwrap();
    assert_eq!(journal.pending_batches(), 3);
    let mut sink = DiskSink(temp.0.clone()); let mut count = 0; let mut completed_jobs = 0;
    while let Some(batch) = journal.next_batch().unwrap() {
        assert_eq!(batch.source_commit(), report.executed_commit());
        assert_eq!(batch.run_id(), binding.run_id());
        for fact in batch.facts() {
            if fact.status == CheckRunStatus::Completed {
                completed_jobs += 1;
                assert_eq!(fact.conclusion, Some(CheckRunConclusion::ActionRequired));
                let expected = fact.receipt_commitment.unwrap();
                let evidence = journal.read_evidence(expected).unwrap();
                assert_eq!(Commitment::of_bytes(&evidence), expected);
            }
        }
        journal.forward_next(&mut sink, &|| true).unwrap().unwrap(); count += 1;
    }
    assert_eq!((count, completed_jobs), (3, 2));
    drop(journal); drop(owner);
    let journal = FileCheckJournal::open(&temp.0.join(JOURNAL_FILE), scope, Default::default(), Some(receipt.journal_pin()), &|| true).unwrap();
    assert_eq!(journal.pending_batches(), 0);
}

#[test]
fn persistence_failure_after_a_closed_job_fences_all_later_scopes() {
    let temp = Temp::new(); let prepared = prepare(&report(&temp)); let binding = prepared.binding;
    let mut executor = Executor::new(&temp); executor.corrupt_after_close = true;
    assert!(matches!(prepared.execute(&temp.0, &mut executor, &|| true), Err(TrustedWorkflowFailure::Journal { .. })));
    assert_eq!(executor.started, ["first"]); assert_eq!(executor.closed, 1);
    let mut owner = FileWorkflowAttempt::open(&temp.0.join(OWNER_FILE), binding, None, &|| true).unwrap();
    assert_eq!(owner.status(), WorkflowAttemptStatus::Started);
    assert!(owner.completed_receipt().unwrap().is_none());
}

#[test]
fn cancelled_intake_and_preexisting_owner_never_open_a_scope() {
    let temp = Temp::new(); let prepared = prepare(&report(&temp)); let binding = prepared.binding;
    let mut executor = Executor::new(&temp);
    assert!(prepared.execute(&temp.0, &mut executor, &|| false).is_err());
    assert!(executor.started.is_empty());
    let owner = FileWorkflowAttempt::open(&temp.0.join(OWNER_FILE), binding, None, &|| true).unwrap();
    assert_eq!(owner.status(), WorkflowAttemptStatus::Prepared);
    drop(owner);
    let temp = Temp::new(); let prepared = prepare(&report(&temp));
    fs::write(temp.0.join(OWNER_FILE), b"existing ownership is not adopted").unwrap();
    let mut executor = Executor::new(&temp);
    assert!(prepared.execute(&temp.0, &mut executor, &|| true).is_err());
    assert!(executor.started.is_empty());
    assert_eq!(fs::read(temp.0.join(OWNER_FILE)).unwrap(), b"existing ownership is not adopted");
}

#[test]
fn containment_observations_survive_completion_and_reopen() {
    let temp = Temp::new(); let prepared = prepare(&report(&temp)); let binding = prepared.binding;
    let mut executor = Executor::new(&temp); executor.retain = true;
    let completed = prepared.execute(&temp.0, &mut executor, &|| true).unwrap();
    assert_eq!(executor.started, ["first"]);
    assert!(completed.jobs.iter().any(fgit_runner::workflow::JobReport::requires_containment));
    let mut owner = FileWorkflowAttempt::open(&temp.0.join(OWNER_FILE), binding, None, &|| true).unwrap();
    assert!(owner.completed_receipt().unwrap().unwrap().requires_containment());
}

#[test]
fn identity_preserves_the_whole_nonce_input_scope_and_exact_time_limits() {
    let temp = Temp::new(); let mut report = report(&temp);
    report.execution.limits.run_timeout = Duration::from_nanos(1_000_001);
    report.execution.limits.step_timeout = Duration::from_nanos(1_000_001);
    let original = prepare(&report);
    assert_eq!(original.workflow.limits(), report.execution.limits);
    report.run_id[15] ^= 1;
    let other = prepare(&report);
    assert_ne!(original.workflow.run_id(), other.workflow.run_id());
    assert_ne!(original.binding, other.binding);
    report.run_id[15] ^= 1;
    report.read_prefixes.push(b"another-input".to_vec());
    let other = prepare(&report);
    assert_ne!(original.scope, other.scope); assert_ne!(original.binding, other.binding);
    report.read_prefixes.pop(); report.incarnation = RepositoryIncarnationId::from_bytes([0xff;16]);
    assert_ne!(original.binding, prepare(&report).binding);
}

#[test]
fn marker_identity_is_stable_after_jobs_complete_but_mismatched_plans_refuse() {
    let temp = Temp::new(); let mut report = report(&temp); let before = scope(&report);
    let completed = prepare(&report).execute(&temp.0, &mut Executor::new(&temp), &|| true).unwrap();
    report.execution = completed; report.workspaces_closed = true;
    assert_eq!(before, scope(&report));
    assert!(Prepared::new(&report, WorkflowPlan::compile(SOURCE).unwrap()).is_err());
    report.execution.jobs.clear(); report.execution.source = Commitment::of_bytes(b"different source");
    assert!(Prepared::new(&report, WorkflowPlan::compile(SOURCE).unwrap()).is_err());
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, name: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes()); encoded.extend((!length).to_le_bytes()); encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521; (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string(); fs::create_dir_all(root.join("objects").join(&text[..2])).unwrap();
    fs::write(root.join("objects").join(&text[..2]).join(&text[2..]), encoded).unwrap(); id
}
fn generation(node: &OneNode) -> u64 {
    node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation().get()
}
fn serve(node: &mut OneNode) {
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
}

#[test]
fn actual_node_jobs_reopen_exact_evidence_without_publishing_or_reexecution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let temp = Temp::new(); let source = temp.0.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(source.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        let workflow = loose(&source, format, GitObjectKind::Blob, "blob", SOURCE.as_bytes());
        let tree = [b"100644 workflow.yml\0".as_slice(), workflow.as_bytes()].concat();
        let tree = loose(&source, format, GitObjectKind::Tree, "tree", &tree);
        let body = format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nworkflow input\n");
        let tip = loose(&source, format, GitObjectKind::Commit, "commit", body.as_bytes());
        fs::write(source.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        let config = NodeConfig::new(temp.0.join("node"), TenantId::from_bytes([0x41;16]), RepositoryId::from_bytes([0x42;16]))
            .with_object_format(format).with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap(); serve(&mut node);
        let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(), &source, PrincipalId::from_bytes([0x43;16]), b"workflow-custody-fixture"
        )).unwrap();
        assert!(imported.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
        let before = generation(&node); let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let mut report = node.runtime().block_on(node.run_trusted_workflow_in(
            &node.request_context(), &reference, b"workflow.yml", [1;16], &temp.0,
            &[b"workflow.yml".to_vec()], (None, Some(tip)), limits()
        )).unwrap();
        assert!(report.succeeded(), "{}", report.to_json());
        assert_eq!(generation(&node), before);
        assert_eq!(report.execution.jobs.len(), 2);
        assert_eq!(report.execution.jobs[0].steps[0].observation.stdout, b"first");
        assert_eq!(report.execution.jobs[0].steps[1].observation.stdout, b"second");
        assert_eq!(report.execution.jobs[1].steps[0].observation.stdout, b"dependent");
        let saved = fs::read(report.run_directory.join("report.json")).unwrap();
        assert_eq!(saved, report.to_json().as_bytes());
        let owner_bytes = fs::read(report.run_directory.join(OWNER_FILE)).unwrap();
        let journal_bytes = fs::read(report.run_directory.join(JOURNAL_FILE)).unwrap();
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config).unwrap(); serve(&mut reopened);
        let retry = reopened.runtime().block_on(reopened.run_trusted_workflow_in(
            &reopened.request_context(), &reference, b"workflow.yml", [1;16], &temp.0,
            &[b"workflow.yml".to_vec()], (None, Some(tip)), limits()
        ));
        assert!(matches!(retry, Err(TrustedWorkflowFailure::AttemptExists(_))));
        assert_eq!(generation(&reopened), before); reopened.shutdown().unwrap();
        assert_eq!(fs::read(report.run_directory.join(OWNER_FILE)).unwrap(), owner_bytes);
        assert_eq!(fs::read(report.run_directory.join(JOURNAL_FILE)).unwrap(), journal_bytes);
        let jobs = std::mem::take(&mut report.execution.jobs);
        let prepared = prepare(&report); report.execution.jobs = jobs;
        let mut owner = FileWorkflowAttempt::open(&report.run_directory.join(OWNER_FILE), prepared.binding, None, &|| true).unwrap();
        let receipt = owner.completed_receipt().unwrap().unwrap();
        let mut journal = FileCheckJournal::open(&report.run_directory.join(JOURNAL_FILE), prepared.scope, Default::default(), Some(receipt.journal_pin()), &|| true).unwrap();
        assert_eq!(journal.pending_batches(), 3);
        let destination = Temp::new(); let mut sink = DiskSink(destination.0.clone());
        let mut outputs = Vec::new();
        while let Some(batch) = journal.next_batch().unwrap() {
            for fact in batch.facts() {
                assert_ne!(fact.conclusion, Some(CheckRunConclusion::Success));
                if let Some(id) = fact.receipt_commitment { outputs.push(journal.read_evidence(id).unwrap()); }
            }
            journal.forward_next(&mut sink, &|| true).unwrap();
        }
        assert_eq!(outputs.len(), 2);
        assert!(outputs.iter().any(|bytes| bytes.windows(10).any(|part| part == b"6669727374")));
        assert_eq!(fs::read(report.run_directory.join("report.json")).unwrap(), saved);
    }
}
