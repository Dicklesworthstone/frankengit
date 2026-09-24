//! The pure intake cases use the existing executed control-flow fixture. Native
//! publication cases use actual OneNode import, shell execution and disk authority.
use super::*;
use super::super::tests::{Temp, Executor, prepare, report};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_runner::coordinator::{CheckRunStatus, CheckRunConclusion};
use fgit_runner::coordinator::delivery::journal::FileCheckJournal;
use fgit_runner::workflow::WorkflowLimits;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId};
use crate::NodeConfig;
use super::super::TrustedWorkflowRun;
use std::fs;
use std::path::Path;

fn source_ref() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn publisher() -> PrincipalId { PrincipalId::from_bytes([0x43; 16]) }
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(publisher(), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn completed(journal: &mut FileCheckJournal) -> (CheckDeliveryBatch, usize, Vec<u8>) {
    let page = journal.read_history(None, None, 128, 1024 * 1024, &|| true).unwrap();
    for entry in page.entries() {
        let batch = entry.batch();
        for (index, fact) in batch.facts().iter().enumerate() {
            if fact.status == CheckRunStatus::Completed {
                let bytes = journal.read_evidence(fact.receipt_commitment.unwrap()).unwrap();
                return (batch.clone(), index, bytes);
            }
        }
    }
    panic!("fixture must have a completed job")
}
fn local_record() -> WorkflowCheckRecord {
    let temp = Temp::new(); let mut report = report(&temp);
    let prepared = prepare(&report);
    report.execution = prepared.execute(&temp.0, &mut Executor::new(&temp), &|| true).unwrap();
    let mut journal = FileCheckJournal::open(&temp.0.join("check-proposals.journal"),
        report.check_journal_scope(), Default::default(), None, &|| true).unwrap();
    let (batch, index, bytes) = completed(&mut journal);
    assert_eq!(batch.facts()[index].conclusion, Some(CheckRunConclusion::ActionRequired));
    let record = OneNode::workflow_check_record_from_batch(source_ref(), &batch, index, &bytes, &|| true).unwrap();
    assert!(OneNode::workflow_check_record_from_batch(source_ref(), &batch, usize::MAX, &bytes, &|| true).is_err());
    let mut corrupt = bytes.clone(); corrupt[0] ^= 1;
    assert!(OneNode::workflow_check_record_from_batch(source_ref(), &batch, index, &corrupt, &|| true).is_err());
    assert!(OneNode::workflow_check_record_from_batch(source_ref(), &batch, index, &bytes, &|| false).is_err());
    record
}

#[test]
fn lowering_uses_one_exact_completed_job_and_never_promotes_local_success() {
    let record = local_record();
    assert_eq!(record.conclusion, WorkflowCheckConclusion::ActionRequired);
    assert_eq!(record.job, "first");
    validate_record(&record, TenantId::from_bytes([1; 16]), RepositoryId::from_bytes([2; 16]), &|| true).unwrap();
}

#[test]
fn every_claimed_coordinate_and_scope_is_checked_against_the_retained_frame() {
    let record = local_record(); let tenant = TenantId::from_bytes([1; 16]); let repository = RepositoryId::from_bytes([2; 16]);
    for change in 0..7 {
        let mut bad = record.clone();
        match change {
            0 => bad.run_id[0] ^= 1,
            1 => bad.attempt_id[0] ^= 1,
            2 => bad.graph_root[0] ^= 1,
            3 => bad.job.push('x'),
            4 => bad.source_commit = GitOid::from_hex(GitHashAlgorithm::Sha1, &"ff".repeat(20)).unwrap(),
            5 => bad.conclusion = WorkflowCheckConclusion::Failure,
            _ => bad.evidence.push(0),
        }
        assert!(validate_record(&bad, tenant, repository, &|| true).is_err(), "coordinate {change}");
    }
    assert!(validate_record(&record, TenantId::from_bytes([9; 16]), repository, &|| true).is_err());
    assert!(validate_record(&record, tenant, RepositoryId::from_bytes([9; 16]), &|| true).is_err());
    assert!(validate_record(&record, tenant, repository, &|| false).is_err());
}

#[test]
fn reported_negative_states_remain_distinct_and_skips_are_not_green() {
    for (outcome, expected) in [
        (JobOutcome::Succeeded, WorkflowCheckConclusion::ActionRequired),
        (JobOutcome::Skipped, WorkflowCheckConclusion::ActionRequired),
        (JobOutcome::Failed, WorkflowCheckConclusion::Failure),
        (JobOutcome::Refused, WorkflowCheckConclusion::Failure),
        (JobOutcome::OutputLimit, WorkflowCheckConclusion::Failure),
        (JobOutcome::Cancelled, WorkflowCheckConclusion::Cancelled),
        (JobOutcome::TimedOut, WorkflowCheckConclusion::TimedOut),
    ] { assert_eq!(conclusion(outcome), expected); }
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap(); let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes()); encoded.extend((!length).to_le_bytes()); encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521; (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string(); let path = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&path).unwrap(); fs::write(path.join(&hex[2..]), encoded).unwrap(); id
}
fn serve(node: &mut OneNode) {
    let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(head.receipt().generation()).unwrap();
}
fn run_fixture(temp: &Temp, format: GitHashAlgorithm, fail: bool) -> (OneNode, NodeConfig, TrustedWorkflowRun) {
    let root = temp.0.join("source"); fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let script = if fail { "false" } else { "printf retained" };
    let source = format!("name: report\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {script}\n");
    let blob = loose(&root, format, GitObjectKind::Blob, "blob", source.as_bytes());
    let tree = loose(&root, format, GitObjectKind::Tree, "tree", &[b"100644 workflow.yml\0".as_slice(), blob.as_bytes()].concat());
    let body = format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nsource\n");
    let tip = loose(&root, format, GitObjectKind::Commit, "commit", body.as_bytes());
    fs::write(root.join("refs/heads/main"), format!("{tip}\n")).unwrap();
    let config = NodeConfig::new(temp.0.join("node"), TenantId::from_bytes([0x41; 16]), RepositoryId::from_bytes([0x42; 16]))
        .with_object_format(format).with_worker_threads(2);
    let (mut node, _) = OneNode::init(config.clone()).unwrap(); serve(&mut node);
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &node.request_context(), &root, publisher(), b"workflow-publication-source"
    )).unwrap();
    assert!(imported.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
    let run = node.runtime().block_on(node.run_trusted_workflow_in(
        &node.request_context(), &source_ref(), b"workflow.yml", [1; 16], &temp.0,
        &[b"workflow.yml".to_vec()], (None, Some(tip)), WorkflowLimits { total_output_bytes: 8192, ..Default::default() },
    )).unwrap();
    assert_eq!(run.succeeded(), !fail);
    (node, config, run)
}
fn submitted_record(run: &TrustedWorkflowRun) -> WorkflowCheckRecord {
    let mut journal = run.open_check_journal(None, &|| true).unwrap();
    let (batch, index, evidence) = completed(&mut journal);
    OneNode::workflow_check_record_from_batch(source_ref(), &batch, index, &evidence, &|| true).unwrap()
}
fn materialize(node: &OneNode) -> crate::MaterializedAdmission {
    node.runtime().block_on(node.materialize_admission_in(&node.request_context())).unwrap()
}
fn publish(node: &OneNode, record: &WorkflowCheckRecord, key: &[u8]) -> (TxId, TerminalOutcome) {
    node.runtime().block_on(node.admit_trusted_workflow_check_in(&node.request_context(), &session(key), record, Default::default())).unwrap()
}

#[test]
fn actual_publication_survives_reopen_with_exact_evidence_and_no_branch_or_policy_change() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let temp = Temp::new(); let (mut node, config, run) = run_fixture(&temp, format, false);
        let record = submitted_record(&run); let before = materialize(&node);
        let journal_before = fs::read(run.run_directory.join("check-proposals.journal")).unwrap();
        let published = publish(&node, &record, b"publish-build");
        assert!(matches!(published.1.outcome, DecisionOutcome::Committed { .. }));
        let after = materialize(&node);
        assert_eq!(after.snapshot().refs, before.snapshot().refs);
        let before_head = before.authenticated_head().body().unwrap(); let after_head = after.authenticated_head().body().unwrap();
        assert_eq!(before_head.ref_root, after_head.ref_root); assert_eq!(before_head.policy_epoch, after_head.policy_epoch);
        assert_eq!(before_head.retention_root, after_head.retention_root);
        assert_ne!(before_head.forge_position_root, after_head.forge_position_root);
        assert_ne!(before_head.outbox_root, after_head.outbox_root);
        let event = record.proposed_event(publisher(), format).unwrap();
        let fgit_forge::AggregateId::WorkflowCheck(id) = event.aggregate else { panic!("workflow aggregate") };
        let basis = PublicationBasis::new(after.authenticated_head().head_id(), after_head);
        let saved = node.runtime().block_on(workflow_checks::read_at(
            &node.authority, node.request_context().authority(), &basis, id, &|| false,
        )).unwrap().unwrap();
        assert_eq!(saved.record, record); assert_eq!(saved.actor, publisher());
        assert_eq!(saved.record.conclusion, WorkflowCheckConclusion::ActionRequired);
        assert_eq!(fs::read(run.run_directory.join("check-proposals.journal")).unwrap(), journal_before);
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config).unwrap(); serve(&mut reopened);
        let head = materialize(&reopened).authenticated_head().head_id();
        assert_eq!(publish(&reopened, &record, b"publish-build"), published);
        assert_eq!(materialize(&reopened).authenticated_head().head_id(), head);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn occupied_job_and_evidence_substitution_cannot_create_a_second_delivery() {
    let temp = Temp::new(); let (mut node, _, run) = run_fixture(&temp, GitHashAlgorithm::Sha1, false);
    let record = submitted_record(&run); let first = publish(&node, &record, b"publish-once");
    assert!(matches!(first.1.outcome, DecisionOutcome::Committed { .. }));
    let outbox = materialize(&node).authenticated_head().body().unwrap().outbox_root;
    let duplicate = publish(&node, &record, b"new-key-same-job");
    assert!(matches!(duplicate.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
    assert_eq!(materialize(&node).authenticated_head().body().unwrap().outbox_root, outbox);
    let mut bad = record.clone(); bad.job.push_str("-forged");
    let refused = publish(&node, &bad, b"bad-evidence");
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceInvalid, .. }));
    assert_eq!(publish(&node, &bad, b"bad-evidence"), refused);
    assert_eq!(materialize(&node).authenticated_head().body().unwrap().outbox_root, outbox);
    bad = record; bad.evidence.push(0);
    assert!(node.runtime().block_on(node.admit_trusted_workflow_check_in(
        &node.request_context(), &session(b"publish-once"), &bad, Default::default()
    )).is_err(), "a changed body cannot reuse the successful key");
    node.shutdown().unwrap();
}

#[test]
fn historical_retry_is_not_rewritten_when_the_current_branch_moves() {
    let temp = Temp::new(); let (mut node, _, run) = run_fixture(&temp, GitHashAlgorithm::Sha256, false);
    let record = submitted_record(&run); let first = publish(&node, &record, b"old-observation");
    let body = format!("tree {}\nparent {}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nnew source\n", run.source_tree, run.source_commit);
    let root = temp.0.join("source"); let next = loose(&root, GitHashAlgorithm::Sha256, GitObjectKind::Commit, "commit", body.as_bytes());
    fs::write(root.join("refs/heads/main"), format!("{next}\n")).unwrap();
    let update = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &node.request_context(), &root, publisher(), b"advance-workflow-source"
    )).unwrap();
    assert!(update.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
    let moved = materialize(&node).authenticated_head().head_id();
    assert_eq!(publish(&node, &record, b"old-observation"), first);
    assert_eq!(materialize(&node).authenticated_head().head_id(), moved);
    let stale = publish(&node, &record, b"new-request-old-source");
    assert!(matches!(stale.1.outcome, DecisionOutcome::Refused { code: RefusalCode::TargetRefMoved, .. }));
    assert_eq!(materialize(&node).snapshot().refs.get(&source_ref()), Some(&next));
    node.shutdown().unwrap();
}

#[test]
fn actual_failed_job_is_recorded_as_failure_without_a_green_conclusion() {
    let temp = Temp::new(); let (mut node, _, run) = run_fixture(&temp, GitHashAlgorithm::Sha1, true);
    let record = submitted_record(&run); assert_eq!(record.conclusion, WorkflowCheckConclusion::Failure);
    assert!(matches!(publish(&node, &record, b"failed-job").1.outcome, DecisionOutcome::Committed { .. }));
    assert_eq!(materialize(&node).snapshot().refs.get(&source_ref()), Some(&run.source_commit));
    node.shutdown().unwrap();
}
