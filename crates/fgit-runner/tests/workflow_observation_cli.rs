#![forbid(unsafe_code)]
#![cfg(unix)]
//! Real command-process readback of a journal produced by the actual coordinator.
//! Worker observations are explicit fixtures, not claims about OS isolation.
use fgit_runner::coordinator::delivery::journal::{
    CheckJournalLimits, CheckJournalScope, FileCheckJournal,
};
use fgit_runner::coordinator::delivery::{CheckDeliverySink, MAX_BATCH_BYTES, MAX_BATCH_FACTS};
use fgit_runner::workflow::{
    StepLimits, StepObservation, StepOutcome, WorkerFailure, WorkflowExecutor, WorkflowLimits,
    WorkflowPlan,
};
use fgit_runner::{
    CheckRunStatus, Commitment, CoordinatorLimits, ResourceCeilings, TriggerContext,
    WorkflowCoordinator,
};
use fgit_types::{GitOid, GitOidSha1, GitOidSha256, RepositoryId, TenantId};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-inspect-command-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Worker;
impl WorkflowExecutor for Worker {
    fn begin_job(
        &mut self,
        _: usize,
        _: &fgit_runner::workflow::WorkflowJob,
        _: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        Ok(())
    }
    fn execute_step(
        &mut self,
        _: usize,
        _: &str,
        _: StepLimits,
        _: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        Ok(StepObservation {
            outcome: StepOutcome::Succeeded,
            exit_code: Some(0),
            stdout: vec![0, 255, 27],
            stderr: Vec::new(),
            elapsed_millis: 1,
            output_complete: true,
            retain_workspace: false,
        })
    }
    fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> {
        Ok(())
    }
}
fn hex(root: Commitment) -> String {
    root.digest()
        .bytes()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn command_reads_saved_binary_output_and_never_changes_the_journal() {
    for sha256 in [false, true] {
        let temp = Temp::new();
        let path = temp.0.join("checks");
        let tenant = TenantId::from_bytes([1; 16]);
        let repository = RepositoryId::from_bytes([2; 16]);
        let scope = CheckJournalScope {
            tenant,
            repository,
            journal_id: Commitment::of_bytes(b"CLI fixture"),
        };
        let mut coordinator = WorkflowCoordinator::new(
            CoordinatorLimits::default(),
            ResourceCeilings::new(
                100_000,
                512 * 1024 * 1024,
                1024 * 1024 * 1024,
                0,
                16,
                60_000,
            )
            .unwrap(),
            4,
        )
        .unwrap();
        let source = if sha256 {
            GitOid::Sha256(GitOidSha256::from_bytes([3; 32]))
        } else {
            GitOid::Sha1(GitOidSha1::from_bytes([3; 20]))
        };
        let plan=WorkflowPlan::compile("name: inspect\non: push\njobs:\n  only:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: fixture\n").unwrap();
        let mut prepared = coordinator
            .enqueue_trusted_workflow(
                tenant,
                repository,
                Commitment::of_bytes(b"head"),
                source,
                plan,
                WorkflowLimits::default(),
                TriggerContext::trusted_push("fixture"),
                1,
                0,
            )
            .unwrap();
        let receipt = coordinator
            .execute_trusted_workflow(&mut prepared, &mut Worker, 1, &|| true)
            .unwrap()
            .clone();
        let batch = coordinator
            .prepare_check_delivery(MAX_BATCH_FACTS, MAX_BATCH_BYTES)
            .unwrap()
            .unwrap();
        let index = batch
            .facts()
            .iter()
            .position(|fact| fact.status == CheckRunStatus::Completed)
            .unwrap();
        let mut journal =
            FileCheckJournal::create(&path, scope, CheckJournalLimits::default()).unwrap();
        for fact in batch.facts() {
            if let Some(root) = fact.receipt_commitment {
                journal
                    .store_evidence(root, &receipt.job_frame(&fact.job_id).unwrap())
                    .unwrap();
            }
        }
        journal.accept(&batch).unwrap();
        let pin = journal.pin();
        drop(journal);
        drop(receipt);
        drop(prepared);
        drop(coordinator);
        let before = fs::read(&path).unwrap();
        let args = [
            "01".repeat(16),
            "02".repeat(16),
            hex(scope.journal_id),
            hex(batch.id()),
            index.to_string(),
            "--minimum".into(),
            pin.byte_len().to_string(),
            hex(pin.tail()),
        ];
        let output = Command::new(env!("CARGO_BIN_EXE_fgit-workflow-inspect"))
            .arg(&path)
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json = String::from_utf8(output.stdout).unwrap();
        assert!(json.contains("\"authoritative_check\":false"));
        assert!(json.contains("\"stdout_hex\":\"00ff1b\""));
        assert!(!json.as_bytes().contains(&27));
        assert!(json.contains(&format!(
            "\"evidence\":\"{}\"",
            batch.facts()[index].receipt_commitment.unwrap()
        )));
        assert_eq!(fs::read(&path).unwrap(), before);
        let mut wrong = args.clone();
        wrong[0] = "09".repeat(16);
        let refusal = Command::new(env!("CARGO_BIN_EXE_fgit-workflow-inspect"))
            .arg(&path)
            .args(wrong)
            .output()
            .unwrap();
        assert!(!refusal.status.success());
        assert!(refusal.stdout.is_empty());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}
