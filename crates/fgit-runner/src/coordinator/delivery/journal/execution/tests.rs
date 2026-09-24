//! Real private-file custody tests with fixture execution. No hostile sandbox
//! or canonical forge-admission claim; the process-exit case is named explicitly.
use super::*;
use crate::coordinator::delivery::CheckDeliveryAcknowledgement;
use crate::coordinator::delivery::journal::{
    CheckJournalLimits, CheckJournalScope, HEADER_BYTES, frame_hash,
};
use crate::workflow::{
    JobReport, StepLimits, StepObservation, StepOutcome, WorkerFailure, WorkflowLimits,
    WorkflowPlan,
};
use crate::{CheckRunFact, CoordinatorLimits, ResourceCeilings, TriggerContext};
use fgit_types::GitOidSha1;
use fgit_types::{GitOid, RepositoryId, TenantId};
use std::cell::Cell;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const SOURCE: &str = "name: durable\non: push\njobs:\n  first:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo first\n  second:\n    runs-on: fgit-trusted-local\n    needs: first\n    steps:\n      - run: echo second\n";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-journal-execution-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn journal(&self) -> PathBuf {
        self.0.join("checks")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn scope() -> CheckJournalScope {
    CheckJournalScope {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        journal_id: Commitment::of_bytes(b"execution-test-instance"),
    }
}
fn prepared() -> (WorkflowCoordinator, PreparedTrustedWorkflow) {
    prepared_sequence(1)
}
fn prepared_sequence(sequence: u64) -> (WorkflowCoordinator, PreparedTrustedWorkflow) {
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
    let prepared = coordinator
        .enqueue_trusted_workflow(
            scope().tenant,
            scope().repository,
            Commitment::of_bytes(b"head"),
            GitOid::Sha1(GitOidSha1::from_bytes([3; 20])),
            WorkflowPlan::compile(SOURCE).unwrap(),
            WorkflowLimits::default(),
            TriggerContext::trusted_push("alice"),
            sequence,
            100,
        )
        .unwrap();
    (coordinator, prepared)
}
fn journal(directory: &Directory, records: usize) -> FileCheckJournal {
    FileCheckJournal::create(
        &directory.journal(),
        scope(),
        CheckJournalLimits {
            records,
            ..CheckJournalLimits::default()
        },
    )
    .unwrap()
}
fn facts(path: &Path) -> Vec<CheckRunFact> {
    let bytes = fs::read(path).unwrap();
    let mut previous = Commitment::of_bytes(&bytes[..HEADER_BYTES as usize]);
    let mut offset = HEADER_BYTES as usize;
    let mut facts = Vec::new();
    while offset < bytes.len() {
        let count = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let payload = &bytes[offset + 4..offset + 4 + count];
        let hash = frame_hash(previous, payload);
        assert_eq!(
            hash.digest().bytes().as_bytes(),
            &bytes[offset + 4 + count..offset + 36 + count]
        );
        if payload[0] == 1 {
            facts.extend(CheckDeliveryBatch::decode(&payload[1..]).unwrap().facts);
        }
        previous = hash;
        offset += count + 36;
    }
    facts
}
/// One injected executor interruption; each test exercises at most one.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ExecutorFault {
    /// Panic after the durable launch intent, before the job begins.
    PanicOnBegin,
    /// Exit the whole process inside a step.
    ExitInStep,
    /// Panic in the observer after custody recorded the job.
    PanicOnObserve,
}
struct Executor<'a> {
    path: PathBuf,
    begun: Vec<String>,
    cancel_on_close: Option<&'a Cell<bool>>,
    fault: Option<ExecutorFault>,
    check_disk: bool,
}
impl Executor<'_> {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            begun: Vec::new(),
            cancel_on_close: None,
            fault: None,
            check_disk: true,
        }
    }
}
impl WorkflowExecutor for Executor<'_> {
    fn begin_job(
        &mut self,
        _: usize,
        job: &fgit_schema::workflow::Job,
        _: &dyn Fn() -> bool,
    ) -> Result<(), WorkerFailure> {
        if self.check_disk {
            let stored = facts(&self.path);
            assert!(
                stored
                    .iter()
                    .any(|fact| fact.job_id == job.id && fact.status == CheckRunStatus::InProgress)
            );
            if job.id == "second" {
                assert!(
                    stored
                        .iter()
                        .any(|fact| fact.job_id == "first"
                            && fact.status == CheckRunStatus::Completed)
                );
            }
        }
        self.begun.push(job.id.clone());
        assert!(
            self.fault != Some(ExecutorFault::PanicOnBegin),
            "uncertain begin after durable launch intent"
        );
        Ok(())
    }
    fn execute_step(
        &mut self,
        _: usize,
        _: &str,
        _: StepLimits,
        _: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        if self.fault == Some(ExecutorFault::ExitInStep) {
            std::process::exit(86);
        }
        Ok(StepObservation {
            outcome: StepOutcome::Succeeded,
            exit_code: Some(0),
            stdout: b"actual fixture output".to_vec(),
            stderr: Vec::new(),
            elapsed_millis: 1,
            output_complete: true,
            retain_workspace: false,
        })
    }
    fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> {
        if let Some(live) = self.cancel_on_close {
            live.set(false);
        }
        Ok(())
    }
    fn observe_job(&mut self, report: &JobReport) {
        assert!(
            self.fault != Some(ExecutorFault::PanicOnObserve),
            "observer interruption after custody"
        );
        // Completed readback is asserted only on the clean path. A deliberate
        // journal failure must still let the interpreter finish cancellation.
        if self.check_disk && report.outcome == JobOutcome::Succeeded {
            assert!(
                facts(&self.path).iter().any(
                    |fact| fact.job_id == report.id && fact.status == CheckRunStatus::Completed
                )
            );
        }
    }
}

#[test]
fn launch_is_synced_before_scope_and_each_result_before_the_next_job() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    let receipt = coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true,
        )
        .unwrap();
    assert!(receipt.report().succeeded());
    assert_eq!(executor.begun, ["first", "second"]);
    for job in &receipt.report().jobs {
        let root = receipt.job_commitment(&job.id).unwrap();
        assert_eq!(
            custody.read_evidence(root).unwrap(),
            receipt.job_frame(&job.id).unwrap()
        );
    }
    let stored = facts(&dir.journal());
    assert_eq!(stored.len(), 6);
    assert!(
        stored
            .iter()
            .filter(|f| f.status == CheckRunStatus::Completed)
            .all(|f| f.conclusion == Some(CheckRunConclusion::ActionRequired))
    );
    assert_eq!(coordinator.pending_check_fact_count(), 0);
    coordinator.verify_quiescence().unwrap();
}

#[test]
fn completed_repeat_verifies_custody_without_reexecution_or_append() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    let root = coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true,
        )
        .unwrap()
        .commitment();
    let pin = custody.pin();
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                999,
                &|| true
            )
            .unwrap()
            .commitment(),
        root
    );
    assert_eq!(custody.pin(), pin);
    assert_eq!(executor.begun.len(), 2);
}

#[test]
fn full_queue_custody_refuses_before_any_executor_scope() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 1);
    let pin = custody.pin();
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::JournalFull
        ))
    );
    assert!(executor.begun.is_empty());
    assert_eq!(custody.pin(), pin);
    assert_eq!(coordinator.obligations().workflow_scopes_opened, 0);
    // Explicit durable selection cannot silently fall back after failed I/O.
    assert!(
        coordinator
            .execute_trusted_workflow(&mut workflow, &mut executor, 200, &|| true)
            .is_err()
    );
    assert!(executor.begun.is_empty());
}

#[test]
fn full_launch_barrier_never_opens_a_scope_and_retains_a_retryable_report() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 4);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    executor.check_disk = false;
    assert!(matches!(
        coordinator.execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true
        ),
        Err(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::JournalFull
        ))
    ));
    assert!(executor.begun.is_empty());
    assert_eq!(coordinator.obligations().workflow_scopes_opened, 0);
    assert!(workflow.receipt().is_some());
    assert!(
        facts(&dir.journal())
            .iter()
            .all(|f| f.status == CheckRunStatus::Queued)
    );
}

#[test]
fn result_capacity_failure_stops_later_jobs_and_reopen_retries_only_custody() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 6);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    executor.check_disk = false;
    assert!(matches!(
        coordinator.execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true
        ),
        Err(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::JournalFull
        ))
    ));
    assert_eq!(executor.begun, ["first"]);
    let receipt = workflow.receipt().unwrap();
    assert_eq!(receipt.report().jobs[0].outcome, JobOutcome::Succeeded);
    assert_eq!(receipt.report().jobs[1].outcome, JobOutcome::Cancelled);
    let root = receipt.commitment();
    let pin = custody.pin();
    drop(custody);
    let mut custody = FileCheckJournal::open(
        &dir.journal(),
        scope(),
        CheckJournalLimits::default(),
        Some(pin),
        &|| true,
    )
    .unwrap();
    let receipt = coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            300,
            &|| true,
        )
        .unwrap();
    assert_eq!(receipt.commitment(), root);
    assert_eq!(executor.begun, ["first"]);
    assert_eq!(coordinator.pending_check_fact_count(), 0);
    coordinator.verify_quiescence().unwrap();
}

#[test]
fn observer_unwind_cannot_erase_the_already_cleaned_up_job_result() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    executor.fault = Some(ExecutorFault::PanicOnObserve);
    assert!(matches!(
        coordinator.execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true
        ),
        Err(JournaledWorkflowRefusal::Coordinator(
            CoordinatorRefusal::ContainmentFailure(_)
        ))
    ));
    assert_eq!(executor.begun, ["first"]);
    assert!(
        facts(&dir.journal())
            .iter()
            .any(|f| f.job_id == "first" && f.status == CheckRunStatus::Completed)
    );
    let pin = custody.pin();
    drop(custody);
    drop(coordinator);
    drop(workflow);
    let mut custody = FileCheckJournal::open(
        &dir.journal(),
        scope(),
        CheckJournalLimits::default(),
        Some(pin),
        &|| true,
    )
    .unwrap();
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::StaleBatch
        ))
    );
    assert!(executor.begun.is_empty());
}

#[test]
fn delivered_history_still_fences_a_recreated_execution_handle() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true,
        )
        .unwrap();
    while let Some(batch) = custody.next_batch().unwrap() {
        custody
            .record_delivery(CheckDeliveryAcknowledgement::after_durable_acceptance(
                &batch,
                Commitment::of_bytes(b"fixture downstream custody"),
            ))
            .unwrap();
    }
    assert_eq!(custody.pending_batches(), 0);
    let pin = custody.pin();
    drop(custody);
    drop(coordinator);
    drop(workflow);
    let mut custody = FileCheckJournal::open(
        &dir.journal(),
        scope(),
        CheckJournalLimits::default(),
        Some(pin),
        &|| true,
    )
    .unwrap();
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                300,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::StaleBatch
        ))
    );
    assert!(executor.begun.is_empty());
    assert_eq!(custody.pin(), pin);
}

#[test]
fn cancellation_before_start_does_not_write_or_launch() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let pin = custody.pin();
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| false
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::Cancelled
        ))
    );
    assert_eq!(custody.pin(), pin);
    assert!(executor.begun.is_empty());
    coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true,
        )
        .unwrap();
    assert_eq!(executor.begun.len(), 2);
}

#[test]
fn cancellation_during_cleanup_still_persists_all_terminal_observations() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let live = Cell::new(true);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    executor.cancel_on_close = Some(&live);
    let receipt = coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| live.get(),
        )
        .unwrap();
    assert!(
        receipt
            .report()
            .jobs
            .iter()
            .all(|job| job.outcome == JobOutcome::Cancelled)
    );
    assert_eq!(executor.begun, ["first"]);
    assert_eq!(
        facts(&dir.journal())
            .iter()
            .filter(|f| f.status == CheckRunStatus::Completed)
            .count(),
        2
    );
    coordinator.verify_quiescence().unwrap();
}

#[test]
fn volatile_completed_execution_cannot_be_relabelled_as_launch_journaled() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let pin = custody.pin();
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    executor.check_disk = false;
    coordinator
        .execute_trusted_workflow(&mut workflow, &mut executor, 200, &|| true)
        .unwrap();
    assert!(matches!(
        coordinator.execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true
        ),
        Err(JournaledWorkflowRefusal::Coordinator(
            CoordinatorRefusal::UnsupportedExecution { .. }
        ))
    ));
    assert_eq!(custody.pin(), pin);
    assert_eq!(executor.begun.len(), 2);
}

#[test]
fn empty_replacement_journal_cannot_certify_a_retained_completed_receipt() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true,
        )
        .unwrap();
    let mut empty =
        FileCheckJournal::create(&dir.0.join("empty"), scope(), CheckJournalLimits::default())
            .unwrap();
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut empty,
                200,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::EvidenceMissing
        ))
    );
    assert_eq!(executor.begun.len(), 2);
}

#[test]
fn unrelated_pending_run_and_wrong_repository_are_refused_without_custody_transfer() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let pin = custody.pin();
    let (mut coordinator, mut workflow) = prepared();
    coordinator
        .enqueue_trusted_workflow(
            scope().tenant,
            scope().repository,
            Commitment::of_bytes(b"head"),
            GitOid::Sha1(GitOidSha1::from_bytes([3; 20])),
            WorkflowPlan::compile(SOURCE).unwrap(),
            WorkflowLimits::default(),
            TriggerContext::trusted_push("alice"),
            2,
            100,
        )
        .unwrap();
    let mut executor = Executor::new(dir.journal());
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::OutOfOrder
        ))
    );
    assert_eq!(custody.pin(), pin);
    assert!(executor.begun.is_empty());
    let (mut coordinator, mut workflow) = prepared();
    let mut foreign = FileCheckJournal::create(
        &dir.0.join("foreign"),
        CheckJournalScope {
            repository: RepositoryId::from_bytes([9; 16]),
            ..scope()
        },
        CheckJournalLimits::default(),
    )
    .unwrap();
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut foreign,
                200,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::ScopeMismatch
        ))
    );
    // A scope rejection must not pin the handle to the wrong journal.
    coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true,
        )
        .unwrap();
}

#[test]
fn corrupted_completed_record_is_not_hidden_by_an_in_memory_receipt() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true,
        )
        .unwrap();
    let mut f = OpenOptions::new().write(true).open(dir.journal()).unwrap();
    let original = fs::read(dir.journal()).unwrap();
    f.seek(SeekFrom::End(-1)).unwrap();
    f.write_all(&[original[original.len() - 1] ^ 1]).unwrap();
    f.sync_all().unwrap();
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::CorruptJournal
        ))
    );
    assert!(custody.is_failed());
    assert_eq!(executor.begun.len(), 2);
}

// Helper invoked only by the process-exit test below. Normal test discovery
// does not terminate the harness or manufacture a crash-recovery pass.
#[test]
fn process_exit_child() {
    let Some(directory) = std::env::var_os("FGIT_JOURNALED_WORKFLOW_EXIT_CHILD") else {
        return;
    };
    let path = PathBuf::from(directory).join("checks");
    let mut custody =
        FileCheckJournal::create(&path, scope(), CheckJournalLimits::default()).unwrap();
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(path);
    executor.fault = Some(ExecutorFault::ExitInStep);
    let _ = coordinator.execute_journaled_trusted_workflow(
        &mut workflow,
        &mut executor,
        &mut custody,
        200,
        &|| true,
    );
    panic!("child must exit from the executor, not return");
}

#[test]
fn actual_process_exit_releases_lock_but_not_the_durable_launch_fence() {
    let dir = Directory::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "coordinator::delivery::journal::execution::tests::process_exit_child",
            "--nocapture",
        ])
        .env("FGIT_JOURNALED_WORKFLOW_EXIT_CHILD", &dir.0)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(86));
    let mut custody = FileCheckJournal::open(
        &dir.journal(),
        scope(),
        CheckJournalLimits::default(),
        None,
        &|| true,
    )
    .unwrap();
    let stored = facts(&dir.journal());
    assert_eq!(
        stored
            .iter()
            .filter(|f| f.status == CheckRunStatus::InProgress)
            .count(),
        1
    );
    assert!(!stored.iter().any(|f| f.status == CheckRunStatus::Completed));
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::StaleBatch
        ))
    );
    assert!(executor.begun.is_empty());
    assert_eq!(
        fs::metadata(dir.journal()).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn a_different_known_inflight_run_blocks_fresh_coordinator_work() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    executor.fault = Some(ExecutorFault::PanicOnBegin);
    assert!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| true
            )
            .is_err()
    );
    assert_eq!(executor.begun, ["first"]);
    assert!(
        facts(&dir.journal())
            .iter()
            .any(|f| f.status == CheckRunStatus::InProgress)
    );
    let pin = custody.pin();
    drop(coordinator);
    drop(workflow);
    drop(custody);
    let mut custody = FileCheckJournal::open(
        &dir.journal(),
        scope(),
        CheckJournalLimits::default(),
        Some(pin),
        &|| true,
    )
    .unwrap();
    let (mut coordinator, mut workflow) = prepared_sequence(2);
    let mut executor = Executor::new(dir.journal());
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::OutOfOrder
        ))
    );
    assert!(executor.begun.is_empty());
    assert_eq!(custody.pin(), pin);
}

#[test]
fn failed_launch_selection_cannot_fall_back_to_existing_per_job_journaling() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 1);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    assert!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| true
            )
            .is_err()
    );
    let pin = custody.pin();
    drop(custody);
    let mut custody = FileCheckJournal::open(
        &dir.journal(),
        scope(),
        CheckJournalLimits::default(),
        Some(pin),
        &|| true,
    )
    .unwrap();
    assert!(matches!(
        coordinator.execute_trusted_workflow_journaled(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true
        ),
        Err(CoordinatorRefusal::UnsupportedExecution { .. })
    ));
    assert_eq!(custody.pin(), pin);
    assert!(executor.begun.is_empty());
    coordinator
        .execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true,
        )
        .unwrap();
    assert_eq!(executor.begun, ["first", "second"]);
}

#[test]
fn existing_per_job_execution_is_preserved_but_cannot_be_relabelled_launch_fenced() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    executor.check_disk = false;
    let root = coordinator
        .execute_trusted_workflow_journaled(
            &mut workflow,
            &mut executor,
            &mut custody,
            200,
            &|| true,
        )
        .unwrap()
        .commitment();
    let pin = custody.pin();
    assert_eq!(
        coordinator
            .execute_trusted_workflow_journaled(
                &mut workflow,
                &mut executor,
                &mut custody,
                201,
                &|| false
            )
            .unwrap()
            .commitment(),
        root
    );
    assert!(matches!(
        coordinator.execute_journaled_trusted_workflow(
            &mut workflow,
            &mut executor,
            &mut custody,
            201,
            &|| true
        ),
        Err(JournaledWorkflowRefusal::Coordinator(
            CoordinatorRefusal::UnsupportedExecution { .. }
        ))
    ));
    assert_eq!(executor.begun, ["first", "second"]);
    assert_eq!(custody.pin(), pin);
}

#[test]
fn a_legacy_drained_queue_cannot_be_interpreted_as_persisted_launch_admission() {
    let dir = Directory::new();
    let mut custody = journal(&dir, 100);
    let (mut coordinator, mut workflow) = prepared();
    let mut executor = Executor::new(dir.journal());
    assert_eq!(coordinator.drain_check_facts().len(), 2);
    let pin = custody.pin();
    assert_eq!(
        coordinator
            .execute_journaled_trusted_workflow(
                &mut workflow,
                &mut executor,
                &mut custody,
                200,
                &|| true
            )
            .err(),
        Some(JournaledWorkflowRefusal::Custody(
            CheckDeliveryRefusal::EvidenceMissing
        ))
    );
    assert!(executor.begun.is_empty());
    assert_eq!(custody.pin(), pin);
}
