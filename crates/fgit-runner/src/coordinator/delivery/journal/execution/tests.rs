//! Real private-file custody tests with fixture execution. No hostile sandbox
//! or canonical forge-admission claim; the process-exit case is named explicitly.
use super::*;
use crate::workflow::{JobReport, StepLimits, StepObservation, StepOutcome, WorkerFailure, WorkflowLimits, WorkflowPlan};
use fgit_types::GitOidSha1;
use std::cell::Cell;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const SOURCE: &str = "name: durable\non: push\njobs:\n  first:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo first\n  second:\n    runs-on: fgit-trusted-local\n    needs: first\n    steps:\n      - run: echo second\n";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fgit-journal-execution-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn journal(&self) -> PathBuf { self.0.join("checks") }
}
impl Drop for Directory {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
fn scope() -> CheckJournalScope {
    CheckJournalScope { tenant: TenantId::from_bytes([1; 16]), repository: RepositoryId::from_bytes([2; 16]),
        journal_id: Commitment::of_bytes(b"execution-test-instance") }
}
fn prepared() -> (WorkflowCoordinator, PreparedTrustedWorkflow) { prepared_sequence(1) }
fn prepared_sequence(sequence: u64) -> (WorkflowCoordinator, PreparedTrustedWorkflow) {
    let mut coordinator = WorkflowCoordinator::new(CoordinatorLimits::default(),
        ResourceCeilings::new(100_000, 512 * 1024 * 1024, 1024 * 1024 * 1024, 0, 16, 60_000).unwrap(), 4).unwrap();
    let prepared = coordinator.enqueue_trusted_workflow(scope().tenant, scope().repository,
        Commitment::of_bytes(b"head"), GitOid::Sha1(GitOidSha1::from_bytes([3; 20])),
        WorkflowPlan::compile(SOURCE).unwrap(), WorkflowLimits::default(),
        TriggerContext::trusted_push("alice"), sequence, 100).unwrap();
    (coordinator, prepared)
}
fn journal(directory: &Directory, records: usize) -> FileCheckJournal {
    FileCheckJournal::create(&directory.journal(), scope(),
        CheckJournalLimits { records, ..CheckJournalLimits::default() }).unwrap()
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
        assert_eq!(hash.digest().bytes().as_bytes(), &bytes[offset + 4 + count..offset + 36 + count]);
        if payload[0] == 1 { facts.extend(CheckDeliveryBatch::decode(&payload[1..]).unwrap().facts); }
        previous = hash;
        offset += count + 36;
    }
    facts
}
struct Executor<'a> {
    path: PathBuf,
    begun: Vec<String>,
    cancel_on_close: Option<&'a Cell<bool>>,
    panic_on_observe: bool,
    panic_on_begin: bool,
    check_disk: bool,
    exit_in_step: bool,
}
impl Executor<'_> {
    fn new(path: PathBuf) -> Self {
        Self { path, begun: Vec::new(), cancel_on_close: None, panic_on_observe: false, panic_on_begin: false,
            check_disk: true, exit_in_step: false }
    }
}
impl WorkflowExecutor for Executor<'_> {
    fn begin_job(&mut self, _: usize, job: &fgit_schema::workflow::Job, _: &dyn Fn() -> bool)
        -> Result<(), WorkerFailure>
    {
        if self.check_disk {
            let stored = facts(&self.path);
            assert!(stored.iter().any(|fact| fact.job_id == job.id && fact.status == CheckRunStatus::InProgress));
            if job.id == "second" {
                assert!(stored.iter().any(|fact| fact.job_id == "first" && fact.status == CheckRunStatus::Completed));
            }
        }
        self.begun.push(job.id.clone());
        if self.panic_on_begin { panic!("uncertain begin after durable launch intent"); }
        Ok(())
    }
    fn execute_step(&mut self, _: usize, _: &str, _: StepLimits, _: &dyn Fn() -> bool)
        -> Result<StepObservation, WorkerFailure>
    {
        if self.exit_in_step { std::process::exit(86); }
        Ok(StepObservation { outcome: StepOutcome::Succeeded, exit_code: Some(0),
            stdout: b"actual fixture output".to_vec(), stderr: Vec::new(), elapsed_millis: 1,
            output_complete: true, retain_workspace: false })
    }
    fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> {
        if let Some(live) = self.cancel_on_close { live.set(false); }
        Ok(())
    }
    fn observe_job(&mut self, report: &JobReport) {
        if self.panic_on_observe { panic!("observer interruption after custody"); }
        // Completed readback is asserted only on the clean path. A deliberate
        // journal failure must still let the interpreter finish cancellation.
        if self.check_disk && report.outcome == JobOutcome::Succeeded {
            assert!(facts(&self.path).iter().any(|fact| fact.job_id == report.id && fact.status == CheckRunStatus::Completed));
        }
    }
}

#[test]
fn launch_is_synced_before_scope_and_each_result_before_the_next_job() {
    let d = Directory::new(); let mut j = journal(&d, 100);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    let r = c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).unwrap();
    assert!(r.report().succeeded());
    assert_eq!(e.begun, ["first", "second"]);
    for job in &r.report().jobs {
        let root = r.job_commitment(&job.id).unwrap();
        assert_eq!(j.read_evidence(root).unwrap(), r.job_frame(&job.id).unwrap());
    }
    let stored = facts(&d.journal());
    assert_eq!(stored.len(), 6);
    assert!(stored.iter().filter(|f| f.status == CheckRunStatus::Completed)
        .all(|f| f.conclusion == Some(CheckRunConclusion::ActionRequired)));
    assert_eq!(c.pending_check_fact_count(), 0);
    c.verify_quiescence().unwrap();
}

#[test]
fn completed_repeat_verifies_custody_without_reexecution_or_append() {
    let d = Directory::new(); let mut j = journal(&d, 100);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    let root = c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).unwrap().commitment();
    let pin = j.pin();
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 999, &|| true).unwrap().commitment(), root);
    assert_eq!(j.pin(), pin); assert_eq!(e.begun.len(), 2);
}

#[test]
fn full_queue_custody_refuses_before_any_executor_scope() {
    let d = Directory::new(); let mut j = journal(&d, 1);
    let pin = j.pin(); let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::JournalFull)));
    assert!(e.begun.is_empty()); assert_eq!(j.pin(), pin);
    assert_eq!(c.obligations().workflow_scopes_opened, 0);
    // Explicit durable selection cannot silently fall back after failed I/O.
    assert!(c.execute_trusted_workflow(&mut p, &mut e, 200, &|| true).is_err());
    assert!(e.begun.is_empty());
}

#[test]
fn full_launch_barrier_never_opens_a_scope_and_retains_a_retryable_report() {
    let d = Directory::new(); let mut j = journal(&d, 4);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal()); e.check_disk = false;
    assert!(matches!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true),
        Err(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::JournalFull))));
    assert!(e.begun.is_empty()); assert_eq!(c.obligations().workflow_scopes_opened, 0);
    assert!(p.receipt().is_some());
    assert!(facts(&d.journal()).iter().all(|f| f.status == CheckRunStatus::Queued));
}

#[test]
fn result_capacity_failure_stops_later_jobs_and_reopen_retries_only_custody() {
    let d = Directory::new(); let mut j = journal(&d, 6);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal()); e.check_disk = false;
    assert!(matches!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true),
        Err(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::JournalFull))));
    assert_eq!(e.begun, ["first"]);
    let r = p.receipt().unwrap();
    assert_eq!(r.report().jobs[0].outcome, JobOutcome::Succeeded);
    assert_eq!(r.report().jobs[1].outcome, JobOutcome::Cancelled);
    let root = r.commitment(); let pin = j.pin(); drop(j);
    let mut j = FileCheckJournal::open(&d.journal(), scope(), CheckJournalLimits::default(), Some(pin), &|| true).unwrap();
    let r = c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 300, &|| true).unwrap();
    assert_eq!(r.commitment(), root); assert_eq!(e.begun, ["first"]);
    assert_eq!(c.pending_check_fact_count(), 0); c.verify_quiescence().unwrap();
}

#[test]
fn observer_unwind_cannot_erase_the_already_cleaned_up_job_result() {
    let d = Directory::new(); let mut j = journal(&d, 100);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal()); e.panic_on_observe = true;
    assert!(matches!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true),
        Err(JournaledWorkflowRefusal::Coordinator(CoordinatorRefusal::ContainmentFailure(_)))));
    assert_eq!(e.begun, ["first"]);
    assert!(facts(&d.journal()).iter().any(|f| f.job_id == "first" && f.status == CheckRunStatus::Completed));
    let pin = j.pin(); drop(j); drop(c); drop(p);
    let mut j = FileCheckJournal::open(&d.journal(), scope(), CheckJournalLimits::default(), Some(pin), &|| true).unwrap();
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::StaleBatch)));
    assert!(e.begun.is_empty());
}

#[test]
fn delivered_history_still_fences_a_recreated_execution_handle() {
    let d = Directory::new(); let mut j = journal(&d, 100);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).unwrap();
    while let Some(batch) = j.next_batch().unwrap() {
        j.record_delivery(CheckDeliveryAcknowledgement::after_durable_acceptance(&batch,
            Commitment::of_bytes(b"fixture downstream custody"))).unwrap();
    }
    assert_eq!(j.pending_batches(), 0); let pin = j.pin(); drop(j); drop(c); drop(p);
    let mut j = FileCheckJournal::open(&d.journal(), scope(), CheckJournalLimits::default(), Some(pin), &|| true).unwrap();
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 300, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::StaleBatch)));
    assert!(e.begun.is_empty()); assert_eq!(j.pin(), pin);
}

#[test]
fn cancellation_before_start_does_not_write_or_launch() {
    let d = Directory::new(); let mut j = journal(&d, 100); let pin = j.pin();
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| false).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::Cancelled)));
    assert_eq!(j.pin(), pin); assert!(e.begun.is_empty());
    c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).unwrap();
    assert_eq!(e.begun.len(), 2);
}

#[test]
fn cancellation_during_cleanup_still_persists_all_terminal_observations() {
    let d = Directory::new(); let mut j = journal(&d, 100); let live = Cell::new(true);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal()); e.cancel_on_close = Some(&live);
    let r = c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| live.get()).unwrap();
    assert!(r.report().jobs.iter().all(|job| job.outcome == JobOutcome::Cancelled));
    assert_eq!(e.begun, ["first"]);
    assert_eq!(facts(&d.journal()).iter().filter(|f| f.status == CheckRunStatus::Completed).count(), 2);
    c.verify_quiescence().unwrap();
}

#[test]
fn volatile_completed_execution_cannot_be_relabelled_as_launch_journaled() {
    let d = Directory::new(); let mut j = journal(&d, 100); let pin = j.pin();
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal()); e.check_disk = false;
    c.execute_trusted_workflow(&mut p, &mut e, 200, &|| true).unwrap();
    assert!(matches!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true),
        Err(JournaledWorkflowRefusal::Coordinator(CoordinatorRefusal::UnsupportedExecution { .. }))));
    assert_eq!(j.pin(), pin); assert_eq!(e.begun.len(), 2);
}

#[test]
fn empty_replacement_journal_cannot_certify_a_retained_completed_receipt() {
    let d = Directory::new(); let mut j = journal(&d, 100);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).unwrap();
    let mut empty = FileCheckJournal::create(&d.0.join("empty"), scope(), CheckJournalLimits::default()).unwrap();
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut empty, 200, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::EvidenceMissing)));
    assert_eq!(e.begun.len(), 2);
}

#[test]
fn unrelated_pending_run_and_wrong_repository_are_refused_without_custody_transfer() {
    let d = Directory::new(); let mut j = journal(&d, 100); let pin = j.pin();
    let (mut c, mut p) = prepared();
    c.enqueue_trusted_workflow(scope().tenant, scope().repository, Commitment::of_bytes(b"head"),
        GitOid::Sha1(GitOidSha1::from_bytes([3; 20])), WorkflowPlan::compile(SOURCE).unwrap(),
        WorkflowLimits::default(), TriggerContext::trusted_push("alice"), 2, 100).unwrap();
    let mut e = Executor::new(d.journal());
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::OutOfOrder)));
    assert_eq!(j.pin(), pin); assert!(e.begun.is_empty());
    let (mut c, mut p) = prepared();
    let mut foreign = FileCheckJournal::create(&d.0.join("foreign"), CheckJournalScope {
        repository: RepositoryId::from_bytes([9; 16]), ..scope()
    }, CheckJournalLimits::default()).unwrap();
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut foreign, 200, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::ScopeMismatch)));
    // A scope rejection must not pin the handle to the wrong journal.
    c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).unwrap();
}

#[test]
fn corrupted_completed_record_is_not_hidden_by_an_in_memory_receipt() {
    let d = Directory::new(); let mut j = journal(&d, 100);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).unwrap();
    let mut f = OpenOptions::new().write(true).open(d.journal()).unwrap();
    let original = fs::read(d.journal()).unwrap();
    f.seek(SeekFrom::End(-1)).unwrap(); f.write_all(&[original[original.len() - 1] ^ 1]).unwrap();
    f.sync_all().unwrap();
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::CorruptJournal)));
    assert!(j.is_failed()); assert_eq!(e.begun.len(), 2);
}

// Helper invoked only by the process-exit test below. Normal test discovery
// does not terminate the harness or manufacture a crash-recovery pass.
#[test]
fn process_exit_child() {
    let Some(directory) = std::env::var_os("FGIT_JOURNALED_WORKFLOW_EXIT_CHILD") else { return; };
    let path = PathBuf::from(directory).join("checks");
    let mut j = FileCheckJournal::create(&path, scope(), CheckJournalLimits::default()).unwrap();
    let (mut c, mut p) = prepared(); let mut e = Executor::new(path); e.exit_in_step = true;
    let _ = c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true);
    panic!("child must exit from the executor, not return");
}

#[test]
fn actual_process_exit_releases_lock_but_not_the_durable_launch_fence() {
    let d = Directory::new();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "coordinator::delivery::journal::execution::tests::process_exit_child", "--nocapture"])
        .env("FGIT_JOURNALED_WORKFLOW_EXIT_CHILD", &d.0).status().unwrap();
    assert_eq!(status.code(), Some(86));
    let mut j = FileCheckJournal::open(&d.journal(), scope(), CheckJournalLimits::default(), None, &|| true).unwrap();
    let stored = facts(&d.journal());
    assert_eq!(stored.iter().filter(|f| f.status == CheckRunStatus::InProgress).count(), 1);
    assert!(!stored.iter().any(|f| f.status == CheckRunStatus::Completed));
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::StaleBatch)));
    assert!(e.begun.is_empty());
    assert_eq!(fs::metadata(d.journal()).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn a_different_known_inflight_run_blocks_fresh_coordinator_work() {
    let d = Directory::new(); let mut j = journal(&d, 100);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal()); e.panic_on_begin = true;
    assert!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).is_err());
    assert_eq!(e.begun, ["first"]);
    assert!(facts(&d.journal()).iter().any(|f| f.status == CheckRunStatus::InProgress));
    let pin = j.pin(); drop(c); drop(p); drop(j);
    let mut j = FileCheckJournal::open(&d.journal(), scope(), CheckJournalLimits::default(), Some(pin), &|| true).unwrap();
    let (mut c, mut p) = prepared_sequence(2); let mut e = Executor::new(d.journal());
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::OutOfOrder)));
    assert!(e.begun.is_empty()); assert_eq!(j.pin(), pin);
}


#[test]
fn failed_launch_selection_cannot_fall_back_to_existing_per_job_journaling() {
    let d = Directory::new(); let mut j = journal(&d, 1);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    assert!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).is_err());
    let pin = j.pin(); drop(j);
    let mut j = FileCheckJournal::open(&d.journal(), scope(), CheckJournalLimits::default(), Some(pin), &|| true).unwrap();
    assert!(matches!(c.execute_trusted_workflow_journaled(&mut p, &mut e, &mut j, 200, &|| true),
        Err(CoordinatorRefusal::UnsupportedExecution { .. })));
    assert_eq!(j.pin(), pin);
    assert!(e.begun.is_empty());
    c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).unwrap();
    assert_eq!(e.begun, ["first", "second"]);
}

#[test]
fn existing_per_job_execution_is_preserved_but_cannot_be_relabelled_launch_fenced() {
    let d = Directory::new(); let mut j = journal(&d, 100);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal()); e.check_disk = false;
    let root = c.execute_trusted_workflow_journaled(&mut p, &mut e, &mut j, 200, &|| true).unwrap().commitment();
    let pin = j.pin();
    assert_eq!(c.execute_trusted_workflow_journaled(&mut p, &mut e, &mut j, 201, &|| false).unwrap().commitment(), root);
    assert!(matches!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 201, &|| true),
        Err(JournaledWorkflowRefusal::Coordinator(CoordinatorRefusal::UnsupportedExecution { .. }))));
    assert_eq!(e.begun, ["first", "second"]);
    assert_eq!(j.pin(), pin);
}

#[test]
fn a_legacy_drained_queue_cannot_be_interpreted_as_persisted_launch_admission() {
    let d = Directory::new(); let mut j = journal(&d, 100);
    let (mut c, mut p) = prepared(); let mut e = Executor::new(d.journal());
    assert_eq!(c.drain_check_facts().len(), 2);
    let pin = j.pin();
    assert_eq!(c.execute_journaled_trusted_workflow(&mut p, &mut e, &mut j, 200, &|| true).err(),
        Some(JournaledWorkflowRefusal::Custody(CheckDeliveryRefusal::EvidenceMissing)));
    assert!(e.begun.is_empty()); assert_eq!(j.pin(), pin);
}
