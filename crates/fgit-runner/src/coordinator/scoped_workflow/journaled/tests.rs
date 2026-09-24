//! Control-flow and real private-file custody tests; not hostile-code tests.
use super::*;
use crate::coordinator::delivery::journal::{CheckJournalLimits, CheckJournalScope};
use crate::coordinator::delivery::{CheckDeliveryAcknowledgement, CheckDeliveryBatch};
use crate::workflow::StepOutcome;
use crate::workflow::{
    JobOutcome, StepLimits, StepObservation, WorkerFailure, WorkflowLimits, WorkflowPlan,
};
use crate::{CheckRunConclusion, CoordinatorLimits, ResourceCeilings, RunStatus, TriggerContext};
use fgit_types::GitOidSha1;
use fgit_types::{GitOid, RepositoryId, TenantId};
use std::cell::Cell;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const SOURCE: &str = "name: journaled\non: push\njobs:\n  first:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo first\n  second:\n    runs-on: fgit-trusted-local\n    needs: first\n    steps:\n      - run: echo second\n";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-job-custody-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("checks")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn scope() -> CheckJournalScope {
    CheckJournalScope {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        journal_id: Commitment::of_bytes(b"journaled-tests"),
    }
}
fn coordinator() -> WorkflowCoordinator {
    WorkflowCoordinator::new(
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
    .unwrap()
}
fn enqueue(c: &mut WorkflowCoordinator, sequence: u64, source: &str) -> PreparedTrustedWorkflow {
    c.enqueue_trusted_workflow(
        scope().tenant,
        scope().repository,
        Commitment::of_bytes(b"head"),
        GitOid::Sha1(GitOidSha1::from_bytes([3; 20])),
        WorkflowPlan::compile(source).unwrap(),
        WorkflowLimits::default(),
        TriggerContext::trusted_push("tester"),
        sequence,
        100,
    )
    .unwrap()
}
struct Executor<'a> {
    path: PathBuf,
    started: Vec<String>,
    journal_lengths: Vec<u64>,
    closed: usize,
    cancel_after_close: Option<&'a Cell<bool>>,
    retain: bool,
}
impl Executor<'_> {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            started: Vec::new(),
            journal_lengths: Vec::new(),
            closed: 0,
            cancel_after_close: None,
            retain: false,
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
        self.started.push(job.id.clone());
        self.journal_lengths
            .push(fs::metadata(&self.path).unwrap().len());
        Ok(())
    }
    fn execute_step(
        &mut self,
        _: usize,
        script: &str,
        _: StepLimits,
        _: &dyn Fn() -> bool,
    ) -> Result<StepObservation, WorkerFailure> {
        Ok(StepObservation {
            outcome: StepOutcome::Succeeded,
            exit_code: Some(0),
            stdout: script.as_bytes().to_vec(),
            stderr: Vec::new(),
            elapsed_millis: 1,
            output_complete: true,
            retain_workspace: self.retain,
        })
    }
    fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> {
        self.closed += 1;
        if let Some(live) = self.cancel_after_close {
            live.set(false);
        }
        Ok(())
    }
}
fn collect(journal: &mut FileCheckJournal) -> Vec<CheckDeliveryBatch> {
    let mut batches = Vec::new();
    while let Some(batch) = journal.next_batch().unwrap() {
        // Fixture downstream custody, not canonical publication.
        journal
            .record_delivery(CheckDeliveryAcknowledgement::after_durable_acceptance(
                &batch,
                Commitment::of_bytes(b"test-sink"),
            ))
            .unwrap();
        batches.push(batch);
    }
    batches
}

#[test]
fn each_completed_job_reaches_disk_before_the_next_scope_and_survives_reopen() {
    let temp = Temp::new();
    let mut c = coordinator();
    let mut prepared = enqueue(&mut c, 1, SOURCE);
    let mut journal =
        FileCheckJournal::create(&temp.path(), scope(), CheckJournalLimits::default()).unwrap();
    let mut executor = Executor::new(temp.path());
    let receipt = c
        .execute_trusted_workflow_journaled(
            &mut prepared,
            &mut executor,
            &mut journal,
            200,
            &|| true,
        )
        .unwrap()
        .clone();
    assert_eq!(executor.started, ["first", "second"]);
    assert_eq!(executor.closed, 2);
    assert!(executor.journal_lengths[0] > 72);
    assert!(executor.journal_lengths[1] > executor.journal_lengths[0]);
    c.verify_quiescence().unwrap();
    let pin = journal.pin();
    drop(c);
    drop(prepared);
    drop(journal);
    let mut journal = FileCheckJournal::open(
        &temp.path(),
        scope(),
        CheckJournalLimits::default(),
        Some(pin),
        &|| true,
    )
    .unwrap();
    let batches = collect(&mut journal);
    assert_eq!(batches.len(), 3);
    assert_eq!(
        batches.iter().map(|b| b.facts().len()).collect::<Vec<_>>(),
        [2, 2, 2]
    );
    for fact in batches.iter().flat_map(|b| b.facts()) {
        if let Some(root) = fact.receipt_commitment {
            assert_eq!(
                journal.read_evidence(root).unwrap(),
                receipt.job_frame(&fact.job_id).unwrap()
            );
            assert_eq!(fact.conclusion, Some(CheckRunConclusion::ActionRequired));
        }
    }
}

#[test]
fn failed_job_handoff_stops_before_opening_a_dependency() {
    let temp = Temp::new();
    let mut c = coordinator();
    let mut prepared = enqueue(&mut c, 1, SOURCE);
    let mut journal = FileCheckJournal::create(
        &temp.path(),
        scope(),
        CheckJournalLimits {
            records: 4,
            ..CheckJournalLimits::default()
        },
    )
    .unwrap();
    let mut executor = Executor::new(temp.path());
    assert!(matches!(
        c.execute_trusted_workflow_journaled(
            &mut prepared,
            &mut executor,
            &mut journal,
            200,
            &|| true
        ),
        Err(CoordinatorRefusal::ObligationLeak(_))
    ));
    assert_eq!(executor.started, ["first"]);
    assert_eq!(executor.closed, 1);
    assert!(prepared.receipt().is_none());
    assert!(matches!(
        c.active_runs[&prepared.run_id()].status,
        RunStatus::Draining { .. }
    ));
    assert!(c.verify_quiescence().is_err());
    assert_eq!(journal.pending_batches(), 1);
    assert!(
        c.execute_trusted_workflow_journaled(
            &mut prepared,
            &mut executor,
            &mut journal,
            201,
            &|| true
        )
        .is_err()
    );
    assert_eq!(executor.started.len(), 1);
}

#[test]
fn initial_journal_capacity_failure_runs_nothing_and_keeps_queue_owned() {
    let temp = Temp::new();
    let mut c = coordinator();
    let mut prepared = enqueue(&mut c, 1, SOURCE);
    let mut journal = FileCheckJournal::create(
        &temp.path(),
        scope(),
        CheckJournalLimits {
            records: 1,
            ..CheckJournalLimits::default()
        },
    )
    .unwrap();
    let pin = journal.pin();
    let mut executor = Executor::new(temp.path());
    assert!(
        c.execute_trusted_workflow_journaled(
            &mut prepared,
            &mut executor,
            &mut journal,
            200,
            &|| true
        )
        .is_err()
    );
    assert!(executor.started.is_empty());
    assert!(!prepared.attempted);
    assert_eq!(journal.pin(), pin);
    assert_eq!(c.pending_check_fact_count(), 2);
}

#[test]
fn completed_repeat_does_not_execute_or_append_duplicates() {
    let temp = Temp::new();
    let mut c = coordinator();
    let mut prepared = enqueue(&mut c, 1, SOURCE);
    let mut journal =
        FileCheckJournal::create(&temp.path(), scope(), CheckJournalLimits::default()).unwrap();
    let mut executor = Executor::new(temp.path());
    let root = c
        .execute_trusted_workflow_journaled(
            &mut prepared,
            &mut executor,
            &mut journal,
            200,
            &|| true,
        )
        .unwrap()
        .commitment();
    let pin = journal.pin();
    assert_eq!(
        c.execute_trusted_workflow_journaled(
            &mut prepared,
            &mut executor,
            &mut journal,
            300,
            &|| false
        )
        .unwrap()
        .commitment(),
        root
    );
    assert_eq!(executor.started.len(), 2);
    assert_eq!(journal.pin(), pin);
}

#[test]
fn cancellation_during_close_still_persists_terminal_results_without_more_work() {
    let temp = Temp::new();
    let mut c = coordinator();
    let mut prepared = enqueue(&mut c, 1, SOURCE);
    let mut journal =
        FileCheckJournal::create(&temp.path(), scope(), CheckJournalLimits::default()).unwrap();
    let live = Cell::new(true);
    let mut executor = Executor::new(temp.path());
    executor.cancel_after_close = Some(&live);
    let receipt = c
        .execute_trusted_workflow_journaled(
            &mut prepared,
            &mut executor,
            &mut journal,
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
    assert_eq!(executor.started, ["first"]);
    assert_eq!(c.pending_check_fact_count(), 0);
    assert_eq!(journal.pending_batches(), 3);
    c.verify_quiescence().unwrap();
}

#[test]
fn cancelled_before_start_has_no_file_or_execution_side_effect() {
    let temp = Temp::new();
    let mut c = coordinator();
    let mut prepared = enqueue(&mut c, 1, SOURCE);
    let mut journal =
        FileCheckJournal::create(&temp.path(), scope(), CheckJournalLimits::default()).unwrap();
    let pin = journal.pin();
    let mut executor = Executor::new(temp.path());
    assert!(
        c.execute_trusted_workflow_journaled(
            &mut prepared,
            &mut executor,
            &mut journal,
            200,
            &|| false
        )
        .is_err()
    );
    assert_eq!(journal.pin(), pin);
    assert!(executor.started.is_empty());
    assert!(!prepared.attempted);
}

#[test]
fn foreign_journal_and_unrelated_pending_runs_are_refused_before_custody() {
    for foreign in [true, false] {
        let temp = Temp::new();
        let mut c = coordinator();
        let mut prepared = enqueue(&mut c, 1, SOURCE);
        let mut selected = scope();
        if foreign {
            selected.repository = RepositoryId::from_bytes([9; 16]);
        } else {
            let _other = enqueue(&mut c, 2, SOURCE);
        }
        let mut journal =
            FileCheckJournal::create(&temp.path(), selected, CheckJournalLimits::default())
                .unwrap();
        let pin = journal.pin();
        let mut executor = Executor::new(temp.path());
        assert!(
            c.execute_trusted_workflow_journaled(
                &mut prepared,
                &mut executor,
                &mut journal,
                200,
                &|| true
            )
            .is_err()
        );
        assert_eq!(journal.pin(), pin);
        assert!(executor.started.is_empty());
    }
}

#[test]
fn containment_observation_is_persisted_without_releasing_the_coordinator() {
    let temp = Temp::new();
    let mut c = coordinator();
    let mut prepared = enqueue(&mut c, 1, SOURCE);
    let mut journal =
        FileCheckJournal::create(&temp.path(), scope(), CheckJournalLimits::default()).unwrap();
    let mut executor = Executor::new(temp.path());
    executor.retain = true;
    let receipt = c
        .execute_trusted_workflow_journaled(
            &mut prepared,
            &mut executor,
            &mut journal,
            200,
            &|| true,
        )
        .unwrap();
    assert!(receipt.report().jobs[0].requires_containment());
    assert_eq!(executor.started, ["first"]);
    assert_eq!(c.pending_check_fact_count(), 0);
    assert!(c.verify_quiescence().is_err());
    assert!(c.eligible_jobs(prepared.run_id()).unwrap().is_empty());
}

#[test]
fn callback_failure_blocks_independent_work_even_after_successful_cleanup() {
    let temp = Temp::new();
    fs::write(temp.path(), b"fixture").unwrap();
    let mut c = coordinator();
    let source = SOURCE.replace("    needs: first\n", "");
    let mut prepared = enqueue(&mut c, 1, &source);
    let mut executor = Executor::new(temp.path());
    let mut callbacks = 0;
    let result = c.execute_trusted_workflow_with_custody(
        &mut prepared,
        &mut executor,
        200,
        &|| true,
        &mut |_, fragment| {
            callbacks += 1;
            if fragment.is_some() {
                Err(CoordinatorRefusal::ObligationLeak(
                    "fixture failed handoff".into(),
                ))
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(executor.started, ["first"]);
    assert_eq!(executor.closed, 1);
    assert_eq!(callbacks, 2);
}

#[test]
fn callback_unwind_does_not_reopen_or_double_close_a_completed_scope() {
    let temp = Temp::new();
    fs::write(temp.path(), b"fixture").unwrap();
    let mut c = coordinator();
    let mut prepared = enqueue(&mut c, 1, SOURCE);
    let mut executor = Executor::new(temp.path());
    let result = c.execute_trusted_workflow_with_custody(
        &mut prepared,
        &mut executor,
        200,
        &|| true,
        &mut |_, fragment| {
            assert!(fragment.is_none(), "fixture persistence panic");
            Ok(())
        },
    );
    assert!(matches!(
        result,
        Err(CoordinatorRefusal::ContainmentFailure(_))
    ));
    assert_eq!(executor.started, ["first"]);
    assert_eq!(executor.closed, 1);
    assert!(prepared.receipt().is_none());
}
