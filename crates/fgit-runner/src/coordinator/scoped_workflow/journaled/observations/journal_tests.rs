//! Actual private-file reopen/read tests, not power-loss or hostile-host proofs.
use super::tests::{produce, rebind_hash, selected};
use super::*;
use crate::coordinator::delivery::journal::{
    CheckJournalLimits, CheckJournalScope, FileCheckJournal,
};
use crate::coordinator::delivery::{CheckDeliveryAcknowledgement, CheckDeliverySink};
use crate::workflow::StepOutcome;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-observation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("journal")
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn scope(batch: &CheckDeliveryBatch) -> CheckJournalScope {
    CheckJournalScope {
        tenant: batch.tenant(),
        repository: batch.repository(),
        journal_id: Commitment::of_bytes(b"typed reader test"),
    }
}
fn store(
    journal: &mut FileCheckJournal,
    batch: &CheckDeliveryBatch,
    receipt: &TrustedWorkflowReceipt,
) {
    for fact in batch.facts() {
        if let Some(root) = fact.receipt_commitment {
            journal
                .store_evidence(root, &receipt.job_frame(&fact.job_id).unwrap())
                .unwrap();
        }
    }
    journal.accept(batch).unwrap();
}

#[test]
fn delivered_job_evidence_reopens_without_source_scheduler_or_execution() {
    for format in [false, true] {
        let temp = Temp::new();
        let path = temp.file();
        let (batch, receipt) = produce(format, StepOutcome::Succeeded);
        let index = selected(&batch);
        let scope = scope(&batch);
        let mut journal =
            FileCheckJournal::create(&path, scope, CheckJournalLimits::default()).unwrap();
        store(&mut journal, &batch, &receipt);
        let stale = journal.pin();
        journal
            .record_delivery(CheckDeliveryAcknowledgement::after_durable_acceptance(
                &batch,
                Commitment::of_bytes(b"fixture destination custody"),
            ))
            .unwrap();
        let pin = journal.pin();
        assert_eq!(
            journal.read_trusted_job(stale, batch.id(), index, MAX_OBSERVATION_BYTES, &|| true),
            Err(ObservationRefusal::Journal(
                CheckDeliveryRefusal::StaleBatch
            ))
        );
        drop(receipt);
        drop(journal);
        let before = fs::read(&path).unwrap();
        let mut reopened = FileCheckJournal::open(
            &path,
            scope,
            CheckJournalLimits::default(),
            Some(pin),
            &|| true,
        )
        .unwrap();
        let actual = reopened
            .read_trusted_job(pin, batch.id(), index, MAX_OBSERVATION_BYTES, &|| true)
            .unwrap();
        assert!(actual.report().succeeded());
        assert_eq!(
            actual.report().jobs[0].steps[0].observation.stdout,
            [0, 255, 27, b'[', b'm']
        );
        assert_eq!(
            actual.evidence(),
            batch.facts()[index].receipt_commitment.unwrap()
        );
        assert_eq!(reopened.pending_batches(), 0);
        assert_eq!(reopened.pin(), pin);
        drop(reopened);
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn committed_hash_of_wrong_subject_is_refused_without_poisoning_custody() {
    let temp = Temp::new();
    let path = temp.file();
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let index = selected(&batch);
    let mut other = receipt.clone();
    other.logical_now += 1;
    let bad = other.job_frame(&batch.facts()[index].job_id).unwrap();
    let changed = rebind_hash(&batch, index, &bad);
    let mut journal =
        FileCheckJournal::create(&path, scope(&batch), CheckJournalLimits::default()).unwrap();
    for fact in changed.facts() {
        if let Some(root) = fact.receipt_commitment {
            let bytes = if fact.job_id == batch.facts()[index].job_id {
                bad.clone()
            } else {
                receipt.job_frame(&fact.job_id).unwrap()
            };
            journal.store_evidence(root, &bytes).unwrap();
        }
    }
    journal.accept(&changed).unwrap();
    let pin = journal.pin();
    let before = fs::read(&path).unwrap();
    assert_eq!(
        journal.read_trusted_job(pin, changed.id(), index, MAX_OBSERVATION_BYTES, &|| true),
        Err(ObservationRefusal::BindingMismatch)
    );
    assert!(!journal.is_failed());
    assert_eq!(journal.pending_batches(), 1);
    assert_eq!(journal.pin(), pin);
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn selectors_limits_and_cancellation_do_not_settle_or_disclose_other_evidence() {
    let temp = Temp::new();
    let path = temp.file();
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let index = selected(&batch);
    let length = receipt
        .job_frame(&batch.facts()[index].job_id)
        .unwrap()
        .len();
    let mut journal =
        FileCheckJournal::create(&path, scope(&batch), CheckJournalLimits::default()).unwrap();
    store(&mut journal, &batch, &receipt);
    let pin = journal.pin();
    let before = fs::read(&path).unwrap();
    assert_eq!(
        journal.read_trusted_job(pin, batch.id(), 0, MAX_OBSERVATION_BYTES, &|| true),
        Err(ObservationRefusal::FactNotCompleted)
    );
    assert_eq!(
        journal.read_trusted_job(pin, batch.id(), usize::MAX, MAX_OBSERVATION_BYTES, &|| true),
        Err(ObservationRefusal::FactNotCompleted)
    );
    assert_eq!(
        journal.read_trusted_job(pin, batch.id(), index, length - 1, &|| true),
        Err(ObservationRefusal::RecordTooLarge)
    );
    assert!(
        journal
            .read_trusted_job(pin, batch.id(), index, length, &|| true)
            .is_ok()
    );
    assert_eq!(
        journal.read_trusted_job(pin, batch.id(), index, MAX_OBSERVATION_BYTES, &|| false),
        Err(ObservationRefusal::Cancelled)
    );
    assert!(
        journal
            .read_trusted_job(
                pin,
                Commitment::of_bytes(b"not accepted"),
                index,
                MAX_OBSERVATION_BYTES,
                &|| true
            )
            .is_err()
    );
    assert_eq!(journal.pending_batches(), 1);
    assert_eq!(journal.pin(), pin);
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn retained_containment_survives_the_typed_storage_read() {
    let temp = Temp::new();
    let (batch, receipt) = produce(false, StepOutcome::ContainmentFailure);
    let index = selected(&batch);
    let mut journal =
        FileCheckJournal::create(&temp.file(), scope(&batch), CheckJournalLimits::default())
            .unwrap();
    store(&mut journal, &batch, &receipt);
    let observed = journal
        .read_trusted_job(
            journal.pin(),
            batch.id(),
            index,
            MAX_OBSERVATION_BYTES,
            &|| true,
        )
        .unwrap();
    assert!(observed.requires_containment());
    assert!(!observed.report().succeeded());
    assert_eq!(
        batch.facts()[index].conclusion,
        Some(CheckRunConclusion::Failure)
    );
}

fn destination_scope(batch: &CheckDeliveryBatch) -> CheckJournalScope {
    CheckJournalScope {
        journal_id: Commitment::of_bytes(b"destination instance"),
        ..scope(batch)
    }
}

#[test]
fn trusted_transfer_persists_bodies_before_ack_and_both_sides_reopen() {
    for format in [false, true] {
        let source_dir = Temp::new();
        let target_dir = Temp::new();
        let (batch, receipt) = produce(format, StepOutcome::Succeeded);
        let mut source = FileCheckJournal::create(
            &source_dir.file(),
            scope(&batch),
            CheckJournalLimits::default(),
        )
        .unwrap();
        let mut target = FileCheckJournal::create(
            &target_dir.file(),
            destination_scope(&batch),
            CheckJournalLimits::default(),
        )
        .unwrap();
        store(&mut source, &batch, &receipt);
        let ack = source
            .transfer_next_trusted(&mut target, MAX_OBSERVATION_BYTES, &|| true)
            .unwrap()
            .unwrap();
        assert_eq!(ack.batch_id(), batch.id());
        assert_eq!(source.pending_batches(), 0);
        assert_eq!(target.pending_batches(), 1);
        assert!(
            source
                .transfer_next_trusted(&mut target, MAX_OBSERVATION_BYTES, &|| true)
                .unwrap()
                .is_none()
        );
        let source_pin = source.pin();
        let target_pin = target.pin();
        drop(source);
        drop(target);
        drop(receipt);
        let mut source = FileCheckJournal::open(
            &source_dir.file(),
            scope(&batch),
            CheckJournalLimits::default(),
            Some(source_pin),
            &|| true,
        )
        .unwrap();
        let mut target = FileCheckJournal::open(
            &target_dir.file(),
            destination_scope(&batch),
            CheckJournalLimits::default(),
            Some(target_pin),
            &|| true,
        )
        .unwrap();
        assert_eq!(
            source
                .read_retained_batch(batch.id())
                .unwrap()
                .delivery_receipt(),
            Some(ack.receipt_root())
        );
        let actual = target
            .read_trusted_job(
                target_pin,
                batch.id(),
                selected(&batch),
                MAX_OBSERVATION_BYTES,
                &|| true,
            )
            .unwrap();
        assert!(actual.report().succeeded());
        assert_eq!(
            actual.report().jobs[0].steps[0].observation.stdout,
            [0, 255, 27, b'[', b'm']
        );
        assert_eq!(source.pending_batches(), 0);
        assert_eq!(target.pending_batches(), 1);
    }
}

#[test]
fn exact_lost_destination_ack_is_reconciled_without_duplicate_records() {
    let source_dir = Temp::new();
    let target_dir = Temp::new();
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let mut source = FileCheckJournal::create(
        &source_dir.file(),
        scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    let mut target = FileCheckJournal::create(
        &target_dir.file(),
        destination_scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    store(&mut source, &batch, &receipt);
    // Destination accepted; the response never reached the source journal.
    store(&mut target, &batch, &receipt);
    let target_pin = target.pin();
    drop(source);
    drop(target);
    drop(receipt);
    let mut source = FileCheckJournal::open(
        &source_dir.file(),
        scope(&batch),
        CheckJournalLimits::default(),
        None,
        &|| true,
    )
    .unwrap();
    let mut target = FileCheckJournal::open(
        &target_dir.file(),
        destination_scope(&batch),
        CheckJournalLimits::default(),
        Some(target_pin),
        &|| true,
    )
    .unwrap();
    let before = fs::read(target_dir.file()).unwrap();
    let ack = source
        .transfer_next_trusted(&mut target, MAX_OBSERVATION_BYTES, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(
        source
            .read_retained_batch(batch.id())
            .unwrap()
            .delivery_receipt(),
        Some(ack.receipt_root())
    );
    assert_eq!(target.pin(), target_pin);
    assert_eq!(target.retained_batches(), 1);
    assert_eq!(fs::read(target_dir.file()).unwrap(), before);
    assert_eq!(source.pending_batches(), 0);
}

#[test]
fn transfer_refuses_a_late_wrong_subject_before_any_destination_write() {
    let source_dir = Temp::new();
    let target_dir = Temp::new();
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let index = batch
        .facts()
        .iter()
        .rposition(|fact| fact.status == CheckRunStatus::Completed)
        .unwrap();
    let mut other = receipt.clone();
    other.binding.head = Commitment::of_bytes(b"other authority");
    let bad = other.job_frame(&batch.facts()[index].job_id).unwrap();
    let changed = rebind_hash(&batch, index, &bad);
    let mut source = FileCheckJournal::create(
        &source_dir.file(),
        scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    let mut target = FileCheckJournal::create(
        &target_dir.file(),
        destination_scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    for fact in changed.facts() {
        if let Some(root) = fact.receipt_commitment {
            let bytes = if fact.job_id == batch.facts()[index].job_id {
                bad.clone()
            } else {
                receipt.job_frame(&fact.job_id).unwrap()
            };
            source.store_evidence(root, &bytes).unwrap();
        }
    }
    source.accept(&changed).unwrap();
    let before = fs::read(target_dir.file()).unwrap();
    assert_eq!(
        source.transfer_next_trusted(&mut target, MAX_OBSERVATION_BYTES, &|| true),
        Err(ObservationRefusal::BindingMismatch)
    );
    assert_eq!(source.pending_batches(), 1);
    assert_eq!(target.retained_batches(), 0);
    assert_eq!(fs::read(target_dir.file()).unwrap(), before);
    assert!(!source.is_failed());
    assert!(!target.is_failed());
}

#[test]
fn aggregate_transfer_budget_is_checked_before_copying_any_evidence() {
    let source_dir = Temp::new();
    let target_dir = Temp::new();
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let total = batch
        .facts()
        .iter()
        .filter(|fact| fact.status == CheckRunStatus::Completed)
        .map(|fact| receipt.job_frame(&fact.job_id).unwrap().len())
        .sum::<usize>();
    let mut source = FileCheckJournal::create(
        &source_dir.file(),
        scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    let mut target = FileCheckJournal::create(
        &target_dir.file(),
        destination_scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    store(&mut source, &batch, &receipt);
    let before = fs::read(target_dir.file()).unwrap();
    assert_eq!(
        source.transfer_next_trusted(&mut target, total - 1, &|| true),
        Err(ObservationRefusal::RecordTooLarge)
    );
    assert_eq!(fs::read(target_dir.file()).unwrap(), before);
    assert_eq!(source.pending_batches(), 1);
    source
        .transfer_next_trusted(&mut target, total, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(source.pending_batches(), 0);
    assert_eq!(target.pending_batches(), 1);
}

#[test]
fn cancelled_partial_copy_retains_source_and_exact_evidence_can_be_reused() {
    let source_dir = Temp::new();
    let target_dir = Temp::new();
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let mut source = FileCheckJournal::create(
        &source_dir.file(),
        scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    let mut target = FileCheckJournal::create(
        &target_dir.file(),
        destination_scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    store(&mut source, &batch, &receipt);
    let initial_len = fs::metadata(target_dir.file()).unwrap().len();
    let live = || fs::metadata(target_dir.file()).unwrap().len() == initial_len;
    assert_eq!(
        source.transfer_next_trusted(&mut target, MAX_OBSERVATION_BYTES, &live),
        Err(ObservationRefusal::Cancelled)
    );
    assert_eq!(source.pending_batches(), 1);
    assert_eq!(target.retained_batches(), 0);
    assert!(fs::metadata(target_dir.file()).unwrap().len() > initial_len);
    drop(target);
    let mut reopened = FileCheckJournal::open(
        &target_dir.file(),
        destination_scope(&batch),
        CheckJournalLimits::default(),
        None,
        &|| true,
    )
    .unwrap();
    source
        .transfer_next_trusted(&mut reopened, MAX_OBSERVATION_BYTES, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(source.pending_batches(), 0);
    assert_eq!(reopened.pending_batches(), 1);
}

#[test]
fn unavailable_or_cross_repository_destination_never_settles_source() {
    let source_dir = Temp::new();
    let target_dir = Temp::new();
    let wrong_dir = Temp::new();
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let mut source = FileCheckJournal::create(
        &source_dir.file(),
        scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    store(&mut source, &batch, &receipt);
    let wrong_scope = CheckJournalScope {
        repository: RepositoryId::from_bytes([9; 16]),
        ..destination_scope(&batch)
    };
    let mut wrong = FileCheckJournal::create(
        &wrong_dir.file(),
        wrong_scope,
        CheckJournalLimits::default(),
    )
    .unwrap();
    assert_eq!(
        source.transfer_next_trusted(&mut wrong, MAX_OBSERVATION_BYTES, &|| true),
        Err(ObservationRefusal::Journal(
            CheckDeliveryRefusal::ScopeMismatch
        ))
    );
    assert_eq!(wrong.retained_batches(), 0);
    assert_eq!(source.pending_batches(), 1);
    let mut target = FileCheckJournal::create(
        &target_dir.file(),
        destination_scope(&batch),
        CheckJournalLimits {
            records: 1,
            ..CheckJournalLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        source.transfer_next_trusted(&mut target, MAX_OBSERVATION_BYTES, &|| true),
        Err(ObservationRefusal::Journal(
            CheckDeliveryRefusal::JournalFull
        ))
    );
    assert_eq!(source.pending_batches(), 1);
    assert_eq!(target.retained_batches(), 0);
    drop(target);
    let mut target = FileCheckJournal::open(
        &target_dir.file(),
        destination_scope(&batch),
        CheckJournalLimits::default(),
        None,
        &|| true,
    )
    .unwrap();
    source
        .transfer_next_trusted(&mut target, MAX_OBSERVATION_BYTES, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(source.pending_batches(), 0);
    assert_eq!(target.pending_batches(), 1);
}

#[test]
fn cancellation_after_destination_acceptance_does_not_erase_custody() {
    let source_dir = Temp::new();
    let target_dir = Temp::new();
    let (batch, receipt) = produce(false, StepOutcome::Succeeded);
    let mut source = FileCheckJournal::create(
        &source_dir.file(),
        scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    let mut target = FileCheckJournal::create(
        &target_dir.file(),
        destination_scope(&batch),
        CheckJournalLimits::default(),
    )
    .unwrap();
    store(&mut source, &batch, &receipt);
    // Become cancelled at the exact point the complete proposal is on disk.
    // Were the adapter to recheck after accept, it would see false. It must
    // instead finish the non-cancellable source acknowledgement obligation.
    let live = || {
        !fs::read(target_dir.file())
            .unwrap()
            .windows(batch.body().len())
            .any(|part| part == batch.body())
    };
    assert!(live());
    let ack = source
        .transfer_next_trusted(&mut target, MAX_OBSERVATION_BYTES, &live)
        .unwrap()
        .unwrap();
    assert!(!live());
    assert_eq!(ack.batch_id(), batch.id());
    assert_eq!(source.pending_batches(), 0);
    assert_eq!(target.pending_batches(), 1);
    assert_eq!(
        source
            .read_retained_batch(batch.id())
            .unwrap()
            .delivery_receipt(),
        Some(ack.receipt_root())
    );
}
