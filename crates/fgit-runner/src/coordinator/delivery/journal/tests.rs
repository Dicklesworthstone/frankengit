//! Real private-file journal tests. Substrate/destination fixtures exercise
//! custody and provenance composition, not OS containment or canonical admission.
use super::*;
use crate::workflow::{StepLimits, StepObservation, StepOutcome, WorkerFailure, WorkflowExecutor, WorkflowLimits, WorkflowPlan};
use fgit_schema::workflow::{Job, Limits, compile};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const SOURCE: &str = "name: custody\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n  b:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fgit-check-journal-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap(); Self(path)
    }
    fn path(&self) -> PathBuf { self.0.join("checks.journal") }
}
impl Drop for Temp { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn scope() -> CheckJournalScope {
    CheckJournalScope { tenant: TenantId::from_bytes([1; 16]), repository: RepositoryId::from_bytes([2; 16]), journal_id: Commitment::of_bytes(b"operator-journal-instance") }
}
fn coordinator() -> WorkflowCoordinator {
    WorkflowCoordinator::new(CoordinatorLimits::default(), ResourceCeilings::new(1000, 1024, 1024, 0, 2, 1000).unwrap(), 2).unwrap()
}
fn enqueue(c: &mut WorkflowCoordinator, sequence: u64) -> WorkflowRunId {
    c.enqueue_run(scope().tenant, scope().repository, Commitment::of_bytes(b"head"),
        GitOid::Sha1(GitOidSha1::from_bytes([3; 20])), compile(SOURCE, &Limits::default()).unwrap(),
        TriggerContext::trusted_push("operator"), sequence, 10).unwrap()
}
fn batch(c: &WorkflowCoordinator) -> CheckDeliveryBatch { c.prepare_check_delivery(128, MAX_BATCH_BYTES).unwrap().unwrap() }
fn create(t: &Temp) -> FileCheckJournal { FileCheckJournal::create(&t.path(), scope(), CheckJournalLimits::default()).unwrap() }
fn open(t: &Temp, pin: Option<CheckJournalPin>) -> Result<FileCheckJournal, CheckDeliveryRefusal> {
    FileCheckJournal::open(&t.path(), scope(), CheckJournalLimits::default(), pin, &|| true)
}
fn ack(batch: &CheckDeliveryBatch) -> CheckDeliveryAcknowledgement {
    CheckDeliveryAcknowledgement::after_durable_acceptance(batch, Commitment::of_bytes(b"fixture-destination-receipt"))
}

#[test]
fn durable_handoff_reopens_without_the_originating_coordinator() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); enqueue(&mut c, 1);
    let expected = batch(&c);
    let acknowledgement = c.journal_check_facts(&mut j, 128, MAX_BATCH_BYTES, None, &|| true).unwrap().unwrap();
    assert_eq!(acknowledgement.batch_id(), expected.id());
    assert_eq!(c.pending_check_fact_count(), 0); c.verify_quiescence().unwrap();
    let pin = j.pin(); drop(c); drop(j);
    let mut recovered = open(&t, Some(pin)).unwrap();
    assert_eq!(recovered.next_batch().unwrap().unwrap(), expected);
    let before = recovered.pin();
    assert_eq!(recovered.accept(&expected).unwrap(), acknowledgement);
    assert_eq!(recovered.pin(), before); assert_eq!(recovered.pending_batches(), 1);
}

#[test]
fn lost_custody_response_retries_without_duplicate_records() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); enqueue(&mut c, 1);
    let pending = batch(&c);
    let lost = j.accept(&pending).unwrap(); let pin = j.pin(); drop(j);
    assert_eq!(c.pending_check_fact_count(), 2);
    let mut j = open(&t, Some(pin)).unwrap();
    let retried = c.deliver_check_facts(&mut j, 128, MAX_BATCH_BYTES, &|| true).unwrap().unwrap();
    assert_eq!(retried, lost); assert_eq!(j.pin(), pin); assert_eq!(j.pending_batches(), 1);
}

#[test]
fn changed_batch_partition_after_lost_response_is_refused_not_duplicated() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); enqueue(&mut c, 1);
    let original = batch(&c); let accepted = j.accept(&original).unwrap(); let pin = j.pin();
    assert_eq!(c.deliver_check_facts(&mut j, 1, MAX_BATCH_BYTES, &|| true), Err(CheckDeliveryRefusal::StaleBatch));
    assert_eq!(c.pending_check_fact_count(), 2); assert_eq!(j.pin(), pin);
    c.acknowledge_check_delivery(&original, accepted).unwrap();
    assert_eq!(c.pending_check_fact_count(), 0);
}

#[test]
fn delivery_is_fifo_durable_and_duplicate_acknowledgement_is_sticky() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); enqueue(&mut c, 1);
    let first = batch(&c); c.deliver_check_facts(&mut j, 128, MAX_BATCH_BYTES, &|| true).unwrap();
    enqueue(&mut c, 2); let second = batch(&c); c.deliver_check_facts(&mut j, 128, MAX_BATCH_BYTES, &|| true).unwrap();
    assert_eq!(j.record_delivery(ack(&second)), Err(CheckDeliveryRefusal::OutOfOrder));
    j.record_delivery(ack(&first)).unwrap(); let pin = j.pin(); drop(j);
    let mut j = open(&t, Some(pin)).unwrap();
    assert_eq!(j.next_batch().unwrap().unwrap(), second);
    j.record_delivery(ack(&first)).unwrap(); assert_eq!(j.pin(), pin);
    let conflicting = CheckDeliveryAcknowledgement::after_durable_acceptance(&first, Commitment::of_bytes(b"different"));
    assert_eq!(j.record_delivery(conflicting), Err(CheckDeliveryRefusal::AcknowledgementMismatch));
    j.record_delivery(ack(&second)).unwrap(); let pin = j.pin(); drop(j);
    assert!(open(&t, Some(pin)).unwrap().next_batch().unwrap().is_none());
}

struct Destination { attempts: Vec<Commitment>, accepted: BTreeSet<Commitment>, fail: bool }
impl CheckDeliverySink for Destination {
    fn accept(&mut self, batch: &CheckDeliveryBatch) -> Result<CheckDeliveryAcknowledgement, CheckDeliveryRefusal> {
        self.attempts.push(batch.id()); self.accepted.insert(batch.id());
        if self.fail { Err(CheckDeliveryRefusal::StorageUnavailable) } else { Ok(ack(batch)) }
    }
}
#[test]
fn ambiguous_destination_is_retried_by_exact_identity_after_reopen() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); enqueue(&mut c, 1);
    c.deliver_check_facts(&mut j, 128, MAX_BATCH_BYTES, &|| true).unwrap();
    let mut destination = Destination { attempts: Vec::new(), accepted: BTreeSet::new(), fail: true };
    assert_eq!(j.forward_next(&mut destination, &|| true), Err(CheckDeliveryRefusal::StorageUnavailable));
    let pin = j.pin(); drop(j); drop(c);
    let mut j = open(&t, Some(pin)).unwrap(); destination.fail = false;
    j.forward_next(&mut destination, &|| true).unwrap();
    assert_eq!(destination.attempts.len(), 2); assert_eq!(destination.accepted.len(), 1);
    assert_eq!(destination.attempts[0], destination.attempts[1]); assert_eq!(j.pending_batches(), 0);
}

#[test]
fn missing_or_mismatched_evidence_never_relinquishes_completed_proposal() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); let run = enqueue(&mut c, 1);
    c.deliver_check_facts(&mut j, 128, MAX_BATCH_BYTES, &|| true).unwrap();
    let evidence = b"complete terminal evidence fixture"; let id = Commitment::of_bytes(evidence);
    c.outbox_facts.push(CheckRunFact { run_id: run, job_id: "a".into(), status: CheckRunStatus::Completed,
        conclusion: Some(CheckRunConclusion::Success), receipt_commitment: Some(id), timestamp_millis: 20 });
    c.obligations.check_publications_emitted += 1;
    let pin = j.pin();
    assert_eq!(c.deliver_check_facts(&mut j, 128, MAX_BATCH_BYTES, &|| true), Err(CheckDeliveryRefusal::EvidenceMissing));
    assert_eq!(j.store_evidence(id, b"wrong bytes"), Err(CheckDeliveryRefusal::AcknowledgementMismatch));
    assert_eq!(j.pin(), pin); assert_eq!(c.pending_check_fact_count(), 1);
    j.store_evidence(id, evidence).unwrap(); let evidence_pin = j.pin();
    j.store_evidence(id, evidence).unwrap(); assert_eq!(j.pin(), evidence_pin);
    c.deliver_check_facts(&mut j, 128, MAX_BATCH_BYTES, &|| true).unwrap();
    let pin = j.pin(); drop(j); drop(c);
    let mut j = open(&t, Some(pin)).unwrap(); assert_eq!(j.read_evidence(id).unwrap(), evidence);
}

struct Executor;
impl WorkflowExecutor for Executor {
    fn begin_job(&mut self, _: usize, _: &Job, _: &dyn Fn() -> bool) -> Result<(), WorkerFailure> { Ok(()) }
    fn execute_step(&mut self, _: usize, _: &str, _: StepLimits, _: &dyn Fn() -> bool) -> Result<StepObservation, WorkerFailure> {
        Ok(StepObservation { outcome: StepOutcome::Succeeded, exit_code: Some(0), stdout: b"observed local output".to_vec(),
            stderr: Vec::new(), elapsed_millis: 1, output_complete: true, retain_workspace: false })
    }
    fn finish_job(&mut self, _: bool) -> Result<(), WorkerFailure> { Ok(()) }
}
#[test]
fn trusted_per_job_evidence_survives_handles_and_preserves_action_required() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator();
    let mut prepared = c.enqueue_trusted_workflow(scope().tenant, scope().repository, Commitment::of_bytes(b"head"),
        GitOid::Sha256(GitOidSha256::from_bytes([4; 32])), WorkflowPlan::compile(SOURCE).unwrap(),
        WorkflowLimits::default(), TriggerContext::trusted_push("operator"), 1, 10).unwrap();
    c.execute_trusted_workflow(&mut prepared, &mut Executor, 20, &|| true).unwrap();
    assert_eq!(c.journal_check_facts(&mut j, 128, MAX_BATCH_BYTES, None, &|| true), Err(CheckDeliveryRefusal::EvidenceMissing));
    let receipt = prepared.receipt().unwrap();
    let mut frames = BTreeMap::new();
    for job in &receipt.report().jobs {
        let bytes = receipt.job_frame(&job.id).unwrap(); let id = receipt.job_commitment(&job.id).unwrap();
        assert_eq!(Commitment::of_bytes(&bytes), id); assert_ne!(id, receipt.commitment()); frames.insert(id, bytes);
    }
    c.journal_check_facts(&mut j, 128, MAX_BATCH_BYTES, Some(receipt), &|| true).unwrap();
    let pin = j.pin(); drop(prepared); drop(c); drop(j);
    let mut j = open(&t, Some(pin)).unwrap();
    let batch = j.next_batch().unwrap().unwrap();
    assert!(matches!(batch.source_commit(), GitOid::Sha256(_)));
    for fact in batch.facts().iter().filter(|fact| fact.status == CheckRunStatus::Completed) {
        assert_eq!(fact.conclusion, Some(CheckRunConclusion::ActionRequired));
        let id = fact.receipt_commitment.unwrap(); assert_eq!(j.read_evidence(id).unwrap(), frames[&id]);
    }
}

#[test]
fn wrong_scope_and_cancelled_open_do_not_modify_a_journal() {
    let t = Temp::new(); let j = create(&t); let pin = j.pin(); drop(j);
    let other = CheckJournalScope { repository: RepositoryId::from_bytes([9; 16]), ..scope() };
    assert_eq!(FileCheckJournal::open(&t.path(), other, CheckJournalLimits::default(), None, &|| true).err(), Some(CheckDeliveryRefusal::ScopeMismatch));
    assert_eq!(FileCheckJournal::open(&t.path(), scope(), CheckJournalLimits::default(), None, &|| false).err(), Some(CheckDeliveryRefusal::Cancelled));
    assert_eq!(open(&t, Some(pin)).unwrap().pin(), pin);
}

#[test]
fn corrupt_or_torn_tail_is_refused_without_silent_truncation() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); enqueue(&mut c, 1);
    let pin = j.pin(); j.accept(&batch(&c)).unwrap(); drop(j);
    let bytes = fs::read(t.path()).unwrap();
    for end in (HEADER_BYTES as usize + 1)..bytes.len() {
        fs::write(t.path(), &bytes[..end]).unwrap();
        assert_eq!(open(&t, Some(pin)).err(), Some(CheckDeliveryRefusal::CorruptJournal), "tail {end}");
        assert_eq!(fs::metadata(t.path()).unwrap().len(), end as u64);
    }
    let mut corrupt = bytes; corrupt[HEADER_BYTES as usize + 20] ^= 1;
    fs::write(t.path(), &corrupt).unwrap();
    assert_eq!(open(&t, Some(pin)).err(), Some(CheckDeliveryRefusal::CorruptJournal));
    assert_eq!(fs::read(t.path()).unwrap(), corrupt);
}

#[test]
fn trusted_minimum_pin_detects_valid_prefix_rollback() {
    let t = Temp::new(); let mut j = create(&t); let old = fs::read(t.path()).unwrap();
    let mut c = coordinator(); enqueue(&mut c, 1); j.accept(&batch(&c)).unwrap();
    let minimum = j.pin(); drop(j); fs::write(t.path(), old).unwrap();
    assert_eq!(open(&t, Some(minimum)).err(), Some(CheckDeliveryRefusal::CorruptJournal));
    // Without an independently retained witness, an empty valid journal cannot
    // be distinguished from an older copy. Do not claim unauthenticated anti-rollback.
    assert_eq!(open(&t, None).unwrap().pending_batches(), 0);
}

#[test]
fn reserved_delivery_space_remains_available_at_both_capacity_limits() {
    let t = Temp::new(); let mut c = coordinator(); enqueue(&mut c, 1); let first = batch(&c);
    let limits = CheckJournalLimits { journal_bytes: HEADER_BYTES + 4 + 1 + first.body().len() as u64 + 32 + DELIVERED_BYTES,
        records: 2, evidence_bytes: 64 };
    let mut j = FileCheckJournal::create(&t.path(), scope(), limits).unwrap();
    c.deliver_check_facts(&mut j, 128, MAX_BATCH_BYTES, &|| true).unwrap();
    enqueue(&mut c, 2); let pin = j.pin();
    assert_eq!(j.accept(&batch(&c)), Err(CheckDeliveryRefusal::JournalFull));
    assert_eq!(j.store_evidence(Commitment::of_bytes(b"x"), b"x"), Err(CheckDeliveryRefusal::JournalFull));
    assert_eq!(j.pin(), pin); assert!(!j.is_failed());
    assert!(j.accept(&first).is_ok());
    j.record_delivery(ack(&first)).unwrap(); assert_eq!(j.pending_batches(), 0);
    assert_eq!(j.pin().byte_len(), limits.journal_bytes);
}

#[test]
fn file_lock_private_permissions_symlinks_and_hardlinks_are_enforced() {
    let t = Temp::new(); let j = create(&t);
    assert_eq!(open(&t, None).err(), Some(CheckDeliveryRefusal::LockUnavailable)); drop(j);
    let link = t.0.join("link"); symlink(t.path(), &link).unwrap();
    assert_eq!(FileCheckJournal::open(&link, scope(), CheckJournalLimits::default(), None, &|| true).err(), Some(CheckDeliveryRefusal::StorageUnavailable));
    fs::hard_link(t.path(), t.0.join("hard")).unwrap();
    assert_eq!(open(&t, None).err(), Some(CheckDeliveryRefusal::StorageUnavailable));
    fs::remove_file(t.0.join("hard")).unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(open(&t, None).err(), Some(CheckDeliveryRefusal::StorageUnavailable));
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(open(&t, None).is_ok());
}

#[test]
fn unknown_records_excessive_lengths_and_duplicate_batches_fail_replay() {
    let t = Temp::new(); let mut j = create(&t); let header = fs::read(t.path()).unwrap();
    j.append(&[99], 0).unwrap(); drop(j);
    assert_eq!(open(&t, None).err(), Some(CheckDeliveryRefusal::CorruptJournal));
    let mut invalid = header.clone(); invalid.extend_from_slice(&u32::MAX.to_be_bytes()); fs::write(t.path(), invalid).unwrap();
    assert_eq!(open(&t, None).err(), Some(CheckDeliveryRefusal::CorruptJournal));
    fs::write(t.path(), header).unwrap(); let mut j = open(&t, None).unwrap();
    let mut c = coordinator(); enqueue(&mut c, 1); let batch = batch(&c); j.accept(&batch).unwrap();
    let mut duplicate = vec![1]; duplicate.extend_from_slice(batch.body()); j.append(&duplicate, 1).unwrap(); drop(j);
    assert_eq!(open(&t, None).err(), Some(CheckDeliveryRefusal::CorruptJournal));
}

#[test]
fn readback_corruption_poisoning_never_degrades_to_an_empty_queue() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); enqueue(&mut c, 1);
    j.accept(&batch(&c)).unwrap();
    // Inject a same-UID writer ignoring the advisory lock; production has no such path.
    let mut other = OpenOptions::new().write(true).open(t.path()).unwrap();
    other.seek(SeekFrom::Start(HEADER_BYTES + 20)).unwrap(); other.write_all(&[255]).unwrap(); other.sync_all().unwrap();
    assert_eq!(j.next_batch(), Err(CheckDeliveryRefusal::CorruptJournal)); assert!(j.is_failed());
    assert_eq!(j.next_batch(), Err(CheckDeliveryRefusal::FailedJournal)); assert_eq!(j.pending_batches(), 1);
}

struct Fragmented { bytes: Vec<u8>, fail_after: usize, interrupted: bool }
impl Write for Fragmented {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.interrupted { self.interrupted = true; return Err(io::ErrorKind::Interrupted.into()); }
        if self.bytes.len() >= self.fail_after { return Err(io::ErrorKind::StorageFull.into()); }
        let count = bytes.len().min(3).min(self.fail_after - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]); Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
#[test]
fn fragmented_and_interrupted_io_finishes_before_the_durability_callback() {
    let payload = b"exact record"; let hash = Commitment::of_bytes(b"frame"); let mut expected = Vec::new();
    write_frame(&mut expected, payload, hash, |_| Ok(())).unwrap();
    let mut writer = Fragmented { bytes: Vec::new(), fail_after: usize::MAX, interrupted: false };
    write_frame(&mut writer, payload, hash, |w| { assert_eq!(w.bytes, expected); Ok(()) }).unwrap();
    assert_eq!(writer.bytes, expected);
}
#[test]
fn every_partial_write_and_sync_failure_returns_no_successful_custody() {
    let payload = b"exact record"; let hash = Commitment::of_bytes(b"frame"); let length = 4 + payload.len() + 32;
    for cut in 0..length {
        let mut writer = Fragmented { bytes: Vec::new(), fail_after: cut, interrupted: false };
        assert!(write_frame(&mut writer, payload, hash, |_| panic!("must not sync partial frame")).is_err());
        assert_eq!(writer.bytes.len(), cut);
    }
    let mut writer = Vec::new();
    assert!(write_frame(&mut writer, payload, hash, |_| Err(io::ErrorKind::StorageFull.into())).is_err());
    assert_eq!(writer.len(), length); // Complete but not acknowledged as durable.
}

struct Substrate;
impl ContainmentSubstrate for Substrate {
    fn launch(&mut self, _: &crate::SandboxPlan) -> Result<crate::SubstrateObservation, crate::SubstrateRefusal> {
        Ok(crate::SubstrateObservation {
            exit: fgit_resource::kinds::ExitClass::Succeeded,
            usage: crate::ResourceUsage { cpu_micros: 1, memory_bytes: 1, disk_bytes: 1, network_bytes: 0, processes: 1, wall_clock_millis: 1 },
            reaped: fgit_resource::kinds::RunnerReaped { processes_reaped: 1, containment: fgit_resource::kinds::ContainmentClass::Cooperative },
            log_redaction: crate::LogRedactor::new(Vec::new()).unwrap().redact(b"fixture log").unwrap().receipt(),
            artifacts: Vec::new(),
        })
    }
}
#[test]
fn command_receipt_evidence_is_collected_and_retrievable_after_restart() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); let run = enqueue(&mut c, 1);
    let receipt = c.execute_job(run, "a", &mut Substrate, 20,
        vec![SourceObject::new(Commitment::of_bytes(b"source fixture"), 14)], Commitment::of_bytes(b"lock"), "pinned-toolchain").unwrap();
    let expected = receipt.evidence().frame().to_vec(); let root = Commitment::of_bytes(&expected);
    c.journal_check_facts(&mut j, 128, MAX_BATCH_BYTES, None, &|| true).unwrap();
    let pin = j.pin(); drop(c); drop(j);
    let mut j = open(&t, Some(pin)).unwrap(); assert_eq!(j.read_evidence(root).unwrap(), expected);
    let batch = j.next_batch().unwrap().unwrap();
    assert!(batch.facts().iter().any(|fact| fact.receipt_commitment == Some(root)));
}

#[test]
fn evidence_limit_and_foreign_coordinator_refuse_before_writing() {
    let t = Temp::new(); let limits = CheckJournalLimits { evidence_bytes: 3, ..CheckJournalLimits::default() };
    let mut j = FileCheckJournal::create(&t.path(), scope(), limits).unwrap(); let pin = j.pin();
    assert_eq!(j.store_evidence(Commitment::of_bytes(b"long"), b"long"), Err(CheckDeliveryRefusal::BatchTooLarge));
    let mut c = coordinator(); let run = enqueue(&mut c, 1);
    c.active_runs.get_mut(&run).unwrap().tenant = TenantId::from_bytes([9; 16]);
    assert_eq!(c.journal_check_facts(&mut j, 128, MAX_BATCH_BYTES, None, &|| true), Err(CheckDeliveryRefusal::ScopeMismatch));
    assert_eq!(j.pin(), pin); assert_eq!(c.pending_check_fact_count(), 2);
}

#[test]
fn damaged_evidence_prevents_forwarding_an_undamaged_proposal() {
    let t = Temp::new(); let mut j = create(&t); let mut c = coordinator(); let run = enqueue(&mut c, 1);
    let evidence = b"receipt body"; let id = Commitment::of_bytes(evidence);
    j.store_evidence(id, evidence).unwrap();
    c.outbox_facts.push(CheckRunFact { run_id: run, job_id: "a".into(), status: CheckRunStatus::Completed,
        conclusion: Some(CheckRunConclusion::Success), receipt_commitment: Some(id), timestamp_millis: 20 });
    c.obligations.check_publications_emitted += 1;
    c.deliver_check_facts(&mut j, 128, MAX_BATCH_BYTES, &|| true).unwrap();
    let frame = j.evidence[&id];
    let mut other = OpenOptions::new().write(true).open(t.path()).unwrap();
    other.seek(SeekFrom::Start(frame.offset + 4 + 33)).unwrap(); other.write_all(&[0]).unwrap(); other.sync_all().unwrap();
    let mut destination = Destination { attempts: Vec::new(), accepted: BTreeSet::new(), fail: false };
    assert_eq!(j.forward_next(&mut destination, &|| true), Err(CheckDeliveryRefusal::CorruptJournal));
    assert!(destination.attempts.is_empty()); assert!(j.is_failed()); assert_eq!(j.pending_batches(), 1);
}

#[test]
fn journal_header_and_evidence_frame_match_independent_sha256_goldens() {
    let header = scope().bytes();
    assert_eq!(header.len(), HEADER_BYTES as usize);
    assert_eq!(sha256_digest(&header), [0x4a, 0xba, 0x62, 0xa0, 0x4a, 0x2e, 0x44, 0x84, 0xa1, 0x89, 0xce, 0xa2, 0x0b, 0x9e, 0x8c, 0xb7, 0x8e, 0xa5, 0xdd, 0x23, 0x96, 0x3a, 0x90, 0x86, 0x72, 0xa3, 0x53, 0x5c, 0x8e, 0x8f, 0x27, 0x47]);
    let mut payload = vec![3]; root(&mut payload, Commitment::of_bytes(b"evidence"));
    payload.extend_from_slice(b"evidence");
    assert_eq!(frame_hash(Commitment::of_bytes(&header), &payload).digest().bytes().as_bytes(),
        &[0xaf, 0xa2, 0x14, 0x50, 0x8d, 0x04, 0x87, 0xef, 0x87, 0x82, 0xa6, 0x66, 0x9f, 0xaf, 0x45, 0x54, 0x73, 0x82, 0xa2, 0xa2, 0x05, 0x73, 0x9d, 0xae, 0xe8, 0x8a, 0x18, 0xda, 0xbc, 0x10, 0x7d, 0x8a]);
}
