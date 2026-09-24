//! Real private-file custody tests, not producer-authentication or CI proofs.
use super::*;
use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-history-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn file(&self) -> PathBuf {
        self.0.join("journal")
    }
    fn journal(&self) -> FileCheckJournal {
        FileCheckJournal::create(&self.file(), scope(), CheckJournalLimits::default()).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn digest(text: &str) -> Commitment {
    Commitment::of_bytes(text.as_bytes())
}
fn scope() -> CheckJournalScope {
    CheckJournalScope {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        journal_id: digest("journal"),
    }
}
fn batch(
    job: &str,
    ordinal: u64,
    completed: bool,
    evidence: Option<Commitment>,
) -> CheckDeliveryBatch {
    let run = WorkflowRunId(digest("run"));
    let mut batch = CheckDeliveryBatch {
        tenant: scope().tenant,
        repository: scope().repository,
        run,
        attempt: AttemptId::derive(run, 1),
        head: digest("head"),
        source: GitOid::Sha1(fgit_types::GitOidSha1::from_bytes([3; 20])),
        graph: digest("graph"),
        trust: TrustDomain::new(RunnerText::parse("trust", "fixture").unwrap()),
        profile: CoordinatorExecutionProfile::CommandOnly,
        ordinal,
        facts: vec![CheckRunFact {
            run_id: run,
            job_id: job.to_owned(),
            status: if completed {
                CheckRunStatus::Completed
            } else {
                CheckRunStatus::Queued
            },
            conclusion: completed.then_some(CheckRunConclusion::Failure),
            receipt_commitment: evidence,
            timestamp_millis: ordinal,
        }],
        body: Vec::new(),
    };
    batch.body = batch.encode().unwrap();
    batch
}
fn accept(journal: &mut FileCheckJournal, job: &str, ordinal: u64) -> CheckDeliveryBatch {
    let batch = batch(job, ordinal, false, None);
    journal.accept(&batch).unwrap();
    batch
}
fn deliver(journal: &mut FileCheckJournal, batch: &CheckDeliveryBatch) {
    journal
        .record_delivery(CheckDeliveryAcknowledgement::after_durable_acceptance(
            batch,
            digest("downstream"),
        ))
        .unwrap();
}
fn page(journal: &mut FileCheckJournal) -> CheckHistoryPage {
    journal
        .read_history(None, None, MAX_HISTORY_BATCHES, MAX_HISTORY_BYTES, &|| true)
        .unwrap()
}

#[test]
fn delivered_results_remain_readable_without_reopening_pending_custody() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    let first = accept(&mut journal, "first", 0);
    let second = accept(&mut journal, "second", 1);
    deliver(&mut journal, &first);
    let pin = journal.pin();
    let bytes = fs::read(directory.file()).unwrap();
    let history = page(&mut journal);
    assert_eq!(history.entries().len(), 2);
    assert_eq!(history.entries()[0].batch(), &first);
    assert_eq!(
        history.entries()[0].delivery_receipt(),
        Some(digest("downstream"))
    );
    assert_eq!(history.entries()[1].batch(), &second);
    assert_eq!(history.entries()[1].delivery_receipt(), None);
    assert_eq!(journal.next_batch().unwrap(), Some(second));
    assert_eq!(journal.pin(), pin);
    assert_eq!(fs::read(directory.file()).unwrap(), bytes);
    assert_eq!(journal.retained_batches(), 2);
}

#[test]
fn pages_follow_acceptance_order_not_commitment_sort_order() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    let batches = (0..7)
        .map(|n| accept(&mut journal, &format!("job-{n}"), n))
        .collect::<Vec<_>>();
    let mut after = None;
    let mut expected = None;
    let mut seen = Vec::new();
    loop {
        let history = journal
            .read_history(expected, after, 2, MAX_HISTORY_BYTES, &|| true)
            .unwrap();
        seen.extend(history.entries().iter().map(|entry| entry.batch().id()));
        expected = Some(history.snapshot());
        after = history.next_after();
        if after.is_none() {
            break;
        }
    }
    assert_eq!(
        seen,
        batches
            .iter()
            .map(CheckDeliveryBatch::id)
            .collect::<Vec<_>>()
    );
    assert_eq!(journal.pending_batches(), 7);
}

#[test]
fn empty_and_final_pages_do_not_fabricate_continuations() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    let empty = page(&mut journal);
    assert!(empty.entries().is_empty());
    assert_eq!(empty.next_after(), None);
    let first = accept(&mut journal, "only", 0);
    let last = journal
        .read_history(None, None, 1, MAX_HISTORY_BYTES, &|| true)
        .unwrap();
    assert_eq!(last.next_after(), None);
    let end = journal
        .read_history(
            Some(last.snapshot()),
            Some(first.id()),
            1,
            MAX_HISTORY_BYTES,
            &|| true,
        )
        .unwrap();
    assert!(end.entries().is_empty());
    assert_eq!(end.next_after(), None);
}

#[test]
fn byte_budget_is_exact_including_delivery_receipt() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    let first = accept(&mut journal, "first", 0);
    accept(&mut journal, "second", 1);
    deliver(&mut journal, &first);
    let size = first.body().len() + 32;
    let history = journal.read_history(None, None, 8, size, &|| true).unwrap();
    assert_eq!(history.entries().len(), 1);
    assert_eq!(history.next_after(), Some(first.id()));
    assert_eq!(
        journal.read_history(None, None, 8, size - 1, &|| true),
        Err(CheckDeliveryRefusal::BatchTooLarge)
    );
}

#[test]
fn append_or_acknowledgement_invalidates_a_paging_snapshot() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    let first = accept(&mut journal, "first", 0);
    let pin = journal.pin();
    accept(&mut journal, "second", 1);
    assert_eq!(
        journal.read_history(Some(pin), Some(first.id()), 1, MAX_HISTORY_BYTES, &|| true),
        Err(CheckDeliveryRefusal::StaleBatch)
    );
    let pin = journal.pin();
    deliver(&mut journal, &first);
    assert_eq!(
        journal.read_history(Some(pin), None, 1, MAX_HISTORY_BYTES, &|| true),
        Err(CheckDeliveryRefusal::StaleBatch)
    );
}

#[test]
fn unpinned_or_foreign_cursors_and_invalid_limits_refuse() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    let first = accept(&mut journal, "first", 0);
    assert_eq!(
        journal.read_history(None, Some(first.id()), 1, 1024, &|| true),
        Err(CheckDeliveryRefusal::StaleBatch)
    );
    assert_eq!(
        journal.read_history(
            Some(journal.pin()),
            Some(digest("unknown")),
            1,
            1024,
            &|| true
        ),
        Err(CheckDeliveryRefusal::StaleBatch)
    );
    for (count, bytes) in [
        (0, 1024),
        (MAX_HISTORY_BATCHES + 1, 1024),
        (1, 0),
        (1, MAX_HISTORY_BYTES + 1),
    ] {
        assert_eq!(
            journal.read_history(None, None, count, bytes, &|| true),
            Err(CheckDeliveryRefusal::InvalidLimits)
        );
    }
    assert!(!journal.is_failed());
}

#[test]
fn restart_retains_delivered_history_and_the_same_page_identity() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    let first = accept(&mut journal, "first", 0);
    let second = accept(&mut journal, "second", 1);
    deliver(&mut journal, &first);
    deliver(&mut journal, &second);
    let expected = page(&mut journal);
    drop(journal);
    let mut reopened = FileCheckJournal::open(
        &directory.file(),
        scope(),
        CheckJournalLimits::default(),
        Some(expected.snapshot()),
        &|| true,
    )
    .unwrap();
    assert_eq!(page(&mut reopened), expected);
    assert_eq!(reopened.pending_batches(), 0);
    assert_eq!(reopened.next_batch().unwrap(), None);
    assert_eq!(reopened.retained_batches(), 2);
}

#[test]
fn evidence_selection_requires_membership_in_the_selected_batch() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    let first = accept(&mut journal, "job", 0);
    journal
        .store_evidence(digest("evidence"), b"evidence")
        .unwrap();
    journal.store_evidence(digest("orphan"), b"orphan").unwrap();
    let completed = batch("job", 1, true, Some(digest("evidence")));
    journal.accept(&completed).unwrap();
    deliver(&mut journal, &first);
    deliver(&mut journal, &completed);
    assert_eq!(
        journal
            .read_batch_evidence(completed.id(), digest("evidence"))
            .unwrap(),
        b"evidence"
    );
    assert_eq!(
        journal.read_batch_evidence(first.id(), digest("evidence")),
        Err(CheckDeliveryRefusal::EvidenceMissing)
    );
    assert_eq!(
        journal.read_batch_evidence(completed.id(), digest("orphan")),
        Err(CheckDeliveryRefusal::EvidenceMissing)
    );
    assert_eq!(
        journal.read_retained_batch(digest("unknown")),
        Err(CheckDeliveryRefusal::StaleBatch)
    );
}

#[test]
fn cancellation_returns_no_partial_page_and_leaves_custody_unchanged() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    accept(&mut journal, "first", 0);
    accept(&mut journal, "second", 1);
    let pin = journal.pin();
    let calls = Cell::new(0);
    assert_eq!(
        journal.read_history(None, None, 8, MAX_HISTORY_BYTES, &|| {
            calls.set(calls.get() + 1);
            calls.get() < 3
        }),
        Err(CheckDeliveryRefusal::Cancelled)
    );
    assert_eq!(journal.pin(), pin);
    assert_eq!(journal.pending_batches(), 2);
    assert!(!journal.is_failed());
}

#[test]
fn corrupt_delivered_proposal_or_acknowledgement_cannot_hide_in_history() {
    for corrupt_ack in [false, true] {
        let directory = Directory::new();
        let mut journal = directory.journal();
        let first = accept(&mut journal, "first", 0);
        deliver(&mut journal, &first);
        let entry = &journal.batches[&first.id()];
        let frame = if corrupt_ack {
            entry.delivered.unwrap().1
        } else {
            entry.frame
        };
        let mut bytes = fs::read(directory.file()).unwrap();
        bytes[frame.offset as usize + 4] ^= 1;
        fs::write(directory.file(), bytes).unwrap();
        assert_eq!(
            journal.read_retained_batch(first.id()),
            Err(CheckDeliveryRefusal::CorruptJournal)
        );
        assert!(journal.is_failed());
    }
}

#[test]
fn empty_history_rechecks_its_on_disk_scope_and_length() {
    let directory = Directory::new();
    let mut journal = directory.journal();
    let mut bytes = fs::read(directory.file()).unwrap();
    bytes[0] ^= 1;
    fs::write(directory.file(), bytes).unwrap();
    assert_eq!(
        journal.read_history(None, None, 1, 1024, &|| true),
        Err(CheckDeliveryRefusal::CorruptJournal)
    );
    assert!(journal.is_failed());
}
