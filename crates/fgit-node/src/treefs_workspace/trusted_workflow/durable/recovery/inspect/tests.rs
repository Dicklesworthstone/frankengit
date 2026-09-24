//! Real workflow coordinator/owner/journal composition with a fixture executor.
//! No source repository or final report is needed for the recovery calls.
use super::super::super::tests::{Executor, Temp, prepare, report};
use super::*;
use fgit_runner::coordinator::delivery::CheckDeliveryAcknowledgement;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

fn saved(temp: &Temp) -> (TenantId, RepositoryId, Digest) {
    let mut report = report(temp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp.0.join("attempt.json"))
        .unwrap();
    file.write_all(report.attempt_marker().as_bytes()).unwrap();
    file.sync_all().unwrap();
    report.execution = prepare(&report)
        .execute(&temp.0, &mut Executor::new(temp), &|| true)
        .unwrap();
    let scope = report.check_journal_scope();
    (scope.tenant, scope.repository, scope.journal_id.digest())
}
fn current(temp: &Temp, expected: (TenantId, RepositoryId, Digest)) -> FileCheckJournal {
    OneNode::open_trusted_workflow_journal(&temp.0, checked_scope(expected).unwrap(), None, &|| {
        true
    })
    .unwrap()
}

#[test]
fn actual_coordinated_results_remain_observable_after_every_delivery_is_acknowledged() {
    let temp = Temp::new();
    let expected = saved(&temp);
    let mut journal = current(&temp, expected);
    let mut count = 0;
    while let Some(batch) = journal.next_batch().unwrap() {
        // This acknowledgement is a test fixture; never a canonical check.
        journal
            .record_delivery(CheckDeliveryAcknowledgement::after_durable_acceptance(
                &batch,
                Commitment::of_bytes(b"fixture custody"),
            ))
            .unwrap();
        count += 1;
    }
    let pin = journal.pin();
    drop(journal);
    let before = fs::read(temp.0.join(JOURNAL_FILE)).unwrap();
    let json = OneNode::trusted_workflow_history_json(
        &temp.0,
        expected,
        Some((pin.byte_len(), pin.tail().digest())),
        None,
        None,
        (128, 8 * 1024 * 1024),
        &|| true,
    )
    .unwrap();
    assert!(json.contains("\"pending_batches\":0"));
    assert_eq!(json.matches("\"delivery\":\"acknowledged\"").count(), count);
    assert!(json.contains("\"conclusion\":\"action_required\""));
    assert!(!json.contains("\"conclusion\":\"success\""));
    assert!(json.contains("\"execution_completion\":\"not_asserted\""));
    assert!(!temp.0.join("report.json").exists());
    assert_eq!(fs::read(temp.0.join(JOURNAL_FILE)).unwrap(), before);
}

#[test]
fn page_continuation_is_exact_and_rejected_after_append() {
    let temp = Temp::new();
    let expected = saved(&temp);
    let mut journal = current(&temp, expected);
    let page = journal
        .read_history(None, None, 1, 1024 * 1024, &|| true)
        .unwrap();
    let after = page.next_after().unwrap().digest();
    let pin = page.snapshot();
    drop(journal);
    let result = OneNode::trusted_workflow_history_json(
        &temp.0,
        expected,
        None,
        Some((pin.byte_len(), pin.tail().digest())),
        Some(after),
        (1, 1024 * 1024),
        &|| true,
    )
    .unwrap();
    assert!(result.contains("\"entries\":[{"));
    let mut journal = current(&temp, expected);
    journal
        .store_evidence(Commitment::of_bytes(b"later"), b"later")
        .unwrap();
    drop(journal);
    assert!(
        OneNode::trusted_workflow_history_json(
            &temp.0,
            expected,
            None,
            Some((pin.byte_len(), pin.tail().digest())),
            Some(after),
            (1, 1024 * 1024),
            &|| true
        )
        .is_err()
    );
}

#[test]
fn exact_job_evidence_is_available_without_report_or_prepared_handle() {
    let temp = Temp::new();
    let expected = saved(&temp);
    let mut journal = current(&temp, expected);
    let page = journal
        .read_history(None, None, 128, 8 * 1024 * 1024, &|| true)
        .unwrap();
    let entry = page
        .entries()
        .iter()
        .find(|entry| {
            entry
                .batch()
                .facts()
                .iter()
                .any(|fact| fact.receipt_commitment.is_some())
        })
        .unwrap();
    let batch = entry.batch().id();
    let evidence = entry
        .batch()
        .facts()
        .iter()
        .find_map(|fact| fact.receipt_commitment)
        .unwrap();
    let retained = journal.read_batch_evidence(batch, evidence).unwrap();
    drop(journal);
    let (bytes, json) = OneNode::trusted_workflow_artifact(
        &temp.0,
        expected,
        None,
        batch.digest(),
        Some(evidence.digest()),
        &|| true,
    )
    .unwrap();
    assert_eq!(bytes, retained);
    assert!(json.contains(&format!("\"sha256\":\"{}\"", root_hex(evidence))));
    assert!(json.contains("\"kind\":\"evidence\""));
    let (bytes, _) =
        OneNode::trusted_workflow_artifact(&temp.0, expected, None, batch.digest(), None, &|| true)
            .unwrap();
    assert_eq!(bytes, entry.batch().body());
    assert!(
        OneNode::trusted_workflow_artifact(
            &temp.0,
            expected,
            None,
            batch.digest(),
            Some(Commitment::of_bytes(b"unrelated").digest()),
            &|| true
        )
        .is_err()
    );
}

#[test]
fn invalid_or_cancelled_recovery_never_creates_a_missing_source() {
    let temp = Temp::new();
    let missing = temp.0.join("missing");
    let expected = (
        TenantId::from_bytes([1; 16]),
        RepositoryId::from_bytes([2; 16]),
        Commitment::of_bytes(b"marker").digest(),
    );
    assert!(
        OneNode::trusted_workflow_history_json(
            &missing,
            expected,
            None,
            None,
            None,
            (1, 1024),
            &|| false
        )
        .is_err()
    );
    assert!(
        OneNode::trusted_workflow_history_json(
            &missing,
            expected,
            None,
            None,
            None,
            (0, 1024),
            &|| true
        )
        .is_err()
    );
    assert!(!missing.exists());
    assert!(checked_pin((71, expected.2)).is_err());
    let wrong_width = Digest::new(
        DigestAlgorithm::Sha256.id(),
        fgit_crypto::DigestBytes::try_new(&[1; 20]).unwrap(),
    );
    assert!(checked_root(wrong_width).is_err());
}

#[test]
fn reader_obeys_producer_lock_and_rejects_foreign_scope_and_corrupt_evidence() {
    let temp = Temp::new();
    let expected = saved(&temp);
    let journal = current(&temp, expected);
    assert!(
        OneNode::trusted_workflow_history_json(
            &temp.0,
            expected,
            None,
            None,
            None,
            (1, 1024),
            &|| true
        )
        .is_err()
    );
    drop(journal);
    let mut foreign = expected;
    foreign.0 = TenantId::from_bytes([9; 16]);
    assert!(
        OneNode::trusted_workflow_history_json(
            &temp.0,
            foreign,
            None,
            None,
            None,
            (1, 1024),
            &|| true
        )
        .is_err()
    );
    let path = temp.0.join(JOURNAL_FILE);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(
        OneNode::trusted_workflow_history_json(
            &temp.0,
            expected,
            None,
            None,
            None,
            (1, 1024),
            &|| true
        )
        .is_err()
    );
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn json_fields_escape_untrusted_strings_and_separate_scope_from_authority() {
    assert_eq!(quoted("job\"\\\n\t"), "\"job\\\"\\\\\\u000a\\u0009\"");
    let scope = CheckJournalScope {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        journal_id: Commitment::of_bytes(b"marker"),
    };
    assert!(scope_json(scope).contains(&root_hex(scope.journal_id)));
    assert_eq!(
        pin_json(CheckJournalPin::new(72, scope.journal_id)),
        quoted(&format!("72:{}", root_hex(scope.journal_id)))
    );
}
