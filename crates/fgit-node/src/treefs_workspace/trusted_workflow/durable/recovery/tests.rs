//! Uses real node composition from the sibling fixture, not a second codec.
use super::*;
use super::super::tests::{Executor, Temp, prepare, report};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::io::Write;

fn marker(report: &TrustedWorkflowRun) {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(report.run_directory.join("attempt.json")).unwrap();
    file.write_all(report.attempt_marker().as_bytes()).unwrap(); file.sync_all().unwrap();
    File::open(&report.run_directory).unwrap().sync_all().unwrap();
}

#[test]
fn complete_custody_reopens_without_final_report_source_or_live_node() {
    let temp = Temp::new(); let mut report = report(&temp); marker(&report);
    let prepared = prepare(&report); let expected = report.check_journal_scope();
    report.execution = prepared.execute(&temp.0, &mut Executor::new(&temp), &|| true).unwrap();
    assert!(!temp.0.join("report.json").exists());
    let mut journal = report.open_check_journal(None, &|| true).unwrap();
    let pin = journal.pin(); let first = journal.next_batch().unwrap().unwrap();
    assert_eq!(journal.pending_batches(), 3); drop(journal); drop(report);
    let mut journal = OneNode::open_trusted_workflow_journal(&temp.0, expected, Some(pin), &|| true).unwrap();
    assert_eq!(journal.next_batch().unwrap().unwrap().body(), first.body());
    assert!(!temp.0.join("report.json").exists());
}

#[test]
fn producer_lock_excludes_recovery_and_partial_queue_is_not_execution_success() {
    let temp = Temp::new(); let report = report(&temp); marker(&report);
    let expected = report.check_journal_scope();
    let journal = FileCheckJournal::create(&temp.0.join(JOURNAL_FILE), expected, Default::default()).unwrap();
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, expected, None, &|| true).is_err());
    let pin = journal.pin(); drop(journal);
    let mut reopened = OneNode::open_trusted_workflow_journal(&temp.0, expected, Some(pin), &|| true).unwrap();
    assert!(reopened.next_batch().unwrap().is_none());
    assert!(!temp.0.join(OWNER_FILE).exists());
    assert!(!temp.0.join("report.json").exists());
}

#[test]
fn missing_marker_missing_journal_and_bad_scope_never_recreate_files() {
    let temp = Temp::new(); let report = report(&temp); let scope = report.check_journal_scope();
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, scope, None, &|| true).is_err());
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
    marker(&report);
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, scope, None, &|| true).is_err());
    assert!(!temp.0.join(JOURNAL_FILE).exists());
    drop(FileCheckJournal::create(&temp.0.join(JOURNAL_FILE), scope, Default::default()).unwrap());
    let bytes = fs::read(temp.0.join(JOURNAL_FILE)).unwrap();
    let mut wrong = scope; wrong.repository = fgit_types::RepositoryId::from_bytes([0xff;16]);
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, wrong, None, &|| true).is_err());
    wrong = scope; wrong.journal_id = Commitment::of_bytes(b"different attempt");
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, wrong, None, &|| true).is_err());
    assert_eq!(fs::read(temp.0.join(JOURNAL_FILE)).unwrap(), bytes);
}

#[test]
fn marker_corruption_symlinks_and_excess_size_refuse_before_journal_access() {
    let temp = Temp::new(); let report = report(&temp); marker(&report);
    let expected = report.check_journal_scope();
    let path = temp.0.join("attempt.json"); let original = fs::read(&path).unwrap();
    fs::write(&path, b"corrupt").unwrap();
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, expected, None, &|| true).is_err());
    fs::write(&path, &original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, expected, None, &|| true).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(MAX_MARKER_BYTES+1).unwrap();
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, expected, None, &|| true).is_err());
    fs::remove_file(&path).unwrap();
    fs::write(temp.0.join("other"), &original).unwrap();
    symlink(temp.0.join("other"), &path).unwrap();
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, expected, None, &|| true).is_err());
    assert!(!temp.0.join(JOURNAL_FILE).exists());
}

#[test]
fn trusted_checkpoint_detects_rollback_and_cancelled_recovery_does_no_io() {
    let temp = Temp::new(); let report = report(&temp); marker(&report);
    let scope = report.check_journal_scope();
    let mut journal = FileCheckJournal::create(&temp.0.join(JOURNAL_FILE), scope, Default::default()).unwrap();
    let prior = fs::read(temp.0.join(JOURNAL_FILE)).unwrap();
    journal.store_evidence(Commitment::of_bytes(b"kept"), b"kept").unwrap();
    let pin = journal.pin(); drop(journal);
    fs::write(temp.0.join(JOURNAL_FILE), &prior).unwrap();
    assert!(OneNode::open_trusted_workflow_journal(&temp.0, scope, Some(pin), &|| true).is_err());
    assert_eq!(fs::read(temp.0.join(JOURNAL_FILE)).unwrap(), prior);
    let missing = temp.0.join("does-not-exist");
    assert!(OneNode::open_trusted_workflow_journal(&missing, scope, None, &|| false).is_err());
    assert!(!missing.exists());
}
