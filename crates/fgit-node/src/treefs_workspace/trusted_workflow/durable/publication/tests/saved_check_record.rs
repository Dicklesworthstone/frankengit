//! The publication loader reads actual saved node executions through the
//! original private marker and journal, without consuming or rerunning them.
use super::*;
use fgit_crypto::Digest;
use fgit_runner::coordinator::delivery::CheckDeliveryAcknowledgement;

#[derive(Clone, Copy)]
struct Selection {
    expected: (TenantId, RepositoryId, Digest),
    minimum: (u64, Digest),
    batch: Digest,
    fact: usize,
    unfinished: (Digest, usize),
}

fn selection(run: &TrustedWorkflowRun) -> Selection {
    let scope = run.check_journal_scope();
    let mut journal = run.open_check_journal(None, &|| true).unwrap();
    let (completed, fact, _) = completed(&mut journal);
    let history = journal
        .read_history(None, None, 128, 1024 * 1024, &|| true)
        .unwrap();
    let unfinished = history
        .entries()
        .iter()
        .find_map(|entry| {
            entry
                .batch()
                .facts()
                .iter()
                .position(|fact| fact.status != CheckRunStatus::Completed)
                .map(|index| (entry.batch().id().digest(), index))
        })
        .unwrap();
    let pin = journal.pin();
    Selection {
        expected: (scope.tenant, scope.repository, scope.journal_id.digest()),
        minimum: (pin.byte_len(), pin.tail().digest()),
        batch: completed.id().digest(),
        fact,
        unfinished,
    }
}

fn load(
    run: &TrustedWorkflowRun,
    selected: Selection,
    live: &dyn Fn() -> bool,
) -> Result<WorkflowCheckRecord, super::super::super::TrustedWorkflowFailure> {
    OneNode::trusted_workflow_check_record(
        &run.run_directory,
        selected.expected,
        Some(selected.minimum),
        selected.batch,
        selected.fact,
        source_ref(),
        live,
    )
}

#[test]
fn actual_saved_job_loads_exact_publication_record_without_source_node_or_final_report() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let temp = Temp::new();
        let (node, _, run) = run_fixture(&temp, format, false);
        let selected = selection(&run);
        let expected = submitted_record(&run);
        let before = materialize(&node).basis().id();
        assert_eq!(load(&run, selected, &|| true).unwrap(), expected);
        assert_eq!(
            materialize(&node).basis().id(),
            before,
            "loading does not publish"
        );
        node.shutdown().unwrap();
        fs::remove_file(run.run_directory.join("report.json")).unwrap();
        fs::remove_dir_all(temp.0.join("source")).unwrap();
        let journal_path = run.run_directory.join("check-proposals.journal");
        let marker_path = run.run_directory.join("attempt.json");
        let owner_path = run.run_directory.join("execution.owner");
        let journal = fs::read(&journal_path).unwrap();
        let marker = fs::read(&marker_path).unwrap();
        let owner = fs::read(&owner_path).unwrap();
        for _ in 0..2 {
            let record = load(&run, selected, &|| true).unwrap();
            assert_eq!(record, expected);
            assert_eq!(record.source_commit.algorithm(), format);
            assert_eq!(record.conclusion, WorkflowCheckConclusion::ActionRequired);
            assert_eq!(fs::read(&journal_path).unwrap(), journal);
            assert_eq!(fs::read(&marker_path).unwrap(), marker);
            assert_eq!(fs::read(&owner_path).unwrap(), owner);
            assert!(!run.run_directory.join("report.json").exists());
            assert!(!temp.0.join("source").exists());
        }
    }
}

#[test]
fn exact_saved_job_selection_rejects_foreign_scope_pin_batch_fact_lock_and_cancellation() {
    let temp = Temp::new();
    let (node, _, run) = run_fixture(&temp, GitHashAlgorithm::Sha1, false);
    let selected = selection(&run);
    let expected = submitted_record(&run);
    let journal_path = run.run_directory.join("check-proposals.journal");
    let before = fs::read(&journal_path).unwrap();
    for case in 0..8 {
        let mut invalid = selected;
        match case {
            0 => invalid.expected.0 = TenantId::from_bytes([0xf1; 16]),
            1 => invalid.expected.1 = RepositoryId::from_bytes([0xf2; 16]),
            2 => invalid.expected.2 = Commitment::of_bytes(b"foreign marker").digest(),
            3 => invalid.batch = Commitment::of_bytes(b"absent batch").digest(),
            4 => invalid.fact = usize::MAX,
            5 => {
                invalid.batch = selected.unfinished.0;
                invalid.fact = selected.unfinished.1;
            }
            6 => invalid.minimum.1 = Commitment::of_bytes(b"unretained checkpoint").digest(),
            _ => invalid.minimum.0 = 71,
        }
        assert!(load(&run, invalid, &|| true).is_err(), "selection {case}");
        assert_eq!(load(&run, selected, &|| true).unwrap(), expected);
        assert_eq!(fs::read(&journal_path).unwrap(), before);
    }
    let held = run.open_check_journal(None, &|| true).unwrap();
    assert!(
        load(&run, selected, &|| true).is_err(),
        "another owner holds the journal lock"
    );
    drop(held);
    assert_eq!(load(&run, selected, &|| true).unwrap(), expected);
    assert!(load(&run, selected, &|| false).is_err());
    assert_eq!(load(&run, selected, &|| true).unwrap(), expected);
    let checkpoints = std::cell::Cell::new(0_usize);
    assert_eq!(
        load(&run, selected, &|| {
            checkpoints.set(checkpoints.get() + 1);
            true
        })
        .unwrap(),
        expected
    );
    let last = checkpoints.get();
    assert!(last > 1);
    checkpoints.set(0);
    assert!(
        load(&run, selected, &|| {
            checkpoints.set(checkpoints.get() + 1);
            checkpoints.get() < last
        })
        .is_err(),
        "cancellation during final lowering cannot return a partial record"
    );
    assert_eq!(load(&run, selected, &|| true).unwrap(), expected);
    assert!(
        OneNode::trusted_workflow_check_record(
            &run.run_directory,
            selected.expected,
            Some(selected.minimum),
            selected.batch,
            selected.fact,
            RefName::try_new(b"refs/tags/v1").unwrap(),
            &|| true,
        )
        .is_err()
    );
    let missing = temp.0.join("missing-attempt");
    assert!(
        OneNode::trusted_workflow_check_record(
            &missing,
            selected.expected,
            Some(selected.minimum),
            selected.batch,
            selected.fact,
            source_ref(),
            &|| false,
        )
        .is_err()
    );
    assert!(!missing.exists());
    assert_eq!(fs::read(&journal_path).unwrap(), before);
    assert_eq!(load(&run, selected, &|| true).unwrap(), expected);
    // Roll back to a VALID earlier prefix. Without the independently retained
    // newer pin this is still an internally consistent completed-job history.
    let mut journal = run.open_check_journal(None, &|| true).unwrap();
    journal
        .store_evidence(
            Commitment::of_bytes(b"later retained evidence"),
            b"later retained evidence",
        )
        .unwrap();
    let pin = journal.pin();
    let pinned = Selection {
        minimum: (pin.byte_len(), pin.tail().digest()),
        ..selected
    };
    drop(journal);
    assert_eq!(load(&run, pinned, &|| true).unwrap(), expected);
    fs::write(&journal_path, &before).unwrap();
    assert!(
        load(&run, pinned, &|| true).is_err(),
        "the saved minimum must detect prefix rollback"
    );
    assert_eq!(load(&run, selected, &|| true).unwrap(), expected);
    assert_eq!(fs::read(&journal_path).unwrap(), before);
    node.shutdown().unwrap();
}

#[test]
fn acknowledged_saved_failure_stays_publishable_without_fabricating_success_or_consuming_history() {
    let temp = Temp::new();
    let (node, _, run) = run_fixture(&temp, GitHashAlgorithm::Sha256, true);
    let selected = selection(&run);
    let expected = submitted_record(&run);
    assert_eq!(expected.conclusion, WorkflowCheckConclusion::Failure);
    let mut journal = run.open_check_journal(None, &|| true).unwrap();
    while let Some(batch) = journal.next_batch().unwrap() {
        // This is test-only downstream custody, not a canonical check receipt.
        journal
            .record_delivery(CheckDeliveryAcknowledgement::after_durable_acceptance(
                &batch,
                Commitment::of_bytes(b"fixture downstream custody"),
            ))
            .unwrap();
    }
    assert_eq!(journal.pending_batches(), 0);
    let retained = journal.retained_batches();
    drop(journal);
    let before = fs::read(run.run_directory.join("check-proposals.journal")).unwrap();
    let record = load(&run, selected, &|| true).unwrap();
    assert_eq!(record, expected);
    assert_eq!(record.conclusion, WorkflowCheckConclusion::Failure);
    assert_eq!(
        fs::read(run.run_directory.join("check-proposals.journal")).unwrap(),
        before
    );
    let reopened = run.open_check_journal(None, &|| true).unwrap();
    assert_eq!(reopened.pending_batches(), 0);
    assert_eq!(reopened.retained_batches(), retained);
    drop(reopened);
    assert!(matches!(
        publish(&node, &record, b"publish-saved-failure").1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    assert_eq!(
        fs::read(run.run_directory.join("check-proposals.journal")).unwrap(),
        before
    );
    node.shutdown().unwrap();
}
