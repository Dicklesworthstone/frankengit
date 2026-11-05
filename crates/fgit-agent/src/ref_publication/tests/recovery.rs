//! Recovery uses the ordinary authenticated authority observation and existing
//! journal codec. The recording sink below is a storage fault model, not a
//! filesystem/durability substitute; native custody and suffix tests live with
//! the node's actual file owner.

use super::*;

#[derive(Debug)]
struct RecordingSink {
    run: IntentRunCommitment,
    before: EffectJournalPosition,
    after: EffectJournalPosition,
    frame: Vec<u8>,
    calls: usize,
    reply: Result<EffectJournalPosition, EffectJournalPersistenceRefusal>,
}

impl RecordingSink {
    fn confirming(prepared: &PreparedRefTransactionAcknowledgement) -> Self {
        Self {
            run: prepared.run_commitment(),
            before: prepared.before_position(),
            after: prepared.after_position(),
            frame: prepared.frame().to_vec(),
            calls: 0,
            reply: Ok(prepared.after_position()),
        }
    }
}

impl RefTransactionAcknowledgementSink for RecordingSink {
    fn persist_acknowledgement(
        &mut self,
        prepared: &PreparedRefTransactionAcknowledgement,
    ) -> Result<EffectJournalPosition, EffectJournalPersistenceRefusal> {
        assert_eq!(prepared.run_commitment(), self.run);
        assert_eq!(prepared.before_position(), self.before);
        assert_eq!(prepared.after_position(), self.after);
        assert_eq!(prepared.frame(), self.frame);
        self.calls += 1;
        self.reply
    }
}

fn observed_terminal(
    fixture: &Fixture,
    attempt: &SealAttempt,
    binding: &RefTransactionBinding,
    commit: bool,
) -> ObservedRefTransaction {
    assert_eq!(
        seal_request(&fixture.store, attempt).unwrap().tx_id(),
        binding.tx_id()
    );
    let terminal = fixture.decide(binding.tx_id(), commit);
    let head = fixture.store.read_head(&fixture.head_key).unwrap();
    let view = AsyncView::new(&fixture.store);
    let observation = poll_ready(observe_ref_transaction_async(
        &view,
        &(),
        &fixture.head_key,
        &fixture.run,
        binding,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(observation.terminal(), &terminal);
    assert_eq!(fixture.store.read_head(&fixture.head_key).unwrap(), head);
    view.assert_read_only();
    observation
}

fn encoded_journal(run: &IntentRun, entries: &[EffectJournalEntry]) -> RecoveredEffectJournal {
    let (mut encoder, mut bytes) = EffectJournalEncoder::new(run).unwrap();
    for entry in entries {
        bytes.extend(encoder.encode(entry).unwrap());
    }
    RecoveredEffectJournal::decode(run, &bytes, Some(encoder.position())).unwrap()
}

fn settle_live(fixture: &Fixture, pending: PendingRefTransactionSubmission) {
    let view = AsyncView::new(&fixture.store);
    assert!(matches!(
        poll_ready(pending.reconcile_async(&view, &(), &fixture.head_key)).unwrap(),
        RefTransactionResolution::Decided(_)
    ));
    view.assert_read_only();
}

#[test]
fn recovered_commit_and_refusal_ack_bytes_equal_the_live_path_after_expiry_and_revocation() {
    for committed in [false, true] {
        let fixture = Fixture::new(901 + u64::from(committed));
        let attempt = seal_attempt(b"recover-exact-terminal");
        let binding = submission_binding(&fixture.run, &attempt)
            .with_custody_commitment([0xa1; 32])
            .unwrap();
        let (mut owner, capture) = broker(&fixture.run);
        let reservation = reserve(&fixture, &mut owner, &binding);
        let pending = start(&fixture, &mut owner, reservation);
        let prefix = capture.decode(&fixture.run).unwrap();
        let original_bytes = capture.0.borrow().bytes.clone();
        let original_record = prefix.records()[0].clone();
        fixture.revoke(&[CapabilityId::new(1)]);
        let observation = observed_terminal(&fixture, &attempt, &binding, committed);
        let now = LogicalTime::new(101);
        assert!(!fixture.run.is_open_at(now));
        let prepared = prepare_recovered_ref_transaction_acknowledgement(
            &fixture.run,
            &prefix,
            &observation,
            now,
        )
        .unwrap();
        assert_eq!(prepared.run_commitment(), fixture.run.commitment().unwrap());
        assert_eq!(prepared.before_position(), prefix.position());
        assert_eq!(
            prepared.after_position().entries,
            prefix.position().entries + 1
        );
        assert!(!prepared.already_acknowledged());
        assert!(!prepared.frame().is_empty());
        assert_eq!(
            prefix.records()[0],
            original_record,
            "preparation does not settle its input"
        );
        let mut expected_bytes = original_bytes;
        expected_bytes.extend_from_slice(prepared.frame());
        let mut sink = RecordingSink::confirming(&prepared);
        let settled = prepared.persist(&mut sink).unwrap();
        assert_eq!(sink.calls, 1);
        assert_eq!(settled.observation(), &observation);
        assert_eq!(settled.before_position(), prefix.position());
        assert_eq!(settled.after_position(), sink.after);
        let expected = RecoveredEffectJournal::decode(
            &fixture.run,
            &expected_bytes,
            Some(settled.after_position()),
        )
        .unwrap();
        assert_eq!(settled.journal().entries(), expected.entries());
        assert_eq!(settled.journal().records(), expected.records());
        let record = &settled.journal().records()[0];
        assert_eq!(record.budget_reserved, original_record.budget_reserved);
        assert_eq!(record.budget_consumed, original_record.budget_consumed);
        assert_eq!(record.obligation_state, ObligationState::Acknowledged);
        assert_eq!(
            record.terminal_outcome,
            Some(EffectTerminalOutcome::Acknowledged)
        );
        assert_eq!(record.output_commitments.len(), 1);
        assert_eq!(
            record.output_commitments[0].as_slice(),
            observation.commitment().bytes().as_bytes()
        );
        let report = settled
            .journal()
            .reconciliation_report(&fixture.run, now)
            .unwrap();
        assert_eq!(report.readiness(), RunReconciliationReadiness::Ready);
        assert_eq!(report.cumulative_budget_consumed(), cost());
        settle_live(&fixture, pending);
        assert_eq!(
            capture.0.borrow().bytes,
            expected_bytes,
            "recovered ACK uses unchanged live event framing"
        );
        assert_eq!(owner.records(), settled.journal().records());
        assert!(owner.close().is_quiescent());
    }
}

#[test]
fn finishing_one_submission_keeps_other_effects_and_their_debt_unchanged() {
    let fixture = Fixture::new(910);
    let attempt = seal_attempt(b"selected-recovered-submission");
    let binding = submission_binding(&fixture.run, &attempt);
    let other = submission_binding(&fixture.run, &seal_attempt(b"still-reserved-submission"));
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let pending = start(&fixture, &mut owner, reservation);
    let other_reservation = reserve(&fixture, &mut owner, &other);
    let prefix = capture.decode(&fixture.run).unwrap();
    let other_before = prefix.records()[1].clone();
    let observation = observed_terminal(&fixture, &attempt, &binding, true);
    let prepared = prepare_recovered_ref_transaction_acknowledgement(
        &fixture.run,
        &prefix,
        &observation,
        LogicalTime::new(40),
    )
    .unwrap();
    let mut sink = RecordingSink::confirming(&prepared);
    let settled = prepared.persist(&mut sink).unwrap();
    assert_eq!(settled.journal().records()[1], other_before);
    assert_eq!(
        settled.journal().ref_transactions(),
        prefix.ref_transactions()
    );
    let report = settled
        .journal()
        .reconciliation_report(&fixture.run, LogicalTime::new(40))
        .unwrap();
    assert_eq!(
        report.readiness(),
        RunReconciliationReadiness::ReservationAbortRequired
    );
    assert_eq!(report.counts().acknowledged(), 1);
    assert_eq!(report.counts().reserved(), 1);
    assert_eq!(report.cumulative_budget_consumed(), cost());
    settle_live(&fixture, pending);
    let _aborted = other_reservation
        .abort(NoCandidateReason::Cancelled)
        .unwrap();
    assert!(owner.close().is_quiescent());
}

#[test]
fn preparation_requires_the_anchor_complete_run_original_custody_and_valid_inventory() {
    let fixture = Fixture::new(920);
    let attempt = seal_attempt(b"recovery-binding");
    let binding = submission_binding(&fixture.run, &attempt)
        .with_custody_commitment([0xa2; 32])
        .unwrap();
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let pending = start(&fixture, &mut owner, reservation);
    let prefix = capture.decode(&fixture.run).unwrap();
    let observation = observed_terminal(&fixture, &attempt, &binding, false);
    let now = LogicalTime::new(40);
    let unanchored =
        RecoveredEffectJournal::decode(&fixture.run, &capture.0.borrow().bytes, None).unwrap();
    assert!(matches!(
        prepare_recovered_ref_transaction_acknowledgement(
            &fixture.run,
            &unanchored,
            &observation,
            now
        ),
        Err(RefTransactionRecoveryRefusal::Journal(
            EffectJournalCodecRefusal::AnchorRequired
        ))
    ));
    let changed_run = IntentRun::new_authenticated(
        fixture.run.run_id(),
        fixture.run.authority_read_receipt().unwrap().clone(),
        fixture.run.allowed_operation_classes(),
        fixture.run.resource_budget(),
        LogicalTime::new(101),
    )
    .unwrap();
    assert!(matches!(
        prepare_recovered_ref_transaction_acknowledgement(&changed_run, &prefix, &observation, now),
        Err(RefTransactionRecoveryRefusal::Journal(
            EffectJournalCodecRefusal::RunMismatch
        ))
    ));
    assert!(matches!(
        prepare_recovered_ref_transaction_acknowledgement(
            &fixture.run,
            &prefix,
            &observation,
            LogicalTime::new(20)
        ),
        Err(RefTransactionRecoveryRefusal::Journal(
            EffectJournalCodecRefusal::Reconciliation
        ))
    ));
    // Same ordinary TxId and canonical terminal, but another custody identity.
    let other = submission_binding(&fixture.run, &attempt)
        .with_custody_commitment([0xa3; 32])
        .unwrap();
    assert_eq!(other.tx_id(), binding.tx_id());
    assert_ne!(other.effect_id(), binding.effect_id());
    let view = AsyncView::new(&fixture.store);
    let substituted = poll_ready(observe_ref_transaction_async(
        &view,
        &(),
        &fixture.head_key,
        &fixture.run,
        &other,
    ))
    .unwrap()
    .unwrap();
    assert!(matches!(
        prepare_recovered_ref_transaction_acknowledgement(&fixture.run, &prefix, &substituted, now),
        Err(RefTransactionRecoveryRefusal::Binding)
    ));
    view.assert_read_only();
    // A canonically framed history with an invalid parent remains unusable.
    let mut entries = prefix.entries().to_vec();
    let EffectJournalEvent::Accepted(record) = &mut entries[0].event else {
        panic!("first event accepts the effect")
    };
    record.parent_effect_id = Some(EffectId::new(0xffff));
    let invalid_inventory = encoded_journal(&fixture.run, &entries);
    assert!(matches!(
        prepare_recovered_ref_transaction_acknowledgement(
            &fixture.run,
            &invalid_inventory,
            &observation,
            now
        ),
        Err(RefTransactionRecoveryRefusal::Journal(
            EffectJournalCodecRefusal::Reconciliation
        ))
    ));
    assert_eq!(
        capture.decode(&fixture.run).unwrap().records(),
        prefix.records()
    );
    settle_live(&fixture, pending);
    assert!(owner.close().is_quiescent());
}

#[test]
fn recovery_only_acknowledges_legal_pending_states() {
    let fixture = Fixture::new(930);
    let attempt = seal_attempt(b"recovery-lifecycle");
    let binding = submission_binding(&fixture.run, &attempt);
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let reserved = capture.decode(&fixture.run).unwrap();
    let pending = start(&fixture, &mut owner, reservation);
    let full = capture.decode(&fixture.run).unwrap();
    let committed = encoded_journal(&fixture.run, &full.entries()[..full.entries().len() - 1]);
    assert_eq!(
        committed.records()[0].obligation_state,
        ObligationState::Committed
    );
    let observation = observed_terminal(&fixture, &attempt, &binding, true);
    assert!(matches!(
        prepare_recovered_ref_transaction_acknowledgement(
            &fixture.run,
            &reserved,
            &observation,
            LogicalTime::new(40)
        ),
        Err(RefTransactionRecoveryRefusal::State(
            ObligationState::Reserved
        ))
    ));
    let prepared = prepare_recovered_ref_transaction_acknowledgement(
        &fixture.run,
        &committed,
        &observation,
        LogicalTime::new(40),
    )
    .unwrap();
    let mut sink = RecordingSink::confirming(&prepared);
    let settled = prepared.persist(&mut sink).unwrap();
    assert_eq!(
        settled.journal().records()[0].obligation_state,
        ObligationState::Acknowledged
    );
    assert_eq!(settled.journal().records()[0].budget_consumed, cost());

    // These fixtures exercise the existing codec's legal lifecycle states;
    // they do not claim that the current ref adapter itself issues escalation.
    let mut escalated_entries = full.entries().to_vec();
    escalated_entries.push(EffectJournalEntry {
        sequence: full.position().entries,
        event: EffectJournalEvent::Lifecycle {
            effect_id: binding.effect_id(),
            event: LifecycleEvent::Escalate,
            budget_consumed: cost(),
            output_commitments: Vec::new(),
            reconciliation_evidence: None,
            terminal_outcome: Some(EffectTerminalOutcome::Escalated {
                owner: PRINCIPAL,
                reason: fgit_resource::EscalationReason::IndeterminateDelivery,
            }),
        },
    });
    let escalated = encoded_journal(&fixture.run, &escalated_entries);
    let prepared = prepare_recovered_ref_transaction_acknowledgement(
        &fixture.run,
        &escalated,
        &observation,
        LogicalTime::new(40),
    )
    .unwrap();
    let mut sink = RecordingSink::confirming(&prepared);
    let settled = prepared.persist(&mut sink).unwrap();
    assert_eq!(
        settled.journal().records()[0].obligation_state,
        ObligationState::Acknowledged
    );
    assert_eq!(settled.journal().records()[0].budget_consumed, cost());

    let mut failed_entries = full.entries().to_vec();
    failed_entries.push(EffectJournalEntry {
        sequence: full.position().entries,
        event: EffectJournalEvent::Lifecycle {
            effect_id: binding.effect_id(),
            event: LifecycleEvent::FailTerminally,
            budget_consumed: cost(),
            output_commitments: Vec::new(),
            reconciliation_evidence: None,
            terminal_outcome: Some(EffectTerminalOutcome::TerminallyFailed {
                reason: fgit_resource::TerminalFailureReason::PermanentDownstreamRejection,
            }),
        },
    });
    let failed = encoded_journal(&fixture.run, &failed_entries);
    assert!(matches!(
        prepare_recovered_ref_transaction_acknowledgement(
            &fixture.run,
            &failed,
            &observation,
            LogicalTime::new(40),
        ),
        Err(RefTransactionRecoveryRefusal::State(
            ObligationState::TerminallyFailed
        ))
    ));

    let (mut aborted_owner, aborted_capture) = broker(&fixture.run);
    // A separate correctly authorized reservation is explicitly aborted.
    let aborted = aborted_owner
        .reserve_ref_transaction(
            &binding,
            &chain(OperationClass::PublishRefTransaction),
            &fixture.revocations(40),
            LogicalTime::new(41),
            cost(),
        )
        .unwrap();
    let _aborted = aborted.abort(NoCandidateReason::Cancelled).unwrap();
    let aborted_prefix = aborted_capture.decode(&fixture.run).unwrap();
    assert!(matches!(
        prepare_recovered_ref_transaction_acknowledgement(
            &fixture.run,
            &aborted_prefix,
            &observation,
            LogicalTime::new(50)
        ),
        Err(RefTransactionRecoveryRefusal::State(
            ObligationState::Aborted
        ))
    ));
    settle_live(&fixture, pending);
    assert!(owner.close().is_quiescent());
    assert!(aborted_owner.close().is_quiescent());
}

#[test]
fn an_identical_recorded_ack_still_confirms_storage_and_conflicting_outputs_refuse() {
    let fixture = Fixture::new(940);
    let attempt = seal_attempt(b"idempotent-recovered-ack");
    let binding = submission_binding(&fixture.run, &attempt);
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let pending = start(&fixture, &mut owner, reservation);
    let observation = observed_terminal(&fixture, &attempt, &binding, true);
    settle_live(&fixture, pending);
    let acknowledged = capture.decode(&fixture.run).unwrap();
    let prepared = prepare_recovered_ref_transaction_acknowledgement(
        &fixture.run,
        &acknowledged,
        &observation,
        LogicalTime::new(40),
    )
    .unwrap();
    assert!(prepared.already_acknowledged());
    assert!(prepared.frame().is_empty());
    assert_eq!(prepared.before_position(), prepared.after_position());
    let mut sink = RecordingSink::confirming(&prepared);
    sink.reply = Err(EffectJournalPersistenceRefusal::Cancelled);
    let refused = prepared.persist(&mut sink).unwrap_err();
    assert_eq!(refused.reason(), EffectJournalPersistenceRefusal::Cancelled);
    assert_eq!(
        sink.calls, 1,
        "an existing ACK never bypasses current file custody"
    );
    sink.reply = Ok(sink.after);
    let settled = refused.into_prepared().persist(&mut sink).unwrap();
    assert!(settled.already_acknowledged());
    assert_eq!(sink.calls, 2);
    assert_eq!(settled.journal().entries(), acknowledged.entries());

    for duplicate in [false, true] {
        let mut entries = acknowledged.entries().to_vec();
        let EffectJournalEvent::Lifecycle {
            output_commitments, ..
        } = &mut entries.last_mut().unwrap().event
        else {
            panic!("last event acknowledges")
        };
        if duplicate {
            output_commitments.push(output_commitments[0]);
        } else {
            output_commitments[0][0] ^= 1;
        }
        let altered = encoded_journal(&fixture.run, &entries);
        assert!(matches!(
            prepare_recovered_ref_transaction_acknowledgement(
                &fixture.run,
                &altered,
                &observation,
                LogicalTime::new(40)
            ),
            Err(RefTransactionRecoveryRefusal::TerminalCommitment)
        ));
    }
    assert!(owner.close().is_quiescent());
}

#[test]
fn refused_or_wrong_tail_confirmation_retains_the_original_terminal_and_exact_candidate() {
    let fixture = Fixture::new(950);
    let attempt = seal_attempt(b"recovery-acknowledgement-failure");
    let binding = submission_binding(&fixture.run, &attempt);
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let pending = start(&fixture, &mut owner, reservation);
    let prefix = capture.decode(&fixture.run).unwrap();
    let observation = observed_terminal(&fixture, &attempt, &binding, false);
    for failure in [
        EffectJournalPersistenceRefusal::Cancelled,
        EffectJournalPersistenceRefusal::OutcomeUnknown,
        EffectJournalPersistenceRefusal::Limit,
        EffectJournalPersistenceRefusal::Unavailable,
    ] {
        let prepared = prepare_recovered_ref_transaction_acknowledgement(
            &fixture.run,
            &prefix,
            &observation,
            LogicalTime::new(40),
        )
        .unwrap();
        let mut sink = RecordingSink::confirming(&prepared);
        sink.reply = Err(failure);
        let refused = prepared.persist(&mut sink).unwrap_err();
        assert_eq!(sink.calls, 1, "no automatic persistence retry");
        assert_eq!(refused.reason(), failure);
        assert_eq!(refused.prepared().frame(), sink.frame);
        assert_eq!(refused.prepared().observation(), &observation);
        assert_eq!(refused.prepared().before_position(), prefix.position());
        assert_eq!(refused.prepared().after_position(), sink.after);
        sink.reply = Ok(sink.after);
        let settled = refused.into_prepared().persist(&mut sink).unwrap();
        assert_eq!(sink.calls, 2);
        assert_eq!(settled.observation(), &observation);
    }
    let prepared = prepare_recovered_ref_transaction_acknowledgement(
        &fixture.run,
        &prefix,
        &observation,
        LogicalTime::new(40),
    )
    .unwrap();
    let mut sink = RecordingSink::confirming(&prepared);
    sink.reply = Ok(sink.before);
    let refused = prepared.persist(&mut sink).unwrap_err();
    assert_eq!(refused.reason(), EffectJournalPersistenceRefusal::Binding);
    assert_eq!(refused.prepared().observation(), &observation);
    assert_eq!(
        capture.decode(&fixture.run).unwrap().records(),
        prefix.records()
    );
    settle_live(&fixture, pending);
    assert!(owner.close().is_quiescent());
}
