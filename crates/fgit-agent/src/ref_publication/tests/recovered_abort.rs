//! Recovered pre-start cleanup uses the real broker, authority, lifecycle, and
//! journal codecs. The recording sink models durability replies only; native
//! exclusive custody, concurrent writers, and partial file appends are tested
//! with the actual file owner in fgit-node.

use super::*;

#[derive(Debug)]
struct AbortSink {
    run: IntentRunCommitment,
    before: EffectJournalPosition,
    after: EffectJournalPosition,
    binding: RefTransactionBinding,
    frame: Vec<u8>,
    calls: usize,
    reply: Result<EffectJournalPosition, EffectJournalPersistenceRefusal>,
}

impl AbortSink {
    fn confirming(prepared: &PreparedRefTransactionAbort) -> Self {
        Self {
            run: prepared.run_commitment(),
            before: prepared.before_position(),
            after: prepared.after_position(),
            binding: prepared.binding().clone(),
            frame: prepared.frame().to_vec(),
            calls: 0,
            reply: Ok(prepared.after_position()),
        }
    }
}

impl RefTransactionAbortSink for AbortSink {
    fn persist_abort(
        &mut self,
        prepared: &PreparedRefTransactionAbort,
    ) -> Result<EffectJournalPosition, EffectJournalPersistenceRefusal> {
        assert_eq!(prepared.run_commitment(), self.run);
        assert_eq!(prepared.before_position(), self.before);
        assert_eq!(prepared.after_position(), self.after);
        assert_eq!(prepared.binding(), &self.binding);
        assert_eq!(prepared.frame(), self.frame);
        self.calls += 1;
        self.reply
    }
}

fn encoded(
    run: &IntentRun,
    entries: &[EffectJournalEntry],
) -> Result<RecoveredEffectJournal, EffectJournalCodecRefusal> {
    let (mut encoder, mut bytes) = EffectJournalEncoder::new(run)?;
    for entry in entries {
        bytes.extend(encoder.encode(entry)?);
    }
    RecoveredEffectJournal::decode(run, &bytes, Some(encoder.position()))
}

fn prepare(
    run: &IntentRun,
    journal: &RecoveredEffectJournal,
    binding: &RefTransactionBinding,
) -> Result<PreparedRefTransactionAbort, RefTransactionAbortRefusal> {
    prepare_recovered_ref_transaction_abort(run, journal, binding.effect_id(), LogicalTime::new(40))
}

fn settle_pending(
    fixture: &Fixture,
    attempt: &SealAttempt,
    pending: PendingRefTransactionSubmission,
) {
    let tx_id = pending.binding().tx_id();
    assert_eq!(
        seal_request(&fixture.store, attempt).unwrap().tx_id(),
        tx_id
    );
    fixture.decide(tx_id, false);
    let view = AsyncView::new(&fixture.store);
    assert!(matches!(
        poll_ready(pending.reconcile_async(&view, &(), &fixture.head_key)).unwrap(),
        RefTransactionResolution::Decided(_)
    ));
    view.assert_read_only();
}

#[test]
fn recovered_abort_matches_live_bytes_after_expiry_and_revocation() {
    let fixture = Fixture::new(960);
    let binding = submission_binding(&fixture.run, &seal_attempt(b"recover-never-started"))
        .with_custody_commitment([0xb1; 32])
        .unwrap();
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let prefix = capture.decode(&fixture.run).unwrap();
    let before = prefix.records()[0].clone();
    let mut expected_bytes = capture.0.borrow().bytes.clone();
    fixture.revoke(&[CapabilityId::new(1)]);
    let authority = fixture.store.read_head(&fixture.head_key).unwrap();
    assert!(!fixture.run.is_open_at(LogicalTime::new(101)));
    let prepared = prepare_recovered_ref_transaction_abort(
        &fixture.run,
        &prefix,
        binding.effect_id(),
        LogicalTime::new(101),
    )
    .unwrap();
    let later = prepare_recovered_ref_transaction_abort(
        &fixture.run,
        &prefix,
        binding.effect_id(),
        LogicalTime::new(1_001),
    )
    .unwrap();
    assert_eq!(
        prepared.frame(),
        later.frame(),
        "cleanup observation time does not alter retry bytes"
    );
    assert_eq!(prepared.after_position(), later.after_position());
    assert_eq!(prepared.run_commitment(), fixture.run.commitment().unwrap());
    assert_eq!(prepared.before_position(), prefix.position());
    assert_eq!(
        prepared.after_position().entries,
        prefix.position().entries + 1
    );
    assert_eq!(prepared.binding(), &binding);
    assert!(!prepared.already_aborted());
    assert_eq!(prefix.records(), std::slice::from_ref(&before));
    expected_bytes.extend_from_slice(prepared.frame());
    let mut sink = AbortSink::confirming(&prepared);
    let settled = prepared.persist(&mut sink).unwrap();
    assert_eq!(sink.calls, 1);
    assert_eq!(settled.binding().tx_id(), binding.tx_id());
    assert_eq!(settled.before_position(), prefix.position());
    assert_eq!(settled.after_position(), sink.after);
    assert!(!settled.already_aborted());
    let mut expected_record = before;
    expected_record.obligation_state = ObligationState::Aborted;
    expected_record.terminal_outcome = Some(EffectTerminalOutcome::Aborted);
    assert_eq!(settled.journal().records(), &[expected_record]);
    let decoded =
        RecoveredEffectJournal::decode(&fixture.run, &expected_bytes, Some(sink.after)).unwrap();
    assert_eq!(settled.journal().entries(), decoded.entries());
    assert_eq!(
        settled.journal().ref_transactions(),
        prefix.ref_transactions()
    );
    let report = settled
        .journal()
        .reconciliation_report(&fixture.run, LogicalTime::new(101))
        .unwrap();
    assert_eq!(report.readiness(), RunReconciliationReadiness::Ready);
    assert_eq!(report.cumulative_budget_consumed(), ResourceVector::ZERO);
    assert_eq!(report.counts().aborted(), 1);
    assert_eq!(
        fixture.store.read_head(&fixture.head_key).unwrap(),
        authority
    );
    assert!(
        fgit_authority::read_seal(&fixture.store, TENANT, REPOSITORY, binding.tx_id())
            .unwrap()
            .is_none()
    );
    let _aborted = reservation.abort(NoCandidateReason::Cancelled).unwrap();
    assert_eq!(
        capture.0.borrow().bytes,
        expected_bytes,
        "recovered Abort uses the unchanged live event framing"
    );
    assert_eq!(owner.records(), settled.into_journal().records());
    assert!(owner.close().is_quiescent());
}

#[test]
fn recovered_abort_preserves_started_siblings_children_and_all_spend() {
    let fixture = Fixture::new(961);
    let binding = submission_binding(&fixture.run, &seal_attempt(b"abort-selected-reservation"));
    let other_attempt = seal_attempt(b"keep-started-submission");
    let other = submission_binding(&fixture.run, &other_attempt);
    let (mut owner, capture) = broker(&fixture.run);
    let selected = reserve(&fixture, &mut owner, &binding);
    let other_reservation = reserve(&fixture, &mut owner, &other);
    let pending = start(&fixture, &mut owner, other_reservation);
    let read_capability = Capability::issue(
        CapabilityId::new(3),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        resources(256, 1),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .unwrap();
    let child = owner
        .request_low_risk(
            &read_capability,
            LogicalTime::new(25),
            &EffectRequest {
                effect_id: EffectId::new(99),
                parent_effect_id: Some(binding.effect_id()),
                operation: OperationClass::ReadCanonicalObject,
                cost: resources(16, 1),
                input_commitment: [0xc1; 32],
            },
        )
        .unwrap();
    let prefix = capture.decode(&fixture.run).unwrap();
    let unchanged = prefix.records()[1..].to_vec();
    let prepared = prepare(&fixture.run, &prefix, &binding).unwrap();
    let mut sink = AbortSink::confirming(&prepared);
    let settled = prepared.persist(&mut sink).unwrap();
    assert_eq!(&settled.journal().records()[1..], unchanged);
    assert_eq!(
        settled.journal().records()[2].parent_effect_id,
        Some(binding.effect_id())
    );
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
        RunReconciliationReadiness::EffectReconciliationRequired
    );
    assert!(report.has_unsettled_effects());
    assert_eq!(report.counts().aborted(), 1);
    assert_eq!(report.counts().reserved(), 1);
    assert_eq!(report.counts().committed_or_deferred(), 1);
    assert_eq!(report.cumulative_budget_consumed(), cost());
    let _aborted = selected.abort(NoCandidateReason::Cancelled).unwrap();
    let _released = owner.abort_low_risk(child).unwrap();
    settle_pending(&fixture, &other_attempt, pending);
    assert!(owner.close().is_quiescent());
}

#[test]
fn recovered_abort_requires_independent_anchor_complete_run_and_original_typed_binding() {
    let fixture = Fixture::new(962);
    let attempt = seal_attempt(b"abort-binding");
    let binding = submission_binding(&fixture.run, &attempt)
        .with_custody_commitment([0xb2; 32])
        .unwrap();
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let prefix = capture.decode(&fixture.run).unwrap();
    let unanchored =
        RecoveredEffectJournal::decode(&fixture.run, &capture.0.borrow().bytes, None).unwrap();
    assert!(matches!(
        prepare(&fixture.run, &unanchored, &binding),
        Err(RefTransactionAbortRefusal::Journal(
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
        prepare(&changed_run, &prefix, &binding),
        Err(RefTransactionAbortRefusal::Journal(
            EffectJournalCodecRefusal::RunMismatch
        ))
    ));
    assert!(matches!(
        prepare_recovered_ref_transaction_abort(
            &fixture.run,
            &prefix,
            binding.effect_id(),
            LogicalTime::new(20)
        ),
        Err(RefTransactionAbortRefusal::Journal(
            EffectJournalCodecRefusal::Reconciliation
        ))
    ));
    assert!(matches!(
        prepare_recovered_ref_transaction_abort(
            &fixture.run,
            &prefix,
            EffectId::new(0xffff),
            LogicalTime::new(40)
        ),
        Err(RefTransactionAbortRefusal::Binding)
    ));
    let another_custody = submission_binding(&fixture.run, &attempt)
        .with_custody_commitment([0xb3; 32])
        .unwrap();
    assert_eq!(another_custody.tx_id(), binding.tx_id());
    assert_ne!(another_custody.effect_id(), binding.effect_id());
    assert!(matches!(
        prepare(&fixture.run, &prefix, &another_custody),
        Err(RefTransactionAbortRefusal::Binding)
    ));
    for events in [1, 2] {
        let incomplete_reservation = encoded(&fixture.run, &prefix.entries()[..events]).unwrap();
        assert!(
            matches!(
                prepare(&fixture.run, &incomplete_reservation, &binding),
                Err(RefTransactionAbortRefusal::Binding)
            ),
            "accepted or bound input without a typed reservation must refuse"
        );
    }
    assert!(prepare(&fixture.run, &prefix, &binding).is_ok());
    let _aborted = reservation.abort(NoCandidateReason::Cancelled).unwrap();
    assert!(owner.close().is_quiescent());
}

#[test]
fn recovered_abort_refuses_every_started_state_and_cannot_erase_a_commit() {
    let fixture = Fixture::new(963);
    let attempt = seal_attempt(b"abort-started-states");
    let binding = submission_binding(&fixture.run, &attempt);
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let pending = start(&fixture, &mut owner, reservation);
    let deferred = capture.decode(&fixture.run).unwrap();
    let committed = encoded(
        &fixture.run,
        &deferred.entries()[..deferred.entries().len() - 1],
    )
    .unwrap();
    for journal in [&committed, &deferred] {
        assert!(
            matches!(prepare(&fixture.run, journal, &binding), Err(RefTransactionAbortRefusal::State(state)) if state == journal.records()[0].obligation_state)
        );
    }
    for (event, terminal, expected_state) in [
        (
            LifecycleEvent::Acknowledge,
            EffectTerminalOutcome::Acknowledged,
            ObligationState::Acknowledged,
        ),
        (
            LifecycleEvent::Escalate,
            EffectTerminalOutcome::Escalated {
                owner: PRINCIPAL,
                reason: fgit_resource::EscalationReason::IndeterminateDelivery,
            },
            ObligationState::Escalated,
        ),
        (
            LifecycleEvent::FailTerminally,
            EffectTerminalOutcome::TerminallyFailed {
                reason: fgit_resource::TerminalFailureReason::PermanentDownstreamRejection,
            },
            ObligationState::TerminallyFailed,
        ),
    ] {
        let mut entries = deferred.entries().to_vec();
        entries.push(EffectJournalEntry {
            sequence: deferred.position().entries,
            event: EffectJournalEvent::Lifecycle {
                effect_id: binding.effect_id(),
                event,
                budget_consumed: cost(),
                output_commitments: Vec::new(),
                reconciliation_evidence: None,
                terminal_outcome: Some(terminal),
            },
        });
        let journal = encoded(&fixture.run, &entries).unwrap();
        assert!(
            matches!(prepare(&fixture.run, &journal, &binding), Err(RefTransactionAbortRefusal::State(state)) if state == expected_state)
        );
    }
    for event in [LifecycleEvent::Abort, LifecycleEvent::Leak] {
        let mut entries = committed.entries().to_vec();
        entries.push(EffectJournalEntry {
            sequence: committed.position().entries,
            event: EffectJournalEvent::Lifecycle {
                effect_id: binding.effect_id(),
                event,
                budget_consumed: ResourceVector::ZERO,
                output_commitments: Vec::new(),
                reconciliation_evidence: None,
                terminal_outcome: (event == LifecycleEvent::Abort)
                    .then_some(EffectTerminalOutcome::Aborted),
            },
        });
        assert!(
            encoded(&fixture.run, &entries).is_err(),
            "a started or leaked obligation cannot be reframed as an abortable reservation"
        );
    }
    settle_pending(&fixture, &attempt, pending);
    assert!(owner.close().is_quiescent());
}

#[test]
fn recovered_abort_rejects_malformed_request_kind_receipt_and_lifecycle_evidence() {
    let fixture = Fixture::new(964);
    let binding = submission_binding(&fixture.run, &seal_attempt(b"abort-malformed-inventory"));
    let other_binding = submission_binding(&fixture.run, &seal_attempt(b"different-transaction"));
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let prefix = capture.decode(&fixture.run).unwrap();
    let changed_run = IntentRun::new_authenticated(
        fixture.run.run_id(),
        fixture.run.authority_read_receipt().unwrap().clone(),
        fixture.run.allowed_operation_classes(),
        fixture.run.resource_budget(),
        LogicalTime::new(101),
    )
    .unwrap();
    for case in 0..20 {
        let mut entries = prefix.entries().to_vec();
        let EffectJournalEvent::Accepted(record) = &mut entries[0].event else {
            panic!("first event accepts")
        };
        match case {
            0 => record.input_commitment[31] ^= 1,
            1 => record.effect_class = crate::EffectClass::PureCanonicalRead,
            2 => record.operation = OperationClass::ReadCanonicalObject,
            3 => record.run_id = RunId::new(8),
            4 => record.run_commitment = changed_run.commitment().unwrap(),
            5 => record.source_authority_receipt = None,
            6 => record.effect_id = EffectId::new(0xffff),
            7 => record.parent_effect_id = Some(EffectId::new(0xffff)),
            8 => record.budget_consumed = cost(),
            9 => record.output_commitments = vec![[0xc2; 32]],
            10 => record.terminal_outcome = Some(EffectTerminalOutcome::Aborted),
            11 => {
                record.reconciliation_evidence = Some(crate::ReconciliationEvidence {
                    downstream_idempotency: fgit_resource::DownstreamIdempotency::Strong,
                    transitions: Vec::new(),
                })
            }
            12 => record.accepted_at = LogicalTime::new(101),
            13 => record.obligation_state = ObligationState::Aborted,
            14 => {
                entries.remove(1);
                for (index, entry) in entries.iter_mut().enumerate() {
                    entry.sequence = index as u64;
                }
            }
            15 => {
                let EffectJournalEvent::RefTransactionBound { binding, .. } = &mut entries[1].event
                else {
                    panic!("binding event")
                };
                *binding = other_binding.clone();
            }
            16 => {
                let EffectJournalEvent::BoundObligation {
                    obligation_class, ..
                } = &mut entries[2].event
                else {
                    panic!("typed reservation")
                };
                *obligation_class = ObligationClass::HeadCasAttempt;
            }
            17 => {
                let EffectJournalEvent::BoundObligation {
                    external_idempotency_key,
                    ..
                } = &mut entries[2].event
                else {
                    panic!("typed reservation")
                };
                *external_idempotency_key = Some(fgit_resource::IdempotencyKey::new(digest(0xc3)));
            }
            18 => record.parent_effect_id = Some(binding.effect_id()),
            19 => {
                let mut seal = binding.seal().clone();
                seal.repository_id = RepositoryId::from_bytes([0xe1; 16]);
                let foreign = RefTransactionBinding::from_parts(
                    fixture.run.commitment().unwrap(),
                    seal,
                    *binding.publication_binding(),
                )
                .unwrap();
                record.effect_id = foreign.effect_id();
                record.input_commitment = *foreign.input_commitment();
                entries[1].event = EffectJournalEvent::RefTransactionBound {
                    effect_id: foreign.effect_id(),
                    binding: foreign.clone(),
                };
                let EffectJournalEvent::BoundObligation { effect_id, .. } = &mut entries[2].event
                else {
                    panic!("typed reservation")
                };
                *effect_id = foreign.effect_id();
                assert!(
                    encoded(&fixture.run, &entries).is_err(),
                    "a fully relabeled foreign seal cannot cross the original authority repository boundary"
                );
            }
            _ => unreachable!(),
        }
        if let Ok(malformed) = encoded(&fixture.run, &entries) {
            assert!(
                prepare(&fixture.run, &malformed, &binding).is_err(),
                "malformed case {case} must not yield an abort permit"
            );
        }
    }
    assert!(prepare(&fixture.run, &prefix, &binding).is_ok());
    let _aborted = reservation.abort(NoCandidateReason::Cancelled).unwrap();
    assert!(owner.close().is_quiescent());
}

#[test]
fn recovered_abort_refuses_even_a_valid_parent_graph_when_the_exact_request_has_no_parent() {
    let fixture = Fixture::new(965);
    let (mut owner, capture) = broker(&fixture.run);
    let capability = Capability::issue(
        CapabilityId::new(3),
        ClassSet::from_classes(&[OperationClass::ReadCanonicalObject]),
        resources(256, 1),
        LogicalTime::new(0),
        LogicalTime::new(100),
    )
    .unwrap();
    let parent_id = EffectId::new(99);
    let parent = owner
        .request_low_risk(
            &capability,
            LogicalTime::new(20),
            &EffectRequest {
                effect_id: parent_id,
                parent_effect_id: None,
                operation: OperationClass::ReadCanonicalObject,
                cost: resources(16, 1),
                input_commitment: [0xc4; 32],
            },
        )
        .unwrap();
    let binding = submission_binding(&fixture.run, &seal_attempt(b"abort-substituted-parent"));
    let reservation = reserve(&fixture, &mut owner, &binding);
    let prefix = capture.decode(&fixture.run).unwrap();
    let mut entries = prefix.entries().to_vec();
    let EffectJournalEvent::Accepted(record) = &mut entries[1].event else {
        panic!("second acceptance")
    };
    record.parent_effect_id = Some(parent_id);
    let substituted = encoded(&fixture.run, &entries).unwrap();
    assert!(
        substituted
            .reconciliation_report(&fixture.run, LogicalTime::new(40))
            .is_ok()
    );
    assert!(matches!(
        prepare(&fixture.run, &substituted, &binding),
        Err(RefTransactionAbortRefusal::Binding)
    ));
    assert!(prepare(&fixture.run, &prefix, &binding).is_ok());
    let _aborted = reservation.abort(NoCandidateReason::Cancelled).unwrap();
    let _released = owner.abort_low_risk(parent).unwrap();
    assert!(owner.close().is_quiescent());
}

#[test]
fn recovered_abort_idempotence_still_requires_custody_and_exact_zero_spend_evidence() {
    let fixture = Fixture::new(966);
    let binding = submission_binding(&fixture.run, &seal_attempt(b"already-aborted"));
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let _aborted = reservation.abort(NoCandidateReason::Cancelled).unwrap();
    let prefix = capture.decode(&fixture.run).unwrap();
    let prepared = prepare(&fixture.run, &prefix, &binding).unwrap();
    assert!(prepared.already_aborted());
    assert!(prepared.frame().is_empty());
    assert_eq!(prepared.before_position(), prepared.after_position());
    let mut sink = AbortSink::confirming(&prepared);
    sink.reply = Err(EffectJournalPersistenceRefusal::Cancelled);
    let refused = prepared.persist(&mut sink).unwrap_err();
    assert_eq!(
        sink.calls, 1,
        "an existing abort cannot bypass actual storage custody"
    );
    assert_eq!(refused.reason(), EffectJournalPersistenceRefusal::Cancelled);
    sink.reply = Ok(sink.after);
    let settled = refused.into_prepared().persist(&mut sink).unwrap();
    assert_eq!(sink.calls, 2);
    assert!(settled.already_aborted());
    assert_eq!(settled.journal().entries(), prefix.entries());
    for consumed in [false, true] {
        let mut entries = prefix.entries().to_vec();
        let EffectJournalEvent::Lifecycle {
            budget_consumed,
            output_commitments,
            ..
        } = &mut entries.last_mut().unwrap().event
        else {
            panic!("last event aborts")
        };
        if consumed {
            *budget_consumed = cost();
        } else {
            output_commitments.push([0xc5; 32]);
        }
        let altered = encoded(&fixture.run, &entries).unwrap();
        assert!(matches!(
            prepare(&fixture.run, &altered, &binding),
            Err(RefTransactionAbortRefusal::TerminalCommitment)
        ));
    }
    assert!(owner.close().is_quiescent());
}

#[test]
fn recovered_abort_persistence_uncertainty_and_wrong_positions_retain_exact_retry_debt() {
    let fixture = Fixture::new(967);
    let binding = submission_binding(&fixture.run, &seal_attempt(b"abort-storage-refusal"));
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let prefix = capture.decode(&fixture.run).unwrap();
    for failure in [
        EffectJournalPersistenceRefusal::Cancelled,
        EffectJournalPersistenceRefusal::OutcomeUnknown,
        EffectJournalPersistenceRefusal::Limit,
        EffectJournalPersistenceRefusal::Unavailable,
        EffectJournalPersistenceRefusal::Binding,
    ] {
        let prepared = prepare(&fixture.run, &prefix, &binding).unwrap();
        let mut sink = AbortSink::confirming(&prepared);
        sink.reply = Err(failure);
        let refused = prepared.persist(&mut sink).unwrap_err();
        assert_eq!(
            sink.calls, 1,
            "never retry an ambiguous append automatically"
        );
        assert_eq!(refused.reason(), failure);
        assert_eq!(refused.prepared().binding(), &binding);
        assert_eq!(refused.prepared().frame(), sink.frame);
        assert_eq!(refused.prepared().before_position(), prefix.position());
        assert_eq!(refused.prepared().after_position(), sink.after);
        sink.reply = Ok(sink.after);
        let settled = refused.into_prepared().persist(&mut sink).unwrap();
        assert_eq!(sink.calls, 2);
        assert_eq!(settled.binding(), &binding);
        assert_eq!(
            settled.journal().records()[0].obligation_state,
            ObligationState::Aborted
        );
    }
    for component in 0..3 {
        let prepared = prepare(&fixture.run, &prefix, &binding).unwrap();
        let mut sink = AbortSink::confirming(&prepared);
        let mut wrong = sink.after;
        match component {
            0 => wrong.entries -= 1,
            1 => wrong.bytes -= 1,
            2 => wrong.digest[0] ^= 1,
            _ => unreachable!(),
        }
        sink.reply = Ok(wrong);
        let refused = prepared.persist(&mut sink).unwrap_err();
        assert_eq!(refused.reason(), EffectJournalPersistenceRefusal::Binding);
        assert_eq!(refused.prepared().frame(), sink.frame);
        assert_eq!(refused.prepared().binding(), &binding);
        assert_eq!(sink.calls, 1);
    }
    assert_eq!(
        capture.decode(&fixture.run).unwrap().records(),
        prefix.records()
    );
    let _aborted = reservation.abort(NoCandidateReason::Cancelled).unwrap();
    assert!(owner.close().is_quiescent());
}

#[test]
fn recovered_abort_only_its_complete_exact_frame_can_confirm_the_candidate_tail() {
    let fixture = Fixture::new(968);
    let binding = submission_binding(&fixture.run, &seal_attempt(b"abort-exact-suffix"));
    let (mut owner, capture) = broker(&fixture.run);
    let reservation = reserve(&fixture, &mut owner, &binding);
    let prefix = capture.decode(&fixture.run).unwrap();
    let prepared = prepare(&fixture.run, &prefix, &binding).unwrap();
    let bytes = capture.0.borrow().bytes.clone();
    for end in 0..prepared.frame().len() {
        let mut partial = bytes.clone();
        partial.extend_from_slice(&prepared.frame()[..end]);
        assert!(
            RecoveredEffectJournal::decode(&fixture.run, &partial, Some(prepared.after_position()))
                .is_err(),
            "partial frame {end} cannot establish the resulting durable inventory"
        );
    }
    let mut complete = bytes.clone();
    complete.extend_from_slice(prepared.frame());
    assert!(
        RecoveredEffectJournal::decode(&fixture.run, &complete, Some(prepared.after_position()))
            .is_ok()
    );
    assert!(matches!(
        RecoveredEffectJournal::decode(&fixture.run, &complete, Some(prefix.position())),
        Err(EffectJournalCodecRefusal::AnchorMismatch)
    ));
    *complete.last_mut().unwrap() ^= 1;
    assert!(
        RecoveredEffectJournal::decode(&fixture.run, &complete, Some(prepared.after_position()))
            .is_err()
    );
    let _aborted = reservation.abort(NoCandidateReason::Cancelled).unwrap();
    assert!(owner.close().is_quiescent());
}
