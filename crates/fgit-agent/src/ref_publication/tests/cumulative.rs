//! Retained outcome witnesses must preserve the original run, seal and custody
//! boundaries. These reference-authority tests exercise real publication and
//! checkpoint collection; native archive persistence is tested by the node.

use super::*;
use fgit_authority::{
    OutcomeFailure, body_key_for_id, collect_cumulative_outcomes,
    collect_cumulative_outcomes_from_checkpoint_async, outcome_key, seal_key,
};
use std::sync::atomic::AtomicBool;

fn collect(fixture: &Fixture) -> CumulativeOutcomes {
    collect_cumulative_outcomes(&fixture.store, &fixture.head_key).unwrap()
}

fn observe(
    fixture: &Fixture,
    view: &AsyncView<'_>,
    binding: &RefTransactionBinding,
    cumulative: &CumulativeOutcomes,
) -> Result<Option<ObservedRefTransaction>, RefTransactionObservationRefusal> {
    poll_ready(observe_ref_transaction_with_cumulative_async(
        view,
        &(),
        &fixture.head_key,
        &fixture.run,
        binding,
        cumulative,
    ))
}

#[test]
fn retained_checkpoint_observation_settles_commit_and_refusal_without_old_history() {
    for committed in [false, true] {
        let fixture = Fixture::new(1100 + u64::from(committed));
        let attempt = seal_attempt(b"retained-agent-terminal");
        let binding = submission_binding(&fixture.run, &attempt)
            .with_custody_commitment([0xa1; 32])
            .unwrap();
        let (mut owner, capture) = broker(&fixture.run);
        let reserved = reserve(&fixture, &mut owner, &binding);
        let pending = start(&fixture, &mut owner, reserved);
        fixture.revoke(&[CapabilityId::new(1)]);
        seal_request(&fixture.store, &attempt).unwrap();
        let terminal = fixture.decide(binding.tx_id(), committed);
        let replayed = poll_ready(observe_ref_transaction_async(
            &AsyncView::new(&fixture.store),
            &(),
            &fixture.head_key,
            &fixture.run,
            &binding,
        ))
        .unwrap()
        .unwrap();
        let cumulative = collect(&fixture);
        let leaves = cumulative
            .checkpoint_decisions_against(cumulative.observed())
            .unwrap();
        let (receipt, head) = fixture.current_head();
        let batch_key =
            body_key_for_id(head.decision_tail_id.unwrap().as_internal_object_id()).unwrap();
        let view = AsyncView::new(&fixture.store)
            .with_immutable_override(batch_key, ImmutableRead::Absent);
        let retained = poll_ready(collect_cumulative_outcomes_from_checkpoint_async(
            &view,
            &(),
            &fixture.head_key,
            &leaves,
            head.decision_tail_id,
            head.latest_decision_sequence,
        ))
        .unwrap();
        let observed = observe(&fixture, &view, &binding, &retained)
            .unwrap()
            .unwrap();
        assert_eq!(observed, replayed);
        assert_eq!(view.overridden_reads.load(Ordering::SeqCst), 0);
        assert!(matches!(
            poll_ready(observe_ref_transaction_async(
                &view,
                &(),
                &fixture.head_key,
                &fixture.run,
                &binding,
            )),
            Err(RefTransactionObservationRefusal::Outcome(error))
                if matches!(*error, OutcomeFailure::StreamBodyMissing { link: "decision batch" })
        ));
        assert_eq!(view.overridden_reads.load(Ordering::SeqCst), 1);

        let RefTransactionResolution::Decided(settled) =
            pending.reconcile_observed(observed).unwrap()
        else {
            panic!("an authenticated retained terminal settles the original submission");
        };
        assert_eq!(settled.observation().terminal(), &terminal);
        assert_eq!(settled.settled().state(), ObligationState::Acknowledged);
        let recovered = capture.decode(&fixture.run).unwrap();
        let report = recovered
            .reconciliation_report(&fixture.run, LogicalTime::new(101))
            .unwrap();
        assert!(!fixture.run.is_open_at(LogicalTime::new(101)));
        assert_eq!(report.readiness(), RunReconciliationReadiness::Ready);
        assert_eq!(report.cumulative_budget_consumed(), cost());
        assert_eq!(recovered.records(), owner.records());
        assert_eq!(fixture.current_head().0, receipt);
        view.assert_read_only();
        assert!(owner.close().is_quiescent());
    }
}

#[test]
fn a_missing_hint_does_not_erase_a_retained_terminal_or_invent_one() {
    for (id, committed) in [(1110, None), (1111, Some(false)), (1112, Some(true))] {
        let fixture = Fixture::new(id);
        let attempt = seal_attempt(b"retained-without-hint");
        let binding = submission_binding(&fixture.run, &attempt);
        let terminal = committed.map(|committed| {
            seal_request(&fixture.store, &attempt).unwrap();
            fixture.decide(binding.tx_id(), committed)
        });
        let cumulative = collect(&fixture);
        let view = AsyncView::new(&fixture.store).with_immutable_override(
            outcome_key(TENANT, REPOSITORY, binding.tx_id()).unwrap(),
            ImmutableRead::Absent,
        );
        let result = observe(&fixture, &view, &binding, &cumulative).unwrap();
        assert_eq!(
            result.as_ref().map(|observed| *observed.terminal()),
            terminal
        );
        assert_eq!(view.overridden_reads.load(Ordering::SeqCst), 1);
        view.assert_read_only();
    }
}

#[test]
fn a_moving_or_absent_head_requires_recollection_instead_of_reporting_undecided() {
    let fixture = Fixture::new(1120);
    let attempt = seal_attempt(b"publication-during-retained-observation");
    let binding = submission_binding(&fixture.run, &attempt);
    seal_request(&fixture.store, &attempt).unwrap();
    let previous = collect(&fixture);
    let hint = outcome_key(TENANT, REPOSITORY, binding.tx_id()).unwrap();
    let moved = AtomicBool::new(false);
    let mut view = AsyncView::new(&fixture.store);
    // A real competing publication occurs after the observer reads an absent
    // hint and before it checks the current head against its retained witness.
    view.after_read = Some(Box::new(|key| {
        if key == &hint && !moved.swap(true, Ordering::SeqCst) {
            fixture.decide(binding.tx_id(), false);
        }
    }));
    assert!(matches!(
        observe(&fixture, &view, &binding, &previous),
        Err(RefTransactionObservationRefusal::StaleOutcomeBasis)
    ));
    assert!(moved.load(Ordering::SeqCst));
    assert!(matches!(
        observe(&fixture, &view, &binding, &previous),
        Err(RefTransactionObservationRefusal::StaleOutcomeBasis)
    ));
    let current = collect(&fixture);
    let observed = observe(&fixture, &view, &binding, &current)
        .unwrap()
        .unwrap();
    assert_eq!(
        observed.terminal(),
        &current.decision_for(binding.tx_id()).unwrap()
    );
    view.assert_read_only();

    let mut absent = AsyncView::new(&fixture.store);
    absent.absent_head = true;
    assert!(matches!(
        observe(&fixture, &absent, &binding, &current),
        Err(RefTransactionObservationRefusal::StaleOutcomeBasis)
    ));
    absent.assert_read_only();
}

#[test]
fn retained_observation_preserves_conflicting_and_phantom_hint_refusals() {
    let attempt = seal_attempt(b"retained-hint-conflict");
    let donor = Fixture::new(1130);
    let donor_binding = submission_binding(&donor.run, &attempt);
    seal_request(&donor.store, &attempt).unwrap();
    donor.decide(donor_binding.tx_id(), false);
    let hint = outcome_key(TENANT, REPOSITORY, donor_binding.tx_id()).unwrap();
    let wrong = donor.store.read_immutable(&hint).unwrap();
    for has_decision in [false, true] {
        let fixture = Fixture::new(1131 + u64::from(has_decision));
        let binding = submission_binding(&fixture.run, &attempt);
        seal_request(&fixture.store, &attempt).unwrap();
        if has_decision {
            fixture.decide(binding.tx_id(), true);
        }
        let cumulative = collect(&fixture);
        let view =
            AsyncView::new(&fixture.store).with_immutable_override(hint.clone(), wrong.clone());
        let Err(RefTransactionObservationRefusal::Outcome(replayed)) = poll_ready(
            observe_ref_transaction_async(&view, &(), &fixture.head_key, &fixture.run, &binding),
        ) else {
            panic!("the original replay must reject the conflicting hint");
        };
        let Err(RefTransactionObservationRefusal::Outcome(retained)) =
            observe(&fixture, &view, &binding, &cumulative)
        else {
            panic!("the retained witness must preserve hint conflict refusal");
        };
        assert!(matches!(
            *retained,
            OutcomeFailure::AcceleratorConflict { .. }
        ));
        assert_eq!(retained, replayed);
        view.assert_read_only();
    }
}

#[test]
fn retained_observation_authenticates_the_complete_run_seal_store_and_slot() {
    let fixture = Fixture::new(1140);
    let attempt = seal_attempt(b"retained-observation-bindings");
    let binding = submission_binding(&fixture.run, &attempt);
    seal_request(&fixture.store, &attempt).unwrap();
    fixture.decide(binding.tx_id(), true);
    let cumulative = collect(&fixture);
    let view = AsyncView::new(&fixture.store);
    let changed_run = IntentRun::new_authenticated(
        fixture.run.run_id(),
        fixture.run.authority_read_receipt().unwrap().clone(),
        fixture.run.allowed_operation_classes(),
        fixture.run.resource_budget(),
        LogicalTime::new(101),
    )
    .unwrap();
    assert!(matches!(
        poll_ready(observe_ref_transaction_with_cumulative_async(
            &view,
            &(),
            &fixture.head_key,
            &changed_run,
            &binding,
            &cumulative,
        )),
        Err(RefTransactionObservationRefusal::Binding)
    ));
    let mut changed_seal = binding.seal().clone();
    changed_seal.authenticated_principal_id = PrincipalId::from_bytes([0x45; 16]);
    let wrong_seal = RefTransactionBinding::from_parts(
        fixture.run.commitment().unwrap(),
        changed_seal,
        *binding.publication_binding(),
    )
    .unwrap();
    assert_eq!(wrong_seal.tx_id(), binding.tx_id());
    assert!(matches!(
        observe(&fixture, &view, &wrong_seal, &cumulative),
        Err(RefTransactionObservationRefusal::Binding)
    ));
    let missing_seal = AsyncView::new(&fixture.store).with_immutable_override(
        seal_key(TENANT, REPOSITORY, binding.tx_id()).unwrap(),
        ImmutableRead::Absent,
    );
    assert!(matches!(
        observe(&fixture, &missing_seal, &binding, &cumulative),
        Err(RefTransactionObservationRefusal::Binding)
    ));
    let other_slot = HeadKey::new(b"retained-other-slot".to_vec()).unwrap();
    initialize_repository(&fixture.store, &other_slot, &fixture.genesis).unwrap();
    assert!(matches!(
        poll_ready(observe_ref_transaction_with_cumulative_async(
            &view,
            &(),
            &other_slot,
            &fixture.run,
            &binding,
            &cumulative,
        )),
        Err(RefTransactionObservationRefusal::Historical(_))
    ));
    let unrelated = Fixture::new(1141);
    let foreign = AsyncView::new(&unrelated.store);
    assert!(matches!(
        poll_ready(observe_ref_transaction_with_cumulative_async(
            &foreign,
            &(),
            &unrelated.head_key,
            &fixture.run,
            &binding,
            &cumulative,
        )),
        Err(RefTransactionObservationRefusal::Historical(_))
    ));
    assert!(
        observe(&fixture, &view, &binding, &cumulative)
            .unwrap()
            .is_some()
    );
    view.assert_read_only();
    missing_seal.assert_read_only();
    foreign.assert_read_only();
}

#[test]
fn another_authentic_observation_cannot_settle_pending_custody_or_change_budget() {
    for changed_run in [false, true] {
        let fixture = Fixture::new(1150 + u64::from(changed_run));
        let attempt = seal_attempt(b"retained-pending-custody");
        let binding = submission_binding(&fixture.run, &attempt)
            .with_custody_commitment([0xa1; 32])
            .unwrap();
        let (mut owner, capture) = broker(&fixture.run);
        let reserved = reserve(&fixture, &mut owner, &binding);
        let pending = start(&fixture, &mut owner, reserved);
        seal_request(&fixture.store, &attempt).unwrap();
        fixture.decide(binding.tx_id(), true);
        let run = IntentRun::new_authenticated(
            fixture.run.run_id(),
            fixture.run.authority_read_receipt().unwrap().clone(),
            fixture.run.allowed_operation_classes(),
            fixture.run.resource_budget(),
            LogicalTime::new(if changed_run { 101 } else { 100 }),
        )
        .unwrap();
        let other = submission_binding(&run, &attempt)
            .with_custody_commitment(if changed_run { [0xa1; 32] } else { [0xa2; 32] })
            .unwrap();
        assert_eq!(other.seal(), binding.seal());
        assert_ne!(other, binding);
        let cumulative = collect(&fixture);
        let view = AsyncView::new(&fixture.store);
        let authentic_but_other = poll_ready(observe_ref_transaction_with_cumulative_async(
            &view,
            &(),
            &fixture.head_key,
            &run,
            &other,
            &cumulative,
        ))
        .unwrap()
        .unwrap();
        let records = owner.records();
        let journal = owner.journal();
        let bytes = capture.0.borrow().bytes.clone();
        let Err(RefTransactionReconciliationRefused::Pending { pending, reason }) =
            pending.reconcile_observed(authentic_but_other)
        else {
            panic!("an authentic terminal for another complete binding must retain custody");
        };
        assert!(matches!(reason, RefTransactionObservationRefusal::Binding));
        assert_eq!(pending.binding(), &binding);
        assert_eq!(owner.records(), records);
        assert_eq!(owner.journal(), journal);
        assert_eq!(capture.0.borrow().bytes, bytes);
        let original = observe(&fixture, &view, &binding, &cumulative)
            .unwrap()
            .unwrap();
        assert!(matches!(
            pending.reconcile_observed(original).unwrap(),
            RefTransactionResolution::Decided(_)
        ));
        assert_eq!(owner.records()[0].budget_consumed, cost());
        assert_eq!(
            capture.decode(&fixture.run).unwrap().records(),
            owner.records()
        );
        view.assert_read_only();
        assert!(owner.close().is_quiescent());
    }
}
