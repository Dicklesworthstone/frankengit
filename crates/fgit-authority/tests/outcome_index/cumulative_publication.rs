//! Reference-store publication and adversarial receipt coverage. The async
//! view delegates to the same atomic store primitive; this is not a benchmark.

use super::*;
use fgit_authority::{
    CumulativeOutcomes, collect_cumulative_outcomes, collect_cumulative_outcomes_async,
    outcome_index_root, publish_decisions_with_cumulative, publish_decisions_with_cumulative_async,
};
use fgit_codec::{DecodeLimits, decode_body};

fn fixture(instance: u64, legacy_empty_root: bool) -> AsyncView {
    let view = AsyncView(MemoryAuthorityStore::new(StoreInstanceId::from_raw(
        instance,
    )));
    let mut head = genesis_head();
    if !legacy_empty_root {
        head.outcome_index_root = outcome_index_root(&[]).unwrap();
    }
    initialize_repository(&view.0, &head_slot(), &head).unwrap();
    view
}

fn current(view: &AsyncView) -> (HeadReadReceipt, RepositoryAuthorityHeadBody) {
    let HeadRead::Present(receipt) = view.0.read_head(&head_slot()).unwrap() else {
        panic!("fixture head exists")
    };
    let body = decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
    (receipt, body)
}

fn collect(view: &AsyncView, asynchronous: bool) -> Result<CumulativeOutcomes, OutcomeFailure> {
    if asynchronous {
        poll_ready(collect_cumulative_outcomes_async(view, &(), &head_slot()))
    } else {
        collect_cumulative_outcomes(&view.0, &head_slot())
    }
}

fn candidate(
    previous: &RepositoryAuthorityHeadBody,
    cumulative: &CumulativeOutcomes,
    identity: u8,
) -> (RepositoryDecisionBatchBody, RepositoryAuthorityHeadBody) {
    let sequence = previous
        .latest_decision_sequence
        .map_or(1, |value| value.get() + 1);
    let decision = refused(tx(identity), sequence, identity);
    let root = cumulative
        .fold_against(
            cumulative.observed(),
            &[(
                decision.tx_id,
                TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                },
            )],
        )
        .unwrap();
    let mut next_batch = batch(previous, sequence, vec![decision]);
    next_batch.resulting_ref_root = previous.ref_root;
    next_batch.resulting_forge_position_root = previous.forge_position_root;
    next_batch.resulting_outcome_index_root = root;
    next_batch.resulting_retention_root = previous.retention_root;
    next_batch.resulting_outbox_root = previous.outbox_root;
    next_batch.resulting_policy_epoch = previous.policy_epoch;
    let mut next = successor_head(previous, batch_id_of(&next_batch), sequence);
    next.outcome_index_root = root;
    (next_batch, next)
}

fn publish_retained(
    view: &AsyncView,
    asynchronous: bool,
    expected: AuthorityVersionToken,
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
    cumulative: &CumulativeOutcomes,
) -> Result<PublicationOutcome, OutcomeFailure> {
    if asynchronous {
        poll_ready(publish_decisions_with_cumulative_async(
            view,
            &(),
            &head_slot(),
            expected,
            batch,
            head,
            tenant(),
            cumulative,
        ))
    } else {
        publish_decisions_with_cumulative(
            &view.0,
            &head_slot(),
            expected,
            batch,
            head,
            tenant(),
            cumulative,
        )
    }
}

fn extend(
    view: &AsyncView,
    asynchronous: bool,
    cumulative: CumulativeOutcomes,
    predecessor: &HeadReadReceipt,
    successor: &HeadReadReceipt,
    batch: &RepositoryDecisionBatchBody,
) -> Result<CumulativeOutcomes, OutcomeFailure> {
    if asynchronous {
        poll_ready(cumulative.extend_after_publication_async(
            view,
            &(),
            predecessor,
            successor,
            batch,
        ))
    } else {
        cumulative.extend_after_publication(&view.0, predecessor, successor, batch)
    }
}

fn published(outcome: PublicationOutcome) -> HeadReadReceipt {
    let PublicationOutcome::Published(receipt) = outcome else {
        panic!("candidate must win, got {outcome:?}")
    };
    receipt.head
}

fn raw_advance(
    view: &AsyncView,
    predecessor: &HeadReadReceipt,
    head: &RepositoryAuthorityHeadBody,
) -> HeadReadReceipt {
    let CasOutcome::Committed(receipt) = view
        .0
        .compare_exchange_head(
            &head_slot(),
            predecessor.token(),
            head.generation,
            &encode_body(head).unwrap(),
        )
        .unwrap()
    else {
        panic!("adversarial fixture advances the real head")
    };
    receipt
}

#[test]
fn retained_publication_and_extension_need_no_history_reads_and_match_replay() {
    for asynchronous in [false, true] {
        for legacy_empty_root in [false, true] {
            let view = fixture(81, legacy_empty_root);
            let mut cumulative = collect(&view, asynchronous).unwrap();
            // Any immutable read would fail. The unchanged generic path below
            // is the control that proves this injector really is armed.
            view.0
                .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                    0,
                    AuthorityOpKind::ReadImmutable,
                    FaultKind::LoseResponse,
                )]));
            for identity in 1..=4 {
                let (predecessor, previous) = current(&view);
                let (batch, head) = candidate(&previous, &cumulative, identity);
                let successor = published(
                    publish_retained(
                        &view,
                        asynchronous,
                        predecessor.token(),
                        &batch,
                        &head,
                        &cumulative,
                    )
                    .unwrap(),
                );
                cumulative = extend(
                    &view,
                    asynchronous,
                    cumulative,
                    &predecessor,
                    &successor,
                    &batch,
                )
                .unwrap();
                assert_eq!(cumulative.observed(), successor.token());
                assert_eq!(cumulative.len(), usize::from(identity));
                for prior in 1..=identity {
                    assert!(cumulative.decision_for(tx(prior)).is_some());
                }
            }
            let (predecessor, previous) = current(&view);
            let (batch, head) = candidate(&previous, &cumulative, 5);
            let generic = if asynchronous {
                poll_ready(publish_decisions_async(
                    &view,
                    &(),
                    &head_slot(),
                    predecessor.token(),
                    &batch,
                    &head,
                    tenant(),
                ))
            } else {
                publish_decisions(
                    &view.0,
                    &head_slot(),
                    predecessor.token(),
                    &batch,
                    &head,
                    tenant(),
                )
            };
            assert!(
                generic.is_err(),
                "ordinary replay must encounter the immutable-read fault"
            );
            assert_eq!(current(&view).0, predecessor);
            view.0.install_fault_plan(FaultPlan::default());
            let replayed = collect(&view, asynchronous).unwrap();
            assert_eq!(
                cumulative
                    .checkpoint_decisions_against(predecessor.token())
                    .unwrap(),
                replayed
                    .checkpoint_decisions_against(predecessor.token())
                    .unwrap(),
            );
            assert_eq!(
                cumulative.fold_against(predecessor.token(), &[]).unwrap(),
                previous.outcome_index_root
            );
        }
    }
}

#[test]
fn retained_publication_preserves_duplicate_conflict_and_stale_verdicts() {
    for asynchronous in [false, true] {
        let view = fixture(82, false);
        let initial = collect(&view, asynchronous).unwrap();
        let (predecessor, previous) = current(&view);
        let (batch, head) = candidate(&previous, &initial, 11);
        let successor = published(
            publish_retained(
                &view,
                asynchronous,
                predecessor.token(),
                &batch,
                &head,
                &initial,
            )
            .unwrap(),
        );
        let cumulative = extend(
            &view,
            asynchronous,
            initial.clone(),
            &predecessor,
            &successor,
            &batch,
        )
        .unwrap();
        assert!(matches!(
            publish_retained(
                &view,
                asynchronous,
                predecessor.token(),
                &batch,
                &head,
                &initial
            )
            .unwrap(),
            PublicationOutcome::PredecessorMismatch,
        ));
        assert!(matches!(
            publish_retained(
                &view,
                asynchronous,
                successor.token(),
                &batch,
                &head,
                &initial
            ),
            Err(OutcomeFailure::CumulativeIndexStale { .. }),
        ));
        let duplicate = publish_retained(
            &view,
            asynchronous,
            successor.token(),
            &batch,
            &head,
            &cumulative,
        )
        .unwrap();
        let PublicationOutcome::AlreadyDecided { decided } = duplicate else {
            panic!("identical terminal must remain decided")
        };
        assert_eq!(
            decided,
            vec![(tx(11), cumulative.decision_for(tx(11)).unwrap())]
        );
        let mut conflict = batch.clone();
        conflict.decisions[0] = refused(tx(11), 1, 12);
        assert!(matches!(
            publish_retained(
                &view,
                asynchronous,
                successor.token(),
                &conflict,
                &head,
                &cumulative
            ),
            Err(OutcomeFailure::AcceleratorConflict { .. }),
        ));
        assert_eq!(current(&view).0, successor);
    }
}

#[test]
fn extension_authenticates_receipts_and_rejects_other_slots_stores_and_candidates() {
    for asynchronous in [false, true] {
        let view = fixture(83, false);
        let initial = collect(&view, asynchronous).unwrap();
        let (predecessor, previous) = current(&view);
        let (batch, head) = candidate(&previous, &initial, 21);
        let staged_only = HeadReadReceipt::new(
            head_slot(),
            predecessor.token(),
            head.generation,
            encode_body(&head).unwrap(),
        );
        assert!(
            extend(
                &view,
                asynchronous,
                initial.clone(),
                &predecessor,
                &staged_only,
                &batch
            )
            .is_err()
        );
        assert_eq!(current(&view).0, predecessor);
        let successor = published(
            publish_retained(
                &view,
                asynchronous,
                predecessor.token(),
                &batch,
                &head,
                &initial,
            )
            .unwrap(),
        );
        let mut different_batch = batch.clone();
        different_batch.decisions[0] = refused(tx(22), 1, 22);
        assert!(matches!(
            extend(
                &view,
                asynchronous,
                initial.clone(),
                &predecessor,
                &successor,
                &different_batch
            ),
            Err(OutcomeFailure::CumulativePublicationMismatch {
                field: "selected decision batch"
            }),
        ));
        assert!(matches!(
            extend(
                &view,
                asynchronous,
                initial.clone(),
                &successor,
                &successor,
                &batch
            ),
            Err(OutcomeFailure::CumulativeIndexStale { .. }),
        ));
        let other_slot = HeadKey::new(b"fg/head/v1/other-slot".to_vec()).unwrap();
        view.0
            .initialize_head(&other_slot, head.generation, &encode_body(&head).unwrap())
            .unwrap();
        let HeadRead::Present(other_receipt) = view.0.read_head(&other_slot).unwrap() else {
            panic!("other slot")
        };
        assert!(matches!(
            extend(
                &view,
                asynchronous,
                initial.clone(),
                &predecessor,
                &other_receipt,
                &batch
            ),
            Err(OutcomeFailure::CumulativePublicationMismatch { field: "head slot" }),
        ));
        let foreign = fixture(84, false);
        let foreign_initial = collect(&foreign, asynchronous).unwrap();
        let (foreign_predecessor, _) = current(&foreign);
        let foreign_successor = published(
            publish_retained(
                &foreign,
                asynchronous,
                foreign_predecessor.token(),
                &batch,
                &head,
                &foreign_initial,
            )
            .unwrap(),
        );
        assert!(
            extend(
                &view,
                asynchronous,
                initial.clone(),
                &predecessor,
                &foreign_successor,
                &batch
            )
            .is_err()
        );
        assert!(
            publish_retained(
                &foreign,
                asynchronous,
                successor.token(),
                &batch,
                &head,
                &initial
            )
            .is_err()
        );
        let retained = extend(
            &view,
            asynchronous,
            initial,
            &predecessor,
            &successor,
            &batch,
        )
        .unwrap();
        assert_eq!(
            retained.len(),
            1,
            "the authentic exact pair remains permitted"
        );
    }
}

#[test]
fn extension_refuses_authenticated_but_nonadjacent_or_wrong_root_successors() {
    for asynchronous in [false, true] {
        for defect in ["predecessor", "generation", "root", "sequence"] {
            let view = fixture(85, false);
            let initial = collect(&view, asynchronous).unwrap();
            let (predecessor, previous) = current(&view);
            let (mut batch, mut head) = candidate(&previous, &initial, 31);
            let field = match defect {
                "predecessor" => {
                    head.predecessor_head_id = None;
                    "predecessor head"
                }
                "generation" => {
                    head.generation = HeadGeneration::try_new(head.generation.get() + 1).unwrap();
                    "head generation"
                }
                "root" => {
                    head.outcome_index_root = digest(99);
                    "successor outcome root"
                }
                "sequence" => {
                    batch.decisions[0].decision_sequence = DecisionSequence::try_new(2).unwrap();
                    head.decision_tail_id = Some(batch_id_of(&batch));
                    head.latest_decision_sequence = Some(DecisionSequence::try_new(2).unwrap());
                    "decision sequence"
                }
                _ => unreachable!(),
            };
            let successor = raw_advance(&view, &predecessor, &head);
            assert!(matches!(
                extend(&view, asynchronous, initial, &predecessor, &successor, &batch),
                Err(OutcomeFailure::CumulativePublicationMismatch { field: observed }) if observed == field,
            ));
        }
    }
}

#[test]
fn a_real_historical_successor_can_extend_but_cannot_replace_a_later_head() {
    for asynchronous in [false, true] {
        let view = fixture(86, false);
        let initial = collect(&view, asynchronous).unwrap();
        let (predecessor, previous) = current(&view);
        let (first_batch, first_head) = candidate(&previous, &initial, 41);
        let first_receipt = published(
            publish_retained(
                &view,
                asynchronous,
                predecessor.token(),
                &first_batch,
                &first_head,
                &initial,
            )
            .unwrap(),
        );
        let first_set = collect(&view, asynchronous).unwrap();
        let (second_batch, second_head) = candidate(&first_head, &first_set, 42);
        let second_receipt = published(
            publish_retained(
                &view,
                asynchronous,
                first_receipt.token(),
                &second_batch,
                &second_head,
                &first_set,
            )
            .unwrap(),
        );
        let late_extension = extend(
            &view,
            asynchronous,
            initial,
            &predecessor,
            &first_receipt,
            &first_batch,
        )
        .unwrap();
        assert_eq!(late_extension.observed(), first_receipt.token());
        assert!(matches!(
            publish_retained(
                &view,
                asynchronous,
                first_receipt.token(),
                &second_batch,
                &second_head,
                &late_extension
            )
            .unwrap(),
            PublicationOutcome::PredecessorMismatch
        ));
        assert_eq!(current(&view).0, second_receipt);
        let current_set = collect(&view, asynchronous).unwrap();
        assert!(current_set.decision_for(tx(41)).is_some());
        assert!(current_set.decision_for(tx(42)).is_some());
    }
}

#[test]
fn a_nonempty_head_with_a_wrong_outcome_root_cannot_mint_an_absence_witness() {
    for asynchronous in [false, true] {
        let view = fixture(87, false);
        let initial = collect(&view, asynchronous).unwrap();
        let (predecessor, previous) = current(&view);
        let (first_batch, first_head) = candidate(&previous, &initial, 51);
        let first_receipt = published(
            publish_retained(
                &view,
                asynchronous,
                predecessor.token(),
                &first_batch,
                &first_head,
                &initial,
            )
            .unwrap(),
        );
        let mut corrupted = first_head.clone();
        corrupted.generation = HeadGeneration::try_new(first_head.generation.get() + 1).unwrap();
        corrupted.outcome_index_root = digest(0);
        let corrupted_receipt = raw_advance(&view, &first_receipt, &corrupted);
        let collected = collect(&view, asynchronous).unwrap();
        assert_eq!(collected.len(), 1);
        let (candidate_batch, candidate_head) = candidate(&corrupted, &collected, 52);
        assert!(matches!(
            publish_retained(
                &view,
                asynchronous,
                corrupted_receipt.token(),
                &candidate_batch,
                &candidate_head,
                &collected
            ),
            Err(OutcomeFailure::CumulativePublicationMismatch {
                field: "predecessor outcome root"
            }),
        ));
        assert_eq!(current(&view).0, corrupted_receipt);
        assert_eq!(
            indexed_outcome(&view.0, tenant(), repository(), tx(52)).unwrap(),
            OutcomeLookup::Undecided
        );
    }
}

#[test]
fn ambiguous_publication_and_receipt_authentication_never_promote_unverified_state() {
    for asynchronous in [false, true] {
        for fault in [FaultKind::LoseRequest, FaultKind::LoseResponse] {
            let view = fixture(88, false);
            let initial = collect(&view, asynchronous).unwrap();
            let (predecessor, previous) = current(&view);
            let (batch, head) = candidate(&previous, &initial, 61);
            view.0
                .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                    0,
                    AuthorityOpKind::CompareExchangeHead,
                    fault,
                )]));
            assert!(
                publish_retained(
                    &view,
                    asynchronous,
                    predecessor.token(),
                    &batch,
                    &head,
                    &initial
                )
                .is_err()
            );
            assert_eq!(initial.observed(), predecessor.token());
            assert!(initial.is_empty());
            view.0.install_fault_plan(FaultPlan::default());
            let (observed, _) = current(&view);
            let recovered = collect(&view, asynchronous).unwrap();
            if fault == FaultKind::LoseResponse {
                assert_ne!(observed, predecessor);
                assert_eq!(recovered.len(), 1);
                assert!(matches!(
                    publish_retained(
                        &view,
                        asynchronous,
                        observed.token(),
                        &batch,
                        &head,
                        &recovered
                    )
                    .unwrap(),
                    PublicationOutcome::AlreadyDecided { .. }
                ));
            } else {
                assert_eq!(observed, predecessor);
                assert!(recovered.is_empty());
                published(
                    publish_retained(
                        &view,
                        asynchronous,
                        predecessor.token(),
                        &batch,
                        &head,
                        &initial,
                    )
                    .unwrap(),
                );
            }
            let successor = current(&view).0;
            for ordinal in [0, 1] {
                view.0
                    .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                        ordinal,
                        AuthorityOpKind::AuthenticateHeadReceipt,
                        FaultKind::LoseResponse,
                    )]));
                assert!(
                    extend(
                        &view,
                        asynchronous,
                        initial.clone(),
                        &predecessor,
                        &successor,
                        &batch
                    )
                    .is_err()
                );
                assert!(initial.is_empty());
                view.0.install_fault_plan(FaultPlan::default());
                let retry = extend(
                    &view,
                    asynchronous,
                    initial.clone(),
                    &predecessor,
                    &successor,
                    &batch,
                )
                .unwrap();
                assert_eq!(retry.len(), 1);
                assert_eq!(retry.observed(), successor.token());
            }
            assert_eq!(collect(&view, asynchronous).unwrap().len(), 1);
        }
    }
}
