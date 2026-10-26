//! Shared-replay outcomes against the real atomic reference store. The exact
//! I/O counts are mechanism evidence, not a durable-node timing claim.

use super::*;
use fgit_authority::{
    AmbiguityReason, AuthorityOpKind, FaultDirective, FaultKind, FaultPlan,
    FaultableAuthorityStore, resolve_outcomes, resolve_outcomes_async,
};
use fgit_codec::encode_body;

fn tx(byte: u8) -> TxId {
    let digest = digest(byte);
    TxId::from_digest(digest.algorithm(), CANONICAL_CODEC_VERSION, *digest.bytes())
}

fn resolve(
    surface: Surface,
    store: &ObservedStore,
    transactions: &[TxId],
) -> Result<Vec<(TxId, OutcomeLookup)>, OutcomeFailure> {
    match surface {
        Surface::Blocking => resolve_outcomes(store, &store.head, TENANT, REPOSITORY, transactions),
        Surface::Async => ready(resolve_outcomes_async(
            store,
            &(),
            &store.head,
            TENANT,
            REPOSITORY,
            transactions,
        )),
    }
}

fn observed_count(store: &ObservedStore, kind: AuthorityOpKind) -> usize {
    store
        .inner
        .effect_log()
        .records()
        .iter()
        .filter(|record| record.op_kind == kind)
        .count()
}

fn reset(store: &ObservedStore) {
    store.inner.install_fault_plan(FaultPlan::default());
    store.head_reads.store(0, Ordering::SeqCst);
    store.hint_reads.store(0, Ordering::SeqCst);
}

fn publish_many(store: &ObservedStore, identities: &[u8]) -> RepositoryDecisionBatchBody {
    let HeadRead::Present(receipt) = store.inner.read_head(&store.head).unwrap() else {
        panic!("fixture head exists")
    };
    let previous: RepositoryAuthorityHeadBody =
        decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
    let first = previous
        .latest_decision_sequence
        .map_or(1, |sequence| sequence.get() + 1);
    let decisions: Vec<_> = identities
        .iter()
        .enumerate()
        .map(|(index, identity)| RepositoryDecision {
            tx_id: tx(*identity),
            decision_sequence: DecisionSequence::try_new(first + index as u64).unwrap(),
            outcome: terminal(RefusalCode::QuotaExceeded).outcome,
        })
        .collect();
    let stamped: Vec<_> = decisions
        .iter()
        .map(|decision| {
            (
                decision.tx_id,
                TerminalOutcome {
                    decision_sequence: decision.decision_sequence,
                    outcome: decision.outcome,
                },
            )
        })
        .collect();
    let root = collect_cumulative_outcomes(&store.inner, &store.head)
        .unwrap()
        .fold_against(receipt.token(), &stamped)
        .unwrap();
    let batch = RepositoryDecisionBatchBody {
        repository_id: REPOSITORY,
        predecessor_head_id: authority_head_identity(&previous).unwrap(),
        predecessor_head_generation: previous.generation,
        first_decision_sequence: decisions[0].decision_sequence,
        decisions,
        committed_rcrs: Vec::new(),
        resulting_ref_root: previous.ref_root,
        resulting_forge_position_root: previous.forge_position_root,
        resulting_outcome_index_root: root,
        resulting_retention_root: previous.retention_root,
        resulting_outbox_root: previous.outbox_root,
        resulting_policy_epoch: previous.policy_epoch,
        batch_evidence_root: digest(91),
        compaction_generation_link: None,
    };
    let next = RepositoryAuthorityHeadBody {
        generation: previous.generation.next().unwrap(),
        predecessor_head_id: Some(batch.predecessor_head_id),
        decision_tail_id: Some(decision_batch_identity(&batch).unwrap()),
        latest_decision_sequence: batch
            .decisions
            .last()
            .map(|decision| decision.decision_sequence),
        outcome_index_root: root,
        ..previous
    };
    assert!(matches!(
        publish_decisions(
            &store.inner,
            &store.head,
            receipt.token(),
            &batch,
            &next,
            TENANT
        )
        .unwrap(),
        PublicationOutcome::Published(_)
    ));
    batch
}

#[test]
fn mixed_queries_share_one_walk_and_preserve_order_and_duplicate_positions() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        for first in [1, 4, 7, 10, 13] {
            publish_many(&store, &[first, first + 1, first + 2]);
        }
        let requested = [tx(15), tx(2), tx(9), tx(250), tx(15)];
        let expected: Vec<_> = requested
            .iter()
            .map(|tx_id| {
                (
                    *tx_id,
                    resolve_outcome(&store.inner, &store.head, TENANT, REPOSITORY, *tx_id).unwrap(),
                )
            })
            .collect();
        reset(&store);
        assert_eq!(resolve(surface, &store, &requested).unwrap(), expected);
        // Four distinct hints, five batches, and five predecessor heads,
        // including the terminal genesis head. No child repeats the walk.
        assert_eq!(
            observed_count(&store, AuthorityOpKind::ReadImmutable),
            4 + 5 * 2
        );
        assert_eq!(observed_count(&store, AuthorityOpKind::ReadHead), 1);
        assert_eq!(
            observed_count(&store, AuthorityOpKind::AuthenticateHeadReceipt),
            1
        );
        assert_eq!(store.inner.effect_log().mutation_count(), 0);
        reset(&store);
        for tx_id in requested {
            resolve_outcome(&store.inner, &store.head, TENANT, REPOSITORY, tx_id).unwrap();
        }
        assert!(
            observed_count(&store, AuthorityOpKind::ReadImmutable) > 4 + 5 * 2,
            "the singular replay control must perform the repeated work this API removes"
        );
    }
}

#[test]
fn recent_terminals_stop_before_older_missing_history_but_absence_does_not() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        let previous = publish_many(&store, &[1, 2]);
        publish_many(&store, &[3, 4]);
        let prior_key = body_key_for_id(
            decision_batch_identity(&previous)
                .unwrap()
                .as_internal_object_id(),
        )
        .unwrap();
        store.override_read(prior_key, ImmutableRead::Absent);
        reset(&store);
        let resolved = resolve(surface, &store, &[tx(4), tx(3), tx(4)]).unwrap();
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0], resolved[2]);
        assert!(
            resolved
                .iter()
                .all(|(_, outcome)| matches!(outcome, OutcomeLookup::Decided(_)))
        );
        assert_eq!(
            observed_count(&store, AuthorityOpKind::ReadImmutable),
            3,
            "two distinct hints and one selected batch, with no predecessor read"
        );
        assert_eq!(
            resolve(surface, &store, &[tx(4), tx(250)]),
            Err(OutcomeFailure::StreamBodyMissing {
                link: "decision batch"
            })
        );
    }
}

#[test]
fn all_hints_precede_the_shared_head_even_when_the_last_hint_publishes() {
    for surface in SURFACES {
        for timing in [HintTiming::BeforeRead, HintTiming::AfterRead] {
            let store = ObservedStore::new();
            *store.publish_on_hint.lock().unwrap() = Some(timing);
            let requested = [tx(250), transaction(), transaction()];
            assert_eq!(
                resolve(surface, &store, &requested).unwrap(),
                vec![
                    (tx(250), OutcomeLookup::Undecided),
                    (
                        transaction(),
                        OutcomeLookup::Decided(terminal(RefusalCode::EvidenceInvalid))
                    ),
                    (
                        transaction(),
                        OutcomeLookup::Decided(terminal(RefusalCode::EvidenceInvalid))
                    ),
                ]
            );
            assert_eq!(store.head_reads.load(Ordering::SeqCst), 1);
            assert_eq!(
                store.hint_reads.load(Ordering::SeqCst),
                1,
                "duplicate queries must reuse the captured hint"
            );
            assert!(store.publish_on_hint.lock().unwrap().is_none());
            assert_eq!(store.writes.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn empty_queries_do_no_io_and_missing_hints_do_not_hide_terminal_outcomes() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        reset(&store);
        assert!(resolve(surface, &store, &[]).unwrap().is_empty());
        assert!(store.inner.effect_log().is_empty());
        assert_eq!(
            resolve(surface, &store, &[tx(249), tx(250)]).unwrap(),
            vec![
                (tx(249), OutcomeLookup::Undecided),
                (tx(250), OutcomeLookup::Undecided),
            ]
        );
        publish_many(&store, &[1, 2]);
        for identity in [1, 2] {
            store.override_read(
                outcome_key(TENANT, REPOSITORY, tx(identity)).unwrap(),
                ImmutableRead::Absent,
            );
        }
        let resolved = resolve(surface, &store, &[tx(2), tx(1)]).unwrap();
        assert!(
            resolved
                .iter()
                .all(|(_, outcome)| matches!(outcome, OutcomeLookup::Decided(_)))
        );
    }
}

#[test]
fn matching_hints_do_not_replace_missing_or_reidentified_batch_bodies() {
    for surface in SURFACES {
        for absent in [false, true] {
            let store = ObservedStore::new();
            let actual = publish_many(&store, &[1, 2]);
            let key = body_key_for_id(
                decision_batch_identity(&actual)
                    .unwrap()
                    .as_internal_object_id(),
            )
            .unwrap();
            let replacement = if absent {
                ImmutableRead::Absent
            } else {
                let mut changed = actual.clone();
                changed.decisions[0].tx_id = tx(99);
                ImmutableRead::Present(encode_body(&changed).unwrap())
            };
            store.override_read(key, replacement);
            let result = resolve(surface, &store, &[tx(2), tx(1)]);
            if absent {
                assert_eq!(
                    result,
                    Err(OutcomeFailure::StreamBodyMissing {
                        link: "decision batch"
                    })
                );
            } else {
                assert!(matches!(
                    result,
                    Err(OutcomeFailure::BodyIdentityMismatch {
                        link: "decision batch",
                        ..
                    })
                ));
            }
        }
    }
}

#[test]
fn stable_phantom_and_conflicting_hints_keep_the_singular_diagnostics() {
    let donor = ObservedStore::new();
    publish(&donor, RefusalCode::QuotaExceeded);
    let wrong_hint = donor.inner.read_immutable(&donor.hint).unwrap();
    for surface in SURFACES {
        for has_decision in [false, true] {
            let store = ObservedStore::new();
            if has_decision {
                publish(&store, RefusalCode::EvidenceInvalid);
            }
            store.override_read(store.hint.clone(), wrong_hint.clone());
            let expected = surface.resolve(&store).unwrap_err();
            assert!(matches!(
                expected,
                OutcomeFailure::AcceleratorConflict { .. }
            ));
            assert_eq!(
                resolve(surface, &store, &[tx(250), transaction(), transaction()]),
                Err(expected)
            );
        }
    }
}

#[test]
fn authentication_or_mid_replay_interruption_returns_no_partial_result_and_retries() {
    for surface in SURFACES {
        for authentication in [false, true] {
            let store = ObservedStore::new();
            publish_many(&store, &[1]);
            publish_many(&store, &[2]);
            let (ordinal, kind) = if authentication {
                (0, AuthorityOpKind::AuthenticateHeadReceipt)
            } else {
                // Two hints, then the latest batch resolves tx(2), then its
                // predecessor read is interrupted before tx(1) is known.
                (3, AuthorityOpKind::ReadImmutable)
            };
            store
                .inner
                .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                    ordinal,
                    kind,
                    FaultKind::LoseResponse,
                )]));
            assert_eq!(
                resolve(surface, &store, &[tx(2), tx(1)]),
                Err(OutcomeFailure::from(AuthorityFailure::Ambiguous(
                    AmbiguityReason::NoResponse
                ),))
            );
            reset(&store);
            let retry = resolve(surface, &store, &[tx(2), tx(1)]).unwrap();
            assert_eq!(retry.len(), 2);
            assert!(
                retry
                    .iter()
                    .all(|(_, outcome)| matches!(outcome, OutcomeLookup::Decided(_)))
            );
            assert_eq!(store.inner.effect_log().mutation_count(), 0);
        }
    }
}
