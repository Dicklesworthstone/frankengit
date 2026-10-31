//! An exact retained witness replaces history I/O without weakening the
//! authority, hint-reconciliation, or moving-head boundary. Every witness in
//! these tests comes from the real collector after real reference publication.

use super::*;
use fgit_authority::{
    AmbiguityReason, AuthorityOpKind, AuthorityRefusal, CumulativeOutcomes, FaultDirective,
    FaultKind, FaultPlan, FaultableAuthorityStore, resolve_outcome_with_cumulative,
    resolve_outcome_with_cumulative_async,
};
use fgit_codec::encode_body;
use fgit_types::RepositoryCommitId;

fn tx(byte: u8) -> TxId {
    let digest = digest(byte);
    TxId::from_digest(digest.algorithm(), CANONICAL_CODEC_VERSION, *digest.bytes())
}

fn collect(store: &ObservedStore) -> CumulativeOutcomes {
    collect_cumulative_outcomes(&store.inner, &store.head).unwrap()
}

fn resolve_at(
    surface: Surface,
    store: &ObservedStore,
    head_key: &HeadKey,
    expected: AuthorityVersionToken,
    repository_id: RepositoryId,
    tx_id: TxId,
    cumulative: &CumulativeOutcomes,
) -> Result<Option<OutcomeLookup>, OutcomeFailure> {
    match surface {
        Surface::Blocking => resolve_outcome_with_cumulative(
            store,
            head_key,
            expected,
            TENANT,
            repository_id,
            tx_id,
            cumulative,
        ),
        Surface::Async => ready(resolve_outcome_with_cumulative_async(
            store,
            &(),
            head_key,
            expected,
            TENANT,
            repository_id,
            tx_id,
            cumulative,
        )),
    }
}

fn resolve(
    surface: Surface,
    store: &ObservedStore,
    cumulative: &CumulativeOutcomes,
    tx_id: TxId,
) -> Result<Option<OutcomeLookup>, OutcomeFailure> {
    resolve_at(
        surface,
        store,
        &store.head,
        cumulative.observed(),
        REPOSITORY,
        tx_id,
        cumulative,
    )
}

fn reset(store: &ObservedStore) {
    store.inner.install_fault_plan(FaultPlan::default());
    store.head_reads.store(0, Ordering::SeqCst);
    store.hint_reads.store(0, Ordering::SeqCst);
    store.writes.store(0, Ordering::SeqCst);
}

fn observed_kinds(store: &ObservedStore) -> Vec<AuthorityOpKind> {
    store
        .inner
        .effect_log()
        .records()
        .iter()
        .map(|record| record.op_kind)
        .collect()
}

fn append(store: &ObservedStore, tx_id: TxId, outcome: DecisionOutcome) {
    let HeadRead::Present(receipt) = store.inner.read_head(&store.head).unwrap() else {
        panic!("fixture head exists");
    };
    let previous: RepositoryAuthorityHeadBody =
        decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
    let sequence = DecisionSequence::try_new(
        previous
            .latest_decision_sequence
            .map_or(1, |previous| previous.get() + 1),
    )
    .unwrap();
    let terminal = TerminalOutcome {
        decision_sequence: sequence,
        outcome,
    };
    let root = collect(store)
        .fold_against(receipt.token(), &[(tx_id, terminal)])
        .unwrap();
    let batch = RepositoryDecisionBatchBody {
        repository_id: REPOSITORY,
        predecessor_head_id: authority_head_identity(&previous).unwrap(),
        predecessor_head_generation: previous.generation,
        first_decision_sequence: sequence,
        decisions: vec![RepositoryDecision {
            tx_id,
            decision_sequence: sequence,
            outcome,
        }],
        // Authority resolution treats commit identities as terminal values.
        // This fixture makes no chronicle-validation or durable-node claim.
        committed_rcrs: Vec::new(),
        resulting_ref_root: previous.ref_root,
        resulting_forge_position_root: previous.forge_position_root,
        resulting_outcome_index_root: root,
        resulting_retention_root: previous.retention_root,
        resulting_outbox_root: previous.outbox_root,
        resulting_policy_epoch: previous.policy_epoch,
        batch_evidence_root: digest(0x91),
        compaction_generation_link: None,
    };
    let successor = RepositoryAuthorityHeadBody {
        generation: previous.generation.next().unwrap(),
        predecessor_head_id: Some(batch.predecessor_head_id),
        decision_tail_id: Some(decision_batch_identity(&batch).unwrap()),
        latest_decision_sequence: Some(sequence),
        outcome_index_root: root,
        ..previous
    };
    assert!(matches!(
        publish_decisions(
            &store.inner,
            &store.head,
            receipt.token(),
            &batch,
            &successor,
            TENANT,
        )
        .unwrap(),
        PublicationOutcome::Published(_)
    ));
}

#[test]
fn retained_terminals_and_absence_match_replay_with_constant_history_io() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        publish(&store, RefusalCode::EvidenceInvalid);
        let commit_digest = digest(0x75);
        let committed = DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                IdentityDomain::RepositoryCommitRecord.algorithm().id(),
                CANONICAL_CODEC_VERSION,
                *commit_digest.bytes(),
            ),
        };
        append(&store, tx(0x76), committed);
        for identity in 0x80..0x88 {
            append(
                &store,
                tx(identity),
                terminal(RefusalCode::QuotaExceeded).outcome,
            );
        }
        let cumulative = collect(&store);
        assert_eq!(cumulative.len(), 10);
        for requested in [transaction(), tx(0x76), tx(0x87), tx(0xfa)] {
            let expected =
                resolve_outcome(&store.inner, &store.head, TENANT, REPOSITORY, requested).unwrap();
            reset(&store);
            assert_eq!(
                resolve(surface, &store, &cumulative, requested).unwrap(),
                Some(expected),
            );
            assert_eq!(
                observed_kinds(&store),
                vec![
                    AuthorityOpKind::ReadImmutable,
                    AuthorityOpKind::ReadHead,
                    AuthorityOpKind::AuthenticateHeadReceipt,
                ],
                "only the accelerator is read; no batch or predecessor is replayed",
            );
            assert_eq!(store.inner.effect_log().mutation_count(), 0);
        }
        reset(&store);
        resolve_outcome(&store.inner, &store.head, TENANT, REPOSITORY, tx(0xfa)).unwrap();
        assert_eq!(
            observed_kinds(&store)
                .iter()
                .filter(|kind| **kind == AuthorityOpKind::ReadImmutable)
                .count(),
            1 + 10 * 2,
            "the ordinary absence control still reads the ten-batch history",
        );
    }
}

#[test]
fn a_missing_hint_and_unavailable_history_use_the_authenticated_retained_decision() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        let batch = publish(&store, RefusalCode::EvidenceInvalid);
        let cumulative = collect(&store);
        let batch_key = body_key_for_id(
            decision_batch_identity(&batch)
                .unwrap()
                .as_internal_object_id(),
        )
        .unwrap();
        store.override_read(store.hint.clone(), ImmutableRead::Absent);
        store.override_read(batch_key, ImmutableRead::Absent);
        reset(&store);
        assert_eq!(
            resolve(surface, &store, &cumulative, transaction()).unwrap(),
            Some(OutcomeLookup::Decided(terminal(
                RefusalCode::EvidenceInvalid
            ))),
        );
        store.assert_read_only_resolution();
        assert_eq!(
            observed_kinds(&store),
            vec![
                AuthorityOpKind::ReadHead,
                AuthorityOpKind::AuthenticateHeadReceipt,
            ],
        );
        assert_eq!(
            surface.resolve(&store),
            Err(OutcomeFailure::StreamBodyMissing {
                link: "decision batch",
            }),
            "without the real retained witness the missing stream remains an error",
        );
    }
}

#[test]
fn phantom_and_conflicting_hints_preserve_the_existing_diagnostics() {
    let donor = ObservedStore::new();
    publish(&donor, RefusalCode::QuotaExceeded);
    let wrong_hint = donor.inner.read_immutable(&donor.hint).unwrap();
    for surface in SURFACES {
        for has_decision in [false, true] {
            let store = ObservedStore::new();
            if has_decision {
                publish(&store, RefusalCode::EvidenceInvalid);
            }
            let cumulative = collect(&store);
            store.override_read(store.hint.clone(), wrong_hint.clone());
            let expected = surface.resolve(&store).unwrap_err();
            assert!(matches!(
                expected,
                OutcomeFailure::AcceleratorConflict { .. }
            ));
            reset(&store);
            assert_eq!(
                resolve(surface, &store, &cumulative, transaction()),
                Err(expected)
            );
            store.assert_read_only_resolution();
        }
    }
}

#[test]
fn witness_token_mismatch_is_an_error_but_an_advanced_head_requires_replanning() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        let previous = collect(&store);
        publish(&store, RefusalCode::EvidenceInvalid);
        let current = collect(&store);
        reset(&store);
        assert_eq!(
            resolve_at(
                surface,
                &store,
                &store.head,
                current.observed(),
                REPOSITORY,
                transaction(),
                &previous,
            ),
            Err(OutcomeFailure::CumulativeIndexStale {
                observed: previous.observed(),
                expected: current.observed(),
            }),
        );
        assert!(store.inner.effect_log().is_empty());
        assert_eq!(
            resolve(surface, &store, &previous, transaction()).unwrap(),
            None
        );
        store.assert_read_only_resolution();
        assert_eq!(
            resolve(surface, &store, &current, transaction()).unwrap(),
            Some(OutcomeLookup::Decided(terminal(
                RefusalCode::EvidenceInvalid
            ))),
        );
    }
}

#[test]
fn publications_on_either_side_of_hint_read_replan_without_a_false_verdict() {
    for surface in SURFACES {
        for timing in [HintTiming::BeforeRead, HintTiming::AfterRead] {
            let store = ObservedStore::new();
            let previous = collect(&store);
            *store.publish_on_hint.lock().unwrap() = Some(timing);
            assert_eq!(
                resolve(surface, &store, &previous, transaction()).unwrap(),
                None
            );
            assert!(store.publish_on_hint.lock().unwrap().is_none());
            store.assert_read_only_resolution();
            let current = collect(&store);
            assert_eq!(
                resolve(surface, &store, &current, transaction()).unwrap(),
                Some(surface.resolve(&store).unwrap()),
            );
        }
    }
}

#[test]
fn an_absent_head_is_not_an_undecided_witness_and_legacy_genesis_remains_valid() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        let absent = HeadKey::new(b"retained/absent-head".to_vec()).unwrap();
        let empty = collect_cumulative_outcomes(&store.inner, &absent).unwrap();
        assert_eq!(
            resolve_at(
                surface,
                &store,
                &absent,
                empty.observed(),
                REPOSITORY,
                transaction(),
                &empty,
            )
            .unwrap(),
            None,
        );
        let current = collect(&store);
        assert_eq!(
            resolve(surface, &store, &current, transaction()).unwrap(),
            Some(OutcomeLookup::Undecided),
        );

        let HeadRead::Present(receipt) = store.inner.read_head(&store.head).unwrap() else {
            panic!("fixture head exists");
        };
        let mut genesis: RepositoryAuthorityHeadBody =
            decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
        genesis.outcome_index_root = digest(0x99);
        let legacy = HeadKey::new(b"retained/legacy-genesis".to_vec()).unwrap();
        initialize_repository(&store.inner, &legacy, &genesis).unwrap();
        let empty = collect_cumulative_outcomes(&store.inner, &legacy).unwrap();
        assert_eq!(
            resolve_at(
                surface,
                &store,
                &legacy,
                empty.observed(),
                REPOSITORY,
                transaction(),
                &empty,
            )
            .unwrap(),
            Some(OutcomeLookup::Undecided),
        );
    }
}

#[test]
fn wrong_repository_and_nonempty_root_fail_before_returning_a_matching_terminal() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        publish(&store, RefusalCode::EvidenceInvalid);
        let cumulative = collect(&store);
        assert_eq!(
            resolve_at(
                surface,
                &store,
                &store.head,
                cumulative.observed(),
                RepositoryId::from_bytes([0x99; 16]),
                transaction(),
                &cumulative,
            ),
            Err(OutcomeFailure::CumulativePublicationMismatch {
                field: "repository"
            }),
        );

        // Deliberately install a corrupt selected root through the reference
        // primitive. This is a fault fixture, not a valid publication path.
        let HeadRead::Present(receipt) = store.inner.read_head(&store.head).unwrap() else {
            panic!("fixture head exists");
        };
        let mut head: RepositoryAuthorityHeadBody =
            decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
        head.predecessor_head_id = Some(authority_head_identity(&head).unwrap());
        head.generation = head.generation.next().unwrap();
        head.outcome_index_root = digest(0x98);
        assert!(matches!(
            store
                .inner
                .compare_exchange_head(
                    &store.head,
                    receipt.token(),
                    head.generation,
                    &encode_body(&head).unwrap(),
                )
                .unwrap(),
            CasOutcome::Committed(_),
        ));
        let corrupted = collect(&store);
        assert_eq!(
            corrupted.decision_for(transaction()),
            cumulative.decision_for(transaction())
        );
        reset(&store);
        assert_eq!(
            resolve(surface, &store, &corrupted, transaction()),
            Err(OutcomeFailure::CumulativePublicationMismatch {
                field: "predecessor outcome root",
            }),
        );
        store.assert_read_only_resolution();
    }
}

#[test]
fn hint_head_and_authentication_failures_propagate_without_manufacturing_absence() {
    for surface in SURFACES {
        for kind in [
            AuthorityOpKind::ReadImmutable,
            AuthorityOpKind::ReadHead,
            AuthorityOpKind::AuthenticateHeadReceipt,
        ] {
            for fault in [
                FaultKind::LoseRequest,
                FaultKind::LoseResponse,
                FaultKind::Throttle,
            ] {
                let store = ObservedStore::new();
                publish(&store, RefusalCode::EvidenceInvalid);
                let cumulative = collect(&store);
                store.inner.install_fault_plan(FaultPlan::explicit(vec![
                    FaultDirective::nth_of_kind(0, kind, fault),
                ]));
                let failure = match fault {
                    FaultKind::Throttle => AuthorityFailure::Refused(AuthorityRefusal::Throttled),
                    _ => AuthorityFailure::Ambiguous(AmbiguityReason::NoResponse),
                };
                assert_eq!(
                    resolve(surface, &store, &cumulative, transaction()),
                    Err(OutcomeFailure::from(failure)),
                );
                assert_eq!(store.inner.effect_log().mutation_count(), 0);
                reset(&store);
                assert_eq!(
                    resolve(surface, &store, &cumulative, transaction()).unwrap(),
                    Some(OutcomeLookup::Decided(terminal(
                        RefusalCode::EvidenceInvalid
                    ))),
                );
            }
        }
    }
}
