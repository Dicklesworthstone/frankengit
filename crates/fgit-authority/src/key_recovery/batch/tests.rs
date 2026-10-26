//! Reference-store evidence for shared replay, not a durable-backend benchmark.
use super::*;
use crate::{
    AuthorityLimits, AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit,
    ImmutableKey, MemoryAuthorityStore, PublicationOutcome, PutOutcome, SealAttempt,
    StoreInstanceId, authority_head_identity, body_key_for_id, collect_cumulative_outcomes,
    decision_batch_identity, outcome_key, publish_decisions, seal_request,
};
use fgit_codec::{RepositoryDecision, RepositoryDecisionBatchBody};
use fgit_types::{DecisionOutcome, DecisionSequence, HeadGeneration, RefusalRecordId};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

struct ObservedStore {
    inner: MemoryAuthorityStore,
    head: HeadKey,
    scope: RecoveryScope,
    reads: AtomicUsize,
    heads: AtomicUsize,
    authentications: AtomicUsize,
    writes: AtomicUsize,
    overrides: Mutex<BTreeMap<ImmutableKey, ImmutableRead>>,
    publish_on_hint: Mutex<Option<Vec<SealAttempt>>>,
}
impl AsyncAuthorityStore for ObservedStore {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }
    async fn put_if_absent(
        &self,
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.put_if_absent(key, body)
    }
    async fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if key.as_bytes().starts_with(crate::OUTCOME_KEY_PREFIX) {
            let publication = self.publish_on_hint.lock().unwrap().take();
            if let Some(attempts) = publication {
                publish(self, &attempts);
            }
        }
        if let Some(value) = self.overrides.lock().unwrap().get(key).cloned() {
            return Ok(value);
        }
        self.inner.read_immutable(key)
    }
    async fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.initialize_head(key, generation, body)
    }
    async fn read_head(&self, _: &(), key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.heads.fetch_add(1, Ordering::SeqCst);
        self.inner.read_head(key)
    }
    async fn compare_exchange_head(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .compare_exchange_head(key, expected, generation, body)
    }
    async fn publish_head_with_outcomes(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness)
    }
    async fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.authentications.fetch_add(1, Ordering::SeqCst);
        self.inner.authenticate_head_receipt(receipt)
    }
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("reference reads do not suspend"),
    }
}
fn setup(count: usize) -> (ObservedStore, Vec<SealAttempt>) {
    let (inner, head, scope, template) = super::super::tests::fixture();
    let attempts = (0..count)
        .map(|index| SealAttempt {
            idempotency_key: IdempotencyKey::new(format!("batch-recovery-{index:05}").into_bytes())
                .unwrap(),
            ..template.clone()
        })
        .collect();
    (
        ObservedStore {
            inner,
            head,
            scope,
            reads: AtomicUsize::new(0),
            heads: AtomicUsize::new(0),
            authentications: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            overrides: Mutex::new(BTreeMap::new()),
            publish_on_hint: Mutex::new(None),
        },
        attempts,
    )
}
fn seal(store: &ObservedStore, attempts: &[SealAttempt]) {
    for attempt in attempts {
        seal_request(&store.inner, attempt).unwrap();
    }
}
fn keys(attempts: &[SealAttempt]) -> Vec<IdempotencyKey> {
    attempts
        .iter()
        .map(|attempt| attempt.idempotency_key.clone())
        .collect()
}
fn recover(
    store: &ObservedStore,
    keys: &[IdempotencyKey],
) -> Result<Vec<RequestRecovery>, RecoveryFailure> {
    ready(recover_requests_async(
        store,
        &(),
        &store.head,
        store.scope,
        keys,
        &|| Ok(()),
    ))
}
fn head(store: &ObservedStore) -> (HeadReadReceipt, RepositoryAuthorityHeadBody) {
    let HeadRead::Present(receipt) = store.inner.read_head(&store.head).unwrap() else {
        panic!("genesis")
    };
    let body = decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
    (receipt, body)
}
fn publish(store: &ObservedStore, attempts: &[SealAttempt]) -> RepositoryDecisionBatchBody {
    let (receipt, predecessor) = head(store);
    let first = predecessor
        .latest_decision_sequence
        .map_or(1, |n| n.get() + 1);
    let digest = fgit_codec::harness::digest_of(77);
    let refusal =
        RefusalRecordId::from_digest(digest.algorithm(), CANONICAL_CODEC_VERSION, *digest.bytes());
    let decisions: Vec<_> = attempts
        .iter()
        .enumerate()
        .map(|(index, attempt)| RepositoryDecision {
            tx_id: attempt.derive().unwrap().0,
            decision_sequence: DecisionSequence::try_new(first + index as u64).unwrap(),
            outcome: DecisionOutcome::Refused {
                code: RefusalCode::EvidenceInvalid,
                refusal_record_id: refusal,
            },
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
        repository_id: store.scope.repository_id,
        predecessor_head_id: authority_head_identity(&predecessor).unwrap(),
        predecessor_head_generation: predecessor.generation,
        first_decision_sequence: DecisionSequence::try_new(first).unwrap(),
        decisions,
        committed_rcrs: Vec::new(),
        resulting_ref_root: predecessor.ref_root,
        resulting_forge_position_root: predecessor.forge_position_root,
        resulting_outcome_index_root: root,
        resulting_retention_root: predecessor.retention_root,
        resulting_outbox_root: predecessor.outbox_root,
        resulting_policy_epoch: predecessor.policy_epoch,
        batch_evidence_root: digest,
        compaction_generation_link: None,
    };
    let next = RepositoryAuthorityHeadBody {
        generation: predecessor.generation.next().unwrap(),
        predecessor_head_id: Some(batch.predecessor_head_id),
        decision_tail_id: Some(decision_batch_identity(&batch).unwrap()),
        latest_decision_sequence: batch
            .decisions
            .last()
            .map(|decision| decision.decision_sequence),
        outcome_index_root: root,
        ..predecessor
    };
    assert!(matches!(
        publish_decisions(
            &store.inner,
            &store.head,
            receipt.token(),
            &batch,
            &next,
            store.scope.tenant_id
        )
        .unwrap(),
        PublicationOutcome::Published(_)
    ));
    batch
}
fn hint_key(store: &ObservedStore, attempt: &SealAttempt) -> ImmutableKey {
    outcome_key(
        store.scope.tenant_id,
        store.scope.repository_id,
        attempt.derive().unwrap().0,
    )
    .unwrap()
}

#[test]
fn shared_replay_matches_single_key_results_with_linear_reads_and_duplicate_queries() {
    let (store, attempts) = setup(129);
    seal(&store, &attempts);
    for chunk in attempts.chunks(64) {
        publish(&store, chunk);
    }
    let before = store.inner.read_head(&store.head).unwrap();
    let mut query = keys(&attempts);
    query.reverse();
    query.push(query[0].clone());
    query.push(query[128].clone());
    let results = recover(&store, &query).unwrap();
    assert_eq!(results.len(), query.len());
    for (key, result) in query.iter().zip(results) {
        assert_eq!(
            result,
            recover_request(&store.inner, &store.head, store.scope, key, &|| Ok(())).unwrap()
        );
    }
    assert_eq!(
        store.reads.load(Ordering::SeqCst),
        3 * query.len() + 2 * 3 - 1
    );
    assert_eq!(store.heads.load(Ordering::SeqCst), 2);
    assert_eq!(store.authentications.load(Ordering::SeqCst), 2);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(store.inner.read_head(&store.head).unwrap(), before);
}

#[test]
fn missing_hints_do_not_hide_terminal_outcomes_and_negative_observations_stay_distinct() {
    let (store, attempts) = setup(4);
    seal(&store, &attempts[..2]);
    publish(&store, &attempts[..1]);
    let (bound, _) = attempts[2].derive().unwrap();
    crate::bind_idempotency_key(&store.inner, &attempts[2], bound).unwrap();
    store
        .overrides
        .lock()
        .unwrap()
        .insert(hint_key(&store, &attempts[0]), ImmutableRead::Absent);
    let results = recover(&store, &keys(&attempts)).unwrap();
    assert!(results[0].terminal().is_some());
    assert!(
        matches!(&results[1], RequestRecovery::Recovered(known) if known.outcome() == OutcomeLookup::Undecided)
    );
    assert_eq!(results[2], RequestRecovery::SealNotObserved);
    assert_eq!(results[3], RequestRecovery::KeyNotObserved);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn a_hint_published_after_initial_authentication_is_resolved_from_the_fresh_head() {
    for singular in [false, true] {
        let (store, attempts) = setup(2);
        seal(&store, &attempts);
        // The first head is genesis. Publication occurs immediately before the
        // first accelerator read, so retaining that first head would falsely
        // report a conflicting hint. Singular and plural production recovery
        // must both select their replay head after observing those hints.
        *store.publish_on_hint.lock().unwrap() = Some(attempts.clone());
        let query = keys(if singular { &attempts[..1] } else { &attempts });
        let results = if singular {
            vec![
                ready(recover_request_async(
                    &store,
                    &(),
                    &store.head,
                    store.scope,
                    &query[0],
                    &|| Ok(()),
                ))
                .unwrap(),
            ]
        } else {
            recover(&store, &query).unwrap()
        };
        assert_eq!(results.len(), query.len());
        for (result, attempt) in results.iter().zip(&attempts) {
            let RequestRecovery::Recovered(known) = result else {
                panic!("the published seal must remain recoverable");
            };
            let (tx_id, seal) = attempt.derive().unwrap();
            assert_eq!(known.tx_id(), tx_id);
            assert_eq!(known.seal(), &seal);
            assert!(result.terminal().is_some());
            assert_eq!(
                known.outcome(),
                crate::replay_outcome(&store.inner, &store.head, tx_id).unwrap()
            );
        }
        assert_eq!(store.heads.load(Ordering::SeqCst), 2);
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn accelerator_conflicts_and_unreachable_claims_fail_closed() {
    for unreachable in [false, true] {
        let (store, attempts) = setup(2);
        seal(&store, &attempts);
        publish(
            &store,
            if unreachable {
                &attempts[..1]
            } else {
                &attempts
            },
        );
        let foreign = store
            .inner
            .read_immutable(&hint_key(&store, &attempts[0]))
            .unwrap();
        store
            .overrides
            .lock()
            .unwrap()
            .insert(hint_key(&store, &attempts[1]), foreign);
        assert!(
            matches!(recover(&store, &keys(&attempts[1..])), Err(RecoveryFailure::Outcome(failure)) if matches!(*failure, OutcomeFailure::AcceleratorConflict { .. }))
        );
    }
}

#[test]
fn complete_batch_identity_is_checked_even_when_only_an_unchanged_first_row_is_requested() {
    let (store, attempts) = setup(2);
    seal(&store, &attempts);
    let mut batch = publish(&store, &attempts);
    let slot = body_key_for_id(
        decision_batch_identity(&batch)
            .unwrap()
            .as_internal_object_id(),
    )
    .unwrap();
    batch.decisions[1].outcome = DecisionOutcome::Refused {
        code: RefusalCode::QuotaExceeded,
        refusal_record_id: match batch.decisions[1].outcome {
            DecisionOutcome::Refused {
                refusal_record_id, ..
            } => refusal_record_id,
            _ => unreachable!(),
        },
    };
    store
        .overrides
        .lock()
        .unwrap()
        .insert(slot, ImmutableRead::Present(encode_body(&batch).unwrap()));
    assert!(
        matches!(recover(&store, &keys(&attempts[..1])), Err(RecoveryFailure::Outcome(failure)) if matches!(*failure, OutcomeFailure::BodyIdentityMismatch { .. }))
    );
}

#[test]
fn scope_and_seal_identity_are_checked_before_disclosure_including_empty_requests() {
    let (store, attempts) = setup(1);
    seal(&store, &attempts);
    let wrong_repository = RecoveryScope {
        repository_id: RepositoryId::from_bytes([8; 16]),
        ..store.scope
    };
    assert!(matches!(
        ready(recover_requests_async(
            &store,
            &(),
            &store.head,
            wrong_repository,
            &[],
            &|| Ok(())
        )),
        Err(RecoveryFailure::Integrity {
            field: "head repository"
        })
    ));
    let wrong_principal = RecoveryScope {
        principal_id: PrincipalId::from_bytes([8; 16]),
        ..store.scope
    };
    assert_eq!(
        ready(recover_requests_async(
            &store,
            &(),
            &store.head,
            wrong_principal,
            &keys(&attempts),
            &|| Ok(())
        ))
        .unwrap(),
        [RequestRecovery::KeyNotObserved]
    );
    let (tx, mut substituted) = attempts[0].derive().unwrap();
    substituted.authenticated_principal_id = PrincipalId::from_bytes([7; 16]);
    store.overrides.lock().unwrap().insert(
        seal_key(store.scope.tenant_id, store.scope.repository_id, tx).unwrap(),
        ImmutableRead::Present(encode_body(&substituted).unwrap()),
    );
    assert!(matches!(
        recover(&store, &keys(&attempts)),
        Err(RecoveryFailure::Integrity {
            field: "seal principal"
        })
    ));
}

#[test]
fn empty_and_maximum_queries_are_bounded_and_the_first_excess_is_refused_before_reads() {
    let (store, attempts) = setup(1);
    assert!(recover(&store, &[]).unwrap().is_empty());
    assert_eq!(store.heads.load(Ordering::SeqCst), 1);
    assert_eq!(store.authentications.load(Ordering::SeqCst), 1);
    let query = vec![attempts[0].idempotency_key.clone(); MAX_RECOVERY_KEYS];
    let results = recover(&store, &query).unwrap();
    assert_eq!(
        results,
        vec![RequestRecovery::KeyNotObserved; MAX_RECOVERY_KEYS]
    );
    let before = (
        store.reads.load(Ordering::SeqCst),
        store.heads.load(Ordering::SeqCst),
    );
    let mut excess = query;
    excess.push(attempts[0].idempotency_key.clone());
    assert!(
        matches!(recover(&store, &excess), Err(RecoveryFailure::BoundExceeded { field: "request key count", limit: MAX_RECOVERY_KEYS, observed }) if observed == MAX_RECOVERY_KEYS + 1)
    );
    assert_eq!(
        (
            store.reads.load(Ordering::SeqCst),
            store.heads.load(Ordering::SeqCst)
        ),
        before
    );
}

#[test]
fn cancellation_interrupts_shared_replay_before_further_bodies_or_decisions_are_read() {
    let (store, attempts) = setup(3);
    seal(&store, &attempts);
    publish(&store, &attempts);
    let before = store.inner.read_head(&store.head).unwrap();
    let replay_probes = AtomicUsize::new(0);
    let checkpoint = || {
        if store.reads.load(Ordering::SeqCst) == 3 * attempts.len() + 1
            && replay_probes.fetch_add(1, Ordering::SeqCst) >= 2
        {
            Err(RefusalCode::ResourceBudgetExceeded)
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        ready(recover_requests_async(
            &store,
            &(),
            &store.head,
            store.scope,
            &keys(&attempts),
            &checkpoint
        )),
        Err(RecoveryFailure::Interrupted(
            RefusalCode::ResourceBudgetExceeded
        ))
    ));
    assert_eq!(store.reads.load(Ordering::SeqCst), 3 * attempts.len() + 1);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    assert_eq!(store.inner.read_head(&store.head).unwrap(), before);
}

#[test]
fn cancellation_after_the_final_resolution_probe_cannot_erase_a_terminal_batch() {
    let (store, attempts) = setup(1);
    seal(&store, &attempts);
    publish(&store, &attempts);
    let replay_probes = AtomicUsize::new(0);
    let checkpoint = || {
        if store.reads.load(Ordering::SeqCst) == 4
            && replay_probes.fetch_add(1, Ordering::SeqCst) >= 2
        {
            Err(RefusalCode::CancellationInProgress)
        } else {
            Ok(())
        }
    };
    let results = ready(recover_requests_async(
        &store,
        &(),
        &store.head,
        store.scope,
        &keys(&attempts),
        &checkpoint,
    ))
    .unwrap();
    assert!(results[0].terminal().is_some());
    assert_eq!(replay_probes.load(Ordering::SeqCst), 2);
    assert_eq!(checkpoint(), Err(RefusalCode::CancellationInProgress));
}
