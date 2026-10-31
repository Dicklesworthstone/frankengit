//! General outcome resolution must reconcile a hint with a sufficiently fresh
//! authoritative head. These interleavings perform real atomic publications in
//! the reference store; they do not manufacture terminal results for the race.

#[path = "outcome_resolution_races/cumulative.rs"]
mod cumulative;
#[path = "outcome_resolution_races/plural.rs"]
mod plural;

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore,
    AuthorityVersionToken, CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead,
    HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore, OutcomeFailure,
    OutcomeLookup, PublicationOutcome, PutOutcome, StoreInstanceId, TerminalOutcome,
    authority_head_identity, body_key_for_id, collect_cumulative_outcomes, decision_batch_identity,
    initialize_repository, outcome_index_root, outcome_key, publish_decisions, resolve_outcome,
    resolve_outcome_async,
};
use fgit_codec::{
    DecodeLimits, RepositoryAuthorityHeadBody, RepositoryDecision, RepositoryDecisionBatchBody,
    wire::decode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, DecisionSequence, HeadGeneration, PolicyEpoch,
    RefusalCode, RefusalRecordId, RegistryEpoch, RepositoryId, TenantId, TxId,
    hash::{Digest, DigestBytes},
};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

const TENANT: TenantId = TenantId::from_bytes([0x41; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x42; 16]);

fn digest(byte: u8) -> Digest {
    Digest::new(
        IdentityDomain::RefTransaction.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).unwrap(),
    )
}

fn transaction() -> TxId {
    let digest = digest(0x43);
    TxId::from_digest(digest.algorithm(), CANONICAL_CODEC_VERSION, *digest.bytes())
}

fn terminal(code: RefusalCode) -> TerminalOutcome {
    let digest = digest(0x44);
    TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(1).unwrap(),
        outcome: DecisionOutcome::Refused {
            code,
            refusal_record_id: RefusalRecordId::from_digest(
                digest.algorithm(),
                CANONICAL_CODEC_VERSION,
                *digest.bytes(),
            ),
        },
    }
}

#[derive(Clone, Copy)]
enum HintTiming {
    BeforeRead,
    AfterRead,
}

struct ObservedStore {
    inner: MemoryAuthorityStore,
    head: HeadKey,
    hint: ImmutableKey,
    publish_on_hint: Mutex<Option<HintTiming>>,
    overrides: Mutex<BTreeMap<ImmutableKey, ImmutableRead>>,
    head_reads: AtomicUsize,
    hint_reads: AtomicUsize,
    writes: AtomicUsize,
}

impl ObservedStore {
    fn new() -> Self {
        let inner = MemoryAuthorityStore::new(StoreInstanceId::from_raw(83));
        let head = HeadKey::new(b"outcome-resolution-races/head".to_vec()).unwrap();
        let root = digest(0);
        let genesis = RepositoryAuthorityHeadBody {
            repository_id: REPOSITORY,
            generation: HeadGeneration::FIRST,
            predecessor_head_id: None,
            decision_tail_id: None,
            latest_decision_sequence: None,
            latest_committed_rcr_id: None,
            latest_repository_sequence: None,
            ref_root: root,
            forge_position_root: root,
            outcome_index_root: outcome_index_root(&[]).unwrap(),
            retention_root: root,
            outbox_root: root,
            configuration_root: root,
            policy_epoch: PolicyEpoch::FIRST,
            format_registry_epoch: RegistryEpoch::FIRST,
            last_checkpoint_id: None,
        };
        initialize_repository(&inner, &head, &genesis).unwrap();
        Self {
            inner,
            head,
            hint: outcome_key(TENANT, REPOSITORY, transaction()).unwrap(),
            publish_on_hint: Mutex::new(None),
            overrides: Mutex::new(BTreeMap::new()),
            head_reads: AtomicUsize::new(0),
            hint_reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        }
    }

    fn override_read(&self, key: ImmutableKey, value: ImmutableRead) {
        self.overrides.lock().unwrap().insert(key, value);
    }

    fn assert_read_only_resolution(&self) {
        assert_eq!(self.head_reads.load(Ordering::SeqCst), 1);
        assert_eq!(self.hint_reads.load(Ordering::SeqCst), 1);
        assert_eq!(self.writes.load(Ordering::SeqCst), 0);
    }
}

impl AuthorityStore for ObservedStore {
    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }

    fn put_if_absent(
        &self,
        key: &ImmutableKey,
        body: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.put_if_absent(key, body)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        if key == &self.hint {
            self.hint_reads.fetch_add(1, Ordering::SeqCst);
            let timing = self.publish_on_hint.lock().unwrap().take();
            match timing {
                Some(HintTiming::BeforeRead) => {
                    publish(self, RefusalCode::EvidenceInvalid);
                }
                Some(HintTiming::AfterRead) => {
                    let observed = self.inner.read_immutable(key)?;
                    publish(self, RefusalCode::EvidenceInvalid);
                    return Ok(observed);
                }
                None => {}
            }
        }
        let override_read = self.overrides.lock().unwrap().get(key).cloned();
        if let Some(value) = override_read {
            return Ok(value);
        }
        self.inner.read_immutable(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.initialize_head(key, generation, body)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.head_reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read_head(key)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .compare_exchange_head(key, expected, generation, body)
    }

    fn publish_head_with_outcomes(
        &self,
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

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.inner.authenticate_head_receipt(receipt)
    }
}

// Deterministic test-only async adapter. Both resolvers see the same reference
// store contract, including the actual atomic publisher used by the interleave.
// Defer each operation until first poll, just as an async function would.
impl AsyncAuthorityStore for ObservedStore {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        AuthorityStore::instance_id(self)
    }

    fn limits(&self) -> AuthorityLimits {
        AuthorityStore::limits(self)
    }

    fn put_if_absent(
        &self,
        (): &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| Poll::Ready(AuthorityStore::put_if_absent(self, key, body)))
    }

    fn read_immutable(
        &self,
        (): &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| Poll::Ready(AuthorityStore::read_immutable(self, key)))
    }

    fn initialize_head(
        &self,
        (): &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| {
            Poll::Ready(AuthorityStore::initialize_head(self, key, generation, body))
        })
    }

    fn read_head(
        &self,
        (): &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| Poll::Ready(AuthorityStore::read_head(self, key)))
    }

    fn compare_exchange_head(
        &self,
        (): &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| {
            Poll::Ready(AuthorityStore::compare_exchange_head(
                self, key, expected, generation, body,
            ))
        })
    }

    fn publish_head_with_outcomes(
        &self,
        (): &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| {
            Poll::Ready(AuthorityStore::publish_head_with_outcomes(
                self, key, expected, generation, body, outcomes, witness,
            ))
        })
    }

    fn authenticate_head_receipt(
        &self,
        (): &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| {
            Poll::Ready(AuthorityStore::authenticate_head_receipt(self, receipt))
        })
    }
}

fn publish(store: &ObservedStore, code: RefusalCode) -> RepositoryDecisionBatchBody {
    let HeadRead::Present(receipt) = store.inner.read_head(&store.head).unwrap() else {
        panic!("initialized repository");
    };
    let predecessor: RepositoryAuthorityHeadBody =
        decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
    let outcome = terminal(code);
    let root = collect_cumulative_outcomes(&store.inner, &store.head)
        .unwrap()
        .fold_against(receipt.token(), &[(transaction(), outcome)])
        .unwrap();
    let batch = RepositoryDecisionBatchBody {
        repository_id: REPOSITORY,
        predecessor_head_id: authority_head_identity(&predecessor).unwrap(),
        predecessor_head_generation: predecessor.generation,
        first_decision_sequence: outcome.decision_sequence,
        decisions: vec![RepositoryDecision {
            tx_id: transaction(),
            decision_sequence: outcome.decision_sequence,
            outcome: outcome.outcome,
        }],
        committed_rcrs: Vec::new(),
        resulting_ref_root: predecessor.ref_root,
        resulting_forge_position_root: predecessor.forge_position_root,
        resulting_outcome_index_root: root,
        resulting_retention_root: predecessor.retention_root,
        resulting_outbox_root: predecessor.outbox_root,
        resulting_policy_epoch: predecessor.policy_epoch,
        batch_evidence_root: digest(0x45),
        compaction_generation_link: None,
    };
    let successor = RepositoryAuthorityHeadBody {
        generation: predecessor.generation.next().unwrap(),
        predecessor_head_id: Some(batch.predecessor_head_id),
        decision_tail_id: Some(decision_batch_identity(&batch).unwrap()),
        latest_decision_sequence: Some(outcome.decision_sequence),
        outcome_index_root: root,
        ..predecessor
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
    batch
}

#[derive(Clone, Copy)]
enum Surface {
    Blocking,
    Async,
}

const SURFACES: [Surface; 2] = [Surface::Blocking, Surface::Async];

impl Surface {
    fn resolve(self, store: &ObservedStore) -> Result<OutcomeLookup, OutcomeFailure> {
        match self {
            Self::Blocking => {
                resolve_outcome(store, &store.head, TENANT, REPOSITORY, transaction())
            }
            Self::Async => ready(resolve_outcome_async(
                store,
                &(),
                &store.head,
                TENANT,
                REPOSITORY,
                transaction(),
            )),
        }
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference reads do not suspend"),
    }
}

#[test]
fn adapter_defers_every_store_operation_until_first_poll() {
    use fgit_authority::{DuplicateScan, FaultableAuthorityStore, scan_for_existing_decisions};

    let store = ObservedStore::new();
    let HeadRead::Present(receipt) = store.inner.read_head(&store.head).unwrap() else {
        panic!("fixture head exists");
    };
    let DuplicateScan::Absent(witness) =
        scan_for_existing_decisions(&store.inner, &store.head, &[transaction()]).unwrap()
    else {
        panic!("fixture transaction is undecided");
    };
    let key = ImmutableKey::new(b"first-poll/body".to_vec()).unwrap();
    let other_head = HeadKey::new(b"first-poll/head".to_vec()).unwrap();
    let mut successor: RepositoryAuthorityHeadBody =
        decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
    successor.predecessor_head_id = Some(authority_head_identity(&successor).unwrap());
    successor.generation = successor.generation.next().unwrap();
    let successor_body = fgit_codec::encode_body(&successor).unwrap();

    // A ready(sync_call()) rewrite would perform reads or writes on construction.
    // Check unpolled drop as well as the first poll, using actual store effects.
    macro_rules! on_first_poll {
        ($operation:expr) => {{
            let before = store.inner.effect_log();
            {
                let _unpolled = $operation;
                assert_eq!(store.inner.effect_log(), before);
            }
            assert_eq!(store.inner.effect_log(), before);
            let future = $operation;
            assert_eq!(store.inner.effect_log(), before);
            let result = ready(future).unwrap();
            assert_eq!(store.inner.effect_log().len(), before.len() + 1);
            result
        }};
    }

    assert_eq!(
        on_first_poll!(AsyncAuthorityStore::put_if_absent(
            &store,
            &(),
            &key,
            b"body"
        )),
        PutOutcome::Created,
    );
    assert_eq!(
        on_first_poll!(AsyncAuthorityStore::read_immutable(&store, &(), &key)),
        ImmutableRead::Present(b"body".to_vec()),
    );
    let HeadInit::Created(other_receipt) = on_first_poll!(AsyncAuthorityStore::initialize_head(
        &store,
        &(),
        &other_head,
        receipt.generation(),
        receipt.body(),
    )) else {
        panic!("first poll initializes the other head");
    };
    assert_eq!(
        on_first_poll!(AsyncAuthorityStore::read_head(&store, &(), &store.head)),
        HeadRead::Present(receipt.clone()),
    );
    on_first_poll!(AsyncAuthorityStore::authenticate_head_receipt(
        &store,
        &(),
        &receipt
    ));
    assert!(matches!(
        on_first_poll!(AsyncAuthorityStore::compare_exchange_head(
            &store,
            &(),
            &other_head,
            other_receipt.token(),
            successor.generation,
            &successor_body,
        )),
        CasOutcome::Committed(_),
    ));
    assert!(matches!(
        on_first_poll!(AsyncAuthorityStore::publish_head_with_outcomes(
            &store,
            &(),
            &store.head,
            receipt.token(),
            successor.generation,
            &successor_body,
            &[],
            &witness,
        )),
        CasOutcome::Committed(_),
    ));
}

#[test]
fn publication_at_either_side_of_hint_read_resolves_from_the_new_head() {
    for surface in SURFACES {
        for timing in [HintTiming::BeforeRead, HintTiming::AfterRead] {
            let store = ObservedStore::new();
            *store.publish_on_hint.lock().unwrap() = Some(timing);
            assert_eq!(
                surface.resolve(&store).unwrap(),
                OutcomeLookup::Decided(terminal(RefusalCode::EvidenceInvalid)),
            );
            assert!(store.publish_on_hint.lock().unwrap().is_none());
            let HeadRead::Present(head) = store.inner.read_head(&store.head).unwrap() else {
                panic!("publication keeps the head present");
            };
            assert_eq!(head.generation(), HeadGeneration::FIRST.next().unwrap());
            store.assert_read_only_resolution();
        }
    }
}

#[test]
fn a_matching_or_missing_hint_both_resolve_the_published_decision() {
    for surface in SURFACES {
        for missing in [false, true] {
            let store = ObservedStore::new();
            publish(&store, RefusalCode::EvidenceInvalid);
            if missing {
                store.override_read(store.hint.clone(), ImmutableRead::Absent);
            }
            assert_eq!(
                surface.resolve(&store).unwrap(),
                OutcomeLookup::Decided(terminal(RefusalCode::EvidenceInvalid)),
            );
            store.assert_read_only_resolution();
        }
    }
}

#[test]
fn an_absent_hint_and_no_terminal_decision_remain_undecided() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        assert_eq!(surface.resolve(&store).unwrap(), OutcomeLookup::Undecided);
        store.assert_read_only_resolution();
    }
}

#[test]
fn stable_phantom_and_conflicting_hints_still_fail_closed() {
    let donor = ObservedStore::new();
    publish(&donor, RefusalCode::QuotaExceeded);
    let wrong_hint = donor.inner.read_immutable(&donor.hint).unwrap();
    assert!(matches!(&wrong_hint, ImmutableRead::Present(_)));
    for surface in SURFACES {
        for has_decision in [false, true] {
            let store = ObservedStore::new();
            if has_decision {
                publish(&store, RefusalCode::EvidenceInvalid);
            }
            store.override_read(store.hint.clone(), wrong_hint.clone());
            let indexed = terminal(RefusalCode::QuotaExceeded);
            let replayed = if has_decision {
                terminal(RefusalCode::EvidenceInvalid)
            } else {
                indexed
            };
            assert_eq!(
                surface.resolve(&store),
                Err(OutcomeFailure::AcceleratorConflict {
                    indexed: Box::new(indexed),
                    replayed: Box::new(replayed),
                }),
            );
            store.assert_read_only_resolution();
        }
    }
}

#[test]
fn even_a_matching_hint_cannot_replace_a_missing_authoritative_batch() {
    for surface in SURFACES {
        let store = ObservedStore::new();
        let batch = publish(&store, RefusalCode::EvidenceInvalid);
        let key = body_key_for_id(
            &decision_batch_identity(&batch)
                .unwrap()
                .into_internal_object_id(),
        )
        .unwrap();
        store.override_read(key, ImmutableRead::Absent);
        assert_eq!(
            surface.resolve(&store),
            Err(OutcomeFailure::StreamBodyMissing {
                link: "decision batch",
            }),
        );
        store.assert_read_only_resolution();
    }
}
