#![forbid(unsafe_code)]
//! Contended batch publication must resolve its children with one authoritative
//! replay. A real rival is published inside the candidate's CAS call; only the
//! subsequent loss-classification reads are counted.

use fgit_authority::{
    AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore,
    AuthorityVersionToken, CasOutcome, CumulativeOutcomes, DuplicateAbsenceWitness, HeadInit,
    HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead, MemoryAuthorityStore,
    OutcomeFailure, OutcomeLookup, PutOutcome, StoreInstanceId, TerminalOutcome,
    authority_head_identity, body_key_for_id, collect_cumulative_outcomes, decision_batch_identity,
    indexed_outcome, initialize_repository, outcome_index_root, outcome_key,
};
use fgit_chronicle::{
    LostCandidate, PublicationBasis, PublicationPlan, PublicationVerdict, ResultingRoots,
    VerifiedPublication, publish, publish_async, publish_with_cumulative,
    publish_with_cumulative_async,
};
use fgit_codec::{CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody, decode_body};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RefusalCode,
    RefusalRecordId, RegistryEpoch, RepositoryId, TenantId, TxId,
};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

const TENANT: TenantId = TenantId::from_bytes([0x51; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x52; 16]);
const HISTORY_BATCHES: u8 = 8;

fn digest(tag: u8) -> Digest {
    Digest::new(
        IdentityDomain::RefTransaction.algorithm().id(),
        DigestBytes::try_new(&[tag; 32]).unwrap(),
    )
}

fn tx(tag: u8) -> TxId {
    let digest = digest(tag);
    TxId::from_digest(digest.algorithm(), CANONICAL_CODEC_VERSION, *digest.bytes())
}

fn head(store: &MemoryAuthorityStore, key: &HeadKey) -> HeadReadReceipt {
    let HeadRead::Present(receipt) = store.read_head(key).unwrap() else {
        panic!("the repository is initialized");
    };
    receipt
}

fn candidate(
    store: &MemoryAuthorityStore,
    key: &HeadKey,
    tags: &[u8],
    code: RefusalCode,
) -> VerifiedPublication {
    let receipt = head(store, key);
    let body: RepositoryAuthorityHeadBody =
        decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
    let basis = PublicationBasis::new(authority_head_identity(&body).unwrap(), body);
    let roots = ResultingRoots::carried_forward(&basis);
    let mut plan = PublicationPlan::open(basis).unwrap();
    for tag in tags {
        let digest = digest(*tag);
        plan.refuse(
            tx(*tag),
            code,
            RefusalRecordId::from_digest(
                digest.algorithm(),
                CANONICAL_CODEC_VERSION,
                *digest.bytes(),
            ),
        );
    }
    let cumulative = collect_cumulative_outcomes(store, key).unwrap();
    plan.seal(&CryptoBodyIdentity, roots, &cumulative, receipt.token())
        .unwrap()
}

fn batch_key(publication: &VerifiedPublication) -> ImmutableKey {
    body_key_for_id(
        decision_batch_identity(publication.batch())
            .unwrap()
            .as_internal_object_id(),
    )
    .unwrap()
}

struct ObservedStore {
    inner: MemoryAuthorityStore,
    head: HeadKey,
    rival: Mutex<Option<VerifiedPublication>>,
    classifying: AtomicBool,
    candidate_cas: AtomicUsize,
    classification_heads: AtomicUsize,
    classification_writes: AtomicUsize,
    classification_reads: Mutex<BTreeMap<ImmutableKey, usize>>,
    overrides: Mutex<BTreeMap<ImmutableKey, ImmutableRead>>,
}

impl ObservedStore {
    fn override_read(&self, key: ImmutableKey, value: ImmutableRead) {
        self.overrides.lock().unwrap().insert(key, value);
    }

    fn read_count(&self, key: &ImmutableKey) -> usize {
        self.classification_reads
            .lock()
            .unwrap()
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    fn note_write(&self) {
        if self.classifying.load(Ordering::SeqCst) {
            self.classification_writes.fetch_add(1, Ordering::SeqCst);
        }
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
        self.note_write();
        self.inner.put_if_absent(key, body)
    }

    fn read_immutable(&self, key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        if self.classifying.load(Ordering::SeqCst) {
            *self
                .classification_reads
                .lock()
                .unwrap()
                .entry(key.clone())
                .or_default() += 1;
            let override_value = self.overrides.lock().unwrap().get(key).cloned();
            if let Some(value) = override_value {
                return Ok(value);
            }
        }
        self.inner.read_immutable(key)
    }

    fn initialize_head(
        &self,
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        self.note_write();
        self.inner.initialize_head(key, generation, body)
    }

    fn read_head(&self, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        if self.classifying.load(Ordering::SeqCst) {
            self.classification_heads.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.read_head(key)
    }

    fn compare_exchange_head(
        &self,
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        self.note_write();
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
        self.note_write();
        self.candidate_cas.fetch_add(1, Ordering::SeqCst);
        let rival = self.rival.lock().unwrap().take();
        if let Some(rival) = rival {
            assert_eq!(rival.expected_head_token(), expected);
            assert!(matches!(
                publish(&self.inner, &self.head, expected, &rival, TENANT).unwrap(),
                PublicationVerdict::Published(_),
            ));
        }
        let result = self
            .inner
            .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness)?;
        assert_eq!(result, CasOutcome::PredecessorMismatch);
        self.classifying.store(true, Ordering::SeqCst);
        Ok(result)
    }

    fn authenticate_head_receipt(
        &self,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.inner.authenticate_head_receipt(receipt)
    }
}

// Poll-driven test-only adapter: the asynchronous signature runs the same
// reference effect and deterministic interleave only when first polled.
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
    ) -> impl core::future::Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| Poll::Ready(AuthorityStore::put_if_absent(self, key, body)))
    }

    fn read_immutable(
        &self,
        (): &(),
        key: &ImmutableKey,
    ) -> impl core::future::Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| Poll::Ready(AuthorityStore::read_immutable(self, key)))
    }

    fn initialize_head(
        &self,
        (): &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl core::future::Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| {
            Poll::Ready(AuthorityStore::initialize_head(self, key, generation, body))
        })
    }

    fn read_head(
        &self,
        (): &(),
        key: &HeadKey,
    ) -> impl core::future::Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::poll_fn(move |_| Poll::Ready(AuthorityStore::read_head(self, key)))
    }

    fn compare_exchange_head(
        &self,
        (): &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl core::future::Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
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
    ) -> impl core::future::Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
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
    ) -> impl core::future::Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send
    {
        std::future::poll_fn(move |_| {
            Poll::Ready(AuthorityStore::authenticate_head_receipt(self, receipt))
        })
    }
}

struct Scenario {
    store: ObservedStore,
    candidate: VerifiedPublication,
    winner: VerifiedPublication,
    cumulative: CumulativeOutcomes,
    old_batches: Vec<ImmutableKey>,
}

impl Scenario {
    fn new(winner_tags: &[u8]) -> Self {
        let inner = MemoryAuthorityStore::new(StoreInstanceId::from_raw(97));
        let head_key = HeadKey::new(b"chronicle/batch-loss-recovery/head".to_vec()).unwrap();
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
        initialize_repository(&inner, &head_key, &genesis).unwrap();
        let mut old_batches = Vec::new();
        for tag in 1..=HISTORY_BATCHES {
            let publication = candidate(&inner, &head_key, &[tag], RefusalCode::QuotaExceeded);
            old_batches.push(batch_key(&publication));
            assert!(matches!(
                publish(
                    &inner,
                    &head_key,
                    publication.expected_head_token(),
                    &publication,
                    TENANT,
                )
                .unwrap(),
                PublicationVerdict::Published(_),
            ));
        }
        // Candidate order deliberately differs from identity and winner order.
        let candidate_tags: Vec<_> = (65..=128).rev().collect();
        let candidate = candidate(
            &inner,
            &head_key,
            &candidate_tags,
            RefusalCode::QuotaExceeded,
        );
        let winner = self::candidate(&inner, &head_key, winner_tags, RefusalCode::EvidenceInvalid);
        let cumulative = collect_cumulative_outcomes(&inner, &head_key).unwrap();
        Self {
            store: ObservedStore {
                inner,
                head: head_key,
                rival: Mutex::new(Some(winner.clone())),
                classifying: AtomicBool::new(false),
                candidate_cas: AtomicUsize::new(0),
                classification_heads: AtomicUsize::new(0),
                classification_writes: AtomicUsize::new(0),
                classification_reads: Mutex::new(BTreeMap::new()),
                overrides: Mutex::new(BTreeMap::new()),
            },
            candidate,
            winner,
            cumulative,
            old_batches,
        }
    }

    fn expected_decided(&self) -> Vec<(TxId, TerminalOutcome)> {
        self.candidate
            .batch()
            .decisions
            .iter()
            .filter_map(|candidate| {
                self.winner
                    .batch()
                    .decisions
                    .iter()
                    .find(|winner| winner.tx_id == candidate.tx_id)
                    .map(|winner| {
                        (
                            winner.tx_id,
                            TerminalOutcome {
                                decision_sequence: winner.decision_sequence,
                                outcome: winner.outcome,
                            },
                        )
                    })
            })
            .collect()
    }

    fn hide_candidate_hints(&self) {
        for decision in &self.candidate.batch().decisions {
            self.store.override_read(
                outcome_key(TENANT, REPOSITORY, decision.tx_id).unwrap(),
                ImmutableRead::Absent,
            );
        }
    }

    fn assert_one_classification(&self, historical_reads: usize) {
        assert_eq!(self.store.candidate_cas.load(Ordering::SeqCst), 1);
        assert!(self.store.rival.lock().unwrap().is_none());
        assert_eq!(self.store.classification_heads.load(Ordering::SeqCst), 1);
        assert_eq!(self.store.classification_writes.load(Ordering::SeqCst), 0);
        assert_eq!(self.store.read_count(&batch_key(&self.winner)), 1);
        for key in &self.old_batches {
            assert_eq!(self.store.read_count(key), historical_reads);
        }
        let actual: RepositoryAuthorityHeadBody = decode_body(
            head(&self.store.inner, &self.store.head).body(),
            DecodeLimits::DEFAULT,
        )
        .unwrap();
        assert_eq!(&actual, self.winner.head());
    }
}

#[derive(Clone, Copy)]
enum Surface {
    Blocking,
    Async,
    BlockingCumulative,
    AsyncCumulative,
}

const SURFACES: [Surface; 4] = [
    Surface::Blocking,
    Surface::Async,
    Surface::BlockingCumulative,
    Surface::AsyncCumulative,
];

impl Surface {
    fn publish(self, scenario: &Scenario) -> Result<PublicationVerdict, OutcomeFailure> {
        let store = &scenario.store;
        let expected = scenario.candidate.expected_head_token();
        match self {
            Self::Blocking => publish(store, &store.head, expected, &scenario.candidate, TENANT),
            Self::Async => ready(publish_async(
                store,
                &(),
                &store.head,
                expected,
                &scenario.candidate,
                TENANT,
            )),
            Self::BlockingCumulative => publish_with_cumulative(
                store,
                &store.head,
                expected,
                &scenario.candidate,
                TENANT,
                &scenario.cumulative,
            ),
            Self::AsyncCumulative => ready(publish_with_cumulative_async(
                store,
                &(),
                &store.head,
                expected,
                &scenario.candidate,
                TENANT,
                &scenario.cumulative,
            )),
        }
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference operations do not suspend"),
    }
}

#[test]
fn an_unpolled_async_observer_does_not_read_or_publish_reference_state() {
    let scenario = Scenario::new(&[200]);
    let store = &scenario.store;
    let expected = head(&store.inner, &store.head);
    store.classifying.store(true, Ordering::SeqCst);

    let unpolled = AsyncAuthorityStore::read_head(store, &(), &store.head);
    assert_eq!(store.classification_heads.load(Ordering::SeqCst), 0);
    drop(unpolled);
    assert_eq!(store.classification_heads.load(Ordering::SeqCst), 0);

    let observed = ready(AsyncAuthorityStore::read_head(store, &(), &store.head)).unwrap();
    let HeadRead::Present(observed) = observed else {
        panic!("the initialized reference head remains present");
    };
    assert_eq!(observed.body(), expected.body());
    assert_eq!(observed.token(), expected.token());
    assert_eq!(store.classification_heads.load(Ordering::SeqCst), 1);
    assert_eq!(store.classification_writes.load(Ordering::SeqCst), 0);
    assert_eq!(store.candidate_cas.load(Ordering::SeqCst), 0);
}

#[test]
fn a_partial_winner_reports_exact_decisions_in_candidate_order_with_one_replay() {
    for surface in SURFACES {
        let scenario = Scenario::new(&[65, 100, 128]);
        scenario.hide_candidate_hints();
        let expected = scenario.expected_decided();
        assert_eq!(expected.len(), 3);
        assert_eq!(expected[0].0, tx(128));
        assert_eq!(expected[2].0, tx(65));
        assert_eq!(
            surface.publish(&scenario).unwrap(),
            PublicationVerdict::Lost(LostCandidate::Superseded { decided: expected }),
        );
        scenario.assert_one_classification(1);
        assert_eq!(
            indexed_outcome(&scenario.store.inner, TENANT, REPOSITORY, tx(99)).unwrap(),
            OutcomeLookup::Undecided,
        );
    }
}

#[test]
fn a_foreign_winner_leaves_all_64_children_replannable_after_one_history_walk() {
    for surface in SURFACES {
        let scenario = Scenario::new(&[200]);
        assert_eq!(
            surface.publish(&scenario).unwrap(),
            PublicationVerdict::Lost(LostCandidate::Replannable),
        );
        scenario.assert_one_classification(1);
        for decision in &scenario.candidate.batch().decisions {
            assert_eq!(
                indexed_outcome(&scenario.store.inner, TENANT, REPOSITORY, decision.tx_id).unwrap(),
                OutcomeLookup::Undecided,
            );
        }
    }
}

#[test]
fn all_recent_children_resolve_without_reading_an_unneeded_broken_old_prefix() {
    for surface in SURFACES {
        let winner_tags: Vec<_> = (65..=128).collect();
        let scenario = Scenario::new(&winner_tags);
        // The interleaving publisher still sees complete history. This missing
        // old body is exposed only after the candidate CAS has actually lost.
        scenario
            .store
            .override_read(scenario.old_batches[0].clone(), ImmutableRead::Absent);
        let expected = scenario.expected_decided();
        assert_eq!(expected.len(), 64);
        assert_eq!(
            surface.publish(&scenario).unwrap(),
            PublicationVerdict::Lost(LostCandidate::Superseded { decided: expected }),
        );
        scenario.assert_one_classification(0);
    }
}

#[test]
fn a_stable_phantom_hint_cannot_turn_a_lost_candidate_into_a_terminal_answer() {
    for surface in SURFACES {
        let scenario = Scenario::new(&[200]);
        let old_hint_key = outcome_key(TENANT, REPOSITORY, tx(1)).unwrap();
        let old_hint = scenario.store.inner.read_immutable(&old_hint_key).unwrap();
        assert!(matches!(&old_hint, ImmutableRead::Present(_)));
        scenario
            .store
            .override_read(outcome_key(TENANT, REPOSITORY, tx(128)).unwrap(), old_hint);
        assert!(matches!(
            surface.publish(&scenario),
            Err(OutcomeFailure::AcceleratorConflict { .. }),
        ));
        scenario.assert_one_classification(1);
    }
}
