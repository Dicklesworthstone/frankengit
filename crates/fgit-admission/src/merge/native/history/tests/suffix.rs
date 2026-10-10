//! Production history readers over a deterministic immutable-body store.
//! The fixture constructs and verifies real cryptographic batch/head chains;
//! it is not a semantic admission, outcome-index, or filesystem durability test.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PutOutcome, StoreInstanceId, authority_head_identity, body_key_for_id,
};
use fgit_chronicle::{batch_evidence_root, batch_identity, repository_commit_identity};
use fgit_codec::{
    Decoder, Encoder, OutboxDeliveryIdentityInput, RepositoryDecision, RepositoryDecisionBatchBody,
    derive_outbox_delivery_key, encode_body,
};
use fgit_forge::{
    AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload,
    PullRequestNumber,
};
use fgit_reference::{effect::NetEffects, intent::OutboxDeliveryKey};
use fgit_resource::settlement::{DeliveryVerdict, Observation, ProbeVerdict};
use fgit_resource::{LifecycleEvent, ReconcilePolicy};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionOutcome, DigestBytes, HeadGeneration, PrincipalSnapshotId,
    RefusalRecordId, RepositoryCommitId, TxId,
};

use super::super::*;

struct Reads {
    memory: MemoryAuthorityStore,
    keys: Mutex<Vec<ImmutableKey>>,
    fault: Mutex<Option<(ImmutableKey, bool)>>,
}

impl Reads {
    fn new() -> Self {
        Self {
            memory: MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x0b07)),
            keys: Mutex::new(Vec::new()),
            fault: Mutex::new(None),
        }
    }
    fn count(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
    fn reset(&self) {
        self.keys.lock().unwrap().clear();
    }
    fn fault(&self, key: Option<ImmutableKey>, corrupt: bool) {
        *self.fault.lock().unwrap() = key.map(|key| (key, corrupt));
    }
    fn was_read(&self, key: &ImmutableKey) -> bool {
        self.keys.lock().unwrap().contains(key)
    }
}

impl AsyncAuthorityStore for Reads {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.memory.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.memory.limits()
    }
    fn put_if_absent(
        &self,
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.memory.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        self.keys.lock().unwrap().push(key.clone());
        let fault = self.fault.lock().unwrap().clone();
        let result = if let Some((_, corrupt)) = fault.filter(|(target, _)| target == key) {
            Ok(if corrupt {
                ImmutableRead::Present(vec![0])
            } else {
                ImmutableRead::Absent
            })
        } else {
            self.memory.read_immutable(key)
        };
        std::future::ready(result)
    }
    fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.memory.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        _: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.memory.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::ready(
            self.memory
                .compare_exchange_head(key, expected, generation, body),
        )
    }
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.memory.authenticate_head_receipt(receipt))
    }
}

fn run<F: Future>(future: F) -> F::Output {
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("model authority operations must not suspend"),
    }
}

fn tx(number: u64) -> TxId {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&number.to_be_bytes());
    TxId::from_digest(
        fgit_codec::harness::digest_of(1).algorithm(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&bytes).unwrap(),
    )
}

fn ordinary(entry: Option<&CanonicalOutboxStateEntry>) -> crate::evidence::OutboxEffectBatch {
    let mut effects = NetEffects::default();
    if let Some(entry) = entry {
        effects.outbox = BTreeMap::from([(
            OutboxDeliveryKey::new(entry.delivery_key()),
            entry.payload_root(),
        )]);
    }
    let bytes = fgit_txn::canonical_outbox_effect_bytes(&effects).unwrap();
    let mut payload = Encoder::new();
    payload
        .write_bytes("outbox_effect_batch.effects", &bytes)
        .unwrap();
    let bytes = payload.into_bytes();
    crate::evidence::OutboxEffectBatch::read_payload(&mut Decoder::new(
        &bytes,
        DecodeLimits::DEFAULT,
    ))
    .unwrap()
}

struct Fixture {
    store: Reads,
    basis: PublicationBasis,
    heads: Vec<RepositoryAuthorityHeadBody>,
    entry: Option<CanonicalOutboxStateEntry>,
    effect: Option<CanonicalOutboxEffectState>,
    creation: Option<usize>,
    next_tx: u64,
}

impl Fixture {
    fn new() -> Self {
        let store = Reads::new();
        let mut genesis = fgit_codec::harness::genesis_head();
        let outbox = CanonicalOutboxState::try_new(genesis.repository_id, Vec::new()).unwrap();
        genesis.outbox_root = storage::root(&outbox).unwrap();
        let basis = PublicationBasis::new(authority_head_identity(&genesis).unwrap(), genesis);
        let fixture = Self {
            store,
            basis,
            heads: Vec::new(),
            entry: None,
            effect: None,
            creation: None,
            next_tx: 100,
        };
        fixture.stage(delivery::OUTBOX_NAMESPACE, &outbox);
        fixture.stage_head(fixture.basis.body());
        fixture
    }
    fn stage<B: CanonicalBody>(&self, namespace: &[u8], body: &B) -> Digest {
        let root = storage::root(body).unwrap();
        let key = storage::body_key(namespace, self.basis.body().repository_id, root).unwrap();
        assert!(matches!(
            self.store
                .memory
                .put_if_absent(&key, &encode_body(body).unwrap())
                .unwrap(),
            PutOutcome::Created | PutOutcome::IdenticalRetry
        ));
        root
    }
    fn stage_head(&self, head: &RepositoryAuthorityHeadBody) {
        let id = authority_head_identity(head).unwrap();
        self.store
            .memory
            .put_if_absent(
                &body_key_for_id(id.as_internal_object_id()).unwrap(),
                &encode_body(head).unwrap(),
            )
            .unwrap();
    }
    fn outbox(&self) -> CanonicalOutboxState {
        CanonicalOutboxState::try_new(
            self.basis.body().repository_id,
            self.entry.into_iter().collect(),
        )
        .unwrap()
    }
    fn record(&mut self, payload: Digest, evidence: Digest) -> RepositoryCommitRecord {
        self.next_tx += 1;
        let mut record = fgit_codec::harness::commit_record();
        record.repository_id = self.basis.body().repository_id;
        record.tx_id = tx(self.next_tx);
        record.principal_snapshot_id = PrincipalSnapshotId::from_digest(
            record.tx_id.as_internal_object_id().algorithm(),
            CANONICAL_CODEC_VERSION,
            *record.tx_id.as_internal_object_id().digest(),
        );
        record.resulting_ref_root = self.basis.body().ref_root;
        record.resulting_forge_position_root = self.basis.body().forge_position_root;
        record.policy_epoch = self.basis.body().policy_epoch;
        record.forge_event_batch_root = payload;
        record.outbox_effect_root = evidence;
        record.invariant_evidence_root = evidence;
        record
    }
    fn append(&mut self, mut records: Vec<RepositoryCommitRecord>) {
        let mut sequence = self.basis.open_decision_sequence().unwrap();
        let mut repository_sequence = self.basis.open_repository_sequence().unwrap();
        let mut parent = self.basis.body().latest_committed_rcr_id;
        let mut decisions = Vec::new();
        if records.is_empty() {
            self.next_tx += 1;
            decisions.push(RepositoryDecision {
                tx_id: tx(self.next_tx),
                decision_sequence: sequence,
                outcome: DecisionOutcome::Refused {
                    code: RefusalCode::QuotaExceeded,
                    refusal_record_id: RefusalRecordId::from_digest(
                        tx(self.next_tx).as_internal_object_id().algorithm(),
                        CANONICAL_CODEC_VERSION,
                        *tx(self.next_tx).as_internal_object_id().digest(),
                    ),
                },
            });
        }
        for record in &mut records {
            record.parent_rcr_id = parent;
            record.repository_sequence = repository_sequence;
            let id = repository_commit_identity(&CryptoBodyIdentity, record).unwrap();
            decisions.push(RepositoryDecision {
                tx_id: record.tx_id,
                decision_sequence: sequence,
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: id,
                },
            });
            parent = Some(id);
            sequence = sequence.next().unwrap();
            repository_sequence = repository_sequence.next().unwrap();
        }
        let outbox_root = if records.is_empty() {
            self.basis.body().outbox_root
        } else {
            self.stage(delivery::OUTBOX_NAMESPACE, &self.outbox())
        };
        let mut batch = RepositoryDecisionBatchBody {
            repository_id: self.basis.body().repository_id,
            predecessor_head_id: self.basis.id(),
            predecessor_head_generation: self.basis.generation(),
            first_decision_sequence: self.basis.open_decision_sequence().unwrap(),
            decisions,
            committed_rcrs: records,
            resulting_ref_root: self.basis.body().ref_root,
            resulting_forge_position_root: self.basis.body().forge_position_root,
            resulting_outcome_index_root: self.basis.body().outcome_index_root,
            resulting_retention_root: self.basis.body().retention_root,
            resulting_outbox_root: outbox_root,
            resulting_policy_epoch: self.basis.body().policy_epoch,
            batch_evidence_root: fgit_codec::harness::digest_of(1),
            compaction_generation_link: None,
        };
        batch.batch_evidence_root = batch_evidence_root(&batch).unwrap();
        let id = batch_identity(&CryptoBodyIdentity, &batch).unwrap();
        let mut head = self.basis.body().clone();
        head.generation = self.basis.successor_generation().unwrap();
        head.predecessor_head_id = Some(self.basis.id());
        head.decision_tail_id = Some(id);
        head.latest_decision_sequence = batch
            .decisions
            .last()
            .map(|decision| decision.decision_sequence);
        head.latest_committed_rcr_id = parent;
        if let Some(record) = batch.committed_rcrs.last() {
            head.latest_repository_sequence = Some(record.repository_sequence);
        }
        head.outbox_root = outbox_root;
        verify_pair(&CryptoBodyIdentity, &self.basis, &batch, &head).unwrap();
        self.store
            .memory
            .put_if_absent(
                &body_key_for_id(id.as_internal_object_id()).unwrap(),
                &encode_body(&batch).unwrap(),
            )
            .unwrap();
        self.stage_head(&head);
        self.heads.push(head.clone());
        self.basis = PublicationBasis::new(authority_head_identity(&head).unwrap(), head);
    }
    fn create(&mut self) {
        let record = self.creation_record(None, None);
        self.creation = Some(self.heads.len());
        self.append(vec![record]);
    }
    fn unrelated_commit(&mut self) {
        let payload = self.stage(
            storage::EVENT_NAMESPACE,
            &ForgeEventBatch { events: Vec::new() },
        );
        let evidence = self.stage(OUTBOX_EFFECT_NAMESPACE, &ordinary(None));
        let record = self.record(payload, evidence);
        self.append(vec![record]);
    }
    fn creation_record(
        &mut self,
        parent_override: Option<Option<RepositoryCommitId>>,
        payload_override: Option<Digest>,
    ) -> RepositoryCommitRecord {
        let events = ForgeEventBatch::of_one(ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
            version: AggregateVersion::FIRST,
            payload: ForgeEventPayload::PullRequestOpened {
                source_ref: b"refs/heads/topic".to_vec(),
                target_ref: b"refs/heads/main".to_vec(),
                source_tip: fgit_codec::harness::digest_of(3),
                target_tip: fgit_codec::harness::digest_of(4),
            },
        });
        let payload = self.stage(storage::EVENT_NAMESPACE, &events);
        let tx_id = tx(self.next_tx + 1);
        let predecessor = parent_override.unwrap_or(self.basis.body().latest_committed_rcr_id);
        let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
            self.basis.body().repository_id,
            AsciiSlug::from_static("forge-event"),
            AsciiSlug::from_static("forge-projection"),
            payload,
            tx_id,
            predecessor,
        ))
        .unwrap();
        let effect = CanonicalOutboxEffectState::committed(
            self.basis.body().repository_id,
            key,
            tx_id,
            payload,
        );
        self.entry = Some(CanonicalOutboxStateEntry::new(
            key,
            AsciiSlug::from_static("forge-event"),
            AsciiSlug::from_static("forge-projection"),
            payload,
            tx_id,
            predecessor,
            self.stage(delivery::EFFECT_NAMESPACE, &effect),
            None,
        ));
        self.effect = Some(effect);
        let root = self.stage(OUTBOX_EFFECT_NAMESPACE, &ordinary(self.entry.as_ref()));
        self.record(payload_override.unwrap_or(payload), root)
    }
    fn effect_record(&mut self, effect: &CanonicalOutboxEffectState) -> RepositoryCommitRecord {
        let root = self.stage(OUTBOX_EFFECT_NAMESPACE, effect);
        self.stage(storage::INVARIANT_NAMESPACE, effect);
        self.stage(delivery::EFFECT_NAMESPACE, effect);
        let entry = self.entry.unwrap();
        self.entry = Some(CanonicalOutboxStateEntry::new(
            entry.delivery_key(),
            entry.effect_class(),
            entry.destination(),
            entry.payload_root(),
            entry.tx_id(),
            entry.predecessor_rcr_id(),
            root,
            effect.predecessor_root(),
        ));
        self.effect = Some(effect.clone());
        self.record(fgit_codec::harness::digest_of(8), root)
    }
    fn defer(&mut self) -> CanonicalOutboxProgress {
        let deferred = self
            .effect
            .as_ref()
            .unwrap()
            .transition(LifecycleEvent::Defer, None)
            .unwrap();
        let record = self.effect_record(&deferred);
        self.append(vec![record]);
        CanonicalOutboxProgress::start(
            self.basis.body().repository_id,
            deferred.delivery_key(),
            self.entry.unwrap().destination(),
            deferred.payload_root(),
            deferred.root().unwrap(),
            ReconcilePolicy::new(core::num::NonZeroU32::new(4).unwrap()),
        )
        .unwrap()
    }
    fn progress_record(&mut self, progress: &CanonicalOutboxProgress) -> RepositoryCommitRecord {
        let root = self.stage(OUTBOX_EFFECT_NAMESPACE, progress);
        self.stage(storage::INVARIANT_NAMESPACE, progress);
        self.record(fgit_codec::harness::digest_of(9), root)
    }
    fn progress(&mut self, progress: &CanonicalOutboxProgress) {
        let record = self.progress_record(progress);
        self.append(vec![record]);
    }
    fn read(&self) -> Result<Option<CanonicalOutboxProgress>, AdmissionError> {
        run(latest_progress_for_entry(
            &self.store,
            &(),
            &self.basis,
            &self.entry.unwrap(),
            &|| false,
        ))
    }
    fn audit(&self) -> Result<Option<CanonicalOutboxProgress>, AdmissionError> {
        run(latest_progress(
            &self.store,
            &(),
            &self.basis,
            self.entry.unwrap().delivery_key(),
            &|| false,
        ))
    }
}

fn batch_key(head: &RepositoryAuthorityHeadBody) -> ImmutableKey {
    body_key_for_id(head.decision_tail_id.unwrap().as_internal_object_id()).unwrap()
}

#[test]
fn recent_obligation_survives_more_than_the_full_history_budget() {
    let mut fixture = Fixture::new();
    for _ in 0..MAX_HISTORY_BATCHES + 4 {
        fixture.append(Vec::new());
    }
    fixture.create();
    fixture.store.reset();
    assert_eq!(fixture.read().unwrap(), None);
    assert!(
        fixture.store.count() < 16,
        "creation lookup is independent of the older prefix"
    );
    assert!(!fixture.store.was_read(&batch_key(&fixture.heads[0])));
    assert!(matches!(
        fixture.audit(),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::ResourceBudgetExceeded
        ))
    ));
}

#[test]
fn selected_progress_matches_full_replay_and_deterministic_repetition() {
    let mut fixture = Fixture::new();
    for _ in 0..5 {
        fixture.append(Vec::new());
    }
    fixture.create();
    assert_eq!(fixture.read().unwrap(), fixture.audit().unwrap());
    let initial = fixture.defer();
    fixture.progress(&initial);
    let pending = initial
        .observe(Observation::Probe(ProbeVerdict::NotDelivered), Vec::new())
        .unwrap();
    let dispatched = pending.mark_dispatch().unwrap();
    for progress in [&pending, &dispatched] {
        fixture.progress(progress);
        let expected = fixture.audit().unwrap();
        assert_eq!(expected, Some(progress.clone()));
        for _ in 0..3 {
            assert_eq!(fixture.read().unwrap(), expected);
        }
    }
}

#[test]
fn old_corruption_is_outside_the_suffix_but_boundary_loss_fails_closed() {
    let mut fixture = Fixture::new();
    for _ in 0..3 {
        fixture.append(Vec::new());
    }
    fixture.create();
    let initial = fixture.defer();
    fixture.progress(&initial);
    for corrupt in [false, true] {
        fixture
            .store
            .fault(Some(batch_key(&fixture.heads[0])), corrupt);
        assert_eq!(fixture.read().unwrap(), Some(initial.clone()));
        assert!(fixture.audit().is_err());
        fixture.store.fault(None, false);
        assert_eq!(fixture.audit().unwrap(), Some(initial.clone()));
        for key in [
            batch_key(&fixture.heads[fixture.creation.unwrap()]),
            body_key_for_id(
                fixture.heads[fixture.creation.unwrap()]
                    .predecessor_head_id
                    .unwrap()
                    .as_internal_object_id(),
            )
            .unwrap(),
            storage::body_key(
                delivery::OUTBOX_NAMESPACE,
                fixture.basis.body().repository_id,
                fixture.heads[fixture.creation.unwrap()].outbox_root,
            )
            .unwrap(),
            storage::body_key(
                storage::EVENT_NAMESPACE,
                fixture.basis.body().repository_id,
                fixture.entry.unwrap().payload_root(),
            )
            .unwrap(),
        ] {
            fixture.store.fault(Some(key), corrupt);
            assert!(fixture.read().is_err());
            fixture.store.fault(None, false);
            assert_eq!(fixture.read().unwrap(), Some(initial.clone()));
        }
    }
}

#[test]
fn caller_entry_and_claimed_head_must_match_the_selected_bytes() {
    let mut fixture = Fixture::new();
    fixture.create();
    let entry = fixture.entry.unwrap();
    let different = CanonicalOutboxStateEntry::new(
        entry.delivery_key(),
        entry.effect_class(),
        AsciiSlug::from_static("another-destination"),
        entry.payload_root(),
        entry.tx_id(),
        entry.predecessor_rcr_id(),
        entry.effect_state_root(),
        entry.predecessor_effect_state_root(),
    );
    assert!(matches!(
        run(latest_progress_for_entry(
            &fixture.store,
            &(),
            &fixture.basis,
            &different,
            &|| false
        )),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::EvidenceStale
        ))
    ));
    fixture.store.reset();
    let mut altered = fixture.basis.body().clone();
    altered.configuration_root = fgit_codec::harness::digest_of(123);
    let wrong = PublicationBasis::new(fixture.basis.id(), altered);
    assert!(
        run(latest_progress_for_entry(
            &fixture.store,
            &(),
            &wrong,
            &entry,
            &|| false
        ))
        .is_err()
    );
    assert_eq!(fixture.store.count(), 0);
    assert_eq!(fixture.read().unwrap(), None);
}

#[test]
fn creation_requires_the_exact_transaction_parent_and_payload() {
    for defect in 0..3 {
        let mut fixture = Fixture::new();
        let parent = if defect == 0 {
            Some(Some(fgit_codec::harness::commit_id()))
        } else {
            None
        };
        let payload = if defect == 1 {
            Some(fgit_codec::harness::digest_of(97))
        } else {
            None
        };
        let mut creation = fixture.creation_record(parent, payload);
        if defect == 2 {
            creation.tx_id = tx(90_000);
        }
        fixture.append(vec![creation]);
        assert!(
            fixture.read().is_err(),
            "an immutable entry alone is not a creation witness"
        );
        let mut permitted = Fixture::new();
        permitted.create();
        assert_eq!(permitted.read().unwrap(), None);
    }
}

#[test]
fn creation_after_a_committed_predecessor_and_refusals_is_an_exact_boundary() {
    let mut fixture = Fixture::new();
    fixture.unrelated_commit();
    let parent = fixture.basis.body().latest_committed_rcr_id;
    fixture.append(Vec::new());
    fixture.create();
    assert!(parent.is_some());
    assert_eq!(fixture.entry.unwrap().predecessor_rcr_id(), parent);
    let initial = fixture.defer();
    fixture.progress(&initial);
    assert_eq!(fixture.read().unwrap(), Some(initial.clone()));
    assert_eq!(fixture.read().unwrap(), fixture.audit().unwrap());
    fixture
        .store
        .fault(Some(batch_key(&fixture.heads[0])), false);
    assert_eq!(fixture.read().unwrap(), Some(initial));
    assert!(fixture.audit().is_err());
}

#[test]
fn a_later_outbox_entry_cannot_invent_membership_in_the_creation_batch() {
    let mut fixture = Fixture::new();
    let record = fixture.creation_record(None, None);
    let entry = fixture.entry.take().unwrap();
    fixture.append(vec![record]);
    fixture.entry = Some(entry);
    fixture.unrelated_commit();
    assert!(
        fixture.read().is_err(),
        "the creating RCR must select its obligation"
    );
    let mut permitted = Fixture::new();
    permitted.create();
    permitted.unrelated_commit();
    assert_eq!(permitted.read().unwrap(), None);
}

#[test]
fn an_existing_binding_cannot_be_relabelled_as_a_new_obligation() {
    let mut fixture = Fixture::new();
    let payload = fixture.stage(
        storage::EVENT_NAMESPACE,
        &ForgeEventBatch { events: Vec::new() },
    );
    let evidence = fixture.stage(OUTBOX_EFFECT_NAMESPACE, &ordinary(None));
    let mut earlier = fixture.record(payload, evidence);
    earlier.parent_rcr_id = fixture.basis.body().latest_committed_rcr_id;
    earlier.repository_sequence = fixture.basis.open_repository_sequence().unwrap();
    let parent = repository_commit_identity(&CryptoBodyIdentity, &earlier).unwrap();
    let creation = fixture.creation_record(Some(Some(parent)), None);
    // The earlier head already selects the binding. A later record matching
    // its transaction/payload coordinates cannot reset its history boundary.
    fixture.append(vec![earlier]);
    fixture.append(vec![creation]);
    assert!(matches!(
        fixture.read(),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::EvidenceInvalid
        ))
    ));

    let mut permitted = Fixture::new();
    permitted.unrelated_commit();
    permitted.create();
    assert_eq!(permitted.read().unwrap(), None);
}

#[test]
fn staged_progress_predecessor_does_not_fill_a_gap_in_the_suffix() {
    let mut fixture = Fixture::new();
    fixture.create();
    let initial = fixture.defer();
    // Stage the initial body but omit its canonical record.
    fixture.progress_record(&initial);
    let pending = initial
        .observe(Observation::Probe(ProbeVerdict::NotDelivered), Vec::new())
        .unwrap();
    fixture.progress(&pending);
    assert!(fixture.read().is_err());

    let mut permitted = Fixture::new();
    permitted.create();
    let initial = permitted.defer();
    permitted.progress(&initial);
    let pending = initial
        .observe(Observation::Probe(ProbeVerdict::NotDelivered), Vec::new())
        .unwrap();
    permitted.progress(&pending);
    assert_eq!(permitted.read().unwrap(), Some(pending));
}

#[test]
fn interruption_at_each_read_boundary_returns_no_partial_result_and_retry_succeeds() {
    let mut fixture = Fixture::new();
    fixture.create();
    let initial = fixture.defer();
    fixture.progress(&initial);
    fixture.store.reset();
    assert_eq!(fixture.read().unwrap(), Some(initial.clone()));
    let reads = fixture.store.count();
    for stop in 0..=reads {
        fixture.store.reset();
        assert!(matches!(
            run(latest_progress_for_entry(
                &fixture.store,
                &(),
                &fixture.basis,
                &fixture.entry.unwrap(),
                &|| fixture.store.count() >= stop
            )),
            Err(AdmissionError::AsyncProjectionUnavailable(
                RefusalCode::CancellationInProgress
            ))
        ));
        assert_eq!(fixture.read().unwrap(), Some(initial.clone()));
    }
}

#[test]
fn old_unresolved_obligations_still_obey_the_unchanged_suffix_budget() {
    let mut fixture = Fixture::new();
    fixture.create();
    for _ in 1..MAX_HISTORY_BATCHES {
        fixture.append(Vec::new());
    }
    assert_eq!(
        fixture.read().unwrap(),
        None,
        "the exact budget remains admitted"
    );
    fixture.append(Vec::new());
    assert!(matches!(
        fixture.read(),
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::ResourceBudgetExceeded
        ))
    ));
}

#[test]
fn terminal_dispositions_keep_their_canonical_receipt_and_progress_bindings() {
    for disposition in [
        OutboxDeliveryDisposition::Acknowledged,
        OutboxDeliveryDisposition::TerminallyRefused,
        OutboxDeliveryDisposition::Indeterminate,
    ] {
        let mut fixture = Fixture::new();
        fixture.create();
        let initial = fixture.defer();
        fixture.progress(&initial);
        let (terminal, lifecycle) = match disposition {
            OutboxDeliveryDisposition::Acknowledged => (
                initial
                    .observe(
                        Observation::Probe(ProbeVerdict::Delivered),
                        b"destination acknowledgement".to_vec(),
                    )
                    .unwrap(),
                LifecycleEvent::Acknowledge,
            ),
            OutboxDeliveryDisposition::TerminallyRefused => {
                let pending = initial
                    .observe(Observation::Probe(ProbeVerdict::NotDelivered), Vec::new())
                    .unwrap();
                fixture.progress(&pending);
                let dispatched = pending.mark_dispatch().unwrap();
                fixture.progress(&dispatched);
                (
                    dispatched
                        .observe(
                            Observation::Delivery(DeliveryVerdict::PermanentRejection),
                            b"destination rejection".to_vec(),
                        )
                        .unwrap(),
                    LifecycleEvent::FailTerminally,
                )
            }
            OutboxDeliveryDisposition::Indeterminate => (
                initial
                    .observe(
                        Observation::Probe(ProbeVerdict::Unknown),
                        b"destination cannot establish delivery".to_vec(),
                    )
                    .unwrap(),
                LifecycleEvent::Escalate,
            ),
        };
        fixture.progress(&terminal);
        let entry = fixture.entry.unwrap();
        let receipt = CanonicalOutboxDeliveryReceipt::try_new(
            fixture.basis.body().repository_id,
            entry.delivery_key(),
            entry.destination(),
            entry.payload_root(),
            terminal.origin_effect_root(),
            disposition,
            terminal.evidence().to_vec(),
        )
        .unwrap();
        let receipt_root = fixture.stage(delivery::RECEIPT_NAMESPACE, &receipt);
        let settled = fixture
            .effect
            .as_ref()
            .unwrap()
            .transition(lifecycle, Some(receipt_root))
            .unwrap();
        let record = fixture.effect_record(&settled);
        fixture.append(vec![record]);
        assert_eq!(fixture.read().unwrap(), Some(terminal.clone()));
        assert_eq!(fixture.read().unwrap(), fixture.audit().unwrap());
        let key = storage::body_key(
            delivery::RECEIPT_NAMESPACE,
            fixture.basis.body().repository_id,
            receipt_root,
        )
        .unwrap();
        for corrupt in [false, true] {
            fixture.store.fault(Some(key.clone()), corrupt);
            assert!(fixture.read().is_err());
            fixture.store.fault(None, false);
            assert_eq!(fixture.read().unwrap(), Some(terminal.clone()));
        }
    }
}

#[test]
fn creation_and_later_progress_in_one_microbatch_share_one_verified_boundary() {
    let mut fixture = Fixture::new();
    for _ in 0..3 {
        fixture.append(Vec::new());
    }
    let creation = fixture.creation_record(None, None);
    let deferred = fixture
        .effect
        .as_ref()
        .unwrap()
        .transition(LifecycleEvent::Defer, None)
        .unwrap();
    let lifecycle = fixture.effect_record(&deferred);
    let initial = CanonicalOutboxProgress::start(
        fixture.basis.body().repository_id,
        deferred.delivery_key(),
        fixture.entry.unwrap().destination(),
        deferred.payload_root(),
        deferred.root().unwrap(),
        ReconcilePolicy::new(core::num::NonZeroU32::new(4).unwrap()),
    )
    .unwrap();
    let progress = fixture.progress_record(&initial);
    fixture.append(vec![creation, lifecycle, progress]);
    assert_eq!(fixture.read().unwrap(), Some(initial));
    assert_eq!(fixture.read().unwrap(), fixture.audit().unwrap());
    fixture.store.reset();
    fixture.read().unwrap();
    assert!(!fixture.store.was_read(&batch_key(&fixture.heads[0])));
}
