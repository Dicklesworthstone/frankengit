//! Reference-store I/O and refusal checks; not filesystem or latency evidence.

use super::*;
use crate::merge::native::{delivery, storage};
use crate::merge::native::event_history::{
    HistoryReadLimits, HistoryReadSummary, visit_selected_at, visit_selected_indexed_at,
};
use crate::merge::native::metadata_read_tests::run;
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PutOutcome, authority_head_identity, initialize_repository_async,
};
use fgit_codec::harness::{genesis_head, tx_id};
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxEffectState, CanonicalOutboxState,
    CanonicalOutboxStateEntry, OutboxDeliveryIdentityInput, derive_outbox_delivery_key,
};
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{ExpectedVersion, ForgeEventBatch, IssueNumber};
use fgit_types::{AsciiSlug, PrincipalId};
use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const INDEX_BYTES: usize = 4 * 1024 * 1024;

struct Store {
    backend: MemoryAuthorityStore,
    reads: AtomicUsize,
    fault: Mutex<Option<(ImmutableKey, bool)>>,
}

impl Store {
    fn new(instance: StoreInstanceId) -> Self {
        Self {
            backend: MemoryAuthorityStore::new(instance),
            reads: AtomicUsize::new(0),
            fault: Mutex::new(None),
        }
    }
    fn reset(&self) {
        self.reads.store(0, Ordering::Relaxed);
    }
    fn count(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }
}

impl AsyncAuthorityStore for Store {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.backend.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.backend.limits()
    }
    fn put_if_absent(
        &self,
        (): &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.backend.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        (): &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let fault = self.fault.lock().unwrap().clone();
        std::future::ready(match fault {
            Some((target, corrupt)) if target == *key => Ok(if corrupt {
                ImmutableRead::Present(vec![0])
            } else {
                ImmutableRead::Absent
            }),
            _ => self.backend.read_immutable(key),
        })
    }
    fn initialize_head(
        &self,
        (): &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.backend.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        (): &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.backend.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        (): &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.backend.compare_exchange_head(key, expected, generation, body))
    }
    fn authenticate_head_receipt(
        &self,
        (): &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.backend.authenticate_head_receipt(receipt))
    }
}

struct Fixture {
    store: Store,
    basis: PublicationBasis,
    forge: CanonicalForgePositionState,
    outbox: CanonicalOutboxState,
}

impl Fixture {
    fn new(history: &[ForgeEventBatch], active: &[ForgeEventBatch]) -> Self {
        Self::with_instance(history, active, StoreInstanceId::from_raw(0xa661))
    }
    fn with_instance(
        history: &[ForgeEventBatch],
        active: &[ForgeEventBatch],
        instance: StoreInstanceId,
    ) -> Self {
        let store = Store::new(instance);
        let mut head = genesis_head();
        let repository = head.repository_id;
        let mut forge = CanonicalForgePositionState::try_new(repository, Vec::new()).unwrap();
        for batch in history {
            let root = run(storage::stage_body(
                &store, &(), repository, storage::EVENT_NAMESPACE, batch,
            ))
            .unwrap();
            forge = storage::advance_positions(&forge, batch, root).unwrap();
        }
        let entries = active
            .iter()
            .map(|batch| {
                let root = run(storage::stage_body(
                    &store, &(), repository, storage::EVENT_NAMESPACE, batch,
                ))
                .unwrap();
                let effect = AsciiSlug::from_static("forge-event");
                let destination = AsciiSlug::from_static("forge-projection");
                let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
                    repository, effect, destination, root, tx_id(), None,
                ))
                .unwrap();
                let state = CanonicalOutboxEffectState::committed(repository, key, tx_id(), root);
                let state_root = run(storage::stage_body(
                    &store, &(), repository, delivery::EFFECT_NAMESPACE, &state,
                ))
                .unwrap();
                CanonicalOutboxStateEntry::new(
                    key, effect, destination, root, tx_id(), None, state_root, None,
                )
            })
            .collect();
        let outbox = CanonicalOutboxState::try_new(repository, entries).unwrap();
        head.forge_position_root = run(storage::stage_body(
            &store, &(), repository, storage::POSITION_NAMESPACE, &forge,
        ))
        .unwrap();
        head.outbox_root = run(storage::stage_body(
            &store, &(), repository, delivery::OUTBOX_NAMESPACE, &outbox,
        ))
        .unwrap();
        let key = HeadKey::new(b"aggregate-history-index/head".to_vec()).unwrap();
        run(initialize_repository_async(&store, &(), &key, &head)).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        Self { store, basis, forge, outbox }
    }
    fn selected(&self, numbers: &[u64]) -> BTreeMap<AggregateId, ForgePositionStateEntry> {
        numbers
            .iter()
            .map(|number| {
                let id = AggregateId::Issue(IssueNumber::try_new(*number).unwrap());
                (id, *self.forge.entry(storage::aggregate_label(id).unwrap()).unwrap())
            })
            .collect()
    }
    fn read(
        &self,
        numbers: &[u64],
        prior: Option<&VerifiedAggregateHistory>,
        maximum: usize,
    ) -> (BTreeMap<(AggregateId, AggregateVersion), ForgeEvent>, HistoryReadSummary, Option<VerifiedAggregateHistory>) {
        let mut events = BTreeMap::new();
        self.store.reset();
        let (summary, index) = run(visit_selected_indexed_at(
            &self.store, &(), &self.basis, &self.forge, &self.outbox, &self.selected(numbers),
            HistoryReadLimits::DEFAULT, prior, maximum,
            &mut |event, bytes| {
                assert_eq!(bytes, fgit_codec::encode_body(event).unwrap().len());
                assert!(events.insert((event.aggregate, event.version), event.clone()).is_none());
                Ok(())
            },
            &|| false,
        ))
        .unwrap();
        (events, summary, index)
    }
    fn fault(&self, batch: &ForgeEventBatch, corrupt: bool) {
        *self.store.fault.lock().unwrap() = Some((
            storage::body_key(storage::EVENT_NAMESPACE, self.basis.body().repository_id,
                storage::root(batch).unwrap()).unwrap(),
            corrupt,
        ));
    }
}

fn event(number: u64, version: u64) -> ForgeEvent {
    IssueCommand {
        number: IssueNumber::try_new(number).unwrap(),
        expected_version: if version == 1 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version - 1).unwrap())
        },
        action: if version == 1 {
            IssueAction::Open { title: format!("Issue {number}"), body: "body".into(), labels: Vec::new() }
        } else {
            IssueAction::Comment { body: format!("Comment {version}") }
        },
    }
    .proposed_event(PrincipalId::from_bytes([3; 16]))
    .unwrap()
}

fn batch(events: Vec<ForgeEvent>) -> ForgeEventBatch {
    ForgeEventBatch { events }
}

fn refuses<T>(result: Result<T, AdmissionError>, expected: RefusalCode) {
    match result {
        Err(AdmissionError::AsyncProjectionUnavailable(actual)) => assert_eq!(actual, expected),
        Err(error) => panic!("expected {expected:?}, observed {error:?}"),
        Ok(_) => panic!("expected {expected:?}, observed success"),
    }
}

#[test]
fn warm_selected_subset_matches_replay_and_skips_unrelated_payloads() {
    let mut history = vec![
        batch(vec![event(1, 1), event(2, 1)]),
        batch(vec![event(1, 2)]),
        batch(vec![event(2, 2)]),
    ];
    history.extend((3..=32).map(|number| batch(vec![event(number, 1)])));
    let f = Fixture::new(&history, &history);
    let (all, _, index) = f.read(&[1, 2], None, INDEX_BYTES);
    let index = index.unwrap();
    assert_eq!(f.store.count(), history.len());
    assert_eq!(index.source_head(), f.basis.id());
    assert_eq!(index.source_generation(), f.basis.body().generation);

    let (warm, summary, replacement) = f.read(&[1], Some(&index), INDEX_BYTES);
    assert!(replacement.is_none());
    assert_eq!(f.store.count(), 2, "only the two selected payload batches");
    assert_eq!(summary.scanned_events, 3, "shared payload events are still charged");
    assert_eq!(warm.len(), 2);
    for (key, value) in warm {
        assert_eq!(all.get(&key), Some(&value));
    }
    let (ordinary, _, _) = f.read(&[1], None, 0);
    assert_eq!(ordinary.len(), 2);
    assert_eq!(f.store.count(), history.len());
}

#[test]
fn a_complete_frontier_cannot_skip_conflicting_active_payloads_during_capture() {
    let original = event(1, 1);
    let mut changed = original.clone();
    let fgit_forge::ForgeEventPayload::IssueChangedNative(change) = &mut changed.payload else {
        unreachable!()
    };
    let IssueAction::Open { body, .. } = &mut change.action else { unreachable!() };
    *body = "conflicting body".into();
    let history = [batch(vec![original])];
    let f = Fixture::new(&history, &[batch(vec![changed])]);
    refuses(run(visit_selected_indexed_at(
        &f.store, &(), &f.basis, &f.forge, &f.outbox, &f.selected(&[1]),
        HistoryReadLimits::DEFAULT, None, INDEX_BYTES, &mut |_, _| Ok(()), &|| false,
    )), RefusalCode::EvidenceInvalid);

    let f = Fixture::new(&history, &history);
    let (events, _, index) = f.read(&[1], None, INDEX_BYTES);
    assert_eq!(events.len(), 1);
    assert!(index.is_some());
}

#[test]
fn absent_active_deliveries_do_not_invent_missing_history_or_prevent_complete_frontiers() {
    let f = Fixture::new(&[batch(vec![event(1, 1)]), batch(vec![event(1, 2)])], &[]);
    refuses(run(visit_selected_indexed_at(
        &f.store, &(), &f.basis, &f.forge, &f.outbox, &f.selected(&[1]),
        HistoryReadLimits::DEFAULT, None, INDEX_BYTES, &mut |_, _| Ok(()), &|| false,
    )), RefusalCode::EvidenceMissing);

    let f = Fixture::new(&[batch(vec![event(1, 1), event(1, 2)])], &[]);
    let (cold, _, index) = f.read(&[1], None, INDEX_BYTES);
    let (warm, _, replacement) = f.read(&[1], index.as_ref(), INDEX_BYTES);
    assert_eq!(warm, cold);
    assert_eq!(warm.len(), 2);
    assert!(replacement.is_none());
    assert_eq!(f.store.count(), 1);
}

#[test]
fn warm_reads_revalidate_selected_old_payloads_and_keep_the_index_after_refusal() {
    let history = [batch(vec![event(1, 1)]), batch(vec![event(1, 2)])];
    let f = Fixture::new(&history, &history);
    let (original, _, index) = f.read(&[1], None, INDEX_BYTES);
    let index = index.unwrap();
    for (corrupt, code) in [(false, RefusalCode::EvidenceMissing), (true, RefusalCode::EvidenceInvalid)] {
        f.fault(&history[0], corrupt);
        refuses(run(visit_selected_indexed_at(
            &f.store, &(), &f.basis, &f.forge, &f.outbox, &f.selected(&[1]),
            HistoryReadLimits::DEFAULT, Some(&index), INDEX_BYTES,
            &mut |_, _| Ok(()), &|| false,
        )), code);
        assert_eq!(index.source_head(), f.basis.id());
    }
    *f.store.fault.lock().unwrap() = None;
    assert_eq!(f.read(&[1], Some(&index), INDEX_BYTES).0, original);
}

#[test]
fn already_verified_unrelated_payloads_are_not_required_by_a_warm_selected_read() {
    let history = [batch(vec![event(1, 1)]), batch(vec![event(2, 1)])];
    let f = Fixture::new(&history, &history);
    let (original, _, index) = f.read(&[1], None, INDEX_BYTES);
    let index = index.unwrap();
    f.fault(&history[1], true);
    assert_eq!(f.read(&[1], Some(&index), INDEX_BYTES).0, original);
    assert_eq!(f.store.count(), 1);
    refuses(run(visit_selected_indexed_at(
        &f.store, &(), &f.basis, &f.forge, &f.outbox, &f.selected(&[1]),
        HistoryReadLimits::DEFAULT, None, INDEX_BYTES, &mut |_, _| Ok(()), &|| false,
    )), RefusalCode::EvidenceInvalid);
}

#[test]
fn retention_exhaustion_preserves_canonical_output_and_never_repeats_the_scan() {
    let history = [batch(vec![event(1, 1)]), batch(vec![event(1, 2)])];
    let f = Fixture::new(&history, &history);
    let (expected, _, index) = f.read(&[1], None, INDEX_BYTES);
    let bytes = index.unwrap().retained_bytes();
    for maximum in [0, bytes - 1] {
        let (events, _, index) = f.read(&[1], None, maximum);
        assert_eq!(events, expected);
        assert!(index.is_none());
        assert_eq!(f.store.count(), 2);
    }
    let (events, _, index) = f.read(&[1], None, bytes);
    assert_eq!(events, expected);
    assert_eq!(index.unwrap().retained_bytes(), bytes);
    assert_eq!(f.store.count(), 2);
}

#[test]
fn uncovered_aggregates_different_stores_and_changed_heads_use_full_replay() {
    let history = [batch(vec![event(1, 1)]), batch(vec![event(2, 1)])];
    let f = Fixture::new(&history, &history);
    let index = f.read(&[1], None, INDEX_BYTES).2.unwrap();
    let (events, _, replacement) = f.read(&[1, 2], Some(&index), INDEX_BYTES);
    assert_eq!(events.len(), 2);
    assert!(replacement.is_some());
    assert_eq!(f.store.count(), 2);

    let other = Fixture::with_instance(&history, &history, StoreInstanceId::from_raw(0xa662));
    assert_eq!(other.basis.id(), f.basis.id());
    assert!(other.read(&[1], Some(&index), INDEX_BYTES).2.is_some());
    assert_eq!(other.store.count(), 2);

    let changed = Fixture::new(&history, &history[..1]);
    assert_ne!(changed.basis.id(), f.basis.id());
    assert!(changed.read(&[1], Some(&index), INDEX_BYTES).2.is_some());
    assert_eq!(index.source_head(), f.basis.id());
}

#[test]
fn malformed_body_and_frontier_bindings_refuse_before_a_cached_read() {
    let f = Fixture::new(&[batch(vec![event(1, 1)])], &[]);
    let index = f.read(&[1], None, INDEX_BYTES).2.unwrap();
    let selected = f.selected(&[1]);
    let mut body = f.basis.body().clone();
    body.policy_epoch = fgit_types::PolicyEpoch::try_new(2).unwrap();
    let forged = PublicationBasis::new(f.basis.id(), body);
    f.store.reset();
    refuses(run(visit_selected_indexed_at(
        &f.store, &(), &forged, &f.forge, &f.outbox, &selected,
        HistoryReadLimits::DEFAULT, Some(&index), INDEX_BYTES,
        &mut |_, _| Ok(()), &|| false,
    )), RefusalCode::EvidenceInvalid);
    assert_eq!(f.store.count(), 0);

    let mut selected = selected;
    let position = selected.values_mut().next().unwrap();
    *position = ForgePositionStateEntry::try_new(
        position.stream(), 0, 1, storage::root(&batch(Vec::new())).unwrap(),
    ).unwrap();
    refuses(run(visit_selected_indexed_at(
        &f.store, &(), &f.basis, &f.forge, &f.outbox, &selected,
        HistoryReadLimits::DEFAULT, Some(&index), INDEX_BYTES,
        &mut |_, _| Ok(()), &|| false,
    )), RefusalCode::EvidenceInvalid);
    assert_eq!(f.store.count(), 0);
}

#[test]
fn warm_limits_charge_entire_selected_batches_before_visiting_and_keep_prior_usable() {
    let payload = batch(vec![event(1, 1), event(1, 2)]);
    let f = Fixture::new(std::slice::from_ref(&payload), &[]);
    let index = f.read(&[1], None, INDEX_BYTES).2.unwrap();
    let bytes = fgit_codec::encode_body(&payload).unwrap().len();
    for limits in [
        HistoryReadLimits { events: 1, scan_bytes: bytes },
        HistoryReadLimits { events: 2, scan_bytes: bytes - 1 },
    ] {
        let mut visited = false;
        refuses(run(visit_selected_indexed_at(
            &f.store, &(), &f.basis, &f.forge, &f.outbox, &f.selected(&[1]),
            limits, Some(&index), INDEX_BYTES,
            &mut |_, _| { visited = true; Ok(()) }, &|| false,
        )), RefusalCode::ResourceBudgetExceeded);
        assert!(!visited);
    }
    assert_eq!(f.read(&[1], Some(&index), INDEX_BYTES).0.len(), 2);
}

#[test]
fn cancellation_and_visitor_refusal_never_publish_partial_coordinates() {
    let history = [batch(vec![event(1, 1)]), batch(vec![event(1, 2)])];
    let f = Fixture::new(&history, &history);
    let index = f.read(&[1], None, INDEX_BYTES).2.unwrap();
    for prior in [None, Some(&index)] {
        f.store.reset();
        refuses(run(visit_selected_indexed_at(
            &f.store, &(), &f.basis, &f.forge, &f.outbox, &f.selected(&[1]),
            HistoryReadLimits::DEFAULT, prior, INDEX_BYTES,
            &mut |_, _| Ok(()), &|| f.store.count() >= 1,
        )), RefusalCode::CancellationInProgress);
        let cancelled = AtomicBool::new(false);
        refuses(run(visit_selected_indexed_at(
            &f.store, &(), &f.basis, &f.forge, &f.outbox, &f.selected(&[1]),
            HistoryReadLimits::DEFAULT, prior, INDEX_BYTES,
            &mut |_, _| { cancelled.store(true, Ordering::Relaxed); Ok(()) },
            &|| cancelled.load(Ordering::Relaxed),
        )), RefusalCode::CancellationInProgress);
        refuses(run(visit_selected_indexed_at(
            &f.store, &(), &f.basis, &f.forge, &f.outbox, &f.selected(&[1]),
            HistoryReadLimits::DEFAULT, prior, INDEX_BYTES,
            &mut |_, _| Err(unavailable(RefusalCode::ResourceBudgetExceeded)), &|| false,
        )), RefusalCode::ResourceBudgetExceeded);
    }
    assert_eq!(f.read(&[1], Some(&index), INDEX_BYTES).0.len(), 2);
}

#[test]
fn the_existing_no_index_visitor_retains_its_complete_replay_semantics() {
    let history = [batch(vec![event(1, 1)]), batch(vec![event(2, 1)])];
    let f = Fixture::new(&history, &history);
    let selected = f.selected(&[1]);
    let mut events = BTreeMap::new();
    f.store.reset();
    let summary = run(visit_selected_at(
        &f.store, &(), &f.basis, &f.forge, &f.outbox, &selected,
        HistoryReadLimits::DEFAULT,
        &mut |event, bytes| { events.insert((event.aggregate, event.version), bytes); Ok(()) },
        &|| false,
    )).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(summary.scanned_events, 2);
    assert_eq!(f.store.count(), 2);
    assert_eq!(authority_head_identity(f.basis.body()).unwrap(), f.basis.id());
}
