//! Production PR readers over authenticated, genesis-seeded canonical maps.
//! The reference store is non-durable; these are not filesystem crash tests.
use super::*;
use fgit_authority::{
    AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken, AuthenticatedHead,
    CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PutOutcome, StoreInstanceId,
};
use fgit_codec::{CanonicalBody, CanonicalOutboxEffectState, CanonicalOutboxStateEntry};
use fgit_codec::harness::{genesis_head, tx_id};
use fgit_forge::ExpectedVersion;
use fgit_types::{PrincipalId, RepositoryId, GitHashAlgorithm, GitOid};
use fgit_codec::CanonicalOutboxState;
use std::future::Future;
use std::task::{Context, Poll, Waker};

fn run<F: Future>(future: F) -> F::Output {
    match Box::pin(future).as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference store operations do not suspend"),
    }
}

struct Store(MemoryAuthorityStore);
impl AsyncAuthorityStore for Store {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId { self.0.instance_id() }
    fn limits(&self) -> AuthorityLimits { self.0.limits() }
    async fn put_if_absent(&self, _: &(), key: &ImmutableKey, body: &[u8]) -> Result<PutOutcome, AuthorityFailure> {
        self.0.put_if_absent(key, body)
    }
    async fn read_immutable(&self, _: &(), key: &ImmutableKey) -> Result<ImmutableRead, AuthorityFailure> {
        self.0.read_immutable(key)
    }
    async fn initialize_head(&self, _: &(), key: &HeadKey, generation: fgit_types::HeadGeneration, body: &[u8]) -> Result<HeadInit, AuthorityFailure> {
        self.0.initialize_head(key, generation, body)
    }
    async fn read_head(&self, _: &(), key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.0.read_head(key)
    }
    async fn compare_exchange_head(&self, _: &(), key: &HeadKey, expected: AuthorityVersionToken, generation: fgit_types::HeadGeneration, body: &[u8]) -> Result<CasOutcome, AuthorityFailure> {
        self.0.compare_exchange_head(key, expected, generation, body)
    }
    async fn authenticate_head_receipt(&self, _: &(), receipt: &HeadReadReceipt) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.0.authenticate_head_receipt(receipt)
    }
}

struct Fixture {
    store: Store,
    basis: PublicationBasis,
    outbox: CanonicalOutboxState,
}
impl Fixture {
    fn new(batches: Vec<ForgeEventBatch>) -> Self {
        let store = Store(MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x1557)));
        let repository = RepositoryId::from_bytes([0x44; 16]);
        let mut forge = CanonicalForgePositionState::try_new(repository, Vec::new()).unwrap();
        let mut obligations = Vec::new();
        for batch in batches {
            let payload = stage(&store, repository, storage::EVENT_NAMESPACE, &batch);
            forge = storage::advance_positions(&forge, &batch, payload).unwrap();
            let destination = AsciiSlug::from_static("forge-projection");
            let key = fgit_codec::derive_outbox_delivery_key(fgit_codec::OutboxDeliveryIdentityInput::new(
                repository, AsciiSlug::from_static("forge-event"), destination, payload, tx_id(), None,
            )).unwrap();
            let effect = CanonicalOutboxEffectState::committed(repository, key, tx_id(), payload);
            let effect_root = stage(&store, repository, delivery::EFFECT_NAMESPACE, &effect);
            obligations.push(CanonicalOutboxStateEntry::new(
                key, AsciiSlug::from_static("forge-event"), destination, payload, tx_id(), None,
                effect_root, None,
            ));
        }
        let outbox = CanonicalOutboxState::try_new(repository, obligations).unwrap();
        let mut head = genesis_head();
        head.repository_id = repository;
        head.forge_position_root = stage(&store, repository, storage::POSITION_NAMESPACE, &forge);
        head.outbox_root = stage(&store, repository, delivery::OUTBOX_NAMESPACE, &outbox);
        let key = HeadKey::new(b"pr-replay/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.0, &key, &head).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        Self { store, basis, outbox }
    }
    fn page(&self, after: u64, limit: u16) -> PullRequestPage {
        run(read_page_at(&self.store, &(), &self.basis, after, limit, &|_, _| true, &|| false)).unwrap()
    }
}
fn stage<B: CanonicalBody + Sync>(store: &Store, repository: RepositoryId, namespace: &[u8], body: &B) -> fgit_types::Digest {
    run(storage::stage_body(store, &(), repository, namespace, body)).unwrap()
}
fn number(value: u64) -> PullRequestNumber { PullRequestNumber::try_new(value).unwrap() }
fn oid(format: GitHashAlgorithm, digit: char) -> GitOid {
    GitOid::from_hex(format, &digit.to_string().repeat(format.digest_len() * 2)).unwrap()
}
fn data(pr: u64, version: u64, format: GitHashAlgorithm, body_bytes: usize) -> PullRequestData {
    PullRequestData {
        source_ref: RefName::try_new(format!("refs/heads/topic-{pr}").as_bytes()).unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: oid(format, '1'), target_tip: oid(format, '2'),
        title: format!("PR {pr} version {version}"), body: "x".repeat(body_bytes),
    }
}
fn event(pr: u64, version: u64, format: GitHashAlgorithm, body_bytes: usize) -> ForgeEvent {
    PullRequestCommand {
        number: number(pr),
        expected_version: if version == 1 { ExpectedVersion::NewStream }
            else { ExpectedVersion::Exactly(AggregateVersion::try_new(version - 1).unwrap()) },
        action: if version == 1 { PullRequestAction::Open } else { PullRequestAction::Update },
        data: data(pr, version, format, body_bytes),
    }.proposed_event(PrincipalId::from_bytes([if version == 1 { 7 } else { 8 }; 16]), format).unwrap()
}
fn history(pr: u64, count: u64, format: GitHashAlgorithm, body_bytes: usize) -> Vec<ForgeEventBatch> {
    let events: Vec<_> = (1..=count).map(|version| event(pr, version, format, body_bytes)).collect();
    // Keep every frame inside the reference store's 1 MiB body envelope.
    events.chunks(8).map(|events| ForgeEventBatch { events: events.to_vec() }).collect()
}
impl Fixture {
    /// Select another explicit genesis fixture, not a simulated publication.
    fn select_outbox(&mut self, entries: Vec<CanonicalOutboxStateEntry>) {
        let repository = self.basis.body().repository_id;
        self.outbox = CanonicalOutboxState::try_new(repository, entries).unwrap();
        let mut head = self.basis.body().clone();
        head.outbox_root = stage(&self.store, repository, delivery::OUTBOX_NAMESPACE, &self.outbox);
        let key = HeadKey::new(b"pr-replay/reselected".to_vec()).unwrap();
        fgit_authority::initialize_repository(&self.store.0, &key, &head).unwrap();
        self.basis = run(crate::read_basis_async(&self.store, &(), &key)).unwrap().0;
    }
    fn entry(&self, payload: fgit_types::Digest, destination: AsciiSlug) -> CanonicalOutboxStateEntry {
        let repository = self.basis.body().repository_id;
        let key = fgit_codec::derive_outbox_delivery_key(fgit_codec::OutboxDeliveryIdentityInput::new(
            repository, AsciiSlug::from_static("forge-event"), destination, payload, tx_id(), None,
        )).unwrap();
        let effect = CanonicalOutboxEffectState::committed(repository, key, tx_id(), payload);
        let root = stage(&self.store, repository, delivery::EFFECT_NAMESPACE, &effect);
        CanonicalOutboxStateEntry::new(key, AsciiSlug::from_static("forge-event"), destination,
            payload, tx_id(), None, root, None)
    }
}

#[test]
fn native_pr_histories_above_4096_preserve_latest_metadata_and_original_opener() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(history(1, 4101, format, 0));
        let page = fixture.page(0, 1);
        assert_eq!(page.source_head, fixture.basis.id());
        assert_eq!(page.next_after, None);
        let view = &page.pull_requests[0];
        assert_eq!(view.event.version.get(), 4101);
        assert_eq!(view.data.as_ref().unwrap(), &data(1, 4101, format, 0));
        assert_eq!(view.opened_by, Some(PrincipalId::from_bytes([7; 16])));
        assert_eq!(view.last_metadata_actor, Some(PrincipalId::from_bytes([8; 16])));
        assert_eq!(fixture.page(0, 1), page);
    }
}

#[test]
fn superseded_metadata_does_not_consume_live_page_memory_repeatedly() {
    // 576 full 64 KiB states exceed the old 32 MiB global byte charge. The
    // live result still holds one latest state and its original opener.
    let fixture = Fixture::new(history(1, 576, GitHashAlgorithm::Sha1, 64 * 1024));
    let page = fixture.page(0, 1);
    let view = &page.pull_requests[0];
    assert_eq!(view.data.as_ref().unwrap().title, "PR 1 version 576");
    assert_eq!(view.data.as_ref().unwrap().body.len(), 64 * 1024);
    assert_eq!(view.opened_by, Some(PrincipalId::from_bytes([7; 16])));
}

#[test]
fn unrelated_large_pr_histories_do_not_consume_the_selected_page_budget() {
    let mut batches = history(1, 1, GitHashAlgorithm::Sha1, 0);
    batches.extend(history(2, 576, GitHashAlgorithm::Sha1, 64 * 1024));
    let fixture = Fixture::new(batches);
    let page = fixture.page(0, 1);
    assert_eq!(page.pull_requests[0].number, number(1));
    assert_eq!(page.pull_requests[0].data.as_ref().unwrap().body, "");
    assert_eq!(page.next_after, Some(1));
    assert_eq!(fixture.page(1, 1).pull_requests[0].number, number(2));
}

#[test]
fn shared_payload_fanout_is_replayed_once_not_once_per_destination() {
    let events = (1..=1000).map(|version| event(1, version, GitHashAlgorithm::Sha1, 0)).collect();
    let mut fixture = Fixture::new(vec![ForgeEventBatch { events }]);
    let payload = fixture.outbox.entries()[0].payload_root();
    let entries = (0..70).map(|index| fixture.entry(payload,
        AsciiSlug::try_new("destination", format!("projection-{index}").as_bytes()).unwrap()
    )).collect();
    fixture.select_outbox(entries);
    // 70 x 1000 would exceed the scan-event budget without root de-duplication.
    let page = fixture.page(0, 1);
    assert_eq!(page.pull_requests[0].event.version.get(), 1000);
    assert_eq!(page.pull_requests[0].opened_by, Some(PrincipalId::from_bytes([7; 16])));
}

#[test]
fn merge_frontier_retains_exact_premerge_metadata_in_both_native_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let metadata = data(1, 2, format, 12);
        let merge = ForgeEvent {
            aggregate: AggregateId::PullRequest(number(1)),
            version: AggregateVersion::try_new(3).unwrap(),
            payload: ForgeEventPayload::MergeCommittedNative(fgit_forge::event::NativeMerge {
                source_ref: metadata.source_ref.clone(), source_tip: metadata.source_tip,
                base_tip: oid(format, '3'), target_ref: metadata.target_ref.clone(),
                target_tip_before: metadata.target_tip, merge_commit: oid(format, '4'),
            }),
        };
        let mut batches = history(1, 2, format, 12);
        batches.push(ForgeEventBatch::of_one(merge.clone()));
        let fixture = Fixture::new(batches);
        let page = fixture.page(0, 1);
        let view = &page.pull_requests[0];
        assert_eq!(view.event, merge);
        assert_eq!(view.data.as_ref(), Some(&metadata));
        assert_eq!(view.opened_by, Some(PrincipalId::from_bytes([7; 16])));
        assert_eq!(view.last_metadata_actor, Some(PrincipalId::from_bytes([8; 16])));
    }
}

#[test]
fn visibility_and_numeric_pagination_are_preserved_after_replay_changes() {
    let fixture = Fixture::new(vec![ForgeEventBatch { events: vec![
        event(10, 1, GitHashAlgorithm::Sha1, 0), event(2, 1, GitHashAlgorithm::Sha1, 0),
        event(1, 1, GitHashAlgorithm::Sha1, 0),
    ] }]);
    let page = run(read_page_at(&fixture.store, &(), &fixture.basis, 0, 1,
        &|source, _| source.as_bytes() != b"refs/heads/topic-1", &|| false)).unwrap();
    assert_eq!(page.pull_requests[0].number, number(2));
    assert_eq!(page.next_after, Some(2));
    assert_eq!(fixture.page(2, 1).pull_requests[0].number, number(10));
    let hidden = run(read_page_at(&fixture.store, &(), &fixture.basis, 0, 1,
        &|_, _| false, &|| false)).unwrap();
    assert!(hidden.pull_requests.is_empty());
    assert_eq!(hidden.next_after, None);
}

#[test]
fn an_unselected_opening_object_cannot_supply_missing_canonical_provenance() {
    let mut fixture = Fixture::new(vec![
        ForgeEventBatch::of_one(event(1, 1, GitHashAlgorithm::Sha1, 0)),
        ForgeEventBatch::of_one(event(1, 2, GitHashAlgorithm::Sha1, 0)),
    ]);
    let payload = storage::root(&ForgeEventBatch::of_one(event(1, 2, GitHashAlgorithm::Sha1, 0))).unwrap();
    let entries = fixture.outbox.entries().iter().filter(|entry| entry.payload_root() == payload).cloned().collect();
    fixture.select_outbox(entries);
    // The old opener still exists in storage but is not selected by the outbox.
    assert!(run(read_page_at(&fixture.store, &(), &fixture.basis, 0, 1,
        &|_, _| true, &|| false)).is_err());
}

#[test]
fn same_version_conflicts_still_refuse_instead_of_picking_a_root_order() {
    let mut fixture = Fixture::new(history(1, 2, GitHashAlgorithm::Sha1, 0));
    let fork = ForgeEventBatch::of_one(event(1, 2, GitHashAlgorithm::Sha1, 10));
    let payload = stage(&fixture.store, fixture.basis.body().repository_id, storage::EVENT_NAMESPACE, &fork);
    let mut entries = fixture.outbox.entries().to_vec();
    entries.push(fixture.entry(payload, AsciiSlug::from_static("conflicting-projection")));
    fixture.select_outbox(entries);
    assert!(run(read_page_at(&fixture.store, &(), &fixture.basis, 0, 1,
        &|_, _| true, &|| false)).is_err());
}

#[test]
fn cancellation_invalid_limits_and_empty_tail_do_not_disclose_partial_rows() {
    let fixture = Fixture::new(history(1, 1, GitHashAlgorithm::Sha1, 0));
    for limit in [0, 101] {
        assert!(run(read_page_at(&fixture.store, &(), &fixture.basis, 0, limit,
            &|_, _| true, &|| false)).is_err());
    }
    assert!(run(read_page_at(&fixture.store, &(), &fixture.basis, 0, 1,
        &|_, _| true, &|| true)).is_err());
    let empty = fixture.page(u64::MAX, 1);
    assert!(empty.pull_requests.is_empty());
    assert_eq!(empty.next_after, None);
    assert_eq!(fixture.page(0, 1).pull_requests.len(), 1);
}
