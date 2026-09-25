//! Production issue readers over authenticated, genesis-seeded canonical maps.
//! The reference store is non-durable; these are not filesystem crash tests.
use super::*;
use fgit_authority::{
    AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken, AuthenticatedHead,
    CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PutOutcome, StoreInstanceId,
};
use fgit_codec::{CanonicalBody, CanonicalOutboxEffectState, CanonicalOutboxStateEntry};
use fgit_codec::harness::{genesis_head, tx_id};
use fgit_forge::event::issue::{IssueAction, IssueEdit};
use fgit_forge::ExpectedVersion;
use fgit_types::PrincipalId;
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
    forge: CanonicalForgePositionState,
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
        let key = HeadKey::new(b"issue-replay/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.0, &key, &head).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        Self { store, basis, forge, outbox }
    }
    fn page(&self, after: u64, limit: u16) -> IssuePage {
        run(read_page_at(&self.store, &(), &self.basis, after, limit, &|| false)).unwrap()
    }
}
fn stage<B: CanonicalBody + Sync>(store: &Store, repository: RepositoryId, namespace: &[u8], body: &B) -> fgit_types::Digest {
    run(storage::stage_body(store, &(), repository, namespace, body)).unwrap()
}
fn number(value: u64) -> IssueNumber { IssueNumber::try_new(value).unwrap() }
fn event(issue: u64, version: u64, action: IssueAction) -> ForgeEvent {
    IssueCommand {
        number: number(issue),
        expected_version: if version == 1 { ExpectedVersion::NewStream }
            else { ExpectedVersion::Exactly(AggregateVersion::try_new(version - 1).unwrap()) },
        action,
    }.proposed_event(PrincipalId::from_bytes([3; 16])).unwrap()
}
fn opened(issue: u64) -> ForgeEvent {
    event(issue, 1, IssueAction::Open {
        title: format!("Issue {issue}"), body: "original body".into(), labels: Vec::new(),
    })
}
fn history(issue: u64, count: u64) -> ForgeEventBatch {
    let mut events = vec![opened(issue)];
    events.extend((2..=count).map(|version| event(issue, version, IssueAction::Comment { body: format!("comment {version}") })));
    ForgeEventBatch { events }
}

#[test]
fn a_long_issue_history_crosses_4096_without_truncating_state_or_pages() {
    let fixture = Fixture::new(vec![history(1, 4101)]);
    let result = run(read_history_at(&fixture.store, &(), &fixture.basis, number(1), 4095, 3, &|| false)).unwrap();
    let issue = result.issue.unwrap();
    assert_eq!(issue.version.get(), 4101);
    assert_eq!(issue.comments, 4100);
    assert_eq!(result.events.iter().map(|event| event.version.get()).collect::<Vec<_>>(), [4096, 4097, 4098]);
    assert_eq!(result.next_after, Some(4098));
    assert_eq!(result.source_head, fixture.basis.id());
    let tail = run(read_history_at(&fixture.store, &(), &fixture.basis, number(1), 4098, 3, &|| false)).unwrap();
    assert_eq!(tail.events.iter().map(|event| event.version.get()).collect::<Vec<_>>(), [4099, 4100, 4101]);
    assert_eq!(tail.next_after, None);
    let past = run(read_history_at(&fixture.store, &(), &fixture.basis, number(1), u64::MAX, 3, &|| false)).unwrap();
    assert!(past.events.is_empty());
    assert_eq!(past.issue.unwrap().version.get(), 4101);
}

#[test]
fn numeric_page_selection_happens_before_replay_and_never_uses_lexical_order() {
    let fixture = Fixture::new(vec![ForgeEventBatch { events: vec![opened(10), opened(2), opened(100), opened(1)] }]);
    let first = fixture.page(0, 2);
    assert_eq!(first.issues.iter().map(|row| row.number.get()).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(first.next_after, Some(2));
    let second = fixture.page(2, 2);
    assert_eq!(second.issues.iter().map(|row| row.number.get()).collect::<Vec<_>>(), [10, 100]);
    assert_eq!(second.next_after, None);
    assert!(fixture.page(u64::MAX, 2).issues.is_empty());
    let selected = BTreeSet::from([number(2)]);
    let timelines = run(replay_selected(&fixture.store, &(), fixture.basis.body().repository_id,
        &fixture.forge, &fixture.outbox, &selected, None, &|| false)).unwrap();
    assert_eq!(timelines.len(), 1);
    assert!(timelines[&number(2)].events.is_empty(), "list/write replay retains no comment timeline");
}

#[test]
fn issue_validation_reuses_the_long_history_without_retaining_it() {
    let fixture = Fixture::new(vec![history(1, 4101)]);
    let selected = BTreeSet::from([number(1)]);
    let timelines = run(replay_selected(&fixture.store, &(), fixture.basis.body().repository_id,
        &fixture.forge, &fixture.outbox, &selected, None, &|| false)).unwrap();
    let prior = &timelines[&number(1)];
    assert!(prior.events.is_empty());
    assert_eq!(prior.latest_event.version.get(), 4101);
    let next = event(1, 4102, IssueAction::Edit(IssueEdit { title: Some("after 4096".into()), ..IssueEdit::default() }));
    assert_eq!(apply_event(Some(&prior.issue), &next).unwrap().title, "after 4096");
    assert!(apply_event(Some(&prior.issue), &opened(1)).is_err());
}

#[test]
fn history_retention_is_the_requested_window_plus_one_lookahead() {
    let fixture = Fixture::new(vec![history(1, 30)]);
    let selected = BTreeSet::from([number(1)]);
    let timelines = run(replay_selected(&fixture.store, &(), fixture.basis.body().repository_id,
        &fixture.forge, &fixture.outbox, &selected, Some((10, 2)), &|| false)).unwrap();
    let row = &timelines[&number(1)];
    assert_eq!(row.events.iter().map(|event| event.version.get()).collect::<Vec<_>>(), [11, 12, 13]);
    assert_eq!(row.issue.version.get(), 30);
    assert_eq!(row.latest_event.version.get(), 30);
}

#[test]
fn unrelated_large_issue_history_does_not_spend_the_selected_page_memory_budget() {
    let mut batches = vec![ForgeEventBatch::of_one(opened(1)), ForgeEventBatch::of_one(opened(2))];
    // More than 32 MiB in a different issue, in frames below the reference store's 1 MiB body bound.
    for group in 0..72 {
        let events = (0..8).map(|offset| event(2, 2 + group * 8 + offset,
            IssueAction::Comment { body: "x".repeat(64 * 1024) })).collect();
        batches.push(ForgeEventBatch { events });
    }
    let fixture = Fixture::new(batches);
    let page = fixture.page(0, 1);
    assert_eq!(page.issues.len(), 1);
    assert_eq!(page.issues[0].number, number(1));
    assert_eq!(page.next_after, Some(1));
    // The same bytes really do exceed the selected-history envelope for #2.
    assert!(run(read_history_at(&fixture.store, &(), &fixture.basis, number(2), 0, 1, &|| false)).is_err());
}

#[test]
fn missing_selected_history_is_not_an_empty_or_partially_replayed_issue() {
    let mut fixture = Fixture::new(vec![ForgeEventBatch::of_one(opened(1)), ForgeEventBatch::of_one(event(1, 2, IssueAction::Close))]);
    // Preserve the selected frontier but omit its predecessor from the outbox.
    let last = fixture.outbox.entries().iter().find(|entry| {
        let batch = run(storage::read_events(&fixture.store, &(), fixture.basis.body().repository_id, entry.payload_root())).unwrap();
        batch.events[0].version.get() == 2
    }).cloned().unwrap();
    fixture.outbox = CanonicalOutboxState::try_new(fixture.basis.body().repository_id, vec![last]).unwrap();
    assert!(run(replay_selected(&fixture.store, &(), fixture.basis.body().repository_id,
        &fixture.forge, &fixture.outbox, &BTreeSet::from([number(1)]), None, &|| false)).is_err());
}

#[test]
fn cancelled_invalid_limit_and_missing_issue_keep_distinct_results() {
    let fixture = Fixture::new(vec![ForgeEventBatch::of_one(opened(1))]);
    for limit in [0, 101] {
        assert!(run(read_page_at(&fixture.store, &(), &fixture.basis, 0, limit, &|| false)).is_err());
    }
    assert!(run(read_page_at(&fixture.store, &(), &fixture.basis, 0, 1, &|| true)).is_err());
    let missing = run(read_history_at(&fixture.store, &(), &fixture.basis, number(99), 0, 1, &|| false)).unwrap();
    assert!(missing.issue.is_none() && missing.events.is_empty() && missing.next_after.is_none());
    assert_eq!(fixture.page(0, 1).issues[0].number, number(1));
}

#[test]
fn canonical_frontiers_above_the_old_global_limit_still_select_bounded_pages() {
    let root = fgit_codec::harness::digest_of(9);
    let entries = (1..=4101).map(|n| fgit_codec::ForgePositionStateEntry::try_new(
        storage::aggregate_label(AggregateId::Issue(number(n))).unwrap(), 0, 1, root,
    ).unwrap()).collect();
    let forge = CanonicalForgePositionState::try_new(RepositoryId::from_bytes([1; 16]), entries).unwrap();
    let (selected, more) = page_numbers(&forge, 4095, 3, &|| false).unwrap();
    assert_eq!(selected.into_iter().map(IssueNumber::get).collect::<Vec<_>>(), [4096, 4097, 4098]);
    assert!(more);
}

#[test]
fn conflicting_selected_versions_and_missing_frontier_bodies_refuse() {
    let fixture = Fixture::new(vec![history(1, 2)]);
    let repository = fixture.basis.body().repository_id;
    let fork = ForgeEventBatch::of_one(event(1, 2, IssueAction::Comment { body: "conflict".into() }));
    let payload = stage(&fixture.store, repository, storage::EVENT_NAMESPACE, &fork);
    let destination = AsciiSlug::from_static("forge-projection");
    let key = fgit_codec::derive_outbox_delivery_key(fgit_codec::OutboxDeliveryIdentityInput::new(
        repository, AsciiSlug::from_static("forge-event"), destination, payload, tx_id(), None,
    )).unwrap();
    let effect = CanonicalOutboxEffectState::committed(repository, key, tx_id(), payload);
    let root = stage(&fixture.store, repository, delivery::EFFECT_NAMESPACE, &effect);
    let mut entries = fixture.outbox.entries().to_vec();
    entries.push(CanonicalOutboxStateEntry::new(key, AsciiSlug::from_static("forge-event"),
        destination, payload, tx_id(), None, root, None));
    let conflicting = CanonicalOutboxState::try_new(repository, entries).unwrap();
    let wanted = BTreeSet::from([number(1)]);
    assert!(run(replay_selected(&fixture.store, &(), repository, &fixture.forge,
        &conflicting, &wanted, None, &|| false)).is_err());
    let missing = CanonicalForgePositionState::try_new(repository, vec![
        fgit_codec::ForgePositionStateEntry::try_new(AsciiSlug::from_static("issue/1"),
            0, 2, fgit_codec::harness::digest_of(200)).unwrap(),
    ]).unwrap();
    assert!(run(replay_selected(&fixture.store, &(), repository, &missing,
        &fixture.outbox, &wanted, None, &|| false)).is_err());
    assert_eq!(fixture.page(0, 1).issues[0].comments, 1);
}
