//! Production discussion readers over authenticated, genesis-seeded canonical maps.
//! The reference store is non-durable; these are not filesystem crash tests.
use super::*;
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, ImmutableRead,
    MemoryAuthorityStore, PutOutcome, StoreInstanceId,
};
use fgit_codec::harness::{genesis_head, tx_id};
use fgit_codec::{CanonicalBody, CanonicalOutboxEffectState, CanonicalOutboxStateEntry};
use fgit_forge::ExpectedVersion;
use fgit_forge::event::discussion::{DiscussionAction, DiscussionState};
use fgit_types::PrincipalId;
use std::future::Future;
use std::task::{Context, Poll, Waker};

fn run<F: Future>(future: F) -> F::Output {
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("reference store operations do not suspend"),
    }
}

struct Store(MemoryAuthorityStore);
impl AsyncAuthorityStore for Store {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }
    fn put_if_absent(
        &self,
        (): &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.0.put_if_absent(key, body))
    }
    fn read_immutable(
        &self,
        (): &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        std::future::ready(self.0.read_immutable(key))
    }
    fn initialize_head(
        &self,
        (): &(),
        key: &HeadKey,
        generation: fgit_types::HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.0.initialize_head(key, generation, body))
    }
    fn read_head(
        &self,
        (): &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        std::future::ready(self.0.read_head(key))
    }
    fn compare_exchange_head(
        &self,
        (): &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: fgit_types::HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::ready(
            self.0
                .compare_exchange_head(key, expected, generation, body),
        )
    }
    fn authenticate_head_receipt(
        &self,
        (): &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        std::future::ready(self.0.authenticate_head_receipt(receipt))
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
            let key = fgit_codec::derive_outbox_delivery_key(
                fgit_codec::OutboxDeliveryIdentityInput::new(
                    repository,
                    AsciiSlug::from_static("forge-event"),
                    destination,
                    payload,
                    tx_id(),
                    None,
                ),
            )
            .unwrap();
            let effect = CanonicalOutboxEffectState::committed(repository, key, tx_id(), payload);
            let effect_root = stage(&store, repository, delivery::EFFECT_NAMESPACE, &effect);
            obligations.push(CanonicalOutboxStateEntry::new(
                key,
                AsciiSlug::from_static("forge-event"),
                destination,
                payload,
                tx_id(),
                None,
                effect_root,
                None,
            ));
        }
        let outbox = CanonicalOutboxState::try_new(repository, obligations).unwrap();
        let mut head = genesis_head();
        head.repository_id = repository;
        head.forge_position_root = stage(&store, repository, storage::POSITION_NAMESPACE, &forge);
        head.outbox_root = stage(&store, repository, delivery::OUTBOX_NAMESPACE, &outbox);
        let key = HeadKey::new(b"discussion-replay/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.0, &key, &head).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        Self {
            store,
            basis,
            forge,
            outbox,
        }
    }
    fn page(&self, after: u64, limit: u16) -> DiscussionPage {
        run(read_page_at(
            &self.store,
            &(),
            &self.basis,
            after,
            limit,
            &|| false,
        ))
        .unwrap()
    }
}
fn stage<B: CanonicalBody + Sync>(
    store: &Store,
    repository: RepositoryId,
    namespace: &[u8],
    body: &B,
) -> fgit_types::Digest {
    run(storage::stage_body(store, &(), repository, namespace, body)).unwrap()
}
fn number(value: u64) -> DiscussionNumber {
    DiscussionNumber::try_new(value).unwrap()
}
fn opened(value: u64) -> ForgeEvent {
    DiscussionCommand {
        number: number(value),
        expected_version: ExpectedVersion::NewStream,
        action: DiscussionAction::Open {
            title: format!("Discussion {value}"),
            body: String::new(),
        },
    }
    .proposed_event(PrincipalId::from_bytes([3; 16]))
    .unwrap()
}

fn following(value: u64, previous: u64, action: DiscussionAction) -> ForgeEvent {
    DiscussionCommand {
        number: number(value),
        expected_version: ExpectedVersion::Exactly(AggregateVersion::try_new(previous).unwrap()),
        action,
    }
    .proposed_event(PrincipalId::from_bytes([4; 16]))
    .unwrap()
}

#[test]
fn numeric_pages_and_history_have_one_exact_source_head_and_complete_fold() {
    let comment = following(
        2,
        1,
        DiscussionAction::Comment {
            body: "before close é\r\n".into(),
        },
    );
    let close = following(2, 2, DiscussionAction::Close);
    let last = following(
        2,
        3,
        DiscussionAction::Comment {
            body: "after close".into(),
        },
    );
    let fixture = Fixture::new(vec![
        ForgeEventBatch {
            events: vec![opened(10), opened(2), opened(1), comment.clone()],
        },
        ForgeEventBatch {
            events: vec![close.clone(), last.clone()],
        },
    ]);
    let first = fixture.page(0, 2);
    assert_eq!(
        first
            .discussions
            .iter()
            .map(|row| row.number.get())
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(first.next_after, Some(2));
    assert_eq!(first.discussions[1].state, DiscussionState::Closed);
    assert_eq!(first.discussions[1].comments, 2);
    assert_eq!(first.discussions[1].version.get(), 4);
    let tail = fixture.page(2, 2);
    assert_eq!(tail.discussions.len(), 1);
    assert_eq!(tail.discussions[0].number, number(10));
    assert_eq!(tail.source_head, first.source_head);
    assert_eq!(tail.next_after, None);
    let history = run(read_history_at(
        &fixture.store,
        &(),
        &fixture.basis,
        number(2),
        0,
        2,
        &|| false,
    ))
    .unwrap();
    assert_eq!(history.source_head, first.source_head);
    assert_eq!(history.discussion, Some(first.discussions[1].clone()));
    assert_eq!(history.events, vec![opened(2), comment]);
    assert_eq!(history.next_after, Some(2));
    let history_tail = run(read_history_at(
        &fixture.store,
        &(),
        &fixture.basis,
        number(2),
        2,
        2,
        &|| false,
    ))
    .unwrap();
    assert_eq!(history_tail.events, vec![close, last]);
    assert_eq!(history_tail.discussion, history.discussion);
    assert_eq!(history_tail.next_after, None);
    assert!(fixture.page(u64::MAX, 1).discussions.is_empty());
}

#[test]
fn missing_predecessors_cancellation_and_bad_limits_never_return_partial_rows() {
    let mut fixture = Fixture::new(vec![
        ForgeEventBatch::of_one(opened(1)),
        ForgeEventBatch::of_one(following(1, 1, DiscussionAction::Close)),
    ]);
    let repository = fixture.basis.body().repository_id;
    let kept = fixture
        .outbox
        .entries()
        .iter()
        .copied()
        .filter(|entry| {
            let batch = run(storage::read_events(
                &fixture.store,
                &(),
                repository,
                entry.payload_root(),
            ))
            .unwrap();
            batch.events[0].version.get() == 2
        })
        .collect();
    fixture.outbox = CanonicalOutboxState::try_new(repository, kept).unwrap();
    assert!(
        run(read_snapshot_from_roots(
            &fixture.store,
            &(),
            repository,
            &fixture.forge,
            &fixture.outbox,
            number(1),
            &|| false
        ))
        .is_err()
    );
    assert!(
        run(read_page_at(
            &fixture.store,
            &(),
            &fixture.basis,
            0,
            10,
            &|| true
        ))
        .is_err()
    );
    assert!(
        run(read_history_at(
            &fixture.store,
            &(),
            &fixture.basis,
            number(1),
            0,
            10,
            &|| true
        ))
        .is_err()
    );
    for limit in [0, 101] {
        assert!(
            run(read_page_at(
                &fixture.store,
                &(),
                &fixture.basis,
                0,
                limit,
                &|| false
            ))
            .is_err()
        );
        assert!(
            run(read_history_at(
                &fixture.store,
                &(),
                &fixture.basis,
                number(1),
                0,
                limit,
                &|| false
            ))
            .is_err()
        );
    }
    let absent = run(read_history_at(
        &fixture.store,
        &(),
        &fixture.basis,
        number(99),
        0,
        10,
        &|| false,
    ))
    .unwrap();
    assert!(absent.discussion.is_none() && absent.events.is_empty());
    assert_eq!(absent.source_head, fixture.basis.id());
}

#[test]
fn invalid_lifecycle_cannot_be_projected_as_an_accepted_history() {
    let fixture = Fixture::new(vec![ForgeEventBatch {
        events: vec![
            opened(1),
            following(1, 1, DiscussionAction::Lock),
            following(
                1,
                2,
                DiscussionAction::Comment {
                    body: "locked".into(),
                },
            ),
        ],
    }]);
    assert!(
        run(read_page_at(
            &fixture.store,
            &(),
            &fixture.basis,
            0,
            10,
            &|| false
        ))
        .is_err()
    );
    assert!(
        run(read_history_at(
            &fixture.store,
            &(),
            &fixture.basis,
            number(1),
            0,
            1,
            &|| false
        ))
        .is_err()
    );
}
