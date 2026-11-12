//! Production milestone and same-head membership readers over authenticated, genesis-seeded canonical maps.
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
use fgit_forge::IssueNumber;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::event::milestone::{MilestoneAction, MilestoneState};
use fgit_types::{PrincipalId, RepositoryId};
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
        let key = HeadKey::new(b"milestone-replay/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.0, &key, &head).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        Self {
            store,
            basis,
            forge,
            outbox,
        }
    }
    /// Select an explicit incomplete genesis, not a simulated delivery.
    /// An old complete basis would legitimately recover retired predecessors.
    fn select_outbox(&mut self, entries: Vec<CanonicalOutboxStateEntry>) {
        let repository = self.basis.body().repository_id;
        self.outbox = CanonicalOutboxState::try_new(repository, entries).unwrap();
        let mut head = self.basis.body().clone();
        head.outbox_root = stage(
            &self.store,
            repository,
            delivery::OUTBOX_NAMESPACE,
            &self.outbox,
        );
        let key = HeadKey::new(b"milestones-replay/incomplete-genesis".to_vec()).unwrap();
        fgit_authority::initialize_repository(&self.store.0, &key, &head).unwrap();
        self.basis = run(crate::read_basis_async(&self.store, &(), &key))
            .unwrap()
            .0;
    }
    fn page(&self, after: u64, limit: u16) -> MilestonePage {
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
fn number(value: u64) -> MilestoneNumber {
    MilestoneNumber::try_new(value).unwrap()
}
fn opened(value: u64) -> ForgeEvent {
    MilestoneCommand {
        number: number(value),
        expected_version: ExpectedVersion::NewStream,
        action: MilestoneAction::Open {
            title: format!("Release {value}"),
            body: String::new(),
            due_at: None,
        },
    }
    .proposed_event(PrincipalId::from_bytes([3; 16]))
    .unwrap()
}
fn issue(value: u64, version: u64, action: IssueAction) -> ForgeEvent {
    IssueCommand {
        number: IssueNumber::try_new(value).unwrap(),
        expected_version: if version == 1 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version - 1).unwrap())
        },
        action,
    }
    .proposed_event(PrincipalId::from_bytes([3; 16]))
    .unwrap()
}
fn issue_open(value: u64) -> ForgeEvent {
    issue(
        value,
        1,
        IssueAction::Open {
            title: format!("Task {value}"),
            body: String::new(),
            labels: Vec::new(),
        },
    )
}
fn set(value: u64, target: u64) -> ForgeEvent {
    issue(
        value,
        2,
        IssueAction::SetMilestone {
            milestone: number(target),
            expected_milestone_version: AggregateVersion::FIRST,
        },
    )
}

#[test]
fn numeric_pages_derive_progress_from_complete_issue_memberships_at_one_head() {
    let fixture = Fixture::new(vec![ForgeEventBatch {
        events: vec![
            opened(10),
            opened(2),
            opened(1),
            issue_open(1),
            set(1, 2),
            issue(1, 3, IssueAction::Close),
            issue_open(2),
            set(2, 10),
            issue_open(3),
            set(3, 2),
            issue(3, 3, IssueAction::ClearMilestone),
        ],
    }]);
    let first = fixture.page(0, 2);
    assert_eq!(
        first
            .milestones
            .iter()
            .map(|row| row.milestone.number.get())
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(first.next_after, Some(2));
    assert_eq!(
        (
            first.milestones[0].open_issues,
            first.milestones[0].closed_issues
        ),
        (0, 0)
    );
    assert_eq!(
        (
            first.milestones[1].open_issues,
            first.milestones[1].closed_issues
        ),
        (0, 1)
    );
    assert_eq!(first.milestones[1].milestone.state, MilestoneState::Open);
    let tail = fixture.page(2, 2);
    assert_eq!(tail.milestones.len(), 1);
    assert_eq!(tail.milestones[0].milestone.number, number(10));
    assert_eq!(
        (
            tail.milestones[0].open_issues,
            tail.milestones[0].closed_issues
        ),
        (1, 0)
    );
    assert_eq!(tail.next_after, None);
    assert_eq!(tail.source_head, first.source_head);
    let history = run(read_history_at(
        &fixture.store,
        &(),
        &fixture.basis,
        number(2),
        0,
        1,
        &|| false,
    ))
    .unwrap();
    assert_eq!(history.source_head, first.source_head);
    assert_eq!(history.milestone, Some(first.milestones[1].clone()));
    assert_eq!(history.events, vec![opened(2)]);
    assert!(fixture.page(u64::MAX, 1).milestones.is_empty());
}

#[test]
fn missing_issue_predecessors_cannot_be_reported_as_zero_or_partial_progress() {
    let mut fixture = Fixture::new(vec![
        ForgeEventBatch::of_one(opened(1)),
        ForgeEventBatch::of_one(issue_open(1)),
        ForgeEventBatch::of_one(set(1, 1)),
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
            !batch.events.iter().any(|event| {
                matches!(event.aggregate, AggregateId::Issue(_))
                    && event.version == AggregateVersion::FIRST
            })
        })
        .collect();
    fixture.select_outbox(kept);
    // The milestone is readable on its own, but the selected head's progress
    // depends on a complete issue fold. It cannot substitute an empty count.
    assert!(
        run(read_snapshot_from_roots(
            &fixture.store,
            &(),
            &fixture.basis,
            &fixture.forge,
            &fixture.outbox,
            number(1),
            &|| false
        ))
        .unwrap()
        .is_some()
    );
    assert!(
        run(issues::milestone_counts_at_roots(
            &fixture.store,
            &(),
            &fixture.basis,
            &fixture.forge,
            &fixture.outbox,
            &BTreeSet::from([number(1)]),
            &|| false
        ))
        .is_err()
    );
}

#[test]
fn missing_milestone_predecessors_and_cancellation_never_return_successful_partial_rows() {
    let close = MilestoneCommand {
        number: number(1),
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: MilestoneAction::Close,
    }
    .proposed_event(PrincipalId::from_bytes([3; 16]))
    .unwrap();
    let mut fixture = Fixture::new(vec![
        ForgeEventBatch::of_one(opened(1)),
        ForgeEventBatch::of_one(close),
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
    fixture.select_outbox(kept);
    assert!(
        run(read_snapshot_from_roots(
            &fixture.store,
            &(),
            &fixture.basis,
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
    assert!(absent.milestone.is_none() && absent.events.is_empty());
}
