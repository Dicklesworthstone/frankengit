//! Canonical notification reconstruction over a non-durable reference authority fixture.
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
use fgit_forge::event::notification::{NotificationAction, NotificationCommand, NotificationMode};
use fgit_forge::{ForgeEventBatch, ForgeEventPayload};
use fgit_types::AsciiSlug;
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
        let key = HeadKey::new(b"notification-replay/head".to_vec()).unwrap();
        fgit_authority::initialize_repository(&store.0, &key, &head).unwrap();
        let basis = run(crate::read_basis_async(&store, &(), &key)).unwrap().0;
        Self {
            store,
            basis,
            forge,
            outbox,
        }
    }
    fn source(&self, principal: u8) -> Result<NotificationSourceSnapshot, AdmissionError> {
        run(read_source_at(
            &self.store,
            &(),
            &self.basis,
            actor(principal),
            &|| false,
        ))
    }
    fn source_kind(
        &self,
        principal: u8,
        kind: NotificationTargetKind,
    ) -> Result<NotificationSourceSnapshot, AdmissionError> {
        run(read_source_for_kind_at(
            &self.store,
            &(),
            &self.basis,
            actor(principal),
            kind,
            &|| false,
        ))
    }
    fn replay(&self, principal: u8) -> Result<Vec<NotificationThread>, AdmissionError> {
        self.replay_kind(principal, NotificationTargetKind::Issue)
    }
    fn replay_kind(
        &self,
        principal: u8,
        kind: NotificationTargetKind,
    ) -> Result<Vec<NotificationThread>, AdmissionError> {
        run(super::replay(
            &self.store,
            &(),
            self.basis.body().repository_id,
            &self.forge,
            &self.outbox,
            actor(principal),
            kind,
            &|| false,
        ))
    }
    fn extra_payload(&mut self, batch: ForgeEventBatch) {
        let repository = self.basis.body().repository_id;
        let payload = stage(&self.store, repository, storage::EVENT_NAMESPACE, &batch);
        let key =
            fgit_codec::derive_outbox_delivery_key(fgit_codec::OutboxDeliveryIdentityInput::new(
                repository,
                AsciiSlug::from_static("forge-event"),
                AsciiSlug::from_static("extra-projection"),
                payload,
                tx_id(),
                None,
            ))
            .unwrap();
        let effect = CanonicalOutboxEffectState::committed(repository, key, tx_id(), payload);
        let effect_root = stage(&self.store, repository, delivery::EFFECT_NAMESPACE, &effect);
        let mut entries = self.outbox.entries().to_vec();
        entries.push(CanonicalOutboxStateEntry::new(
            key,
            AsciiSlug::from_static("forge-event"),
            AsciiSlug::from_static("extra-projection"),
            payload,
            tx_id(),
            None,
            effect_root,
            None,
        ));
        self.outbox = CanonicalOutboxState::try_new(repository, entries).unwrap();
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

fn actor(value: u8) -> PrincipalId {
    PrincipalId::from_bytes([value; 16])
}
fn issue(number: u64, before: u64, who: u8, action: IssueAction) -> ForgeEvent {
    IssueCommand {
        number: IssueNumber::try_new(number).unwrap(),
        expected_version: if before == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(before).unwrap())
        },
        action,
    }
    .proposed_event(actor(who))
    .unwrap()
}
fn opened(number: u64, who: u8) -> ForgeEvent {
    issue(
        number,
        0,
        who,
        IssueAction::Open {
            title: format!("Issue {number}"),
            body: String::new(),
            labels: Vec::new(),
        },
    )
}
fn preference(number: u64, before: u64, who: u8, action: NotificationAction) -> ForgeEvent {
    NotificationCommand {
        target: NotificationTarget::Issue(IssueNumber::try_new(number).unwrap()),
        expected_version: if before == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(before).unwrap())
        },
        action,
    }
    .proposed_event(actor(who))
    .unwrap()
}

#[test]
fn real_source_fold_is_self_scoped_numeric_and_preserves_latest_other_activity() {
    let events = vec![
        opened(10, 2),
        opened(2, 1),
        issue(
            10,
            1,
            1,
            IssueAction::Comment {
                body: "participation".into(),
            },
        ),
        issue(
            10,
            2,
            2,
            IssueAction::Edit(fgit_forge::event::issue::IssueEdit {
                title: Some("Current title".into()),
                ..Default::default()
            }),
        ),
        preference(
            10,
            0,
            1,
            NotificationAction::SetMode(NotificationMode::Subscribed),
        ),
        preference(
            10,
            1,
            1,
            NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(3).unwrap())),
        ),
        preference(
            10,
            0,
            3,
            NotificationAction::SetMode(NotificationMode::Muted),
        ),
    ];
    let grouped = Fixture::new(vec![ForgeEventBatch {
        events: events.clone(),
    }]);
    let fixture = Fixture::new(events.into_iter().map(ForgeEventBatch::of_one).collect());
    let own = fixture.source(1).unwrap();
    assert_eq!(grouped.source(1).unwrap().threads, own.threads);
    assert_eq!(own.source_head, fixture.basis.id());
    assert_eq!(own.forge_root, fixture.basis.body().forge_position_root);
    assert_eq!(own.outbox_root, fixture.basis.body().outbox_root);
    assert_eq!(
        own.threads
            .iter()
            .map(|t| t.subject.target().number())
            .collect::<Vec<_>>(),
        [2, 10]
    );
    assert!(own.threads[0].latest_other_version.is_none());
    assert!(own.threads[0].participated);
    let thread = &own.threads[1];
    assert_eq!(thread.subject.title(), "Current title");
    assert_eq!(thread.latest_other_version.unwrap().get(), 3);
    assert!(thread.participated);
    let prefs = thread.preference.as_ref().unwrap();
    assert_eq!(prefs.principal, actor(1));
    assert_eq!(prefs.mode, NotificationMode::Subscribed);
    assert_eq!(prefs.read_through.unwrap().get(), 3);
    let author = fixture.source(2).unwrap();
    assert!(author.threads[1].preference.is_none());
    assert_eq!(author.threads[1].latest_other_version.unwrap().get(), 2);
    let other = fixture.source(3).unwrap();
    assert_eq!(
        other.threads[1].preference.as_ref().unwrap().mode,
        NotificationMode::Muted
    );
    assert!(!other.threads[1].participated);
    let next = preference(
        10,
        2,
        1,
        NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(4).unwrap())),
    );
    assert!(super::super::validate_current_thread(Some(thread), &next).is_err());
    let valid = preference(10, 2, 1, NotificationAction::SetReadThrough(None));
    assert!(super::super::validate_current_thread(Some(thread), &valid).is_ok());
    assert!(super::super::validate_current_thread(None, &valid).is_err());
}

#[test]
fn duplicate_events_collapse_and_conflicts_missing_history_or_selected_batches_refuse() {
    let first = opened(1, 2);
    let second = issue(
        1,
        1,
        1,
        IssueAction::Comment {
            body: "reply".into(),
        },
    );
    let mut fixture = Fixture::new(vec![
        ForgeEventBatch::of_one(first.clone()),
        ForgeEventBatch::of_one(second.clone()),
    ]);
    let original = fixture.replay(1).unwrap();
    fixture.extra_payload(ForgeEventBatch {
        events: vec![first.clone(), second.clone()],
    });
    assert_eq!(fixture.replay(1).unwrap(), original);
    let mut conflict = first.clone();
    let ForgeEventPayload::IssueChangedNative(change) = &mut conflict.payload else {
        unreachable!()
    };
    let IssueAction::Open { title, .. } = &mut change.action else {
        unreachable!()
    };
    *title = "Different bytes at same canonical version".into();
    fixture.extra_payload(ForgeEventBatch::of_one(conflict));
    assert!(fixture.replay(1).is_err());
    for remove in [first.clone(), second.clone()] {
        let mut fixture = Fixture::new(vec![
            ForgeEventBatch::of_one(first.clone()),
            ForgeEventBatch::of_one(second.clone()),
        ]);
        let remove_root = storage::root(&ForgeEventBatch::of_one(remove)).unwrap();
        fixture.outbox = CanonicalOutboxState::try_new(
            fixture.basis.body().repository_id,
            fixture
                .outbox
                .entries()
                .iter()
                .copied()
                .filter(|entry| entry.payload_root() != remove_root)
                .collect(),
        )
        .unwrap();
        assert!(fixture.replay(1).is_err());
    }
}

#[test]
fn orphan_or_future_preferences_bad_head_identity_and_cancellation_never_produce_rows() {
    for event in [
        preference(
            2,
            0,
            1,
            NotificationAction::SetMode(NotificationMode::Subscribed),
        ),
        preference(
            1,
            0,
            1,
            NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(2).unwrap())),
        ),
    ] {
        let fixture = Fixture::new(vec![
            ForgeEventBatch::of_one(opened(1, 2)),
            ForgeEventBatch::of_one(event),
        ]);
        assert!(fixture.source(1).is_err());
    }
    let fixture = Fixture::new(vec![ForgeEventBatch::of_one(opened(1, 2))]);
    let wrong = PublicationBasis::new(fgit_codec::harness::head_id(), fixture.basis.body().clone());
    assert_ne!(wrong.id(), fixture.basis.id());
    assert!(
        run(read_source_at(
            &fixture.store,
            &(),
            &wrong,
            actor(1),
            &|| false
        ))
        .is_err()
    );
    assert!(
        run(read_source_at(
            &fixture.store,
            &(),
            &fixture.basis,
            actor(1),
            &|| true
        ))
        .is_err()
    );
    assert_eq!(fixture.source(1).unwrap().threads.len(), 1);
}

#[path = "discussion_tests.rs"]
mod discussion_tests;
