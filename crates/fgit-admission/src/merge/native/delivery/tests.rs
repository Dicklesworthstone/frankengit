//! The reference authority is a deterministic store adapter here. Assertions
//! exercise the production body bridge; this is not durable-node/CAS evidence.

use std::future::Future;
use std::task::{Context, Poll, Waker};

use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityStore, AuthorityVersionToken,
    CasOutcome, DuplicateAbsenceWitness, HeadInit, HeadKey, HeadRead, HeadReadReceipt,
    ImmutableKey, ImmutableRead, MemoryAuthorityStore, PutOutcome, StoreInstanceId,
};
use fgit_codec::harness::{digest_of, genesis_head, head_id, tx_id};
use fgit_forge::{AggregateId, AggregateVersion, ForgeEvent, ForgeEventPayload, PullRequestNumber};
use fgit_resource::{LifecycleEvent, ObligationState};
use fgit_types::{AsciiSlug, HeadGeneration};

use super::*;

struct AsyncView(MemoryAuthorityStore);

impl AsyncView {
    fn new() -> Self {
        Self(MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x57)))
    }
}

impl AsyncAuthorityStore for AsyncView {
    type Context = ();
    fn instance_id(&self) -> StoreInstanceId {
        self.0.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.0.limits()
    }
    fn put_if_absent(
        &self,
        _: &(),
        key: &ImmutableKey,
        body: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        let result = self.0.put_if_absent(key, body);
        async move { result }
    }
    fn read_immutable(
        &self,
        _: &(),
        key: &ImmutableKey,
    ) -> impl Future<Output = Result<ImmutableRead, AuthorityFailure>> + Send {
        let result = self.0.read_immutable(key);
        async move { result }
    }
    fn initialize_head(
        &self,
        _: &(),
        key: &HeadKey,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        let result = self.0.initialize_head(key, generation, body);
        async move { result }
    }
    fn read_head(
        &self,
        _: &(),
        key: &HeadKey,
    ) -> impl Future<Output = Result<HeadRead, AuthorityFailure>> + Send {
        let result = self.0.read_head(key);
        async move { result }
    }
    fn compare_exchange_head(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        let result = self
            .0
            .compare_exchange_head(key, expected, generation, body);
        async move { result }
    }
    fn publish_head_with_outcomes(
        &self,
        _: &(),
        key: &HeadKey,
        expected: AuthorityVersionToken,
        generation: HeadGeneration,
        body: &[u8],
        outcomes: &[(ImmutableKey, Vec<u8>)],
        witness: &DuplicateAbsenceWitness,
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        let result = self
            .0
            .publish_head_with_outcomes(key, expected, generation, body, outcomes, witness);
        async move { result }
    }
    fn authenticate_head_receipt(
        &self,
        _: &(),
        receipt: &HeadReadReceipt,
    ) -> impl Future<Output = Result<AuthenticatedHead, AuthorityFailure>> + Send {
        let result = self.0.authenticate_head_receipt(receipt);
        async move { result }
    }
}

fn run<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    match Box::pin(future).as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("reference adapter must not suspend"),
    }
}

fn initial_basis() -> PublicationBasis {
    let mut head = genesis_head();
    head.forge_position_root = storage::legacy_genesis_root(head.repository_id, b"forge-position");
    head.outbox_root = storage::legacy_genesis_root(head.repository_id, b"outbox");
    PublicationBasis::new(head_id(), head)
}

fn fixture() -> (DeliveryState, ForgeEventBatch, CanonicalOutboxEffectState) {
    let repository = initial_basis().body().repository_id;
    let events = ForgeEventBatch::of_one(ForgeEvent {
        aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::PullRequestOpened {
            source_ref: b"refs/heads/topic".to_vec(),
            target_ref: b"refs/heads/main".to_vec(),
            source_tip: digest_of(3),
            target_tip: digest_of(4),
        },
    });
    fixture_for_events(repository, events)
}

fn fixture_for_events(
    repository: RepositoryId,
    events: ForgeEventBatch,
) -> (DeliveryState, ForgeEventBatch, CanonicalOutboxEffectState) {
    let payload = storage::root(&events).expect("event root");
    let empty = CanonicalForgePositionState::try_new(repository, Vec::new()).expect("empty");
    let forge =
        storage::advance_positions(&empty, &events, payload).expect("ordered event positions");
    let key = derive_outbox_delivery_key(OutboxDeliveryIdentityInput::new(
        repository,
        AsciiSlug::from_static("forge-event"),
        AsciiSlug::from_static("forge-projection"),
        payload,
        tx_id(),
        None,
    ))
    .expect("delivery identity");
    let effect = CanonicalOutboxEffectState::committed(repository, key, tx_id(), payload);
    let outbox = index_for(&effect);
    (DeliveryState { forge, outbox }, events, effect)
}

fn index_for(effect: &CanonicalOutboxEffectState) -> CanonicalOutboxState {
    CanonicalOutboxState::try_new(
        effect.repository_id(),
        vec![CanonicalOutboxStateEntry::new(
            effect.delivery_key(),
            AsciiSlug::from_static("forge-event"),
            AsciiSlug::from_static("forge-projection"),
            effect.payload_root(),
            effect.tx_id(),
            None,
            effect.root().expect("effect root"),
            effect.predecessor_root(),
        )],
    )
    .expect("canonical outbox")
}

fn receipt_for(effect: &CanonicalOutboxEffectState) -> CanonicalOutboxDeliveryReceipt {
    CanonicalOutboxDeliveryReceipt::try_new(
        effect.repository_id(),
        effect.delivery_key(),
        AsciiSlug::from_static("forge-projection"),
        effect.payload_root(),
        effect.root().expect("predecessor root"),
        OutboxDeliveryDisposition::Acknowledged,
        b"destination observed stable key".to_vec(),
    )
    .expect("bounded observation evidence")
}

fn selected(state: &DeliveryState) -> PublicationBasis {
    let mut head = initial_basis().body().clone();
    head.forge_position_root = storage::root(&state.forge).expect("forge root");
    head.outbox_root = storage::root(&state.outbox).expect("outbox root");
    PublicationBasis::new(head_id(), head)
}

#[test]
fn exact_empty_legacy_outbox_is_permitted_but_arbitrary_missing_root_refuses() {
    let store = AsyncView::new();
    let basis = initial_basis();
    let empty = run(read_in(&store, &(), &basis, &|| false)).expect("initial roots");
    assert!(empty.forge.entries().is_empty());
    assert!(empty.outbox.entries().is_empty());
    let mut missing = basis.body().clone();
    missing.outbox_root = digest_of(0x59);
    assert!(
        run(read_in(
            &store,
            &(),
            &PublicationBasis::new(head_id(), missing),
            &|| false
        ))
        .is_err()
    );
    assert!(run(read_in(&store, &(), &basis, &|| true)).is_err());
}

#[test]
fn repeated_staging_resolves_identical_state_without_publishing_a_head() {
    let store = AsyncView::new();
    let (state, events, effect) = fixture();
    let basis = selected(&state);
    for _ in 0..2 {
        run(stage_in(&store, &(), &state, &events, &effect, &|| false)).expect("stage");
    }
    let loaded = run(read_in(&store, &(), &basis, &|| false)).expect("complete roots resolve");
    assert_eq!(loaded, state);
    assert_eq!(
        loaded.forge_positions().values().next(),
        Some(&ForgeStreamPosition::new(1))
    );
    assert_eq!(
        loaded.outbox_bindings().values().next(),
        Some(&effect.payload_root())
    );
    let key = HeadKey::new(b"no-publication".to_vec()).expect("head key");
    assert!(matches!(
        store.0.read_head(&key).expect("read"),
        HeadRead::Absent
    ));
}

#[test]
fn missing_event_and_missing_effect_fail_before_identical_retry_completes_staging() {
    for omit_event in [true, false] {
        let store = AsyncView::new();
        let (state, events, effect) = fixture();
        let repository = effect.repository_id();
        if omit_event {
            run(storage::stage_body(
                &store,
                &(),
                repository,
                EFFECT_NAMESPACE,
                &effect,
            ))
            .expect("effect");
        } else {
            run(storage::stage_body(
                &store,
                &(),
                repository,
                storage::EVENT_NAMESPACE,
                &events,
            ))
            .expect("event");
        }
        run(storage::stage_body(
            &store,
            &(),
            repository,
            storage::POSITION_NAMESPACE,
            &state.forge,
        ))
        .expect("position");
        run(storage::stage_body(
            &store,
            &(),
            repository,
            OUTBOX_NAMESPACE,
            &state.outbox,
        ))
        .expect("outbox");
        let basis = selected(&state);
        assert!(run(read_in(&store, &(), &basis, &|| false)).is_err());
        run(stage_in(&store, &(), &state, &events, &effect, &|| false)).expect("resume");
        assert_eq!(
            run(read_in(&store, &(), &basis, &|| false)).expect("resolved"),
            state
        );
    }
}

#[test]
fn settlement_requires_resolvable_predecessor_and_preserves_merge_semantics() {
    let store = AsyncView::new();
    let (state, events, effect) = fixture();
    let receipt = receipt_for(&effect);
    let ack = effect
        .transition(
            LifecycleEvent::Acknowledge,
            Some(receipt.root().expect("receipt root")),
        )
        .expect("ack");
    let next_outbox = index_for(&ack);
    assert!(
        run(stage_effect_and_outbox_in(
            &store,
            &(),
            &next_outbox,
            &ack,
            &|| false
        ))
        .is_err()
    );
    run(stage_in(&store, &(), &state, &events, &effect, &|| false)).expect("initial");
    run(storage::stage_body(
        &store,
        &(),
        effect.repository_id(),
        RECEIPT_NAMESPACE,
        &receipt,
    ))
    .expect("receipt");
    run(stage_effect_and_outbox_in(
        &store,
        &(),
        &next_outbox,
        &ack,
        &|| false,
    ))
    .expect("successor");
    let next = DeliveryState {
        forge: state.forge.clone(),
        outbox: next_outbox,
    };
    let loaded = run(read_in(&store, &(), &selected(&next), &|| false)).expect("entire chain");
    let entry = loaded.outbox.entry(effect.delivery_key()).expect("entry");
    let body = run(read_effect_in(
        &store,
        &(),
        effect.repository_id(),
        entry,
        &|| false,
    ))
    .expect("body");
    assert_eq!(body.state(), ObligationState::Acknowledged);
    assert_eq!(body.tx_id(), effect.tx_id());
    assert_eq!(body.payload_root(), effect.payload_root());
    assert_eq!(
        body.predecessor_root(),
        Some(effect.root().expect("initial root"))
    );
    assert_eq!(loaded.forge, state.forge);
}

#[test]
fn missing_corrupt_and_unbound_receipts_refuse_beside_a_complete_observation() {
    for malformed in 0..7 {
        let store = AsyncView::new();
        let (state, events, effect) = fixture();
        run(stage_in(&store, &(), &state, &events, &effect, &|| false)).expect("initial");
        let receipt = CanonicalOutboxDeliveryReceipt::try_new(
            if malformed == 2 {
                RepositoryId::from_bytes([0x78; 16])
            } else {
                effect.repository_id()
            },
            if malformed == 3 {
                AsciiSlug::from_static("other-key")
            } else {
                effect.delivery_key()
            },
            if malformed == 4 {
                AsciiSlug::from_static("other-destination")
            } else {
                AsciiSlug::from_static("forge-projection")
            },
            effect.payload_root(),
            if malformed == 5 {
                digest_of(0x79)
            } else {
                effect.root().expect("initial root")
            },
            if malformed == 6 {
                OutboxDeliveryDisposition::TerminallyRefused
            } else {
                OutboxDeliveryDisposition::Acknowledged
            },
            b"destination observation".to_vec(),
        )
        .expect("structurally valid receipt");
        let receipt_root = receipt.root().expect("receipt identity");
        match malformed {
            0 => (), // Missing immutable receipt.
            1 => {
                let key =
                    storage::body_key(RECEIPT_NAMESPACE, effect.repository_id(), receipt_root)
                        .expect("key");
                assert!(matches!(
                    store
                        .0
                        .put_if_absent(&key, b"corrupt receipt frame")
                        .expect("plant corrupt frame"),
                    PutOutcome::Created
                ));
            }
            _ => {
                run(storage::stage_body(
                    &store,
                    &(),
                    effect.repository_id(),
                    RECEIPT_NAMESPACE,
                    &receipt,
                ))
                .expect("plant mismatched receipt");
            }
        }
        let ack = effect
            .transition(LifecycleEvent::Acknowledge, Some(receipt_root))
            .expect("codec-valid acknowledgement");
        let outbox = index_for(&ack);
        assert!(
            run(stage_effect_and_outbox_in(
                &store,
                &(),
                &outbox,
                &ack,
                &|| false
            ))
            .is_err(),
            "staging refuses bad receipt {malformed}"
        );
        // Plant the state/index directly to test recovery independently of the
        // staging guard. The production read must still reject its receipt.
        run(storage::stage_body(
            &store,
            &(),
            effect.repository_id(),
            EFFECT_NAMESPACE,
            &ack,
        ))
        .expect("plant state");
        run(storage::stage_body(
            &store,
            &(),
            effect.repository_id(),
            OUTBOX_NAMESPACE,
            &outbox,
        ))
        .expect("plant index");
        let bad = DeliveryState {
            forge: state.forge.clone(),
            outbox,
        };
        assert!(
            run(read_in(&store, &(), &selected(&bad), &|| false)).is_err(),
            "recovery refuses bad receipt {malformed}"
        );

        let complete = receipt_for(&effect);
        run(storage::stage_body(
            &store,
            &(),
            effect.repository_id(),
            RECEIPT_NAMESPACE,
            &complete,
        ))
        .expect("adjacent complete receipt");
        let settled = effect
            .transition(
                LifecycleEvent::Acknowledge,
                Some(complete.root().expect("root")),
            )
            .expect("complete ack");
        let outbox = index_for(&settled);
        run(stage_effect_and_outbox_in(
            &store,
            &(),
            &outbox,
            &settled,
            &|| false,
        ))
        .expect("complete successor");
        let good = DeliveryState {
            forge: state.forge,
            outbox,
        };
        assert!(run(read_in(&store, &(), &selected(&good), &|| false)).is_ok());
    }
}

#[test]
fn mixed_aggregate_payloads_preserve_each_streams_gap_free_order() {
    let store = AsyncView::new();
    let (_, mut events, _) = fixture();
    let mut other = events.events[0].clone();
    other.aggregate = AggregateId::PullRequest(PullRequestNumber::try_new(2).expect("second PR"));
    events.events.push(other);
    let mut next = events.events[0].clone();
    next.version = AggregateVersion::try_new(2).expect("next version");
    next.payload = ForgeEventPayload::PullRequestHeadAdvanced {
        source_tip: digest_of(8),
    };
    events.events.push(next);
    let (state, events, effect) = fixture_for_events(initial_basis().body().repository_id, events);
    run(stage_in(&store, &(), &state, &events, &effect, &|| false)).expect("mixed batch");
    assert_eq!(
        run(read_in(&store, &(), &selected(&state), &|| false)).expect("read mixed batch"),
        state
    );
    let stream = storage::aggregate_label(events.events[0].aggregate).expect("stream");
    assert_eq!(
        state
            .forge
            .entry(stream)
            .expect("first PR")
            .successor_position(),
        2
    );
}

#[test]
fn cancellation_wrong_ranges_and_payload_substitution_refuse() {
    let store = AsyncView::new();
    let (state, events, effect) = fixture();
    assert!(run(stage_in(&store, &(), &state, &events, &effect, &|| true)).is_err());
    let wrong = DeliveryState {
        forge: CanonicalForgePositionState::try_new(
            effect.repository_id(),
            vec![
                ForgePositionStateEntry::try_new(
                    storage::aggregate_label(events.events[0].aggregate).expect("stream"),
                    1,
                    1,
                    effect.payload_root(),
                )
                .expect("well-formed but wrong range"),
            ],
        )
        .expect("map"),
        outbox: state.outbox.clone(),
    };
    assert!(run(stage_in(&store, &(), &wrong, &events, &effect, &|| false)).is_err());
    let key = storage::body_key(
        storage::EVENT_NAMESPACE,
        effect.repository_id(),
        effect.payload_root(),
    )
    .expect("key");
    assert!(matches!(
        store.0.read_immutable(&key).expect("read"),
        ImmutableRead::Absent
    ));
    run(stage_in(&store, &(), &state, &events, &effect, &|| false)).expect("valid staging");
    let replaced = CanonicalOutboxEffectState::committed(
        effect.repository_id(),
        effect.delivery_key(),
        effect.tx_id(),
        digest_of(0x77),
    );
    run(storage::stage_body(
        &store,
        &(),
        effect.repository_id(),
        EFFECT_NAMESPACE,
        &replaced,
    ))
    .expect("unreachable foreign payload");
    let entry = state.outbox.entry(effect.delivery_key()).expect("entry");
    let forged = CanonicalOutboxStateEntry::new(
        entry.delivery_key(),
        entry.effect_class(),
        entry.destination(),
        entry.payload_root(),
        entry.tx_id(),
        entry.predecessor_rcr_id(),
        replaced.root().expect("root"),
        None,
    );
    assert!(
        run(read_effect_in(
            &store,
            &(),
            effect.repository_id(),
            &forged,
            &|| false
        ))
        .is_err()
    );
    assert!(
        run(read_effect_in(
            &store,
            &(),
            effect.repository_id(),
            entry,
            &|| false
        ))
        .is_ok()
    );
}
