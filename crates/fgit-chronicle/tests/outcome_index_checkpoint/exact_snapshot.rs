//! Snapshot selection must survive optional-leaf fallback without a head reread.

use super::*;
use fgit_authority::{
    AmbiguityReason, AsyncAuthorityStore, AuthenticatedHead, AuthorityFailure, AuthorityLimits,
    AuthorityRefusal, AuthorityVersionToken, CasOutcome, HeadInit, HeadReadReceipt, ImmutableKey,
    ImmutableRead, PutOutcome, SealFailure, body_key, body_key_for_id,
    collect_cumulative_outcomes_at_authenticated_head_async,
};
use fgit_chronicle::collect_cumulative_outcomes_at_authenticated_head_with_fabric_async;
use std::future::Future;
use std::sync::Mutex;

/// A read-only fault view over genuine publication/issuance state. The exact
/// collector cannot accidentally pass by finding the requested old head current:
/// any mutable-head read panics, while immutable reads can be withheld by key.
struct SnapshotStore<'a> {
    store: &'a MemoryAuthorityStore,
    replacements: Vec<(ImmutableKey, ImmutableRead)>,
    cancelled_key: Option<ImmutableKey>,
    reads: Mutex<Vec<ImmutableKey>>,
}

impl<'a> SnapshotStore<'a> {
    const fn new(store: &'a MemoryAuthorityStore) -> Self {
        Self {
            store,
            replacements: Vec::new(),
            cancelled_key: None,
            reads: Mutex::new(Vec::new()),
        }
    }

    fn did_read(&self, key: &ImmutableKey) -> bool {
        self.reads.lock().unwrap().contains(key)
    }
}

#[allow(clippy::unused_async_trait_impl)]
impl AsyncAuthorityStore for SnapshotStore<'_> {
    type Context = ();

    fn instance_id(&self) -> StoreInstanceId {
        self.store.instance_id()
    }

    fn limits(&self) -> AuthorityLimits {
        self.store.limits()
    }

    async fn put_if_absent(
        &self,
        (): &(),
        _: &ImmutableKey,
        _: &[u8],
    ) -> Result<PutOutcome, AuthorityFailure> {
        panic!("snapshot collection cannot mutate immutable evidence")
    }

    async fn read_immutable(
        &self,
        (): &(),
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        self.reads.lock().unwrap().push(key.clone());
        if self.cancelled_key.as_ref() == Some(key) {
            return Err(AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled));
        }
        match self
            .replacements
            .iter()
            .find(|(candidate, _)| candidate == key)
        {
            Some((_, value)) => Ok(value.clone()),
            None => self.store.read_immutable(key),
        }
    }

    async fn initialize_head(
        &self,
        (): &(),
        _: &HeadKey,
        _: HeadGeneration,
        _: &[u8],
    ) -> Result<HeadInit, AuthorityFailure> {
        panic!("snapshot collection cannot initialize authority")
    }

    async fn read_head(&self, (): &(), _: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        panic!("snapshot collection must never substitute the mutable head")
    }

    async fn compare_exchange_head(
        &self,
        (): &(),
        _: &HeadKey,
        _: AuthorityVersionToken,
        _: HeadGeneration,
        _: &[u8],
    ) -> Result<CasOutcome, AuthorityFailure> {
        panic!("snapshot collection cannot publish authority")
    }

    async fn authenticate_head_receipt(
        &self,
        (): &(),
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.store.authenticate_head_receipt(receipt)
    }
}

fn ready<F: Future>(future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    match Box::pin(future).as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the reference store completes each operation immediately"),
    }
}

fn current(store: &MemoryAuthorityStore) -> HeadReadReceipt {
    let HeadRead::Present(receipt) = store.read_head(&head_key()).unwrap() else {
        panic!("fixture head is initialized")
    };
    receipt
}

fn append(store: &MemoryAuthorityStore, tag: u8) -> HeadReadReceipt {
    let receipt = current(store);
    let head = decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
    let basis = PublicationBasis::new(authority_head_identity(&head).unwrap(), head);
    let collected = collect_cumulative_outcomes(store, &head_key()).unwrap();
    let mut plan = PublicationPlan::open(basis.clone()).unwrap();
    plan.refuse(
        derived!(TxId, tag),
        RefusalCode::ProtectedRefTransitionDenied,
        derived!(RefusalRecordId, tag + 1),
    );
    let publication = plan
        .seal(
            &CryptoBodyIdentity,
            roots(&basis),
            &collected,
            receipt.token(),
        )
        .unwrap();
    publish_decisions(
        store,
        &head_key(),
        receipt.token(),
        publication.batch(),
        publication.head(),
        tenant(),
    )
    .unwrap();
    current(store)
}

struct Fixture {
    store: MemoryAuthorityStore,
    fabric: ReferenceMemoryFabric,
    selected: AuthenticatedHead,
    checkpoint: OutcomeIndexCheckpointBody,
    checkpoint_key: ImmutableKey,
    prefix_key: ImmutableKey,
    tail_key: ImmutableKey,
    expected: Vec<RepositoryDecision>,
}

impl Fixture {
    fn new() -> Self {
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x951));
        let (first, first_receipt) = publish_first_refusal(&store, &head_key());
        let leaves = collect_cumulative_outcomes(&store, &head_key())
            .unwrap()
            .checkpoint_decisions_against(first_receipt.token())
            .unwrap();
        let (fabric, manifest) = stage_leaf_archive(&leaves);
        let checkpoint = OutcomeIndexCheckpointBody::new(
            repository(),
            first.head().decision_tail_id,
            first.head().latest_decision_sequence,
            None,
            manifest,
        )
        .unwrap();
        // A valid capsule may bind a checkpoint older than its own position.
        // Publish before AND after activation so a consumer must find the
        // exact checkpoint tail, not stop at the activation predecessor.
        let second = append(&store, 0x21);
        let frozen = freeze_capsule_with_outcome_index_checkpoint(
            &store,
            &fabric,
            &CryptoBodyIdentity,
            &second,
            None,
            closure(),
            &checkpoint,
        )
        .unwrap();
        activate_frozen_capsule(&store, &second, &frozen).unwrap();
        let third = append(&store, 0x31);
        let selected = store.authenticate_head_receipt(&third).unwrap();
        let expected = collect_cumulative_outcomes(&store, &head_key())
            .unwrap()
            .checkpoint_decisions_against(third.token())
            .unwrap();
        append(&store, 0x41);
        Self {
            checkpoint_key: body_key(IdentityDomain::OutcomeIndexCheckpoint, &checkpoint).unwrap(),
            prefix_key: body_key_for_id(
                first
                    .head()
                    .decision_tail_id
                    .unwrap()
                    .as_internal_object_id(),
            )
            .unwrap(),
            tail_key: body_key_for_id(
                selected
                    .body()
                    .unwrap()
                    .decision_tail_id
                    .unwrap()
                    .as_internal_object_id(),
            )
            .unwrap(),
            store,
            fabric,
            selected,
            checkpoint,
            expected,
        }
    }

    fn collect(
        &self,
        view: &SnapshotStore<'_>,
        fabric: &ReferenceMemoryFabric,
    ) -> Result<Vec<RepositoryDecision>, OutcomeFailure> {
        ready(
            collect_cumulative_outcomes_at_authenticated_head_with_fabric_async(
                view,
                &(),
                fabric,
                &CryptoBodyIdentity,
                &self.selected,
            ),
        )?
        .checkpoint_decisions_against(self.selected.receipt().token())
    }
}

#[test]
fn historical_checkpoint_plus_both_tails_matches_oracle_without_reading_old_batches() {
    let fixture = Fixture::new();
    for unavailable in [ImmutableRead::Absent, ImmutableRead::Present(vec![0xff])] {
        let mut view = SnapshotStore::new(&fixture.store);
        view.replacements
            .push((fixture.prefix_key.clone(), unavailable));
        let decisions = fixture.collect(&view, &fixture.fabric).unwrap();
        assert_eq!(decisions, fixture.expected);
        assert_eq!(decisions.len(), 3);
        assert_eq!(
            root_of(&decisions),
            fixture.selected.body().unwrap().outcome_index_root
        );
        assert!(!view.did_read(&fixture.prefix_key));
        assert!(view.did_read(&fixture.tail_key));
        assert!(
            ready(collect_cumulative_outcomes_at_authenticated_head_async(
                &view,
                &(),
                &fixture.selected,
            ))
            .is_err(),
            "the independent genesis replay control encounters the unavailable old batch"
        );
        assert!(view.did_read(&fixture.prefix_key));
    }
}

#[test]
fn optional_checkpoint_failures_replay_the_same_snapshot_and_never_return_a_short_set() {
    let fixture = Fixture::new();
    let mut wrong_identity = fixture.checkpoint.clone();
    wrong_identity.repository_id = RepositoryId::from_bytes([0xee; OPAQUE_ID_LEN]);
    for bad_checkpoint in [
        ImmutableRead::Absent,
        ImmutableRead::Present(vec![0xff]),
        ImmutableRead::Present(encode_body(&wrong_identity).unwrap()),
    ] {
        let mut view = SnapshotStore::new(&fixture.store);
        view.replacements
            .push((fixture.checkpoint_key.clone(), bad_checkpoint));
        assert_eq!(
            fixture.collect(&view, &fixture.fabric).unwrap(),
            fixture.expected
        );
        assert!(
            view.did_read(&fixture.prefix_key),
            "fallback actually replays genesis"
        );
        view.replacements
            .push((fixture.prefix_key.clone(), ImmutableRead::Absent));
        assert!(matches!(
            fixture.collect(&view, &fixture.fabric),
            Err(OutcomeFailure::StreamBodyMissing { .. })
        ));
    }
}

#[test]
fn missing_leaf_manifest_uses_exact_genesis_fallback_and_missing_tail_fails_closed() {
    let fixture = Fixture::new();
    let (empty_archive, _) = stage_leaf_archive(&[]);
    let mut view = SnapshotStore::new(&fixture.store);
    assert_eq!(
        fixture.collect(&view, &empty_archive).unwrap(),
        fixture.expected
    );
    assert!(view.did_read(&fixture.prefix_key));
    view.replacements
        .push((fixture.prefix_key.clone(), ImmutableRead::Absent));
    assert!(matches!(
        fixture.collect(&view, &empty_archive),
        Err(OutcomeFailure::StreamBodyMissing { .. })
    ));

    let mut view = SnapshotStore::new(&fixture.store);
    view.replacements
        .push((fixture.tail_key.clone(), ImmutableRead::Absent));
    assert!(matches!(
        fixture.collect(&view, &fixture.fabric),
        Err(OutcomeFailure::StreamBodyMissing { .. })
    ));
    assert!(!view.did_read(&fixture.prefix_key));
}

#[test]
fn authority_cancellation_propagates_without_fallback_and_foreign_snapshot_never_reads_hints() {
    let fixture = Fixture::new();
    let mut view = SnapshotStore::new(&fixture.store);
    view.cancelled_key = Some(fixture.checkpoint_key.clone());
    assert!(matches!(
        fixture.collect(&view, &fixture.fabric),
        Err(OutcomeFailure::Seal(error))
            if matches!(error.as_ref(), SealFailure::Store(AuthorityFailure::Ambiguous(
                AmbiguityReason::Cancelled
            )))
    ));
    assert!(!view.did_read(&fixture.prefix_key));
    assert!(!view.did_read(&fixture.tail_key));

    let foreign = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0x952));
    let view = SnapshotStore::new(&foreign);
    assert!(matches!(
        fixture.collect(&view, &fixture.fabric),
        Err(OutcomeFailure::Seal(error))
            if matches!(error.as_ref(), SealFailure::Store(AuthorityFailure::Refused(
                AuthorityRefusal::UnknownVersionToken
            )))
    ));
    assert!(view.reads.lock().unwrap().is_empty());
}
