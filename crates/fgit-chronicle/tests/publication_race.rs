//! Evidence for what a conditional head replacement does on a win and on a
//! loss, inspected against the real in-memory authority store.
//!
//! The store and its publication protocol belong to `fgit-authority`; what is
//! under test here is that a chronicle publication uses them correctly and
//! that a loser learns the right thing about itself.

use fgit_authority::{
    AuthorityStore, HeadInit, HeadKey, HeadRead, ImmutableKey, ImmutableRead, MemoryAuthorityStore,
    OutcomeLookup, StoreInstanceId, body_key, canonical_body_id, indexed_outcome,
    initialize_repository,
};
use fgit_chronicle::{
    LostCandidate, PublicationBasis, PublicationPlan, PublicationVerdict, ResultingRoots,
    VerifiedPublication, publish,
};
use fgit_codec::CryptoBodyIdentity;
use fgit_codec::schema::{RepositoryAuthorityHeadBody, RepositoryCommitRecord};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, HeadGeneration, OPAQUE_ID_LEN,
    PolicyEpoch, PrincipalSnapshotId, RefusalCode, RefusalRecordId, RegistryEpoch,
    RepositoryAuthorityHeadId, RepositoryId, RepositorySequence, TenantId, TxId,
};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(1).expect("code point one is valid"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("thirty-two bytes is a valid digest"),
        )
    };
}

const fn tenant() -> TenantId {
    TenantId::from_bytes([3; OPAQUE_ID_LEN])
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; OPAQUE_ID_LEN])
}

fn head_key() -> HeadKey {
    HeadKey::new(b"head/frankengit/test".to_vec()).expect("a valid head key")
}

fn genesis() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(0x10),
        forge_position_root: digest(0x11),
        outcome_index_root: digest(0x12),
        retention_root: digest(0x13),
        outbox_root: digest(0x14),
        configuration_root: digest(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn record(tag: u8) -> RepositoryCommitRecord {
    RepositoryCommitRecord {
        repository_id: repository(),
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id: derived!(TxId, tag),
        principal_snapshot_id: derived!(PrincipalSnapshotId, tag),
        canonical_request_digest: digest(tag),
        ref_delta_root: digest(tag),
        resulting_ref_root: digest(0x30),
        object_closure_root: digest(tag),
        forge_event_batch_root: digest(tag),
        resulting_forge_position_root: digest(0x31),
        policy_epoch: PolicyEpoch::FIRST,
        policy_decision_root: digest(tag),
        invariant_evidence_root: digest(tag),
        outbox_effect_root: digest(tag),
        retention_delta_root: digest(tag),
    }
}

fn roots() -> ResultingRoots {
    ResultingRoots {
        ref_root: digest(0x30),
        forge_position_root: digest(0x31),
        outcome_index_root: digest(0x32),
        retention_root: digest(0x33),
        outbox_root: digest(0x34),
        policy_epoch: PolicyEpoch::FIRST,
        batch_evidence_root: digest(0x35),
    }
}

/// Opens a store whose head holds the genesis body, and returns the basis.
fn opened() -> (MemoryAuthorityStore, PublicationBasis) {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    let head = genesis();
    match initialize_repository(&store, &head_key(), &head).expect("genesis initializes") {
        HeadInit::Created(_) | HeadInit::IdenticalRetry(_) => {}
        HeadInit::Conflict => panic!("a fresh store cannot conflict on genesis"),
    }
    // The basis id must be the head body's REAL identity, not a tag: replay
    // walks the predecessor chain by identity, so a fabricated id makes the
    // genesis body unfindable and the walk fails. The old accelerator-only
    // classification never touched the chain, which is why this fixture looked
    // fine until loss classification started replaying the stream.
    let id = RepositoryAuthorityHeadId::from_internal_object_id(
        canonical_body_id(
            IdentityDomain::RepositoryAuthorityHead,
            CANONICAL_CODEC_VERSION,
            &head,
        )
        .expect("a head body has an identity"),
    )
    .expect("the identity carries the authority-head domain");
    (store, PublicationBasis::new(id, head))
}

fn candidate(basis: &PublicationBasis, commit_tag: u8) -> VerifiedPublication {
    let mut plan = PublicationPlan::open(basis.clone()).expect("the basis opens");
    plan.commit(record(commit_tag));
    plan.seal(&CryptoBodyIdentity, roots())
        .expect("the plan is well formed")
}

fn current_token(store: &MemoryAuthorityStore) -> fgit_authority::AuthorityVersionToken {
    match store.read_head(&head_key()).expect("the head reads") {
        HeadRead::Present(receipt) => receipt.token(),
        HeadRead::Absent => panic!("the head was initialized"),
    }
}

fn staged(store: &MemoryAuthorityStore, key: &ImmutableKey) -> bool {
    matches!(
        store.read_immutable(key).expect("an immutable read"),
        ImmutableRead::Present(_)
    )
}

#[test]
fn a_winning_publication_makes_every_decision_canonical_at_once() {
    let (store, basis) = opened();
    let publication = candidate(&basis, 0x40);
    let tx = publication
        .batch()
        .decisions
        .first()
        .expect("one decision")
        .tx_id;

    // Before: the head is genesis and the transaction is undecided.
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), tx).expect("a lookup"),
        OutcomeLookup::Undecided
    );

    let verdict = publish(
        &store,
        &head_key(),
        current_token(&store),
        &publication,
        tenant(),
    )
    .expect("publication runs");

    let PublicationVerdict::Published(receipt) = verdict else {
        panic!("an uncontended publication wins: {verdict:?}");
    };
    let (batch, indexed) = (receipt.batch, receipt.indexed);
    assert_eq!(
        Some(batch),
        publication.head().decision_tail_id,
        "the head names exactly the batch that was published"
    );
    assert_eq!(
        indexed, 1,
        "the one decision is indexed after the head moved"
    );

    // After: the head advanced and the decision is terminal.
    match store.read_head(&head_key()).expect("the head reads") {
        HeadRead::Present(receipt) => assert!(
            receipt.generation() > HeadGeneration::FIRST,
            "the head advanced past genesis"
        ),
        HeadRead::Absent => panic!("the head exists"),
    }
    assert!(matches!(
        indexed_outcome(&store, tenant(), repository(), tx).expect("a lookup"),
        OutcomeLookup::Decided(_)
    ));
}

#[test]
fn a_losing_publication_exposes_nothing_and_may_replan() {
    let (store, basis) = opened();
    // Two candidates prepared against the same basis: only one can publish.
    let winner = candidate(&basis, 0x50);
    let loser = candidate(&basis, 0x60);
    let loser_tx = loser.batch().decisions.first().expect("one decision").tx_id;
    let loser_batch_key =
        body_key(IdentityDomain::RepositoryDecisionBatch, loser.batch()).expect("a body key");

    let stale = current_token(&store);
    let won = publish(&store, &head_key(), stale, &winner, tenant()).expect("the winner publishes");
    assert!(matches!(won, PublicationVerdict::Published(_)));

    let head_after_win = match store.read_head(&head_key()).expect("the head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("the head exists"),
    };

    // The loser presents the same, now-stale predecessor token.
    let verdict = publish(&store, &head_key(), stale, &loser, tenant()).expect("the loser runs");
    assert_eq!(
        verdict,
        PublicationVerdict::Lost(LostCandidate::Replannable),
        "an undecided loser learns it may replan, not that it was refused"
    );

    // Nothing the loser staged is referenced, and nothing it carried is decided.
    let head_after_loss = match store.read_head(&head_key()).expect("the head reads") {
        HeadRead::Present(receipt) => receipt,
        HeadRead::Absent => panic!("the head exists"),
    };
    assert_eq!(
        head_after_loss.token(),
        head_after_win.token(),
        "a lost race leaves the winner's head exactly as it was"
    );
    assert_eq!(head_after_loss.generation(), head_after_win.generation());
    assert!(
        staged(&store, &loser_batch_key),
        "the loser's body is staged, which is harmless: staged is not visible"
    );
    assert_eq!(
        indexed_outcome(&store, tenant(), repository(), loser_tx).expect("a lookup"),
        OutcomeLookup::Undecided,
        "a lost race must not index a decision for a transaction nobody decided"
    );
}

#[test]
fn a_loser_whose_transaction_was_already_decided_is_superseded() {
    let (store, basis) = opened();
    // Both candidates carry the SAME transaction; the winner decides it.
    let winner = candidate(&basis, 0x70);
    let loser = candidate(&basis, 0x70);
    let tx = loser.batch().decisions.first().expect("one decision").tx_id;

    let stale = current_token(&store);
    let won = publish(&store, &head_key(), stale, &winner, tenant()).expect("the winner publishes");
    assert!(matches!(won, PublicationVerdict::Published(_)));

    let verdict = publish(&store, &head_key(), stale, &loser, tenant()).expect("the loser runs");
    match verdict {
        PublicationVerdict::Lost(LostCandidate::Superseded { decided }) => {
            assert_eq!(decided.len(), 1);
            assert_eq!(
                decided.first().expect("one entry").0,
                tx,
                "the superseded verdict names the transaction that is already terminal"
            );
        }
        other => panic!("a loser carrying a decided transaction is superseded: {other:?}"),
    }
}

#[test]
fn a_refusal_only_publication_advances_the_head_without_committing() {
    let (store, basis) = opened();
    let mut plan = PublicationPlan::open(basis.clone()).expect("the basis opens");
    plan.refuse(
        derived!(TxId, 0x80),
        RefusalCode::QuotaExceeded,
        derived!(RefusalRecordId, 0x81),
    );
    let publication = plan
        .seal(
            &CryptoBodyIdentity,
            ResultingRoots {
                outcome_index_root: digest(0x32),
                ..ResultingRoots::carried_forward(&basis, digest(0x35))
            },
        )
        .expect("a refusal-only plan is well formed");
    assert!(publication.is_refusal_only());

    let verdict = publish(
        &store,
        &head_key(),
        current_token(&store),
        &publication,
        tenant(),
    )
    .expect("publication runs");
    assert!(matches!(verdict, PublicationVerdict::Published(_)));

    match store.read_head(&head_key()).expect("the head reads") {
        HeadRead::Present(receipt) => assert!(receipt.generation() > HeadGeneration::FIRST),
        HeadRead::Absent => panic!("the head exists"),
    }
    let head = publication.head();
    assert_eq!(
        head.latest_repository_sequence, None,
        "a published refusal still advances no committed-transition position"
    );
    assert_eq!(head.ref_root, genesis().ref_root, "source root untouched");
}
