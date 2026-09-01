#![forbid(unsafe_code)]
//! Public-path tests for exact authenticated-read identity.

use fgit_agent::{AuthorityReadReceipt, LogicalTime};
use fgit_authority::{
    AuthenticatedHead, AuthorityStore, HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId,
    initialize_repository, outcome_index_root,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_crypto::{IdentityDomain, NativeObjectIdentity};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch,
    RepositoryCommitId, RepositoryId, RepositorySequence,
};

fn digest(byte: u8) -> Digest {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    Digest::new(
        root.algorithm(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[0x5a; 32]).expect("fixed-width RCR digest"),
    )
}

fn authenticated_head(store_id: u64) -> AuthenticatedHead {
    let root = outcome_index_root(&[]).expect("empty outcome-index root is canonical");
    let body = RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x27; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: Some(rcr_id()),
        latest_repository_sequence: Some(RepositorySequence::FIRST),
        ref_root: root,
        forge_position_root: digest(0x31),
        outcome_index_root: digest(0x32),
        retention_root: digest(0x33),
        outbox_root: digest(0x34),
        configuration_root: digest(0x35),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(store_id));
    let key = HeadKey::new(format!("authority-read-identity-{store_id}").into_bytes())
        .expect("bounded nonempty head key");
    let read = match initialize_repository(&store, &key, &body).expect("initialize head") {
        HeadInit::Created(read) => read,
        HeadInit::IdenticalRetry(_) | HeadInit::Conflict => panic!("fresh store must create"),
    };
    store
        .authenticate_head_receipt(&read)
        .expect("issuing store authenticates its receipt")
}

#[test]
fn identical_authenticated_read_event_has_one_deterministic_identity() {
    let authenticated = authenticated_head(301);
    let first = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(40),
        [0x71; 32],
    )
    .expect("authenticated receipt");
    let second = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(40),
        [0x71; 32],
    )
    .expect("identical authenticated receipt");

    assert_eq!(first.receipt_id().expect("identity"), second.receipt_id().expect("identity"));
    assert_ne!(first.receipt_id().expect("identity").as_bytes(), &[0; 32]);
}

#[test]
fn verifier_time_and_profile_are_part_of_the_read_event() {
    let authenticated = authenticated_head(302);
    let basis = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(40),
        [0x71; 32],
    )
    .expect("basis receipt");
    let later = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(41),
        [0x71; 32],
    )
    .expect("later receipt");
    let other_profile = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        LogicalTime::new(40),
        [0x72; 32],
    )
    .expect("other verifier profile");

    assert_ne!(basis.receipt_id().expect("basis identity"), later.receipt_id().expect("later identity"));
    assert_ne!(
        basis.receipt_id().expect("basis identity"),
        other_profile.receipt_id().expect("profile identity")
    );
}

#[test]
fn same_head_from_another_store_token_is_another_read_event() {
    let first_authenticated = authenticated_head(303);
    let second_authenticated = authenticated_head(304);
    let first = AuthorityReadReceipt::from_authenticated_head(
        &first_authenticated,
        LogicalTime::new(40),
        [0x71; 32],
    )
    .expect("first store receipt");
    let second = AuthorityReadReceipt::from_authenticated_head(
        &second_authenticated,
        LogicalTime::new(40),
        [0x71; 32],
    )
    .expect("second store receipt");

    assert_eq!(first.authority_head_id(), second.authority_head_id());
    assert_ne!(first.backend_version_token(), second.backend_version_token());
    assert_ne!(first.receipt_id().expect("first identity"), second.receipt_id().expect("second identity"));
}
