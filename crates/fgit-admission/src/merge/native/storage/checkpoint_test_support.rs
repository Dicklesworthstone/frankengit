//! Canonical checkpoint edges for model-store history-reader tests.
//! This stages immutable evidence; callers that need a published current head
//! must additionally exercise their store's exact-head compare-and-exchange.

use fgit_authority::{
    AuthorityStore, ImmutableKey, PutOutcome, authority_head_identity, body_key_for_id,
};
use fgit_chronicle::{
    BackupProfile, PublicationBasis, RepositoryCapsuleBody, capsule_identity,
    verify_checkpoint_successor,
};
use fgit_codec::{CryptoBodyIdentity, encode_body};

pub(in crate::merge::native) fn stage_checkpoint(
    store: &(impl AuthorityStore + ?Sized),
    basis: &PublicationBasis,
) -> (PublicationBasis, ImmutableKey) {
    assert_eq!(authority_head_identity(basis.body()).unwrap(), basis.id());
    let capsule = RepositoryCapsuleBody::at_head(
        basis.id(),
        basis.body(),
        basis.body().last_checkpoint_id,
        fgit_codec::harness::digest_of(0xc1),
        fgit_codec::harness::digest_of(0xc2),
        BackupProfile::DecisionHistoryOnly,
    );
    let capsule_id = capsule_identity(&CryptoBodyIdentity, &capsule).unwrap();
    let capsule_key = body_key_for_id(capsule_id.as_internal_object_id()).unwrap();
    let capsule_bytes = encode_body(&capsule).unwrap();
    let mut head = basis.body().clone();
    head.predecessor_head_id = Some(basis.id());
    head.generation = basis.successor_generation().unwrap();
    head.last_checkpoint_id = Some(capsule_id);
    verify_checkpoint_successor(basis, &head, &capsule_bytes).unwrap();
    let head_id = authority_head_identity(&head).unwrap();
    for (key, bytes) in [
        (
            body_key_for_id(basis.id().as_internal_object_id()).unwrap(),
            encode_body(basis.body()).unwrap(),
        ),
        (capsule_key.clone(), capsule_bytes),
        (
            body_key_for_id(head_id.as_internal_object_id()).unwrap(),
            encode_body(&head).unwrap(),
        ),
    ] {
        assert!(matches!(
            store.put_if_absent(&key, &bytes).unwrap(),
            PutOutcome::Created | PutOutcome::IdenticalRetry,
        ));
    }
    (PublicationBasis::new(head_id, head), capsule_key)
}
