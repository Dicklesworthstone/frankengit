//! `AuthenticatedHead::body()` — the decode-and-cross-check that used to be the
//! caller's problem.
//!
//! Authentication proves the store issued a receipt. It does **not** prove the
//! bytes inside describe the head that receipt names, so a caller who decodes
//! without comparing generations can act on a body one generation away from the
//! head it just authenticated — and §5.1 admits only the exact predecessor.
//!
//! `fgit-admission` performs that comparison today, correctly, in its own
//! fifteen lines. The reader FG-028a is blocked on would have been the second
//! copy. Two implementations of "what does this head say" are free to disagree,
//! which is `frankengit-0kqi` one crate over.
//!
//! Every check here that asserts a refusal is paired with the permitted case,
//! and the cross-check is shown *firing* rather than merely being present.

use fgit_authority::{
    AuthenticatedHead, AuthorityVersionToken, HeadBodyRefusal, HeadKey, HeadReadReceipt,
    StoreInstanceId, VERSION_TOKEN_BYTES,
};
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_codec::wire::encode_body;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::RepositoryId;
use fgit_types::numeric::{HeadGeneration, PolicyEpoch, RegistryEpoch};

fn digest(byte: u8) -> Digest {
    Digest::new(
        fgit_crypto::IdentityDomain::RepositoryAuthorityHead
            .algorithm()
            .id(),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0x22; 16])
}

/// A head body at `generation`, with a recognisable `ref_root`.
fn head_at(generation: HeadGeneration, ref_root: u8) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(ref_root),
        forge_position_root: digest(0),
        outcome_index_root: digest(0),
        retention_root: digest(0),
        outbox_root: digest(0),
        configuration_root: digest(0),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn head_key() -> HeadKey {
    HeadKey::new(b"refs/heads/main".to_vec()).expect("a short key is admissible")
}

const fn token() -> AuthorityVersionToken {
    AuthorityVersionToken::from_opaque_bytes([3_u8; VERSION_TOKEN_BYTES])
}

/// An authenticated head whose receipt claims `receipt_generation` while its
/// body carries `body_generation`.
fn authenticated(
    receipt_generation: HeadGeneration,
    body: &RepositoryAuthorityHeadBody,
) -> AuthenticatedHead {
    let bytes = encode_body(body).expect("a head body encodes");
    AuthenticatedHead::new(
        HeadReadReceipt::new(head_key(), token(), receipt_generation, bytes),
        StoreInstanceId::from_raw(1),
    )
}

#[test]
fn an_authenticated_head_reads_back_as_its_typed_body() {
    // The permitted case. Without it, every refusal below would be satisfied by
    // an accessor that refused everything.
    let generation = HeadGeneration::try_new(4).expect("a small generation is admissible");
    let expected = head_at(generation, 9);

    let body = authenticated(generation, &expected)
        .body()
        .expect("a head whose receipt and body agree must decode");

    assert_eq!(
        body, expected,
        "the decoded body must be the one that was encoded"
    );
    assert_eq!(
        body.ref_root,
        digest(9),
        "ref_root must survive the round trip; it is the field FG-028a's reader needs and the \
         reason this accessor exists rather than callers reading opaque bytes"
    );
}

#[test]
fn the_generation_cross_check_actually_fires() {
    // The presence case for the check itself, not for the accessor.
    //
    // This is the assertion that makes the permitted case above mean something.
    // An accessor that decoded and never compared would pass that test forever,
    // and would hand a caller a body from a different head than the one it
    // authenticated — which is the failure the cross-check exists to prevent.
    let receipt_generation = HeadGeneration::try_new(4).expect("admissible");
    let body_generation = HeadGeneration::try_new(5).expect("admissible");
    let skewed = head_at(body_generation, 9);

    let refusal = authenticated(receipt_generation, &skewed)
        .body()
        .expect_err("a body one generation away from its receipt must be refused");

    assert_eq!(
        refusal,
        HeadBodyRefusal::GenerationMismatch {
            receipt: receipt_generation,
            body: body_generation,
        },
        "the refusal must name both generations: a caller that cannot see which side moved \
         cannot tell a stale read from a corrupted body"
    );
}

#[test]
fn undecodable_bytes_are_refused_as_codec_rather_than_panicking() {
    // Authentication says nothing about whether the bytes parse. A store that
    // returned a truncated body would otherwise reach a decode that panics or,
    // worse, a caller's `unwrap`.
    let authenticated = AuthenticatedHead::new(
        HeadReadReceipt::new(
            head_key(),
            token(),
            HeadGeneration::FIRST,
            b"not a head body".to_vec(),
        ),
        StoreInstanceId::from_raw(1),
    );

    let refusal = authenticated
        .body()
        .expect_err("bytes that are not a head body must be refused, not decoded");

    assert!(
        matches!(refusal, HeadBodyRefusal::Codec(_)),
        "undecodable bytes must refuse as Codec rather than as a generation mismatch; got \
         {refusal:?}"
    );
}
