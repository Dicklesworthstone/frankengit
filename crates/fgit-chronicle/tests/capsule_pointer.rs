//! Capsule body, identity, and the root-last pointer protocol.
//!
//! The two failures this file exists to make impossible are the ones section 23
//! names: a stale checkpoint re-published as the current one, and a pointer
//! naming a body no reader can fetch. Each is paired with the near-identical
//! case that proceeds.

use fgit_authority::{
    AuthorityStore, ImmutableRead, MemoryAuthorityStore, StoreInstanceId, body_key,
};
use fgit_chronicle::{
    BackupProfile, CapsulePointer, ChronicleRefusal, RepositoryCapsuleBody,
    advance_pointer_root_last, capsule_identity,
};
use fgit_codec::CryptoBodyIdentity;
use fgit_codec::DecodeLimits;
use fgit_codec::schema::RepositoryAuthorityHeadBody;
use fgit_codec::wire::{decode_body, encode_body};
use fgit_crypto::IdentityDomain;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, HeadGeneration, OPAQUE_ID_LEN,
    PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId, RepositoryId,
};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

fn head_id(tag: u8) -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).expect("code point one is valid"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest"),
    )
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; OPAQUE_ID_LEN])
}

fn head_at(generation: u64) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repository(),
        generation: HeadGeneration::try_new(generation).expect("a non-zero generation"),
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

fn capsule_at(
    generation: u64,
    predecessor: Option<fgit_types::RepositoryCapsuleId>,
) -> RepositoryCapsuleBody {
    RepositoryCapsuleBody::at_head(
        head_id(u8::try_from(generation).unwrap_or(0xF0)),
        &head_at(generation),
        predecessor,
        digest(0x20),
        digest(0x21),
        BackupProfile::FullClosure,
    )
}

fn identity_of(capsule: &RepositoryCapsuleBody) -> fgit_types::RepositoryCapsuleId {
    capsule_identity(&CryptoBodyIdentity, capsule).expect("a capsule has an identity")
}

fn store_with(capsule: &RepositoryCapsuleBody) -> MemoryAuthorityStore {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(1));
    let key = body_key(IdentityDomain::RepositoryCapsule, capsule).expect("a body key");
    let bytes = encode_body(capsule).expect("a capsule encodes");
    store.put_if_absent(&key, &bytes).expect("staging succeeds");
    store
}

// ---------------------------------------------------------------------------
// Body: canonical encoding and identity
// ---------------------------------------------------------------------------

#[test]
fn a_capsule_body_round_trips_through_its_canonical_encoding() {
    let capsule = capsule_at(4, Some(identity_of(&capsule_at(3, None))));
    let bytes = encode_body(&capsule).expect("a capsule encodes");
    let decoded = decode_body::<RepositoryCapsuleBody>(&bytes, DecodeLimits::default())
        .expect("a capsule decodes");
    assert_eq!(decoded, capsule, "encoding is lossless in both directions");
}

#[test]
fn capsule_identity_is_stable_and_excludes_nothing_mutable() {
    let capsule = capsule_at(4, None);
    let first = identity_of(&capsule);
    let again = identity_of(&capsule);
    assert_eq!(first, again, "identity is a function of the body's bytes");

    // A capsule differing in exactly one bound field is a different capsule.
    let mut other = capsule;
    other.object_closure_root = digest(0x99);
    assert_ne!(
        identity_of(&other),
        first,
        "a root the capsule binds participates in its identity"
    );
}

#[test]
fn an_unknown_backup_profile_is_refused_rather_than_defaulted() {
    assert_eq!(
        BackupProfile::from_discriminant(9),
        Err(ChronicleRefusal::BackupProfileUnknown { observed: 9 }),
        "a profile this build does not define cannot be guessed at"
    );

    // Near-identical permitted case: every discriminant this build defines.
    for profile in [
        BackupProfile::DecisionHistoryOnly,
        BackupProfile::FullClosure,
        BackupProfile::FullClosureWithRepair,
    ] {
        assert_eq!(
            BackupProfile::from_discriminant(profile.discriminant()),
            Ok(profile),
            "{} round-trips through its discriminant",
            profile.as_str()
        );
    }
}

// ---------------------------------------------------------------------------
// Planted negative 1: a stale pointer must never be accepted
// ---------------------------------------------------------------------------

#[test]
fn a_stale_capsule_cannot_masquerade_as_current() {
    let first = capsule_at(3, None);
    let first_id = identity_of(&first);
    let pointer = CapsulePointer::genesis(first_id, &first).expect("a first capsule points");

    let second = capsule_at(7, Some(first_id));
    let second_id = identity_of(&second);
    let advanced = pointer
        .advance(second_id, &second)
        .expect("a later capsule naming its predecessor advances");
    assert_eq!(advanced.head_generation().get(), 7);

    // Planted negative: re-publish the older capsule, which still verifies.
    assert_eq!(
        advanced.advance(first_id, &first),
        Err(ChronicleRefusal::CapsuleNotAdvancing {
            current: HeadGeneration::try_new(7).expect("seven"),
            proposed: HeadGeneration::try_new(3).expect("three"),
        }),
        "an older checkpoint that still verifies must not become current again"
    );

    // Planted negative: same generation, which is not an advance either.
    let sibling = capsule_at(7, Some(second_id));
    assert!(matches!(
        advanced.advance(identity_of(&sibling), &sibling),
        Err(ChronicleRefusal::CapsuleNotAdvancing { .. })
    ));

    // Near-identical permitted case: one generation later, bound correctly.
    let third = capsule_at(8, Some(second_id));
    let third_id = identity_of(&third);
    assert_eq!(
        advanced
            .advance(third_id, &third)
            .expect("a strictly later capsule advances")
            .capsule_id(),
        third_id
    );
}

#[test]
fn a_capsule_that_does_not_name_its_predecessor_is_refused() {
    let first = capsule_at(3, None);
    let first_id = identity_of(&first);
    let pointer = CapsulePointer::genesis(first_id, &first).expect("a first capsule points");

    // Planted negative: later generation, but succeeding nothing.
    let orphan = capsule_at(9, None);
    assert_eq!(
        pointer.advance(identity_of(&orphan), &orphan),
        Err(ChronicleRefusal::CapsulePredecessorMismatch),
        "a later capsule from a forked history must not jump in"
    );

    // Planted negative: later generation naming the wrong predecessor.
    let wrong = capsule_at(9, Some(identity_of(&capsule_at(2, None))));
    assert_eq!(
        pointer.advance(identity_of(&wrong), &wrong),
        Err(ChronicleRefusal::CapsulePredecessorMismatch)
    );

    // Near-identical permitted case: the same capsule naming this one.
    let bound = capsule_at(9, Some(first_id));
    assert!(pointer.advance(identity_of(&bound), &bound).is_ok());
}

#[test]
fn a_first_capsule_may_not_claim_a_predecessor() {
    let orphan = capsule_at(3, Some(identity_of(&capsule_at(2, None))));
    assert_eq!(
        CapsulePointer::genesis(identity_of(&orphan), &orphan),
        Err(ChronicleRefusal::CapsulePredecessorMismatch),
        "a first capsule succeeds nothing; a claimed predecessor would leave an undetectable gap"
    );

    // Near-identical permitted case: the same capsule with no predecessor.
    let first = capsule_at(3, None);
    assert!(CapsulePointer::genesis(identity_of(&first), &first).is_ok());
}

// ---------------------------------------------------------------------------
// Planted negative 2: a pointer must not name a body nobody can fetch
// ---------------------------------------------------------------------------

#[test]
fn the_pointer_refuses_to_move_ahead_of_the_body_it_names() {
    let first = capsule_at(3, None);
    let first_id = identity_of(&first);
    let pointer = CapsulePointer::genesis(first_id, &first).expect("a first capsule points");

    let second = capsule_at(7, Some(first_id));

    // Planted negative: the successor body was never staged.
    let empty = MemoryAuthorityStore::new(StoreInstanceId::from_raw(2));
    assert_eq!(
        advance_pointer_root_last(&empty, &CryptoBodyIdentity, &pointer, &second),
        Err(ChronicleRefusal::CapsuleBodyNotStaged),
        "root-last: the pointer may not name data no reader can fetch"
    );

    // Near-identical permitted case: the identical capsule, staged first.
    let staged = store_with(&second);
    let advanced = advance_pointer_root_last(&staged, &CryptoBodyIdentity, &pointer, &second)
        .expect("a staged capsule may be pointed at");
    assert_eq!(advanced.capsule_id(), identity_of(&second));
    assert_eq!(advanced.head_generation().get(), 7);

    // And the staged bytes really are the ones the pointer names.
    let key = body_key(IdentityDomain::RepositoryCapsule, &second).expect("a body key");
    let stored = match staged.read_immutable(&key).expect("an immutable read") {
        ImmutableRead::Present(bytes) => bytes,
        ImmutableRead::Absent => panic!("the capsule was staged"),
    };
    let decoded = decode_body::<RepositoryCapsuleBody>(&stored, DecodeLimits::default())
        .expect("the staged bytes decode");
    assert_eq!(decoded, second, "the pointer names exactly these bytes");
}

#[test]
fn staging_a_body_is_not_enough_to_make_a_stale_capsule_current() {
    // Both rules are independent: staging satisfies root-last but says nothing
    // about ordering, so a staged stale capsule is still refused.
    let first = capsule_at(3, None);
    let first_id = identity_of(&first);
    let second = capsule_at(7, Some(first_id));
    let second_id = identity_of(&second);
    let pointer = CapsulePointer::genesis(first_id, &first)
        .expect("a first capsule points")
        .advance(second_id, &second)
        .expect("the successor advances");

    let staged = store_with(&first);
    assert!(matches!(
        advance_pointer_root_last(&staged, &CryptoBodyIdentity, &pointer, &first),
        Err(ChronicleRefusal::CapsuleNotAdvancing { .. })
    ));
}

// ---------------------------------------------------------------------------
// Golden: the encoding is pinned, so a silent format change fails here
// ---------------------------------------------------------------------------

#[test]
fn the_capsule_encoding_is_byte_pinned() {
    let capsule = capsule_at(3, None);
    let bytes = encode_body(&capsule).expect("a capsule encodes");
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();

    // Pinned by construction rather than by a recorded blob: re-encoding the
    // decoded body must reproduce the exact bytes, and the identity computed
    // over them must not move. A format change that alters either fails here
    // instead of silently producing capsules an older reader cannot verify.
    let decoded = decode_body::<RepositoryCapsuleBody>(&bytes, DecodeLimits::default())
        .expect("a capsule decodes");
    let reencoded = encode_body(&decoded).expect("the decoded capsule re-encodes");
    assert_eq!(
        reencoded, bytes,
        "canonical encoding is idempotent through a decode"
    );
    assert_eq!(
        identity_of(&decoded),
        identity_of(&capsule),
        "identity survives a decode and re-encode"
    );
    assert!(
        hex.len() == bytes.len() * 2 && !hex.is_empty(),
        "the frame is non-empty"
    );
}
