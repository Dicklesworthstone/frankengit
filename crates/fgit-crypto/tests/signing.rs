//! Detached-signature envelope behaviour.
//!
//! The RFC 8032 known-answer vectors live in `src/signing.rs`, next to the
//! primitive binding they pin. What is tested here is the part `FrankenGit`
//! owns: what goes into the signed preimage, and therefore which replays the
//! construction refuses.
//!
//! Every refusal below is paired with the nearest case that must still
//! succeed, so a test cannot pass because verification broke outright.

use fgit_crypto::{
    AuthorityAdmin, Capsule, DetachedSignature, ED25519_CODE_POINT, Identity, IdentityDomain,
    KeyEpoch, KeyScope, PackageRelease, RootSecret, SIGNATURE_SCHEME_RESERVED_CODE_POINTS,
    SchemaFamily, SchemaId, SecretKey, SignatureError, SignatureSchemeError, VerifyingKey,
    is_allocatable, resolve_signature_scheme,
};

const BODY: &[u8] = b"one canonical capsule body";

const fn root() -> RootSecret {
    RootSecret::from_bytes([0x5a; 32])
}

const fn schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("frankengit.capsule"), 1, 0)
}

fn capsule_key() -> SecretKey<Capsule> {
    SecretKey::<Capsule>::derive(&root(), KeyEpoch::FIRST, KeyScope::OPERATOR)
}

#[test]
fn a_signature_verifies_against_the_signers_trusted_key() {
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);

    assert_eq!(signed.scheme(), ED25519_CODE_POINT);
    assert_eq!(signed.epoch(), KeyEpoch::FIRST);
    assert_eq!(signed.key_commitment(), key.id().commitment());
    assert_eq!(
        signed.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Ok(())
    );
}

#[test]
fn signing_the_same_body_twice_produces_identical_bytes() {
    // Ed25519 derives its nonce from the key and message. This is the
    // property that makes the ECDSA nonce failure mode absent by
    // construction, so it is asserted rather than assumed.
    let key = capsule_key();
    let first = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    let second = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    assert_eq!(first.signature(), second.signature());
}

#[test]
fn a_different_body_does_not_verify() {
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);

    assert_eq!(
        signed.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            b"one canonical capsule bodY"
        ),
        Err(SignatureError::Invalid)
    );
}

#[test]
fn the_same_body_in_another_domain_does_not_verify() {
    // The replay this construction exists to stop: identical bytes, signed as
    // a capsule, presented as a release asset.
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);

    assert_eq!(
        signed.verify_with(
            &key.verifying_key(),
            IdentityDomain::ReleaseAsset,
            schema(),
            BODY
        ),
        Err(SignatureError::Invalid)
    );
    assert_eq!(
        signed.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Ok(()),
        "the same envelope in its own domain must still verify"
    );
}

#[test]
fn a_schema_version_bump_does_not_verify() {
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    let next = SchemaId::new(SchemaFamily::from_static("frankengit.capsule"), 1, 1);

    assert_eq!(
        signed.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            next,
            BODY
        ),
        Err(SignatureError::Invalid)
    );
}

#[test]
fn a_schema_family_substitution_does_not_verify() {
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    let other = SchemaId::new(SchemaFamily::from_static("frankengit.capsul"), 1, 0);

    assert_eq!(
        signed.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            other,
            BODY
        ),
        Err(SignatureError::Invalid),
        "a one-character-shorter family must not collide with the original"
    );
}

#[test]
fn verifying_against_another_key_is_a_mismatch_not_a_forgery() {
    // The distinction matters operationally: a mismatch is "you asked the
    // wrong question", a forgery is a security event. Reporting one as the
    // other sends an operator down the wrong path.
    let authoring_key = capsule_key();
    let other = SecretKey::<Capsule>::derive(
        &RootSecret::from_bytes([0xa5; 32]),
        KeyEpoch::FIRST,
        KeyScope::OPERATOR,
    );
    let signed = authoring_key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);

    assert_eq!(
        signed.verify_with(
            &other.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Err(SignatureError::KeyMismatch)
    );
}

#[test]
fn two_purposes_under_one_root_do_not_share_a_verifying_key() {
    let root = root();
    let identity = SecretKey::<Identity>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let authority = SecretKey::<AuthorityAdmin>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let release = SecretKey::<PackageRelease>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR);

    assert_ne!(identity.verifying_key(), authority.verifying_key());
    assert_ne!(identity.verifying_key(), release.verifying_key());
    assert_ne!(authority.verifying_key(), release.verifying_key());
}

#[test]
fn two_epochs_under_one_root_do_not_share_a_verifying_key() {
    let root = root();
    let first = SecretKey::<Capsule>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR);
    let second = SecretKey::<Capsule>::derive(
        &root,
        KeyEpoch::FIRST.next().expect("epoch two exists"),
        KeyScope::OPERATOR,
    );
    assert_ne!(first.verifying_key(), second.verifying_key());
}

#[test]
fn two_tenants_under_one_root_do_not_share_a_verifying_key() {
    let root = root();
    let left = SecretKey::<Capsule>::derive(&root, KeyEpoch::FIRST, KeyScope::tenant(b"left"));
    let right = SecretKey::<Capsule>::derive(&root, KeyEpoch::FIRST, KeyScope::tenant(b"right"));
    assert_ne!(left.verifying_key(), right.verifying_key());
}

#[test]
fn a_relabelled_epoch_does_not_verify() {
    // Rebuilt through the wire constructor, which is the only way an attacker
    // gets to choose these fields.
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    let relabelled = DetachedSignature::from_parts(
        signed.scheme(),
        signed.purpose(),
        KeyEpoch::new(9).expect("nine is a valid epoch"),
        *signed.key_commitment(),
        *signed.declared_verifying_key().as_bytes(),
        *signed.signature(),
    );

    assert_eq!(
        relabelled.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Err(SignatureError::Invalid)
    );
}

#[test]
fn a_relabelled_purpose_does_not_verify() {
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    let relabelled = DetachedSignature::from_parts(
        signed.scheme(),
        SecretKey::<AuthorityAdmin>::purpose(),
        signed.epoch(),
        *signed.key_commitment(),
        *signed.declared_verifying_key().as_bytes(),
        *signed.signature(),
    );

    assert_eq!(
        relabelled.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Err(SignatureError::Invalid),
        "a capsule signature must not be presentable as an authority-admin one"
    );
}

#[test]
fn a_relabelled_key_commitment_does_not_verify() {
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    let relabelled = DetachedSignature::from_parts(
        signed.scheme(),
        signed.purpose(),
        signed.epoch(),
        [0; 32],
        *signed.declared_verifying_key().as_bytes(),
        *signed.signature(),
    );

    assert_eq!(
        relabelled.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Err(SignatureError::Invalid)
    );
}

#[test]
fn a_flipped_signature_bit_does_not_verify() {
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    let mut bytes = *signed.signature();
    bytes[0] ^= 0x01;
    let tampered = DetachedSignature::from_parts(
        signed.scheme(),
        signed.purpose(),
        signed.epoch(),
        *signed.key_commitment(),
        *signed.declared_verifying_key().as_bytes(),
        bytes,
    );

    assert_eq!(
        tampered.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Err(SignatureError::Invalid)
    );
}

#[test]
fn an_unimplemented_scheme_is_refused_before_any_curve_operation() {
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    let foreign = DetachedSignature::from_parts(
        7,
        signed.purpose(),
        signed.epoch(),
        *signed.key_commitment(),
        *signed.declared_verifying_key().as_bytes(),
        *signed.signature(),
    );

    assert_eq!(
        foreign.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Err(SignatureError::UnsupportedScheme { code_point: 7 })
    );
}

#[test]
fn an_off_curve_declared_key_is_refused_as_malformed() {
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    // Choosing this value mattered more than it looks. The obvious guess --
    // all-ones -- decompresses fine, and both ed25519-dalek and `OpenSSL` accept
    // it, so the first version of this test asserted MalformedVerifyingKey and
    // got Invalid instead.
    //
    // This encoding is y = 2, little-endian, sign bit clear. Decompression
    // solves x^2 = (y^2 - 1) / (d*y^2 + 1) over GF(2^255 - 19); for y = 2 that
    // value is a quadratic non-residue, so no x exists and the point cannot be
    // decompressed at all. Computed independently rather than guessed.
    let mut bogus = [0x00; 32];
    bogus[0] = 0x02;
    let malformed = DetachedSignature::from_parts(
        signed.scheme(),
        signed.purpose(),
        signed.epoch(),
        *signed.key_commitment(),
        bogus,
        *signed.signature(),
    );

    assert_eq!(
        malformed.verify_with(
            &VerifyingKey::from_bytes(bogus),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Err(SignatureError::MalformedVerifyingKey)
    );
}

#[test]
fn the_declared_key_is_reachable_only_under_a_name_that_says_what_it_is_not() {
    // Self-attested verification is possible, because a decoder legitimately
    // needs it for well-formedness. What the API refuses is letting it happen
    // by accident: the only spelling names the key as *declared*.
    let key = capsule_key();
    let signed = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    assert_eq!(signed.declared_verifying_key(), key.verifying_key());
    assert_eq!(
        signed.verify_with(
            &signed.declared_verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Ok(())
    );
}

#[test]
fn the_registry_resolves_ed25519_and_agrees_with_the_implementation() {
    let row = resolve_signature_scheme(ED25519_CODE_POINT).expect("ed25519 is registered");
    assert_eq!(row.name, "ed25519");
    assert_eq!(
        row.signature_len,
        capsule_key()
            .sign(IdentityDomain::RepositoryCapsule, schema(), BODY)
            .signature()
            .len()
    );
    assert_eq!(
        row.public_key_len,
        capsule_key().verifying_key().as_bytes().len()
    );
}

#[test]
fn the_harness_range_is_still_refused_distinctly_from_an_unknown_scheme() {
    let reserved = *SIGNATURE_SCHEME_RESERVED_CODE_POINTS.start();
    assert_eq!(
        resolve_signature_scheme(reserved),
        Err(SignatureSchemeError::ReservedForHarness {
            code_point: reserved
        })
    );
    assert_eq!(
        resolve_signature_scheme(0x0100),
        Err(SignatureSchemeError::Unregistered { code_point: 0x0100 })
    );
    assert!(!is_allocatable(reserved));
    assert!(is_allocatable(ED25519_CODE_POINT));
}

#[test]
fn a_fixture_shaped_signature_has_the_registered_length_and_still_fails_verification() {
    // The concrete hazard from allocating code point 1: fgit-codec fixtures
    // carry 64 bytes of 0xa0 at scheme 1, which is exactly the registered
    // Ed25519 signature length. A decoder that validated only the length would
    // now accept them.
    //
    // This is the test that makes allocating 1 safe, so it asserts both halves:
    // the length check a naive decoder would run DOES pass, and verification
    // still refuses.
    let key = capsule_key();
    let genuine = key.sign(IdentityDomain::RepositoryCapsule, schema(), BODY);
    let fixture_payload = [0xa0_u8; 64];

    let row = resolve_signature_scheme(ED25519_CODE_POINT).expect("ed25519 is registered");
    assert_eq!(
        fixture_payload.len(),
        row.signature_len,
        "the fixture really is the registered length, or this test proves nothing"
    );

    let fixture = DetachedSignature::from_parts(
        ED25519_CODE_POINT,
        genuine.purpose(),
        genuine.epoch(),
        *genuine.key_commitment(),
        *genuine.declared_verifying_key().as_bytes(),
        fixture_payload,
    );

    assert_eq!(
        fixture.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Err(SignatureError::Invalid),
        "a constant-byte fixture must not verify"
    );
    assert_eq!(
        genuine.verify_with(
            &key.verifying_key(),
            IdentityDomain::RepositoryCapsule,
            schema(),
            BODY
        ),
        Ok(()),
        "the genuine signature must still verify, or the refusal above is vacuous"
    );
}
