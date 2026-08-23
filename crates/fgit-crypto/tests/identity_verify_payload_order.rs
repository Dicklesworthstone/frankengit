//! `verify_internal_object_id`: what its refusals SAY, and which one wins.
//!
//! This is the checked path for an attached identity — the crate's own doc notes
//! that the `fgit-types` shell "can hold any digest bytes under any domain tag",
//! so a body arriving with an identity is trustworthy only once this function
//! has agreed with it. It runs four guards in sequence:
//!
//! ```text
//! 1  algorithm     -> AlgorithmMismatch    { expected, actual }
//! 2  domain        -> DomainMismatch       { expected, actual }
//! 3  codec version -> CodecVersionMismatch { expected, actual }
//! 4  digest        -> DigestMismatch       { domain, expected, actual }
//! ```
//!
//! # What was already covered, and what was not
//!
//! `identity_boundaries.rs` and `domain_sweep.rs` already destructure and assert
//! the payloads of guards 1 and 2 — this file is not a claim that the crate is
//! untested. Guards 3 and 4 were asserted only as
//! `matches!(refusal, ..::DigestMismatch { .. })`, which discards every field.
//!
//! That matters most for guard 4, the only one carrying a **domain** and the one
//! stating the actual cryptographic verdict. Two defects were invisible:
//!
//! - **`expected` and `actual` swapped.** The single raise site builds them from
//!   two different sources — `expected` is recomputed from the supplied inputs,
//!   `actual` is what the identity carries — and `Display` prints "expected
//!   {expected}, found {actual}". Swap them and the refusal tells the caller the
//!   opposite of what happened, with every existing assertion still passing.
//! - **A wrong `domain` tag**, the domain-separation label §5.2 makes
//!   fail-closed.
//!
//! # Order
//!
//! No existing input fails two of the four guards, so the sequence was
//! unpinned. Order is observable only from an input that breaks more than one
//! rule, and each pair below is built to break exactly two.

use fgit_crypto::{
    CodecVersion, DigestAlgorithm, IdentityDomain, InternalIdentityError, InternalObjectId,
    SchemaFamily, SchemaId, internal_object_id, lowercase_hex, verify_internal_object_id,
};

const CODEC: CodecVersion = CodecVersion::new(1, 0);
const ORIGINAL: &[u8] = b"original body";
const TAMPERED: &[u8] = b"tampered body";

fn schema() -> SchemaId {
    SchemaId::new(
        SchemaFamily::try_new(b"frankengit.canonical-body").expect("a canonical test family"),
        1,
        0,
    )
}

/// Guard 4's payload: which digest lands in which field.
///
/// Both figures are computed independently here — `expected` from an identity
/// built over the bytes actually supplied to the verifier, `actual` from the
/// identity under test — so a swap at the raise site fails this test. The
/// crate's own `lowercase_hex` is used deliberately: the claim is about field
/// assignment, not hex formatting, and rolling a second formatter would risk
/// failing on a cosmetic difference instead.
#[test]
fn a_digest_mismatch_reports_the_recomputed_digest_as_expected_and_the_carried_one_as_actual() {
    let domain = IdentityDomain::ObjectEnvelope;
    let carried = internal_object_id(domain, schema(), CODEC, ORIGINAL);
    let recomputed = internal_object_id(domain, schema(), CODEC, TAMPERED);

    let refusal = verify_internal_object_id(&carried, domain, schema(), CODEC, TAMPERED)
        .expect_err("an identity over other bytes must not verify");

    match refusal {
        InternalIdentityError::DigestMismatch {
            domain: reported,
            expected,
            actual,
        } => {
            assert_eq!(
                expected,
                lowercase_hex(recomputed.digest().as_bytes()),
                "`expected` must be the digest recomputed from the supplied inputs",
            );
            assert_eq!(
                actual,
                lowercase_hex(carried.digest().as_bytes()),
                "`actual` must be the digest the identity carries",
            );
            assert_ne!(expected, actual, "the fixture must really disagree");
            assert_eq!(
                reported,
                domain.tag(),
                "the refusal names the domain it was verified under",
            );
        }
        other => panic!("expected a digest mismatch, got {other}"),
    }
}

/// Guard 3's payload, asserted rather than discarded.
#[test]
fn a_codec_version_mismatch_reports_the_requested_and_the_carried_version() {
    let domain = IdentityDomain::ObjectEnvelope;
    let identity = internal_object_id(domain, schema(), CODEC, ORIGINAL);
    let requested = CodecVersion::new(2, 0);

    let refusal = verify_internal_object_id(&identity, domain, schema(), requested, ORIGINAL)
        .expect_err("a codec-version disagreement must not verify");

    match refusal {
        InternalIdentityError::CodecVersionMismatch { expected, actual } => {
            assert_eq!(expected, requested, "`expected` is the version asked for");
            assert_eq!(
                actual, CODEC,
                "`actual` is the version the identity carries"
            );
        }
        other => panic!("expected a codec-version mismatch, got {other}"),
    }
}

/// Guard 1 precedes guard 2.
#[test]
fn the_algorithm_check_precedes_the_domain_check() {
    let domain = IdentityDomain::RefTransaction;
    let honest = internal_object_id(domain, schema(), CODEC, ORIGINAL);

    // Wrong algorithm AND wrong domain, in one identity.
    let doubly_wrong = InternalObjectId::new(
        DigestAlgorithm::Sha1.id(),
        IdentityDomain::ObjectEnvelope.domain_tag(),
        CODEC,
        *honest.digest(),
    );

    assert!(
        matches!(
            verify_internal_object_id(&doubly_wrong, domain, schema(), CODEC, ORIGINAL),
            Err(InternalIdentityError::AlgorithmMismatch { .. })
        ),
        "the algorithm guard runs first",
    );

    // The domain fault really is present: with the algorithm corrected it is
    // what refuses.
    let only_domain_wrong = InternalObjectId::new(
        domain.algorithm().id(),
        IdentityDomain::ObjectEnvelope.domain_tag(),
        CODEC,
        *honest.digest(),
    );
    assert!(matches!(
        verify_internal_object_id(&only_domain_wrong, domain, schema(), CODEC, ORIGINAL),
        Err(InternalIdentityError::DomainMismatch { .. })
    ));
}

/// Guard 2 precedes guard 3.
#[test]
fn the_domain_check_precedes_the_codec_version_check() {
    let domain = IdentityDomain::RefTransaction;
    let honest = internal_object_id(domain, schema(), CODEC, ORIGINAL);
    let stale_codec = CodecVersion::new(2, 0);

    let doubly_wrong = InternalObjectId::new(
        domain.algorithm().id(),
        IdentityDomain::ObjectEnvelope.domain_tag(),
        CODEC,
        *honest.digest(),
    );

    assert!(
        matches!(
            verify_internal_object_id(&doubly_wrong, domain, schema(), stale_codec, ORIGINAL),
            Err(InternalIdentityError::DomainMismatch { .. })
        ),
        "the domain guard runs before the codec-version guard",
    );

    // The codec fault really is present on its own.
    assert!(matches!(
        verify_internal_object_id(&honest, domain, schema(), stale_codec, ORIGINAL),
        Err(InternalIdentityError::CodecVersionMismatch { .. })
    ));
}

/// Guard 3 precedes guard 4.
#[test]
fn the_codec_version_check_precedes_the_digest_check() {
    let domain = IdentityDomain::ObjectEnvelope;
    let carried = internal_object_id(domain, schema(), CODEC, ORIGINAL);
    let stale_codec = CodecVersion::new(2, 0);

    assert!(
        matches!(
            verify_internal_object_id(&carried, domain, schema(), stale_codec, TAMPERED),
            Err(InternalIdentityError::CodecVersionMismatch { .. })
        ),
        "the codec-version guard runs before the digest is recomputed",
    );

    // The digest fault really is present on its own.
    assert!(matches!(
        verify_internal_object_id(&carried, domain, schema(), CODEC, TAMPERED),
        Err(InternalIdentityError::DigestMismatch { .. })
    ));
}

/// The permitted twin. Without it, a verifier that refused everything would
/// satisfy every expectation above.
#[test]
fn an_identity_agreeing_on_all_four_fields_verifies() {
    for domain in [
        IdentityDomain::ObjectEnvelope,
        IdentityDomain::RefTransaction,
    ] {
        let identity = internal_object_id(domain, schema(), CODEC, ORIGINAL);
        verify_internal_object_id(&identity, domain, schema(), CODEC, ORIGINAL)
            .expect("an identity over exactly these inputs must verify");
    }
}
