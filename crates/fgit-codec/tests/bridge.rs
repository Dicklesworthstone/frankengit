// The production identity bridge.
//
// One clause in an earlier version of this comment was false and CloudyTiger
// caught it: `an_identity_this_crate_produces_is_one_fgit_crypto_verifies`
// cannot detect preimage-framing drift, because both the construction and the
// verification route through `fgit-crypto`'s framing. Change that framing and
// both move together and the test still passes.
//
// What that test does pin is that `fgit-codec` hands over the *payload* and
// not the frame — the defect fixed at 158c899, now regression-locked — plus
// domain separation, rejection against a different body, and the
// unregistered-domain refusal.
//
// The framing cross-check is a separate assertion below
// (`the_corpus_preimage_framing_matches_the_production_framing`), and it is
// the one that actually bites: it compares the corpus's own re-implementation
// of the framing against the production one. Those are the two independent
// implementations, so that is where drift can hide.

use fgit_codec::harness as support;

use fgit_codec::attest::{BodyIdentity, SignedEnvelopeBody};
use fgit_codec::schema::{RepositoryCommitRecord, TransactionSealBody};
use fgit_codec::{
    CODEC_VERSION, CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, body_id,
    body_id_of_frame_as, canonical_body_bytes, encode_body,
};
use fgit_crypto::{IdentityDomain, verify_internal_object_id};
use fgit_types::{DomainTag, RefusalCode};

#[test]
fn an_identity_this_crate_produces_is_one_fgit_crypto_verifies() {
    // `fgit-codec` decides the canonical body bytes; `fgit-crypto` decides the
    // preimage and the digest. This pins that the bytes handed over are the
    // payload rather than the frame, and that the identity round-trips through
    // verification. It does NOT pin the framing itself — see the module
    // comment and the framing test below.
    let seal = support::transaction_seal();
    let identity = body_id(&CryptoBodyIdentity, &seal).expect("a registered domain identifies");
    let body = canonical_body_bytes(&seal).expect("encodes");

    let domain = IdentityDomain::from_tag(TransactionSealBody::DOMAIN.as_str())
        .expect("the seal domain is registered");
    verify_internal_object_id(
        &identity,
        domain,
        TransactionSealBody::schema_id(),
        CODEC_VERSION,
        &body,
    )
    .expect("fgit-crypto must verify an identity fgit-codec produced");

    // And it must reject the same identity against a different body.
    let other = canonical_body_bytes(&support::commit_record()).expect("encodes");
    assert!(
        verify_internal_object_id(
            &identity,
            domain,
            TransactionSealBody::schema_id(),
            CODEC_VERSION,
            &other,
        )
        .is_err(),
        "an identity must not verify against another body"
    );
}

#[test]
fn the_bridge_separates_domains() {
    let seal_body = canonical_body_bytes(&support::transaction_seal()).expect("encodes");
    let as_seal = CryptoBodyIdentity
        .identify(
            TransactionSealBody::DOMAIN,
            TransactionSealBody::schema_id(),
            CODEC_VERSION,
            &seal_body,
        )
        .expect("registered");
    let as_record = CryptoBodyIdentity
        .identify(
            RepositoryCommitRecord::DOMAIN,
            RepositoryCommitRecord::schema_id(),
            CODEC_VERSION,
            &seal_body,
        )
        .expect("registered");
    assert_ne!(
        as_seal, as_record,
        "identical bytes in two domains must be two identities"
    );
    assert_ne!(as_seal.digest(), as_record.digest());
}

#[test]
fn an_unregistered_domain_is_refused_and_a_registered_one_proceeds() {
    let body = canonical_body_bytes(&support::transaction_seal()).expect("encodes");
    let unregistered = DomainTag::from_static("frankengit/not-a-registered-domain/v1");
    let refusal = CryptoBodyIdentity
        .identify(
            unregistered,
            TransactionSealBody::schema_id(),
            CODEC_VERSION,
            &body,
        )
        .expect_err("an identity under an unregistered domain is unverifiable");
    assert!(matches!(
        refusal,
        CodecRefusal::IdentityDomainUnregistered { .. }
    ));
    assert_eq!(refusal.refusal_code(), RefusalCode::SchemaUnsupported);

    // Permitted counterpart: the same body under its own registered domain.
    assert!(
        CryptoBodyIdentity
            .identify(
                TransactionSealBody::DOMAIN,
                TransactionSealBody::schema_id(),
                CODEC_VERSION,
                &body,
            )
            .is_ok()
    );
}

#[test]
fn a_signature_does_not_move_the_production_identity_either() {
    // The corpus proves this under the corpus function; this proves it under
    // the real one, which is the claim that actually matters.
    let seal = support::transaction_seal();
    let direct = body_id(&CryptoBodyIdentity, &seal).expect("identifies");

    let mut envelope = SignedEnvelopeBody::seal(&seal).expect("seals");
    let unsigned = envelope
        .carried_body_id(&CryptoBodyIdentity, DecodeLimits::DEFAULT)
        .expect("identifies");
    assert_eq!(direct, unsigned);

    envelope
        .attach(
            fgit_codec::DetachedSignature {
                scheme: fgit_codec::SignatureSchemeId::try_new(1).expect("nonzero"),
                key_id: b"key-a".to_vec(),
                body_id: direct,
                signature: vec![0xa0; 64],
            },
            DecodeLimits::DEFAULT,
        )
        .expect("a signature in the carried body's domain attaches");
    let signed = envelope
        .carried_body_id(&CryptoBodyIdentity, DecodeLimits::DEFAULT)
        .expect("identifies");
    assert_eq!(
        unsigned, signed,
        "attaching a signature must not move the body's identity"
    );

    // The envelope's own bytes did change, so the signature is observable.
    let bare = SignedEnvelopeBody::seal(&seal).expect("seals");
    assert_ne!(
        encode_body(&envelope).expect("encodes"),
        encode_body(&bare).expect("encodes")
    );
}

#[test]
fn the_corpus_preimage_framing_matches_the_production_framing() {
    // The corpus re-implements the preimage framing on purpose, so the golden
    // identities cross-check that framing rather than copy it. The cost of
    // that choice is drift: two implementations that never meet. This is
    // where they meet.
    //
    // `fgit-crypto` cannot host this — it must not depend on `fgit-codec`, and
    // that direction stays closed — so it lives here.
    for (domain, schema) in [
        (
            TransactionSealBody::DOMAIN,
            TransactionSealBody::schema_id(),
        ),
        (
            RepositoryCommitRecord::DOMAIN,
            RepositoryCommitRecord::schema_id(),
        ),
        (SignedEnvelopeBody::DOMAIN, SignedEnvelopeBody::schema_id()),
    ] {
        let registered =
            IdentityDomain::from_tag(domain.as_str()).expect("body domains are registered");
        for body in [
            &b""[..],
            b"one",
            &canonical_body_bytes(&support::transaction_seal()).expect("encodes"),
        ] {
            assert_eq!(
                support::identity_preimage(domain, schema, body),
                fgit_crypto::internal_id_preimage(registered, schema, body),
                "the corpus framing and the production framing disagree for {domain}"
            );
        }
    }
}

#[test]
fn the_corpus_algorithm_slot_stays_inside_the_range_fgit_crypto_reserved() {
    // The corpus identity function is deliberately non-cryptographic and lives
    // at a slot fgit-crypto has reserved for harness use. Asserting the two
    // agree here means neither side can drift into the other's range without
    // a test failing, rather than the reservation living only in two mails.
    assert!(
        fgit_crypto::CORPUS_RESERVED_CODE_POINTS.contains(&support::CORPUS_ALGORITHM_CODE_POINT),
        "the corpus slot {:#06x} escaped the reserved range {:#06x}..={:#06x}",
        support::CORPUS_ALGORITHM_CODE_POINT,
        fgit_crypto::CORPUS_RESERVED_CODE_POINTS.start(),
        fgit_crypto::CORPUS_RESERVED_CODE_POINTS.end(),
    );
    // And no registered construction may sit there.
    assert!(
        fgit_crypto::DigestAlgorithm::ALL
            .iter()
            .all(|algorithm| !fgit_crypto::CORPUS_RESERVED_CODE_POINTS
                .contains(&algorithm.code_point())),
        "a production algorithm landed in the corpus-reserved range"
    );
}

#[test]
fn every_body_domain_this_crate_uses_is_registered() {
    // A body whose domain has no registry row would be unidentifiable at
    // runtime; catching that here rather than at first use is the point.
    for tag in [
        TransactionSealBody::DOMAIN,
        RepositoryCommitRecord::DOMAIN,
        fgit_codec::RepositoryDecisionBatchBody::DOMAIN,
        fgit_codec::RepositoryAuthorityHeadBody::DOMAIN,
        fgit_codec::RefusalRecordBody::DOMAIN,
        SignedEnvelopeBody::DOMAIN,
    ] {
        assert!(
            IdentityDomain::from_tag(tag.as_str()).is_some(),
            "body domain {tag} has no fgit-crypto registry row"
        );
    }
}

#[test]
fn a_registered_domain_on_the_wrong_body_type_is_refused_when_the_caller_knows() {
    // The hole neither of fgit-crypto's refusals can reach: the tag is
    // registered and the digest is right, but the frame holds a different body
    // than the caller expects. Untyped identification cannot see it because it
    // never learns what was expected.
    let record_frame = encode_body(&support::commit_record()).expect("encodes");

    // Untyped: succeeds, because the frame's own domain is perfectly valid.
    let untyped =
        fgit_codec::body_id_of_frame(&CryptoBodyIdentity, &record_frame, DecodeLimits::DEFAULT)
            .expect("a commit record identifies as a commit record");
    assert_eq!(
        untyped.domain(),
        RepositoryCommitRecord::DOMAIN,
        "untyped identification reports what the frame says it is"
    );

    // Typed as the wrong body: refused.
    let refusal = body_id_of_frame_as::<TransactionSealBody, _>(
        &CryptoBodyIdentity,
        &record_frame,
        DecodeLimits::DEFAULT,
    )
    .expect_err("a commit record must not be identified as a seal");
    assert!(matches!(refusal, CodecRefusal::DomainUnexpected { .. }));
    assert_eq!(
        refusal.refusal_code(),
        fgit_types::RefusalCode::SchemaUnsupported
    );

    // Permitted counterpart: typed as what it actually is.
    let typed = body_id_of_frame_as::<RepositoryCommitRecord, _>(
        &CryptoBodyIdentity,
        &record_frame,
        DecodeLimits::DEFAULT,
    )
    .expect("a commit record identifies as a commit record");
    assert_eq!(
        typed, untyped,
        "pinning the type must not change the identity"
    );
}

#[test]
fn an_envelope_carrying_the_wrong_body_type_is_refused_when_the_caller_knows() {
    let envelope = SignedEnvelopeBody::seal(&support::commit_record()).expect("seals");

    assert!(
        envelope
            .carried_body_id_as::<TransactionSealBody, _>(
                &CryptoBodyIdentity,
                DecodeLimits::DEFAULT
            )
            .is_err(),
        "an envelope carrying a commit record must not yield a seal identity"
    );
    let carried = envelope
        .carried_body_id_as::<RepositoryCommitRecord, _>(&CryptoBodyIdentity, DecodeLimits::DEFAULT)
        .expect("the carried type is a commit record");
    assert_eq!(
        carried,
        body_id(&CryptoBodyIdentity, &support::commit_record()).expect("identifies"),
        "the carried identity must equal the body's own identity"
    );
}
