// The production identity bridge.
//
// These are the cross-crate assertions the golden corpus deliberately cannot
// make: the corpus re-implements the preimage framing so it cross-checks the
// shape, but only a test that runs both crates can prove that bytes produced
// here yield an identity `fgit-crypto` itself verifies.

use fgit_codec::harness as support;

use fgit_codec::attest::{BodyIdentity, SignedEnvelopeBody};
use fgit_codec::schema::{RepositoryCommitRecord, TransactionSealBody};
use fgit_codec::{
    CODEC_VERSION, CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, body_id,
    canonical_body_bytes, encode_body,
};
use fgit_crypto::{IdentityDomain, verify_internal_object_id};
use fgit_types::{DomainTag, RefusalCode};

#[test]
fn an_identity_this_crate_produces_is_one_fgit_crypto_verifies() {
    // The binding that closes the seam. `fgit-codec` decides the canonical
    // body bytes; `fgit-crypto` decides the preimage and the digest. If either
    // side drifts, this fails.
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
