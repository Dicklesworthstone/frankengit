// The frame-header chain, and the fact that there are two copies of it.
//
// `decode_body` (wire.rs) and `body_id_of_frame_as` (attest.rs) each validate an
// incoming frame header against the body type the caller named, and each runs
// the same three guards in the same written order:
//
//     domain  != B::DOMAIN         -> DomainUnexpected
//     family  != B::SCHEMA_FAMILY  -> SchemaFamilyUnexpected
//     major   != B::SCHEMA_MAJOR   -> SchemaMajorUnsupported
//
// Two things here had no test.
//
// The middle guard was driven by nothing at either site. Every `raw_frame` in
// the crate's suite passes the correct family, so no input ever reached it. It
// was not absent from the suite, which is what made it easy to miss: another
// test CONSTRUCTS `CodecRefusal::schema_family_unexpected(..)` to check its
// protocol code and Display. That is a constructor twin — it proves the refusal
// renders, not that any frame reaches it.
//
// And nothing pinned the two chains against each other. They are duplicated
// logic over one wire contract, and AGENTS.md §6 makes refusal behaviour a
// compatibility semantic: the same malformed frame must get the same answer
// whether the caller is decoding a body or deriving an identity. If one chain
// were reordered, every existing test would stay green.
//
// Order is only observable from an input that fails MORE THAN ONE guard at
// once, so the order tests below deliberately build frames that are wrong twice.

use fgit_codec::harness as support;

use fgit_codec::schema::{RepositoryCommitRecord, TransactionSealBody};
use fgit_codec::wire::{CODEC_MAJOR, FRAME_MAGIC};
use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, Encoder, body_id_of_frame_as,
    decode_body,
};
use fgit_types::{DomainTag, SchemaFamily, SchemaId};

fn seal_payload() -> Vec<u8> {
    let mut payload = Encoder::new();
    support::transaction_seal()
        .write_payload(&mut payload)
        .expect("the fixture encodes");
    payload.into_bytes()
}

/// A frame carrying a real seal payload under whatever header is asked for.
fn frame_with(domain: DomainTag, family: SchemaFamily, major: u16) -> Vec<u8> {
    let mut frame = Encoder::new();
    frame.write_raw(&FRAME_MAGIC);
    frame.write_scalar(CODEC_MAJOR);
    frame.write_scalar(0_u16);
    frame.write_domain_tag(domain).expect("label fits");
    frame
        .write_schema_id(SchemaId::new(
            family,
            major,
            TransactionSealBody::SCHEMA_MINOR,
        ))
        .expect("label fits");
    frame
        .write_bytes("payload", &seal_payload())
        .expect("payload fits");
    frame.into_bytes()
}

/// A header correct in all three fields.
fn well_formed() -> Vec<u8> {
    frame_with(
        TransactionSealBody::DOMAIN,
        TransactionSealBody::SCHEMA_FAMILY,
        TransactionSealBody::SCHEMA_MAJOR,
    )
}

const fn wrong_family() -> SchemaFamily {
    SchemaFamily::from_static("rcr")
}

/// Surface one: decoding the body.
fn refused_by_decode(frame: &[u8]) -> CodecRefusal {
    decode_body::<TransactionSealBody>(frame, DecodeLimits::DEFAULT)
        .expect_err("the header does not describe a transaction seal")
}

/// Surface two: deriving an identity while pinned to the same body type.
fn refused_by_identify(frame: &[u8]) -> CodecRefusal {
    body_id_of_frame_as::<TransactionSealBody, _>(&CryptoBodyIdentity, frame, DecodeLimits::DEFAULT)
        .expect_err("the header does not describe a transaction seal")
}

#[test]
fn a_header_declaring_another_family_is_refused_when_the_body_is_decoded() {
    let frame = frame_with(
        TransactionSealBody::DOMAIN,
        wrong_family(),
        TransactionSealBody::SCHEMA_MAJOR,
    );
    assert_eq!(
        refused_by_decode(&frame),
        CodecRefusal::schema_family_unexpected(TransactionSealBody::SCHEMA_FAMILY, wrong_family())
    );
}

#[test]
fn a_header_declaring_another_family_is_refused_when_an_identity_is_derived() {
    let frame = frame_with(
        TransactionSealBody::DOMAIN,
        wrong_family(),
        TransactionSealBody::SCHEMA_MAJOR,
    );
    assert_eq!(
        refused_by_identify(&frame),
        CodecRefusal::schema_family_unexpected(TransactionSealBody::SCHEMA_FAMILY, wrong_family())
    );
}

/// The two surfaces are asserted against EACH OTHER, not against two separately
/// written expectations. A divergence cannot be absorbed by updating one
/// literal, which is the failure mode duplicated logic actually has.
#[test]
fn both_surfaces_answer_identically_for_the_same_malformed_frame() {
    let cases = [
        (
            "family alone",
            frame_with(
                TransactionSealBody::DOMAIN,
                wrong_family(),
                TransactionSealBody::SCHEMA_MAJOR,
            ),
        ),
        (
            "domain and family together",
            frame_with(
                RepositoryCommitRecord::DOMAIN,
                wrong_family(),
                TransactionSealBody::SCHEMA_MAJOR,
            ),
        ),
        (
            "family and major together",
            frame_with(
                TransactionSealBody::DOMAIN,
                wrong_family(),
                TransactionSealBody::SCHEMA_MAJOR + 1,
            ),
        ),
    ];
    for (what, frame) in cases {
        assert_eq!(
            refused_by_decode(&frame),
            refused_by_identify(&frame),
            "decoding and identifying disagree about a frame wrong in {what}"
        );
    }
}

#[test]
fn a_frame_wrong_in_domain_and_family_reports_the_domain_on_both_surfaces() {
    let frame = frame_with(
        RepositoryCommitRecord::DOMAIN,
        wrong_family(),
        TransactionSealBody::SCHEMA_MAJOR,
    );
    let expected = CodecRefusal::domain_unexpected(
        TransactionSealBody::DOMAIN,
        RepositoryCommitRecord::DOMAIN,
    );
    assert_eq!(refused_by_decode(&frame), expected);
    assert_eq!(refused_by_identify(&frame), expected);
}

#[test]
fn a_frame_wrong_in_family_and_major_reports_the_family_on_both_surfaces() {
    let frame = frame_with(
        TransactionSealBody::DOMAIN,
        wrong_family(),
        TransactionSealBody::SCHEMA_MAJOR + 1,
    );
    let expected =
        CodecRefusal::schema_family_unexpected(TransactionSealBody::SCHEMA_FAMILY, wrong_family());
    assert_eq!(refused_by_decode(&frame), expected);
    assert_eq!(refused_by_identify(&frame), expected);
}

/// The permitted twin. Without it, a chain that refused every frame would
/// satisfy every expectation above.
#[test]
fn a_header_matching_on_all_three_fields_is_accepted_by_both_surfaces() {
    let frame = well_formed();
    let decoded = decode_body::<TransactionSealBody>(&frame, DecodeLimits::DEFAULT)
        .expect("a well-formed seal frame decodes");
    assert_eq!(decoded, support::transaction_seal());

    body_id_of_frame_as::<TransactionSealBody, _>(
        &CryptoBodyIdentity,
        &frame,
        DecodeLimits::DEFAULT,
    )
    .expect("a well-formed seal frame identifies");
}
