//! Descriptors are claims about `fgit-codec`'s types. This is what checks them.
//!
//! Rust has no reflection, so a descriptor cannot be compared to a struct
//! field-by-field at runtime. What it CAN be compared to is the bytes that
//! struct encodes to. Each test here encodes a real canonical body through
//! `CanonicalBody::write_payload`, then walks the payload consuming exactly
//! what the descriptor says each field occupies, and requires the walk to land
//! precisely on the end.
//!
//! That is a strong check rather than a shape check: a wrong field order, a
//! wrong width, a missing field, or an extra one all leave the cursor in the
//! wrong place, and the run either overruns the buffer or finishes with bytes
//! left over. Both are failures with the offending field named.

use fgit_codec::harness as support;
use fgit_codec::{CanonicalBody, Encoder};
use fgit_schema::descriptor::{Cardinality, FieldType, SchemaDescriptor};
use fgit_schema::registry;

/// Consumes the bytes one field occupies, returning the new offset.
///
/// Every arm mirrors an encoder method in `fgit-codec/src/writer.rs`; the
/// mapping is the substance of the claim a descriptor makes.
fn consume(ty: FieldType, payload: &[u8], mut at: usize, field: &str) -> usize {
    /// Reads a `u32` length prefix and returns it with the new offset.
    fn length_prefix(payload: &[u8], at: usize, field: &str) -> (usize, usize) {
        assert!(
            at + 4 <= payload.len(),
            "{field}: payload ends inside a u32 length prefix at {at}"
        );
        let bytes: [u8; 4] = payload[at..at + 4].try_into().expect("four bytes");
        (u32::from_be_bytes(bytes) as usize, at + 4)
    }

    match ty {
        FieldType::Scalar(width) => at + width.byte_len() as usize,
        // write_opaque_id pushes the 16 bytes with no prefix.
        FieldType::OpaqueId => at + 16,
        // write_scalar(u16) for the code point.
        FieldType::CodePoint { .. } => at + 2,
        // write_digest: u16 algorithm, then length-prefixed body.
        FieldType::Digest => {
            at += 2;
            let (len, next) = length_prefix(payload, at, field);
            next + len
        }
        // write_internal_object_id: u16 algorithm, length-prefixed domain,
        // u16 codec major, u16 codec minor, length-prefixed digest.
        FieldType::DerivedId { .. } => {
            at += 2;
            let (domain_len, next) = length_prefix(payload, at, field);
            at = next + domain_len + 4;
            let (digest_len, next) = length_prefix(payload, at, field);
            next + digest_len
        }
        // write_schema_id: length-prefixed family, u16 major, u16 minor.
        FieldType::SchemaId => {
            let (family_len, next) = length_prefix(payload, at, field);
            next + family_len + 4
        }
        // write_text: length-prefixed UTF-8.
        FieldType::Text { .. } => {
            let (len, next) = length_prefix(payload, at, field);
            next + len
        }
    }
}

/// Walks `payload` with `schema` and asserts the walk consumes it exactly.
fn assert_describes(schema: &SchemaDescriptor, payload: &[u8]) {
    let mut at = 0_usize;
    for field in schema.fields {
        assert!(
            at <= payload.len(),
            "{}: cursor {at} is past the {}-byte payload before field {}",
            schema.family,
            payload.len(),
            field.name
        );
        if field.cardinality == Cardinality::Optional {
            // write_option pushes a single 0x00 / 0x01 tag byte first.
            assert!(
                at < payload.len(),
                "{}: payload ends where the presence tag for {} should be",
                schema.family,
                field.name
            );
            let tag = payload[at];
            assert!(
                tag == 0 || tag == 1,
                "{}: presence tag for {} is {tag:#04x}, not 0x00 or 0x01",
                schema.family,
                field.name
            );
            at += 1;
            if tag == 0 {
                continue;
            }
        }
        at = consume(field.ty, payload, at, field.name);
    }
    assert_eq!(
        at,
        payload.len(),
        "{}: the descriptor accounts for {at} bytes but the body encodes {}. \
         A leftover means a missing or too-narrow field; an overrun means an \
         extra or too-wide one.",
        schema.family,
        payload.len()
    );
}

/// Encodes a body's payload without the frame.
fn payload_of<B: CanonicalBody>(body: &B) -> Vec<u8> {
    let mut encoder = Encoder::new();
    body.write_payload(&mut encoder)
        .expect("the fixture encodes");
    encoder.into_bytes()
}

/// Asserts the descriptor's schema identity matches the real body's constants.
fn assert_identity<B: CanonicalBody>(schema: &SchemaDescriptor) {
    assert_eq!(
        schema.family,
        B::SCHEMA_FAMILY.as_str(),
        "descriptor family disagrees with CanonicalBody::SCHEMA_FAMILY"
    );
    assert_eq!(schema.major, B::SCHEMA_MAJOR, "major disagrees");
    assert_eq!(schema.minor, B::SCHEMA_MINOR, "minor disagrees");
    assert_eq!(
        schema.domain,
        B::DOMAIN.as_str(),
        "descriptor domain disagrees with CanonicalBody::DOMAIN"
    );
}

#[test]
fn the_txn_seal_descriptor_accounts_for_every_byte_the_body_encodes() {
    assert_identity::<fgit_codec::schema::TransactionSealBody>(&registry::TXN_SEAL);
    assert_describes(
        &registry::TXN_SEAL,
        &payload_of(&support::transaction_seal()),
    );
}

#[test]
fn the_commit_record_descriptor_accounts_for_every_byte_the_body_encodes() {
    assert_identity::<fgit_codec::schema::RepositoryCommitRecord>(
        &registry::REPOSITORY_COMMIT_RECORD,
    );
    assert_describes(
        &registry::REPOSITORY_COMMIT_RECORD,
        &payload_of(&support::commit_record()),
    );
}

#[test]
fn the_refusal_record_descriptor_accounts_for_every_byte_the_body_encodes() {
    assert_identity::<fgit_codec::schema::RefusalRecordBody>(&registry::REFUSAL_RECORD);
    assert_describes(
        &registry::REFUSAL_RECORD,
        &payload_of(&support::refusal_record()),
    );
}

#[test]
fn the_authority_head_descriptor_accounts_for_both_the_genesis_and_advanced_heads() {
    assert_identity::<fgit_codec::schema::RepositoryAuthorityHeadBody>(&registry::AUTHORITY_HEAD);
    // Two fixtures on purpose. The genesis head leaves every optional absent
    // and the advanced head fills them, so between them each presence tag is
    // walked down both branches. A descriptor that mis-declared a required
    // field as optional would pass on one and fail on the other.
    assert_describes(
        &registry::AUTHORITY_HEAD,
        &payload_of(&support::genesis_head()),
    );
    assert_describes(
        &registry::AUTHORITY_HEAD,
        &payload_of(&support::advanced_head()),
    );
}

#[test]
fn the_walker_would_notice_a_wrong_descriptor() {
    // The tests above prove the descriptors agree with the bodies. They do NOT
    // prove the walker could tell if they disagreed, and a checker that cannot
    // fail is not a checker. So: truncate a real payload by one byte and
    // require the walk to reject it.
    let payload = payload_of(&support::transaction_seal());
    let truncated = &payload[..payload.len() - 1];
    let outcome = std::panic::catch_unwind(|| {
        assert_describes(&registry::TXN_SEAL, truncated);
    });
    assert!(
        outcome.is_err(),
        "the walker accepted a payload one byte short of the encoding, so it \
         cannot distinguish a correct descriptor from a wrong one"
    );

    // Permitted twin: the untruncated payload still passes, so the rejection
    // above is about the missing byte rather than the walker refusing anything.
    assert_describes(&registry::TXN_SEAL, &payload);
}

#[test]
fn every_described_family_resolves_and_the_undescribed_one_refuses_by_name() {
    for schema in registry::DESCRIBED {
        let found = registry::descriptor_for(schema.family).expect("a described family resolves");
        assert_eq!(found.family, schema.family);
    }
    // decision-batch is a real canonical body that is deliberately not
    // described. It must refuse with the reason rather than read as absent.
    let refusal = registry::descriptor_for("decision-batch")
        .expect_err("decision-batch is not describable by this format");
    assert_eq!(refusal.kind(), "shape_unsupported");
    // ... and an invented family is a different refusal, so "not described"
    // and "does not exist" stay distinguishable.
    let missing = registry::descriptor_for("no-such-family").expect_err("unknown family");
    assert_eq!(missing.kind(), "family_unregistered");
}
