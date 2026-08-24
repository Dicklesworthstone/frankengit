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
use fgit_schema::descriptor::{Cardinality, FieldDescriptor, FieldType, SchemaDescriptor};
use fgit_schema::registry;

/// Consumes the bytes one field's VALUE occupies, returning the new offset.
///
/// Every arm mirrors an encoder method in `fgit-codec`'s writer; the mapping is
/// the substance of the claim a descriptor makes.
fn consume(ty: FieldType, payload: &[u8], mut at: usize, field: &str) -> usize {
    /// Reads a `u32` length or count prefix and returns it with the new offset.
    fn prefix(payload: &[u8], at: usize, field: &str) -> (usize, usize) {
        assert!(
            at + 4 <= payload.len(),
            "{field}: payload ends inside a u32 prefix at {at}"
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
            let (len, next) = prefix(payload, at, field);
            next + len
        }
        // write_internal_object_id: u16 algorithm, length-prefixed domain,
        // u16 codec major, u16 codec minor, length-prefixed digest.
        FieldType::DerivedId { .. } => {
            at += 2;
            let (domain_len, next) = prefix(payload, at, field);
            at = next + domain_len + 4;
            let (digest_len, next) = prefix(payload, at, field);
            next + digest_len
        }
        // write_schema_id: length-prefixed family, u16 major, u16 minor.
        FieldType::SchemaId => {
            let (family_len, next) = prefix(payload, at, field);
            next + family_len + 4
        }
        // write_text: length-prefixed UTF-8.
        FieldType::Text { .. } => {
            let (len, next) = prefix(payload, at, field);
            next + len
        }
        // A referenced structure is inlined: its fields, in order, no framing.
        FieldType::Structure { name } => {
            let fields = registry::structure_fields(name)
                .unwrap_or_else(|| panic!("{field}: structure {name} is not registered"));
            walk(fields, payload, at, name)
        }
        // write_raw_byte(discriminant), then that variant's fields. The byte is
        // NOT length-prefixed, so an unknown discriminant is unrecoverable --
        // which is why the walker must fail rather than skip.
        FieldType::Union { name } => {
            let union = registry::union_for(name)
                .unwrap_or_else(|| panic!("{field}: union {name} is not registered"));
            assert!(
                at < payload.len(),
                "{field}: payload ends where the {name} discriminant should be"
            );
            let discriminant = payload[at];
            let variant = union.variant(discriminant).unwrap_or_else(|| {
                panic!("{field}: {name} has no variant for discriminant {discriminant}")
            });
            walk(variant.fields, payload, at + 1, variant.name)
        }
    }
}

/// Walks a field list, returning the offset just past the last field.
fn walk(fields: &[FieldDescriptor], payload: &[u8], mut at: usize, owner: &str) -> usize {
    for field in fields {
        assert!(
            at <= payload.len(),
            "{owner}: cursor {at} is past the {}-byte payload before field {}",
            payload.len(),
            field.name
        );
        match field.cardinality {
            Cardinality::Required => at = consume(field.ty, payload, at, field.name),
            Cardinality::Optional => {
                // write_option pushes a single 0x00 / 0x01 tag byte first.
                assert!(
                    at < payload.len(),
                    "{owner}: payload ends where the presence tag for {} should be",
                    field.name
                );
                let tag = payload[at];
                assert!(
                    tag == 0 || tag == 1,
                    "{owner}: presence tag for {} is {tag:#04x}, not 0x00 or 0x01",
                    field.name
                );
                at += 1;
                if tag == 1 {
                    at = consume(field.ty, payload, at, field.name);
                }
            }
            Cardinality::Sequence => {
                // write_sequence: u32 count, then that many elements.
                assert!(
                    at + 4 <= payload.len(),
                    "{owner}: payload ends inside the count for {}",
                    field.name
                );
                let bytes: [u8; 4] = payload[at..at + 4].try_into().expect("four bytes");
                let count = u32::from_be_bytes(bytes) as usize;
                at += 4;
                for index in 0..count {
                    at = consume(field.ty, payload, at, &format!("{}[{index}]", field.name));
                }
            }
        }
    }
    at
}

/// Walks `payload` with `schema` and asserts the walk consumes it exactly.
fn assert_describes(schema: &SchemaDescriptor, payload: &[u8]) {
    let at = walk(schema.fields, payload, 0, schema.family);
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
fn every_described_family_resolves_and_the_shape_refusal_is_still_drivable() {
    for schema in registry::DESCRIBED {
        let found = registry::descriptor_for(schema.family).expect("a described family resolves");
        assert_eq!(found.family, schema.family);
    }
    // decision-batch used to be THE ShapeUnsupported case. It resolves now.
    assert!(registry::descriptor_for("decision-batch").is_ok());
    assert!(
        registry::UNDESCRIBED.is_empty(),
        "every canonical body is described, so the table is empty"
    );

    // Which means the refusal arm can no longer fire through the public entry
    // point -- the unreachable-variant defect `oxlt` was filed about. Drive it
    // with a supplied table instead of leaving it to rot.
    let synthetic = [registry::UndescribedBody {
        family: "some-future-body",
        construct: "a recursive field type, which this format still does not have",
    }];
    let refusal = registry::descriptor_for_in("some-future-body", registry::DESCRIBED, &synthetic)
        .expect_err("an undescribable body must refuse");
    assert_eq!(refusal.kind(), "shape_unsupported");
    assert!(refusal.to_string().contains("recursive field type"));

    // A described family still wins over the same name in the undescribed
    // table, so adding a row cannot mask a real descriptor.
    let shadowed = [registry::UndescribedBody {
        family: "decision-batch",
        construct: "unreachable: decision-batch is described",
    }];
    assert!(registry::descriptor_for_in("decision-batch", registry::DESCRIBED, &shadowed).is_ok());

    // And an unknown family is a DIFFERENT refusal, so "cannot be described"
    // and "does not exist" stay distinguishable to a caller.
    let missing = registry::descriptor_for("no-such-family").expect_err("unknown family");
    assert_eq!(missing.kind(), "family_unregistered");
    assert_ne!(refusal.kind(), missing.kind());
}

#[test]
fn the_decision_batch_descriptor_accounts_for_sequences_a_reference_and_a_union() {
    assert_identity::<fgit_codec::schema::RepositoryDecisionBatchBody>(&registry::DECISION_BATCH);

    // The fixture is the demanding case on purpose: BOTH outcome variants, a
    // non-empty committed_rcrs (which references the `rcr` descriptor rather
    // than copying it), and compaction_generation_link absent.
    let batch = support::decision_batch();
    assert_eq!(
        batch.decisions.len(),
        2,
        "the fixture must exercise both variants"
    );
    assert_eq!(batch.committed_rcrs.len(), 1);
    assert!(batch.compaction_generation_link.is_none());
    assert_describes(&registry::DECISION_BATCH, &payload_of(&batch));

    // EMPTY SEQUENCES. A walker that only ever sees a populated sequence has
    // not tested the count prefix at zero, and zero is where an off-by-one in
    // the prefix handling hides.
    let mut empty = support::decision_batch();
    empty.decisions.clear();
    empty.committed_rcrs.clear();
    assert_describes(&registry::DECISION_BATCH, &payload_of(&empty));

    // And the OTHER branch of the optional, which the fixture leaves absent.
    let mut linked = support::decision_batch();
    linked.compaction_generation_link = Some(support::digest_of(0x99));
    assert_describes(&registry::DECISION_BATCH, &payload_of(&linked));
}

#[test]
fn the_walker_would_notice_a_wrong_batch_descriptor() {
    // Presence case extended to the new constructs. If the walker cannot
    // reject a truncated batch, its acceptance of the correct one is worthless.
    let payload = payload_of(&support::decision_batch());
    let truncated = &payload[..payload.len() - 1];
    let outcome = std::panic::catch_unwind(|| {
        assert_describes(&registry::DECISION_BATCH, truncated);
    });
    assert!(
        outcome.is_err(),
        "the walker accepted a batch payload one byte short, so it cannot tell \
         a correct descriptor from a wrong one"
    );
    assert_describes(&registry::DECISION_BATCH, &payload);
}

#[test]
fn decision_batch_no_longer_refuses_and_the_refusal_path_is_still_reachable() {
    // The whole point of the bead: this used to be a ShapeUnsupported refusal.
    let found = registry::descriptor_for("decision-batch").expect("now described");
    assert_eq!(found.family, "decision-batch");
    assert_eq!(registry::DESCRIBED.len(), 5, "all five canonical bodies");

    // The refusal path must stay REACHABLE even with the table empty, or the
    // next undescribable body would panic instead of refusing.
    let unknown = registry::descriptor_for("not-a-family").expect_err("unknown family");
    assert_eq!(unknown.kind(), "family_unregistered");
}

#[test]
fn a_referenced_structure_is_the_same_definition_as_its_standalone_use() {
    // `committed_rcrs` references `rcr` by NAME. If it had been inlined, the
    // copy could drift from the standalone body and only one of them would be
    // conformance-checked. This asserts they are literally the same fields.
    let referenced = registry::structure_fields("rcr").expect("rcr resolves");
    assert!(
        std::ptr::eq(referenced, registry::REPOSITORY_COMMIT_RECORD.fields),
        "the reference must resolve to the SAME slice, not an equal copy"
    );

    let nested = registry::structure_fields("repository-decision").expect("resolves");
    assert_eq!(nested.len(), 3);
    assert!(registry::structure_fields("no-such-structure").is_none());
}

#[test]
fn the_union_is_well_formed_and_covers_the_encoder_discriminants() {
    let union = registry::union_for("decision-outcome").expect("registered");
    assert!(
        union.is_well_formed(),
        "variants must be unique and ascending, or `variant` depends on slice order"
    );
    // 1 and 2 are what `DecisionOutcome::discriminant` returns.
    assert_eq!(union.variant(1).expect("committed").name, "Committed");
    assert_eq!(union.variant(2).expect("refused").name, "Refused");
    // An unallocated byte resolves to nothing, which is what forces a refusal
    // rather than a skip: the payload is not length-prefixed.
    assert!(union.variant(0).is_none());
    assert!(union.variant(3).is_none());
    assert!(registry::union_for("no-such-union").is_none());
}
