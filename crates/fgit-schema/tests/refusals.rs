//! Every typed refusal, each paired with the permitted case it is the negative
//! of.
//!
//! AGENTS.md §16.3: refusal-only work is worth less than the capability, and
//! every forbidden case pairs with a near-identical permitted one. A refusal
//! nobody can reach is the same defect as a check nobody calls.

use fgit_schema::descriptor::{Cardinality, FieldType, ScalarWidth};
use fgit_schema::error::SchemaRefusal;
use fgit_schema::registry;

#[test]
fn an_unregistered_family_refuses_and_a_registered_one_does_not() {
    let refusal = registry::descriptor_for("not-a-family").expect_err("no such family");
    assert!(matches!(refusal, SchemaRefusal::FamilyUnregistered { .. }));
    assert!(refusal.to_string().contains("not-a-family"));

    // Permitted twin.
    let found = registry::descriptor_for("rcr").expect("rcr is described");
    assert_eq!(found.family, "rcr");
}

#[test]
fn an_undescribable_body_refuses_with_the_missing_construct_named() {
    let refusal =
        registry::descriptor_for("decision-batch").expect_err("decision-batch is not describable");
    match &refusal {
        SchemaRefusal::ShapeUnsupported { family, construct } => {
            assert_eq!(&**family, "decision-batch");
            // Naming the construct is the difference between a gap someone can
            // close and one they have to rediscover.
            assert!(construct.contains("sequence"));
            assert!(construct.contains("tagged union"));
        }
        other => panic!("expected ShapeUnsupported, got {other:?}"),
    }

    // The two "not available" refusals stay distinguishable: an undescribable
    // body is a different fact from a nonexistent one, and collapsing them
    // would hide a real canonical body behind a typo-shaped error.
    let unknown = registry::descriptor_for("decision-batches").expect_err("typo");
    assert_ne!(refusal.kind(), unknown.kind());
}

#[test]
fn duplicate_families_refuse_and_the_real_registry_does_not() {
    // PRESENCE CASE for the uniqueness guard. `descriptor_for` returns the
    // first match, so a duplicate family would make resolution depend on slice
    // order — silently wrong output rather than an error.
    let duplicated = &[&registry::TXN_SEAL, &registry::TXN_SEAL][..];
    let refusal =
        registry::check_families_unique_in(duplicated).expect_err("a duplicate must refuse");
    match &refusal {
        SchemaRefusal::FamilyDuplicated { family } => assert_eq!(&**family, "txn-seal"),
        other => panic!("expected FamilyDuplicated, got {other:?}"),
    }

    // Permitted twin: two DIFFERENT descriptors are fine, so the guard is
    // about duplication rather than about having more than one entry.
    registry::check_families_unique_in(&[&registry::TXN_SEAL, &registry::REFUSAL_RECORD][..])
        .expect("distinct families are permitted");

    // And the real registry is clean.
    registry::check_families_unique().expect("the shipped registry has no duplicate family");
}

#[test]
fn every_refusal_variant_prints_and_has_a_distinct_kind() {
    let samples = [
        SchemaRefusal::FamilyUnregistered {
            family: "ghost".into(),
        },
        SchemaRefusal::ShapeUnsupported {
            family: "decision-batch".into(),
            construct: "a nested sequence",
        },
        SchemaRefusal::ArtifactStale {
            artifact: "canonical_bodies.ts".into(),
            offset: 41,
        },
        SchemaRefusal::ArtifactMissing {
            artifact: "canonical_bodies.py".into(),
        },
        SchemaRefusal::FamilyDuplicated {
            family: "rcr".into(),
        },
    ];
    let mut kinds = std::collections::BTreeSet::new();
    for sample in &samples {
        assert!(!sample.to_string().is_empty(), "a refusal must print");
        assert!(
            kinds.insert(sample.kind()),
            "two variants share the kind {}",
            sample.kind()
        );
    }
    assert_eq!(kinds.len(), samples.len());

    // The array is hand-maintained, so it can silently fall behind the enum.
    // This forces the author of a new variant here rather than trusting them
    // to remember: adding one without a sample fails to compile.
    const fn _every_variant_is_sampled(refusal: &SchemaRefusal) {
        match refusal {
            SchemaRefusal::FamilyUnregistered { .. }
            | SchemaRefusal::ShapeUnsupported { .. }
            | SchemaRefusal::ArtifactStale { .. }
            | SchemaRefusal::ArtifactMissing { .. }
            | SchemaRefusal::FamilyDuplicated { .. } => {}
        }
    }
}

#[test]
fn the_descriptor_vocabulary_reports_widths_honestly() {
    // Fixed-width types report a width; length-prefixed ones report none. A
    // reader that skipped a body by a constant offset would be wrong for every
    // described body, so `is_fixed_size` is asserted false rather than assumed.
    assert_eq!(
        FieldType::Scalar(ScalarWidth::U64).fixed_byte_len(),
        Some(8)
    );
    assert_eq!(FieldType::OpaqueId.fixed_byte_len(), Some(16));
    assert_eq!(
        FieldType::CodePoint {
            vocabulary: "RefusalCode"
        }
        .fixed_byte_len(),
        Some(2)
    );
    assert_eq!(FieldType::Digest.fixed_byte_len(), None);
    assert_eq!(FieldType::SchemaId.fixed_byte_len(), None);
    assert_eq!(FieldType::Text { max_len: 4096 }.fixed_byte_len(), None);

    for schema in registry::DESCRIBED {
        assert!(
            !schema.is_fixed_size(),
            "{} reports a constant size; every described body carries at least \
             one length-prefixed field",
            schema.family
        );
    }
}

#[test]
fn descriptors_expose_their_fields_in_wire_order() {
    let rcr = registry::descriptor_for("rcr").expect("described");
    let names = rcr.field_names();
    assert_eq!(names.len(), rcr.field_count());
    // Wire order is normative: it IS the encoding, so the first field is the
    // first bytes. `tests/conformance.rs` is what proves this order matches
    // the real encoder; here it only has to be stable and complete.
    assert_eq!(names[0], "repository_id");
    assert_eq!(names[1], "repository_sequence");
    assert_eq!(names[2], "parent_rcr_id");

    assert!(rcr.field("parent_rcr_id").is_some());
    assert!(rcr.field("no_such_field").is_none());
    assert_eq!(
        rcr.field("parent_rcr_id").expect("present").cardinality,
        Cardinality::Optional
    );
    assert_eq!(
        rcr.field("repository_id").expect("present").cardinality,
        Cardinality::Required
    );
}
