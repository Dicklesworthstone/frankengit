// Bounded ASCII labels: one canonical form, a narrow character set, and
// lexicographic ordering over the logical bytes.

use fgit_types::TypeRefusal;
use fgit_types::label::{AsciiSlug, DomainTag, MAX_LABEL_LEN, SchemaFamily, SchemaId};

#[test]
fn the_permitted_character_set_is_accepted() {
    for source in [
        &b"a"[..],
        b"frankengit/ref-txn/v2",
        b"segment-manifest.v1",
        b"abcdefghijklmnopqrstuvwxyz0123456789-_./",
    ] {
        let slug = AsciiSlug::try_new("test", source).expect("inside the character set");
        assert_eq!(slug.as_bytes(), source);
        assert_eq!(slug.len(), source.len());
        assert!(!slug.is_empty());
    }
}

#[test]
fn characters_outside_the_set_are_refused() {
    // Uppercase, space, and non-ASCII each have a permitted near-identical
    // counterpart, so the refusal is about canonical form, not capability.
    for (source, offset) in [
        (&b"Frankengit"[..], 0_u32),
        (b"ref txn", 3),
        (b"ref:txn", 3),
        ("ref\u{2010}txn".as_bytes(), 3),
    ] {
        let refusal = AsciiSlug::try_new("test", source)
            .expect_err("a second spelling of one identity must not exist");
        assert!(
            matches!(
                refusal,
                TypeRefusal::ByteNotPermitted { field: "test", offset: seen, .. } if seen == offset
            ),
            "unexpected refusal for {source:?}: {refusal}"
        );
    }
    assert!(AsciiSlug::try_new("test", b"frankengit").is_ok());
    assert!(AsciiSlug::try_new("test", b"ref-txn").is_ok());
}

#[test]
fn the_length_window_is_enforced_at_both_ends() {
    let empty = AsciiSlug::try_new("test", b"").expect_err("a label is never empty");
    assert!(matches!(
        empty,
        TypeRefusal::LengthOutOfRange {
            observed: 0,
            minimum: 1,
            maximum: 64,
            ..
        }
    ));

    let at_bound = vec![b'a'; MAX_LABEL_LEN];
    assert!(
        AsciiSlug::try_new("test", &at_bound).is_ok(),
        "exactly at the bound must be permitted"
    );

    let over_bound = vec![b'a'; MAX_LABEL_LEN + 1];
    let refusal =
        AsciiSlug::try_new("test", &over_bound).expect_err("one byte over the bound is refused");
    assert!(matches!(
        refusal,
        TypeRefusal::LengthOutOfRange { observed: 65, .. }
    ));
}

#[test]
fn ordering_is_lexicographic_over_the_logical_bytes() {
    let short = AsciiSlug::try_new("test", b"ab").expect("valid");
    let long = AsciiSlug::try_new("test", b"abc").expect("valid");
    let other = AsciiSlug::try_new("test", b"abd").expect("valid");
    assert!(short < long, "a prefix sorts before its extension");
    assert!(long < other);
    assert_eq!(short, AsciiSlug::try_new("test", b"ab").expect("valid"));
    assert_ne!(short, long);

    let mut sorted = vec![other, short, long];
    sorted.sort_unstable();
    assert_eq!(
        sorted.iter().map(AsciiSlug::as_str).collect::<Vec<_>>(),
        vec!["ab", "abc", "abd"]
    );
}

#[test]
fn the_const_and_runtime_constructors_agree() {
    const TAG: DomainTag = DomainTag::from_static("frankengit/ref-txn/v2");
    let runtime = DomainTag::try_new(b"frankengit/ref-txn/v2").expect("valid");
    assert_eq!(TAG, runtime);
    assert_eq!(TAG.as_str(), "frankengit/ref-txn/v2");
    assert_eq!(TAG.as_bytes(), b"frankengit/ref-txn/v2");
    assert_eq!(TAG.to_string(), "frankengit/ref-txn/v2");
}

#[test]
fn domain_tags_and_schema_families_do_not_conflate() {
    let tag = DomainTag::try_new(b"ref-txn").expect("valid");
    let family = SchemaFamily::try_new(b"ref-txn").expect("valid");
    assert_eq!(tag.as_bytes(), family.as_bytes());
    // They are distinct types, so a domain tag cannot be passed where a schema
    // family is required; equality across them does not compile.
    assert_eq!(family.to_string(), "ref-txn");
}

#[test]
fn schema_identifiers_expose_an_explicit_compatibility_boundary() {
    let family = SchemaFamily::from_static("ref-txn");
    let one_zero = SchemaId::new(family, 1, 0);
    let one_seven = SchemaId::new(family, 1, 7);
    let two_zero = SchemaId::new(family, 2, 0);
    assert_eq!(one_zero.family(), family);
    assert_eq!(one_seven.minor(), 7);
    assert_eq!(two_zero.major(), 2);
    assert!(one_zero < one_seven, "minor versions order within a major");
    assert!(one_seven < two_zero, "a major bump sorts after every minor");
    assert_eq!(two_zero.to_string(), "ref-txn/v2.0");
}
