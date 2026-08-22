#![forbid(unsafe_code)]
//! The loose-object envelope: `type SPACE size NUL body` (`frankengit-v788`).
//!
//! This parser decides whether a byte sequence **is** a Git loose object, and
//! §6 makes refusal behaviour a compatibility semantic rather than an
//! implementation detail. `NonCanonicalLooseLength` is the sharpest case: a
//! size of `0123` parses unambiguously as 123 and is refused anyway, because
//! accepting it would let two byte sequences claim one object identity.
//!
//! # The bead's premise was half wrong, and the correction is worth stating
//!
//! `frankengit-v788` was filed claiming all four variants below are "not
//! covered anywhere". Re-measured against the tree before writing this file,
//! that is true for only two of them. `tests/corpus/adversarial-refusals.tsv`
//! is a data-driven fixture consumed by `adversarial_refusal.rs`, and it
//! already carries two rows in this cluster:
//!
//! ```text
//! loose-missing-nul          blob 1        MissingLooseHeaderTerminator
//! loose-noncanonical-length  blob 01\0x    NonCanonicalLooseLength
//! ```
//!
//! The original scan looked for variant names in `.rs` test sources and a
//! corpus row spells its expectation in a TSV column, so it was invisible. The
//! honest scope is therefore:
//!
//! ```text
//! MalformedLooseHeader          3 axes   NO prior coverage
//! UnsupportedObjectType         2 axes   NO prior coverage
//! NonCanonicalLooseLength       1 axis   one corpus row; the BOUNDARY is uncovered
//! MissingLooseHeaderTerminator  1 axis   one corpus row
//! ```
//!
//! The two already-covered rows are still probed here, because a refusal proven
//! only through a corpus driver is proven only for that driver's decoding of an
//! escaped string; but they are not claimed as new coverage.
//!
//! # What the corpus cannot see, and this file can
//!
//! The leading-zero rule is guarded on `length_bytes.len() > 1`, so a bare `0`
//! must remain **legal** — a zero-length blob is an ordinary Git object. The
//! corpus row uses `01`, which has length two and stays refused if that guard
//! is widened to `>= 1`. So the existing fixture is blind to a change that
//! makes every empty object unparseable.
//! [`a_bare_zero_length_is_accepted_while_a_padded_zero_is_refused`] is the
//! probe that sees it, and the mutation recorded in the bead confirms the
//! split rather than asserting it.
//!
//! # Ordering is a property here, not an accident
//!
//! `parse_loose_header` runs its checks in sequence, so an input that violates
//! two rules reports the **earlier** one. Three probes pin that precedence with
//! inputs that are deliberately wrong twice; without them, a reordering of the
//! guards would leave every single-fault probe above green. Each probe below
//! states what it passes through to reach the check it is named for.
//!
//! # Reachability
//!
//! `DecoderStateInconsistent` is excluded deliberately, and it is **defensive**:
//! `finish` reads `object_type` and `declared_size`, and `push` assigns both
//! from one `parse_loose_header` result in a single statement pair, so a
//! `Some`/`None` split cannot be produced through the public API. It is
//! documented here rather than given a manufactured fixture.
//!
//! # Non-claims
//!
//! This closes four of the sixteen genuinely-unnamed `ObjectError` variants,
//! two of which had partial corpus coverage already. The tree-entry cluster
//! remains, `zxfi` holds the commit/tag header cluster, and the eighteen
//! variants covered only by in-src `cfg(test)` modules are a separate question.
//! `LooseLengthMismatch` and `TrailingLooseBytes` are out of scope because
//! `src/lib.rs`'s own test module already covers them. That is a LEAD count,
//! not a remaining-work total.
//!
//! Nothing here modifies `crates/fgit-git-object/src/**`.

use fgit_git_object::{ObjectError, ObjectType, ParseLimits, parse_loose_framed};

fn parse(bytes: &[u8]) -> Result<fgit_git_object::LooseObject, ObjectError> {
    parse_loose_framed(bytes, ParseLimits::default())
}

fn refusal(bytes: &[u8], what: &str) -> ObjectError {
    match parse(bytes) {
        Ok(object) => panic!(
            "{what} must be refused, but parsed as {:?} with declared size {}",
            object.object_type, object.declared_size
        ),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// The permitted terminus, first — every refusal below is measured against it
// ---------------------------------------------------------------------------

/// A complete well-formed loose object round-trips.
///
/// This comes first because without it the refusals are unattributable: a
/// parser that rejected everything would satisfy every negative probe in this
/// file.
#[test]
fn a_canonical_loose_object_parses() {
    let object = parse(b"blob 5\0hello").expect("a canonical loose object must parse");
    assert_eq!(object.object_type, ObjectType::Blob);
    assert_eq!(object.declared_size, 5);
    assert_eq!(object.body, b"hello");
}

/// All four native labels are accepted, which is the permitted twin for both
/// `UnsupportedObjectType` axes.
///
/// The framing parser does not validate body structure, so a zero-length body
/// is legal for every type here; this probe is about `from_label` resolving
/// exactly the four Git types and nothing else.
#[test]
fn every_native_type_label_resolves() {
    for (label, expected) in [
        ("commit", ObjectType::Commit),
        ("tree", ObjectType::Tree),
        ("blob", ObjectType::Blob),
        ("tag", ObjectType::Tag),
    ] {
        let framed = format!("{label} 0\0");
        let object = parse(framed.as_bytes())
            .unwrap_or_else(|error| panic!("the native label {label} must resolve, got {error:?}"));
        assert_eq!(
            object.object_type, expected,
            "the label {label} must resolve to its own type"
        );
    }
}

// ---------------------------------------------------------------------------
// MalformedLooseHeader — three axes
// ---------------------------------------------------------------------------

/// Axis 1: no space at all. The header ends before a separator is ever seen.
#[test]
fn a_header_with_no_space_is_refused() {
    assert_eq!(
        refusal(b"blob\0", "a header with no space"),
        ObjectError::MalformedLooseHeader
    );
}

/// Axis 2: a second space inside the length field.
///
/// Passes through: the first space is found at index 4, so this reaches the
/// second-space check rather than the missing-space one.
#[test]
fn a_second_space_inside_the_length_is_refused() {
    assert_eq!(
        refusal(b"blob 1 2\0xx", "a header with a second space"),
        ObjectError::MalformedLooseHeader
    );
}

/// Axis 3, first shape: an empty length.
///
/// Passes through: a space is present and `blob` is a valid label, so this
/// reaches the length check.
#[test]
fn an_empty_length_is_refused() {
    assert_eq!(
        refusal(b"blob \0", "a header with an empty length"),
        ObjectError::MalformedLooseHeader
    );
}

/// Axis 3, second shape: a non-digit length.
///
/// One condition covers both shapes, so both get a probe — an empty slice and a
/// non-digit slice fail different halves of `is_empty() || !all_ascii_digit`.
#[test]
fn a_non_digit_length_is_refused() {
    assert_eq!(
        refusal(b"blob xy\0", "a header with a non-digit length"),
        ObjectError::MalformedLooseHeader
    );
}

// ---------------------------------------------------------------------------
// UnsupportedObjectType — two axes
// ---------------------------------------------------------------------------

/// Axis 1: a type label that is not UTF-8 at all.
///
/// Passes through: a space sits at index 2 and the remainder is the single
/// digit `5`, so neither space check fires and this reaches the label decode.
#[test]
fn a_non_utf8_type_label_is_refused() {
    assert_eq!(
        refusal(b"\xff\xfe 5\0hello", "a non-UTF-8 type label"),
        ObjectError::UnsupportedObjectType
    );
}

/// Axis 2: a well-formed label that is not one of the four Git types.
///
/// This is a different failure from the one above — valid UTF-8 that
/// `from_label` does not resolve — and a probe hitting only one leaves the
/// other unexercised.
#[test]
fn a_well_formed_but_unknown_type_label_is_refused() {
    assert_eq!(
        refusal(b"widget 5\0hello", "an unknown type label"),
        ObjectError::UnsupportedObjectType
    );
}

// ---------------------------------------------------------------------------
// NonCanonicalLooseLength — and the boundary the rule turns on
// ---------------------------------------------------------------------------

/// A padded length is refused even though it parses unambiguously.
///
/// The corpus already carries `blob 01\0x`; this uses a longer pad to show the
/// rule is about the leading zero rather than about a two-character field.
#[test]
fn a_length_with_leading_zeros_is_refused() {
    assert_eq!(
        refusal(b"blob 0123\0", "a length padded with a leading zero"),
        ObjectError::NonCanonicalLooseLength
    );
    assert_eq!(
        refusal(b"blob 01\0x", "the corpus leading-zero case"),
        ObjectError::NonCanonicalLooseLength
    );
}

/// **The boundary.** A bare `0` is legal; a padded zero is not.
///
/// The guard reads `length_bytes.len() > 1 && length_bytes[0] == b'0'`, so a
/// single `0` must still parse — an empty blob is an ordinary Git object, and
/// the empty tree is one of the most common objects in any repository.
///
/// This is the case the existing corpus cannot see: its `blob 01\0x` row has a
/// two-character length and stays refused if the guard is widened to `>= 1`.
/// Widening it makes every zero-length object unparseable while leaving the
/// corpus green.
#[test]
fn a_bare_zero_length_is_accepted_while_a_padded_zero_is_refused() {
    let empty = parse(b"blob 0\0").expect("a zero-length blob is an ordinary Git object");
    assert_eq!(empty.declared_size, 0);
    assert!(
        empty.body.is_empty(),
        "a zero length declares an empty body"
    );

    assert_eq!(
        refusal(b"blob 00\0", "a zero padded to two characters"),
        ObjectError::NonCanonicalLooseLength
    );
}

/// The permitted twin for the leading-zero rule at a non-zero value: `123`
/// parses where `0123` refuses, and the accepted body is the declared length.
#[test]
fn an_unpadded_length_parses_where_its_padded_twin_refuses() {
    let mut framed = b"blob 123\0".to_vec();
    framed.extend(std::iter::repeat_n(b'x', 123));
    let object = parse(&framed).expect("an unpadded three-digit length must parse");
    assert_eq!(object.declared_size, 123);
    assert_eq!(object.body.len(), 123);

    let mut padded = b"blob 0123\0".to_vec();
    padded.extend(std::iter::repeat_n(b'x', 123));
    assert_eq!(
        refusal(&padded, "the padded twin of an accepted length"),
        ObjectError::NonCanonicalLooseLength
    );
}

// ---------------------------------------------------------------------------
// MissingLooseHeaderTerminator
// ---------------------------------------------------------------------------

/// The NUL never arrives, so the decoder finishes having parsed no header.
///
/// `push` returns `Ok` here — an unterminated header is not yet an error, since
/// more input could still supply the NUL. The refusal is `finish`'s to make,
/// which is why this axis lives on the decoder rather than the header parser.
#[test]
fn a_header_that_is_never_terminated_is_refused_at_finish() {
    assert_eq!(
        refusal(b"blob 5", "a header with no NUL terminator"),
        ObjectError::MissingLooseHeaderTerminator
    );
}

/// The permitted twin: the same bytes plus the terminator and a body parse.
///
/// Without this, the refusal above could be the parser rejecting `blob 5` for
/// some reason unrelated to the missing terminator.
#[test]
fn the_same_header_with_its_terminator_parses() {
    let object = parse(b"blob 5\0world").expect("the terminated form of the same header parses");
    assert_eq!(object.declared_size, 5);
}

// ---------------------------------------------------------------------------
// Ordering — inputs that are wrong twice, reporting the earlier fault
// ---------------------------------------------------------------------------

/// The second-space check runs **before** the type is validated.
///
/// This input is wrong twice: `widget` is not a type AND the length field
/// carries a second space. It must report `MalformedLooseHeader`. Reordering
/// those two guards would flip this to `UnsupportedObjectType` and leave every
/// single-fault probe above green.
#[test]
fn a_second_space_outranks_an_unknown_type() {
    assert_eq!(
        refusal(b"widget 1 2\0xx", "an unknown type with a second space"),
        ObjectError::MalformedLooseHeader
    );
}

/// The type is validated **before** the length is.
///
/// Wrong twice again: an unknown type AND a non-digit length. It must report
/// `UnsupportedObjectType`, which is the opposite precedence from the probe
/// above — so the two together pin the order of all three guards.
#[test]
fn an_unknown_type_outranks_a_malformed_length() {
    assert_eq!(
        refusal(b"widget xy\0", "an unknown type with a non-digit length"),
        ObjectError::UnsupportedObjectType
    );
}

/// The type is validated before the canonical-length rule too.
#[test]
fn an_unknown_type_outranks_a_non_canonical_length() {
    assert_eq!(
        refusal(b"widget 01\0x", "an unknown type with a padded length"),
        ObjectError::UnsupportedObjectType
    );
}
