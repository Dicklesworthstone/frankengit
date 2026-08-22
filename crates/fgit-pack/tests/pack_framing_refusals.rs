#![forbid(unsafe_code)]
//! frankengit-q3op: the framing guards a malformed pack hits first.
//!
//! `parse_pack_header` is the first thing `parse_quarantined_pack` calls after
//! the trailer split, and `EntryKind::from_type_code` gates every entry before
//! its payload is inflated. A pack that lies about its signature, its version,
//! or an entry type must be refused *before* anything is decompressed — that
//! ordering is the point of a bounded reader, and none of it was exercised.
//!
//! # Why the shared fixture could not reach one of these
//!
//! `fixtures::entry_header` asserts `matches!(kind, 1..=4 | 6 | 7)`, so
//! `fixtures::entry()` **cannot build an invalid type code** — it panics first.
//! That assert is a good thing for the fixtures' own callers and it is also,
//! most likely, why `InvalidEntryType` was never probed. This file builds the
//! malformed entry header itself rather than relaxing the shared assert, since
//! three other test targets compile that fixture and loosening it to suit a new
//! probe is how an existing assertion quietly changes meaning.

mod fixtures;

use fgit_pack::{ObjectFormat, PackError, parse_quarantined_pack};

/// A minimal single-byte entry header for `kind`, declaring a zero-length body.
///
/// The encoding is `(kind << 4) | (size & 0x0f)` with the continuation bit
/// clear, which is exactly what the shared fixture emits for a size under 16 —
/// this reproduces it for the kind codes that fixture refuses to build.
fn entry_header_byte(kind: u8) -> Vec<u8> {
    vec![kind << 4]
}

fn parse(bytes: &[u8]) -> Result<fgit_pack::QuarantinedPack, PackError> {
    parse_quarantined_pack(
        bytes,
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
    )
}

/// A pack whose leading four bytes are not `PACK` is refused.
///
/// This is the first check in `parse_pack_header`, so nothing earlier can
/// pre-empt it. The twin is the identical pack with the signature restored,
/// which must parse — otherwise the refusal could be coming from anything.
#[test]
fn a_pack_without_the_pack_signature_is_refused() {
    let good = fixtures::pack_with_entries(&[]);

    let mut bad = good.clone();
    bad[..4].copy_from_slice(b"XACK");
    assert_eq!(parse(&bad), Err(PackError::InvalidPackSignature));

    parse(&good).expect("the same pack with its signature intact must parse");
}

/// A pack declaring a version other than 2 is refused, naming the version.
///
/// Earlier check satisfied: the signature is left intact, so
/// `InvalidPackSignature` cannot fire first — which is the whole reason this
/// probe has to mutate only bytes 4..8.
///
/// The version is asserted, not just the variant: a guard that refused the
/// right packs while reporting the wrong version would survive a
/// variant-only check and tell an operator something false.
#[test]
fn a_pack_declaring_an_unsupported_version_is_refused_and_names_it() {
    let good = fixtures::pack_with_entries(&[]);

    let mut bad = good.clone();
    bad[4..8].copy_from_slice(&3_u32.to_be_bytes());
    assert_eq!(parse(&bad), Err(PackError::UnsupportedPackVersion(3)));

    // Version 3 is not merely "some other number" — it is the next one up, so
    // a guard written as `version > 2` would still refuse it. Version 1 is the
    // case that separates `!= 2` from `> 2`.
    let mut older = good.clone();
    older[4..8].copy_from_slice(&1_u32.to_be_bytes());
    assert_eq!(parse(&older), Err(PackError::UnsupportedPackVersion(1)));

    parse(&good).expect("version 2 must parse");
}

/// Entry type codes outside the valid set are refused, at both boundaries.
///
/// `from_type_code` accepts 1, 2, 3, 4, 6 and 7. Code 5 is the reserved gap
/// *inside* that span and code 0 is below it, so probing both is what
/// distinguishes an enumeration from a range check: a guard written as
/// `(1..=7).contains(&code)` would admit 5 while still refusing 0.
///
/// Earlier checks satisfied: the signature and version come from the shared
/// fixture and are correct, so the walk reaches the entry header.
#[test]
fn reserved_and_zero_entry_type_codes_are_refused() {
    for code in [0_u8, 5] {
        let pack = fixtures::pack_with_entries(&[entry_header_byte(code)]);
        assert_eq!(
            parse(&pack),
            Err(PackError::InvalidEntryType(code)),
            "entry type code {code} must be refused, naming itself",
        );
    }
}

/// The permitted twin for the entry-type guard: every valid code is accepted
/// through the same path.
///
/// Without this, the refusals above are equally satisfied by a
/// `from_type_code` that refuses everything, which would prove nothing about
/// which codes are valid. The two delta kinds (6, 7) are excluded here because
/// they carry a base reference the single-byte header does not supply — they
/// would refuse as truncated, for a reason unrelated to the type code.
#[test]
fn every_non_delta_entry_type_code_is_accepted() {
    for code in [1_u8, 2, 3, 4] {
        let pack = fixtures::pack_with_entries(&[fixtures::entry(code, b"x")]);
        let parsed = parse(&pack);
        assert!(
            !matches!(parsed, Err(PackError::InvalidEntryType(_))),
            "entry type code {code} is valid and must not be refused as an \
             invalid type; got {parsed:?}",
        );
    }
}
