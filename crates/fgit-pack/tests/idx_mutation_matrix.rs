#![forbid(unsafe_code)]

//! One-to-one discrimination over the idx v2 framing guards
//! (`frankengit-audit-debt-rytx-ledger-mutation-hqc0`, follow-on to `rytx`).
//!
//! `idx_framing_refusals.rs` proves each framing guard **refuses**. That is a
//! weaker property than it looks: a parser in which two guards collapsed onto
//! one answer — or in which a single earlier guard swallowed every malformed
//! image — would satisfy every assertion in that file. Each probe there is
//! checked in isolation, and isolation is exactly what cannot see a collapse.
//!
//! This file pins the stronger property: each planted mutation produces its
//! **own** guard's answer and **no other guard's answer**. The guards, with the
//! sites they pair to in `src/idx.rs`:
//!
//! ```text
//! :144  input.len() < minimum        -> Truncated { context: "idx header or checksums" }
//! :149  input[..4] != IDX_SIGNATURE  -> InvalidIndexSignature
//! :154  version != IDX_V2            -> UnsupportedIndexVersion(version)
//! :199  large_bytes % 8 != 0         -> TrailingIndexBytes
//! ```
//!
//! # Non-claim
//!
//! This is discrimination evidence over four framing guards and their two
//! permitted twins, not a proof that the idx parser is correct and not
//! exhaustive fuzzing. It says nothing about the fanout, OID, CRC or offset
//! tables, which `bombs_idx.rs` and `fuzz_deterministic.rs` cover. A guard
//! absent from the table below is not claimed to be discriminated.

use fgit_pack::{IdxV2, ObjectFormat, PackError, PackLimits};

const SHA1_LEN: usize = 20;
const FANOUT_BYTES: usize = 256 * 4;
const MINIMUM_LEN: usize = 8 + FANOUT_BYTES + 2 * SHA1_LEN;

/// A deadline that never fires, so no outcome below can be budget exhaustion.
const fn never_expires() -> bool {
    true
}

/// A structurally valid, zero-entry idx v2 image — the buffer every mutation
/// below is a single-field edit of.
fn valid_idx() -> Vec<u8> {
    let mut out = Vec::with_capacity(MINIMUM_LEN);
    out.extend_from_slice(&[0xff, b't', b'O', b'c']);
    out.extend_from_slice(&2_u32.to_be_bytes());
    out.extend_from_slice(&[0; FANOUT_BYTES]);
    out.extend_from_slice(&[0xaa; SHA1_LEN]);
    out.extend_from_slice(&[0xbb; SHA1_LEN]);
    out
}

/// `valid_idx` with `extra` filler bytes where the large-offset table lives.
fn with_large_offset_region(extra: usize) -> Vec<u8> {
    let base = valid_idx();
    let split = base.len() - 2 * SHA1_LEN;
    let mut out = base[..split].to_vec();
    out.extend(std::iter::repeat_n(0_u8, extra));
    out.extend_from_slice(&base[split..]);
    out
}

fn parse(bytes: &[u8]) -> Result<IdxV2, PackError> {
    IdxV2::parse(
        bytes,
        ObjectFormat::Sha1,
        &PackLimits::default(),
        &mut never_expires,
    )
}

/// One planted mutation and the single outcome it is paired with.
///
/// `expected` is written by hand per row. It is deliberately NOT derived from
/// running the parser, which would restate the implementation and pass whatever
/// the parser did.
struct Case {
    name: &'static str,
    guard_site: &'static str,
    bytes: Vec<u8>,
    expected: Option<PackError>,
}

fn matrix() -> Vec<Case> {
    let signature = {
        let mut bytes = valid_idx();
        bytes[0] = 0x00;
        bytes
    };
    let version_low = {
        let mut bytes = valid_idx();
        bytes[4..8].copy_from_slice(&1_u32.to_be_bytes());
        bytes
    };
    let version_high = {
        let mut bytes = valid_idx();
        bytes[4..8].copy_from_slice(&3_u32.to_be_bytes());
        bytes
    };
    // Wrong twice on purpose: a short buffer that ALSO carries a bad signature.
    // If the length gate and the signature gate were reordered, this row would
    // report InvalidIndexSignature and the table would fail.
    let short_and_bad_signature = {
        let mut bytes = valid_idx();
        bytes[0] = 0x00;
        bytes.truncate(MINIMUM_LEN - 1);
        bytes
    };

    vec![
        Case {
            name: "baseline/well-formed",
            guard_site: "none (permitted twin)",
            bytes: valid_idx(),
            expected: None,
        },
        Case {
            name: "signature/first-byte",
            guard_site: "idx.rs:149",
            bytes: signature,
            expected: Some(PackError::InvalidIndexSignature),
        },
        Case {
            name: "version/below",
            guard_site: "idx.rs:154",
            bytes: version_low,
            expected: Some(PackError::UnsupportedIndexVersion(1)),
        },
        Case {
            name: "version/above",
            guard_site: "idx.rs:154",
            bytes: version_high,
            expected: Some(PackError::UnsupportedIndexVersion(3)),
        },
        Case {
            name: "large-offset/partial-slot",
            guard_site: "idx.rs:199",
            bytes: with_large_offset_region(4),
            expected: Some(PackError::TrailingIndexBytes),
        },
        Case {
            name: "large-offset/whole-slot",
            guard_site: "idx.rs:199 (permitted twin)",
            bytes: with_large_offset_region(8),
            expected: None,
        },
        Case {
            name: "ordering/short-and-bad-signature",
            guard_site: "idx.rs:144 before :149",
            bytes: short_and_bad_signature,
            expected: Some(PackError::Truncated {
                context: "idx header or checksums",
            }),
        },
    ]
}

/// **Harness self-test.** If the shared fixture stopped parsing, every refusal
/// row below would still "pass" while proving nothing — the mutations would be
/// refused for being malformed rather than for the field each one edits.
#[test]
fn the_baseline_fixture_parses_before_any_mutation_is_judged() {
    let index = parse(&valid_idx()).expect("the unmutated fixture must parse");
    assert!(
        index.entries().is_empty(),
        "an all-zero fanout commits to zero objects",
    );
    assert_eq!(
        valid_idx().len(),
        MINIMUM_LEN,
        "the fixture must sit exactly on the minimum, or the truncation row is not minimal",
    );
}

/// Every planted mutation produces exactly the outcome it is paired with.
#[test]
fn every_planted_mutation_produces_exactly_its_paired_outcome() {
    for case in matrix() {
        let observed = parse(&case.bytes).err();
        assert_eq!(
            observed, case.expected,
            "{} (guard {}) produced the wrong outcome",
            case.name, case.guard_site,
        );
    }
}

/// **The discrimination claim.** Distinct guards must not collapse onto one
/// answer.
///
/// `idx_framing_refusals.rs` cannot see a collapse, because it checks each
/// probe alone: a parser whose signature check also fired for a bad version
/// would satisfy both of its assertions separately. Here the refusals are
/// compared against each other, so a collapse fails.
///
/// The two version rows are deliberately excluded from the distinctness set and
/// asserted separately: they share a guard by design and must differ only in
/// the value they carry — which is the property that distinguishes the `!= 2`
/// the parser writes from a one-sided `> 2`.
#[test]
fn distinct_guards_produce_distinct_refusals() {
    let cases = matrix();
    let refusals: Vec<(&str, PackError)> = cases
        .iter()
        .filter(|case| !case.name.starts_with("version/"))
        .filter_map(|case| case.expected.clone().map(|error| (case.name, error)))
        .collect();

    for (index, (left_name, left)) in refusals.iter().enumerate() {
        for (right_name, right) in refusals.iter().skip(index + 1) {
            assert_ne!(
                left, right,
                "{left_name} and {right_name} guard different faults but answer identically, \
                 so no test can tell which one fired",
            );
        }
    }

    let versions: Vec<PackError> = cases
        .iter()
        .filter(|case| case.name.starts_with("version/"))
        .filter_map(|case| case.expected.clone())
        .collect();
    assert_eq!(versions.len(), 2, "both version directions must be planted");
    assert_ne!(
        versions[0], versions[1],
        "the version refusal must carry the offending version, or the two \
         directions are indistinguishable",
    );
}

/// Every framing guard named in this file's header appears in the table, and
/// each refusing guard is planted at least once.
#[test]
fn the_matrix_covers_every_framing_guard() {
    let cases = matrix();
    for site in ["idx.rs:144", "idx.rs:149", "idx.rs:154", "idx.rs:199"] {
        assert!(
            cases.iter().any(|case| case.guard_site.contains(site)),
            "guard {site} is named in the header but planted by no row",
        );
    }
    assert!(
        cases.iter().filter(|case| case.expected.is_none()).count() >= 2,
        "the table must keep both permitted twins, or an over-strict parser passes it",
    );
}

/// Receipt, in the convention of `fuzz_deterministic.rs`.
#[test]
fn emit_matrix_receipt() {
    let cases = matrix();
    let planted = cases.len();
    let refusals = cases.iter().filter(|case| case.expected.is_some()).count();
    let accepted = planted - refusals;
    println!(
        "{{\"schema\":\"frankengit.idx-mutation-matrix.v1\",\"planted\":{planted},\
         \"refusal_rows\":{refusals},\"permitted_twins\":{accepted},\
         \"guards\":[\"idx.rs:144\",\"idx.rs:149\",\"idx.rs:154\",\"idx.rs:199\"],\
         \"non_claim\":\"one-to-one discrimination over four idx framing guards and their \
         permitted twins; not a correctness proof of the idx parser and not exhaustive fuzzing\"}}"
    );
}
