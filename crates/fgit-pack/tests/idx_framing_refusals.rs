#![forbid(unsafe_code)]

//! frankengit-rytx: the framing guards of the idx v2 parser.
//!
//! A `.idx` file is the lookup table that turns an object id into a pack
//! offset. If the parser accepts one that lies about its identity, every
//! subsequent lookup reads the wrong bytes at the wrong offset -- so the header
//! checks are not hygiene, they are what makes an index trustworthy at all.
//! AGENTS.md §6 makes refusal behaviour a compatibility semantic.
//!
//! Three guards had no test anywhere in the workspace. Verified per variant
//! against all of `crates/`, not just the declaring crate:
//! `InvalidIndexSignature`, `UnsupportedIndexVersion` and `TrailingIndexBytes`
//! appear only in `src/lib.rs` (declaration and Display) and `src/idx.rs`
//! (construction). The existing `bombs_idx.rs` drives this parser but asserts
//! only `IndexEntryCrcMismatch` and `ObjectCountMismatch`.
//!
//! Every probe is a single-field corruption of one known-good buffer, so a
//! refusal cannot be blamed on some other part of the image being malformed.

use fgit_pack::{IdxV2, ObjectFormat, PackError, PackLimits};

const SHA1_LEN: usize = 20;
const FANOUT_BYTES: usize = 256 * 4;

/// The smallest buffer the parser will look past: header, fanout, and the two
/// trailing checksums (`idx.rs:137`). Anything shorter is `Truncated` before
/// the signature is ever compared, which is the ordering
/// `a_short_buffer_reports_truncation_before_the_signature_is_judged` pins.
const MINIMUM_LEN: usize = 8 + FANOUT_BYTES + 2 * SHA1_LEN;

/// A deadline that never fires: `checkpoint` treats `true` as "budget remains",
/// so no refusal below can be budget exhaustion.
const fn never_expires() -> bool {
    true
}

/// A structurally valid, zero-entry idx v2 image.
///
/// Zero entries is the smallest shape the parser accepts, and that is the
/// point: it makes each probe a one-field edit of a buffer that is known to
/// parse, rather than a hand-rolled near-miss that might be refused for a
/// reason the test did not intend.
fn valid_idx() -> Vec<u8> {
    let mut out = Vec::with_capacity(MINIMUM_LEN);
    out.extend_from_slice(&[0xff, b't', b'O', b'c']);
    out.extend_from_slice(&2_u32.to_be_bytes());
    out.extend_from_slice(&[0; FANOUT_BYTES]);
    out.extend_from_slice(&[0xaa; SHA1_LEN]);
    out.extend_from_slice(&[0xbb; SHA1_LEN]);
    assert_eq!(
        out.len(),
        MINIMUM_LEN,
        "the fixture must be exactly minimal"
    );
    out
}

/// `valid_idx` with `extra` filler bytes inserted between the tables and the
/// two trailing checksums, which is where the large-offset table lives.
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

/// The permitted twin: the known-good image parses and describes no objects.
///
/// Load-bearing rather than decorative. Every probe below differs from this
/// buffer by one field, and without it they would all pass against a `parse`
/// that refused unconditionally.
#[test]
fn a_well_formed_zero_entry_index_parses() {
    let index = parse(&valid_idx()).expect("a minimal well-formed idx v2 must parse");
    assert!(
        index.entries().is_empty(),
        "an all-zero fanout commits to zero objects",
    );
}

/// An image whose first four bytes are not the idx signature is refused.
///
/// Only byte 0 changes. The length still clears the minimum, so `Truncated`
/// cannot be what fires.
#[test]
fn an_image_without_the_idx_signature_is_refused() {
    let mut bytes = valid_idx();
    bytes[0] = 0x00;
    assert_eq!(bytes.len(), MINIMUM_LEN, "only the signature may differ");
    assert_eq!(parse(&bytes), Err(PackError::InvalidIndexSignature));
}

/// A version other than 2 is refused, in BOTH directions, and the refusal
/// carries the offending version.
///
/// Version 1 is a real historical idx format, not an arbitrary number, so its
/// refusal is the case that matters in practice. Testing 1 and 3 together is
/// what distinguishes the `!= 2` the parser actually writes from a `> 2` or
/// `< 2` that a one-sided test would accept.
#[test]
fn an_index_version_other_than_two_is_refused_in_both_directions() {
    for version in [1_u32, 3] {
        let mut bytes = valid_idx();
        bytes[4..8].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            parse(&bytes),
            Err(PackError::UnsupportedIndexVersion(version)),
            "idx v{version} must be refused, and the refusal must name the version",
        );
    }
}

/// A large-offset region that is not a whole number of 8-byte slots is refused.
///
/// The large-offset table is an array of `u64`, so a region of 4 bytes cannot
/// be one: something else is in the file. Everything before the region is
/// byte-identical to the image that parses.
#[test]
fn a_partial_large_offset_slot_is_refused() {
    assert_eq!(
        parse(&with_large_offset_region(4)),
        Err(PackError::TrailingIndexBytes),
    );
}

/// The permitted twin at the exact boundary: a WHOLE 8-byte slot is accepted.
///
/// This is the half that gives the test above its meaning. The guard is
/// `large_bytes % 8 != 0`, and a probe that only ever showed "4 extra bytes are
/// refused" is equally consistent with `large_bytes != 0` -- which would reject
/// every index that legitimately has large offsets. Eight bytes distinguishes
/// the two, and it is the smallest input that does.
#[test]
fn a_whole_large_offset_slot_is_accepted() {
    parse(&with_large_offset_region(8))
        .expect("an 8-byte large-offset region is exactly one u64 slot");
}

/// Ordering: a buffer shorter than the minimum reports truncation, and the
/// signature is never consulted.
///
/// The length check at `idx.rs:144` runs before the signature comparison at
/// `:149`. This buffer has a WRONG signature as well, so if the two were
/// reordered it would report `InvalidIndexSignature` and this assertion would
/// fail. That makes the test sensitive to the ordering rather than merely
/// compatible with it.
#[test]
fn a_short_buffer_reports_truncation_before_the_signature_is_judged() {
    let mut bytes = valid_idx();
    bytes[0] = 0x00;
    bytes.truncate(MINIMUM_LEN - 1);

    assert_eq!(
        parse(&bytes),
        Err(PackError::Truncated {
            context: "idx header or checksums",
        }),
        "the length gate runs first, so a short buffer is truncated and not \
         judged on its signature",
    );
}
