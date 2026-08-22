#![forbid(unsafe_code)]

//! frankengit-eit2: the pack entry's inflated-size commitment.
//!
//! A pack entry header declares the size of the object it carries, before the
//! zlib member is decompressed. `AGENTS.md` §4 names "a decoder result accepted
//! without original commitments" as a forbidden substitute, and §6 requires
//! incoming pack data to stay in quarantine until bounded validation completes.
//! This is that commitment for the entry decoder: what came out must be the
//! length the header promised.
//!
//! `InflatedEntrySizeMismatch` had no test anywhere in the workspace. It is
//! constructed at two sites, and the interesting result of this bead is that
//! they are reachable under sharply different conditions.
//!
//! # The two sites, and why one is nearly dead
//!
//! * `reader.rs:244`, after the stream finishes -- the entry inflated SHORT of
//!   its declaration. Reachable for any declared size.
//! * `reader.rs:297`, inside `append_inflated` -- appending would OVERRUN the
//!   declaration. Reachable at exactly one declared size: **zero**.
//!
//! The reason is `inflate_limits` (reader.rs:272), which hands the inflater
//! `max_output_bytes: declared_size.max(1)`. For any declared size of one or
//! more, the inflater's own output budget IS the declared size, so it refuses
//! with `Inflate(ResourceLimit { resource: OutputBytes, .. })` before
//! `append_inflated` ever sees an overrun. The `.max(1)` is what leaves a door
//! open at zero: a zero-length entry lets the inflater emit one byte, and that
//! byte is what `:297` catches.
//!
//! Every payload asserted below was MEASURED first and then written down, not
//! predicted. The oversize case in particular does not report the variant one
//! would expect, which is exactly why it gets a test of its own.

mod fixtures;

use fgit_pack::{ObjectFormat, PackError, parse_quarantined_pack};

/// Native pack entry type 3, a blob.
const KIND_BLOB: u8 = 3;
const PAYLOAD: &[u8] = b"hello";

/// A zlib member wrapping one stored (uncompressed) DEFLATE block.
///
/// Stored rather than compressed so the inflated length is exactly the input
/// length, with no dependence on how the encoder chose to pack symbols.
fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).expect("fixture member is small");
    let mut member = vec![0x78, 0x01, 0x01];
    member.extend_from_slice(&length.to_le_bytes());
    member.extend_from_slice(&(!length).to_le_bytes());
    member.extend_from_slice(bytes);
    member.extend_from_slice(&adler32(bytes).to_be_bytes());
    member
}

fn adler32(bytes: &[u8]) -> u32 {
    let mut a = 1_u32;
    let mut b = 0_u32;
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

/// Parses a one-entry pack, returning the entry count so a success is asserted
/// on something rather than merely being `Ok`.
fn parse_one(entry: Vec<u8>) -> Result<usize, PackError> {
    parse_quarantined_pack(
        &fixtures::pack_with_entries(&[entry]),
        ObjectFormat::Sha1,
        &fixtures::limits(),
        &mut fixtures::always,
    )
    .map(|pack| pack.entries().len())
}

/// An entry that inflates to fewer bytes than it declared is refused.
///
/// This is `reader.rs:244`, the post-stream check. Without it a truncated or
/// doctored member yields a SHORT object presented as complete -- and a short
/// object is still a well-formed object, so nothing downstream would notice.
#[test]
fn an_entry_inflating_short_of_its_declared_size_is_refused() {
    let declared = PAYLOAD.len() + 4;

    assert_eq!(
        parse_one(fixtures::declared_entry(
            KIND_BLOB,
            declared,
            &zlib_stored(PAYLOAD),
        )),
        Err(PackError::InflatedEntrySizeMismatch {
            declared,
            actual: PAYLOAD.len(),
        }),
    );
}

/// An oversize entry is refused by the INFLATER, not by the pack reader.
///
/// This pins the layering, and it is the test that explains why `:297` is
/// otherwise unreachable. `inflate_limits` gives the inflater
/// `max_output_bytes: declared_size.max(1)`, so at any nonzero declared size
/// the inflater stops the moment output would exceed it and reports its own
/// resource refusal. The pack reader's overrun branch is never consulted.
///
/// Recorded as an executable fact rather than a comment because it is a
/// cross-layer coupling: change the inflater's budget and this refusal silently
/// becomes a different variant, which callers matching on `Inflate` would stop
/// seeing.
#[test]
fn an_oversize_entry_is_refused_by_the_inflater_before_the_reader_sees_it() {
    let refusal = parse_one(fixtures::declared_entry(
        KIND_BLOB,
        PAYLOAD.len() - 3,
        &zlib_stored(PAYLOAD),
    ));

    assert!(
        matches!(refusal, Err(PackError::Inflate(_))),
        "the inflater's own output budget must fire first, not the reader's \
         overrun branch; got {refusal:?}",
    );
}

/// A zero-length entry that inflates any bytes at all is refused.
///
/// This is `reader.rs:297`, and this is the ONLY input that reaches it. The
/// `.max(1)` in `inflate_limits` permits the inflater one byte of output even
/// when the entry declared none, so the overrun branch is what catches that
/// byte. At every other declared size the inflater refuses first.
#[test]
fn a_zero_length_entry_that_inflates_any_bytes_is_refused() {
    assert_eq!(
        parse_one(fixtures::declared_entry(KIND_BLOB, 0, &zlib_stored(b"x"))),
        Err(PackError::InflatedEntrySizeMismatch {
            declared: 0,
            actual: 1,
        }),
    );
}

/// The permitted twin at the exact boundary: a genuinely empty entry is
/// accepted.
///
/// An empty blob is a real Git object and must parse. This is the half that
/// stops the zero-length probe above from being satisfied by a guard that
/// simply rejected every zero-declared entry.
#[test]
fn a_zero_length_entry_that_inflates_nothing_is_accepted() {
    assert_eq!(
        parse_one(fixtures::declared_entry(KIND_BLOB, 0, &zlib_stored(b""))),
        Ok(1),
        "an empty blob declares zero bytes and inflates to zero bytes",
    );
}

/// The ordinary permitted twin: an honest entry parses.
///
/// `fixtures::entry` builds the header from the payload's real length, so this
/// differs from the short probe in exactly the declared number.
#[test]
fn an_entry_matching_its_declared_size_is_accepted() {
    assert_eq!(parse_one(fixtures::entry(KIND_BLOB, PAYLOAD)), Ok(1));
}
