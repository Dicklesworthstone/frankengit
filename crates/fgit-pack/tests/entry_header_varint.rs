#![forbid(unsafe_code)]

//! frankengit-dn96: the entry-header varint's shift bound.
//!
//! `decode_entry_header` reads a pack entry's type-and-size varint from
//! untrusted bytes. The size is accumulated seven bits at a time into a `u64`,
//! and a hostile pack can keep setting the continuation bit forever. The bound
//! that stops it (`pack.rs:178`) had no test:
//!
//! ```text
//! shift starts at 4 and grows by 7 per continuation byte:
//!   4, 11, 18, 25, 32, 39, 46, 53, 60, 67
//!                                     ^ first value >= 64  -> InvalidVarint
//! ```
//!
//! So nine continuation reads are admissible and the tenth is refused. That is
//! an exact boundary, and both sides are pinned below.
//!
//! # The second `InvalidVarint` site is dominated, and is recorded not tested
//!
//! `pack.rs:184` builds the same variant from
//! `u64::from(next & 0x7f).checked_shl(shift)`. `checked_shl` returns `None`
//! only when `shift >= 64` — which the guard three lines above has already
//! refused. The second site is therefore **unreachable while the first stands**:
//! it is belt-and-braces against the bound being removed, not a distinct
//! condition. No honest test drives it, and it must not be counted as covered.
//!
//! Three `IntegerOverflow` arms in the same loop are unreachable for the same
//! class of reason — `index.checked_add(1)` and `shift.checked_add(7)` would
//! need counters near `usize::MAX` / `u32::MAX`, and the shift bound caps the
//! loop long before either. Also recorded, also not counted.

use fgit_pack::{EntryKind, PackError, PackLimits, decode_entry_header};

/// A blob entry header byte with the continuation bit set and a zero size
/// nibble: `0x80 | (kind << 4)`.
const BLOB_CONTINUES: u8 = 0x80 | (3 << 4);

/// A continuation byte carrying no size bits, so `value` stays small and only
/// the shift can be what trips.
const CONTINUE: u8 = 0x80;

/// A terminating byte: no continuation bit, no size bits.
const END: u8 = 0x00;

const fn never_expires() -> bool {
    true
}

fn decode(input: &[u8]) -> Result<(fgit_pack::PackEntryHeader, usize), PackError> {
    decode_entry_header(input, &PackLimits::default(), &mut never_expires)
}

/// A varint whose tenth continuation read pushes the shift past 63 is refused.
///
/// Ten continuation-carrying bytes then a terminator. Every payload nibble is
/// zero, so the accumulated value never overflows and `IntegerOverflow` cannot
/// be what fires — only the shift bound can.
#[test]
fn a_varint_shifting_past_sixty_three_is_refused() {
    let mut input = vec![BLOB_CONTINUES];
    input.extend(std::iter::repeat_n(CONTINUE, 9));
    input.push(END);

    assert_eq!(
        decode(&input),
        Err(PackError::InvalidVarint {
            context: "pack entry size",
        }),
    );
}

/// The permitted twin at the exact boundary: nine continuation reads decode.
///
/// One byte shorter than the refusal above. The last shift consulted is 60,
/// which is admissible; the guard is `>= 64`, and written `>= 57` — or any
/// other conservative-looking bound — it would refuse a varint Git itself can
/// emit, while the ten-byte probe still passed.
///
/// Asserted on the decoded header rather than `is_ok`: a decoder that silently
/// produced the wrong size would satisfy a weaker check.
#[test]
fn a_varint_stopping_at_shift_sixty_is_accepted() {
    let mut input = vec![BLOB_CONTINUES];
    input.extend(std::iter::repeat_n(CONTINUE, 8));
    input.push(END);

    let (header, consumed) = decode(&input).expect("nine continuation reads stay within the bound");

    assert_eq!(header.kind, EntryKind::Blob);
    assert_eq!(
        header.declared_size, 0,
        "every payload nibble is zero, so the decoded size is zero",
    );
    assert_eq!(consumed, input.len(), "the whole varint is consumed");
}

/// A continuation bit with nothing after it is truncation, not a bad varint.
///
/// Ordering probe. The truncation check sits immediately above the shift bound,
/// and this input satisfies neither a complete varint nor the shift limit — it
/// simply ends. It must be diagnosed as truncated, which is what a caller needs
/// to distinguish "send me more bytes" from "this pack is malformed".
#[test]
fn a_varint_that_ends_mid_continuation_reports_truncation() {
    assert_eq!(
        decode(&[BLOB_CONTINUES]),
        Err(PackError::Truncated {
            context: "pack entry size varint",
        }),
    );
}
