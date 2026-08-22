#![forbid(unsafe_code)]
//! `max_object_bytes` as a typed refusal at each public entry point
//! (`frankengit-gitobj-object-budget-dapb`).
//!
//! §7 requires bounds enforced BEFORE allocation and work, and several of the
//! surfaces below are `emit_*` paths that build buffers — exactly where a bound
//! applied after an allocation would bite.
//!
//! # The claim here is PER ENTRY POINT, never per site
//!
//! `ObjectError::ObjectTooLarge` is raised at sixteen sites in `src/lib.rs`, and
//! fifteen of them report the identical payload `{ limit: max_object_bytes }`.
//! A caller cannot tell which check fired and neither can a test, so driving
//! entry point X proves nothing about site Y. A per-site coverage claim would be
//! unfalsifiable and none is made anywhere in this file. The honest unit is the
//! public API: either it refuses over-budget input with this typed refusal, or
//! it does not.
//!
//! # Why every probe is a PAIR
//!
//! Each entry point gets a refusal at `max + 1` and a permitted twin at exactly
//! `max`. Every bound below is spelled `> max`, so `max` itself is legal — a
//! refusal-only corpus is satisfied by a guard that refuses everything, and an
//! off-by-one is visible only at the inclusive boundary.
//!
//! # Two sites are NOT covered here, and neither is counted as covered
//!
//! `native_object_hasher` (`src/lib.rs:492`) reports `limit: usize::MAX` from
//! `u64::try_from(declared_size)` where `declared_size: usize`. **That arm is
//! dead by target width**, not by caller discipline: Rust's `usize` is at most
//! 64 bits on every supported target, so the conversion to `u64` is always
//! `Ok` and the `map_err` cannot fire. Recording it as a truthful null rather
//! than manufacturing a probe; it would become reachable only on a target with
//! `usize` wider than 64 bits, which does not exist.
//!
//! `LooseObjectDecoder::push` (`src/lib.rs:396`) raises `ObjectTooLarge` only
//! when `self.body.len().checked_add(chunk.len())` overflows `usize` — also
//! unreachable for the same reason. The decoder's REAL budget enforcement is
//! the header check exercised below, and it is the stronger property anyway.
//!
//! Nothing here modifies `crates/fgit-git-object/src/**`.

use fgit_git_object::{
    AcceptanceProfile, LooseObjectDecoder, ObjectError, ObjectType, ParseLimits, ParsedObject,
    TreeEntry, emit_object_body, emit_tree, parse_object_body, parse_tree,
};

/// SHA-1 tree references are 20 raw bytes.
const REFERENCE_BYTES: usize = 20;

/// `mode SPACE name NUL oid` with a six-byte mode: everything but the name.
const RECORD_OVERHEAD: usize = 6 + 1 + 1 + REFERENCE_BYTES;

/// Small enough that an exact-boundary fixture is cheap to build, and larger
/// than `RECORD_OVERHEAD` so a one-entry tree can reach it exactly.
const MAX: usize = 48;

const fn limits() -> ParseLimits {
    ParseLimits {
        max_object_bytes: MAX,
        max_loose_header_bytes: 128,
        max_tree_entries: 16,
        max_header_lines: 16,
        max_header_line_bytes: 256,
        tree_reference_bytes: REFERENCE_BYTES,
    }
}

fn reference(tag: u8) -> Vec<u8> {
    vec![tag; REFERENCE_BYTES]
}

/// A tree body whose total serialized length is exactly `total` bytes.
fn tree_body_of_len(total: usize) -> Vec<u8> {
    let name_len = total - RECORD_OVERHEAD;
    let mut bytes = b"100644".to_vec();
    bytes.push(b' ');
    bytes.extend_from_slice(&vec![b'a'; name_len]);
    bytes.push(0);
    bytes.extend_from_slice(&reference(0x11));
    assert_eq!(bytes.len(), total, "fixture arithmetic");
    bytes
}

/// A single tree entry whose serialized length is exactly `total` bytes.
///
/// `name_byte` distinguishes entries within one tree. It is a parameter rather
/// than a constant because `emit_tree` refuses a duplicate name BEFORE it
/// reaches the byte total, so a multi-entry fixture built from one byte is
/// refused by the wrong guard.
fn tree_entry_of_len(total: usize, name_byte: u8) -> TreeEntry {
    TreeEntry {
        mode: b"100644".to_vec(),
        name: vec![name_byte; total - RECORD_OVERHEAD],
        object_id: reference(0x11),
    }
}

/// The refusal must be `ObjectTooLarge` AND must name the configured limit.
///
/// Asserting the payload matters: a guard that refused with a different limit
/// would be reporting a bound the caller never configured.
#[track_caller]
fn assert_too_large(error: &ObjectError, what: &str) {
    match error {
        ObjectError::ObjectTooLarge { limit } => assert_eq!(
            *limit, MAX,
            "{what} must name the configured limit, not some other bound"
        ),
        other => panic!("{what} must refuse with ObjectTooLarge, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// parse_object_body
// ---------------------------------------------------------------------------

#[test]
fn parse_object_body_refuses_over_budget_and_accepts_the_exact_bound() {
    let limits = limits();

    let accepted = parse_object_body(
        ObjectType::Blob,
        &vec![b'x'; MAX],
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .expect("a body of exactly max_object_bytes is within the bound");
    assert_eq!(
        accepted,
        ParsedObject::Blob(vec![b'x'; MAX]),
        "the permitted twin must round-trip its bytes, not merely avoid refusing"
    );

    let refused = parse_object_body(
        ObjectType::Blob,
        &vec![b'x'; MAX + 1],
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .expect_err("one byte past the bound must be refused");
    assert_too_large(&refused, "parse_object_body over budget");
}

// ---------------------------------------------------------------------------
// parse_tree
// ---------------------------------------------------------------------------

#[test]
fn parse_tree_refuses_over_budget_and_accepts_the_exact_bound() {
    let limits = limits();

    let entries = parse_tree(
        &tree_body_of_len(MAX),
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .expect("a tree body of exactly max_object_bytes is within the bound");
    assert_eq!(
        entries.len(),
        1,
        "the permitted twin must actually parse, so the refusal below is \
         attributable to the bound rather than to a malformed fixture"
    );

    let refused = parse_tree(
        &tree_body_of_len(MAX + 1),
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .expect_err("one byte past the bound must be refused");
    assert_too_large(&refused, "parse_tree over budget");
}

// ---------------------------------------------------------------------------
// emit_tree
// ---------------------------------------------------------------------------

#[test]
fn emit_tree_refuses_over_budget_and_accepts_the_exact_bound() {
    let limits = limits();

    let emitted = emit_tree(
        &[tree_entry_of_len(MAX, b'a')],
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .expect("a tree emitting exactly max_object_bytes is within the bound");
    assert_eq!(
        emitted.len(),
        MAX,
        "the permitted twin must emit exactly the boundary length"
    );

    let refused = emit_tree(
        &[tree_entry_of_len(MAX + 1, b'a')],
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .expect_err("one byte past the bound must be refused");
    assert_too_large(&refused, "emit_tree over budget");
}

/// The byte bound is reached even when the entry COUNT is legal.
///
/// `emit_tree` checks `max_tree_entries` before the byte total, so a probe that
/// tripped both would not show which guard fired. Two entries is well inside
/// the configured sixteen.
#[test]
fn emit_tree_refuses_on_total_bytes_while_the_entry_count_is_legal() {
    let limits = limits();
    let half = RECORD_OVERHEAD + 1;
    let entries = vec![tree_entry_of_len(half, b'a'), tree_entry_of_len(half, b'b')];
    assert!(
        entries.len() <= limits.max_tree_entries,
        "the entry-count guard must NOT be what fires here"
    );
    assert_ne!(
        entries[0].name, entries[1].name,
        "the names must differ: emit_tree refuses a duplicate name before it \
         reaches the byte total, so equal names would prove the wrong guard"
    );
    assert!(
        half * 2 > MAX,
        "the two entries must together exceed the byte bound"
    );

    let refused = emit_tree(&entries, AcceptanceProfile::StrictCreate, &limits)
        .expect_err("a legal entry count over the byte budget must be refused");
    assert_too_large(&refused, "emit_tree accumulated total");
}

// ---------------------------------------------------------------------------
// emit_object_body
// ---------------------------------------------------------------------------

#[test]
fn emit_object_body_refuses_over_budget_and_accepts_the_exact_bound() {
    let limits = limits();

    let emitted = emit_object_body(
        &ParsedObject::Blob(vec![b'x'; MAX]),
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .expect("a blob of exactly max_object_bytes is within the bound");
    assert_eq!(
        emitted.len(),
        MAX,
        "the permitted twin must emit exactly the boundary length"
    );

    let refused = emit_object_body(
        &ParsedObject::Blob(vec![b'x'; MAX + 1]),
        AcceptanceProfile::StrictCreate,
        &limits,
    )
    .expect_err("one byte past the bound must be refused");
    assert_too_large(&refused, "emit_object_body over budget");
}

// ---------------------------------------------------------------------------
// the streaming decoder
// ---------------------------------------------------------------------------

/// The decoder refuses an over-budget object from its DECLARED SIZE, before a
/// single body byte is accumulated.
///
/// This is the §7 property stated directly: the refusal happens while the
/// header is still being consumed, so an over-budget object never reaches the
/// body buffer at all. Feeding the header and the body in ONE chunk is what
/// makes that observable — if the bound were applied to accumulated bytes
/// instead, this call would have to buffer before deciding.
#[test]
fn the_streaming_decoder_refuses_an_over_budget_declared_size_before_any_body_byte() {
    let mut decoder = LooseObjectDecoder::new(limits());
    let mut input = format!("blob {}\0", MAX + 1).into_bytes();
    input.extend_from_slice(&vec![b'x'; MAX + 1]);

    let refused = decoder
        .push(&input)
        .expect_err("a declared size past the bound must be refused at the header");
    assert_too_large(&refused, "streaming decoder declared size");
}

#[test]
fn the_streaming_decoder_accepts_a_declared_size_at_the_exact_bound() {
    let mut decoder = LooseObjectDecoder::new(limits());
    let mut input = format!("blob {MAX}\0").into_bytes();
    input.extend_from_slice(&vec![b'x'; MAX]);

    decoder
        .push(&input)
        .expect("a declared size of exactly max_object_bytes is within the bound");
    let object = decoder
        .finish()
        .expect("the boundary object must decode to completion");
    assert_eq!(
        object.body.len(),
        MAX,
        "the permitted twin must yield the whole body"
    );
}
