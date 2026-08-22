#![forbid(unsafe_code)]

//! frankengit-3qss: the two size commitments a Git delta header makes.
//!
//! A delta is not self-describing data; it is a program whose header commits to
//! two facts before a single instruction runs -- the exact length of the base it
//! must be applied to, and the exact length of the object it must produce.
//! `AGENTS.md` §4 names "a decoder result accepted without original commitments"
//! as a forbidden substitute, and §6 requires incoming pack data to stay in
//! quarantine until bounded validation completes. These two checks are those
//! commitments for the delta decoder.
//!
//! Before this file, `DeltaBaseSizeMismatch` and `DeltaResultSizeMismatch`
//! appeared nowhere in the workspace except their declaration in `src/lib.rs`
//! and their construction in `src/delta.rs`. No test named either.
//!
//! `DeltaResultSizeMismatch` is raised at TWO sites that mean different things,
//! and the outer variant does not distinguish them:
//!
//! * `delta.rs:803` (in `append_copy`) -- an instruction would push the result
//!   PAST the declared length. Caught eagerly, mid-stream, before the bytes are
//!   appended.
//! * `delta.rs:681` (after the instruction loop) -- the stream ended and the
//!   result is SHORT of the declared length.
//!
//! The only available discriminator is the payload direction: over-production
//! reports `actual > declared`, under-production reports `actual < declared`.
//! Every probe below therefore asserts the full payload rather than the
//! variant, and `the_two_result_size_refusals_are_told_apart_only_by_direction`
//! makes that the explicit subject of a test.

use fgit_pack::{PackError, PackLimits, apply_delta};

/// The base object every probe applies its delta to.
const BASE: &[u8] = b"base-object";

/// The literal payload the single insert instruction carries.
const LITERAL: &[u8] = b"wxyz";

/// Appends a delta-header size in Git's little-endian base-128 varint form.
///
/// This is the encoding `read_delta_size` consumes: seven value bits per byte,
/// low group first, with the high bit set on every byte but the last.
fn push_size(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).expect("seven bits fit a u8");
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

/// A complete delta: a header declaring `declared_base` and `declared_result`,
/// then one literal-insert instruction carrying `LITERAL`.
///
/// Holding the instruction stream FIXED across every probe is what makes the
/// refusals attributable: only the two declared numbers ever change, so a
/// refusal cannot be blamed on a malformed instruction.
fn delta_declaring(declared_base: usize, declared_result: usize) -> Vec<u8> {
    let mut delta = Vec::new();
    push_size(declared_base, &mut delta);
    push_size(declared_result, &mut delta);
    let length = u8::try_from(LITERAL.len()).expect("literal fits one instruction byte");
    assert!(
        length > 0 && length < 0x80,
        "an insert instruction is a nonzero byte with the high bit clear",
    );
    delta.push(length);
    delta.extend_from_slice(LITERAL);
    delta
}

/// A deadline that never fires.
///
/// `checkpoint` treats `true` as "budget remains" (lib.rs:150), so every
/// refusal below is attributable to a size commitment and never to budget
/// exhaustion. Default limits are used for the same reason: the objects here
/// are eleven bytes, so no resource guard can be what fires.
const fn never_expires() -> bool {
    true
}

fn apply(delta: &[u8]) -> Result<Vec<u8>, PackError> {
    apply_delta(BASE, delta, &PackLimits::default(), &mut never_expires)
}

/// The permitted twin: a delta whose header tells the truth applies cleanly.
///
/// This is the load-bearing half. The three refusal probes below differ from
/// this call in exactly one number each, and without it they would all pass
/// against an `apply_delta` that refused unconditionally.
#[test]
fn a_delta_matching_both_declared_sizes_applies() {
    assert_eq!(
        apply(&delta_declaring(BASE.len(), LITERAL.len())),
        Ok(LITERAL.to_vec()),
        "a header that tells the truth about both sizes must apply",
    );
}

/// A delta declaring a base length other than the one it is handed is refused.
///
/// This is the commitment binding a delta to its base OBJECT. Without it a
/// delta could be applied against the wrong base and still produce a
/// well-formed result of the right length -- a decoder result accepted without
/// its original commitment, which is precisely the §4 substitute.
///
/// Both directions are checked. The guard is `!=`, and an inequality written in
/// one direction would still pass a test that only ever declared too much.
#[test]
fn a_delta_declaring_the_wrong_base_size_is_refused() {
    for declared in [BASE.len() - 1, BASE.len() + 1] {
        assert_eq!(
            apply(&delta_declaring(declared, LITERAL.len())),
            Err(PackError::DeltaBaseSizeMismatch {
                declared,
                actual: BASE.len(),
            }),
            "a delta declaring a {declared}-byte base cannot be applied to a \
             {}-byte one",
            BASE.len(),
        );
    }
}

/// A delta whose instructions stop short of the declared result is refused.
///
/// Raised at `delta.rs:681`, after the instruction loop ends. Without it a
/// truncated instruction stream would yield a SHORT object presented as
/// complete -- the failure mode with no loud symptom, since a short object is
/// still a valid object.
#[test]
fn a_delta_producing_fewer_bytes_than_declared_is_refused() {
    let declared = LITERAL.len() + 4;
    assert_eq!(
        apply(&delta_declaring(BASE.len(), declared)),
        Err(PackError::DeltaResultSizeMismatch {
            declared,
            actual: LITERAL.len(),
        }),
        "an instruction stream that ends early cannot satisfy its declaration",
    );
}

/// A delta whose instructions overrun the declared result is refused.
///
/// Raised at `delta.rs:803`, inside `append_copy`, BEFORE the bytes are
/// appended -- the refusal is what keeps the overrun from being written at all,
/// so `actual` here is the length the append WOULD have reached, not a length
/// the buffer ever held.
#[test]
fn a_delta_producing_more_bytes_than_declared_is_refused() {
    let declared = LITERAL.len() - 1;
    assert_eq!(
        apply(&delta_declaring(BASE.len(), declared)),
        Err(PackError::DeltaResultSizeMismatch {
            declared,
            actual: LITERAL.len(),
        }),
        "an instruction that would overrun the declaration must refuse before \
         appending",
    );
}

/// The two `DeltaResultSizeMismatch` sites are distinguishable only by
/// direction.
///
/// Recorded as an executable fact rather than a comment, because it is a real
/// limitation of the current error type: a caller that matches on the variant
/// alone cannot tell "the stream ended early" from "the stream overran", which
/// are different diagnoses about a hostile or corrupt pack. If the variant is
/// ever split, this test is what will fail and point at the decision.
///
/// This asserts the discriminator EXISTS; it does not endorse it.
#[test]
fn the_two_result_size_refusals_are_told_apart_only_by_direction() {
    let short = apply(&delta_declaring(BASE.len(), LITERAL.len() + 4));
    let long = apply(&delta_declaring(BASE.len(), LITERAL.len() - 1));

    let (short_declared, short_actual) = match short {
        Err(PackError::DeltaResultSizeMismatch { declared, actual }) => (declared, actual),
        other => panic!("an early-ending stream must refuse: {other:?}"),
    };
    let (long_declared, long_actual) = match long {
        Err(PackError::DeltaResultSizeMismatch { declared, actual }) => (declared, actual),
        other => panic!("an overrunning stream must refuse: {other:?}"),
    };

    assert!(
        short_actual < short_declared,
        "under-production must report actual below declared",
    );
    assert!(
        long_actual > long_declared,
        "over-production must report actual above declared",
    );
}
