#![forbid(unsafe_code)]

//! frankengit-hw6t: `StreamingSegmentVerifier`'s declared-total commitment.
//!
//! The verifier is told a segment's total length up front and then fed chunks.
//! That declared total is a commitment the stream must meet exactly: too many
//! bytes and the footer digest would be assembled from the wrong window, too
//! few and the hash covers a prefix of the segment the sender promised.
//! AGENTS.md §4 names "a decoder result accepted without original commitments"
//! as a forbidden substitute, and §7 wants the bound enforced during the work
//! rather than after it.
//!
//! `StreamingLengthMismatch` had no test anywhere in the workspace.
//!
//! # Four construction sites, two reachable
//!
//! ```text
//! lib.rs:1111  push   chunk_end > total_len    over-run      REACHABLE
//! lib.rs:1136  finish received != total_len    under-run     REACHABLE
//! lib.rs:1119  push   state.as_mut() is None                 unreachable
//! lib.rs:1141  finish state.take() is None                   unreachable
//! ```
//!
//! The two `state` arms cannot fire. `new` always sets `state: Some(..)`, and
//! the ONLY thing that clears it is `finish`, which takes `self` by value and
//! therefore consumes the verifier. There is no sequence of public calls that
//! reaches either arm, so they are recorded as unreachable rather than counted;
//! manufacturing one would mean constructing the struct by hand, which its
//! private fields correctly prevent.
//!
//! # Every assertion is on the CALL that should refuse
//!
//! Both reachable sites report the same payloadless variant, so a test that
//! only checked the final outcome could not tell an over-run caught at `push`
//! from an under-run caught at `finish`. Asserting the `push` result separately
//! from the `finish` result is what makes these tests notice which site ran --
//! and the mutation matrix confirms it: disabling the push guard leaves the
//! stream failing at `finish` with the identical error.
//!
//! Every value below was measured before it was written down.

use fgit_object_fabric::{CryptoDigest, FabricError, SegmentLimits, StreamingSegmentVerifier};

/// The smallest segment the verifier admits: `FOOTER_BYTES`.
///
/// A shorter declaration is refused by `new` as `Truncated`, which is a
/// different guard and is pinned separately below so this constant cannot
/// drift into meaninglessness.
const TOTAL: usize = 92;

/// The verifier hashes everything before the trailing 32-byte commitment.
const DIGEST_OFFSET: usize = TOTAL - 32;

const fn limits() -> SegmentLimits {
    SegmentLimits {
        max_segment_bytes: 64 * 1024,
        max_records: 128,
        max_namespace_bytes: 16,
        max_object_identity_bytes: 32,
        max_envelope_bytes: 256,
        max_record_bytes: 512,
    }
}

fn verifier(total: usize) -> StreamingSegmentVerifier<'static, CryptoDigest> {
    StreamingSegmentVerifier::new(&CryptoDigest, total, &limits())
        .expect("a total of at least the footer size is admitted")
}

fn filler(len: usize) -> Vec<u8> {
    vec![7_u8; len]
}

/// A chunk carrying the stream past its declared total is refused AT THE PUSH.
///
/// Asserted on `push` rather than on the eventual outcome, and that is the
/// whole point: disable this guard and the over-run is still caught at
/// `finish`, reporting the identical variant. Only the call site separates
/// them.
#[test]
fn a_chunk_past_the_declared_total_is_refused_at_the_push() {
    let mut verifier = verifier(TOTAL);

    assert_eq!(
        verifier.push(&filler(TOTAL + 1)),
        Err(FabricError::StreamingLengthMismatch),
    );
}

/// Finishing before the declared total is reached is refused AT THE FINISH.
///
/// The short chunk itself is legitimate — a stream is allowed to arrive in
/// pieces — so `push` must accept it and only `finish` may object. Asserting
/// both halves is what distinguishes "short chunks are rejected" (which would
/// break all chunked streaming) from "an incomplete stream is rejected".
#[test]
fn finishing_short_of_the_declared_total_is_refused_at_the_finish() {
    let mut verifier = verifier(TOTAL);

    verifier
        .push(&filler(TOTAL - 1))
        .expect("a partial chunk is a normal streaming step, not an error");

    assert_eq!(verifier.finish(), Err(FabricError::StreamingLengthMismatch),);
}

/// The permitted twin at the exact inclusive boundary: a final chunk landing
/// exactly on the declared total is accepted BY THE PUSH.
///
/// This is the ordinary end of EVERY complete stream, and the guard is
/// `chunk_end > total_len`. Written `>=` it would reject the last chunk of
/// every well-formed segment, making the verifier unable to accept anything --
/// and the over-run probe above would still pass under that change.
///
/// Deliberately asserts ONLY the push. Its sibling below asserts only the
/// finish. Combining them would let an over-strict push guard and an
/// over-strict finish guard kill the same test, and the matrix could not tell
/// which one a change had touched.
#[test]
fn a_final_chunk_reaching_exactly_the_declared_total_is_accepted() {
    let mut verifier = verifier(TOTAL);

    verifier
        .push(&filler(TOTAL))
        .expect("a chunk ending exactly on the declared total must be admitted");
}

/// A complete stream passes the length gate at `finish` and reaches the digest
/// check.
///
/// `finish` reports `SegmentDigestMismatch`, not `StreamingLengthMismatch`, and
/// that is the assertion rather than an inconvenience: the filler bytes are not
/// a real segment, so the digest cannot match, and the error MOVING to the
/// digest check is precisely the evidence that the length commitment was
/// satisfied and the verifier proceeded past it.
///
/// This is the twin for the finish-side guard, which is `received != total_len`
/// -- written `<=` it would reject every complete stream while the
/// short-stream probe above still passed.
#[test]
fn a_complete_stream_passes_the_length_gate_and_reaches_the_digest_check() {
    let mut verifier = verifier(TOTAL);
    verifier.push(&filler(TOTAL)).expect("the complete stream");

    assert_eq!(
        verifier.finish(),
        Err(FabricError::SegmentDigestMismatch),
        "reaching the digest check proves the length commitment was met",
    );
}

/// A stream split across chunks accumulates to the declared total.
///
/// Split at the digest offset, so one chunk is entirely hashed content and the
/// other is entirely the trailing commitment — the boundary the push loop
/// actually branches on. A verifier that mishandled the split would either
/// refuse a legitimate stream or hash the wrong window.
#[test]
fn a_stream_split_across_chunks_accumulates_to_the_declared_total() {
    let mut verifier = verifier(TOTAL);

    verifier
        .push(&filler(DIGEST_OFFSET))
        .expect("the hashed prefix is a legitimate chunk");
    verifier
        .push(&filler(TOTAL - DIGEST_OFFSET))
        .expect("the trailing commitment completes the declared total");

    assert_eq!(
        verifier.finish(),
        Err(FabricError::SegmentDigestMismatch),
        "two chunks summing to the total satisfy the length commitment exactly \
         as one chunk does",
    );
}

/// A declared total below the footer size is refused by the constructor.
///
/// A different guard from the ones above, pinned so `TOTAL` is anchored to a
/// measured minimum rather than being a magic number: one byte less and the
/// verifier will not be built at all.
#[test]
fn a_declared_total_below_the_footer_size_is_refused() {
    assert_eq!(
        StreamingSegmentVerifier::new(&CryptoDigest, TOTAL - 1, &limits())
            .map(|_| ())
            .unwrap_err(),
        FabricError::Truncated,
    );
}
