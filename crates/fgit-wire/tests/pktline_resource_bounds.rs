#![forbid(unsafe_code)]
//! The pkt-line resource bounds (`frankengit-88o7`).
//!
//! These are the limits every byte from an untrusted peer crosses before any
//! protocol logic runs, and §6 makes them compatibility semantics rather than
//! implementation detail: *"Resource limits and refusal behavior are
//! compatibility semantics"*, and *"Quarantine all incoming pack/object data
//! until bounded validation completes."*
//!
//! Measured before writing: `WireError` has 41 constructed variants and 26 that
//! no test names — the largest single gap in the workspace. This file closes
//! four of them, the bound cluster:
//!
//! ```text
//! PendingBytesExceeded   PktLineDecoder::push    undecoded bytes held between frames
//! PacketCountExceeded    PktLineDecoder::push    packets yielded by ONE call
//! TruncatedPacket        PktLineDecoder::finish  stream ends between frames
//! OutboundBytesExceeded  TWO sites, see below
//! ```
//!
//! # The guard that made this worth a bead rather than a chore
//!
//! `check_packet_count` reads `decoded_count == self.limits.max_packets_per_push`
//! — **exact equality**, where every other bound in this crate is `>` or `>=`.
//! An equality guard is only sound if the counter provably visits the limit
//! value; if any path could step past it, the bound would be silently
//! unenforced.
//!
//! Resolved by reading `push`, and the answer is that the equality is **safe**.
//! `decoded_count` is `packets.len()` on a vector that gains exactly one element
//! per loop iteration, and the check runs at the top of every iteration, so the
//! sequence is 0, 1, 2, … with no gaps. It cannot skip the limit.
//! [`every_count_up_to_the_bound_is_admitted_so_the_equality_cannot_be_skipped`]
//! is the presence case for that reading rather than an assertion of it: it
//! drives *every* count from 1 to the limit and shows each is admitted, which is
//! what makes the refusal at limit + 1 attributable to the bound.
//!
//! This is a truthful null result. The equality looked like a latent hole and is
//! not one; recording that is the point, so the next reader does not re-derive
//! it or "fix" it into a `>=`.
//!
//! # The boundary is `limit` admitted, not `limit - 1`
//!
//! The bead's acceptance asked for a permitted twin at `limit - 1`. Reading the
//! loop shows the tight boundary is one higher: a call yielding **exactly**
//! `max_packets_per_push` packets succeeds, because the buffer empties and the
//! loop breaks on `pending.len() < 4` before the check can fire again. Only a
//! call that would yield `limit + 1` refuses. The tighter pair is tested, which
//! also satisfies the looser one the bead asked for.
//!
//! # Two sites for one variant
//!
//! `OutboundBytesExceeded` is constructed in `encode_packets` and again in
//! `add_output_packet`, which are different accumulators — the first compares
//! against `output.len()`, the second against a running `used_bytes`. Both are
//! probed, because a refusal reached only through one says nothing about the
//! other. `Capabilities::encode_v2_advertisement` is the public route to the
//! second.
//!
//! # Non-claims
//!
//! Four of twenty-six unnamed `WireError` variants. The capability cluster
//! (`CapabilityTooLarge`, `TooManyCapabilities`, `DuplicateCapability`,
//! `InvalidVersionAdvertisement`), the fetch-negotiation cluster (`InvalidDepth`,
//! `InvalidTimestamp`, `UnknownDeepenNotRef`, `InvalidFilter`,
//! `TooManyFilterParts`), the advertisement cluster and the sideband pair all
//! remain. LEAD count, not a remaining-work total.
//!
//! This file deliberately does **not** touch `tests/receivepack_adversarial.rs`
//! or `tests/receivepack_limits_propagation.rs`:
//! `scripts/e2e/suites/wire/receivepack_adversarial.sh` counts passing probes in
//! those two named `--test` targets and asserts exact totals, so editing them
//! would change an e2e assertion. A new file with a new name does not.
//!
//! Nothing here modifies `crates/fgit-wire/src/**`.

use fgit_wire::{Capabilities, Packet, PktLineDecoder, WireError, WireLimits, encode_packets};

/// A frame header declaring a 100-byte total (four-byte header + 96 payload).
const FRAME_100: &[u8] = b"0064";

/// Limits whose pending bound is as tight as `validate` permits: equal to the
/// packet bound, so one incomplete frame can fill it exactly.
fn tight_pending_limits() -> WireLimits {
    WireLimits {
        max_packet_bytes: 100,
        max_pending_bytes: 100,
        ..WireLimits::default()
    }
}

fn packet_count_limits(max_packets_per_push: usize) -> WireLimits {
    WireLimits {
        max_packets_per_push,
        ..WireLimits::default()
    }
}

fn outbound_limits(max_outbound_bytes: usize) -> WireLimits {
    WireLimits {
        max_outbound_bytes,
        ..WireLimits::default()
    }
}

/// A decoder holding 94 bytes of a declared 100-byte frame: six short.
fn decoder_with_partial_frame() -> PktLineDecoder {
    let mut decoder = PktLineDecoder::new(tight_pending_limits()).expect("tight limits validate");
    let mut partial = FRAME_100.to_vec();
    partial.extend(std::iter::repeat_n(b'a', 90));
    let packets = decoder
        .push(&partial)
        .expect("an incomplete frame is held, not refused");
    assert!(
        packets.is_empty(),
        "an incomplete frame yields no packets yet"
    );
    assert_eq!(decoder.pending_len(), 94, "94 of the declared 100 bytes");
    decoder
}

/// `n` complete flush packets back to back.
fn flushes(n: usize) -> Vec<u8> {
    b"0000".repeat(n)
}

// ---------------------------------------------------------------------------
// The baseline control
// ---------------------------------------------------------------------------

/// The default limits build a decoder and a fresh decoder finishes cleanly.
///
/// Without this, every refusal below could be a rejected fixture rather than
/// the bound the test is named for.
#[test]
fn the_default_limits_build_a_decoder_that_finishes_clean() {
    let decoder = PktLineDecoder::new(WireLimits::default()).expect("default limits validate");
    decoder
        .finish()
        .expect("a decoder that consumed nothing is between frames, not mid-frame");
    assert_eq!(decoder.pending_len(), 0);
}

// ---------------------------------------------------------------------------
// PendingBytesExceeded
// ---------------------------------------------------------------------------

/// One byte past the pending bound is refused.
///
/// The decoder already holds 94 of a declared 100-byte frame, so six bytes are
/// available; seven is one too many.
#[test]
fn pending_bytes_past_the_bound_are_refused() {
    let mut decoder = decoder_with_partial_frame();
    let error = decoder
        .push(&[b'b'; 7])
        .expect_err("seven bytes into six bytes of headroom must refuse");
    assert_eq!(
        error,
        WireError::PendingBytesExceeded { limit: 100 },
        "the refusal must name the pending bound"
    );
}

/// **The permitted twin at the exact boundary.** Filling the headroom exactly
/// is admitted — and completes the frame, so the call also yields its packet.
///
/// The guard reads `bytes.len() > available`, so `== available` is legal.
/// Tightening it to `>=` would leave the refusal above green and break only
/// this.
#[test]
fn pending_bytes_at_exactly_the_bound_are_admitted() {
    let mut decoder = decoder_with_partial_frame();
    let packets = decoder
        .push(&[b'b'; 6])
        .expect("six bytes into six bytes of headroom is exactly the bound");
    assert_eq!(packets.len(), 1, "the completed frame decodes");
    assert_eq!(decoder.pending_len(), 0, "and is drained");
    match &packets[0] {
        Packet::Data(payload) => assert_eq!(payload.len(), 96, "100 total minus the 4-byte header"),
        other => panic!("a completed data frame must decode as data, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// PacketCountExceeded — and the equality guard
// ---------------------------------------------------------------------------

/// One packet past the per-call bound is refused.
#[test]
fn more_packets_than_the_bound_in_one_call_are_refused() {
    let mut decoder = PktLineDecoder::new(packet_count_limits(3)).expect("limits validate");
    let error = decoder
        .push(&flushes(4))
        .expect_err("a fourth packet in one call must refuse at a bound of three");
    assert_eq!(error, WireError::PacketCountExceeded { limit: 3 });
}

/// **The tight boundary.** Exactly the bound, in one call, is admitted.
///
/// This is one higher than the bead asked for, and reading the loop is what
/// found it: after the third packet the buffer is empty, so `pending.len() < 4`
/// breaks the loop before `check_packet_count` runs again.
#[test]
fn exactly_the_bound_of_packets_in_one_call_is_admitted() {
    let mut decoder = PktLineDecoder::new(packet_count_limits(3)).expect("limits validate");
    let packets = decoder
        .push(&flushes(3))
        .expect("exactly the bound must be admitted");
    assert_eq!(packets.len(), 3);
    assert_eq!(decoder.pending_len(), 0);
}

/// The presence case for the equality guard being sound.
///
/// `check_packet_count` tests `==` rather than `>=`, which is only safe if the
/// counter visits every value. It is `packets.len()` on a vector that gains
/// exactly one element per iteration, checked once per iteration — so this
/// drives every count from 1 to the bound and shows each is admitted, then
/// shows `bound + 1` refuses. Together those make the refusal attributable to
/// the bound rather than to some count being skipped.
#[test]
fn every_count_up_to_the_bound_is_admitted_so_the_equality_cannot_be_skipped() {
    const BOUND: usize = 5;
    for count in 1..=BOUND {
        let mut decoder = PktLineDecoder::new(packet_count_limits(BOUND)).expect("limits validate");
        let packets = decoder.push(&flushes(count)).unwrap_or_else(|error| {
            panic!("{count} packets at a bound of {BOUND} must be admitted, got {error:?}")
        });
        assert_eq!(packets.len(), count);
    }

    let mut decoder = PktLineDecoder::new(packet_count_limits(BOUND)).expect("limits validate");
    let error = decoder
        .push(&flushes(BOUND + 1))
        .expect_err("one past the bound must refuse");
    assert_eq!(error, WireError::PacketCountExceeded { limit: BOUND });
}

// ---------------------------------------------------------------------------
// TruncatedPacket
// ---------------------------------------------------------------------------

/// A stream that stops mid-frame is refused when the caller finishes.
#[test]
fn a_stream_ending_between_frames_is_refused_at_finish() {
    let decoder = decoder_with_partial_frame();
    let error = decoder
        .finish()
        .expect_err("94 bytes of a 100-byte frame is not a complete stream");
    assert_eq!(error, WireError::TruncatedPacket { pending: 94 });
}

/// Two permitted twins, so the refusal above is attributable to the partial
/// frame rather than to `finish` being strict about anything else.
///
/// A decoder that consumed nothing finishes clean, and so does one that
/// consumed a *complete* frame — the difference is only the leftover bytes.
#[test]
fn finish_is_clean_on_an_empty_decoder_and_after_a_complete_frame() {
    PktLineDecoder::new(WireLimits::default())
        .expect("default limits validate")
        .finish()
        .expect("a decoder that consumed nothing is not mid-frame");

    let mut decoder = PktLineDecoder::new(WireLimits::default()).expect("default limits validate");
    let packets = decoder
        .push(&flushes(1))
        .expect("one complete frame decodes");
    assert_eq!(packets.len(), 1);
    decoder
        .finish()
        .expect("a fully consumed stream is not mid-frame");
}

// ---------------------------------------------------------------------------
// OutboundBytesExceeded — site 1, encode_packets
// ---------------------------------------------------------------------------

/// Two flush packets encode to eight bytes; a seven-byte ceiling refuses the
/// second.
#[test]
fn encode_packets_refuses_past_the_outbound_bound() {
    let error = encode_packets(&[Packet::Flush, Packet::Flush], &outbound_limits(7))
        .expect_err("eight bytes of output must not fit a seven-byte ceiling");
    assert_eq!(error, WireError::OutboundBytesExceeded { limit: 7 });
}

/// **The permitted twin at the exact boundary**: output of exactly the ceiling
/// is admitted.
#[test]
fn encode_packets_at_exactly_the_outbound_bound_is_admitted() {
    let encoded = encode_packets(&[Packet::Flush, Packet::Flush], &outbound_limits(8))
        .expect("output of exactly the ceiling must be admitted");
    assert_eq!(encoded, b"00000000", "two flush packets, eight bytes");
}

// ---------------------------------------------------------------------------
// OutboundBytesExceeded — site 2, add_output_packet
// ---------------------------------------------------------------------------

/// The advertisement encoder accumulates through a different counter than
/// `encode_packets`, so it gets its own probe.
///
/// An empty advertisement is `version 2\n` (10 bytes + 4 header = 14) followed
/// by a flush (4): eighteen bytes. A seventeen-byte ceiling admits the version
/// line and refuses the flush.
#[test]
fn the_v2_advertisement_encoder_refuses_past_the_outbound_bound() {
    let error = Capabilities::default()
        .encode_v2_advertisement(&outbound_limits(17))
        .expect_err("eighteen bytes of advertisement must not fit a seventeen-byte ceiling");
    assert_eq!(error, WireError::OutboundBytesExceeded { limit: 17 });
}

/// **The permitted twin at the exact boundary** for the second site.
#[test]
fn the_v2_advertisement_encoder_at_exactly_the_outbound_bound_is_admitted() {
    let packets = Capabilities::default()
        .encode_v2_advertisement(&outbound_limits(18))
        .expect("an advertisement of exactly the ceiling must be admitted");
    assert_eq!(packets.len(), 2, "the version line and the closing flush");
    assert_eq!(packets[0], Packet::Data(b"version 2\n".to_vec()));
    assert_eq!(packets[1], Packet::Flush);
}
