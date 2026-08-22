#![forbid(unsafe_code)]
//! Capability-negotiation refusals (`frankengit-m0mj`).
//!
//! §6 keeps fetch and push as separate service/capability matrices and makes
//! resource limits and refusal behaviour compatibility semantics. Capability
//! parsing is where an untrusted peer's advertised feature set is admitted or
//! refused, and a duplicate or over-long capability is exactly the ambiguity a
//! downstream negotiation would otherwise resolve arbitrarily.
//!
//! Measured before writing (scan reads every file under `tests/`, not only
//! `.rs`): `WireError` is 26 unnamed of 41 constructed. `frankengit-88o7`
//! closed the pkt-line resource bounds; this is the capability cluster, a
//! different surface with different entry points.
//!
//! # Three properties that force the probes into a particular shape
//!
//! **The duplicate rule collides on NAME only.** `insert` compares
//! `entry.name`, not the whole capability, so `foo=1` and `foo=2` must collide.
//! A probe using two *identical* tokens would still pass against an
//! implementation that compared whole capabilities, so it would not test the
//! property the guard actually has.
//!
//! **`InvalidToken` carries `{field, offset, byte}`, and that payload is the
//! only thing telling its two sites apart** — `"capability"` at the name site,
//! `"capability value"` at the value site. Both are asserted in full; matching
//! the bare variant would let one probe appear to cover both.
//!
//! **One helper, different behaviour per caller.** `Capability::parse` and
//! `Capability::parse_v2` both delegate to `parse_with_spaces` with
//! `allow_value_spaces` `false` and `true`. So a value containing a space is
//! **refused by v1 and admitted by v2**.
//! [`the_two_surfaces_disagree_on_a_space_inside_a_value`] asserts the
//! disagreement in one test, which is what would catch either caller's flag
//! being flipped — neither surface's own probes can see that alone.
//!
//! # The equality bound, settled by reading
//!
//! `insert` reads `self.entries.len() == limits.max_capabilities` — exact
//! equality, the same shape as `check_packet_count` in `88o7`. It is **safe**:
//! `entries` is a `Vec` pushed exactly once per successful `insert`, and the
//! check runs before every push, so the length sequence is 0, 1, 2, … with no
//! gaps and cannot step over the limit.
//! [`every_count_up_to_the_capability_bound_is_admitted`] is the presence case
//! for that reading. A truthful null result, recorded so nobody "fixes" it into
//! a `>=` and moves the boundary by one.
//!
//! # Scope grew by one
//!
//! The bead scoped four variants plus two sites. `MissingLineFeed` sits on the
//! same v2 advertisement path — an advertisement line that does not end in LF —
//! and cost one probe, so it is closed here too rather than left for a
//! follow-up.
//!
//! # Non-claims
//!
//! Four more of the 26 unnamed `WireError` variants, plus `MissingLineFeed` and
//! two previously-uncovered `EmptyCapability` sites. The fetch-negotiation
//! cluster (`InvalidDepth`, `InvalidTimestamp`, `UnknownDeepenNotRef`,
//! `InvalidFilter`, `TooManyFilterParts`), the advertisement cluster
//! (`RefNameTooLarge`, `TooManyAdvertisedRefs`,
//! `UnsortedOrDuplicateAdvertisement`) and the sideband pair remain. LEAD
//! count, not a remaining-work total.
//!
//! This file deliberately does not touch `tests/receivepack_adversarial.rs` or
//! `tests/receivepack_limits_propagation.rs`, whose passing-probe counts are
//! asserted exactly by `scripts/e2e/suites/wire/receivepack_adversarial.sh`.
//!
//! Nothing here modifies `crates/fgit-wire/src/**`.

use fgit_wire::{Capabilities, Capability, Packet, WireError, WireLimits};

/// Mirrors the crate-private capability-name/value byte bound used below.
const SMALL_CAPABILITY_BYTES: usize = 16;

fn limits() -> WireLimits {
    WireLimits::default()
}

fn capped(max_capabilities: usize, max_capability_bytes: usize) -> WireLimits {
    WireLimits {
        max_capabilities,
        max_capability_bytes,
        ..WireLimits::default()
    }
}

/// One v2 advertisement line: the token plus its required LF.
fn line(token: &[u8]) -> Packet {
    let mut data = token.to_vec();
    data.push(b'\n');
    Packet::Data(data)
}

fn version_line() -> Packet {
    Packet::Data(b"version 2\n".to_vec())
}

// ---------------------------------------------------------------------------
// The permitted terminus, first
// ---------------------------------------------------------------------------

/// A well-formed v1 capability set parses, preserving order and values.
///
/// Every refusal below is measured against this; without it a parser that
/// rejected everything would satisfy the whole file.
#[test]
fn a_well_formed_v1_capability_set_parses() {
    let parsed = Capabilities::parse_v1(b"ofs-delta side-band-64k agent=fgit/1", &limits())
        .expect("a canonical v1 capability set must parse");
    let entries = parsed.entries();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, b"ofs-delta");
    assert_eq!(entries[0].value, None);
    assert_eq!(entries[2].name, b"agent");
    assert_eq!(entries[2].value, Some(b"fgit/1".to_vec()));
}

/// A well-formed v2 advertisement parses.
#[test]
fn a_well_formed_v2_advertisement_parses() {
    let parsed = Capabilities::parse_v2_advertisement(
        &[version_line(), line(b"ofs-delta"), Packet::Flush],
        &limits(),
    )
    .expect("a canonical v2 advertisement must parse");
    assert_eq!(parsed.entries().len(), 1);
    assert!(parsed.contains(b"ofs-delta"));
}

// ---------------------------------------------------------------------------
// CapabilityTooLarge
// ---------------------------------------------------------------------------

#[test]
fn a_capability_token_past_the_bound_is_refused() {
    let token = vec![b'a'; SMALL_CAPABILITY_BYTES + 1];
    let error = Capability::parse(&token, &capped(256, SMALL_CAPABILITY_BYTES))
        .expect_err("one byte past the capability bound must refuse");
    assert_eq!(
        error,
        WireError::CapabilityTooLarge {
            limit: SMALL_CAPABILITY_BYTES
        }
    );
}

/// **The permitted twin at the exact boundary.** The guard reads `>`, so a
/// token of exactly the bound is legal — and that is the case a refusal-only
/// corpus cannot see.
#[test]
fn a_capability_token_at_exactly_the_bound_is_admitted() {
    let token = vec![b'a'; SMALL_CAPABILITY_BYTES];
    let parsed = Capability::parse(&token, &capped(256, SMALL_CAPABILITY_BYTES))
        .expect("a token of exactly the bound must be admitted");
    assert_eq!(parsed.name, token);
}

// ---------------------------------------------------------------------------
// TooManyCapabilities — and its equality bound
// ---------------------------------------------------------------------------

#[test]
fn more_capabilities_than_the_bound_are_refused() {
    let error = Capabilities::parse_v1(b"a b c", &capped(2, 4096))
        .expect_err("a third capability must refuse at a bound of two");
    assert_eq!(error, WireError::TooManyCapabilities { limit: 2 });
}

/// The presence case for the equality bound being sound.
///
/// `insert` tests `entries.len() == max_capabilities`, which is only safe if the
/// length visits every value. It is a `Vec` pushed exactly once per successful
/// insert with the check before every push, so this drives every count from 1 to
/// the bound and shows each admitted, then shows `bound + 1` refusing.
#[test]
fn every_count_up_to_the_capability_bound_is_admitted() {
    const BOUND: usize = 4;
    let names = [&b"a"[..], b"b", b"c", b"d", b"e"];
    for count in 1..=BOUND {
        let tokens = names[..count].join(&b' ');
        let parsed =
            Capabilities::parse_v1(&tokens, &capped(BOUND, 4096)).unwrap_or_else(|error| {
                panic!("{count} capabilities at a bound of {BOUND} must be admitted, got {error:?}")
            });
        assert_eq!(parsed.entries().len(), count);
    }

    let tokens = names.join(&b' ');
    let error = Capabilities::parse_v1(&tokens, &capped(BOUND, 4096))
        .expect_err("one past the bound must refuse");
    assert_eq!(error, WireError::TooManyCapabilities { limit: BOUND });
}

// ---------------------------------------------------------------------------
// DuplicateCapability — collides on the NAME only
// ---------------------------------------------------------------------------

/// Two capabilities sharing a name but carrying **different values** collide.
///
/// The check compares `entry.name`, so this is the shape that tests the rule. A
/// probe repeating one identical token would pass against an implementation
/// comparing whole capabilities, and would prove nothing about name-collision.
#[test]
fn two_capabilities_with_the_same_name_but_different_values_collide() {
    let error = Capabilities::parse_v1(b"agent=one agent=two", &limits())
        .expect_err("one capability name cannot be advertised twice");
    assert_eq!(
        error,
        WireError::DuplicateCapability {
            name: b"agent".to_vec()
        },
        "the refusal names the colliding capability"
    );
}

/// The permitted twin: distinct names are admitted, so the collision above is
/// attributable to the names matching rather than to a second capability being
/// rejected at all.
#[test]
fn two_capabilities_with_different_names_are_admitted() {
    let parsed = Capabilities::parse_v1(b"agent=one client=two", &limits())
        .expect("two distinct capability names must be admissible");
    assert_eq!(parsed.entries().len(), 2);
}

// ---------------------------------------------------------------------------
// InvalidVersionAdvertisement — three sites
// ---------------------------------------------------------------------------

/// Site 1: the advertisement does not begin with a data packet — probed both
/// with no packets at all and with a control packet first.
#[test]
fn an_advertisement_not_beginning_with_a_data_packet_is_refused() {
    for packets in [&[][..], &[Packet::Flush][..]] {
        let error = Capabilities::parse_v2_advertisement(packets, &limits())
            .expect_err("an advertisement must open with its version line");
        assert_eq!(error, WireError::InvalidVersionAdvertisement);
    }
}

/// Site 2: the first data packet is not exactly `version 2\n`.
#[test]
fn an_advertisement_with_the_wrong_version_line_is_refused() {
    let error = Capabilities::parse_v2_advertisement(
        &[Packet::Data(b"version 1\n".to_vec()), Packet::Flush],
        &limits(),
    )
    .expect_err("only version 2 is advertised on this lane");
    assert_eq!(error, WireError::InvalidVersionAdvertisement);
}

/// Site 3: the advertisement never flushes.
///
/// Passes through: the version line is correct and the capability line parses,
/// so this reaches the terminal flush check rather than an earlier one.
#[test]
fn an_advertisement_that_never_flushes_is_refused() {
    let error =
        Capabilities::parse_v2_advertisement(&[version_line(), line(b"ofs-delta")], &limits())
            .expect_err("an unterminated advertisement is incomplete");
    assert_eq!(error, WireError::InvalidVersionAdvertisement);
}

/// An advertisement line that does not end in LF is refused.
///
/// Beyond the bead's scope, closed here because it sits on this same path and
/// cost one probe.
#[test]
fn an_advertisement_line_without_a_line_feed_is_refused() {
    let error = Capabilities::parse_v2_advertisement(
        &[
            version_line(),
            Packet::Data(b"ofs-delta".to_vec()),
            Packet::Flush,
        ],
        &limits(),
    )
    .expect_err("every advertisement line carries its LF");
    assert_eq!(error, WireError::MissingLineFeed);
}

// ---------------------------------------------------------------------------
// InvalidToken — two sites, told apart by the payload
// ---------------------------------------------------------------------------

/// Site 1: a control byte in the capability **name**.
#[test]
fn a_control_byte_in_a_capability_name_is_refused() {
    let error = Capability::parse(b"of\x01s-delta", &limits())
        .expect_err("a control byte is not a capability token character");
    assert_eq!(
        error,
        WireError::InvalidToken {
            field: "capability",
            offset: 2,
            byte: 1,
        },
        "the payload identifies the name site and the exact offset"
    );
}

/// Site 2: a control byte in the capability **value**.
///
/// Same variant, different site — distinguishable only by `field`, and the
/// offset is relative to the value rather than the whole token.
#[test]
fn a_control_byte_in_a_capability_value_is_refused() {
    let error = Capability::parse(b"agent=fg\x01it", &limits())
        .expect_err("a control byte is not permitted in a capability value");
    assert_eq!(
        error,
        WireError::InvalidToken {
            field: "capability value",
            offset: 2,
            byte: 1,
        },
        "the payload identifies the value site, and the offset is within the value"
    );
}

// ---------------------------------------------------------------------------
// EmptyCapability — the two sites the existing corpus does not reach
// ---------------------------------------------------------------------------

/// An entirely empty token.
#[test]
fn an_empty_capability_token_is_refused() {
    let error = Capability::parse(b"", &limits()).expect_err("an empty token names nothing");
    assert_eq!(error, WireError::EmptyCapability);
}

/// A token that is all value and no name.
///
/// A different site from the one above: the token is non-empty, so it passes
/// the first check and fails after the `=` split.
#[test]
fn a_capability_with_an_empty_name_is_refused() {
    let error =
        Capability::parse(b"=value", &limits()).expect_err("a value without a name names nothing");
    assert_eq!(error, WireError::EmptyCapability);
}

// ---------------------------------------------------------------------------
// One helper, different behaviour per caller
// ---------------------------------------------------------------------------

/// The v1 and v2 surfaces **disagree** on a space inside a capability value.
///
/// Both delegate to one helper, differing only in `allow_value_spaces`. v1
/// refuses the space as an invalid token; v2 admits it and keeps it in the
/// value. Asserting the disagreement in one test is what would catch either
/// caller's flag being flipped — a probe of either surface alone would still
/// pass with both flags set the same way.
#[test]
fn the_two_surfaces_disagree_on_a_space_inside_a_value() {
    const TOKEN: &[u8] = b"agent=fgit 1";

    let v1 = Capability::parse(TOKEN, &limits())
        .expect_err("a v1 capability value may not contain a space");
    assert_eq!(
        v1,
        WireError::InvalidToken {
            field: "capability value",
            offset: 4,
            byte: b' ',
        }
    );

    let v2 = Capability::parse_v2(TOKEN, &limits())
        .expect("a v2 capability value may contain printable spaces");
    assert_eq!(v2.name, b"agent");
    assert_eq!(v2.value, Some(b"fgit 1".to_vec()));
}
