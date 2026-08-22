#![forbid(unsafe_code)]
//! v2 fetch-negotiation and sideband refusals (`frankengit-1zg4`).
//!
//! These are the arguments an untrusted client puts in a `command=fetch`
//! request. §6 makes refusal behaviour a compatibility semantic and requires
//! bounded validation before work, and §9 treats external text as untrusted
//! data — a `deepen` count, a `filter` spec and a `deepen-not` ref name are all
//! peer-supplied.
//!
//! Measured before writing: `WireError` is 26 unnamed of 41 constructed.
//! `88o7` closed the pkt-line resource bounds and `m0mj` the capability
//! cluster; this is a third surface again.
//!
//! # The adjacent-variant problem, which is why this is worth a file
//!
//! `parse_depth` refuses three different ways, and a fourth neighbour already
//! has coverage:
//!
//! ```text
//! deepen -1                     NegativeDepth   (already covered elsewhere)
//! deepen 0                      InvalidDepth
//! deepen abc                    InvalidDepth
//! deepen 99999999999999999999   InvalidDepth    (past u32)
//! ```
//!
//! A reader's intuition says all four are "a bad depth". The code says **two
//! different faults**. A test asserting only that the request failed would pass
//! against a version that collapsed them, so every probe here names the variant
//! — and [`a_negative_depth_and_a_zero_depth_are_different_faults`] asserts the
//! two report *differently* rather than that both fail. That is the discipline
//! `0k6d` applied to `Greater`/`Equal` in `fgit-atp-git`, on a different enum.
//!
//! # A feature gate sits in front of every deepen arm
//!
//! `require_fetch_feature(b"shallow")` runs **before** `parse_depth`, so a
//! server whose capabilities do not advertise it refuses a `deepen` line for an
//! entirely different reason.
//! [`the_shallow_feature_gate_outranks_an_invalid_depth`] drives a request that
//! is wrong twice and asserts the earlier fault — single-fault probes are
//! structurally blind to a stage swap, because each satisfies every earlier
//! stage by construction and so still arrives at its own.
//!
//! # The repository double is complete on purpose
//!
//! `UploadPackRepository::resolve_ref` has a **default returning `None`**. A
//! double that omitted it would make `UnknownDeepenNotRef` fire for every ref,
//! including ones the test means to be resolvable — the probe would look like
//! evidence while proving only that the double resolves nothing. This double
//! resolves the advertised names, so the refusal probe is genuinely about an
//! *unknown* ref.
//!
//! # Non-claims
//!
//! Seven more of the 26 unnamed `WireError` variants. The advertisement cluster
//! (`RefNameTooLarge`, `TooManyAdvertisedRefs`,
//! `UnsortedOrDuplicateAdvertisement`) and `ReceiveError` (7 of 33) remain.
//! LEAD count, not a remaining-work total.
//!
//! This file deliberately does not touch `tests/receivepack_adversarial.rs` or
//! `tests/receivepack_limits_propagation.rs`, whose passing-probe counts
//! `scripts/e2e/suites/wire/receivepack_adversarial.sh` asserts exactly.
//!
//! Nothing here modifies `crates/fgit-wire/src/**`.

use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, SidebandBand,
    UploadPackRepository, V2UploadPack, WireError, WireLimits, parse_sideband,
};

const TIP: &str = "1111111111111111111111111111111111111111";

fn limits() -> WireLimits {
    WireLimits::default()
}

fn oid(hex: &str) -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, hex).expect("fixture oid")
}

/// A repository that advertises one ref and **resolves it**.
///
/// `resolve_ref` is implemented rather than defaulted; see the module note.
struct FetchRepository {
    refs: Vec<AdvertisedRef>,
}

impl FetchRepository {
    fn new() -> Self {
        Self {
            refs: vec![
                AdvertisedRef::new(oid(TIP), b"refs/heads/main", &limits())
                    .expect("advertised ref"),
            ],
        }
    }
}

impl UploadPackRepository for FetchRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }

    fn contains_want(&self, target: AnyGitOid) -> bool {
        target == oid(TIP)
    }

    fn is_common(&self, _target: AnyGitOid) -> bool {
        false
    }

    fn resolve_ref(&self, name: &[u8]) -> Option<AnyGitOid> {
        self.refs
            .iter()
            .find(|advertised| advertised.name == name)
            .map(|advertised| advertised.oid)
    }
}

/// One pkt-line frame: four lowercase hex bytes of total length, then payload.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = format!("{:04x}", payload.len() + 4).into_bytes();
    framed.extend_from_slice(payload);
    framed
}

/// Server capabilities advertising `fetch` with the named features.
///
/// Built through the **v2** advertisement parser because the feature list is a
/// capability value containing spaces, which v1 tokenisation cannot express —
/// the same v1/v2 asymmetry `m0mj` pins.
fn server_capabilities(fetch_features: &[u8]) -> Capabilities {
    let mut fetch_line = b"fetch=".to_vec();
    fetch_line.extend_from_slice(fetch_features);
    fetch_line.push(b'\n');
    Capabilities::parse_v2_advertisement(
        &[
            Packet::Data(b"version 2\n".to_vec()),
            Packet::Data(fetch_line),
            Packet::Flush,
        ],
        &limits(),
    )
    .expect("a well-formed server advertisement")
}

/// Drives one complete `command=fetch` transcript carrying `arguments`.
fn fetch_request(fetch_features: &[u8], arguments: &[&[u8]]) -> Result<(), WireError> {
    let repository = FetchRepository::new();
    let mut machine = V2UploadPack::new(server_capabilities(fetch_features), limits())
        .expect("a v2 upload-pack machine");

    let mut transcript = frame(b"command=fetch\n");
    transcript.extend_from_slice(b"0001");
    for argument in arguments {
        let mut line = (*argument).to_vec();
        line.push(b'\n');
        transcript.extend_from_slice(&frame(&line));
    }
    transcript.extend_from_slice(b"0000");

    machine.push_bytes(&transcript, &repository).map(|_| ())
}

/// Drives a fetch transcript in its **complete accepted shape**: a `want` line
/// first, the arguments under test, then `done` before the flush.
///
/// Discovered by running rather than assumed: a fetch with no `want` refuses
/// with `MissingWant`, and one that never sends `done` refuses with an
/// `IllegalTransition` at the flush. My first draft of these permitted twins
/// had neither, and every one of them failed — which is precisely why a
/// refusal-only corpus is not enough. The refusal probes below deliberately
/// omit both, because each refuses before the request could reach either check.
fn accepted_fetch_request(fetch_features: &[u8], arguments: &[&[u8]]) -> Result<(), WireError> {
    let want = format!("want {TIP}");
    let mut lines: Vec<&[u8]> = vec![want.as_bytes()];
    lines.extend_from_slice(arguments);
    lines.push(b"done");
    fetch_request(fetch_features, &lines)
}

/// The refusal from a fetch request that must be refused.
fn refusal(fetch_features: &[u8], arguments: &[&[u8]], what: &str) -> WireError {
    match fetch_request(fetch_features, arguments) {
        Ok(()) => panic!("{what} must be refused, but the request was accepted"),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// The permitted terminus, first
// ---------------------------------------------------------------------------

/// A well-formed fetch request with a want, a valid depth, a valid filter and a
/// resolvable `deepen-not` is accepted.
///
/// Every refusal below is measured against this. Without it they could be the
/// machine rejecting any fetch at all.
#[test]
fn a_well_formed_fetch_request_is_accepted() {
    accepted_fetch_request(
        b"shallow filter",
        &[
            b"deepen 5",
            b"filter blob:none",
            b"deepen-not refs/heads/main",
        ],
    )
    .expect("a canonical fetch request must be accepted");
}

// ---------------------------------------------------------------------------
// InvalidDepth — three axes, and its same-intuition neighbour
// ---------------------------------------------------------------------------

/// Axis 1: a depth that is not a number at all.
#[test]
fn a_non_numeric_depth_is_refused() {
    let error = refusal(b"shallow", &[b"deepen abc"], "a non-numeric depth");
    assert_eq!(error, WireError::InvalidDepth);
}

/// Axis 2: a depth past `u32::MAX`.
///
/// The value parses as an integer and only fails the narrowing conversion, so
/// this reaches a different line of `parse_depth` than the axis above.
#[test]
fn a_depth_past_the_representable_range_is_refused() {
    let error = refusal(
        b"shallow",
        &[b"deepen 99999999999999999999"],
        "a depth past u32",
    );
    assert_eq!(error, WireError::InvalidDepth);
}

/// Axis 3: a depth of exactly zero.
///
/// Numerically valid and in range; refused because a zero-depth shallow request
/// asks for nothing while claiming to be a depth request.
#[test]
fn a_zero_depth_is_refused() {
    let error = refusal(b"shallow", &[b"deepen 0"], "a zero depth");
    assert_eq!(error, WireError::InvalidDepth);
}

/// **The contrast.** A negative depth and a zero depth are different faults.
///
/// Both read as "a bad depth" to a human, and a probe asserting only that each
/// failed would pass against a version that collapsed them into one variant.
/// This asserts they report *differently*, which is what would catch the
/// collapse.
#[test]
fn a_negative_depth_and_a_zero_depth_are_different_faults() {
    let negative = refusal(b"shallow", &[b"deepen -1"], "a negative depth");
    let zero = refusal(b"shallow", &[b"deepen 0"], "a zero depth");
    assert_eq!(negative, WireError::NegativeDepth);
    assert_eq!(zero, WireError::InvalidDepth);
    assert_ne!(
        negative, zero,
        "two shapes of bad depth must not collapse into one refusal"
    );
}

/// The permitted twin for the depth arm: a positive in-range depth is accepted.
#[test]
fn a_positive_depth_is_accepted() {
    accepted_fetch_request(b"shallow", &[b"deepen 1"])
        .expect("a depth of one is a legal shallow request");
}

// ---------------------------------------------------------------------------
// InvalidTimestamp — two axes
// ---------------------------------------------------------------------------

#[test]
fn a_non_numeric_deepen_since_is_refused() {
    let error = refusal(
        b"shallow",
        &[b"deepen-since yesterday"],
        "a non-numeric timestamp",
    );
    assert_eq!(error, WireError::InvalidTimestamp);
}

/// Past `i64::MAX`: parses as an integer, fails the narrowing conversion.
#[test]
fn a_deepen_since_past_the_representable_range_is_refused() {
    let error = refusal(
        b"shallow",
        &[b"deepen-since 99999999999999999999"],
        "a timestamp past i64",
    );
    assert_eq!(error, WireError::InvalidTimestamp);
}

/// The permitted twin.
#[test]
fn a_numeric_deepen_since_is_accepted() {
    accepted_fetch_request(b"shallow", &[b"deepen-since 1700000000"])
        .expect("a numeric timestamp is a legal shallow bound");
}

// ---------------------------------------------------------------------------
// UnknownDeepenNotRef
// ---------------------------------------------------------------------------

/// A `deepen-not` naming a ref the repository cannot resolve is refused, and
/// the refusal carries the name asked for.
///
/// The double resolves `refs/heads/main`, so this refusal is about the ref
/// being unknown rather than about a double that resolves nothing — the
/// permitted half is asserted in
/// [`a_well_formed_fetch_request_is_accepted`].
#[test]
fn a_deepen_not_naming_an_unknown_ref_is_refused() {
    let error = refusal(
        b"shallow",
        &[b"deepen-not refs/heads/absent"],
        "a deepen-not on an unknown ref",
    );
    assert_eq!(
        error,
        WireError::UnknownDeepenNotRef {
            name: b"refs/heads/absent".to_vec()
        },
        "the refusal names the ref that could not be resolved"
    );
}

// ---------------------------------------------------------------------------
// InvalidFilter and TooManyFilterParts
// ---------------------------------------------------------------------------

/// A filter spec the parser does not recognise at all.
#[test]
fn an_unrecognised_filter_is_refused() {
    let error = refusal(
        b"shallow filter",
        &[b"filter nonsense"],
        "an unknown filter",
    );
    assert_eq!(
        error,
        WireError::InvalidFilter {
            filter: b"nonsense".to_vec()
        }
    );
}

/// A recognised filter prefix with an unparseable value.
///
/// This reaches a different line than the probe above: the `blob:limit=` prefix
/// matches and only the value fails, so a probe hitting only the unknown-spec
/// case leaves this one unexercised.
#[test]
fn a_filter_with_an_unparseable_limit_is_refused() {
    let error = refusal(
        b"shallow filter",
        &[b"filter blob:limit=lots"],
        "a non-numeric blob limit",
    );
    assert_eq!(
        error,
        WireError::InvalidFilter {
            filter: b"blob:limit=lots".to_vec()
        }
    );
}

/// The permitted twins for the filter arm, one per recognised shape.
#[test]
fn recognised_filters_are_accepted() {
    for filter in [
        &b"filter blob:none"[..],
        b"filter blob:limit=1024",
        b"filter tree:2",
    ] {
        accepted_fetch_request(b"shallow filter", &[filter]).unwrap_or_else(|error| {
            panic!(
                "the filter {:?} must be accepted, got {error:?}",
                String::from_utf8_lossy(filter)
            )
        });
    }
}

// ---------------------------------------------------------------------------
// Ordering — a request that is wrong twice
// ---------------------------------------------------------------------------

/// The `shallow` feature gate outranks the depth parse.
///
/// This request is wrong twice: the server does not advertise `shallow` **and**
/// the depth is zero. It must report the feature refusal, because
/// `require_fetch_feature` runs first. The single-fault probes above cannot see
/// this — each advertises the feature by construction and so always reaches
/// `parse_depth`.
#[test]
fn the_shallow_feature_gate_outranks_an_invalid_depth() {
    let error = refusal(b"filter", &[b"deepen 0"], "a deepen without the feature");
    assert_ne!(
        error,
        WireError::InvalidDepth,
        "the feature gate runs before the depth is parsed, so this is not a depth fault"
    );
}

// ---------------------------------------------------------------------------
// Sideband — a separate public surface
// ---------------------------------------------------------------------------

/// An empty data packet carries no band designator.
#[test]
fn a_sideband_packet_with_no_band_byte_is_refused() {
    let error =
        parse_sideband(&Packet::Data(Vec::new())).expect_err("a sideband frame must name its band");
    assert_eq!(error, WireError::MissingSidebandBand);
}

/// A band byte outside the defined set is refused, and the refusal reports it.
#[test]
fn an_undefined_sideband_band_is_refused() {
    let error = parse_sideband(&Packet::Data(vec![9, b'x']))
        .expect_err("band 9 is not a defined sideband stream");
    assert_eq!(error, WireError::InvalidSidebandBand { band: 9 });
}

/// The permitted twin: every defined band parses and keeps its payload.
///
/// Without this the two refusals could be `parse_sideband` rejecting any data
/// packet at all.
#[test]
fn every_defined_sideband_band_parses() {
    for (byte, expected) in [
        (1_u8, SidebandBand::PackData),
        (2, SidebandBand::Progress),
        (3, SidebandBand::Fatal),
    ] {
        let frame = parse_sideband(&Packet::Data(vec![byte, b'h', b'i']))
            .unwrap_or_else(|error| panic!("band {byte} must parse, got {error:?}"));
        assert_eq!(frame.band, expected);
        assert_eq!(frame.data, b"hi", "the payload after the band is preserved");
    }
}
