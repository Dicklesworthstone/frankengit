#![forbid(unsafe_code)]
//! Signed-push admission: configuration coherence and the certificate gate
//! (`frankengit-ax3h`).
//!
//! Signed push is refused or admitted in **two** places, and neither was named
//! by a test.
//!
//! **At configuration time**, `ReceiveContext::new` runs
//! `validate_server_capabilities`, which enforces that a server cannot
//! advertise something it will not honour:
//!
//! ```text
//! advertises push-cert while refusing signed push -> SignedPushUnsupported
//! advertises push-cert=X while expecting Y        -> InvalidLimit{advertised signed push nonce}
//! ```
//!
//! **At protocol time**, `start_certificate` gates the opening line:
//!
//! ```text
//! profile is Refuse                       -> SignedPushUnsupported
//! client never negotiated push-cert        -> SignedPushCapabilityMissing
//! profile parses but holds an empty nonce  -> InvalidLimit{signed push expected nonce}
//! otherwise                                -> the certificate builder opens
//! ```
//!
//! # Two things this file exists to pin
//!
//! **`SignedPushUnsupported` fires at two different sites for two different
//! reasons** — a misconfigured server at construction, and a client offering a
//! certificate to a server that refuses them. Both are tested, because a single
//! probe naming the variant cannot tell you which site produced it.
//!
//! **The two `InvalidLimit` field labels are distinct** — *"advertised signed
//! push nonce"* is a server that would advertise a nonce it does not expect,
//! and *"signed push expected nonce"* is a server that expects nothing at all.
//! Every probe asserts the label, not just the variant, so a guard reporting
//! the wrong field is caught.
//!
//! The strongest test here is
//! [`the_same_opening_refused_by_a_refusing_server_is_admitted_by_a_parsing_one`]:
//! identical client bytes, refused by one server and admitted by another. That
//! is what proves `Refuse` is a **policy** decision rather than a parse
//! failure, which a refusal test alone cannot show.
//!
//! # The ordering is what keeps these probes honest
//!
//! Each guard runs only if every earlier one passed, so a probe for a later
//! guard must satisfy the earlier ones or it trips the wrong wall while
//! claiming to test its own. Each test states what it is passing through.
//!
//! # One arm is deliberately not tested
//!
//! `start_certificate` opens with a `strip_prefix(b"push-cert\0")` check
//! refusing `MalformedCertificate`. Its only caller, `push_command_line`, guards
//! the call with `line.starts_with(b"push-cert\0")`, so by the time
//! `start_certificate` runs the prefix is guaranteed and that arm **cannot fail
//! through this path**. Recorded as unreached rather than given a manufactured
//! fixture. `MalformedCertificate` has other sites in the certificate parser
//! proper; those are a separate question.
//!
//! # Not extending the neighbouring corpus, on purpose
//!
//! `scripts/e2e/suites/wire/receivepack_adversarial.sh` asserts that file's
//! passing-test count is **exactly** `WIRE_PROBES=9`, so adding to it would fail
//! that lane — which exists precisely so a shrinking corpus is caught.
//!
//! Every probe drives the public API; nothing here modifies
//! `crates/fgit-wire/src/**`.

use fgit_wire::receive::{
    ReceiveContext, ReceiveError, ReceiveLimits, ReceivePack, SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

/// The nonce a correctly configured fixture server both advertises and expects.
const NONCE: &str = "nonce-fixture-0001";

fn capabilities(source: &str) -> Capabilities {
    if source.is_empty() {
        return Capabilities::default();
    }
    Capabilities::parse_v1(source.as_bytes(), &WireLimits::default())
        .expect("fixture capabilities parse")
}

fn parse_v1(nonce: &str) -> SignedPushProfile {
    SignedPushProfile::ParseV1 {
        expected_nonce: nonce.as_bytes().to_vec(),
    }
}

/// Build a context, returning the refusal rather than panicking, so the
/// construction-time guards can be probed.
fn build_context(server: &str, profile: SignedPushProfile) -> Result<ReceiveContext, ReceiveError> {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        capabilities(server),
        ReceiveLimits::default(),
        profile,
    )
}

/// A first command line opening a certificate, carrying the client's negotiated
/// capability list.
fn certificate_opening(client: &str) -> Packet {
    let mut line = b"push-cert\0".to_vec();
    line.extend_from_slice(client.as_bytes());
    Packet::Data(line)
}

/// Feed one certificate-opening line to a fresh machine built from a context
/// that must itself be valid.
fn open_certificate(
    server: &str,
    profile: SignedPushProfile,
    client: &str,
) -> Result<(), ReceiveError> {
    let context = build_context(server, profile).expect("this fixture's context must be coherent");
    let mut machine = ReceivePack::new(context).expect("fixture machine");
    machine.push_packet(certificate_opening(client)).map(|_| ())
}

// ---------------------------------------------------------------------------
// Configuration coherence — a server may not advertise what it will not honour
// ---------------------------------------------------------------------------

/// A server that advertises `push-cert` while refusing signed push is rejected
/// at construction.
#[test]
fn advertising_push_cert_while_refusing_signed_push_is_rejected() {
    let Err(refusal) = build_context(
        &format!("report-status push-cert={NONCE}"),
        SignedPushProfile::Refuse,
    ) else {
        panic!("a server cannot advertise a capability its profile refuses");
    };
    assert!(
        matches!(refusal, ReceiveError::SignedPushUnsupported),
        "advertising push-cert under a refusing profile must be rejected as unsupported, \
         got {refusal:?}"
    );
}

/// A server that advertises one nonce while expecting another is rejected at
/// construction, naming the advertised side.
///
/// This is the coherence check that stops a server publishing a nonce it will
/// not accept — every client following the advertisement would be refused at
/// verification time for a fault that is entirely the server's.
#[test]
fn advertising_a_nonce_the_profile_does_not_expect_is_rejected() {
    let Err(refusal) = build_context(
        &format!("report-status push-cert={NONCE}"),
        parse_v1("a-different-nonce"),
    ) else {
        panic!("an advertised nonce must match the one the profile expects");
    };
    assert!(
        matches!(
            refusal,
            ReceiveError::InvalidLimit {
                field: "advertised signed push nonce"
            }
        ),
        "a mismatched advertisement must name the ADVERTISED nonce field, distinguishing it from \
         the expected-nonce failure at certificate time, got {refusal:?}"
    );
}

/// The permitted twin for both construction guards: advertisement and
/// expectation agree.
#[test]
fn a_server_whose_advertisement_matches_its_expectation_is_accepted() {
    build_context(&format!("report-status push-cert={NONCE}"), parse_v1(NONCE))
        .expect("a coherent signed-push configuration must be constructible");
}

/// The other coherent configuration: refusing signed push and advertising none.
///
/// Without this, the two rejections above are consistent with a constructor
/// that refuses every signed-push configuration.
#[test]
fn a_server_that_refuses_signed_push_and_advertises_none_is_accepted() {
    build_context("report-status delete-refs", SignedPushProfile::Refuse)
        .expect("refusing signed push without advertising it must be constructible");
}

// ---------------------------------------------------------------------------
// The certificate gate — what happens when a client offers one
// ---------------------------------------------------------------------------

/// A client offering a certificate to a server that refuses signed push is
/// refused as unsupported.
///
/// Note this is the **same variant** as the construction guard above, produced
/// at an entirely different site: there a misconfigured server, here a
/// well-configured one meeting a client that ignored its advertisement.
#[test]
fn a_certificate_offered_to_a_refusing_server_is_unsupported() {
    let refusal = open_certificate(
        "report-status delete-refs",
        SignedPushProfile::Refuse,
        "push-cert",
    )
    .expect_err("a server that refuses signed push must refuse a certificate");
    assert!(
        matches!(refusal, ReceiveError::SignedPushUnsupported),
        "a certificate offered to a refusing server must be unsupported, got {refusal:?}"
    );
}

/// A client that never negotiated `push-cert` cannot open a certificate.
///
/// Passes through the profile guard by using a parsing server, so this is
/// attributable to the capability check rather than to the profile.
#[test]
fn a_certificate_without_the_negotiated_capability_is_refused() {
    let refusal = open_certificate(
        &format!("report-status push-cert={NONCE}"),
        parse_v1(NONCE),
        "report-status",
    )
    .expect_err("a client that never negotiated push-cert must not open a certificate");
    assert!(
        matches!(refusal, ReceiveError::SignedPushCapabilityMissing),
        "an unnegotiated capability must refuse as missing, got {refusal:?}"
    );
}

/// A server that parses certificates but expects an empty nonce refuses with a
/// typed limit naming the *expected* side.
///
/// Reaching this guard needs a genuinely degenerate but legal configuration:
/// the server must ADVERTISE an empty nonce too, because the coherence check at
/// construction requires the advertised value to equal the expected one, and
/// the client must then negotiate the capability. Established by measurement,
/// not assumed — an earlier draft advertised nothing and refused with
/// `CapabilityNotAdvertised` two guards earlier, proving nothing about this one.
///
/// Passes through the profile and capability guards. The label distinguishes
/// this from the advertisement mismatch above — same variant, different field,
/// different fault: there the server would publish a nonce it does not expect,
/// here it expects nothing at all.
#[test]
fn a_parsing_server_expecting_an_empty_nonce_is_refused_as_an_invalid_limit() {
    let refusal = open_certificate("report-status push-cert=", parse_v1(""), "push-cert")
        .expect_err("a server expecting no nonce cannot verify a certificate");
    assert!(
        matches!(
            refusal,
            ReceiveError::InvalidLimit {
                field: "signed push expected nonce"
            }
        ),
        "an empty expected nonce must name the EXPECTED nonce field, got {refusal:?}"
    );
}

/// The permitted terminus: a negotiated certificate under a coherent parsing
/// server opens the builder.
///
/// Without it, every refusal above is consistent with a gate that refuses all
/// certificates unconditionally.
#[test]
fn a_well_formed_certificate_opening_is_admitted() {
    open_certificate(
        &format!("report-status push-cert={NONCE}"),
        parse_v1(NONCE),
        "push-cert",
    )
    .expect("a negotiated certificate under a coherent parsing server must open");
}

/// **The pair that carries this bead.** Identical client bytes, refused by one
/// server and admitted by another.
///
/// Only the server's signed-push policy differs. That is what distinguishes a
/// **policy** refusal from a parse failure, and no refusal test alone can show
/// it.
#[test]
fn the_same_opening_refused_by_a_refusing_server_is_admitted_by_a_parsing_one() {
    let opening = "push-cert";

    let refused = open_certificate(
        "report-status delete-refs",
        SignedPushProfile::Refuse,
        opening,
    )
    .expect_err("the refusing server must refuse");
    assert!(
        matches!(refused, ReceiveError::SignedPushUnsupported),
        "expected a policy refusal, got {refused:?}"
    );

    open_certificate(
        &format!("report-status push-cert={NONCE}"),
        parse_v1(NONCE),
        opening,
    )
    .expect(
        "the identical client opening must be admitted by a parsing server — if this refuses, the \
         refusal above is a parse failure rather than the policy decision it is documented as",
    );
}
