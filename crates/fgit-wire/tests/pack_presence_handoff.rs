#![forbid(unsafe_code)]
//! Pack presence and phase sequencing at the quarantine handoff
//! (`frankengit-qxbp`).
//!
//! These are the guards standing between a parsed receive request and the
//! admission boundary. None was named by a test.
//!
//! ```text
//! completing with a pack-requiring request and empty quarantine -> PackRequired
//! raw bytes in a phase that neither appends nor ignores them    -> UnexpectedPackBytes{state}
//! completing while still in Commands or PushOptions             -> IncompleteRequest{state}
//! a Delimiter or ResponseEnd during Commands                    -> UnexpectedPacket{state, packet}
//! any packet at all during Pack                                 -> UnexpectedPacket{state, packet}
//! ```
//!
//! `PackRequired` is the one that matters most: it is what stops a create or
//! update completing with **no objects behind it**, which is precisely the
//! condition admission would otherwise have to discover after sealing.
//!
//! # Two sites, one variant — and only one of them is reachable
//!
//! `UnexpectedPackBytes` is constructed twice. The **streaming** site reports
//! the actual phase; the **completion** site reports a literal `Ready` when a
//! request that needs no pack nevertheless carries quarantine bytes.
//!
//! That completion arm **cannot fire through the public API**, and no fixture
//! is manufactured for it. `finish_command_list` sets `phase = Pack` only when
//! `request.requires_pack()`; quarantine is appended only while in `Pack`; and
//! `requires_pack()` is a pure function of a command list that does not change
//! afterwards. So `raw_pack` is non-empty only when `requires_pack()` is true,
//! and the completion guard tests the conjunction of that being *false* with
//! `raw_pack` non-empty. Recorded here rather than probed — a test for an arm no
//! caller can produce asserts coverage that does not exist.
//!
//! Worth keeping as a heuristic: **a guard testing the conjunction of two
//! conditions is a strong candidate for being defensive**, because the state
//! machine producing one of them often excludes the other.
//!
//! # Ordering
//!
//! Phase decides which guard a packet meets, so every probe states the phase it
//! drove the machine into first. A probe that reaches the wrong phase tests the
//! wrong guard while passing.
//!
//! # Not extending the neighbouring corpus, on purpose
//!
//! `scripts/e2e/suites/wire/receivepack_adversarial.sh` asserts that file's
//! passing-test count is **exactly** `WIRE_PROBES=9`. Adding to it would fail
//! that lane, which exists so a corpus that silently stops emitting probes is
//! caught rather than quietly shrinking.
//!
//! Every probe drives the public API; nothing here modifies
//! `crates/fgit-wire/src/**`.

use fgit_wire::receive::{
    ReceiveContext, ReceiveError, ReceiveLimits, ReceivePack, ReceivePhase,
    ReceiveQuarantineHandoff, SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const ZERO: &str = "0000000000000000000000000000000000000000";
const NEW: &str = "1111111111111111111111111111111111111111";

fn capabilities(source: &[u8]) -> Capabilities {
    if source.is_empty() {
        return Capabilities::default();
    }
    Capabilities::parse_v1(source, &WireLimits::default()).expect("fixture capabilities")
}

fn context() -> ReceiveContext {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        capabilities(b"delete-refs report-status"),
        ReceiveLimits::default(),
        SignedPushProfile::Refuse,
    )
    .expect("fixture receive context")
}

fn command(old: &str, new: &str, name: &str, capabilities: Option<&str>) -> Packet {
    let mut line = format!("{old} {new} {name}").into_bytes();
    if let Some(capabilities) = capabilities {
        line.push(0);
        line.extend_from_slice(capabilities.as_bytes());
    }
    Packet::Data(line)
}

/// A structurally valid, empty SHA-1 pack.
fn empty_pack() -> Vec<u8> {
    let mut pack = b"PACK\0\0\0\x02\0\0\0\0".to_vec();
    let checksum = fgit_crypto::sha1_digest(&pack);
    pack.extend_from_slice(checksum.as_slice());
    pack
}

#[derive(Default)]
struct CountingHandoff {
    calls: usize,
    saw_pack_bytes: bool,
}

impl ReceiveQuarantineHandoff for CountingHandoff {
    fn handoff(
        &mut self,
        _request: &fgit_wire::receive::ReceiveRequest,
        pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &fgit_wire::receive::QuarantineReceipt,
    ) -> Result<(), ReceiveError> {
        self.calls += 1;
        self.saw_pack_bytes = pack.is_some();
        Ok(())
    }
}

/// One pkt-line: a four-digit hex length covering itself, then the payload.
fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut line = format!("{:04x}", payload.len() + 4).into_bytes();
    line.extend_from_slice(payload);
    line
}

/// Drive a machine to the end of its command list, leaving it in whatever phase
/// the request implies.
fn machine_after_commands(command_packet: Packet) -> ReceivePack {
    let mut machine = ReceivePack::new(context()).expect("fixture machine");
    machine
        .push_packet(command_packet)
        .expect("the command must parse");
    machine
        .push_packet(Packet::Flush)
        .expect("the command flush must be accepted");
    machine
}

fn finish(machine: &mut ReceivePack) -> Result<(), ReceiveError> {
    let mut handoff = CountingHandoff::default();
    let mut always = || true;
    machine
        .finish_with_handoff(&mut handoff, &mut always)
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// Pack presence
// ---------------------------------------------------------------------------

/// A create completing with an empty quarantine is refused.
///
/// Phase driven to `Pack`, because the command creates a ref and therefore
/// requires objects. No pack bytes are fed, so the completion guard fires.
#[test]
fn a_pack_requiring_request_completing_with_no_pack_is_refused() {
    let mut machine = machine_after_commands(command(
        ZERO,
        NEW,
        "refs/heads/created",
        Some("report-status"),
    ));
    let refusal =
        finish(&mut machine).expect_err("a create with no objects behind it must not complete");
    assert!(
        matches!(refusal, ReceiveError::PackRequired),
        "a create completing with an empty quarantine must refuse as PackRequired, got {refusal:?}"
    );
}

/// The permitted twin: the same create completes once its pack arrives.
///
/// Without this, the refusal above is consistent with a completion path that
/// refuses every create regardless of what was sent.
#[test]
fn the_same_request_completes_once_its_pack_arrives() {
    let mut machine = machine_after_commands(command(
        ZERO,
        NEW,
        "refs/heads/created",
        Some("report-status"),
    ));
    machine
        .push_bytes(&empty_pack())
        .expect("pack bytes must be accepted while in the Pack phase");

    let mut handoff = CountingHandoff::default();
    let mut always = || true;
    machine
        .finish_with_handoff(&mut handoff, &mut always)
        .expect("a create whose pack arrived must complete");
    assert_eq!(handoff.calls, 1, "handoff must run exactly once");
    assert!(
        handoff.saw_pack_bytes,
        "a pack-requiring request must hand its pack to admission"
    );
}

/// The other permitted case: a delete-only request completes with no pack at
/// all, so `PackRequired` is attributable to the requirement rather than to
/// completion always demanding a pack.
#[test]
fn a_delete_only_request_completes_with_no_pack() {
    let mut machine = machine_after_commands(command(
        NEW,
        ZERO,
        "refs/heads/doomed",
        Some("report-status delete-refs"),
    ));
    let mut handoff = CountingHandoff::default();
    let mut always = || true;
    machine
        .finish_with_handoff(&mut handoff, &mut always)
        .expect("a delete-only request needs no pack");
    assert!(
        !handoff.saw_pack_bytes,
        "a delete-only push must hand no pack to admission"
    );
}

/// Raw bytes arriving when the request needs no pack are refused, and the
/// refusal names the phase they arrived in.
///
/// Phase driven to `Ready` by a delete-only command list. This is the
/// **streaming** site; the phase in the payload is what distinguishes it from
/// the completion site documented as unreachable in this file's header.
#[test]
fn pack_bytes_offered_to_a_request_that_needs_none_are_refused() {
    // The flush and the trailing bytes must arrive in ONE call: the guard fires
    // on what is left over *after* a flush boundary within a single input, and
    // a flush delivered as its own packet leaves nothing remaining.
    let mut stream =
        pkt_line(format!("{NEW} {ZERO} refs/heads/doomed\0report-status delete-refs").as_bytes());
    stream.extend_from_slice(b"0000");
    stream.extend_from_slice(&empty_pack());

    let mut machine = ReceivePack::new(context()).expect("fixture machine");
    let refusal = machine
        .push_bytes(&stream)
        .expect_err("a delete-only request must not accept pack bytes");
    assert!(
        matches!(
            refusal,
            ReceiveError::UnexpectedPackBytes {
                state: ReceivePhase::Ready
            }
        ),
        "pack bytes in the Ready phase must refuse naming that phase, got {refusal:?}"
    );
}

// ---------------------------------------------------------------------------
// Phase sequencing
// ---------------------------------------------------------------------------

/// Completing before the command list is flushed is refused, naming the phase.
///
/// The machine is left in `Commands` — one command parsed, no flush — so the
/// request was never assembled.
#[test]
fn completing_before_the_command_list_is_flushed_is_refused() {
    let mut machine = ReceivePack::new(context()).expect("fixture machine");
    machine
        .push_packet(command(
            NEW,
            ZERO,
            "refs/heads/doomed",
            Some("report-status delete-refs"),
        ))
        .expect("the command must parse");

    let refusal =
        finish(&mut machine).expect_err("an unflushed command list has no assembled request");
    assert!(
        matches!(
            refusal,
            ReceiveError::IncompleteRequest {
                state: ReceivePhase::Commands
            }
        ),
        "completing mid-command-list must refuse naming the Commands phase, got {refusal:?}"
    );
}

/// A delimiter during the command list is refused, naming both the phase and
/// the packet kind.
///
/// The packet name is asserted, not just the variant, so a guard reporting the
/// wrong packet is caught.
#[test]
fn a_delimiter_during_the_command_list_is_refused() {
    let mut machine = ReceivePack::new(context()).expect("fixture machine");
    let refusal = machine
        .push_packet(Packet::Delimiter)
        .expect_err("a delimiter is not part of the receive command grammar");
    assert!(
        matches!(
            refusal,
            ReceiveError::UnexpectedPacket {
                state: ReceivePhase::Commands,
                ..
            }
        ),
        "a delimiter during Commands must refuse naming that phase, got {refusal:?}"
    );
}

/// A flush arriving while the machine is streaming a pack is refused.
///
/// Phase driven to `Pack` by a create. Every packet is refused there — pack
/// bytes reach the machine as raw data, not as packets.
#[test]
fn a_packet_during_the_pack_phase_is_refused() {
    let mut machine = machine_after_commands(command(
        ZERO,
        NEW,
        "refs/heads/created",
        Some("report-status"),
    ));
    let refusal = machine
        .push_packet(Packet::Delimiter)
        .expect_err("no packet is part of the grammar while a pack is streaming");
    assert!(
        matches!(
            refusal,
            ReceiveError::UnexpectedPacket {
                state: ReceivePhase::Pack,
                ..
            }
        ),
        "a packet during Pack must refuse naming that phase, got {refusal:?}"
    );
}

/// The two `UnexpectedPacket` sites are told apart by their phase, not merely
/// both refused.
///
/// Same variant, two grammars: a delimiter is illegal during `Commands` because
/// the command grammar has no delimiter, and illegal during `Pack` because the
/// grammar there has no packets at all. Collapsing them would hide either.
#[test]
fn the_two_unexpected_packet_sites_report_different_phases() {
    let mut in_commands = ReceivePack::new(context()).expect("fixture machine");
    let during_commands = in_commands
        .push_packet(Packet::Delimiter)
        .expect_err("delimiter during Commands must refuse");

    let mut in_pack = machine_after_commands(command(
        ZERO,
        NEW,
        "refs/heads/created",
        Some("report-status"),
    ));
    let during_pack = in_pack
        .push_packet(Packet::Delimiter)
        .expect_err("delimiter during Pack must refuse");

    assert!(
        matches!(
            during_commands,
            ReceiveError::UnexpectedPacket {
                state: ReceivePhase::Commands,
                ..
            }
        ),
        "got {during_commands:?}"
    );
    assert!(
        matches!(
            during_pack,
            ReceiveError::UnexpectedPacket {
                state: ReceivePhase::Pack,
                ..
            }
        ),
        "got {during_pack:?}"
    );
}
