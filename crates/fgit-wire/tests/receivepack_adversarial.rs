#![forbid(unsafe_code)]
//! FG-019c: receive-pack adversarial and race campaign.
//!
//! Independent adversary over the receive-pack state machine. Nothing here
//! modifies `crates/fgit-wire/src/**`; every probe drives the public surface
//! and reads only what that surface exposes.
//!
//! ## The two properties this file exists to attack
//!
//! **Zero quarantine leakage.** `ReceivePhase::Refused` documents that "the
//! local quarantine was discarded". That is a claim, and a claim about the
//! *absence* of retained bytes is exactly the kind that passes silently when
//! untested. Every refusal probe below asserts `quarantine_len() == 0`
//! afterwards, so a machine that refused correctly but kept the bytes fails
//! here rather than in production.
//!
//! **No stuck intermediate.** The disconnect matrix requires that a push
//! interrupted at *any* phase leaves a state the caller can act on: refused,
//! complete, or still legitimately mid-stream — never a state that is neither
//! finished nor resumable. The matrix walks the phases rather than sampling
//! one, because "we tested cancellation" usually means one convenient point.
//!
//! ## Every forbidden case is paired with its nearest permitted twin
//!
//! `AGENTS.md` §16.3 requires it and it is load-bearing here: a bound that
//! refuses everything is not a bound, it is a broken parser. So each quota
//! probe asserts the value **at** the limit is accepted and the value one past
//! it is refused, and each malformed-input probe sits beside the well-formed
//! input it was derived from.
//!
//! ## Non-claims
//!
//! * These are **in-process** probes of one state machine. They say nothing
//!   about a real network peer, and nothing here is differential evidence
//!   against upstream Git — that is the oracle lane's job, and it is separate.
//! * The seal/outcome-race dimensions of this bead reach the authority layer,
//!   where the pack owner has two open P0 findings at `8fed725`. Anything this
//!   file discovers there is corroboration of theirs, not a second finding.

use fgit_wire::receive::ReceiveContext;
use fgit_wire::receive::{
    ReceiveCancellation, ReceiveError, ReceiveLimits, ReceivePack, ReceivePhase,
    ReceiveQuarantineHandoff, SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const ZERO: &str = "0000000000000000000000000000000000000000";
const NEW: &str = "1111111111111111111111111111111111111111";
const OTHER: &str = "2222222222222222222222222222222222222222";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn capabilities(source: &[u8]) -> Capabilities {
    if source.is_empty() {
        return Capabilities::default();
    }
    Capabilities::parse_v1(source, &WireLimits::default()).expect("fixture capabilities")
}

fn context_with(limits: ReceiveLimits) -> ReceiveContext {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        capabilities(b"delete-refs report-status"),
        limits,
        SignedPushProfile::Refuse,
    )
    .expect("fixture receive context")
}

fn context() -> ReceiveContext {
    context_with(ReceiveLimits::default())
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

/// A cancellation probe that permits exactly `budget` checkpoints, then stops.
///
/// This is the supported disconnect seam — `ReceiveCancellation` — rather than
/// reaching around the state machine to simulate a dropped socket.
struct CancelAfter {
    budget: usize,
    consumed: usize,
}

impl CancelAfter {
    const fn new(budget: usize) -> Self {
        Self {
            budget,
            consumed: 0,
        }
    }
}

impl ReceiveCancellation for CancelAfter {
    fn checkpoint(&mut self) -> bool {
        self.consumed += 1;
        self.consumed <= self.budget
    }
}

// ---------------------------------------------------------------------------
// Quarantine leakage: the absence claim, attacked
// ---------------------------------------------------------------------------

/// Four different routes all reach a typed refusal and the `Refused` phase.
///
/// **What this does and does not prove.** The routes below all refuse during
/// the command phase, before any pack byte is buffered, so their
/// `quarantine_len() == 0` assertion is *vacuous on its own* — it would pass on
/// a machine that never discards anything, because there is nothing to
/// discard. Measured: all four report zero buffered bytes at the point of
/// refusal.
///
/// The check is kept because it is free and would catch a machine that somehow
/// accrued bytes on these paths, but the load-bearing quarantine evidence is
/// `a_refusal_after_pack_bytes_were_buffered_still_leaves_nothing`, which
/// buffers real bytes first and asserts that it did. What *this* test carries
/// on its own is that four structurally different malformed inputs each reach a
/// typed refusal rather than being absorbed.
///
/// **Each route is bound to the refusal it is meant to exercise.** An earlier
/// version asserted only `is_err()`, which cannot tell "this route refused for
/// its own reason" from "this route refused for some unrelated reason that
/// happens to fire first". That distinction is the whole value of a route
/// table: four labels asserting one generic failure are one probe wearing four
/// names. Binding the variant also pins the routes apart from each other, since
/// each names a different one.
///
/// It does **not** prove the refusal is the *earliest* possible one, nor that
/// no other defect coexists on the path — only that the named guard is the one
/// that answered.
#[test]
fn every_refusal_route_leaves_an_empty_quarantine() {
    // (label, the packets to feed, the refusal this route exists to provoke).
    // The predicate is a plain fn pointer so the table stays a table.
    let routes: Vec<(&str, Vec<Packet>, fn(&ReceiveError) -> bool)> = vec![
        (
            "malformed command line",
            vec![Packet::Data(b"not-a-command".to_vec())],
            |error| matches!(error, ReceiveError::MalformedCommand { .. }),
        ),
        (
            "both object ids zero",
            vec![command(
                ZERO,
                ZERO,
                "refs/heads/main",
                Some("report-status"),
            )],
            |error| matches!(error, ReceiveError::BothObjectIdsZero),
        ),
        (
            "duplicate ref command",
            vec![
                command(ZERO, NEW, "refs/heads/main", Some("report-status")),
                command(NEW, OTHER, "refs/heads/main", None),
            ],
            |error| matches!(error, ReceiveError::DuplicateRefCommand { .. }),
        ),
        (
            "capabilities after the first command",
            vec![
                command(ZERO, NEW, "refs/heads/main", Some("report-status")),
                command(ZERO, OTHER, "refs/heads/other", Some("report-status")),
            ],
            |error| matches!(error, ReceiveError::CapabilitiesNotFirstCommand),
        ),
    ];

    for (label, packets, expected) in routes {
        let mut machine = ReceivePack::new(context()).expect("machine");
        let mut refusal: Option<ReceiveError> = None;
        for packet in packets {
            if let Err(error) = machine.push_packet(packet) {
                refusal = Some(error);
                break;
            }
        }
        if refusal.is_none() {
            // Some routes only refuse at the flush that parses the request.
            if let Err(error) = machine.push_packet(Packet::Flush) {
                refusal = Some(error);
            }
        }

        let Some(error) = refusal else {
            panic!("{label}: expected a typed refusal and got none");
        };
        assert!(
            expected(&error),
            "{label}: refused with {error:?}, which is not the guard this route \
             exists to exercise — the route may be reaching a different failure \
             first, which would make its label wrong"
        );
        assert_eq!(
            machine.quarantine_len(),
            0,
            "{label}: refused but retained {} quarantine bytes",
            machine.quarantine_len()
        );
        assert_eq!(
            machine.phase(),
            ReceivePhase::Refused,
            "{label}: refusal did not move the machine to Refused"
        );
    }
}

/// The permitted twin of the corpus above: a well-formed request is *not*
/// refused, so the refusals are discriminating rather than a parser that
/// rejects everything.
#[test]
fn the_well_formed_request_those_probes_were_derived_from_is_accepted() {
    let mut machine = ReceivePack::new(context()).expect("machine");
    machine
        .push_packet(command(ZERO, NEW, "refs/heads/main", Some("report-status")))
        .expect("a well-formed create command must be accepted");
    machine
        .push_packet(Packet::Flush)
        .expect("the command flush must be accepted");
    assert_ne!(
        machine.phase(),
        ReceivePhase::Refused,
        "the twin of every refusal probe must not itself refuse"
    );
}

/// A refusal that arrives *after* pack bytes have entered quarantine must still
/// leave nothing behind.
///
/// This is the leak that matters: refusing before any bytes are retained is
/// easy, and proves little. The interesting case is a machine that has already
/// buffered raw pack bytes and then refuses.
#[test]
fn a_refusal_after_pack_bytes_were_buffered_still_leaves_nothing() {
    let mut machine = ReceivePack::new(context()).expect("machine");
    machine
        .push_packet(command(ZERO, NEW, "refs/heads/main", Some("report-status")))
        .expect("create command");
    machine.push_packet(Packet::Flush).expect("command flush");

    // Feed a truncated pack: enough to enter the quarantine buffer, not enough
    // to be a valid pack.
    let pack = empty_pack();
    let truncated = &pack[..pack.len() / 2];
    let _ = machine.push_bytes(truncated);
    let buffered = machine.quarantine_len();
    // Verified, not assumed: if nothing was buffered this test would prove
    // nothing about discarding, and would pass on a machine that never
    // discards. Measured at 16 bytes when this was written.
    assert!(
        buffered > 0,
        "the truncated pack buffered nothing, so this probe cannot observe a discard"
    );

    // Now force a refusal by reusing the machine illegally.
    let outcome = machine.push_packet(Packet::Data(b"unexpected".to_vec()));
    if outcome.is_err() {
        assert_eq!(
            machine.quarantine_len(),
            0,
            "refused while holding {buffered} buffered bytes and kept {} of them",
            machine.quarantine_len()
        );
    } else {
        // If the machine did not refuse, it must not have silently dropped the
        // buffered bytes either — that would be a different defect.
        assert!(
            machine.quarantine_len() >= buffered,
            "bytes vanished without a refusal: had {buffered}, now {}",
            machine.quarantine_len()
        );
    }
}

// ---------------------------------------------------------------------------
// The disconnect matrix: no stuck intermediate
// ---------------------------------------------------------------------------

/// Cancelling at every checkpoint budget leaves an actionable state.
///
/// The acceptance line is that a push interrupted at any phase leaves no seal,
/// a retryable seal, or a terminal outcome — never a stuck intermediate. At the
/// wire layer that reads as: the machine is either refused, complete, or in a
/// phase that legitimately expects more input. A machine that cancelled into
/// `Ready` and stayed there would be stuck, because `Ready` asserts a handoff
/// is owed that will never come.
///
/// Sweeping the budget from 0 upward walks the cancellation across every
/// checkpoint the machine takes, rather than picking one convenient moment.
#[test]
fn cancelling_at_every_checkpoint_leaves_no_stuck_intermediate() {
    let pack = empty_pack();
    let mut observed_phases = Vec::new();
    let mut observed_cancellation = false;

    for budget in 0..12_usize {
        let mut machine = ReceivePack::new(context()).expect("machine");
        machine
            .push_packet(command(ZERO, NEW, "refs/heads/main", Some("report-status")))
            .expect("create command");
        machine.push_packet(Packet::Flush).expect("command flush");
        let _ = machine.push_bytes(&pack);

        let mut handoff = CountingHandoff::default();
        let mut cancel = CancelAfter::new(budget);
        let outcome = machine.finish_with_handoff(&mut handoff, &mut cancel);
        let phase = machine.phase();
        observed_phases.push(phase);

        // The owner's stated contract, applied exactly rather than loosely.
        // Per the wire owner: a structural cancel must yield Err(Cancelled), phase
        // Refused, and an empty quarantine. An earlier version of this test
        // accepted ANY error and also accepted phase Pack, which would have
        // passed on a machine that cancelled into a mid-stream state while
        // still holding bytes — looser than the contract it claimed to check.
        match outcome {
            Err(ReceiveError::Cancelled) => {
                observed_cancellation = true;
                assert_eq!(
                    phase,
                    ReceivePhase::Refused,
                    "budget {budget}: cancelled but left the machine in {phase:?}"
                );
                assert_eq!(
                    machine.quarantine_len(),
                    0,
                    "budget {budget}: cancelled while still holding {} bytes",
                    machine.quarantine_len()
                );
            }
            Ok(_completion) => {
                assert_eq!(
                    phase,
                    ReceivePhase::Complete,
                    "budget {budget}: succeeded but left the machine in {phase:?}"
                );
                assert_eq!(
                    machine.quarantine_len(),
                    0,
                    "budget {budget}: completed while still holding {} bytes",
                    machine.quarantine_len()
                );
            }
            Err(other) => {
                // A different typed refusal is permitted, but it must still be
                // terminal and must still have discarded.
                assert_eq!(
                    phase,
                    ReceivePhase::Refused,
                    "budget {budget}: refused with {other:?} but left {phase:?}"
                );
                assert_eq!(
                    machine.quarantine_len(),
                    0,
                    "budget {budget}: refused with {other:?} while holding {} bytes",
                    machine.quarantine_len()
                );
            }
        }

        // The handoff must never be called more than once: a second call would
        // mean one push could admit twice.
        assert!(
            handoff.calls <= 1,
            "budget {budget}: handoff called {} times",
            handoff.calls
        );
    }

    // Non-vacuity: the sweep must actually have cancelled something, or it
    // proved only that an uncancelled push works.
    assert!(
        observed_cancellation,
        "no budget in the sweep produced Err(Cancelled); the matrix never exercised \
         the cancellation contract at all"
    );
    assert!(
        observed_phases.contains(&ReceivePhase::Complete),
        "no budget in the sweep completed; the matrix never reached the success path"
    );
}

/// A terminal machine refuses further input rather than accepting it.
///
/// Reusing a finished session is the shape of a client that retries on a
/// connection it already spent. It must fail closed with a typed refusal, not
/// silently accept a second request into the same state.
#[test]
fn a_terminal_machine_refuses_reuse_instead_of_accepting_a_second_request() {
    let mut machine = ReceivePack::new(context()).expect("machine");
    machine
        .push_packet(command(ZERO, NEW, "refs/heads/main", Some("report-status")))
        .expect("create command");
    machine.push_packet(Packet::Flush).expect("command flush");
    let _ = machine.push_bytes(&empty_pack());

    let mut handoff = CountingHandoff::default();
    let mut always = || true;
    let _ = machine.finish_with_handoff(&mut handoff, &mut always);

    let error = machine
        .push_packet(command(ZERO, OTHER, "refs/heads/second", None))
        .expect_err("a terminal machine must refuse a second request");
    assert!(
        matches!(error, ReceiveError::TerminalState { .. }),
        "reuse produced {error:?} rather than a TerminalState refusal"
    );
    assert_eq!(
        machine.quarantine_len(),
        0,
        "a terminal machine retained bytes across an attempted reuse"
    );
}

// ---------------------------------------------------------------------------
// Quota boundaries: refused past the bound, accepted at it
// ---------------------------------------------------------------------------

/// The command ceiling refuses one past the limit and accepts exactly the
/// limit.
///
/// Asserting only the refusal would pass on a parser that rejects every
/// request, which is why the twin at the boundary is the load-bearing half.
#[test]
fn the_command_ceiling_accepts_the_bound_and_refuses_one_past_it() {
    let limits = ReceiveLimits {
        max_commands: 3,
        ..ReceiveLimits::default()
    };

    // At the bound: accepted.
    let mut at_bound = ReceivePack::new(context_with(limits.clone())).expect("machine");
    for index in 0..3 {
        let caps = if index == 0 {
            Some("report-status")
        } else {
            None
        };
        at_bound
            .push_packet(command(ZERO, NEW, &format!("refs/heads/b{index}"), caps))
            .unwrap_or_else(|error| panic!("command {index} at the bound was refused: {error:?}"));
    }
    at_bound
        .push_packet(Packet::Flush)
        .expect("a request exactly at the command bound must be accepted");
    assert_ne!(at_bound.phase(), ReceivePhase::Refused);

    // One past: refused, with the bound named.
    let mut past_bound = ReceivePack::new(context_with(limits)).expect("machine");
    let mut refusal = None;
    for index in 0..4 {
        let caps = if index == 0 {
            Some("report-status")
        } else {
            None
        };
        if let Err(error) =
            past_bound.push_packet(command(ZERO, NEW, &format!("refs/heads/b{index}"), caps))
        {
            refusal = Some(error);
            break;
        }
    }
    let refusal = refusal
        .or_else(|| past_bound.push_packet(Packet::Flush).err())
        .expect("one command past the bound must be refused");
    assert!(
        matches!(refusal, ReceiveError::TooManyCommands { limit: 3 }),
        "expected TooManyCommands {{ limit: 3 }}, got {refusal:?}"
    );
    assert_eq!(
        past_bound.quarantine_len(),
        0,
        "a quota refusal retained quarantine bytes"
    );
}

// ---------------------------------------------------------------------------
// Bomb packs: the retention ceiling, refused before the bytes are kept
// ---------------------------------------------------------------------------

/// A pack larger than the quarantine ceiling is refused, and the ceiling is not
/// exceeded on the way to refusing it.
///
/// This is the property that distinguishes a real bound from a check: a machine
/// that buffered the whole oversized pack and *then* noticed would have already
/// paid the memory cost the bound exists to prevent. Asserting only the refusal
/// would pass on exactly that machine. So this asserts the refusal **and** that
/// the retained byte count never exceeded the limit.
///
/// The pack here is a bomb only in the sense that matters at this layer — it is
/// bigger than the machine agreed to hold. Decompression bombs are the pack
/// reader's dimension and are covered by `pack_bombs.sh`; duplicating them here
/// would be re-testing someone else's boundary through a thinner interface.
#[test]
fn a_pack_past_the_quarantine_ceiling_is_refused_without_ever_exceeding_it() {
    // The ceiling must not exceed the pack reader's own input bound, so shrink
    // both together rather than only one.
    let mut limits = ReceiveLimits::default();
    limits.pack.max_input_bytes = 64;
    limits.max_quarantine_bytes = 64;

    let mut machine = ReceivePack::new(context_with(limits)).expect("machine");
    machine
        .push_packet(command(ZERO, NEW, "refs/heads/main", Some("report-status")))
        .expect("create command");
    machine.push_packet(Packet::Flush).expect("command flush");

    // Feed well past the ceiling, in chunks, checking after every chunk that the
    // machine never held more than it agreed to.
    let chunk = [0_u8; 32];
    let mut refusal = None;
    for _ in 0..8 {
        match machine.push_bytes(&chunk) {
            Ok(_) => {
                assert!(
                    machine.quarantine_len() <= 64,
                    "the machine held {} bytes against a 64-byte ceiling",
                    machine.quarantine_len()
                );
            }
            Err(error) => {
                refusal = Some(error);
                break;
            }
        }
    }

    let refusal = refusal.expect("a pack past the quarantine ceiling must be refused");
    assert!(
        matches!(refusal, ReceiveError::QuarantineBytesExceeded { limit: 64 }),
        "expected QuarantineBytesExceeded {{ limit: 64 }}, got {refusal:?}"
    );
    assert_eq!(
        machine.quarantine_len(),
        0,
        "refused the oversized pack but kept {} bytes",
        machine.quarantine_len()
    );
    assert_eq!(machine.phase(), ReceivePhase::Refused);
}

/// The permitted twin: a pack that fits is accepted and retained.
///
/// Without this the ceiling test would pass on a machine that refused every
/// byte, and "the bound works" would mean "nothing gets through".
#[test]
fn a_pack_within_the_quarantine_ceiling_is_accepted_and_retained() {
    let mut limits = ReceiveLimits::default();
    limits.pack.max_input_bytes = 64;
    limits.max_quarantine_bytes = 64;

    let mut machine = ReceivePack::new(context_with(limits)).expect("machine");
    machine
        .push_packet(command(ZERO, NEW, "refs/heads/main", Some("report-status")))
        .expect("create command");
    machine.push_packet(Packet::Flush).expect("command flush");

    machine
        .push_bytes(&[0_u8; 64])
        .expect("a pack exactly at the ceiling must be accepted");
    assert_eq!(
        machine.quarantine_len(),
        64,
        "a pack at the ceiling must actually be retained, or the twin proves nothing"
    );
    assert_ne!(machine.phase(), ReceivePhase::Refused);
}

// ---------------------------------------------------------------------------
// Disclosure boundary
// ---------------------------------------------------------------------------

/// The handoff never receives pack bytes for a delete-only request.
///
/// `finish_with_handoff` documents that it "never returns pack bytes or
/// entries". For a delete-only push there is no pack at all, so a handoff that
/// saw one would be disclosing something that does not exist — the clearest
/// possible form of the leak this acceptance line is about.
#[test]
fn a_delete_only_push_hands_off_no_pack_at_all() {
    let mut machine = ReceivePack::new(context()).expect("machine");
    machine
        .push_packet(command(
            NEW,
            ZERO,
            "refs/heads/doomed",
            Some("report-status delete-refs"),
        ))
        .expect("delete command");
    machine.push_packet(Packet::Flush).expect("command flush");

    let mut handoff = CountingHandoff::default();
    let mut always = || true;
    machine
        .finish_with_handoff(&mut handoff, &mut always)
        .expect("a delete-only request needs no pack");

    assert_eq!(handoff.calls, 1, "handoff must run exactly once");
    assert!(
        !handoff.saw_pack_bytes,
        "a delete-only push handed a pack to admission"
    );
    assert_eq!(
        machine.quarantine_len(),
        0,
        "a delete-only push retained quarantine bytes"
    );
}
