#![forbid(unsafe_code)]
//! Receive-pack push-option and report-status refusals (`frankengit-9xyg`).
//!
//! §6 keeps fetch and push as **separate** service and capability matrices and
//! makes refusal behaviour a compatibility semantic. This is the push half:
//! what a client may send as options, and what the server may say back in
//! report-status. `StatusCountMismatch` in particular guards the report against
//! disagreeing with the command list it answers — a status report with the
//! wrong arity is a lie about which ref succeeded.
//!
//! Measured per variant, with the both-trees grep: `fgit-wire` has no
//! suite-like module in `src/`, so a `tests/` scan is sound here. (It is not
//! everywhere — `fgit-authority` keeps its capacity assertions in
//! `src/suite.rs`, invoked from `tests/capacity_conformance.rs`, which makes a
//! covered variant look untested.)
//!
//! # The property that makes this more than a coverage chore
//!
//! `validate_push_option` and `validate_status_message` are **structurally
//! identical**:
//!
//! ```text
//! value.is_empty() || value.len() > <bound> || value contains NUL, CR or LF
//! ```
//!
//! Same three conditions, same order — but **different refusal variants** and
//! different bounds. A probe of either surface alone cannot tell that these are
//! two distinct guards rather than one shared helper called twice: if they were
//! refactored into a single helper with a single variant, every single-surface
//! probe would stay green.
//! [`the_two_identically_shaped_guards_report_different_refusals`] drives one
//! identically-shaped bad value through both in a single test and asserts they
//! differ, which is what would catch that collapse.
//!
//! # The equality bound, third instance
//!
//! `push_option` reads `self.push_options.len() == max_push_options` — exact
//! equality, after `check_packet_count` (`88o7`) and `Capabilities::insert`
//! (`m0mj`). Safe for the same reason all three are: `push_options` is a `Vec`
//! pushed exactly once per accepted option with the check before every push, so
//! the length sequence has no gaps and cannot step over the bound.
//! [`every_count_up_to_the_push_option_bound_is_admitted`] is the presence case
//! for that reading rather than an assertion of it.
//!
//! # The accepted path was built first, on purpose
//!
//! On `1zg4` all four of my permitted twins failed on their first run while
//! every refusal probe passed — the accepted transcript needed a `want` and a
//! `done` I had not supplied, so each refusal was green for the wrong reason. A
//! refusal-only corpus would have looked finished. Here the accepted
//! transcripts were made to pass before any refusal probe was written.
//!
//! # Non-claims
//!
//! Four `ReceiveError` variants. The signed-push certificate pair
//! (`CertificateTooLarge`, `CertificateTruncated`) is **left open**: it needs a
//! nonce-bearing signed context and a multi-line certificate body, which is a
//! different fixture from anything here. `AllocationFailure` (16 sites) needs a
//! real allocation failure and is defensive. LEAD count, not a remaining-work
//! total.
//!
//! This file deliberately does not touch `tests/receivepack_adversarial.rs` or
//! `tests/receivepack_limits_propagation.rs`, whose passing-probe counts
//! `scripts/e2e/suites/wire/receivepack_adversarial.sh` asserts exactly.
//!
//! Nothing here modifies `crates/fgit-wire/src/**`.

use fgit_wire::receive::{
    ReceiveCommandStatus, ReceiveContext, ReceiveError, ReceiveEvent, ReceiveLimits, ReceivePack,
    ReceiveRequest, SignedPushProfile, UnpackStatus, report_status,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const OLD: &str = "1111111111111111111111111111111111111111";
const NEW: &str = "2222222222222222222222222222222222222222";

/// Capabilities for a request that ends at the command flush.
///
/// Deliberately WITHOUT `push-options`: negotiating it moves the machine into
/// the push-option phase, so the request is not ready until a second flush.
/// Discovered by running — my first draft used one capability set for both
/// helpers and every status probe panicked at "the command flush must expose a
/// parsed request".
const STATUS_CAPS: &str = "report-status";

/// Capabilities for a request that continues into the push-option phase.
const OPTION_CAPS: &str = "report-status push-options";

fn capabilities(source: &[u8]) -> Capabilities {
    Capabilities::parse_v1(source, &WireLimits::default()).expect("fixture capabilities")
}

fn limits() -> ReceiveLimits {
    ReceiveLimits::default()
}

fn context(limits: ReceiveLimits) -> ReceiveContext {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        capabilities(b"report-status push-options delete-refs"),
        limits,
        SignedPushProfile::Refuse,
    )
    .expect("fixture receive context")
}

fn command(name: &str, capabilities: Option<&str>) -> Packet {
    let mut line = format!("{OLD} {NEW} {name}").into_bytes();
    if let Some(capabilities) = capabilities {
        line.push(0);
        line.extend_from_slice(capabilities.as_bytes());
    }
    Packet::Data(line)
}

/// A machine that has consumed `commands` command lines and their flush, so it
/// is in the push-option phase.
fn machine_after_commands(limits: ReceiveLimits, commands: &[&str]) -> ReceivePack {
    let mut machine = ReceivePack::new(context(limits)).expect("receive machine");
    for (index, name) in commands.iter().enumerate() {
        let caps = (index == 0).then_some(OPTION_CAPS);
        machine
            .push_packet(command(name, caps))
            .unwrap_or_else(|error| panic!("command {name} must be accepted, got {error:?}"));
    }
    machine
        .push_packet(Packet::Flush)
        .expect("the command flush closes the command list");
    machine
}

/// Drives one command plus its flush and returns the parsed request.
fn ready_request(commands: &[&str]) -> ReceiveRequest {
    let mut machine = ReceivePack::new(context(limits())).expect("receive machine");
    for (index, name) in commands.iter().enumerate() {
        let caps = (index == 0).then_some(STATUS_CAPS);
        machine
            .push_packet(command(name, caps))
            .expect("command accepted");
    }
    let transition = machine
        .push_packet(Packet::Flush)
        .expect("the command flush exposes the request");
    let Some(ReceiveEvent::RequestReady(request)) = transition.events.first() else {
        panic!("the command flush must expose a parsed request");
    };
    (**request).clone()
}

/// Pushes one push-option line, returning the refusal if there is one.
fn push_option(machine: &mut ReceivePack, value: &[u8]) -> Result<(), ReceiveError> {
    machine
        .push_packet(Packet::Data(value.to_vec()))
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// The accepted paths, first — built before any refusal probe
// ---------------------------------------------------------------------------

/// A report answering exactly its command list is produced.
#[test]
fn a_report_matching_its_command_list_is_produced() {
    let request = ready_request(&["refs/heads/main"]);
    let packets = report_status(
        &request,
        UnpackStatus::Ok,
        &[ReceiveCommandStatus::Ok],
        &limits(),
    )
    .expect("a report answering one command must be produced");
    assert!(
        !packets.is_empty(),
        "a report-status client receives report packets"
    );
}

/// A well-formed push option is accepted.
#[test]
fn a_well_formed_push_option_is_accepted() {
    let mut machine = machine_after_commands(limits(), &["refs/heads/main"]);
    push_option(&mut machine, b"verify=1").expect("a bounded printable option is accepted");
}

// ---------------------------------------------------------------------------
// StatusCountMismatch — both directions
// ---------------------------------------------------------------------------

/// Fewer statuses than commands is refused, and the refusal reports both counts.
#[test]
fn a_report_with_too_few_statuses_is_refused() {
    let request = ready_request(&["refs/heads/main", "refs/heads/next"]);
    let error = report_status(
        &request,
        UnpackStatus::Ok,
        &[ReceiveCommandStatus::Ok],
        &limits(),
    )
    .expect_err("one status cannot answer two commands");
    assert_eq!(
        error,
        ReceiveError::StatusCountMismatch {
            expected: 2,
            actual: 1
        },
        "the refusal reports what was expected and what arrived"
    );
}

/// More statuses than commands is the other direction of the same guard.
///
/// A probe hitting only one direction leaves the other unexercised — and a
/// report claiming a result for a ref the client never asked about is the more
/// alarming of the two.
#[test]
fn a_report_with_too_many_statuses_is_refused() {
    let request = ready_request(&["refs/heads/main"]);
    let error = report_status(
        &request,
        UnpackStatus::Ok,
        &[ReceiveCommandStatus::Ok, ReceiveCommandStatus::Ok],
        &limits(),
    )
    .expect_err("two statuses cannot answer one command");
    assert_eq!(
        error,
        ReceiveError::StatusCountMismatch {
            expected: 1,
            actual: 2
        }
    );
}

// ---------------------------------------------------------------------------
// InvalidPushOption — every condition of the guard
// ---------------------------------------------------------------------------

/// An empty push option carries nothing.
#[test]
fn an_empty_push_option_is_refused() {
    let mut machine = machine_after_commands(limits(), &["refs/heads/main"]);
    let error = push_option(&mut machine, b"").expect_err("an empty option carries nothing");
    assert_eq!(error, ReceiveError::InvalidPushOption);
}

/// **Only one of the three control bytes reaches this guard, and finding out
/// which took running it.**
///
/// `validate_push_option` rejects NUL, CR and LF. But the option line first
/// passes `command_packet_text`, which rejects CR and LF *and deliberately
/// permits NUL* — because a receive-pack command line uses NUL as its
/// capability separator. So from the wire:
///
/// ```text
/// a\0b   reaches validate_push_option   -> InvalidPushOption
/// a\rb   caught by command_packet_text  -> Wire(MalformedRequestLine)
/// a\nb   caught by command_packet_text  -> Wire(MalformedRequestLine)
/// ```
///
/// `validate_push_option`'s CR/LF term is therefore **unreachable through this
/// entry point** — defensive, guarding against a future caller that does not
/// pre-filter. Asserting both outcomes is more informative than asserting all
/// three refuse: it pins which layer owns which byte, and the one-byte
/// difference between the two line guards is load-bearing rather than an
/// oversight.
///
/// My first draft asserted all three gave `InvalidPushOption` and failed on the
/// CR case. The failure was the finding.
#[test]
fn only_nul_reaches_the_push_option_content_guard() {
    let mut nul_machine = machine_after_commands(limits(), &["refs/heads/main"]);
    let nul = push_option(&mut nul_machine, b"a\0b")
        .expect_err("a NUL passes the line guard and is refused by the content guard");
    assert_eq!(
        nul,
        ReceiveError::InvalidPushOption,
        "NUL is permitted by command_packet_text, so it reaches validate_push_option"
    );

    for injected in [&b"a\rb"[..], b"a\nb"] {
        let mut machine = machine_after_commands(limits(), &["refs/heads/main"]);
        let error = push_option(&mut machine, injected).expect_err(&format!(
            "the option {:?} must be refused",
            String::from_utf8_lossy(injected)
        ));
        assert!(
            matches!(
                error,
                ReceiveError::Wire(fgit_wire::WireError::MalformedRequestLine { .. })
            ),
            "{:?} is caught by the line guard before the content guard, got {error:?}",
            String::from_utf8_lossy(injected)
        );
    }
}

/// **The permitted twin at the exact boundary**, paired with one byte past it.
///
/// The guard reads `>`, so a value of exactly the bound is legal — the case a
/// refusal-only corpus cannot see.
#[test]
fn a_push_option_at_exactly_the_bound_is_admitted() {
    let bound = limits().max_push_option_bytes;

    let mut admitting = machine_after_commands(limits(), &["refs/heads/main"]);
    push_option(&mut admitting, &vec![b'a'; bound])
        .expect("an option of exactly the bound must be admitted");

    let mut refusing = machine_after_commands(limits(), &["refs/heads/main"]);
    let error = push_option(&mut refusing, &vec![b'a'; bound + 1])
        .expect_err("one byte past the bound must refuse");
    assert_eq!(error, ReceiveError::InvalidPushOption);
}

// ---------------------------------------------------------------------------
// TooManyPushOptions — and its equality bound
// ---------------------------------------------------------------------------

#[test]
fn more_push_options_than_the_bound_are_refused() {
    let mut limits = limits();
    limits.max_push_options = 2;
    let mut machine = machine_after_commands(limits, &["refs/heads/main"]);
    push_option(&mut machine, b"one").expect("the first option fits");
    push_option(&mut machine, b"two").expect("the second option fits");

    let error =
        push_option(&mut machine, b"three").expect_err("a third option exceeds a bound of two");
    assert_eq!(error, ReceiveError::TooManyPushOptions { limit: 2 });
}

/// The presence case for the equality bound being sound.
///
/// `push_option` tests `len() == max_push_options`, which is only safe if the
/// length visits every value. It is a `Vec` pushed exactly once per accepted
/// option with the check before every push, so this drives every count from 1
/// to the bound and shows each admitted.
#[test]
fn every_count_up_to_the_push_option_bound_is_admitted() {
    const BOUND: usize = 4;
    for count in 1..=BOUND {
        let mut limits = limits();
        limits.max_push_options = BOUND;
        let mut machine = machine_after_commands(limits, &["refs/heads/main"]);
        for index in 0..count {
            let option = format!("option-{index}");
            push_option(&mut machine, option.as_bytes()).unwrap_or_else(|error| {
                panic!("{count} options at a bound of {BOUND} must be admitted, got {error:?}")
            });
        }
    }
}

// ---------------------------------------------------------------------------
// The two identically-shaped guards must stay distinct
// ---------------------------------------------------------------------------

/// One identically-shaped bad value, two surfaces, **two different refusals**.
///
/// `validate_push_option` and `validate_status_message` apply the same three
/// conditions in the same order and differ only in their bound and their
/// variant. A probe of either alone would still pass if the two were collapsed
/// into one shared helper with one variant; this asserts the distinction that
/// collapse would destroy.
#[test]
fn the_two_identically_shaped_guards_report_different_refusals() {
    // NUL, not CR: CR is caught by the line guard before the push-option
    // content guard ever sees it. See only_nul_reaches_the_push_option_content_guard.
    const INJECTED: &[u8] = b"a\0b";

    let mut machine = machine_after_commands(limits(), &["refs/heads/main"]);
    let option_error =
        push_option(&mut machine, INJECTED).expect_err("a NUL is rejected as a push option");

    let request = ready_request(&["refs/heads/main"]);
    let status_error = report_status(
        &request,
        UnpackStatus::Rejected {
            message: INJECTED.to_vec(),
        },
        &[ReceiveCommandStatus::Ok],
        &limits(),
    )
    .expect_err("a NUL is rejected in a status message");

    assert_eq!(option_error, ReceiveError::InvalidPushOption);
    assert_eq!(status_error, ReceiveError::InvalidStatusMessage);
    assert_ne!(
        option_error, status_error,
        "two structurally identical guards must not collapse into one refusal"
    );
}

/// `InvalidStatusMessage` on its own surface, with the empty case.
#[test]
fn an_empty_status_message_is_refused() {
    let request = ready_request(&["refs/heads/main"]);
    let error = report_status(
        &request,
        UnpackStatus::Rejected {
            message: Vec::new(),
        },
        &[ReceiveCommandStatus::Ok],
        &limits(),
    )
    .expect_err("an empty status message explains nothing");
    assert_eq!(error, ReceiveError::InvalidStatusMessage);
}

/// The permitted twin for the status-message surface.
#[test]
fn a_well_formed_status_message_is_accepted() {
    let request = ready_request(&["refs/heads/main"]);
    report_status(
        &request,
        UnpackStatus::Rejected {
            message: b"index-pack failed".to_vec(),
        },
        &[ReceiveCommandStatus::Ok],
        &limits(),
    )
    .expect("a bounded printable status message must be accepted");
}
