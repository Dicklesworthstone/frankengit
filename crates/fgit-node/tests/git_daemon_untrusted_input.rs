#![forbid(unsafe_code)]
//! The git-daemon untrusted-input boundary (`frankengit-2wly`).
//!
//! `parse_git_daemon_request` is the **first code an anonymous network peer
//! reaches**. §9 treats external text as untrusted data; §6 makes refusal
//! behaviour a compatibility semantic and requires bounded validation before
//! work. `GitDaemonPathRefusal::ParentComponent` exists so that
//! `/repo/../../etc` cannot be read as a filesystem traversal — and until this
//! file, nothing tested it.
//!
//! **This is `fgit-node`'s first integration test.** The crate had no `tests/`
//! directory at all, so every refusal it owns was covered — if at all — only by
//! its inline `cfg(test)` module, and a reader of `tests/` counted zero.
//! Measured before writing: `GitDaemonTransportRefusal` is 10 unnamed of 14
//! constructed, `GitDaemonPathRefusal` 5 of 6.
//!
//! # Everything here goes through one public function taking raw bytes
//!
//! ```text
//! pub fn parse_git_daemon_request(frame: &[u8], limits: WireLimits)
//!     -> Result<GitDaemonRequest, GitDaemonTransportRefusal>
//! ```
//!
//! No fixture plumbing, no fabricated state — every probe below is a byte
//! string a peer could put on a socket.
//!
//! # Two ordered chains, and the second is subtler than it looks
//!
//! ```text
//! payload:  MissingGreetingTerminator -> parameter terminator ->
//!           MalformedServiceRequest -> UnsupportedService -> path parse ->
//!           DuplicateProtocolVersion -> UnsupportedProtocolVersion
//!
//! path:     Empty -> NotAbsolute -> then PER COMPONENT, in loop order,
//!           EmptyComponent -> DotComponent -> ParentComponent -> ControlByte
//! ```
//!
//! The four per-component arms are **mutually exclusive within one component**:
//! a component cannot both be `..` and contain a control byte. So the only
//! observable ordering among them is *across* components — the first offending
//! component wins, which is **loop order, not check order**. Conflating the two
//! is the easy mistake here, so
//! [`the_first_offending_component_wins_whichever_fault_comes_first`] probes it
//! both ways round: a result that held for only one ordering would be arm
//! order, and a result that holds for both is position.
//!
//! Single-fault probes are structurally blind to a stage swap — each violates
//! one rule and still reaches its own stage wherever that stage sits. So five
//! probes here drive inputs that are wrong **twice**.
//!
//! # Assertion style
//!
//! `GitDaemonPathRefusal` is `PartialEq`, so path arms assert the exact inner
//! reason with `assert_eq!` — never merely that the path was rejected.
//! `GitDaemonTransportRefusal` carries an `io::Error` and derives only `Debug`,
//! so its arms use `matches!`, with payload fields checked inside the pattern.
//!
//! # Non-claims
//!
//! This closes the **parse-reachable** subset only. `Io`,
//! `GreetingPacketTooLarge`, `GreetingPacketTooSmall`, `InvalidGreetingLength`
//! and `IncompleteNegotiation` are constructed in `read_git_daemon_request` and
//! `git_daemon_packet_length`, which are private and need an `impl Read`; they
//! are unreachable from an integration test and are **not** counted as closed.
//! `NodeRefusal` (13 unnamed of 19) and `AdmissionMaterializationRefusal` (15 of
//! 25) keep their own gaps. LEAD count, not a remaining-work total.
//!
//! Nothing here modifies `crates/fgit-node/src/**` or any manifest.

use fgit_node::{GitDaemonPathRefusal, GitDaemonTransportRefusal, parse_git_daemon_request};
use fgit_wire::WireLimits;

/// Wraps a payload in one pkt-line frame: four lowercase hex bytes of total
/// length, then the payload.
///
/// Written out here rather than borrowed from `fgit-wire`'s encoder, because a
/// probe of an untrusted-input boundary should speak the wire format in its own
/// vocabulary rather than through the encoder the parser is paired with.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = format!("{:04x}", payload.len() + 4).into_bytes();
    framed.extend_from_slice(payload);
    framed
}

/// A complete, well-formed upload-pack greeting for `path`.
fn greeting(path: &[u8]) -> Vec<u8> {
    let mut payload = b"git-upload-pack ".to_vec();
    payload.extend_from_slice(path);
    payload.push(0);
    frame(&payload)
}

fn parse(bytes: &[u8]) -> Result<fgit_node::GitDaemonRequest, GitDaemonTransportRefusal> {
    parse_git_daemon_request(bytes, WireLimits::default())
}

/// The refusal from a greeting naming `path`, which must be refused.
fn path_refusal(path: &[u8]) -> GitDaemonPathRefusal {
    match parse(&greeting(path)) {
        Ok(request) => panic!(
            "the path {:?} must be refused, but parsed as {:?}",
            String::from_utf8_lossy(path),
            String::from_utf8_lossy(request.repository_path().as_bytes())
        ),
        Err(GitDaemonTransportRefusal::InvalidRepositoryPath { reason }) => reason,
        Err(other) => panic!(
            "the path {:?} must refuse as an invalid repository path, got {other:?}",
            String::from_utf8_lossy(path)
        ),
    }
}

// ---------------------------------------------------------------------------
// The permitted terminus, first
// ---------------------------------------------------------------------------

/// A well-formed greeting parses and yields the exact requested key.
///
/// Every refusal below is measured against this. Without it a parser that
/// rejected all input would satisfy the entire file.
#[test]
fn a_well_formed_greeting_parses() {
    let request = parse(&greeting(b"/repo")).expect("a canonical upload-pack greeting must parse");
    assert_eq!(
        request.repository_path().as_bytes(),
        b"/repo",
        "the validated key is the exact requested path"
    );
}

/// **The permitted twin a refusal-only corpus cannot see.** A component that
/// *contains* dots is admitted; only a component that *is* `.` or `..` is not.
///
/// `/repo.git` is the overwhelmingly common real path, and a careless
/// tightening of the dot guard — matching "contains a dot" instead of "is a
/// dot" — would refuse it while leaving every refusal probe below green.
#[test]
fn a_component_containing_dots_is_admitted() {
    for path in [
        &b"/repo.git"[..],
        &b"/a..b"[..],
        &b"/...."[..],
        &b"/deep/nested.git"[..],
    ] {
        let request = parse(&greeting(path)).unwrap_or_else(|error| {
            panic!(
                "the path {:?} contains dots but is no dot component, got {error:?}",
                String::from_utf8_lossy(path)
            )
        });
        assert_eq!(request.repository_path().as_bytes(), path);
    }
}

// ---------------------------------------------------------------------------
// Frame-level refusals
// ---------------------------------------------------------------------------

/// A frame whose length header is not hex never reaches the greeting parser.
#[test]
fn a_malformed_pkt_line_frame_is_refused_as_a_wire_error() {
    let error = parse(b"zzzzgit-upload-pack /repo\0")
        .expect_err("a non-hex length header is not a pkt-line");
    assert!(
        matches!(error, GitDaemonTransportRefusal::Wire(_)),
        "frame syntax stays owned by the wire decoder, got {error:?}"
    );
}

/// A control packet where the greeting belongs is refused as such, not as a
/// count mismatch.
#[test]
fn a_control_packet_where_the_greeting_belongs_is_refused() {
    let error = parse(b"0000").expect_err("a flush is not a greeting");
    assert!(
        matches!(error, GitDaemonTransportRefusal::GreetingControlPacket),
        "a non-data packet is a control packet, not a sequence error, got {error:?}"
    );
}

/// Both directions of the count guard: no data packets, and two of them.
#[test]
fn the_wrong_number_of_data_packets_is_refused() {
    let none = parse(b"").expect_err("an empty stream carries no greeting");
    assert!(
        matches!(
            none,
            GitDaemonTransportRefusal::InvalidGreetingPacketSequence { packets: 0 }
        ),
        "got {none:?}"
    );

    let mut two = greeting(b"/repo");
    two.extend_from_slice(&greeting(b"/other"));
    let error = parse(&two).expect_err("two greetings are not one greeting");
    assert!(
        matches!(
            error,
            GitDaemonTransportRefusal::InvalidGreetingPacketSequence { packets: 2 }
        ),
        "the refusal reports how many packets arrived, got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// MissingGreetingTerminator — two construction sites
// ---------------------------------------------------------------------------

/// Site 1: the greeting carries no NUL at all.
#[test]
fn a_greeting_with_no_terminator_is_refused() {
    let error = parse(&frame(b"git-upload-pack /repo"))
        .expect_err("a greeting without its NUL is incomplete");
    assert!(
        matches!(error, GitDaemonTransportRefusal::MissingGreetingTerminator),
        "got {error:?}"
    );
}

/// Site 2: the greeting is terminated, but its trailing parameter section is
/// not.
///
/// A probe hitting only site 1 leaves this one unexercised — they are different
/// checks over different slices of the same payload.
#[test]
fn an_unterminated_parameter_section_is_refused() {
    let error = parse(&frame(b"git-upload-pack /repo\0host=example"))
        .expect_err("a parameter section must itself end in NUL");
    assert!(
        matches!(error, GitDaemonTransportRefusal::MissingGreetingTerminator),
        "got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Service selection
// ---------------------------------------------------------------------------

#[test]
fn a_greeting_with_no_space_is_refused() {
    let error = parse(&frame(b"git-upload-pack/repo\0"))
        .expect_err("service and path must be separated by a space");
    assert!(
        matches!(error, GitDaemonTransportRefusal::MalformedServiceRequest),
        "got {error:?}"
    );
}

/// Only `git-upload-pack` is served on this lane; the refusal reports the
/// length of what was asked for rather than echoing untrusted bytes.
#[test]
fn a_service_other_than_upload_pack_is_refused() {
    let error = parse(&frame(b"git-receive-pack /repo\0"))
        .expect_err("receive-pack is not served on the V0 daemon lane");
    assert!(
        matches!(
            error,
            GitDaemonTransportRefusal::UnsupportedService { service_bytes: 16 }
        ),
        "got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// GitDaemonPathRefusal — all six arms
// ---------------------------------------------------------------------------

#[test]
fn an_empty_repository_path_is_refused() {
    assert_eq!(path_refusal(b""), GitDaemonPathRefusal::Empty);
}

#[test]
fn a_relative_repository_path_is_refused() {
    assert_eq!(path_refusal(b"repo"), GitDaemonPathRefusal::NotAbsolute);
}

/// Both shapes that produce an empty component: a doubled separator and a
/// trailing slash.
#[test]
fn an_empty_path_component_is_refused() {
    assert_eq!(
        path_refusal(b"/a//b"),
        GitDaemonPathRefusal::EmptyComponent,
        "a doubled separator"
    );
    assert_eq!(
        path_refusal(b"/a/"),
        GitDaemonPathRefusal::EmptyComponent,
        "a trailing separator"
    );
}

/// A `.` component would admit a second spelling of one key.
#[test]
fn a_dot_component_is_refused() {
    assert_eq!(path_refusal(b"/a/./b"), GitDaemonPathRefusal::DotComponent);
}

/// **The traversal arm.** A `..` component is refused.
///
/// This is the one whose absence would be a defect rather than a coverage gap:
/// it is what stops `/repo/../../etc` being read as a filesystem traversal.
#[test]
fn a_parent_component_is_refused() {
    assert_eq!(
        path_refusal(b"/a/../b"),
        GitDaemonPathRefusal::ParentComponent
    );
    assert_eq!(
        path_refusal(b"/repo/../../etc"),
        GitDaemonPathRefusal::ParentComponent,
        "the shape the guard exists for"
    );
}

/// A control byte in a path component is refused, including NUL-adjacent and
/// newline forms that could confuse a downstream log or lookup.
#[test]
fn a_control_byte_in_a_component_is_refused() {
    assert_eq!(
        path_refusal(b"/a/\x01b"),
        GitDaemonPathRefusal::ControlByte,
        "SOH"
    );
    assert_eq!(
        path_refusal(b"/a/b\nc"),
        GitDaemonPathRefusal::ControlByte,
        "a newline"
    );
}

// ---------------------------------------------------------------------------
// Protocol-version parameters
// ---------------------------------------------------------------------------

#[test]
fn a_requested_protocol_version_is_refused() {
    let error = parse(&frame(b"git-upload-pack /repo\0version=2\0"))
        .expect_err("V2 serving is not wired on this daemon lane");
    assert!(
        matches!(
            error,
            GitDaemonTransportRefusal::UnsupportedProtocolVersion { version_bytes: 1 }
        ),
        "got {error:?}"
    );
}

#[test]
fn two_version_parameters_are_refused_as_a_duplicate() {
    let error = parse(&frame(b"git-upload-pack /repo\0version=2\0version=2\0"))
        .expect_err("one greeting cannot request two protocol versions");
    assert!(
        matches!(error, GitDaemonTransportRefusal::DuplicateProtocolVersion),
        "got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Ordering — inputs wrong twice
// ---------------------------------------------------------------------------

/// The terminator check runs before the service split: an input with neither a
/// NUL nor a space reports the terminator.
#[test]
fn a_missing_terminator_outranks_a_missing_space() {
    let error = parse(&frame(b"git-upload-pack/repo"))
        .expect_err("an input wrong in two ways must still refuse");
    assert!(
        matches!(error, GitDaemonTransportRefusal::MissingGreetingTerminator),
        "the terminator is found before the service is split, got {error:?}"
    );
}

/// The service is checked before the path is parsed: a wrong service carrying a
/// traversal path reports the service.
///
/// This matters beyond ordering — it means an unsupported service never reaches
/// path validation at all, so the path guard is not the only thing standing
/// between a hostile peer and a lookup key.
#[test]
fn an_unsupported_service_outranks_a_traversal_path() {
    let error = parse(&frame(b"git-receive-pack /../../etc\0"))
        .expect_err("an input wrong in two ways must still refuse");
    assert!(
        matches!(
            error,
            GitDaemonTransportRefusal::UnsupportedService { service_bytes: 16 }
        ),
        "the service is rejected before the path is parsed, got {error:?}"
    );
}

/// Inside the path chain, `Empty` outranks `NotAbsolute`.
///
/// An empty path is *also* not absolute, so this input qualifies for both and
/// the reported arm is the earlier one.
#[test]
fn an_empty_path_outranks_not_absolute() {
    assert_eq!(
        path_refusal(b""),
        GitDaemonPathRefusal::Empty,
        "an empty path is also not absolute; the empty check runs first"
    );
}

/// `NotAbsolute` outranks every per-component arm.
///
/// A relative path containing `..` qualifies for both, and must report
/// `NotAbsolute` — the component loop is never entered.
#[test]
fn a_relative_path_outranks_a_parent_component() {
    assert_eq!(
        path_refusal(b"a/../b"),
        GitDaemonPathRefusal::NotAbsolute,
        "the absolute check runs before the component loop"
    );
}

/// **Position, not arm order.** With two offending components, the first one in
/// the path wins — probed both ways round.
///
/// The four per-component arms are mutually exclusive within a single
/// component, so their relative order is *not* observable from one component.
/// Running the same pair in both positions is what separates "the loop reports
/// the earliest component" from "`ParentComponent` is checked before
/// `ControlByte`": a result holding for only one ordering would be arm order,
/// and one holding for both is position.
#[test]
fn the_first_offending_component_wins_whichever_fault_comes_first() {
    assert_eq!(
        path_refusal(b"/../\x01"),
        GitDaemonPathRefusal::ParentComponent,
        "the parent component comes first in the path"
    );
    assert_eq!(
        path_refusal(b"/\x01/.."),
        GitDaemonPathRefusal::ControlByte,
        "the control byte comes first in the path"
    );
}

/// The duplicate scan runs inside the parameter loop, before the unsupported
/// check that follows it: two `version=` parameters report the duplicate.
#[test]
fn a_duplicate_version_outranks_an_unsupported_one() {
    let error = parse(&frame(b"git-upload-pack /repo\0version=2\0version=3\0"))
        .expect_err("an input wrong in two ways must still refuse");
    assert!(
        matches!(error, GitDaemonTransportRefusal::DuplicateProtocolVersion),
        "the duplicate is detected in the loop, before the unsupported check after it, got {error:?}"
    );
}
