#![forbid(unsafe_code)]
//! Object-id parsing and v2 command dispatch (`frankengit-k7dz`).
//!
//! Four `WireError` variants were named by no test anywhere, measured with an
//! enum-qualified search because other crates carry same-spelled variants and a
//! bare-name grep is noisy here: `DuplicateObjectId`, `InvalidObjectId`,
//! `PackSourceRefused`, `UnsupportedCommand`.
//!
//! Reading the construction sites turned up three findings that are worth more
//! than the coverage that prompted the file.
//!
//! # 1. `UnsupportedCommand` answers two different questions
//!
//! ```text
//! lib.rs:2361  the command name is not in the closed set (ls-refs, fetch)
//! lib.rs:2371  the command IS known, but the server never advertised it
//! ```
//!
//! Both return `UnsupportedCommand { command }`, and the payload carries only
//! the name — so a caller cannot tell *"you asked for something that does not
//! exist"* from *"you asked for something this server did not offer"*. §6 keeps
//! fetch and push as **separate service/capability matrices**; the second case
//! is a capability-matrix answer and the first is a vocabulary answer. Both are
//! probed below, and the collapse is documented rather than assumed. This is a
//! fifth instance of `frankengit-r2an`'s pattern.
//!
//! # 2. One `InvalidObjectId` site cannot fire
//!
//! `parse_object_id` has three:
//!
//! ```text
//! 1211  wrong length, or a byte outside [0-9a-z]   REACHABLE
//! 1215  std::str::from_utf8 fails                  UNREACHABLE
//! 1216  AnyGitOid::from_hex fails                  REACHABLE
//! ```
//!
//! 1215 cannot fire: every byte passing 1211 is ASCII
//! (`is_ascii_digit() || is_ascii_lowercase()`), and ASCII is always valid
//! UTF-8. 1216 *can*, and the reason is exact — the charset guard admits
//! `[0-9a-z]` while hex is `[0-9a-f]`, so an id of the right length made of
//! letters `g`–`z` clears the first guard and is refused by `from_hex`.
//!
//! **And then the mutation corrected me, which is the honest half of this
//! file.** I planted a mutation deleting the charset clause, expecting the
//! probe below to catch it. It did not — 176 tests across 20 binaries stayed
//! green. So I deleted the **entire** first guard, length clause and all:
//! still 176 green.
//!
//! That is not a hole in the corpus. **The pre-check is an equivalent mutant
//! with respect to `WireError`**: all three sites emit
//! `InvalidObjectId { algorithm }` with an identical payload, so *no input can
//! distinguish them* and no test ever could. The guard's value is bounding work
//! — refusing before UTF-8 validation and hex parsing on hostile input — not
//! changing the answer.
//!
//! Two consequences stated plainly. The unreachable site is **reported, not
//! probed**; a defensive guard with a stated reason to exist is a fine thing to
//! keep and a dishonest thing to claim coverage of. And the `g`–`z` case below
//! is a **documented input, not a discriminating probe** — under the real code
//! it does reach 1216, but nothing here can prove which site fired, so it is
//! not claimed to.
//!
//! # 3. `PackSourceRefused` is constructed by nothing
//!
//! Whole-repository search: the enum declaration (`lib.rs:259`) and its
//! `Display` arm (`lib.rs:375`). No third occurrence. Its doc says "The
//! deferred pack source reported a typed refusal", so it is either vocabulary
//! waiting for a producer or a leftover. **No test is manufactured for it** —
//! the null is the deliverable, and this paragraph is it.
//!
//! # Measured mutations
//!
//! ```text
//! M1  the charset clause deleted            176 passed  0 failed   SURVIVED
//! M1b the ENTIRE first guard deleted        176 passed  0 failed   SURVIVED
//! M2  duplicate/limit order swapped         175 passed  1 failed   caught
//! ```
//!
//! M1/M1b are equivalent mutants, established above and reported rather than
//! papered over. M2 changes observable behaviour and is caught by exactly one
//! test — `a_duplicate_at_exactly_the_limit_reports_the_duplicate_not_the_ceiling`
//! — with the other 175 across 20 binaries blind to it.
//!
//! # Non-claims
//!
//! This covers four variants and the findings above. It does not verify the v2
//! command state machine as a whole, and it does not resolve whether
//! `UnsupportedCommand` should be split — that is `r2an`'s question and this
//! file only adds an instance to it. Nothing here modifies
//! `crates/fgit-wire/src/**`.

use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, Packet, UploadPackRepository,
    V2UploadPack, WireError, WireLimits,
};

const TIP: &str = "1111111111111111111111111111111111111111";
const OTHER: &str = "2222222222222222222222222222222222222222";

fn limits() -> WireLimits {
    WireLimits::default()
}

fn oid(hex: &str) -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, hex).expect("fixture oid")
}

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

    /// Both fixture ids are wantable, so a refusal below is never the
    /// repository declining an unknown object instead of the guard under test.
    fn contains_want(&self, target: AnyGitOid) -> bool {
        target == oid(TIP) || target == oid(OTHER)
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

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut framed = format!("{:04x}", payload.len() + 4).into_bytes();
    framed.extend_from_slice(payload);
    framed
}

/// Server capabilities from an explicit v2 advertisement line set.
fn capabilities_from(lines: &[&[u8]]) -> Capabilities {
    let mut packets = vec![Packet::Data(b"version 2\n".to_vec())];
    for line in lines {
        packets.push(Packet::Data((*line).to_vec()));
    }
    packets.push(Packet::Flush);
    Capabilities::parse_v2_advertisement(&packets, &limits())
        .expect("a well-formed server advertisement")
}

/// A server advertising both commands.
fn full_capabilities() -> Capabilities {
    capabilities_from(&[b"ls-refs\n", b"fetch=shallow filter\n"])
}

/// Drive a `command=<name>` transcript carrying `arguments`.
fn command_request(
    capabilities: Capabilities,
    command: &[u8],
    arguments: &[&[u8]],
    wire_limits: WireLimits,
) -> Result<(), WireError> {
    let repository = FetchRepository::new();
    let mut machine = V2UploadPack::new(capabilities, wire_limits).expect("a v2 upload-pack");

    let mut line = b"command=".to_vec();
    line.extend_from_slice(command);
    line.push(b'\n');
    let mut transcript = frame(&line);
    transcript.extend_from_slice(b"0001");
    for argument in arguments {
        let mut argument_line = (*argument).to_vec();
        argument_line.push(b'\n');
        transcript.extend_from_slice(&frame(&argument_line));
    }
    transcript.extend_from_slice(b"0000");

    machine.push_bytes(&transcript, &repository).map(|_| ())
}

/// A `command=fetch` request against a fully-advertising server.
fn fetch(arguments: &[&[u8]], wire_limits: WireLimits) -> Result<(), WireError> {
    command_request(full_capabilities(), b"fetch", arguments, wire_limits)
}

#[track_caller]
fn fetch_refusal(arguments: &[&[u8]], wire_limits: WireLimits, what: &str) -> WireError {
    match fetch(arguments, wire_limits) {
        Ok(()) => panic!("{what} must be refused, but the request was accepted"),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// The permitted direction, first
// ---------------------------------------------------------------------------

/// A well-formed object id parses, and a well-formed fetch is accepted.
///
/// Every refusal below is measured against this. Without it they could be the
/// machine rejecting any fetch at all.
#[test]
fn a_well_formed_request_with_a_valid_object_id_is_accepted() {
    let want = format!("want {TIP}");
    fetch(&[want.as_bytes(), b"done"], limits())
        .expect("a canonical fetch request must be accepted");
}

/// Two DISTINCT object ids are both admitted, so `DuplicateObjectId` below is
/// about repetition and not about the second id being unwelcome.
#[test]
fn two_distinct_object_ids_are_both_admitted() {
    let first = format!("want {TIP}");
    let second = format!("want {OTHER}");
    fetch(&[first.as_bytes(), second.as_bytes(), b"done"], limits())
        .expect("two distinct wants are admissible");
}

// ---------------------------------------------------------------------------
// InvalidObjectId — the two reachable axes
// ---------------------------------------------------------------------------

/// Axis 1: the wrong length.
#[test]
fn an_object_id_of_the_wrong_length_is_refused() {
    for text in ["11111111", &"1".repeat(41)] {
        let want = format!("want {text}");
        let error = fetch_refusal(&[want.as_bytes()], limits(), "a mis-sized object id");
        assert_eq!(
            error,
            WireError::InvalidObjectId {
                algorithm: GitObjectFormat::Sha1
            },
            "an id of {} characters must be refused",
            text.len()
        );
    }
}

/// Axis 1 again, on its other clause: a byte outside `[0-9a-z]`.
///
/// Uppercase is the interesting case — it is valid hex to a human and to many
/// parsers, and is refused here because Git's canonical form is lowercase.
#[test]
fn an_object_id_outside_the_accepted_charset_is_refused() {
    for text in [
        "1111111111111111111111111111111111111111".replace('1', "A"),
        "1111111111111111111111111111111111111111".replace('1', "-"),
    ] {
        let want = format!("want {text}");
        let error = fetch_refusal(&[want.as_bytes()], limits(), "an out-of-charset object id");
        assert_eq!(
            error,
            WireError::InvalidObjectId {
                algorithm: GitObjectFormat::Sha1
            }
        );
    }
}

/// An id that clears the charset guard and is still not hex.
///
/// The charset guard admits `[0-9a-z]` while hex is `[0-9a-f]`, so forty `z`
/// characters clear the first guard and are refused by `from_hex` one line
/// later. **This is a documented input, not a discriminating probe**: the two
/// sites emit an identical variant and payload, so this test cannot prove which
/// one fired, and the mutation matrix in the bead shows the whole pre-check can
/// be deleted with nothing failing. It is here because the `[0-9a-z]` versus
/// `[0-9a-f]` gap is a real and surprising property of this parser that a
/// reader should not have to rediscover.
#[test]
fn an_object_id_that_clears_the_charset_guard_but_is_not_hex_is_refused() {
    let want = format!("want {}", "z".repeat(40));
    let error = fetch_refusal(
        &[want.as_bytes()],
        limits(),
        "a non-hex lowercase object id",
    );
    assert_eq!(
        error,
        WireError::InvalidObjectId {
            algorithm: GitObjectFormat::Sha1
        },
        "letters g through z pass the charset guard and must be caught by from_hex"
    );
}

// ---------------------------------------------------------------------------
// DuplicateObjectId, and its ordering against the limit
// ---------------------------------------------------------------------------

/// The same object id offered twice is refused, naming the field and the id.
#[test]
fn the_same_object_id_offered_twice_is_refused() {
    let want = format!("want {TIP}");
    let error = fetch_refusal(
        &[want.as_bytes(), want.as_bytes()],
        limits(),
        "a repeated want",
    );
    assert_eq!(
        error,
        WireError::DuplicateObjectId {
            field: "want",
            oid: oid(TIP),
        },
        "the refusal names which field repeated and which id"
    );
}

/// **Ordering.** The duplicate check runs before the limit check, so a repeat
/// offered when the set is already full reports the duplicate rather than the
/// ceiling.
///
/// Both halves are needed: the pair below shows the order, where either alone
/// would be satisfied by an arbitrary one.
#[test]
fn a_duplicate_at_exactly_the_limit_reports_the_duplicate_not_the_ceiling() {
    let one_want = WireLimits {
        max_wants: 1,
        ..limits()
    };
    let first = format!("want {TIP}");
    let second = format!("want {OTHER}");

    // A repeat while the set is already at its ceiling: duplicate wins.
    assert_eq!(
        fetch_refusal(
            &[first.as_bytes(), first.as_bytes()],
            one_want.clone(),
            "a repeat at the ceiling"
        ),
        WireError::DuplicateObjectId {
            field: "want",
            oid: oid(TIP),
        }
    );

    // A DISTINCT id at the same ceiling reports the ceiling, so the test above
    // is about order and not about the ceiling being unreachable.
    assert_eq!(
        fetch_refusal(
            &[first.as_bytes(), second.as_bytes()],
            one_want,
            "a second distinct want at the ceiling"
        ),
        WireError::TooManyObjectIds {
            field: "want",
            limit: 1,
        }
    );
}

// ---------------------------------------------------------------------------
// UnsupportedCommand — two sites, two meanings, one variant
// ---------------------------------------------------------------------------

/// **Site 1: a vocabulary answer.** The name is not in the closed set.
#[test]
fn a_command_outside_the_closed_set_is_refused() {
    let error = command_request(full_capabilities(), b"push", &[], limits())
        .expect_err("a command this protocol does not define must be refused");
    assert_eq!(
        error,
        WireError::UnsupportedCommand {
            command: b"push".to_vec(),
        },
        "the refusal echoes the command that was asked for"
    );
}

/// **Site 2: a capability-matrix answer.** The command is known and
/// implemented; this server simply never advertised it.
///
/// Asserted separately, and with the payload, because it is the SAME variant as
/// the case above while meaning something different to whoever is diagnosing:
/// one says the command does not exist, the other says this server did not
/// offer it. A client should retry elsewhere in the second case and never in
/// the first.
#[test]
fn a_known_command_the_server_did_not_advertise_is_refused_the_same_way() {
    let ls_refs_only = capabilities_from(&[b"ls-refs\n"]);
    let error = command_request(ls_refs_only, b"fetch", &[], limits())
        .expect_err("an unadvertised command must be refused");
    assert_eq!(
        error,
        WireError::UnsupportedCommand {
            command: b"fetch".to_vec(),
        },
        "the refusal echoes the command, which is the only discriminator it carries"
    );
}

/// The two sites are shown to be indistinguishable by anything but the name.
///
/// This is the finding, asserted rather than described: a caller matching on
/// the variant learns only *which command*, never *which question was answered*.
/// If `UnsupportedCommand` is ever split, this test is what will fail and say
/// so.
#[test]
fn the_two_unsupported_command_sites_differ_only_in_the_name_they_echo() {
    let undefined = command_request(full_capabilities(), b"push", &[], limits())
        .expect_err("an undefined command refuses");
    let unadvertised = command_request(capabilities_from(&[b"ls-refs\n"]), b"fetch", &[], limits())
        .expect_err("an unadvertised command refuses");

    match (&undefined, &unadvertised) {
        (
            WireError::UnsupportedCommand { command: first },
            WireError::UnsupportedCommand { command: second },
        ) => {
            assert_ne!(
                first, second,
                "the echoed name is the only thing separating the two conditions"
            );
        }
        other => panic!("both sites must report UnsupportedCommand today, got {other:?}"),
    }
}
