#![forbid(unsafe_code)]
//! FG-019c: bomb packs through the *push path* — do a receive session's
//! configured pack bounds actually reach the pack reader?
//!
//! Independent adversary over ProudJaguar's `fgit-wire`. Nothing here modifies
//! `crates/fgit-wire/src/**`; every probe drives the public API.
//!
//! ## The gap this closes, and why it falls between two owners
//!
//! `fgit-pack` already proves its own bomb defences: `bombs_reader.rs`,
//! `bombs_resolver.rs`, and the `pack_bombs.sh` lane all pass `PackLimits`
//! **directly** to the reader and assert it refuses. `receivepack_adversarial.rs`
//! proves the receive machine's own quarantine ceiling. Neither asks the
//! composition question:
//!
//! > when a pack arrives through `push_bytes`, is it validated against **this
//! > session's** limits, or against something else?
//!
//! That question has a failure mode neither owner's suite can see. If
//! `finish_with_handoff` validated with `PackLimits::default()` instead of
//! `self.context.limits.pack`, every bomb test in `fgit-pack` would stay green,
//! the quarantine ceiling test would stay green, and every session-level bound
//! an operator configured would be **silently ignored** on the only path that
//! matters — the one an untrusted client actually pushes through. A bound that
//! is not consulted is not a bound.
//!
//! ## How the probes isolate propagation, and nothing else
//!
//! Each probe feeds **the same pack bytes twice**, changing only one field of
//! `ReceiveLimits::pack` between the two runs:
//!
//! * tightened past what the pack needs → must be refused, with the reader's
//!   own typed error naming the configured limit;
//! * left permissive → the identical bytes must be **accepted**.
//!
//! Same input, one variable. A machine that ignored its configured limits would
//! accept both and fail the refusal half; a machine that refused everything
//! would fail the acceptance half. Neither half is load-bearing alone, which is
//! why both run over one `pack_bytes` binding rather than two constructions
//! that could quietly drift apart.
//!
//! The packs are **real**: planned and written by `fgit-pack`'s own
//! `PackPlanner`/`PackWriter` over genuine Git blob objects identified with
//! `native_object_oid`. A hand-assembled byte string could be refused for being
//! malformed while the test reported it as refused for exceeding a bound, which
//! would invert the finding.
//!
//! ## Non-claims
//!
//! * This is about **plumbing**, not about the bounds themselves. That
//!   `max_entries` correctly stops a runaway entry count is `fgit-pack`'s claim
//!   and is not re-litigated here; what is asserted is only that the value the
//!   session was configured with is the value that decided.
//! * **Three** bounds are probed, not all eleven `PackLimits` fields. A field
//!   not listed in [`PROBES`] is not covered, and this file must not be cited
//!   as evidence that every limit propagates. The three were chosen because
//!   each is reachable with a small real pack; the delta and inflate-work
//!   bounds need a crafted delta chain and are left to whoever builds one.
//! * Nothing here is differential evidence against upstream Git.

use std::collections::BTreeMap;

use fgit_git_object::{ObjectType, Sha1, native_object_oid};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, ObjectFormat, ObjectId, PackError, PackLimits,
    PackPlanner, PackWriteError, PackWriteProfile, PackWriter,
};
use fgit_wire::receive::{
    ReceiveCancellation, ReceiveCompletion, ReceiveContext, ReceiveError, ReceiveLimits,
    ReceivePack, ReceivePhase, ReceiveQuarantineHandoff, ReceiveRequest, SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const ZERO: &str = "0000000000000000000000000000000000000000";
const NEW: &str = "1111111111111111111111111111111111111111";

/// Body size of each blob in the probe corpus.
///
/// Large enough that an object-size bound can be set below it without colliding
/// with pack framing overhead, small enough to stay a unit test.
const BLOB_BYTES: usize = 512;

/// How many blobs the probe pack carries.
const BLOB_COUNT: usize = 3;

// ---------------------------------------------------------------------------
// A real pack, built by the writer that owns pack construction
// ---------------------------------------------------------------------------

/// A `CanonicalObjectSource` over a handful of standalone blobs.
///
/// Blobs reference nothing, so the planned closure is exactly the roots — which
/// keeps the entry count of the probe pack a fact of this fixture rather than
/// something the planner might expand.
struct BlobSource {
    objects: BTreeMap<ObjectId, (Vec<u8>, u64)>,
}

impl CanonicalObjectSource for BlobSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        let (body, recency) = self
            .objects
            .get(id)
            .unwrap_or_else(|| panic!("probe corpus is missing an object it referenced: {id:?}"));
        Ok(CanonicalPackObject::new(
            *id,
            ObjectType::Blob,
            body.clone(),
            Vec::new(),
            *recency,
            // A stable function of identity, never of iteration order.
            u64::from(id.as_bytes().first().copied().unwrap_or(0)),
        ))
    }
}

/// Builds a genuine pack carrying [`BLOB_COUNT`] distinct blobs.
///
/// Planned and written with **default** limits deliberately: the pack must be
/// one that a default-configured reader accepts, so that any refusal observed
/// below is attributable to the session limit under test and not to the pack.
fn probe_pack() -> Vec<u8> {
    let mut objects = BTreeMap::new();
    let mut roots = Vec::new();
    for index in 0..BLOB_COUNT {
        // Distinct content per blob, so the three are three objects rather than
        // one object counted three times.
        let body = vec![b'a' + u8::try_from(index).expect("small index"); BLOB_BYTES];
        let id = ObjectId::from(native_object_oid::<Sha1>(ObjectType::Blob, &body));
        let recency = u64::try_from(index).expect("small index");
        objects.insert(id, (body, recency));
        roots.push(id);
    }

    let source = BlobSource { objects };
    let planner = PackPlanner::new(
        ObjectFormat::Sha1,
        PackWriteProfile::STORED_V1,
        PackLimits::default(),
    );
    let mut deadline = || true;
    let plan = planner
        .plan(&source, &roots, &mut deadline)
        .unwrap_or_else(|error| panic!("planning the probe pack failed: {error:?}"));
    assert_eq!(
        plan.entries().len(),
        BLOB_COUNT,
        "the probe pack must carry exactly the blobs the bounds are set against"
    );

    let writer = PackWriter::new(PackLimits::default());
    let mut deadline = || true;
    let (bytes, _receipt) = writer
        .write(&plan, &mut deadline)
        .unwrap_or_else(|error| panic!("writing the probe pack failed: {error:?}"));
    bytes
}

// ---------------------------------------------------------------------------
// Driving one push
// ---------------------------------------------------------------------------

#[derive(Default)]
struct AcceptingHandoff {
    saw_pack: bool,
    entries: usize,
}

impl ReceiveQuarantineHandoff for AcceptingHandoff {
    fn handoff(
        &mut self,
        _request: &ReceiveRequest,
        pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &fgit_wire::receive::QuarantineReceipt,
    ) -> Result<(), ReceiveError> {
        self.saw_pack = pack.is_some();
        self.entries = pack.map_or(0, |pack| pack.entries().len());
        Ok(())
    }
}

struct NeverCancels;

impl ReceiveCancellation for NeverCancels {
    fn checkpoint(&mut self) -> bool {
        true
    }
}

fn context_with(limits: ReceiveLimits) -> ReceiveContext {
    ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(b"delete-refs report-status", &WireLimits::default())
            .expect("fixture capabilities"),
        limits,
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

/// The outcome of one complete push, including where the machine ended up.
struct PushOutcome {
    result: Result<ReceiveCompletion, ReceiveError>,
    phase: ReceivePhase,
    quarantine_len: usize,
    handoff: AcceptingHandoff,
}

/// Pushes `pack` through a session configured with `limits`.
///
/// The pack is delivered in chunks so a bound that fires during buffering is
/// reached the same way a real client would reach it, rather than in one write
/// the machine could special-case.
fn push(pack: &[u8], limits: ReceiveLimits) -> PushOutcome {
    let mut machine = ReceivePack::new(context_with(limits)).expect("machine");
    machine
        .push_packet(command(ZERO, NEW, "refs/heads/main", Some("report-status")))
        .expect("create command");
    machine.push_packet(Packet::Flush).expect("command flush");

    let mut buffering = None;
    for chunk in pack.chunks(64) {
        if let Err(error) = machine.push_bytes(chunk) {
            buffering = Some(error);
            break;
        }
    }

    let mut handoff = AcceptingHandoff::default();
    let mut cancellation = NeverCancels;
    let result = match buffering {
        Some(error) => Err(error),
        None => machine.finish_with_handoff(&mut handoff, &mut cancellation),
    };

    PushOutcome {
        result,
        phase: machine.phase(),
        quarantine_len: machine.quarantine_len(),
        handoff,
    }
}

/// The pack error a refusal carried, or `None` if it refused for another reason.
fn pack_error(outcome: &PushOutcome) -> Option<&PackError> {
    match &outcome.result {
        Err(ReceiveError::Pack(error)) => Some(error),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// One bound at a time, same bytes, opposite outcomes
// ---------------------------------------------------------------------------

/// One propagation probe: a bound, how to tighten it past the probe pack, and
/// the reader error that must name it.
struct Probe {
    name: &'static str,
    tighten: fn(&mut PackLimits),
    /// Whether the refusal carried the error this bound is supposed to raise,
    /// *and* whether that error reports the configured value.
    names_the_limit: fn(&PackError) -> bool,
}

/// The bounds probed. A field absent here is **not** covered by this file.
const PROBES: &[Probe] = &[
    Probe {
        name: "max_entries",
        tighten: |limits| limits.max_entries = 1,
        names_the_limit: |error| matches!(error, PackError::EntryCountLimit { limit: 1, .. }),
    },
    Probe {
        name: "max_object_bytes",
        tighten: |limits| limits.max_object_bytes = BLOB_BYTES / 2,
        names_the_limit: |error| matches!(error, PackError::ObjectSizeLimit { limit, .. } if *limit == BLOB_BYTES / 2),
    },
    Probe {
        name: "max_total_expanded_bytes",
        tighten: |limits| limits.max_total_expanded_bytes = BLOB_BYTES,
        names_the_limit: |error| matches!(error, PackError::TotalExpandedLimit { limit, .. } if *limit == BLOB_BYTES),
    },
];

/// A pack that a permissively configured session accepts is refused by a
/// session whose own bound was tightened past it — and the refusal names the
/// configured value.
///
/// This is the whole point of the file: the only difference between the two
/// runs is one field of `ReceiveLimits::pack`, so an accept in the tightened
/// run would mean the session's configuration never reached the reader.
#[test]
fn a_tightened_session_bound_refuses_the_very_pack_a_permissive_one_accepts() {
    let pack = probe_pack();

    for probe in PROBES {
        // The permitted twin first, so a probe that could never be accepted at
        // all is caught before its refusal is credited to the bound.
        let permissive = push(&pack, ReceiveLimits::default());
        let accepted = permissive.result.as_ref().unwrap_or_else(|error| {
            panic!(
                "{}: the probe pack must be accepted under default limits, got {error:?}",
                probe.name
            )
        });
        let _ = accepted;
        assert!(
            permissive.handoff.saw_pack,
            "{}: a permissive session must hand the pack over",
            probe.name
        );
        assert_eq!(
            permissive.handoff.entries, BLOB_COUNT,
            "{}: the permissive run handed over {} entries, so the corpus is not what the bounds are set against",
            probe.name, permissive.handoff.entries
        );

        // The same bytes, one field tightened.
        let mut limits = ReceiveLimits::default();
        (probe.tighten)(&mut limits.pack);
        let tightened = push(&pack, limits);

        let error = pack_error(&tightened).unwrap_or_else(|| {
            panic!(
                "{}: tightening the session bound must produce a typed pack refusal, got {:?}",
                probe.name, tightened.result
            )
        });
        assert!(
            (probe.names_the_limit)(error),
            "{}: refused, but not with the configured bound — got {error:?}. A refusal that \
             names a different limit means the reader used its own value, not the session's",
            probe.name
        );
        assert!(
            !tightened.handoff.saw_pack,
            "{}: refused the pack but still handed it to the quarantine consumer",
            probe.name
        );
        assert_eq!(
            tightened.quarantine_len, 0,
            "{}: refused the pack but retained {} quarantine bytes",
            probe.name, tightened.quarantine_len
        );
        assert_eq!(
            tightened.phase,
            ReceivePhase::Refused,
            "{}: a refused push must end in Refused",
            probe.name
        );
    }
}

/// Every probed bound is refused by a *different* error.
///
/// Without this, three bounds could all be firing one generic check — and the
/// test above would pass while proving only that *something* refuses. Distinct
/// discriminants are what show each configured field is separately consulted.
#[test]
fn each_probed_bound_is_refused_on_its_own_terms() {
    let pack = probe_pack();
    let mut discriminants = Vec::new();

    for probe in PROBES {
        let mut limits = ReceiveLimits::default();
        (probe.tighten)(&mut limits.pack);
        let outcome = push(&pack, limits);
        let error = pack_error(&outcome)
            .unwrap_or_else(|| panic!("{}: expected a typed pack refusal", probe.name));
        discriminants.push(std::mem::discriminant(error));
    }

    for (left, probe) in PROBES.iter().enumerate() {
        for right in (left + 1)..PROBES.len() {
            assert_ne!(
                discriminants[left], discriminants[right],
                "{} and {} refuse with the same error, so they are not separately consulted",
                probe.name, PROBES[right].name
            );
        }
    }
}

/// The corpus is non-degenerate: the probe pack really does carry more than one
/// entry and more than one byte per object.
///
/// A pack with one tiny blob would make `max_entries = 1` and a halved
/// `max_object_bytes` unreachable, and every refusal above would be an artefact
/// of an empty corpus rather than of a bound. Asserted rather than assumed
/// because the corpus is generated.
#[test]
fn the_probe_pack_is_large_enough_for_every_bound_to_be_reachable() {
    let pack = probe_pack();
    let outcome = push(&pack, ReceiveLimits::default());
    outcome
        .result
        .as_ref()
        .expect("the probe pack must be accepted under default limits");

    assert_eq!(
        outcome.handoff.entries, BLOB_COUNT,
        "the probe pack carries {} entries, not the {BLOB_COUNT} the bounds assume",
        outcome.handoff.entries
    );
    assert!(
        BLOB_COUNT > 1,
        "max_entries = 1 is only a tightening if the pack has more than one entry"
    );
    assert!(
        BLOB_BYTES / 2 > 0 && BLOB_BYTES > BLOB_BYTES / 2,
        "max_object_bytes must be tightened to a positive value below the blob size"
    );

    // Every probe must actually TIGHTEN against the default it is compared
    // with. If `PackLimits::default()` ever moved down to meet one of these
    // values, that probe would stop being a tightening and its refusal would
    // no longer distinguish "the session's limit decided" from "the default
    // decided" — the exact confusion this file exists to rule out. The suite
    // would keep passing, so the drift is asserted rather than trusted.
    let defaults = PackLimits::default();
    for probe in PROBES {
        let mut tightened = PackLimits::default();
        (probe.tighten)(&mut tightened);
        assert!(
            is_strictly_tighter(&defaults, &tightened),
            "{}: the probe no longer tightens anything against PackLimits::default(), \
             so its refusal would not prove the session's value was consulted",
            probe.name
        );
    }
}

/// Whether `tightened` lowers at least one bound below `defaults` and raises
/// none.
fn is_strictly_tighter(defaults: &PackLimits, tightened: &PackLimits) -> bool {
    let lowered = tightened.max_entries < defaults.max_entries
        || tightened.max_object_bytes < defaults.max_object_bytes
        || tightened.max_total_expanded_bytes < defaults.max_total_expanded_bytes
        || tightened.max_input_bytes < defaults.max_input_bytes;
    let raised = tightened.max_entries > defaults.max_entries
        || tightened.max_object_bytes > defaults.max_object_bytes
        || tightened.max_total_expanded_bytes > defaults.max_total_expanded_bytes
        || tightened.max_input_bytes > defaults.max_input_bytes;
    lowered && !raised
}
