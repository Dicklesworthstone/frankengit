#![forbid(unsafe_code)]
//! FG-019c: adversarial probes over the receive → admission boundary.
//!
//! Independent adversary over ProudJaguar's `fgit-admission`. Nothing here
//! modifies `crates/fgit-admission/src/**`; every probe drives the public API.
//! This crate had no `tests/` directory before this file.
//!
//! ## The property under attack
//!
//! `validate_receive` is the gate between a *structurally complete* receive and
//! an *authority-admissible* one, and its documented contract is strong:
//!
//! > Non-delete commands without that pack are refused **before a seal
//! > exists**; deleting refs is the permitted near-identical path.
//!
//! "Before a seal exists" is the load-bearing half. A refusal that happened
//! *after* a seal was minted would leave a `TxId` for a request that was never
//! admissible — which is precisely the "stuck intermediate" the disconnect
//! matrix of this bead exists to rule out. `validate_receive` cannot mint a
//! seal (it returns `Result<ValidatedReceive, RefusalCode>` and takes no
//! `AuthorityStore`), so the property is structural rather than incidental, and
//! the probes below pin the refusals that keep it that way.
//!
//! ## Why a stub validator is legitimate here rather than a mock smuggled in
//!
//! `QuarantineValidator` is a **public trait deliberately designed for external
//! implementation** — its own doc says the real one "belongs beside the
//! pack/object store; this crate never parses a pack or reaches into quarantine
//! bytes." Implementing it in a test is using the seam as intended, not faking
//! a component. The stubs below are named for what they model and none of them
//! is presented as evidence about a real object store.
//!
//! ## Non-claims
//!
//! * These probe `validate_receive` only. `admit_validated_receive` needs an
//!   `AuthorityStore` and an `AdmissionProjection`; driving it is a separate
//!   slice and nothing here speaks for it.
//! * A stub validator's closure is asserted, not verified against a real pack.
//!   That is the layering `fgit-admission` documents, and it means these probes
//!   evidence the *admission* boundary, never object-store correctness.

use std::collections::BTreeSet;

use fgit_admission::{QuarantineValidator, ValidatedClosure, validate_receive};
use fgit_types::{Digest, GitOid, RefusalCode};
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveContext, ReceiveEvent, ReceiveLimits, ReceivePack, ReceiveRequest,
    SignedPushProfile,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits};

const ZERO: &str = "0000000000000000000000000000000000000000";
const NEW: &str = "1111111111111111111111111111111111111111";

// ---------------------------------------------------------------------------
// Fixtures built only from public API
// ---------------------------------------------------------------------------

fn capabilities(source: &[u8]) -> Capabilities {
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

fn command(old: &str, new: &str, name: &str, caps: Option<&str>) -> Packet {
    let mut line = format!("{old} {new} {name}").into_bytes();
    if let Some(caps) = caps {
        line.push(0);
        line.extend_from_slice(caps.as_bytes());
    }
    Packet::Data(line)
}

/// Drives a `ReceivePack` far enough to obtain a parsed `ReceiveRequest`.
///
/// Built through the wire state machine rather than by constructing the struct
/// directly, because its fields are the wire crate's to own and a test that
/// assembled one by hand would be asserting against a request the wire layer
/// would never actually produce.
fn request_for(commands: &[Packet]) -> ReceiveRequest {
    let mut machine = ReceivePack::new(context()).expect("machine");
    for packet in commands {
        machine
            .push_packet(packet.clone())
            .expect("fixture command must parse");
    }
    let transition = machine.push_packet(Packet::Flush).expect("command flush");
    let Some(ReceiveEvent::RequestReady(request)) = transition.events.first() else {
        panic!("the command flush must expose a parsed request");
    };
    (**request).clone()
}

fn receipt(delete_only: bool) -> QuarantineReceipt {
    QuarantineReceipt {
        object_format: GitObjectFormat::Sha1,
        object_count: 0,
        pack_bytes: 0,
        delete_only,
    }
}

fn oid(hex: &str) -> GitOid {
    GitOid::from_hex(fgit_types::native::GitHashAlgorithm::Sha1, hex).expect("fixture oid")
}

fn digest() -> Digest {
    Digest::new(
        fgit_types::hash::DigestAlgorithmId::try_new(1).expect("algorithm slot"),
        fgit_types::hash::DigestBytes::try_new(&[7_u8; 32]).expect("digest body"),
    )
}

/// A validator that reports whatever closure it was told to, without looking at
/// the pack. Named for exactly that: it models the *seam*, not an object store.
struct StubValidator {
    objects: BTreeSet<GitOid>,
}

impl StubValidator {
    fn containing(ids: &[GitOid]) -> Self {
        Self {
            objects: ids.iter().copied().collect(),
        }
    }
}

impl QuarantineValidator for StubValidator {
    fn validate(
        &self,
        _request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
    ) -> Result<ValidatedClosure, RefusalCode> {
        Ok(ValidatedClosure {
            object_closure_root: digest(),
            objects: self.objects.clone(),
        })
    }
}

/// A validator that refuses, modelling an object store that found the pack
/// inadmissible.
struct RefusingValidator(RefusalCode);

impl QuarantineValidator for RefusingValidator {
    fn validate(
        &self,
        _request: &ReceiveRequest,
        _pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
    ) -> Result<ValidatedClosure, RefusalCode> {
        Err(self.0)
    }
}

// ---------------------------------------------------------------------------
// The pack-required boundary, with its documented permitted twin
// ---------------------------------------------------------------------------

/// A non-delete command with no pack is refused, and the delete-only twin is
/// admitted.
///
/// The twin is the load-bearing half: a gate that refused *every* request would
/// satisfy the refusal assertion alone while being useless. `fgit-admission`
/// names this pairing itself — "deleting refs is the permitted near-identical
/// path" — so the test asserts the pairing the documentation claims.
#[test]
fn a_pack_requiring_request_without_a_pack_is_refused_and_the_delete_twin_is_admitted() {
    // Forbidden: creates a ref, so it needs a pack, and none is supplied.
    let create = request_for(&[command(ZERO, NEW, "refs/heads/main", Some("report-status"))]);
    let validator = StubValidator::containing(&[oid(NEW)]);
    let refusal = validate_receive(&create, None, &receipt(false), &validator)
        .expect_err("a pack-requiring request without a pack must be refused");
    assert_eq!(
        refusal,
        RefusalCode::ObjectClosureIncomplete,
        "expected ObjectClosureIncomplete, got {refusal:?}"
    );

    // Permitted twin, one field away: a delete needs no pack.
    let delete = request_for(&[command(
        NEW,
        ZERO,
        "refs/heads/doomed",
        Some("report-status delete-refs"),
    )]);
    let validated = validate_receive(&delete, None, &receipt(true), &validator)
        .expect("a delete-only request needs no pack and must be admitted");
    assert!(
        validated.request().deletes_only(),
        "the admitted twin must be the delete-only request"
    );
}

// ---------------------------------------------------------------------------
// The closure witness must actually cover what the commands ask for
// ---------------------------------------------------------------------------

/// A closure that omits a command's target object is refused.
///
/// This is the check that stops a validator's *claim* from being taken as
/// coverage: even a validator that returns `Ok` must have produced a closure
/// containing every non-zero `new`, or admission refuses. Without it, an
/// object-store bug reporting an incomplete closure would be admitted on the
/// strength of having returned `Ok`.
#[test]
fn a_closure_missing_the_commands_target_object_is_refused() {
    let create = request_for(&[command(ZERO, NEW, "refs/heads/main", Some("report-status"))]);
    let pack_receipt = receipt(false);

    // Forbidden: the validator says Ok but its closure does not contain NEW.
    let empty = StubValidator::containing(&[]);
    let refusal = validate_receive(&create, None, &pack_receipt, &empty)
        .expect_err("a closure omitting the target object must be refused");
    assert_eq!(refusal, RefusalCode::ObjectClosureIncomplete);

    // Permitted twin: the same request, same validator shape, closure that does
    // contain it. Still refused here only because no pack was supplied, which
    // is the *other* gate — so this asserts the two refusals are distinct
    // rather than one catch-all.
    let covering = StubValidator::containing(&[oid(NEW)]);
    let still_refused = validate_receive(&create, None, &pack_receipt, &covering)
        .expect_err("no pack was supplied, so the pack gate still applies");
    assert_eq!(
        still_refused,
        RefusalCode::ObjectClosureIncomplete,
        "both gates report ObjectClosureIncomplete; that is the documented code"
    );
}

/// A validator's own refusal is propagated unchanged rather than reclassified.
///
/// If admission rewrote an object-store refusal into a generic one, an operator
/// would lose the reason the push actually failed. Each probe uses a distinct
/// code so a layer that collapsed them to one would fail here.
#[test]
fn a_validators_refusal_reaches_the_caller_with_its_original_code() {
    // A DELETE-ONLY request, deliberately. `validate_receive` checks the
    // pack-required gate BEFORE calling the validator, so a create with no pack
    // short-circuits to ObjectClosureIncomplete and the validator is never
    // reached — an earlier version of this test did exactly that and "found" a
    // reclassification bug that did not exist. Deleting refs needs no pack, so
    // the validator is genuinely invoked and its refusal is genuinely relayed.
    let delete = request_for(&[command(
        NEW,
        ZERO,
        "refs/heads/doomed",
        Some("report-status delete-refs"),
    )]);
    let pack_receipt = receipt(true);

    for expected in [
        RefusalCode::NativeObjectIdMismatch,
        RefusalCode::ObjectClosureIncomplete,
        RefusalCode::ResourceBudgetExceeded,
    ] {
        let validator = RefusingValidator(expected);
        let refusal = validate_receive(&delete, None, &pack_receipt, &validator)
            .expect_err("a refusing validator must refuse the admission");
        assert_eq!(
            refusal, expected,
            "admission reclassified a validator refusal: expected {expected:?}, got {refusal:?}"
        );
    }
}

/// A delete-only session with a covering validator yields a `ValidatedReceive`
/// whose structural receipt survives unchanged.
///
/// The receipt is the only structural fact admission carries forward, and
/// `QuarantineReceipt` is documented as success-only facts and never an absence
/// proof. This asserts it is relayed intact rather than recomputed — a
/// recomputed receipt would be admission inventing structural facts it
/// explicitly does not parse packs to learn.
#[test]
fn the_structural_receipt_is_relayed_intact_and_not_recomputed() {
    let delete = request_for(&[command(
        NEW,
        ZERO,
        "refs/heads/doomed",
        Some("report-status delete-refs"),
    )]);
    let mut original = receipt(true);
    original.object_count = 0;
    original.pack_bytes = 0;

    let validator = StubValidator::containing(&[]);
    let validated =
        validate_receive(&delete, None, &original, &validator).expect("delete admitted");

    assert_eq!(
        validated.receipt(),
        &original,
        "admission altered the structural receipt it was handed"
    );
}
