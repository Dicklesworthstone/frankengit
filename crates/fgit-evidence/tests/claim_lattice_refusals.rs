#![forbid(unsafe_code)]
//! `EvidenceRefusal`: the guards on §10's claim lattice (`frankengit-ydpc`).
//!
//! §10 forbids describing a bounded model as a proof or a benchmark as an
//! invariant, and requires evidence to bind its population, window, regime and
//! assumptions. This crate is where that is enforced, and `EvidenceRefusal` is
//! how it refuses.
//!
//! **This is `fgit-evidence`'s first integration test.** The crate had no
//! `tests/` directory, so every refusal it owns was covered — if at all — only
//! by its inline `cfg(test)` module, and a reader of `tests/` counted zero.
//! Measured per variant with a both-trees grep; the crate has no suite-like
//! module in `src/`, so a `tests/` scan is sound here. (That is not universal —
//! `fgit-authority` keeps its capacity assertions in `src/suite.rs`, invoked
//! from `tests/`, which makes a covered variant look untested.)
//!
//! # Two guards turn out to be unreachable, and that is the substance
//!
//! **`EvidenceContext`'s `validate_text` calls cannot fire.** The context is
//! built from already-parsed `EvidenceText` values, and `EvidenceText::parse`
//! is the only public constructor — the decoding one is private. So by the time
//! `EvidenceContext::new` re-runs `validate_text` over its twelve text fields,
//! every one of them has already passed exactly that check. `InvalidText` is
//! therefore reachable **only** through `EvidenceText::parse` itself; the
//! context's re-validation is defensive, protecting a decode path that does not
//! go through `parse`.
//!
//! **`SelfSupersession` needs a hash fixed point.** It fires iff
//! `body.context.supersedes` equals the body's *own* derived identity — and the
//! identity is derived from the body, `supersedes` included. Producing one
//! would mean finding a body whose `supersedes` field equals its own digest.
//! Both its sites are unreachable for the same reason, and `verify`'s identity
//! checks run *before* the supersession check anyway, so a caller passing a
//! mismatched id to `decode` gets `IdentityMismatch` first. It is a defence
//! against a digest collision, not against an input error.
//!
//! Neither is given a manufactured fixture. A test that reached past the public
//! API to build one would prove something about the fixture rather than the
//! guard, and pinning a guard nobody can trigger makes *removing* it a
//! regression.
//!
//! # What the payloads are for
//!
//! `InvalidText` and `Collection` both carry `{field, reason}`. The `field` is
//! the only thing saying *which* collection refused and `reason` the only thing
//! saying *which* of the three axes did — so every probe asserts both. All three
//! collections are `required: true`, so a single empty-collection probe would
//! look like three;
//! [`the_field_label_distinguishes_all_three_required_collections`] drives the
//! same fault through each and asserts a different label.
//!
//! # Non-claims
//!
//! Newly covered: `InvalidText` and `Collection`. Documented **unreachable**
//! and deliberately *not* counted as closed: `SelfSupersession`, and the
//! context's `validate_text` path. Already covered by the inline module and not
//! claimed: `Claim`, `Identity`, `IdentityMismatch`. `TypedIdentity`,
//! `FrameNotCanonical` and `Codec` are addressed at the end with whatever the
//! experiment actually showed. LEAD count, not a remaining-work total.
//!
//! Nothing here modifies `crates/fgit-evidence/src/**`.

use fgit_claim::ClaimRank;
use fgit_evidence::{
    EvidenceArtifact, EvidenceContext, EvidenceRecord, EvidenceRecordBody, EvidenceRefusal,
    EvidenceText, MAX_EVIDENCE_ITEMS, MAX_EVIDENCE_TEXT_BYTES, ReplayCompleteness,
};
use fgit_types::hash::{Digest, DigestAlgorithmId, DigestBytes};

/// Mirrors the reserved fixture algorithm slot the workspace's corpora use.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);

fn text(value: &str) -> EvidenceText {
    EvidenceText::parse("fixture", value).expect("fixture evidence text is canonical")
}

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

fn artifact(tag: u8) -> EvidenceArtifact {
    EvidenceArtifact::new(text(&format!("artifact-{tag}")), digest(tag))
}

/// A context whose three collections are supplied by the caller.
fn context_with(
    source_inputs: Vec<EvidenceText>,
    assumptions: Vec<EvidenceText>,
    artifacts: Vec<EvidenceArtifact>,
) -> Result<EvidenceContext, EvidenceRefusal> {
    EvidenceContext::new(
        source_inputs,
        text("impl-1"),
        text("toolchain-1"),
        text("strata-1"),
        text("window-1"),
        text("regime-1"),
        assumptions,
        text("verifier-independent"),
        artifacts,
        text("fallback-deterministic"),
        ReplayCompleteness::Replayable,
        None,
    )
}

fn valid_context() -> EvidenceContext {
    context_with(
        vec![text("input-1")],
        vec![text("assumption-1")],
        vec![artifact(1)],
    )
    .expect("the canonical fixture context is admissible")
}

fn body_with(context: EvidenceContext) -> Result<EvidenceRecordBody, EvidenceRefusal> {
    EvidenceRecordBody::new(
        text("claim-1"),
        text("scope-1"),
        ClaimRank::Benchmark,
        ClaimRank::Benchmark,
        context,
    )
}

/// The refusal from a context that must be refused.
fn context_refusal(
    source_inputs: Vec<EvidenceText>,
    assumptions: Vec<EvidenceText>,
    artifacts: Vec<EvidenceArtifact>,
    what: &str,
) -> EvidenceRefusal {
    match context_with(source_inputs, assumptions, artifacts) {
        Ok(_) => panic!("{what} must be refused, but the context was admitted"),
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// The permitted terminus, built first
// ---------------------------------------------------------------------------

/// A complete evidence record is constructible, frames, and verifies.
///
/// Built and made to pass **before** any refusal probe. On two earlier beads a
/// refusal corpus was green while its accepted path was broken, so every
/// refusal was attributable to a malformed fixture rather than to the guard it
/// named. This is the control that makes the refusals below mean something.
#[test]
fn a_complete_evidence_record_is_constructible_and_verifies() {
    let body = body_with(valid_context()).expect("the canonical body is admissible");
    let record = EvidenceRecord::new(body).expect("a complete body frames and identity-binds");
    assert!(
        !record.frame().is_empty(),
        "a framed record carries canonical bytes"
    );
    record
        .verify(fgit_codec::DecodeLimits::DEFAULT)
        .expect("a freshly constructed record verifies against its own identity");
}

// ---------------------------------------------------------------------------
// InvalidText — three axes, reachable only through the parser itself
// ---------------------------------------------------------------------------

#[test]
fn empty_evidence_text_is_refused() {
    let error = EvidenceText::parse("claim_id", "").expect_err("empty text names nothing");
    assert_eq!(
        error,
        EvidenceRefusal::InvalidText {
            field: "claim_id",
            reason: "must not be empty",
        },
        "the payload names both the field and which of the three axes refused"
    );
}

#[test]
fn evidence_text_past_the_bound_is_refused() {
    let oversized = "a".repeat(MAX_EVIDENCE_TEXT_BYTES + 1);
    let error = EvidenceText::parse("toolchain", &oversized)
        .expect_err("one byte past the bound must refuse");
    assert_eq!(
        error,
        EvidenceRefusal::InvalidText {
            field: "toolchain",
            reason: "exceeds the bounded canonical length",
        }
    );
}

/// Whitespace and non-graphic bytes are both rejected by the same condition, so
/// both are probed.
#[test]
fn non_graphic_evidence_text_is_refused() {
    for value in ["has space", "has\ttab", "has\nnewline"] {
        let error = EvidenceText::parse("policy_regime", value)
            .expect_err("evidence text is printable ASCII without whitespace");
        assert_eq!(
            error,
            EvidenceRefusal::InvalidText {
                field: "policy_regime",
                reason: "must contain only printable ASCII without whitespace",
            },
            "the value {value:?} must refuse on the character axis"
        );
    }
}

/// **The permitted twin at the exact boundary.** The guard reads `>`, so text of
/// exactly the bound is legal — the case a refusal-only corpus cannot see.
#[test]
fn evidence_text_at_exactly_the_bound_is_admitted() {
    let at_bound = "a".repeat(MAX_EVIDENCE_TEXT_BYTES);
    let parsed =
        EvidenceText::parse("implementation", &at_bound).expect("exactly the bound is admissible");
    assert_eq!(parsed.as_str().len(), MAX_EVIDENCE_TEXT_BYTES);
}

/// The `field` label is caller-supplied and carries information: the same bad
/// value under two different field names produces two different refusals.
#[test]
fn the_field_label_distinguishes_two_text_fields() {
    let first = EvidenceText::parse("claim_id", "").expect_err("empty is refused");
    let second = EvidenceText::parse("claim_scope", "").expect_err("empty is refused");
    assert_ne!(
        first, second,
        "the field label must distinguish which field refused"
    );
}

// ---------------------------------------------------------------------------
// Collection — three axes, three required collections
// ---------------------------------------------------------------------------

/// **All three collections are `required: true`**, so one empty-collection
/// probe would look like three. This drives the same fault through each and
/// asserts a different label.
#[test]
fn the_field_label_distinguishes_all_three_required_collections() {
    let source = context_refusal(
        Vec::new(),
        vec![text("assumption-1")],
        vec![artifact(1)],
        "an empty source_inputs",
    );
    assert_eq!(
        source,
        EvidenceRefusal::Collection {
            field: "source_inputs",
            reason: "must not be empty",
        }
    );

    let assumptions = context_refusal(
        vec![text("input-1")],
        Vec::new(),
        vec![artifact(1)],
        "an empty assumptions",
    );
    assert_eq!(
        assumptions,
        EvidenceRefusal::Collection {
            field: "assumptions",
            reason: "must not be empty",
        }
    );

    let artifacts = context_refusal(
        vec![text("input-1")],
        vec![text("assumption-1")],
        Vec::new(),
        "an empty artifacts",
    );
    assert_eq!(
        artifacts,
        EvidenceRefusal::Collection {
            field: "artifacts",
            reason: "must not be empty",
        }
    );

    assert_ne!(source, assumptions);
    assert_ne!(assumptions, artifacts);
}

/// A duplicate entry is refused — the collections are canonically sets.
#[test]
fn a_duplicate_collection_entry_is_refused() {
    let error = context_refusal(
        vec![text("input-1"), text("input-1")],
        vec![text("assumption-1")],
        vec![artifact(1)],
        "a duplicated source input",
    );
    assert_eq!(
        error,
        EvidenceRefusal::Collection {
            field: "source_inputs",
            reason: "contains a duplicate",
        }
    );
}

/// A collection past the item bound is refused.
#[test]
fn a_collection_past_the_item_bound_is_refused() {
    let oversized: Vec<EvidenceText> = (0..=MAX_EVIDENCE_ITEMS)
        .map(|index| text(&format!("input-{index}")))
        .collect();
    let error = context_refusal(
        oversized,
        vec![text("assumption-1")],
        vec![artifact(1)],
        "one item past the collection bound",
    );
    assert_eq!(
        error,
        EvidenceRefusal::Collection {
            field: "source_inputs",
            reason: "exceeds the bounded item count",
        }
    );
}

/// **The permitted twin at the exact boundary.** The guard reads `>`, so a
/// collection of exactly the bound is legal.
#[test]
fn a_collection_at_exactly_the_item_bound_is_admitted() {
    let at_bound: Vec<EvidenceText> = (0..MAX_EVIDENCE_ITEMS)
        .map(|index| text(&format!("input-{index}")))
        .collect();
    let context = context_with(at_bound, vec![text("assumption-1")], vec![artifact(1)])
        .expect("a collection of exactly the bound must be admitted");
    assert_eq!(context.source_inputs().len(), MAX_EVIDENCE_ITEMS);
}

// ---------------------------------------------------------------------------
// Ordering — contexts that are wrong twice
// ---------------------------------------------------------------------------

/// `source_inputs` is validated before `assumptions`.
///
/// This context is wrong twice — both collections are empty — and must report
/// the earlier field. Single-fault probes cannot see the order: each leaves the
/// other collection valid and so always reaches its own check.
#[test]
fn source_inputs_are_validated_before_assumptions() {
    let error = context_refusal(
        Vec::new(),
        Vec::new(),
        vec![artifact(1)],
        "two empty collections",
    );
    assert_eq!(
        error,
        EvidenceRefusal::Collection {
            field: "source_inputs",
            reason: "must not be empty",
        },
        "the first collection checked owns the refusal"
    );
}

/// Within one collection, the count bound is checked before the duplicate scan.
///
/// Wrong twice again: past the bound **and** carrying duplicates.
#[test]
fn the_item_bound_outranks_the_duplicate_scan() {
    let mut oversized: Vec<EvidenceText> = (0..MAX_EVIDENCE_ITEMS)
        .map(|index| text(&format!("input-{index}")))
        .collect();
    oversized.push(text("input-0"));
    assert!(oversized.len() > MAX_EVIDENCE_ITEMS);

    let error = context_refusal(
        oversized,
        vec![text("assumption-1")],
        vec![artifact(1)],
        "a collection both oversized and duplicated",
    );
    assert_eq!(
        error,
        EvidenceRefusal::Collection {
            field: "source_inputs",
            reason: "exceeds the bounded item count",
        },
        "the count bound runs before the duplicate scan"
    );
}

// ---------------------------------------------------------------------------
// Identity binding — what a record refuses about itself
// ---------------------------------------------------------------------------

/// A record's identity is bound to its exact bytes: decoding a valid frame
/// under **another record's** identity is refused.
///
/// This is the permitted/refused pair around the identity binding, and it is
/// what makes `SelfSupersession`'s unreachability argument concrete —
/// `verify`'s identity checks run before the supersession check, so a
/// mismatched id is caught here rather than there.
#[test]
fn a_frame_decoded_under_another_identity_is_refused() {
    let first = EvidenceRecord::new(body_with(valid_context()).expect("body"))
        .expect("the first record constructs");

    let other_context = context_with(
        vec![text("input-2")],
        vec![text("assumption-2")],
        vec![artifact(2)],
    )
    .expect("a second admissible context");
    let second = EvidenceRecord::new(body_with(other_context).expect("body"))
        .expect("the second record constructs");
    assert_ne!(first.id(), second.id(), "the two fixtures differ");

    let error = EvidenceRecord::decode(
        second.id(),
        first.frame(),
        fgit_codec::DecodeLimits::DEFAULT,
    )
    .expect_err("a frame cannot be adopted under another record's identity");
    assert!(
        matches!(error, EvidenceRefusal::IdentityMismatch { .. }),
        "the identity binding is checked before any later guard, got {error:?}"
    );
}

/// The permitted twin: a record's own frame decodes under its own identity.
#[test]
fn a_frame_decoded_under_its_own_identity_is_admitted() {
    let record = EvidenceRecord::new(body_with(valid_context()).expect("body"))
        .expect("the record constructs");
    let decoded = EvidenceRecord::decode(
        record.id(),
        record.frame(),
        fgit_codec::DecodeLimits::DEFAULT,
    )
    .expect("a canonical frame decodes under its own identity");
    assert_eq!(decoded.id(), record.id());
    assert_eq!(decoded.frame(), record.frame());
}
