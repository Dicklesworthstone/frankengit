#![forbid(unsafe_code)]
//! §10's claim lattice, as tests (`frankengit-yufm`).
//!
//! **This crate had no `tests/` directory and no inline `cfg(test)` module.**
//! All three `ClaimRefusal` variants were named by nothing, anywhere — measured
//! per variant across both trees. 397 lines of `src`, two public entry points,
//! and it is the crate that decides whether one class of evidence may support a
//! claim of another class.
//!
//! # The constitution's own two examples are literally these two calls
//!
//! §10 says, in these words: *do not describe a proposal as implemented, a
//! local test as differential, a **bounded model as a proof**, or a
//! **benchmark as an invariant***.
//!
//! That last pair is not a metaphor here. `ClaimRank` is a closed order —
//! `Benchmark`, `Slo`, `Statistical`, `BoundedModel`, `Proof`, `Invariant` —
//! and `justifies` compares it, so the two examples are exactly:
//!
//! ```text
//! validate_justification(claim: Invariant, evidence: Benchmark)     must refuse
//! validate_justification(claim: Proof,     evidence: BoundedModel)  must refuse
//! ```
//!
//! Both are pinned below, asserting the refusal carries **both** ranks — a bare
//! variant match could not tell the two cases apart, and "which claim, on what
//! evidence" is the whole content of the complaint.
//!
//! # The order has to be tested in the permitted direction too
//!
//! `justifies` reads `>=`, so:
//!
//! - **equal ranks are admitted** — the boundary the rule turns on, and the one
//!   a refusal-only corpus cannot see;
//! - **stronger evidence justifies a weaker claim** — a proof may support a
//!   benchmark claim. A lattice that refused *that* would be wrong in the
//!   opposite direction, and no refusal probe anywhere would notice.
//!
//! The mutation recorded in the bead targets precisely this: tightening `>=` to
//! `>` wrongly refuses equal ranks. **Every refusal probe in this file stayed
//! green**; three tests fell and all three were accepted-path cases — the two
//! permitted-direction tests here, and `strongest_rank_justifies_every_closed_rank`
//! in the crate's own inline module, which happens to include an equal-rank
//! pairing.
//!
//! Measured rather than predicted, and it corrected me twice. I expected one
//! test to fall, not two, and I expected the inline module to be blind. It is
//! not — this is the **second** crate today where an inline `cfg(test)` module
//! caught a mutation that every `tests/` refusal probe missed, so "the existing
//! suites are blind" is a per-crate measurement rather than a rule. `2gzj`
//! measured the same loosened/tightened asymmetry on a different crate.
//!
//! # Non-claims
//!
//! Three variants is the **whole** enum, so `ClaimRefusal` is now fully named
//! from `tests/`. That is **not** the same as the claim-lattice behaviour being
//! fully verified: the registries, the claim-class rules in
//! `docs/`, and every caller's decision about which rank its evidence deserves
//! are separate questions this file says nothing about. LEAD count, not a
//! remaining-work total.
//!
//! Nothing here modifies `crates/fgit-claim/src/**`.

use fgit_claim::{
    ClaimRank, ClaimRefusal, ClaimText, MAX_CLAIM_TEXT_BYTES, validate_justification,
};

// ---------------------------------------------------------------------------
// The permitted directions, built first
// ---------------------------------------------------------------------------

/// **The boundary the rule turns on.** Equal ranks justify each other.
///
/// `justifies` reads `>=`. Built and made to pass before any refusal probe.
/// Tightening that comparison to `>` fails this test and the one below, while
/// every refusal probe in this file stays green.
#[test]
fn evidence_of_equal_rank_justifies_a_claim() {
    for rank in ClaimRank::ALL {
        validate_justification(rank, rank).unwrap_or_else(|error| {
            panic!("{rank:?} evidence must justify a {rank:?} claim, got {error:?}")
        });
    }
}

/// Stronger evidence justifies a weaker claim.
///
/// A lattice that refused this would be wrong in the opposite direction from
/// the one §10 warns about, and no refusal probe would notice — the whole
/// corpus would stay green while the crate rejected perfectly sound evidence.
#[test]
fn stronger_evidence_justifies_a_weaker_claim() {
    validate_justification(ClaimRank::Benchmark, ClaimRank::Proof)
        .expect("a proof is more than enough for a benchmark claim");
    validate_justification(ClaimRank::BoundedModel, ClaimRank::Invariant)
        .expect("a machine-checked invariant covers a bounded-model claim");

    // Exhaustive over the declared order: every rank justifies every rank at or
    // below it, so a reordering of the enum would fail here rather than
    // silently changing which evidence counts.
    for (claim_index, claim) in ClaimRank::ALL.iter().enumerate() {
        for evidence in ClaimRank::ALL.iter().skip(claim_index) {
            validate_justification(*claim, *evidence).unwrap_or_else(|error| {
                panic!("{evidence:?} must justify {claim:?}, got {error:?}")
            });
        }
    }
}

/// Every rank round-trips through its stable registry spelling.
///
/// A closed vocabulary with a silent gap is how an unknown rank becomes a
/// silently accepted one, so this is exhaustive over `ClaimRank::ALL` rather
/// than a sample.
#[test]
fn every_rank_round_trips_through_its_token() {
    for rank in ClaimRank::ALL {
        let parsed = ClaimRank::parse(rank.token())
            .unwrap_or_else(|error| panic!("{rank:?}'s own token must parse, got {error:?}"));
        assert_eq!(parsed, rank, "the token must round-trip to its own rank");
    }
}

// ---------------------------------------------------------------------------
// EvidenceTooWeak — the constitution's own examples
// ---------------------------------------------------------------------------

/// **"a benchmark as an invariant"** — §10, verbatim.
#[test]
fn a_benchmark_cannot_justify_an_invariant_claim() {
    let error = validate_justification(ClaimRank::Invariant, ClaimRank::Benchmark)
        .expect_err("a benchmark is not a machine-checked invariant");
    assert_eq!(
        error,
        ClaimRefusal::EvidenceTooWeak {
            claim: ClaimRank::Invariant,
            evidence: ClaimRank::Benchmark,
        },
        "the refusal names both the claim and the evidence offered for it"
    );
}

/// **"a bounded model as a proof"** — §10, verbatim.
///
/// Asserted separately from the case above, and with both ranks checked,
/// because a probe matching the bare variant could not tell the two apart —
/// and telling them apart is the entire content of the complaint.
#[test]
fn a_bounded_model_cannot_justify_a_proof_claim() {
    let error = validate_justification(ClaimRank::Proof, ClaimRank::BoundedModel)
        .expect_err("a bounded exploration is not a proof");
    assert_eq!(
        error,
        ClaimRefusal::EvidenceTooWeak {
            claim: ClaimRank::Proof,
            evidence: ClaimRank::BoundedModel,
        }
    );
}

/// Every strictly-weaker pairing is refused, exhaustively.
///
/// The two named cases above are the ones §10 calls out; this is the rest of
/// the order, so a change that weakened one pairing rather than the rule as a
/// whole would still fail.
#[test]
fn every_strictly_weaker_evidence_rank_is_refused() {
    for (claim_index, claim) in ClaimRank::ALL.iter().enumerate() {
        for evidence in ClaimRank::ALL.iter().take(claim_index) {
            let error = validate_justification(*claim, *evidence).expect_err(&format!(
                "{evidence:?} must not justify the stronger claim {claim:?}"
            ));
            assert_eq!(
                error,
                ClaimRefusal::EvidenceTooWeak {
                    claim: *claim,
                    evidence: *evidence,
                }
            );
        }
    }
}

// ---------------------------------------------------------------------------
// UnknownRank — a closed vocabulary
// ---------------------------------------------------------------------------

/// A token outside the closed lattice is refused, and the refusal reports what
/// was actually written.
///
/// The payload matters: a caller reporting "unknown rank" without saying which
/// token it saw cannot tell a typo from a registry that has drifted.
#[test]
fn a_token_outside_the_lattice_is_refused() {
    for token in ["", "Benchmark", "PROOF", "heuristic", "bounded model"] {
        let error = ClaimRank::parse(token)
            .expect_err(&format!("the token {token:?} must not parse as a rank"));
        assert_eq!(
            error,
            ClaimRefusal::UnknownRank {
                observed: token.to_owned(),
            },
            "the refusal must echo the token that was offered"
        );
    }
}

// ---------------------------------------------------------------------------
// InvalidText — three axes
// ---------------------------------------------------------------------------

#[test]
fn empty_claim_text_is_refused() {
    let error = ClaimText::parse("claim_id", "").expect_err("empty text names nothing");
    assert_eq!(
        error,
        ClaimRefusal::InvalidText {
            field: "claim_id",
            reason: "must not be empty",
        },
        "the payload names the field and which of the three axes refused"
    );
}

#[test]
fn claim_text_past_the_bound_is_refused() {
    let oversized = "a".repeat(MAX_CLAIM_TEXT_BYTES + 1);
    let error =
        ClaimText::parse("scope", &oversized).expect_err("one byte past the bound must refuse");
    assert_eq!(
        error,
        ClaimRefusal::InvalidText {
            field: "scope",
            reason: "exceeds the bounded canonical length",
        }
    );
}

/// The character axis, including the tab the guard excludes explicitly.
///
/// A tab is not `is_ascii_graphic`, so the extra `!= b'\t'` clause is
/// belt-and-braces — probed anyway, because a future simplification that
/// dropped one of the two conditions would still need this case to fail.
#[test]
fn non_graphic_claim_text_is_refused() {
    for value in ["has space", "has\ttab", "has\nnewline"] {
        let error = ClaimText::parse("artifact", value)
            .expect_err("claim text is printable ASCII without whitespace");
        assert_eq!(
            error,
            ClaimRefusal::InvalidText {
                field: "artifact",
                reason: "must contain only printable ASCII without whitespace",
            },
            "the value {value:?} must refuse on the character axis"
        );
    }
}

/// **The permitted twin at the exact boundary.** The guard reads `>`, so text of
/// exactly the bound is admitted.
#[test]
fn claim_text_at_exactly_the_bound_is_admitted() {
    let at_bound = "a".repeat(MAX_CLAIM_TEXT_BYTES);
    let parsed = ClaimText::parse("claim_id", &at_bound).expect("exactly the bound is admissible");
    assert_eq!(parsed.as_str().len(), MAX_CLAIM_TEXT_BYTES);
}

/// The field label carries information: the same fault under two field names
/// produces two distinguishable refusals.
#[test]
fn the_field_label_distinguishes_two_claim_fields() {
    let first = ClaimText::parse("claim_id", "").expect_err("empty is refused");
    let second = ClaimText::parse("scope", "").expect_err("empty is refused");
    assert_ne!(
        first, second,
        "the field label must say which field was refused"
    );
}
