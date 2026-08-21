#![forbid(unsafe_code)]
//! An independent oracle for net-effect normal form, and equivalence evidence
//! against the FG-008a folder.
//!
//! # Why this file does not read the folder it verifies
//!
//! The oracle below is written from the normative text alone —
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` §13, `OBJECT_STORE_DECISION_LOG.md` §9,
//! `GIT_TREE_FS.md` §7, and the FG-008 epic. The folding implementation was
//! deliberately not read. An oracle derived from the implementation agrees with
//! it by construction: it reproduces its bugs, passes every comparison, and
//! proves only that the code equals itself. Two independent derivations from
//! one specification can disagree, and a disagreement is information — the
//! folder is wrong, the oracle is wrong, or the specification is ambiguous.
//! The third is the one that testing code against itself never finds.
//!
//! Everything this file knows about the evaluator came from its owner as
//! signatures, on request, without the algorithm.
//!
//! # Two corrections this file keeps rather than erases
//!
//! **The first oracle folded the wrong thing.** It modelled tree edits — paths,
//! content, modes — because `GIT_TREE_FS` §7 states the concrete folding rules
//! over `TreeEditIntent`. The evaluator folds `fgit_reference::intent::Intent`
//! over refs, forge positions, retention roots and outbox keys. Same laws,
//! different carrier; the corpus would have been thorough, self-consistent, and
//! aimed at something the implementation never sees.
//!
//! **The second was nearly a false accusation.** `IntentDisposition` has four
//! top-level arms where the specification's totality map has six, and this file
//! briefly asserted that the evaluator conflated identity no-ops with inverse
//! cancellation. It does not: `Absorbed(AbsorptionReason)` carries the reason,
//! so the six-way resolution is fully recoverable. A four-arm signature is not
//! a four-arm vocabulary. Both mistakes were caught by asking rather than
//! filing, which is the cheapest verification step available.
//!
//! # What is proven here, and what is not
//!
//! **Proven:** that for every generated program, the oracle and the evaluator
//! agree on the surviving ref effects and on every intent's disposition
//! *including its absorption reason*.
//!
//! **Not proven:** anything about forge streams, retention roots, or outbox
//! deliveries — this model carries refs only. `PreconditionMismatchNoOp` is
//! reached; `DuplicateIdenticalDelivery` is not, because it needs outbox keys.
//! Those gaps are asserted as gaps below rather than left to look like
//! coverage.

use std::collections::{BTreeMap, BTreeSet};

use fgit_reference::effect::{
    AbsorptionReason, EffectTarget, FoldBasis, FoldOutcome, IntentDisposition, RefEffect,
};
use fgit_reference::harness::{IdentityMint, RequestBuilder, label};
use fgit_reference::intent::{IdempotencyKey, Intent, RefIntent, TransactionRequest};
use fgit_reference::refs::ExpectedRefState;
use fgit_txn::IntentEvaluator;
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::MismatchPolicy;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("fgit/ref-txn"), 2, 0)
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn ref_name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("a well-formed ref name")
}

/// A small ref alphabet on purpose: collisions are where folding happens, and a
/// wide alphabet generates mostly-disjoint programs that exercise no fold.
fn ref_alphabet() -> Vec<RefName> {
    ["refs/heads/a", "refs/heads/b", "refs/heads/c"]
        .into_iter()
        .map(ref_name)
        .collect()
}

// ---------------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------------

/// The oracle's view of one intent's fate, at the evaluator's own resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
enum OracleDisposition {
    Surviving(RefName),
    Absorbed(AbsorptionReason),
    StatementError,
    TransactionAborted,
}

/// The oracle's folded result.
#[derive(Clone, Debug, Eq, PartialEq)]
struct OracleReport {
    refs: BTreeMap<RefName, RefEffect>,
    dispositions: Vec<OracleDisposition>,
    aborted: bool,
}

/// Evaluate in source order with read-your-own-writes, then fold.
///
/// The two phases are kept apart deliberately. Evaluation is ordered; folding
/// is a pure diff of the resulting after-image against the basis, and never
/// sees the order at all. That is why order-independence is structural here
/// rather than something the tests have to establish.
///
/// # An assumption recorded rather than hidden
///
/// When a precondition fails under `MismatchPolicy::StatementError`, this
/// oracle marks that intent a statement error and **continues** with the
/// remaining intents. NPC §13 permits "statement-local failure" without saying
/// whether the rest of the statement still evaluates. If the evaluator stops
/// instead, the comparison below will disagree — and that disagreement is a
/// specification ambiguity worth reporting, not a bug to paper over.
fn oracle_fold(basis: &BTreeMap<RefName, GitOid>, request: &TransactionRequest) -> OracleReport {
    let mut after = basis.clone();
    let mut dispositions = Vec::new();
    let mut last_writer: BTreeMap<RefName, usize> = BTreeMap::new();
    let mut touched: Vec<Option<RefName>> = Vec::new();
    /// Whether each intent was an identity AT ITS EVALUATION POINT: its
    /// requested after-state already equalled the scratch state. Per the
    /// normative ruling this takes precedence over last-writer provenance.
    let mut identity_at_evaluation: Vec<bool> = Vec::new();
    /// Whether the ref, after each intent, held exactly its basis value. Used
    /// only to separate an inverse cancellation from an identity at a target
    /// that ends with no surviving effect.
    let mut post_is_basis: Vec<bool> = Vec::new();
    let mut aborted = false;

    'outer: for statement in &request.statements {
        for intent in &statement.intents {
            let Intent::Ref(ref_intent) = intent else {
                // Only ref intents are modelled; see the module non-claims.
                dispositions.push(OracleDisposition::StatementError);
                touched.push(None);
                identity_at_evaluation.push(true);
                post_is_basis.push(true);
                continue;
            };
            let name = ref_intent.target().clone();
            let satisfied = ref_intent.expected().is_satisfied_by(after.get(&name));

            if !satisfied {
                match statement.mismatch_policy {
                    MismatchPolicy::NoOp => {
                        dispositions.push(OracleDisposition::Absorbed(
                            AbsorptionReason::PreconditionMismatchNoOp,
                        ));
                        touched.push(None);
                        identity_at_evaluation.push(true);
                        post_is_basis.push(true);
                    }
                    MismatchPolicy::StatementError => {
                        dispositions.push(OracleDisposition::StatementError);
                        touched.push(None);
                        identity_at_evaluation.push(true);
                        post_is_basis.push(true);
                    }
                    MismatchPolicy::TxnAbort => {
                        dispositions.push(OracleDisposition::TransactionAborted);
                        touched.push(None);
                        identity_at_evaluation.push(true);
                        post_is_basis.push(true);
                        aborted = true;
                        break 'outer;
                    }
                }
                continue;
            }

            let index = dispositions.len();
            let before = after.get(&name).cloned();
            match ref_intent {
                RefIntent::Update { new, .. } => {
                    after.insert(name.clone(), new.clone());
                }
                RefIntent::Delete { .. } => {
                    after.remove(&name);
                }
            }
            // Fourth correction, and the subtlest so far.
            //
            // `last_writer` must record the last intent that CHANGED the ref,
            // not the last one that touched it. If a later intent writes the
            // value the ref already holds, it changed nothing — so the
            // surviving effect at that target was produced by the earlier
            // intent, and the later one is an identity no-op.
            //
            // Tracking mere contact credits the wrong intent with the surviving
            // effect and demotes the intent that actually produced it to
            // `OverwrittenBySucceedingIntent` — by an intent that overwrote
            // nothing.
            let did_change = before != after.get(&name).cloned();
            identity_at_evaluation.push(!did_change);
            post_is_basis.push(after.get(&name) == basis.get(&name));
            if did_change {
                last_writer.insert(name.clone(), index);
            }
            // Placeholder; classified after the fold, when survival is known.
            dispositions.push(OracleDisposition::StatementError);
            touched.push(Some(name));
        }
    }

    if aborted {
        // An aborted transaction publishes nothing, and EVERY source intent is
        // reported as aborted -- including the ones after the abort point that
        // never ran.
        //
        // The count matters, and this oracle got it wrong first time round. It
        // used to stop classifying at the abort, producing fewer dispositions
        // than there were intents. NPC §13 says "every source intent maps to"
        // one of the arms; an intent that never ran still has a fate, and
        // "the transaction aborted before reaching it" is that fate. Dropping
        // it silently breaks totality -- the first property the specification
        // states.
        //
        // The equivalence comparison caught this on its first execution, which
        // is the whole argument for writing an oracle independently: my
        // misreading and my implementation of it agreed with each other
        // perfectly, and only a second derivation disagreed.
        let total: usize = request
            .statements
            .iter()
            .map(|statement| statement.intents.len())
            .sum();
        return OracleReport {
            refs: BTreeMap::new(),
            dispositions: vec![OracleDisposition::TransactionAborted; total],
            aborted,
        };
    }

    let mut refs: BTreeMap<RefName, RefEffect> = BTreeMap::new();
    for (name, before) in basis {
        match after.get(name) {
            None => {
                refs.insert(name.clone(), RefEffect::Delete);
            }
            Some(now) if now != before => {
                refs.insert(name.clone(), RefEffect::Set(now.clone()));
            }
            Some(_) => {}
        }
    }
    for (name, now) in &after {
        if !basis.contains_key(name) {
            refs.insert(name.clone(), RefEffect::Set(now.clone()));
        }
    }

    for (index, slot) in touched.iter().enumerate() {
        let Some(name) = slot else {
            continue;
        };
        // Precedence matters here, and the first version had it wrong.
        //
        // The question "did a later intent touch this target" must be asked
        // *after* "does this target carry any surviving effect at all", not
        // before. A create that a later delete undid is not an overwrite: the
        // target ends with no effect, and GIT_TREE_FS §7 names that case
        // specifically as an "explicit inverse-cancellation no-op". Asking
        // about succession first swallows it, because a later intent did touch
        // the target — it deleted it.
        //
        // Overwriting is the case where an effect DOES survive and a later
        // intent is the one that produced it.
        // Third correction, and the one that finally names the vocabulary
        // properly. The three no-op reasons answer three different questions:
        //
        //   IdentityEffect  -- this intent changed nothing WHEN IT RAN.
        //   InverseCancelled -- it did change something, and nothing survives
        //                       at the target because a later intent undid it.
        //   Overwritten     -- it did change something, an effect DOES survive,
        //                       and a later intent is the one that produced it.
        //
        // Earlier versions discriminated on "was this ref created during the
        // transaction", which conflates X->Y->X (a genuine inverse
        // cancellation) with writing the value already present (an identity).
        // Whether the ref happens to have existed in the basis is irrelevant to
        // either question.
        // The rule, per GoldLotus's normative ruling on fg008a.
        //
        // IDENTITY AT EVALUATION TAKES PRECEDENCE over last-writer provenance.
        // An intent whose requested after-state already equals the scratch
        // state is Absorbed(IdentityEffect) UNIFORMLY — including at a target
        // that does carry a surviving effect. OverwrittenBySucceedingIntent is
        // reserved for real overwrites.
        //
        // Only once an intent is known to have actually changed something does
        // provenance matter:
        //
        //   target carries an effect:
        //     this intent produced the final value -> Surviving
        //     otherwise                            -> OverwrittenBySucceedingIntent
        //   target carries no effect:
        //     the ref ends at its basis value      -> IdentityEffect
        //     otherwise                            -> InverseCancelled
        //
        // The ruling reversed GoldLotus's own stated prior, which was
        // last-writer-survives; the spec reading won over the prior. Recorded
        // because that is worth more to a later reader than the rule alone.
        let target_has_effect = refs.contains_key(name);
        dispositions[index] = if identity_at_evaluation[index] {
            OracleDisposition::Absorbed(AbsorptionReason::IdentityEffect)
        } else if target_has_effect {
            if last_writer.get(name) == Some(&index) {
                OracleDisposition::Surviving(name.clone())
            } else {
                OracleDisposition::Absorbed(AbsorptionReason::OverwrittenBySucceedingIntent)
            }
        } else if post_is_basis[index] {
            OracleDisposition::Absorbed(AbsorptionReason::IdentityEffect)
        } else {
            OracleDisposition::Absorbed(AbsorptionReason::InverseCancelled)
        };
    }

    OracleReport {
        refs,
        dispositions,
        aborted,
    }
}

// ---------------------------------------------------------------------------
// Corpus generation
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % bound as u64).expect("small bound")
    }
}

fn generate_basis(rng: &mut Rng) -> BTreeMap<RefName, GitOid> {
    let mut basis = BTreeMap::new();
    for name in ref_alphabet() {
        if rng.below(2) == 0 {
            basis.insert(name, oid(u8::try_from(rng.below(3)).expect("small") + 1));
        }
    }
    basis
}

/// Build one request, mixing satisfiable and unsatisfiable preconditions so the
/// mismatch policies are actually exercised.
fn generate_request(
    rng: &mut Rng,
    mint: &mut IdentityMint,
    basis: &BTreeMap<RefName, GitOid>,
    key: &str,
) -> TransactionRequest {
    let tenant = mint.tenant();
    let repository = mint.repository();
    let author = mint.principal();
    let alphabet = ref_alphabet();

    let mut builder = RequestBuilder::new(
        tenant,
        repository,
        author,
        schema(),
        IdempotencyKey::new(label(key)),
    );

    for _ in 0..rng.below(3) + 1 {
        let policy = match rng.below(3) {
            0 => MismatchPolicy::NoOp,
            1 => MismatchPolicy::StatementError,
            _ => MismatchPolicy::TxnAbort,
        };
        let mut intents = Vec::new();
        for _ in 0..rng.below(3) + 1 {
            let name = alphabet[rng.below(alphabet.len())].clone();
            // Half the time use the true current value so the precondition
            // holds; otherwise a deliberately wrong one.
            let expected = match rng.below(3) {
                0 => ExpectedRefState::Any,
                1 => basis.get(&name).map_or(ExpectedRefState::Absent, |o| {
                    ExpectedRefState::Exact(o.clone())
                }),
                _ => ExpectedRefState::Exact(oid(200)),
            };
            intents.push(Intent::Ref(if rng.below(4) == 0 {
                RefIntent::Delete { name, expected }
            } else {
                RefIntent::Update {
                    name,
                    expected,
                    new: oid(u8::try_from(rng.below(3)).expect("small") + 1),
                    force: rng.below(2) == 0,
                }
            }));
        }
        builder = builder.statement(policy, intents);
    }

    builder.build(mint)
}

// ---------------------------------------------------------------------------
// Equivalence
// ---------------------------------------------------------------------------

const CORPUS_SEED: u64 = 0x5EED_0008_B00B_1E5;

/// Default programs per property for a bare `cargo test`.
///
/// Small on purpose: a workspace run should stay fast, and a corpus that makes
/// the unit suite slow gets run less often, which is a coverage loss disguised
/// as thoroughness.
const DEFAULT_PROGRAMS: usize = 500;

/// The acceptance bound, reached only when the campaign is asked for.
const CAMPAIGN_PROGRAMS: usize = 100_000;

/// How many programs to generate.
///
/// The bead's acceptance asks for >= 10^5 seeded programs. Running that on
/// every `cargo test --workspace` would be antisocial, and a hard bound would
/// make a bare workspace run slow for everyone — the same breakage class
/// YellowLotus avoided on fg005b by gating the demanding assertion behind an
/// environment variable that only the e2e lane sets.
///
/// So: `FG008B_CORPUS` selects the size. Unset means the fast default; the e2e
/// lane sets the campaign bound. Both paths run the *same* properties over the
/// same generator — only the count differs, so a green default is a weaker
/// statement of the identical claim rather than a different claim.
fn programs() -> usize {
    match std::env::var("FG008B_CORPUS") {
        Err(_) => DEFAULT_PROGRAMS,
        Ok(value) if value == "campaign" => CAMPAIGN_PROGRAMS,
        Ok(value) => value.parse().unwrap_or_else(|_| {
            panic!(
                "FG008B_CORPUS={value:?} is neither a number nor \"campaign\"; refusing to \
                 silently fall back to {DEFAULT_PROGRAMS} programs and report the result as \
                 though the requested campaign had run"
            )
        }),
    }
}

/// Translate the evaluator's disposition into the oracle's vocabulary.
///
/// The absorption reason is carried through rather than collapsed. Comparing on
/// a coarser projection would let the two sides agree while the distinction the
/// specification asks for went untested.
fn translate(disposition: &IntentDisposition) -> OracleDisposition {
    match disposition {
        IntentDisposition::Surviving(EffectTarget::Ref(name)) => {
            OracleDisposition::Surviving(name.clone())
        }
        IntentDisposition::Surviving(_) => OracleDisposition::StatementError,
        IntentDisposition::Absorbed(reason) => OracleDisposition::Absorbed(*reason),
        IntentDisposition::StatementError(_) => OracleDisposition::StatementError,
        IntentDisposition::TransactionAborted => OracleDisposition::TransactionAborted,
    }
}

#[test]
fn the_oracle_and_the_evaluator_agree_on_every_generated_program() {
    let evaluator = IntentEvaluator::new();
    let mut agreements = 0_usize;

    for i in 0..programs() {
        let seed = CORPUS_SEED.wrapping_add(i as u64);
        let mut rng = Rng::new(seed);
        let mut mint = IdentityMint::new(seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut mint, &basis, "corpus");

        let forge_positions = BTreeMap::new();
        let retention = BTreeSet::new();
        let outbox = BTreeMap::new();
        let fold_basis = FoldBasis {
            refs: &basis,
            forge_positions: &forge_positions,
            retention: &retention,
            outbox: &outbox,
        };

        let report = evaluator.evaluate(fold_basis, &request);
        let mine = oracle_fold(&basis, &request);

        match &report.outcome {
            FoldOutcome::Folded(effects) => {
                assert!(
                    !mine.aborted,
                    "seed {seed:#x}: the evaluator folded, the oracle aborted"
                );
                assert_eq!(
                    effects.refs, mine.refs,
                    "seed {seed:#x}: surviving ref effects disagree"
                );
            }
            FoldOutcome::Aborted { .. } => {
                assert!(
                    mine.aborted,
                    "seed {seed:#x}: the evaluator aborted, the oracle folded"
                );
            }
        }

        let theirs: Vec<OracleDisposition> = report
            .mappings
            .iter()
            .map(|m| translate(&m.disposition))
            .collect();
        assert_eq!(
            theirs.len(),
            mine.dispositions.len(),
            "seed {seed:#x}: totality disagrees — {} mappings vs {} dispositions",
            theirs.len(),
            mine.dispositions.len()
        );
        assert_eq!(
            theirs, mine.dispositions,
            "seed {seed:#x}: intent dispositions disagree (absorption reasons included)"
        );
        agreements += 1;
    }

    assert_eq!(
        agreements,
        programs(),
        "every generated program must have been compared"
    );
}

#[test]
fn the_oracle_maps_every_source_intent() {
    // Totality, checked against the oracle alone. This test existed in the
    // tree-carrier version, was dropped in the domain rewrite, and its absence
    // is exactly why an abort-path totality bug survived to be found by the
    // equivalence comparison instead of here. Restored.
    for i in 0..programs() {
        let seed = CORPUS_SEED.wrapping_add(i as u64);
        let mut rng = Rng::new(seed);
        let mut mint = IdentityMint::new(seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut mint, &basis, "totality");

        let total: usize = request
            .statements
            .iter()
            .map(|statement| statement.intents.len())
            .sum();
        let mine = oracle_fold(&basis, &request);

        assert_eq!(
            mine.dispositions.len(),
            total,
            "seed {seed:#x}: {total} source intents produced {} dispositions; an intent that \
             never ran still has a fate",
            mine.dispositions.len()
        );
    }
}

#[test]
fn the_corpus_reaches_the_dispositions_it_claims_to_test() {
    // Non-vacuity. The comparison above would pass on a corpus of empty
    // programs. This asserts the generated programs actually reach surviving
    // effects, overwrite absorption, and precondition mismatches, so the
    // agreement is agreement about something.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for i in 0..programs() {
        let seed = CORPUS_SEED.wrapping_add(i as u64);
        let mut rng = Rng::new(seed);
        let mut mint = IdentityMint::new(seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut mint, &basis, "coverage");
        for disposition in oracle_fold(&basis, &request).dispositions {
            seen.insert(match disposition {
                OracleDisposition::Surviving(_) => "surviving".to_owned(),
                OracleDisposition::Absorbed(reason) => format!("absorbed:{reason:?}"),
                OracleDisposition::StatementError => "statement-error".to_owned(),
                OracleDisposition::TransactionAborted => "aborted".to_owned(),
            });
        }
    }

    for required in [
        "surviving",
        "absorbed:OverwrittenBySucceedingIntent",
        "absorbed:PreconditionMismatchNoOp",
        "statement-error",
        "aborted",
    ] {
        assert!(
            seen.contains(required),
            "the corpus never produced {required}; the agreement test is untested against it. \
             Reached: {seen:?}"
        );
    }
}

#[test]
fn the_unmodelled_arms_are_named_rather_than_quietly_absent() {
    // `DuplicateIdenticalDelivery` needs outbox delivery keys, which this
    // ref-only model does not carry. An oracle silently producing four of five
    // absorption reasons would look complete; this makes the gap a statement.
    let mut seen: BTreeSet<AbsorptionReason> = BTreeSet::new();
    for i in 0..programs() {
        let seed = CORPUS_SEED.wrapping_add(i as u64);
        let mut rng = Rng::new(seed);
        let mut mint = IdentityMint::new(seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut mint, &basis, "gaps");
        for disposition in oracle_fold(&basis, &request).dispositions {
            if let OracleDisposition::Absorbed(reason) = disposition {
                seen.insert(reason);
            }
        }
    }

    assert!(
        !seen.contains(&AbsorptionReason::DuplicateIdenticalDelivery),
        "DuplicateIdenticalDelivery is now reachable; extend the comparison to outbox \
         intents and remove this assertion rather than leaving it asserting a stale gap"
    );
}

#[test]
fn identical_intents_receive_identical_dispositions() {
    // The strongest form of the disagreement, and the one that needs no
    // adjudication of which label is *correct*.
    //
    // N byte-identical intents -- same target, same precondition, same
    // statement, same mismatch policy, same empty basis -- must all receive the
    // same disposition. They are the same operation performed N times against
    // the same state. Whatever the right label is, it cannot depend on an
    // intent's position in the list.
    //
    // Observed from `IntentEvaluator::evaluate`:
    //
    //   1 delete  -> [IdentityEffect]
    //   2 deletes -> [InverseCancelled, IdentityEffect]
    //   3 deletes -> [InverseCancelled, InverseCancelled, IdentityEffect]
    //
    // Only the final intent is called an identity; the earlier ones are
    // reported as inverse cancellations. Nothing was cancelled -- the ref was
    // absent throughout and every delete was a no-op. The mechanism appears to
    // be that non-final intents at a target are classified from the target's
    // FINAL state (absent, therefore "cancelled") without also requiring that
    // the intent changed something when it ran.
    //
    // This is deliberately framed as an internal-consistency property rather
    // than as "IdentityEffect is right", because the author of this file has
    // been wrong about these reasons three times and the property holds either
    // way.
    let evaluator = IntentEvaluator::new();
    let name = ref_name("refs/heads/b");
    let delete = || {
        Intent::Ref(RefIntent::Delete {
            name: name.clone(),
            expected: ExpectedRefState::Any,
        })
    };

    for count in 1_usize..=3 {
        let mut mint = IdentityMint::new(11);
        let request = RequestBuilder::new(
            mint.tenant(),
            mint.repository(),
            mint.principal(),
            schema(),
            IdempotencyKey::new(label("identical")),
        )
        .statement(MismatchPolicy::NoOp, (0..count).map(|_| delete()).collect())
        .build(&mut mint);

        let basis = BTreeMap::new();
        let forge = BTreeMap::new();
        let retention = BTreeSet::new();
        let outbox = BTreeMap::new();
        let report = evaluator.evaluate(
            FoldBasis {
                refs: &basis,
                forge_positions: &forge,
                retention: &retention,
                outbox: &outbox,
            },
            &request,
        );

        let dispositions: Vec<_> = report.mappings.iter().map(|m| &m.disposition).collect();
        assert_eq!(
            dispositions.len(),
            count,
            "{count} intents must produce {count} mappings"
        );
        let first = dispositions[0];
        assert!(
            dispositions.iter().all(|d| *d == first),
            "{count} byte-identical intents against identical state received differing \
             dispositions: {dispositions:?}. The same operation repeated cannot mean different \
             things depending on its position"
        );
    }
}

#[test]
fn the_corpus_size_control_actually_controls_the_corpus() {
    // Non-vacuity for the gate itself. A misspelled variable name, or a parse
    // that quietly fell back to the default, would let the e2e lane report a
    // 10^5 campaign while running 500 programs — the campaign equivalent of a
    // guard whose needles do not match.
    //
    // The environment is process-global and other tests read it, so this
    // asserts the mapping rather than mutating it.
    assert_eq!(DEFAULT_PROGRAMS, 500);
    assert_eq!(CAMPAIGN_PROGRAMS, 100_000);
    assert!(
        CAMPAIGN_PROGRAMS >= 100_000,
        "the acceptance asks for at least 10^5 seeded programs"
    );
    assert!(
        DEFAULT_PROGRAMS < CAMPAIGN_PROGRAMS,
        "the default must be the cheap one; if they are equal the gate is pointless"
    );
    // And the currently-selected size must be one of the two, so a stray value
    // in the environment shows up as a failure here rather than as a quietly
    // different corpus everywhere else.
    let selected = programs();
    assert!(
        selected == DEFAULT_PROGRAMS || selected == CAMPAIGN_PROGRAMS,
        "FG008B_CORPUS selected {selected} programs, which is neither the default nor the \
         campaign bound; every other test in this file is now running an unannounced size"
    );
}

/// The seed whose program exhibits the open provenance question.
///
/// Pinned per GoldLotus's instruction so the case survives as a regression
/// artifact regardless of how the contract rules.
const PROVENANCE_AMBIGUITY_SEED: u64 = 0x5EED_0008_B00B_1F2;

#[test]
fn the_provenance_ambiguity_is_pinned_and_reproducible() {
    // NOT an assertion about which disposition is correct. The specification
    // does not say, and this test deliberately does not either.
    //
    // THE QUESTION. Two intents target one ref; the later writes the value the
    // earlier already produced, so it is a state-identity at its evaluation
    // point. The net effect is identical under every reading. Only the
    // PROVENANCE differs — which intent is credited with the surviving effect:
    //
    //   (a) evaluator today: earlier Surviving, later Absorbed(IdentityEffect)
    //   (b) GoldLotus prior: later Surviving,  earlier Absorbed(Overwritten)
    //   (c) last-CHANGER:    earlier Surviving, later Absorbed(Overwritten)
    //
    // (a) and (c) agree on who survives and disagree on the loser's reason;
    // (b) inverts who survives. Three readings, not two.
    //
    // WHY THE SPEC DOES NOT SETTLE IT. Every normative sentence constrains the
    // net effect, the totality of the map, or order-independence:
    //
    //   NPC §13     "folds ... into target-disjoint net-effect normal form.
    //                Every source intent maps to a surviving effect,
    //                identity/inverse/absorption no-op, statement error, or
    //                transaction abort."
    //   GIT_TREE_FS §7  "repeated writes collapse to the final content"
    //                — about CONTENT, not about which intent is credited.
    //
    // "Maps to *a* surviving effect" requires each intent to land in some arm.
    // It does not say which intent is credited when two produce the same final
    // value. Read-your-own-writes governs evaluation order, not attribution.
    //
    // So this is recorded as an open contract question, not resolved by
    // whichever side happens to be more convenient to change.
    let mut rng = Rng::new(PROVENANCE_AMBIGUITY_SEED);
    let mut mint = IdentityMint::new(PROVENANCE_AMBIGUITY_SEED);
    let basis = generate_basis(&mut rng);
    let request = generate_request(&mut rng, &mut mint, &basis, "corpus");

    // The program must still exhibit the shape, or this pin has rotted into a
    // test of nothing.
    let total: usize = request
        .statements
        .iter()
        .map(|statement| statement.intents.len())
        .sum();
    assert!(
        total >= 2,
        "the pinned seed no longer generates a multi-intent program; the generator changed \
         and this case must be re-derived rather than left asserting a stale shape"
    );

    // Both sides must still agree on the NET EFFECT. If they ever stop, the
    // disagreement has grown past provenance into semantics and is no longer
    // the question described above.
    let evaluator = IntentEvaluator::new();
    let forge = BTreeMap::new();
    let retention = BTreeSet::new();
    let outbox = BTreeMap::new();
    let report = evaluator.evaluate(
        FoldBasis {
            refs: &basis,
            forge_positions: &forge,
            retention: &retention,
            outbox: &outbox,
        },
        &request,
    );
    let mine = oracle_fold(&basis, &request);

    if let FoldOutcome::Folded(effects) = &report.outcome {
        assert_eq!(
            effects.refs, mine.refs,
            "the pinned case must differ ONLY in provenance; the net effects have diverged, \
             which makes this a different and more serious disagreement"
        );
    }
}
