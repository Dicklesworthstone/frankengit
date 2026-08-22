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
    AbsorptionReason, EffectTarget, FoldBasis, FoldOutcome, IntentDisposition, NetEffects,
    RefEffect,
};
use fgit_reference::harness::{IdentityMint, RequestBuilder, label};
use fgit_reference::intent::{
    ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId, ForgeStreamPosition, IdempotencyKey,
    Intent, OutboxDeliveryKey, OutboxIntent, RefIntent, TransactionRequest,
};
use fgit_reference::refs::ExpectedRefState;
use fgit_txn::{IntentEvaluator, Workspace, apply_net_effects};
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::{MismatchPolicy, RefusalCode};
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const fn schema() -> SchemaId {
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
    Surviving(EffectTarget),
    Absorbed(AbsorptionReason),
    /// The refusal code is carried, not discarded.
    ///
    /// An earlier version compared a bare `StatementError`, which let the two
    /// sides agree while saying nothing about *why* a statement was refused —
    /// the same coarse-resolution mistake this file already made once with
    /// `Absorbed`, and which only surfaced then because someone corrected it.
    /// The intent-relevant taxonomy is four codes out of `RefusalCode`'s 61;
    /// comparing at the arm rather than the code tests none of them.
    StatementError(RefusalCode),
    TransactionAborted,
}

/// The oracle's folded result.
#[derive(Clone, Debug, Eq, PartialEq)]
struct OracleReport {
    refs: BTreeMap<RefName, RefEffect>,
    dispositions: Vec<OracleDisposition>,
    aborted: bool,
    /// The end state the ordered evaluation actually produced.
    ///
    /// Distinct from `refs`, which is the DIFF against the basis. The round-trip
    /// property needs the state itself: a diff round-trips against its own
    /// basis by construction, so comparing diffs would prove nothing about
    /// whether the fold preserved semantics.
    final_refs: BTreeMap<RefName, GitOid>,
    final_forge: BTreeMap<ForgeStreamId, Vec<ForgeEventKind>>,
    final_outbox: BTreeMap<OutboxDeliveryKey, Digest>,
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
    // Whether each intent was an identity AT ITS EVALUATION POINT: its
    // requested after-state already equalled the scratch state. Per the
    // normative ruling this takes precedence over last-writer provenance.
    let mut identity_at_evaluation: Vec<bool> = Vec::new();
    // Outbox deliveries bound so far, read-your-own-writes like `after`.
    // Seeded empty because every call site passes an empty outbox basis; if a
    // caller ever seeds one, this must take it as a parameter or the two
    // sides start from different states and every disagreement is spurious.
    let mut outbox_scratch: BTreeMap<OutboxDeliveryKey, Digest> = BTreeMap::new();
    // Forge positions, seeded from the same fixture the evaluator is given.
    let mut forge_scratch: BTreeMap<ForgeStreamId, ForgeStreamPosition> = forge_basis();
    // Positions decide admission; EVENTS are what the normal form carries, so
    // the round-trip needs both tracked independently.
    let mut forge_events: BTreeMap<ForgeStreamId, Vec<ForgeEventKind>> = BTreeMap::new();
    let mut aborted = false;

    'outer: for statement in &request.statements {
        for intent in &statement.intents {
            let Intent::Ref(ref_intent) = intent else {
                // This arm used to score EVERY non-ref intent as
                // `StatementError(ExpectedOldRefMismatch)`. That was dead code
                // while the generator emitted refs only, and it would have
                // become silently wrong the moment it wasn't: a valid outbox
                // delivery would have been reported as a precondition mismatch,
                // the evaluator would have disagreed, and the obvious "fix"
                // would have been to copy the evaluator here -- destroying the
                // independence this oracle exists to provide.
                match intent {
                    Intent::Outbox(outbox) => {
                        // Derived from the rule, not from the folder: an outbox
                        // delivery is owed once per key. The same key with the
                        // same canonical parameters owes nothing new; with
                        // different parameters it is a reuse of an effect key
                        // that already means something else.
                        //
                        // Note an outbox target, unlike a ref, can never be
                        // overwritten inside one transaction -- a second intent
                        // at a bound key is either absorbed or refused, never a
                        // later writer. So these dispositions are final here and
                        // need none of the survival machinery below.
                        let bound = outbox_scratch.get(&outbox.delivery_key).copied();
                        match bound {
                            Some(parameters) if parameters == outbox.parameters => {
                                dispositions.push(OracleDisposition::Absorbed(
                                    AbsorptionReason::DuplicateIdenticalDelivery,
                                ));
                            }
                            // A mismatch, and the statement policy governs it
                            // exactly as it governs a ref precondition
                            // mismatch. Verified at `effect.rs:296`, which
                            // routes every `Applied::Mismatch` through the
                            // policy uniformly rather than per intent kind.
                            Some(_) => match statement.mismatch_policy {
                                MismatchPolicy::NoOp => {
                                    dispositions.push(OracleDisposition::Absorbed(
                                        AbsorptionReason::PreconditionMismatchNoOp,
                                    ));
                                }
                                MismatchPolicy::StatementError => {
                                    dispositions.push(OracleDisposition::StatementError(
                                        RefusalCode::EffectIdempotencyKeyReuse,
                                    ));
                                }
                                MismatchPolicy::TxnAbort => {
                                    dispositions.push(OracleDisposition::TransactionAborted);
                                    touched.push(None);
                                    identity_at_evaluation.push(true);
                                    aborted = true;
                                    break 'outer;
                                }
                            },
                            None => {
                                outbox_scratch.insert(outbox.delivery_key, outbox.parameters);
                                dispositions.push(OracleDisposition::Surviving(
                                    EffectTarget::Outbox(outbox.delivery_key),
                                ));
                            }
                        }
                        touched.push(None);
                        identity_at_evaluation.push(true);
                        continue;
                    }
                    Intent::Forge(forge) => {
                        // Derived from the rule: a forge intent advances one
                        // stream by one position, and may do so only from the
                        // position the caller expected. Two refusals, in this
                        // order, because a stale expectation is a different
                        // fault from a stream that cannot advance at all.
                        let current = forge_scratch
                            .get(&forge.stream)
                            .copied()
                            .unwrap_or(ForgeStreamPosition::GENESIS);
                        let refusal = if current != forge.expected_position {
                            Some(RefusalCode::ForgeTransitionInvalid)
                        } else if current.is_exhausted() {
                            // NOT a general budget refusal despite the name --
                            // forge-stream exhaustion specifically. An earlier
                            // reading of this file guessed otherwise and would
                            // have sent whoever extended it hunting for a
                            // declared budget that does not exist.
                            Some(RefusalCode::ResourceBudgetExceeded)
                        } else {
                            None
                        };
                        match refusal {
                            // Same uniform policy routing as the outbox and ref
                            // mismatches; effect.rs:296.
                            Some(code) => match statement.mismatch_policy {
                                MismatchPolicy::NoOp => {
                                    dispositions.push(OracleDisposition::Absorbed(
                                        AbsorptionReason::PreconditionMismatchNoOp,
                                    ));
                                }
                                MismatchPolicy::StatementError => {
                                    dispositions.push(OracleDisposition::StatementError(code));
                                }
                                MismatchPolicy::TxnAbort => {
                                    dispositions.push(OracleDisposition::TransactionAborted);
                                    touched.push(None);
                                    identity_at_evaluation.push(true);
                                    aborted = true;
                                    break 'outer;
                                }
                            },
                            None => {
                                forge_scratch.insert(forge.stream, current.successor());
                                forge_events
                                    .entry(forge.stream)
                                    .or_default()
                                    .push(forge.event.clone());
                                dispositions.push(OracleDisposition::Surviving(
                                    EffectTarget::ForgeStream(forge.stream),
                                ));
                            }
                        }
                        touched.push(None);
                        identity_at_evaluation.push(true);
                        continue;
                    }
                    // Retention roots remain unmodelled; the generator does not
                    // emit them. Loudly, because a placeholder disposition is
                    // precisely what made the original version of this arm
                    // wrong-in-waiting.
                    other => panic!(
                        "the generator emitted {other:?}, which this oracle does not model. \
                         Extend the oracle in the same commit that extends the generator, or \
                         the comparison stops testing what it claims"
                    ),
                }
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
                    }
                    MismatchPolicy::StatementError => {
                        // Refs-only model: the sole reachable intent refusal is
                        // a precondition mismatch. The other three
                        // intent-relevant codes need carriers this model does
                        // not have; see `the_intent_refusal_taxonomy_is_bounded`.
                        dispositions.push(OracleDisposition::StatementError(
                            RefusalCode::ExpectedOldRefMismatch,
                        ));
                        touched.push(None);
                        identity_at_evaluation.push(true);
                    }
                    MismatchPolicy::TxnAbort => {
                        dispositions.push(OracleDisposition::TransactionAborted);
                        touched.push(None);
                        identity_at_evaluation.push(true);
                        aborted = true;
                        break 'outer;
                    }
                }
                continue;
            }

            let index = dispositions.len();
            let before = after.get(&name).copied();
            match ref_intent {
                RefIntent::Update { new, .. } => {
                    after.insert(name.clone(), *new);
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
            let did_change = before != after.get(&name).copied();
            identity_at_evaluation.push(!did_change);
            if did_change {
                last_writer.insert(name.clone(), index);
            }
            // Placeholder; classified after the fold, when survival is known.
            dispositions.push(OracleDisposition::StatementError(
                RefusalCode::ExpectedOldRefMismatch,
            ));
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
            // An aborted transaction publishes nothing, so the end state is the
            // basis untouched -- NOT the partially mutated scratch the
            // evaluation had reached when it aborted. Returning the scratch here
            // would make the round-trip assert that an abort publishes its
            // partial work.
            final_refs: basis.clone(),
            final_forge: BTreeMap::new(),
            final_outbox: BTreeMap::new(),
        };
    }

    let mut refs: BTreeMap<RefName, RefEffect> = BTreeMap::new();
    for (name, before) in basis {
        match after.get(name) {
            None => {
                refs.insert(name.clone(), RefEffect::Delete);
            }
            Some(now) if now != before => {
                refs.insert(name.clone(), RefEffect::Set(*now));
            }
            Some(_) => {}
        }
    }
    for (name, now) in &after {
        if !basis.contains_key(name) {
            refs.insert(name.clone(), RefEffect::Set(*now));
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
                OracleDisposition::Surviving(EffectTarget::Ref(name.clone()))
            } else {
                OracleDisposition::Absorbed(AbsorptionReason::OverwrittenBySucceedingIntent)
            }
        } else if last_writer.get(name) == Some(&index) {
            // At a target that ends with no surviving effect, only the LAST
            // intent to change it earns the identity label: its restoration to
            // the basis value is the one that stands. An earlier intent that
            // also landed on the basis value had its restoration undone by a
            // later change, so it was itself cancelled.
            //
            // Found by the 10^5 campaign and NOT by the 500-program default: it
            // needs one target written four or more times with two separate
            // returns to the basis value. That is the argument for the
            // acceptance bound being what it is.
            OracleDisposition::Absorbed(AbsorptionReason::IdentityEffect)
        } else {
            OracleDisposition::Absorbed(AbsorptionReason::InverseCancelled)
        };
    }

    OracleReport {
        refs,
        dispositions,
        aborted,
        final_refs: after,
        final_forge: forge_events,
        final_outbox: outbox_scratch,
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
    const fn next_u64(&mut self) -> u64 {
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

/// A delivery key from a deliberately tiny alphabet.
///
/// Two keys, so a generated statement collides with itself often enough that
/// both outbox arms -- identical redelivery and key reuse -- are reached
/// without hand-built programs. Widening this alphabet makes the corpus cover
/// LESS, which is the opposite of the usual intuition.
fn delivery_key(index: usize) -> OutboxDeliveryKey {
    OutboxDeliveryKey::new(label(if index == 0 { "outbox-a" } else { "outbox-b" }))
}

/// A canonical-parameters digest that is a pure function of `tag`.
///
/// Determinism is the point: two intents carrying the same tag must produce
/// byte-identical parameters, or `DuplicateIdenticalDelivery` is unreachable
/// and the corpus silently tests only the reuse arm.
fn digest_of(tag: u8) -> Digest {
    let algorithm = DigestAlgorithmId::try_new(1).expect("a non-zero algorithm slot is admissible");
    let bytes =
        DigestBytes::try_new(&[tag; 20]).expect("20-byte SHA-1 digest fits its registered width");
    Digest::new(algorithm, bytes)
}

/// The two forge streams the corpus drives.
fn forge_stream(index: usize) -> ForgeStreamId {
    ForgeStreamId::new(label(if index == 0 {
        "forge-fresh"
    } else {
        "forge-exhausted"
    }))
}

/// The forge basis, and it is a FIXTURE rather than generated data.
///
/// One stream is left absent so it reads as `GENESIS` and can advance
/// normally. The other is seeded at `u64::MAX` **deliberately**, because
/// `ResourceBudgetExceeded` fires only on a stream that `is_exhausted()` and
/// scratch positions advance through a saturating `successor()` -- so
/// exhaustion is 2^64 steps away and no generator will ever reach it by
/// advancing. `FoldBasis::forge_positions` is caller-supplied and
/// `ForgeStreamPosition::new` is public, which is the only reason that arm is
/// reachable at all.
///
/// Stated at this length because the next reader would otherwise assume the
/// generator produces exhaustion on its own, and quietly delete the seed.
///
/// Both the oracle and the evaluator must start from this same map or every
/// forge disagreement is spurious.
fn forge_basis() -> BTreeMap<ForgeStreamId, ForgeStreamPosition> {
    let mut positions = BTreeMap::new();
    positions.insert(forge_stream(1), ForgeStreamPosition::new(u64::MAX));
    positions
}

/// A forge event with no cross-intent obligations.
///
/// `PullRequestOpened` on purpose: `PullRequestMerged` may only appear
/// alongside a ref effect that moves its target, and a generator emitting it
/// freely would be producing programs the specification does not admit.
fn forge_event() -> ForgeEventKind {
    ForgeEventKind::PullRequestOpened {
        pull_request: ForgeEntityId::new(label("pr-1")),
        target: ref_name("refs/heads/forge-target"),
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

    for _ in 0..=rng.below(3) {
        let policy = match rng.below(3) {
            0 => MismatchPolicy::NoOp,
            1 => MismatchPolicy::StatementError,
            _ => MismatchPolicy::TxnAbort,
        };
        let mut intents = Vec::new();
        for _ in 0..=rng.below(3) {
            let name = alphabet[rng.below(alphabet.len())].clone();
            // Half the time use the true current value so the precondition
            // holds; otherwise a deliberately wrong one.
            let expected = match rng.below(3) {
                0 => ExpectedRefState::Any,
                1 => basis
                    .get(&name)
                    .map_or(ExpectedRefState::Absent, |o| ExpectedRefState::Exact(*o)),
                _ => ExpectedRefState::Exact(oid(200)),
            };
            // ONE draw selects the intent kind, and it must stay one draw.
            //
            // Stage 2 first added forge as a SECOND independent `rng.below(4)`
            // beside the outbox one. Every property still passed and the
            // equivalence campaign stayed green -- but the extra draw shifted
            // the sequence and outbox collisions fell below the default bound's
            // reach, so `EffectIdempotencyKeyReuse` silently stopped being
            // reached. The taxonomy test caught it; nothing else would have.
            //
            // Independent per-kind draws make each kind's frequency depend on
            // every other kind's, so adding a kind quietly reduces the coverage
            // of the ones already there. A single selector keeps the weights
            // explicit and local.
            match rng.below(8) {
                // Forge. The expected position is drawn from three values so
                // all three outcomes occur naturally: matching a fresh stream
                // advances it, matching the seeded exhausted stream hits the
                // exhaustion arm, and anything else is a stale expectation.
                0 | 1 => {
                    let expected = match rng.below(3) {
                        0 => ForgeStreamPosition::GENESIS,
                        1 => ForgeStreamPosition::new(u64::MAX),
                        // Neither stream's real position, so a guaranteed stale
                        // expectation whichever stream it lands on.
                        _ => ForgeStreamPosition::new(7),
                    };
                    intents.push(Intent::Forge(ForgeIntent {
                        stream: forge_stream(rng.below(2)),
                        expected_position: expected,
                        event: forge_event(),
                    }));
                }
                // Outbox, from the tiny key/parameter alphabets above so that
                // identical redelivery and key reuse both occur by collision
                // rather than by hand-built programs.
                2 | 3 => {
                    intents.push(Intent::Outbox(OutboxIntent {
                        delivery_key: delivery_key(rng.below(2)),
                        parameters: digest_of(u8::try_from(rng.below(2)).expect("small")),
                    }));
                }
                _ => {
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
            }
        }
        builder = builder.statement(policy, intents);
    }

    builder.build(mint)
}

// ---------------------------------------------------------------------------
// Equivalence
// ---------------------------------------------------------------------------

const CORPUS_SEED: u64 = 0x05EE_D000_8B00_B1E5;

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
/// `YellowLotus` avoided on fg005b by gating the demanding assertion behind an
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

/// The disagreement between the two folders, if there is one.
///
/// Extracted so the SAME comparison decides both the assertion and the
/// shrinker's predicate. Two copies would let the shrinker minimise against a
/// subtly different question from the one that actually failed, and report a
/// "minimal" program that does not exhibit the reported fault.
fn disagreement(basis: &BTreeMap<RefName, GitOid>, request: &TransactionRequest) -> Option<String> {
    // Constructed here rather than threaded in: `IntentEvaluator` is
    // zero-sized, so passing it by reference costs a pointer to nothing and
    // clippy is right to object.
    let evaluator = IntentEvaluator::new();
    let forge_positions = forge_basis();
    let retention = BTreeSet::new();
    let outbox = BTreeMap::new();
    let report = evaluator.evaluate(
        FoldBasis {
            refs: basis,
            forge_positions: &forge_positions,
            retention: &retention,
            outbox: &outbox,
        },
        request,
    );
    let oracle = oracle_fold(basis, request);

    match &report.outcome {
        FoldOutcome::Folded(effects) => {
            if oracle.aborted {
                return Some("the evaluator folded, the oracle aborted".to_owned());
            }
            if effects.refs != oracle.refs {
                return Some("surviving ref effects disagree".to_owned());
            }
        }
        FoldOutcome::Aborted { .. } => {
            if !oracle.aborted {
                return Some("the evaluator aborted, the oracle folded".to_owned());
            }
        }
    }

    let theirs: Vec<OracleDisposition> = report
        .mappings
        .iter()
        .map(|m| translate(&m.disposition))
        .collect();
    if theirs.len() != oracle.dispositions.len() {
        return Some(format!(
            "totality disagrees — {} mappings vs {} dispositions",
            theirs.len(),
            oracle.dispositions.len()
        ));
    }
    if theirs != oracle.dispositions {
        return Some("intent dispositions disagree (absorption reasons included)".to_owned());
    }
    None
}

/// How many intents a program carries, across all statements.
fn intent_count(request: &TransactionRequest) -> usize {
    request
        .statements
        .iter()
        .map(|statement| statement.intents.len())
        .sum()
}

/// Reduce a program that satisfies `still_fails` to a locally minimal one.
///
/// The acceptance asks that a failure "auto-shrinks to a minimal program".
/// Greedy delta debugging: drop whole statements while the failure survives,
/// then drop individual intents, and repeat until a pass changes nothing.
/// Locally minimal rather than globally minimal -- no single further deletion
/// preserves the failure, which is the property a reader needs and is reachable
/// without searching subsets.
///
/// Deletion only. Nothing is mutated or reordered, so every candidate is a
/// sub-program of the original and a minimal result cannot exhibit a fault the
/// original did not.
///
/// CAVEAT, because the result is a diagnostic and not a replayable request:
/// `canonical_request_digest` and `tx_id` are carried over unchanged and no
/// longer describe the shrunken statements. That is sound here only because the
/// fold path reads neither -- verified by grep against `effect.rs` and
/// `fgit-txn/src/lib.rs`. A caller wanting to REPLAY a shrunken program must
/// rebuild it through `RequestBuilder` so those fields are recomputed.
fn shrink_to_minimal<F>(request: &TransactionRequest, still_fails: &F) -> TransactionRequest
where
    F: Fn(&TransactionRequest) -> bool,
{
    let mut best = request.clone();
    loop {
        let mut improved = false;

        // Whole statements first: one deletion can remove many intents, so the
        // cheap large reductions happen before the expensive small ones.
        let mut index = best.statements.len();
        while index > 0 {
            index -= 1;
            let mut candidate = best.clone();
            candidate.statements.remove(index);
            if still_fails(&candidate) {
                best = candidate;
                improved = true;
            }
        }

        // Then individual intents, including emptying a statement entirely --
        // an empty statement is still a statement and its mismatch policy may
        // be part of the fault.
        let mut statement = best.statements.len();
        while statement > 0 {
            statement -= 1;
            let mut intent = best.statements[statement].intents.len();
            while intent > 0 {
                intent -= 1;
                let mut candidate = best.clone();
                candidate.statements[statement].intents.remove(intent);
                if still_fails(&candidate) {
                    best = candidate;
                    improved = true;
                }
            }
        }

        if !improved {
            return best;
        }
    }
}

/// Translate the evaluator's disposition into the oracle's vocabulary.
///
/// The absorption reason is carried through rather than collapsed. Comparing on
/// a coarser projection would let the two sides agree while the distinction the
/// specification asks for went untested.
fn translate(disposition: &IntentDisposition) -> OracleDisposition {
    match disposition {
        IntentDisposition::Surviving(
            target
            @ (EffectTarget::Ref(_) | EffectTarget::Outbox(_) | EffectTarget::ForgeStream(_)),
        ) => OracleDisposition::Surviving(target.clone()),
        // A surviving effect at a target this model does not carry. The
        // original version mapped it silently onto StatementError, which would
        // have made an escaped model look like an ordinary refusal and agree
        // with an oracle that never generated it. Loud is correct here. Refs
        // and outbox deliveries are modelled; forge streams and retention roots
        // are stage 2.
        IntentDisposition::Surviving(other) => panic!(
            "the corpus produced a surviving effect at a non-ref target ({other:?}); this \
             model generates ref intents only, so either the generator or the evaluator has \
             moved and the comparison is no longer testing what it claims"
        ),
        IntentDisposition::Absorbed(reason) => OracleDisposition::Absorbed(*reason),
        IntentDisposition::StatementError(code) => OracleDisposition::StatementError(*code),
        IntentDisposition::TransactionAborted => OracleDisposition::TransactionAborted,
    }
}

#[test]
fn the_oracle_and_the_evaluator_agree_on_every_generated_program() {
    let mut agreements = 0_usize;

    for i in 0..programs() {
        let seed = CORPUS_SEED.wrapping_add(i as u64);
        let mut rng = Rng::new(seed);
        let mut identity_mint = IdentityMint::new(seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut identity_mint, &basis, "corpus");

        // The acceptance asks that a failure auto-shrinks. A 10^5 campaign
        // that reports "seed 0x… disagrees" hands the reader a program of up to
        // a dozen intents to bisect by hand; the shrinker does it in the same
        // run, against the identical predicate that failed.
        if let Some(why) = disagreement(&basis, &request) {
            let minimal = shrink_to_minimal(&request, &|candidate| {
                disagreement(&basis, candidate).is_some()
            });
            panic!(
                "seed {seed:#x}: {why}\n\
                 shrunk from {} statements / {} intents to {} statements / {} intents, and no \
                 single further deletion preserves the disagreement:\n{:#?}",
                request.statements.len(),
                intent_count(&request),
                minimal.statements.len(),
                intent_count(&minimal),
                minimal.statements
            );
        }
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
        let mut identity_mint = IdentityMint::new(seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut identity_mint, &basis, "totality");

        let total: usize = request
            .statements
            .iter()
            .map(|statement| statement.intents.len())
            .sum();
        let oracle = oracle_fold(&basis, &request);

        assert_eq!(
            oracle.dispositions.len(),
            total,
            "seed {seed:#x}: {total} source intents produced {} dispositions; an intent that \
             never ran still has a fate",
            oracle.dispositions.len()
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
        let case_seed = CORPUS_SEED.wrapping_add(i as u64);
        let mut rng = Rng::new(case_seed);
        let mut identity_mint = IdentityMint::new(case_seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut identity_mint, &basis, "coverage");
        for disposition in oracle_fold(&basis, &request).dispositions {
            seen.insert(match disposition {
                OracleDisposition::Surviving(_) => "surviving".to_owned(),
                OracleDisposition::Absorbed(reason) => format!("absorbed:{reason:?}"),
                OracleDisposition::StatementError(code) => format!("statement-error:{code:?}"),
                OracleDisposition::TransactionAborted => "aborted".to_owned(),
            });
        }
    }

    for required in [
        "surviving",
        "absorbed:OverwrittenBySucceedingIntent",
        "absorbed:PreconditionMismatchNoOp",
        "statement-error:ExpectedOldRefMismatch",
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
fn every_absorption_reason_including_duplicate_delivery_is_reached() {
    // Was `the_unmodelled_arms_are_named_rather_than_quietly_absent`, asserting
    // that `DuplicateIdenticalDelivery` was NOT reachable. The carrier now
    // emits outbox intents, so the gap is closed and the assertion is inverted
    // in the same commit that closes it -- removing it a commit early is how a
    // coverage claim quietly widens.
    let mut seen: BTreeSet<AbsorptionReason> = BTreeSet::new();
    for i in 0..programs() {
        let case_seed = CORPUS_SEED.wrapping_add(i as u64);
        let mut rng = Rng::new(case_seed);
        let mut identity_mint = IdentityMint::new(case_seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut identity_mint, &basis, "gaps");
        for disposition in oracle_fold(&basis, &request).dispositions {
            if let OracleDisposition::Absorbed(reason) = disposition {
                seen.insert(reason);
            }
        }
    }

    assert!(
        seen.contains(&AbsorptionReason::DuplicateIdenticalDelivery),
        "the corpus must redeliver an outbox key with identical canonical parameters; without \
         it the permitted twin of EffectIdempotencyKeyReuse is untested, and a folder that \
         refused every redelivery would pass the refusal half alone. Reached: {seen:?}"
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
        // Same fixture the oracle seeds, so these stay consistent if a forge
        // intent is ever added to this hand-built request.
        let forge = forge_basis();
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
    const {
        assert!(
            CAMPAIGN_PROGRAMS >= 100_000,
            "the acceptance asks for at least 10^5 seeded programs"
        );
        assert!(
            DEFAULT_PROGRAMS < CAMPAIGN_PROGRAMS,
            "the default must be the cheap one; if they are equal the gate is pointless"
        );
    }
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
/// Pinned per `GoldLotus`'s instruction so the case survives as a regression
/// artifact regardless of how the contract rules.
const PROVENANCE_AMBIGUITY_SEED: u64 = 0x05EE_D000_8B00_B1F2;

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
    let mut identity_mint = IdentityMint::new(PROVENANCE_AMBIGUITY_SEED);
    let basis = generate_basis(&mut rng);
    let request = generate_request(&mut rng, &mut identity_mint, &basis, "corpus");

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
    // Same fixture the oracle seeds; see above.
    let forge = forge_basis();
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
    let oracle = oracle_fold(&basis, &request);

    if let FoldOutcome::Folded(effects) = &report.outcome {
        assert_eq!(
            effects.refs, oracle.refs,
            "the pinned case must differ ONLY in provenance; the net effects have diverged, \
             which makes this a different and more serious disagreement"
        );
    }
}

/// The intent-relevant refusal taxonomy.
///
/// `RefusalCode` has 61 variants; the folder emits exactly these four on the
/// intent path. Enumerated here so "exhaustive over the refusal taxonomy
/// relevant to intents" is a checkable claim rather than a feeling.
const INTENT_REFUSAL_TAXONOMY: [RefusalCode; 4] = [
    RefusalCode::ExpectedOldRefMismatch,
    RefusalCode::EffectIdempotencyKeyReuse,
    RefusalCode::ForgeTransitionInvalid,
    RefusalCode::ResourceBudgetExceeded,
];

#[test]
fn the_intent_refusal_taxonomy_is_exhaustively_reached() {
    // The acceptance asks for a refusal corpus exhaustive over the taxonomy
    // relevant to intents. This states exactly how far that is met, because a
    // corpus reaching one of four codes while claiming exhaustiveness is worse
    // than one that admits the gap.
    //
    // Reasons verified at the emission sites in `fgit-reference/src/effect.rs`,
    // not inferred from the code names. One of them was inferred first and was
    // wrong, which is why they are now cited by mechanism:
    //
    //   ExpectedOldRefMismatch     REACHED — every precondition mismatch under
    //                              MismatchPolicy::StatementError.
    //   ForgeTransitionInvalid     Intent::Forge only, when the stream's
    //                              current position != expected_position.
    //   ResourceBudgetExceeded     Intent::Forge only, when the stream position
    //                              is_exhausted(). NOTE: despite the name this
    //                              is NOT a general budget or count refusal —
    //                              it is forge-stream exhaustion specifically.
    //                              An earlier version of this comment guessed
    //                              "needs a declared budget the generator can
    //                              exceed", which would have sent whoever
    //                              extended this model looking for the wrong
    //                              lever.
    //   EffectIdempotencyKeyReuse  Intent::Outbox only, same delivery key with
    //                              DIFFERENT canonical parameters. Same key
    //                              with identical parameters is the separate
    //                              Absorbed(DuplicateIdenticalDelivery) arm.
    //
    // STAGE 2 LANDED: the carrier now emits forge transitions as well as
    // outbox deliveries, and all four intent-relevant codes are reached. The
    // acceptance line -- "exhaustive over the refusal taxonomy relevant to
    // intents" -- is met by REACHING the taxonomy, not by narrowing it.
    //
    // Worth keeping: the tempting way to "meet" this line was to shrink
    // INTENT_REFUSAL_TAXONOMY to the one code a refs-only corpus reached.
    // That is editing the gate to fit the result, and this constant is
    // deliberately declared above the test so the two cannot be adjusted
    // together without it being obvious in a diff.
    //
    // ResourceBudgetExceeded is reached only because `forge_basis()` seeds a
    // stream at u64::MAX. Scratch positions advance through a saturating
    // successor(), so no generator reaches exhaustion by advancing -- it is
    // 2^64 steps away. Delete that seed and this test fails, which is the
    // intended relationship between the two.
    let mut reached: BTreeSet<RefusalCode> = BTreeSet::new();
    for i in 0..programs() {
        let seed = CORPUS_SEED.wrapping_add(i as u64);
        let mut rng = Rng::new(seed);
        let mut mint = IdentityMint::new(seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut mint, &basis, "taxonomy");
        for disposition in oracle_fold(&basis, &request).dispositions {
            if let OracleDisposition::StatementError(code) = disposition {
                reached.insert(code);
            }
        }
    }

    assert!(
        reached.contains(&RefusalCode::ExpectedOldRefMismatch),
        "the corpus must exercise a precondition mismatch; it is the one intent refusal a \
         refs-only model can reach, and without it the statement-error arm is untested"
    );

    // Every code, named individually rather than by a set comparison, so a
    // failure says WHICH code stopped being reached instead of reporting a
    // set difference the reader has to decode.
    for code in INTENT_REFUSAL_TAXONOMY {
        assert!(
            reached.contains(&code),
            "{code:?} is in the intent-relevant taxonomy and the corpus no longer reaches \
             it. Something narrowed the generator: check the intent-kind selector weights, \
             the two-wide outbox key/parameter alphabets (collisions are what reach the \
             outbox arms), and `forge_basis()`'s seeded exhausted stream. Reached: \
             {reached:?}"
        );
    }

    assert_eq!(
        reached.len(),
        INTENT_REFUSAL_TAXONOMY.len(),
        "the corpus should reach exactly the four intent refusal codes; \
         reaching more means the model grew and this claim needs updating, reaching none \
         means the statement-error path went untested. Reached: {reached:?}"
    );
}

#[test]
fn the_shrinker_reduces_a_planted_failure_to_its_minimum() {
    // The shrinker runs only on failure, and there are no failures -- so
    // without this test it would execute for the first time on the day it is
    // needed most, which is the day nobody wants to debug it. A safety net
    // nothing has ever pulled on is not a safety net.
    //
    // Planted rather than real, because manufacturing a genuine oracle/evaluator
    // disagreement would mean deliberately breaking one of them. The predicate
    // here has a KNOWN minimum instead: "this program still contains at least
    // one intent" is satisfied by exactly one intent and by nothing smaller, so
    // the expected result is checkable rather than eyeballed.
    let mut rng = Rng::new(CORPUS_SEED);
    let mut mint = IdentityMint::new(CORPUS_SEED);
    let basis = generate_basis(&mut rng);

    // Find a program with enough structure to exercise BOTH loops: more than
    // one statement, and more than one intent.
    let mut request = generate_request(&mut rng, &mut mint, &basis, "shrink");
    for _ in 0..64 {
        if request.statements.len() > 1 && intent_count(&request) > 2 {
            break;
        }
        request = generate_request(&mut rng, &mut mint, &basis, "shrink");
    }
    assert!(
        request.statements.len() > 1 && intent_count(&request) > 2,
        "the planted program must be big enough that shrinking it means something; got {} \
         statements / {} intents",
        request.statements.len(),
        intent_count(&request)
    );

    let before_statements = request.statements.len();
    let before_intents = intent_count(&request);
    let minimal = shrink_to_minimal(&request, &|candidate| {
        candidate
            .statements
            .iter()
            .any(|statement| !statement.intents.is_empty())
    });

    // It reduced.
    assert!(
        intent_count(&minimal) < before_intents,
        "the shrinker returned a program no smaller than the original ({before_intents} \
         intents); a shrinker that cannot shrink reports the failure it was given"
    );

    // It reduced to the KNOWN minimum, and not past it. Stopping short would
    // leave a reader bisecting by hand; going past would mean it returned a
    // program that does not exhibit the fault at all, which is worse than not
    // shrinking.
    assert_eq!(
        intent_count(&minimal),
        1,
        "the predicate holds for exactly one intent, so a locally minimal program has exactly \
         one; got {} intents across {} statements (from {before_statements} / {before_intents})",
        intent_count(&minimal),
        minimal.statements.len()
    );
    assert_eq!(
        minimal.statements.len(),
        1,
        "an empty statement can always be deleted while the predicate holds, so none should \
         survive; got {} statements",
        minimal.statements.len()
    );

    // The invariant that makes the result trustworthy: the returned program
    // still satisfies the predicate it was minimised against.
    assert!(
        minimal
            .statements
            .iter()
            .any(|statement| !statement.intents.is_empty()),
        "the shrinker returned a program that no longer satisfies the predicate; a minimal \
         program that does not reproduce is a false lead, not a smaller lead"
    );
}

#[test]
fn the_normal_form_applied_to_the_basis_reproduces_the_evaluated_workspace() {
    // FG-008 epic acceptance, line 2: "apply(normal_form, basis) ==
    // evaluator-final-workspace for the whole reference corpus".
    //
    // This is a DIFFERENT property from the equivalence campaign above, and the
    // difference is the reason it is worth having. That campaign compares the
    // two folders' outputs — `effects.refs` against the oracle's diff, and the
    // dispositions. This one closes the loop: it takes the normal form the
    // evaluator produced, applies it to the basis, and requires the result to
    // equal the state that ORDERED evaluation with read-your-own-writes
    // reached. Folding is target-disjoint and unordered; evaluation is ordered.
    // They agree only if the fold preserved semantics.
    //
    // It also covers three effect classes nothing else here checks. The
    // equivalence campaign asserts `effects.refs` and stops, so a fold that
    // mangled forge events or outbox bindings passes it today. This compares
    // refs, forge and outbox together.
    let evaluator = IntentEvaluator::new();
    let mut non_trivial = 0_usize;
    let mut aborted = 0_usize;

    for i in 0..programs() {
        let seed = CORPUS_SEED.wrapping_add(i as u64);
        let mut rng = Rng::new(seed);
        let mut identity_mint = IdentityMint::new(seed);
        let basis = generate_basis(&mut rng);
        let request = generate_request(&mut rng, &mut identity_mint, &basis, "roundtrip");

        let forge_positions = forge_basis();
        let retention = BTreeSet::new();
        let outbox = BTreeMap::new();
        let report = evaluator.evaluate(
            FoldBasis {
                refs: &basis,
                forge_positions: &forge_positions,
                retention: &retention,
                outbox: &outbox,
            },
            &request,
        );
        let oracle = oracle_fold(&basis, &request);

        // The basis carries no prior forge events, retention roots or outbox
        // bindings: `forge_basis()` seeds POSITIONS, which gate admission, and
        // the normal form carries the events this transaction appends.
        let basis_workspace = Workspace {
            refs: basis.clone(),
            ..Workspace::default()
        };

        let applied = match &report.outcome {
            FoldOutcome::Folded(effects) => {
                if !effects.is_empty() {
                    non_trivial += 1;
                }
                apply_net_effects(&basis_workspace, effects)
            }
            // An aborted transaction publishes nothing, so applying its (empty)
            // normal form must leave the basis exactly as it was.
            FoldOutcome::Aborted { .. } => {
                aborted += 1;
                apply_net_effects(&basis_workspace, &NetEffects::default())
            }
        };

        let expected = Workspace {
            refs: oracle.final_refs.clone(),
            forge: oracle.final_forge.clone(),
            retention: BTreeSet::new(),
            outbox: oracle.final_outbox.clone(),
        };

        assert_eq!(
            applied, expected,
            "seed {seed:#x}: applying the normal form to the basis did not reproduce the state \
             ordered evaluation reached. The fold lost or invented information: an unordered, \
             target-disjoint effect set must be interchangeable with replaying the intents in \
             source order, and here it is not"
        );
    }

    // Non-vacuity. A corpus whose programs all folded to nothing would satisfy
    // every assertion above by comparing two copies of the basis.
    assert!(
        non_trivial > 0,
        "no generated program produced a non-empty normal form, so the round-trip compared the \
         basis against itself every time and proved nothing"
    );
    assert!(
        aborted > 0,
        "no generated program aborted, so the publishes-nothing half of the property is untested; \
         the generator emits MismatchPolicy::TxnAbort and should reach it"
    );
}
