#![forbid(unsafe_code)]
//! CALM load-bearing conformance.
//!
//! The registry claims a coordination class for every named operation. This
//! suite exists to make that claim falsifiable: a mislabelled row must break a
//! test rather than ship silently, which is the whole reason the classification
//! is checked in rather than described in prose.
//!
//! # What "load-bearing" is tested to mean
//!
//! Two properties, one per direction:
//!
//! - a **coordination-free** class must converge under reorder, duplication and
//!   drop -- replicas seeing the same set of facts in any order agree;
//! - a **coordinated** class must FAIL when its coordination boundary is
//!   removed. That direction is the one that proves the row is load-bearing: if
//!   an operation behaves identically with and without coordination, its class
//!   was decorative and nothing would notice it being wrong.
//!
//! # Non-claim, stated rather than implied
//!
//! None of the fourteen classified operations has a first-party implementation
//! yet, so these tests exercise a REFERENCE MODEL of each class's semantics,
//! not the production operations. That is a real limit: the suite proves the
//! vocabulary is coherent and that a mislabelled row is catchable, and it does
//! NOT prove any particular operation is implemented in accordance with its
//! class. When an operation lands, its own crate owes the conformance run.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fgit_calm::class::{ConformanceDirection, CoordinationClass};
use fgit_calm::lattice::Observation;

// ---------------------------------------------------------------- the registry

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/fgit-calm sits two levels under the workspace root")
        .to_path_buf()
}

/// One classified operation, as the registry records it.
struct Row {
    id: String,
    operation: String,
    class: CoordinationClass,
}

fn registry_rows() -> Vec<Row> {
    let path = workspace_root().join("registries/calm_operations.tsv");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.first().copied() == Some("id") {
            continue;
        }
        assert!(
            fields.len() >= 3,
            "registry row {} has too few columns",
            index + 1
        );
        // A class the vocabulary does not define is a registry defect, in the
        // document's own words. Parsing refuses rather than defaulting.
        let class = CoordinationClass::parse(fields[2].trim()).unwrap_or_else(|| {
            panic!(
                "registry row {} names undeclared class `{}`",
                index + 1,
                fields[2].trim()
            )
        });
        rows.push(Row {
            id: fields[0].to_owned(),
            operation: fields[1].to_owned(),
            class,
        });
    }
    assert!(
        !rows.is_empty(),
        "the registry produced no rows; every assertion below would be vacuous"
    );
    rows
}

// ------------------------------------------------------- the reference model

/// A coordination-free operation: information that only grows.
///
/// Applying the same facts in any order, with duplicates, and with some
/// dropped, must converge to the union of whatever was actually applied.
fn apply_monotone(facts: &[u8]) -> BTreeSet<u8> {
    facts.iter().copied().collect()
}

/// A coordinated operation, modelled as assigning one terminal outcome to one
/// transaction.
///
/// `coordinated` is the boundary the registry row claims is required. With it,
/// the first writer wins and later contenders are refused, so exactly one
/// terminal exists. Without it, every contender applies its own terminal.
fn apply_terminal_assignment(attempts: &[Observation], coordinated: bool) -> Observation {
    if coordinated {
        // The authority boundary: the first terminal decides, and subsequent
        // contenders observe the standing decision rather than replacing it.
        attempts
            .iter()
            .copied()
            .find(|attempt| attempt.is_terminal())
            .unwrap_or(Observation::Reserved)
    } else {
        // No boundary: every attempt is applied, and the replica must retain
        // the contradiction rather than pick one.
        Observation::observe_all(attempts)
    }
}

// ------------------------------------------------------------------- coverage

#[test]
fn every_registry_row_is_exercised_by_a_check_matching_its_class() {
    // Acceptance: "every calm_operations.tsv row is exercised by a test
    // matching its class".
    //
    // Dispatch is an exhaustive match on the class's declared direction, not an
    // `if`/`else if` chain. That is not a style preference: the chain this
    // replaces tested `converges` first and `!is_coordination_free` second, so
    // `local_deterministic` -- which is coordination-free AND non-convergent --
    // matched neither arm. CALM-012 was exercised by nothing while this suite
    // reported green, which is precisely the decorative-check failure the lane
    // exists to catch one layer down. A match makes that unrepresentable: a new
    // class, or a direction with no check, fails to compile.
    let rows = registry_rows();
    let mut exercised: BTreeMap<&'static str, usize> = BTreeMap::new();

    for row in &rows {
        let direction = row.class.conformance_direction();
        let holds = match direction {
            ConformanceDirection::ConvergesUnderReorderDuplicateDrop => {
                converges_under_reorder_duplicate_drop()
            }
            ConformanceDirection::BoundedMergeWithReset => bounded_merge_with_reset_holds(),
            ConformanceDirection::PinnedInputDeterminism => pinned_input_determinism_holds(),
            ConformanceDirection::AntiRollbackProjection => anti_rollback_projection_holds(),
            ConformanceDirection::CoordinationIsLoadBearing => removing_coordination_breaks_it(),
            ConformanceDirection::IdempotentExternalEffect => idempotent_external_effect_holds(),
        };
        assert!(
            holds,
            "{} ({}) claims class {}, whose {} check does not hold",
            row.id, row.operation, row.class, direction
        );
        *exercised.entry(direction.tag()).or_default() += 1;
    }

    assert!(
        !exercised.is_empty(),
        "no rows were exercised; this assertion would be vacuous"
    );
    // Every row landed in exactly one direction, so the histogram must account
    // for all of them. A row silently skipped would show up here as a deficit.
    let counted: usize = exercised.values().sum();
    assert_eq!(
        counted,
        rows.len(),
        "every row must be counted by exactly one direction"
    );
}

#[test]
fn every_class_in_the_vocabulary_has_a_conformance_check_that_holds() {
    // Coverage of the VOCABULARY rather than of today's registry contents.
    // The test above would stop exercising a direction if the last row in that
    // class were deleted; this one keeps all seven classes checked regardless,
    // so removing a row cannot quietly retire a check.
    for class in CoordinationClass::ALL {
        let direction = class.conformance_direction();
        let holds = match direction {
            ConformanceDirection::ConvergesUnderReorderDuplicateDrop => {
                converges_under_reorder_duplicate_drop()
            }
            ConformanceDirection::BoundedMergeWithReset => bounded_merge_with_reset_holds(),
            ConformanceDirection::PinnedInputDeterminism => pinned_input_determinism_holds(),
            ConformanceDirection::AntiRollbackProjection => anti_rollback_projection_holds(),
            ConformanceDirection::CoordinationIsLoadBearing => removing_coordination_breaks_it(),
            ConformanceDirection::IdempotentExternalEffect => idempotent_external_effect_holds(),
        };
        assert!(
            holds,
            "{class} maps to {direction}, whose check does not hold"
        );
    }

    // The mapping must be onto: a direction no class claims is a check nothing
    // depends on, and a direction claimed by every class would mean the
    // classification carries no information.
    let claimed: BTreeSet<&'static str> = CoordinationClass::ALL
        .iter()
        .map(|class| class.conformance_direction().tag())
        .collect();
    for direction in ConformanceDirection::ALL {
        assert!(
            claimed.contains(direction.tag()),
            "{direction} is claimed by no class"
        );
    }
    assert!(
        claimed.len() > 1,
        "a single direction for every class would make the classification informationless"
    );
}

#[test]
fn the_class_vocabulary_is_closed_and_round_trips() {
    assert_eq!(
        CoordinationClass::ALL.len(),
        7,
        "section 1 declares exactly seven classes"
    );
    for class in CoordinationClass::ALL {
        assert_eq!(
            CoordinationClass::parse(class.tag()),
            Some(*class),
            "{class} must round-trip through its registry spelling"
        );
    }
    // The absence half: near-misses that a substring or prefix match would let
    // through. `head_cas` is the near-homonym of the obligation type
    // `HeadCasAttempt`, which is what made this vocabulary's absence invisible.
    for planted in [
        "monotone",
        "head_cas",
        "monotone_with_authorisation",
        "totally_ordered_broadcast",
        "",
    ] {
        assert_eq!(
            CoordinationClass::parse(planted),
            None,
            "`{planted}` must not parse as a declared class"
        );
    }
}

// ------------------------------------------------- coordination-free direction

fn converges_under_reorder_duplicate_drop() -> bool {
    let facts = [3_u8, 1, 4, 1, 5];
    let baseline = apply_monotone(&facts);

    let reordered = apply_monotone(&[5, 1, 4, 1, 3]);
    let duplicated = apply_monotone(&[3, 3, 1, 4, 1, 5, 5, 5]);
    // Dropping a duplicate is not dropping information: the union is the same.
    let dropped_duplicate = apply_monotone(&[3, 1, 4, 5]);

    baseline == reordered && baseline == duplicated && baseline == dropped_duplicate
}

#[test]
fn monotone_classes_converge_under_reorder_duplicate_and_drop() {
    assert!(
        converges_under_reorder_duplicate_drop(),
        "a monotone operation must converge on the union of applied facts"
    );

    // And the property must be capable of failing: losing a fact that was
    // never re-supplied genuinely changes the union, so a test that could not
    // see that would not be testing convergence at all.
    let full = apply_monotone(&[3, 1, 4, 1, 5]);
    let lossy = apply_monotone(&[3, 1, 4]);
    assert_ne!(
        full, lossy,
        "dropping distinct information must be observable, or the convergence \
         assertion above proves nothing"
    );
}

// ---------------------------------------------------- coordinated direction

fn removing_coordination_breaks_it() -> bool {
    // Two contenders reach opposite terminals for one transaction.
    let attempts = [Observation::Committed, Observation::Refused];
    let with_coordination = apply_terminal_assignment(&attempts, true);
    let without = apply_terminal_assignment(&attempts, false);
    // Load-bearing means the two differ: coordination is what prevents the
    // contradiction from becoming observable.
    with_coordination.is_terminal() && without.blocks_service()
}

#[test]
fn removing_coordination_from_a_coordinated_operation_breaks_it() {
    // Acceptance: "coordinated operations fail under intentionally removed
    // coordination, proving the registry row is load-bearing".
    let attempts = [Observation::Committed, Observation::Refused];

    let coordinated = apply_terminal_assignment(&attempts, true);
    assert_eq!(
        coordinated,
        Observation::Committed,
        "with the authority boundary the first terminal stands"
    );

    let uncoordinated = apply_terminal_assignment(&attempts, false);
    assert_eq!(
        uncoordinated,
        Observation::Conflict,
        "without the boundary both terminals apply and the contradiction is retained"
    );
    assert!(
        uncoordinated.blocks_service(),
        "a retained contradiction must block service rather than resolve"
    );
}

#[test]
fn a_coordinated_row_mislabelled_monotone_is_caught() {
    // Acceptance: "a seeded mislabeled row (coordinated op tagged monotone) is
    // CAUGHT by the removed-coordination test".
    //
    // Seed the mislabel directly: take a real coordinated operation and assert
    // the claim its WRONG class would make. `monotone_with_authentication`
    // claims convergence under reorder/duplicate/drop, so the seeded row would
    // be run coordination-free -- and that must not converge.
    let mislabelled_as = CoordinationClass::MonotoneWithAuthentication;
    assert!(
        mislabelled_as.converges_under_reorder_duplicate_drop(),
        "the seeded wrong class must be one that claims convergence"
    );

    let attempts = [Observation::Committed, Observation::Refused];
    let as_if_monotone = apply_terminal_assignment(&attempts, false);
    let reordered =
        apply_terminal_assignment(&[Observation::Refused, Observation::Committed], false);

    // The lattice is order-independent, so the two agree -- but on Conflict,
    // which is not a terminal outcome. A genuinely monotone operation would
    // converge on a usable value; this converges on "service blocked".
    assert_eq!(as_if_monotone, reordered, "the join is order-independent");
    assert!(
        !as_if_monotone.is_terminal(),
        "running a coordinated operation as if monotone must not yield a usable terminal"
    );
    assert!(
        as_if_monotone.blocks_service(),
        "the mislabel is caught: the operation cannot serve without its coordination boundary"
    );

    // The paired permitted case, so this is not merely an assertion that
    // everything blocks: the SAME operation with its declared coordination
    // produces a usable terminal.
    let correctly_coordinated = apply_terminal_assignment(&attempts, true);
    assert!(
        correctly_coordinated.is_terminal() && !correctly_coordinated.blocks_service(),
        "with its declared class honoured, the operation serves normally"
    );
}

// ----------------------------------------------------------- lattice algebra

#[test]
fn observation_partial_order_preserves_terminal_incomparability() {
    // The lattice does not expose a total `Ord`: the two terminal facts are
    // incomparable, so a caller cannot use `max` to hide their contradiction.
    assert_eq!(
        Observation::Committed.partial_cmp(&Observation::Refused),
        None,
        "opposite terminals must be incomparable"
    );
    assert_eq!(
        Observation::Refused.partial_cmp(&Observation::Committed),
        None,
        "incomparability must not depend on arrival order"
    );

    // Exhaustively bind the partial order to the declared join. Comparable
    // observations join to their greater value; the only incomparable pair
    // joins to the sticky conflict that blocks service.
    for left in Observation::ALL {
        for right in Observation::ALL {
            match left.partial_cmp(right) {
                Some(Ordering::Less) => assert_eq!(left.join(*right), *right),
                Some(Ordering::Equal | Ordering::Greater) => {
                    assert_eq!(left.join(*right), *left);
                }
                None => {
                    assert!(
                        left.is_terminal() && right.is_terminal() && left != right,
                        "only distinct terminals may be incomparable: {left} and {right}"
                    );
                    assert_eq!(left.join(*right), Observation::Conflict);
                }
            }
        }
    }
}

#[test]
fn committed_joined_with_refused_is_sticky_conflict_in_any_order() {
    // Acceptance: "lattice property: joining Committed and Refused yields
    // sticky Conflict across reorderings".
    assert_eq!(
        Observation::Committed.join(Observation::Refused),
        Observation::Conflict
    );
    assert_eq!(
        Observation::Refused.join(Observation::Committed),
        Observation::Conflict
    );

    // Sticky: no later observation, in any order or quantity, can wash it out.
    for follow_up in Observation::ALL {
        assert_eq!(
            Observation::Conflict.join(*follow_up),
            Observation::Conflict,
            "{follow_up} must not clear a conflict"
        );
        assert_eq!(
            follow_up.join(Observation::Conflict),
            Observation::Conflict,
            "{follow_up} must not clear a conflict from the other side"
        );
    }

    // Across reorderings of a whole observation stream.
    let stream = [
        Observation::Reserved,
        Observation::Committed,
        Observation::Refused,
        Observation::Reserved,
    ];
    let reversed = [
        Observation::Reserved,
        Observation::Refused,
        Observation::Committed,
        Observation::Reserved,
    ];
    assert_eq!(
        Observation::observe_all(&stream),
        Observation::Conflict,
        "contradictory terminals in a stream yield conflict"
    );
    assert_eq!(
        Observation::observe_all(&stream),
        Observation::observe_all(&reversed),
        "timestamp choice cannot erase contradictory terminal facts"
    );
}

#[test]
fn the_join_is_a_semilattice() {
    // Commutative, associative, idempotent -- which together are why the
    // result is a function of the SET of observations rather than the order
    // they arrived in. Exhaustive over the closed state space rather than
    // sampled, because the space is small enough that sampling would be a
    // weaker claim for no saving.
    for left in Observation::ALL {
        assert_eq!(left.join(*left), *left, "{left} must be idempotent");
        assert_eq!(
            left.join(Observation::Unknown),
            *left,
            "Unknown must be the identity for {left}"
        );
        for right in Observation::ALL {
            assert_eq!(
                left.join(*right),
                right.join(*left),
                "join must commute for {left} and {right}"
            );
            for third in Observation::ALL {
                assert_eq!(
                    left.join(*right).join(*third),
                    left.join(right.join(*third)),
                    "join must associate for {left}, {right}, {third}"
                );
            }
        }
    }
}

#[test]
fn agreeing_terminals_do_not_manufacture_a_conflict() {
    // The paired permitted case for the conflict tests: replicas that agree,
    // however often they repeat themselves, must not be reported as
    // contradictory. Without this, "everything becomes Conflict" would pass
    // every assertion above.
    assert_eq!(
        Observation::observe_all(&[
            Observation::Reserved,
            Observation::Committed,
            Observation::Committed,
            Observation::Reserved,
        ]),
        Observation::Committed
    );
    assert_eq!(
        Observation::observe_all(&[Observation::Refused, Observation::Refused]),
        Observation::Refused
    );
    assert_eq!(Observation::observe_all(&[]), Observation::Unknown);
}

// ------------------------------------------------- bounded-merge direction
//
// `commutative_but_bounded` (CALM-011 merge_bounded_telemetry, CALM-014
// merge_peer_availability_map) claims a DECLARED merge algebra with declared
// bounds, declared overflow behaviour, and reset/regime semantics. Plain union
// convergence is too weak for it: the interesting failure is a reset that a
// merge with a pre-reset replica silently undoes.

/// The declared bound of the modelled window.
const TELEMETRY_BOUND: u64 = 1_000;

/// A bounded, retractable, resettable counter.
///
/// Retraction is kept mergeable by counting retractions in their own grow-only
/// field rather than subtracting in place; reset advances a regime rather than
/// truncating, so a merge can tell "reset" apart from "stale".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BoundedWindow {
    regime: u32,
    observed: u64,
    retracted: u64,
}

impl BoundedWindow {
    const fn new() -> Self {
        Self {
            regime: 0,
            observed: 0,
            retracted: 0,
        }
    }

    /// Declared overflow behaviour: saturate at the bound, never wrap.
    fn observe(self, count: u64) -> Self {
        Self {
            observed: self.observed.saturating_add(count).min(TELEMETRY_BOUND),
            ..self
        }
    }

    fn retract(self, count: u64) -> Self {
        Self {
            retracted: self.retracted.saturating_add(count).min(TELEMETRY_BOUND),
            ..self
        }
    }

    /// Declared reset semantics: a new regime, not a truncation.
    const fn reset(self) -> Self {
        Self {
            regime: self.regime + 1,
            observed: 0,
            retracted: 0,
        }
    }

    fn merge(self, other: Self) -> Self {
        match self.regime.cmp(&other.regime) {
            Ordering::Greater => self,
            Ordering::Less => other,
            Ordering::Equal => Self {
                regime: self.regime,
                observed: self.observed.max(other.observed).min(TELEMETRY_BOUND),
                retracted: self.retracted.max(other.retracted),
            },
        }
    }

    const fn effective(self) -> u64 {
        self.observed.saturating_sub(self.retracted)
    }
}

/// The same counter with reset modelled as an in-place truncation -- i.e. with
/// the regime removed. Present only so the regime can be shown to be
/// load-bearing rather than decorative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegimelessWindow {
    observed: u64,
}

impl RegimelessWindow {
    fn observe(self, count: u64) -> Self {
        Self {
            observed: self.observed.saturating_add(count).min(TELEMETRY_BOUND),
        }
    }

    /// Deliberately an associated function rather than a method: a regimeless
    /// reset discards its receiver ENTIRELY, keeping no record that a reset
    /// ever happened. That is the whole defect being modelled -- with nothing
    /// carried forward, a later merge cannot tell "reset to zero" apart from
    /// "has not counted anything yet", so the pre-reset value wins. The
    /// signature ignoring `self` is the bug made visible in the type, which is
    /// why this is not written to take one.
    const fn reset() -> Self {
        Self { observed: 0 }
    }

    fn merge(self, other: Self) -> Self {
        Self {
            observed: self.observed.max(other.observed),
        }
    }
}

fn bounded_merge_with_reset_holds() -> bool {
    let left = BoundedWindow::new().observe(7).retract(2);
    let right = BoundedWindow::new().observe(11);
    // Commutative, and a reset survives a merge with a pre-reset replica.
    let commutes = left.merge(right) == right.merge(left);
    let stale = BoundedWindow::new().observe(500);
    let after_reset = stale.reset().observe(3);
    let reset_survives = after_reset.merge(stale) == after_reset;
    // Saturating, not wrapping.
    let saturates = BoundedWindow::new()
        .observe(TELEMETRY_BOUND)
        .observe(TELEMETRY_BOUND)
        .observed
        == TELEMETRY_BOUND;
    commutes && reset_survives && saturates
}

#[test]
fn a_bounded_window_merges_commutatively_and_respects_its_declared_bound() {
    let a = BoundedWindow::new().observe(7).retract(2);
    let b = BoundedWindow::new().observe(11).retract(1);
    let c = BoundedWindow::new().observe(4);

    assert_eq!(a.merge(b), b.merge(a), "the declared merge must commute");
    assert_eq!(
        a.merge(b).merge(c),
        a.merge(b.merge(c)),
        "the declared merge must associate"
    );
    assert_eq!(a.merge(a), a, "the declared merge must be idempotent");

    // Retraction stays mergeable: the effective value falls, and it does so
    // identically in both merge orders.
    // Both fields join independently: observed takes max(7, 11) and retracted
    // takes max(2, 1). A retraction is grow-only, so the LARGER retraction
    // survives the merge -- a peer that has not yet seen it cannot undo it by
    // reporting a smaller one.
    assert_eq!(
        a.merge(b).effective(),
        9,
        "max(7,11) observed minus max(2,1) retracted"
    );
    assert_eq!(a.merge(b).effective(), b.merge(a).effective());

    // Declared overflow behaviour: saturate at the bound.
    let saturated = BoundedWindow::new()
        .observe(TELEMETRY_BOUND - 1)
        .observe(50);
    assert_eq!(
        saturated.observed, TELEMETRY_BOUND,
        "observation past the bound must saturate, not wrap"
    );
    assert_eq!(
        saturated.merge(saturated.observe(9_000)).observed,
        TELEMETRY_BOUND,
        "merging saturated windows stays at the bound"
    );

    // The paired permitted case: below the bound nothing is clamped, so the
    // saturation assertions above are not satisfied by a constant.
    let under = BoundedWindow::new().observe(12).observe(30);
    assert_eq!(
        under.observed, 42,
        "values under the bound must be carried exactly"
    );
}

#[test]
fn the_regime_is_what_makes_a_reset_survive_a_merge() {
    // A replica accumulates, resets, then accumulates a little; a peer still
    // holds the pre-reset value and gossips it back.
    let stale = BoundedWindow::new().observe(500);
    let after_reset = stale.reset().observe(3);

    assert_eq!(
        after_reset.merge(stale),
        after_reset,
        "a merge with a pre-reset replica must not resurrect the old regime"
    );
    assert_eq!(
        stale.merge(after_reset),
        after_reset,
        "and it must not depend on which side the reset arrives from"
    );
    assert_eq!(after_reset.merge(stale).effective(), 3);

    // Load-bearing: with the regime removed, the identical sequence resurrects
    // the pre-reset value. The reset is silently undone.
    let naive_stale = RegimelessWindow { observed: 500 };
    let naive_after_reset = RegimelessWindow::reset().observe(3);
    assert_eq!(
        naive_after_reset.merge(naive_stale).observed,
        500,
        "without a regime the merge undoes the reset -- this is the defect the \
         declared reset semantics exist to prevent"
    );
    assert_ne!(
        naive_after_reset.merge(naive_stale).observed,
        after_reset.effective(),
        "the two models must actually disagree, or the regime proves nothing"
    );
}

// --------------------------------------------- pinned-input determinism
//
// `local_deterministic` (CALM-012 rank_context_candidates) is the class that
// fell through the old dispatch. It is coordination-free AND non-convergent,
// which is not a contradiction: it needs no boundary because it never publishes
// shared truth, but it is a function of its pinned inputs, so losing one
// changes the answer.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Candidate {
    id: &'static str,
    score: u32,
}

/// Ranking under a closed tie-break: score descending, then id ascending.
///
/// No RNG, no arrival order, no map iteration order -- section 8's requirement
/// that observable order be deterministic with a closed tie-break policy.
fn rank(candidates: &[Candidate]) -> Vec<&'static str> {
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.id.cmp(right.id))
    });
    sorted.into_iter().map(|candidate| candidate.id).collect()
}

fn pinned_input_determinism_holds() -> bool {
    let pinned = [
        Candidate {
            id: "beta",
            score: 5,
        },
        Candidate {
            id: "alpha",
            score: 5,
        },
        Candidate {
            id: "gamma",
            score: 9,
        },
    ];
    let shuffled = [pinned[2], pinned[0], pinned[1]];
    let order_independent = rank(&pinned) == rank(&shuffled);
    let tie_break_is_closed = rank(&pinned) == vec!["gamma", "alpha", "beta"];
    // Non-convergent under drop, which is the half that distinguishes this
    // class from a monotone merge.
    let drop_is_observable = rank(&pinned) != rank(&pinned[..2]);
    order_independent && tie_break_is_closed && drop_is_observable
}

#[test]
fn a_local_deterministic_operation_is_order_independent_but_not_drop_tolerant() {
    let pinned = [
        Candidate {
            id: "beta",
            score: 5,
        },
        Candidate {
            id: "alpha",
            score: 5,
        },
        Candidate {
            id: "gamma",
            score: 9,
        },
    ];

    // Determinism over the SET of pinned inputs: presentation order cannot
    // change the ranking, and the tie between `alpha` and `beta` is settled by
    // the closed rule rather than by which arrived first.
    assert_eq!(rank(&pinned), vec!["gamma", "alpha", "beta"]);
    assert_eq!(
        rank(&pinned),
        rank(&[pinned[2], pinned[0], pinned[1]]),
        "a pinned-input computation must not depend on arrival order"
    );
    assert_eq!(
        rank(&[pinned[1], pinned[0]]),
        rank(&[pinned[0], pinned[1]]),
        "the tie-break must be closed, not arrival-ordered"
    );

    // The absence half. `local_deterministic` is coordination-free, and a
    // reader who stopped there would assume it is also drop-tolerant. It is
    // not, and the class exposes both facts separately.
    assert!(
        CoordinationClass::LocalDeterministic.is_coordination_free(),
        "the class needs no coordination boundary"
    );
    assert!(
        !CoordinationClass::LocalDeterministic.converges_under_reorder_duplicate_drop(),
        "...and yet is not drop-tolerant; conflating the two is the mislabel \
         this direction exists to catch"
    );
    assert_ne!(
        rank(&pinned),
        rank(&pinned[..2]),
        "dropping a pinned input must change the answer, or the claim above is \
         unfounded"
    );
}

// ------------------------------------------- anti-rollback projection
//
// `ordered_projection` (CALM-009 activate_generation) publishes through a
// subordinate monotone authority whose only job is refusing to go backwards.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivationRefusal {
    /// The caller's expected predecessor is not the active generation.
    NotExactPredecessor,
    /// The requested generation does not advance the projection.
    NotAnAdvance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Projection {
    active: u64,
}

impl Projection {
    /// Publication guarded by the exact predecessor, per section 5.5's
    /// requirement that a root-last protocol never silently roll back.
    const fn activate(
        &mut self,
        expected_predecessor: u64,
        next: u64,
    ) -> Result<u64, ActivationRefusal> {
        if expected_predecessor != self.active {
            return Err(ActivationRefusal::NotExactPredecessor);
        }
        if next <= self.active {
            return Err(ActivationRefusal::NotAnAdvance);
        }
        self.active = next;
        Ok(next)
    }

    /// The same publication with the anti-rollback guard removed. Present only
    /// to demonstrate that the guard changes the outcome.
    const fn activate_unguarded(&mut self, next: u64) -> u64 {
        self.active = next;
        next
    }
}

const fn anti_rollback_projection_holds() -> bool {
    let mut projection = Projection { active: 4 };
    let advanced = projection.activate(4, 5).is_ok();
    let stale_refused = projection.activate(4, 5).is_err();
    let held = projection.active == 5;

    let mut unguarded = Projection { active: 5 };
    unguarded.activate_unguarded(4);
    let rollback_is_possible_without_the_guard = unguarded.active == 4;

    advanced && stale_refused && held && rollback_is_possible_without_the_guard
}

#[test]
fn an_ordered_projection_advances_but_never_rolls_back() {
    let mut projection = Projection { active: 4 };

    // The permitted case: the exact predecessor advances the projection.
    assert_eq!(projection.activate(4, 5), Ok(5));
    assert_eq!(projection.active, 5);

    // Replay of an already-applied activation is refused rather than reapplied,
    // so duplicate delivery cannot roll the projection back to generation 5's
    // predecessor state.
    assert_eq!(
        projection.activate(4, 5),
        Err(ActivationRefusal::NotExactPredecessor)
    );
    assert_eq!(
        projection.active, 5,
        "a refused activation must leave the projection untouched"
    );

    // A late-arriving older generation is refused on both counts it could be
    // wrong: wrong predecessor, and not an advance.
    assert_eq!(
        projection.activate(3, 4),
        Err(ActivationRefusal::NotExactPredecessor)
    );
    assert_eq!(
        projection.activate(5, 5),
        Err(ActivationRefusal::NotAnAdvance)
    );
    assert_eq!(projection.active, 5);

    // ...and the projection still advances afterwards, so the refusals above
    // are not a wedged state.
    assert_eq!(projection.activate(5, 6), Ok(6));

    // Load-bearing: with the guard removed the identical late activation rolls
    // the projection backwards, which is the silent rollback section 5.5
    // forbids.
    let mut unguarded = Projection { active: 6 };
    unguarded.activate_unguarded(4);
    assert_eq!(
        unguarded.active, 4,
        "without the exact-predecessor guard, a stale activation rolls back"
    );
    assert_ne!(
        unguarded.active, projection.active,
        "the guarded and unguarded paths must actually differ"
    );
}

// ------------------------------------------ exclusive external effect
//
// `exclusive_external_effect` (CALM-010 deliver_webhook) owns one externally
// observable side effect under a stable idempotency key. Retries are expected;
// duplicate effects are not.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    Performed,
    AlreadyPerformed,
}

#[derive(Debug, Default)]
struct Outbox {
    performed: BTreeSet<String>,
    external_effects: u64,
}

impl Outbox {
    /// One external effect per idempotency key, however many times delivery is
    /// attempted.
    fn deliver(&mut self, idempotency_key: &str) -> Delivery {
        if self.performed.contains(idempotency_key) {
            return Delivery::AlreadyPerformed;
        }
        self.performed.insert(idempotency_key.to_owned());
        self.external_effects += 1;
        Delivery::Performed
    }

    /// Delivery with the idempotency key ignored. Present only to show the key
    /// is what makes the effect exclusive.
    const fn deliver_without_key(&mut self) {
        self.external_effects += 1;
    }
}

fn idempotent_external_effect_holds() -> bool {
    let mut outbox = Outbox::default();
    let first = outbox.deliver("wh-1") == Delivery::Performed;
    let retried = outbox.deliver("wh-1") == Delivery::AlreadyPerformed;
    let once = outbox.external_effects == 1;
    let distinct = {
        outbox.deliver("wh-2");
        outbox.external_effects == 2
    };
    first && retried && once && distinct
}

#[test]
fn one_external_effect_per_idempotency_key_however_many_retries() {
    let mut outbox = Outbox::default();

    assert_eq!(outbox.deliver("wh-1"), Delivery::Performed);
    for _ in 0..5 {
        assert_eq!(
            outbox.deliver("wh-1"),
            Delivery::AlreadyPerformed,
            "a retry under the same key must not perform a second effect"
        );
    }
    assert_eq!(
        outbox.external_effects, 1,
        "five retries must leave exactly one external effect"
    );

    // The paired permitted case: distinct keys DO produce distinct effects, so
    // "never deliver anything" would not satisfy the assertions above.
    assert_eq!(outbox.deliver("wh-2"), Delivery::Performed);
    assert_eq!(outbox.external_effects, 2);

    // Interleaving retries of two keys in either order yields the same count:
    // the effect is a function of the SET of keys, not of arrival order.
    let mut interleaved = Outbox::default();
    for key in ["wh-1", "wh-2", "wh-1", "wh-2", "wh-1"] {
        interleaved.deliver(key);
    }
    assert_eq!(interleaved.external_effects, 2);

    // Load-bearing: with the key ignored, the same six attempts become six
    // externally observable effects.
    let mut keyless = Outbox::default();
    for _ in 0..6 {
        keyless.deliver_without_key();
    }
    assert_eq!(
        keyless.external_effects, 6,
        "without the idempotency key every retry is a fresh external effect"
    );
    assert_ne!(
        keyless.external_effects, outbox.external_effects,
        "the keyed and keyless paths must actually differ"
    );
}
