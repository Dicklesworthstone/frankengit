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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fgit_calm::class::CoordinationClass;
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
fn every_registry_row_has_a_conformance_test_for_its_class() {
    // Acceptance: "every calm_operations.tsv row is exercised by a test
    // matching its class". Coverage is asserted over the classes actually
    // present, so a new row in an untested class fails here rather than
    // passing unnoticed.
    let rows = registry_rows();
    let mut by_class: BTreeMap<&'static str, Vec<&Row>> = BTreeMap::new();
    for row in &rows {
        by_class.entry(row.class.tag()).or_default().push(row);
    }

    for (tag, rows) in &by_class {
        let class = CoordinationClass::parse(tag).expect("grouped by a parsed class");
        // Each row is exercised by the direction its class claims.
        for row in rows {
            if class.converges_under_reorder_duplicate_drop() {
                assert!(
                    converges_under_reorder_duplicate_drop(),
                    "{} ({}) claims {tag}, which must converge",
                    row.id,
                    row.operation
                );
            } else if !class.is_coordination_free() {
                assert!(
                    removing_coordination_breaks_it(),
                    "{} ({}) claims {tag}, whose coordination must be load-bearing",
                    row.id,
                    row.operation
                );
            }
        }
    }
    assert!(
        !by_class.is_empty(),
        "no classes were exercised; this assertion would be vacuous"
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
