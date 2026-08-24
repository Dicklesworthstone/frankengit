//! Rendezvous scoring. `frankengit-fg036a`.
//!
//! The selection policy is tested in `fgit-types`; these cases are about the
//! score itself — that its preimage is unambiguous, that it is stable, and that
//! it delivers the minimal-disruption property that is the whole reason to use
//! rendezvous hashing instead of modular arithmetic.

use std::collections::BTreeMap;

use fgit_crypto::{combiner_order, placement_score, preferred_combiner};
use fgit_types::routing::PlacementCandidate;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Cell(&'static str);

impl PlacementCandidate for Cell {
    fn placement_key(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

const CELLS: [Cell; 6] = [
    Cell("cell-alpha"),
    Cell("cell-bravo"),
    Cell("cell-charlie"),
    Cell("cell-delta"),
    Cell("cell-echo"),
    Cell("cell-foxtrot"),
];

/// A spread of routing keys, enough to see placement behaviour rather than luck.
fn keys() -> Vec<String> {
    (0..240)
        .map(|index| format!("refs/heads/topic-{index}"))
        .collect()
}

#[test]
fn the_length_prefix_stops_the_two_fields_from_borrowing_bytes() {
    // The collision this preimage is shaped to avoid. Concatenated plainly,
    // ("ab", "c") and ("a", "bc") are the same byte string, and two different
    // cells would tie on a key for a reason nobody chose.
    assert_ne!(
        placement_score(b"ab", b"c"),
        placement_score(b"a", b"bc"),
        "the candidate and the routing key must not be able to borrow each other's bytes"
    );

    // Two more shapes of the same hazard, including the empty-field case where
    // a length prefix is the only thing distinguishing them at all.
    assert_ne!(placement_score(b"", b"xy"), placement_score(b"xy", b""));
    assert_ne!(placement_score(b"x", b""), placement_score(b"", b"x"));
}

#[test]
fn scoring_is_deterministic_and_depends_on_both_inputs() {
    let baseline = placement_score(b"cell-alpha", b"refs/heads/main");
    for _ in 0..8 {
        assert_eq!(placement_score(b"cell-alpha", b"refs/heads/main"), baseline);
    }
    assert_ne!(
        placement_score(b"cell-bravo", b"refs/heads/main"),
        baseline,
        "a different candidate must score differently"
    );
    assert_ne!(
        placement_score(b"cell-alpha", b"refs/heads/next"),
        baseline,
        "a different key must score differently"
    );
}

#[test]
fn the_preference_is_the_head_of_the_ranking() {
    // If these disagreed, a caller retrying down the fallback list would start
    // somewhere other than where the preference sent it.
    for key in keys().iter().take(32) {
        let ranked = combiner_order(&CELLS, key.as_bytes());
        assert_eq!(ranked.len(), CELLS.len(), "every candidate must be ranked");
        assert_eq!(
            preferred_combiner(&CELLS, key.as_bytes()),
            Some(ranked[0]),
            "{key}: preference and ranking must agree"
        );
    }
}

#[test]
fn removing_one_cell_moves_only_the_keys_that_cell_held() {
    // The minimal-disruption property, measured exactly rather than sampled.
    // This is the entire reason to prefer rendezvous over modular hashing: with
    // `key % n`, changing n reshuffles almost everything.
    let all: Vec<Cell> = CELLS.to_vec();
    let before: BTreeMap<String, Cell> = keys()
        .into_iter()
        .map(|key| {
            let chosen = *preferred_combiner(&all, key.as_bytes()).expect("a preference");
            (key, chosen)
        })
        .collect();

    for departing in CELLS {
        let survivors: Vec<Cell> = all.iter().copied().filter(|c| *c != departing).collect();
        let mut moved = 0_usize;
        for (key, previous) in &before {
            let now = *preferred_combiner(&survivors, key.as_bytes()).expect("a preference");
            if *previous == departing {
                assert_ne!(
                    now, departing,
                    "{key}: the departed cell cannot still hold it"
                );
                moved += 1;
            } else {
                assert_eq!(
                    now, *previous,
                    "{key} was held by {previous:?}, which did not leave, so it must not move \
                     when {departing:?} does"
                );
            }
        }
        // And it must actually have held something, or the case above is vacuous
        // for this cell.
        assert!(
            moved > 0,
            "{departing:?} held no keys at all, so its removal proves nothing"
        );
    }
}

#[test]
fn adding_a_cell_only_takes_keys_and_never_shuffles_the_rest() {
    // The other direction of the same property: growth must not reshuffle.
    let smaller: Vec<Cell> = CELLS[..5].to_vec();
    let larger: Vec<Cell> = CELLS.to_vec();
    let joining = CELLS[5];

    let mut taken = 0_usize;
    for key in keys() {
        let before = *preferred_combiner(&smaller, key.as_bytes()).expect("a preference");
        let after = *preferred_combiner(&larger, key.as_bytes()).expect("a preference");
        if after == joining {
            taken += 1;
        } else {
            assert_eq!(
                after, before,
                "{key} did not move to the new cell, so it must not have moved at all"
            );
        }
    }
    assert!(
        taken > 0,
        "the joining cell took nothing, so this proves nothing"
    );
}

#[test]
fn keys_do_not_all_land_on_one_cell() {
    // Not a distribution claim and not a statistical test — no bound is
    // asserted on how even the spread is. It catches a scorer that ignores the
    // routing key, which every other test in this file would still pass.
    let mut held: BTreeMap<Cell, usize> = BTreeMap::new();
    for key in keys() {
        let chosen = *preferred_combiner(&CELLS, key.as_bytes()).expect("a preference");
        *held.entry(chosen).or_default() += 1;
    }
    assert_eq!(
        held.len(),
        CELLS.len(),
        "every cell should hold at least one of 240 keys; got {held:?}"
    );
}

#[test]
fn an_empty_candidate_set_has_no_preferred_combiner() {
    assert_eq!(preferred_combiner(&[] as &[Cell], b"refs/heads/main"), None);
    assert_eq!(
        combiner_order(&[] as &[Cell], b"refs/heads/main"),
        Vec::<&Cell>::new()
    );
}
