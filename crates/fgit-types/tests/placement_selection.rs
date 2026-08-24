//! Preferred-combiner selection. `frankengit-fg036a`.
//!
//! Selection policy only: these cases supply their own scorer, because what
//! must be deterministic and observable per §8 is the tie-break and the order
//! independence, not the choice of hash.

use fgit_types::routing::{
    PlacementCandidate, PlacementScore, placement_order, preferred_candidate,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cell(&'static str);

impl PlacementCandidate for Cell {
    fn placement_key(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A scorer that mixes the candidate and the key without being a real hash.
///
/// Deliberately not cryptographic: these tests are about selection policy, and
/// using a real digest here would make the expected answers unreadable without
/// proving anything extra about the policy.
fn scorer(key: &'static [u8]) -> impl Fn(&Cell) -> PlacementScore {
    move |cell: &Cell| {
        let mut bytes = [0_u8; 32];
        let mut accumulator: u8 = 17;
        for (index, byte) in cell.0.as_bytes().iter().chain(key).enumerate() {
            accumulator = accumulator
                .wrapping_mul(31)
                .wrapping_add(*byte)
                .wrapping_add(u8::try_from(index % 256).unwrap_or_default());
        }
        bytes[0] = accumulator;
        PlacementScore::from_bytes(bytes)
    }
}

/// Every candidate scores identically, so only the tie-break can decide.
const fn degenerate(_: &Cell) -> PlacementScore {
    PlacementScore::from_bytes([7_u8; 32])
}

fn cells() -> Vec<Cell> {
    vec![
        Cell("cell-a"),
        Cell("cell-b"),
        Cell("cell-c"),
        Cell("cell-d"),
    ]
}

#[test]
fn an_empty_candidate_set_has_no_preference() {
    // Inventing a preference from nothing would be a routing decision made out
    // of thin air, and the caller could not tell it from a real one.
    assert_eq!(
        preferred_candidate(&[] as &[Cell], scorer(b"refs/heads/main")),
        None
    );
    assert_eq!(
        placement_order(&[] as &[Cell], scorer(b"refs/heads/main")),
        Vec::<&Cell>::new()
    );
}

#[test]
fn selection_does_not_depend_on_the_order_candidates_are_listed() {
    // Two cells with the same membership view must agree, even if one of them
    // enumerated a map and the other read a config file. This is the property
    // that a "first wins" tie-break would quietly destroy.
    let forward = cells();
    let mut reversed = cells();
    reversed.reverse();
    let mut rotated = cells();
    rotated.rotate_left(2);

    let expected = preferred_candidate(&forward, scorer(b"refs/heads/main")).copied();
    assert!(expected.is_some());
    for (label, arrangement) in [("reversed", reversed), ("rotated", rotated)] {
        assert_eq!(
            preferred_candidate(&arrangement, scorer(b"refs/heads/main")).copied(),
            expected,
            "{label}: selection must not depend on enumeration order"
        );
    }
}

#[test]
fn a_tie_breaks_on_the_lowest_key_not_on_position() {
    // With every score equal, position is the only other thing available, so
    // this is the case that proves position is not what is used.
    let forward = cells();
    let mut reversed = cells();
    reversed.reverse();

    assert_eq!(
        preferred_candidate(&forward, degenerate),
        Some(&Cell("cell-a")),
        "the lowest placement key must win a tie"
    );
    assert_eq!(
        preferred_candidate(&reversed, degenerate),
        Some(&Cell("cell-a")),
        "and it must still win when it is listed last"
    );

    assert_eq!(
        placement_order(&reversed, degenerate)
            .into_iter()
            .map(|cell| cell.0)
            .collect::<Vec<_>>(),
        vec!["cell-a", "cell-b", "cell-c", "cell-d"],
        "a fully tied ranking must be key order, not input order"
    );
}

#[test]
fn removing_a_candidate_that_was_not_preferred_changes_nothing() {
    // The rendezvous property, and the reason this is not modular hashing:
    // membership churn must move only the keys the departing cell held.
    for key in [
        b"refs/heads/main".as_slice(),
        b"refs/heads/next".as_slice(),
        b"refs/tags/v1".as_slice(),
        b"refs/heads/topic/long-name".as_slice(),
    ] {
        let all = cells();
        let scored = scorer(key);
        let preferred = *preferred_candidate(&all, &scored).expect("a preference");

        let survivors: Vec<Cell> = all
            .iter()
            .copied()
            .filter(|cell| *cell != preferred)
            .collect();
        // Drop a cell that was NOT preferred: pick the last survivor.
        let dropped = *survivors.last().expect("three survivors");
        let reduced: Vec<Cell> = all
            .iter()
            .copied()
            .filter(|cell| *cell != dropped)
            .collect();

        assert_eq!(
            preferred_candidate(&reduced, &scored).copied(),
            Some(preferred),
            "removing {dropped:?}, which was not preferred, must not move this key"
        );
    }
}

#[test]
fn removing_the_preferred_candidate_falls_to_the_next_in_the_same_order() {
    // The fallback list and the preference must not disagree about "second",
    // or a cell retrying after a timeout would try a different cell than the
    // one the ranking named.
    let all = cells();
    let ranked: Vec<Cell> = placement_order(&all, scorer(b"refs/heads/main"))
        .into_iter()
        .copied()
        .collect();
    assert_eq!(ranked.len(), 4);
    assert_eq!(
        preferred_candidate(&all, scorer(b"refs/heads/main")).copied(),
        Some(ranked[0]),
        "the head of the ranking must be the preference"
    );

    let reduced: Vec<Cell> = all.into_iter().filter(|cell| *cell != ranked[0]).collect();
    assert_eq!(
        preferred_candidate(&reduced, scorer(b"refs/heads/main")).copied(),
        Some(ranked[1]),
        "losing the preferred cell must fall to the ranking's second, not somewhere new"
    );
}

#[test]
fn selection_is_deterministic_across_repeated_calls() {
    let all = cells();
    let first = preferred_candidate(&all, scorer(b"refs/heads/main")).copied();
    for _ in 0..16 {
        assert_eq!(
            preferred_candidate(&all, scorer(b"refs/heads/main")).copied(),
            first
        );
    }
}

#[test]
fn different_keys_do_not_all_land_on_one_candidate() {
    // Not a distribution claim — the scorer here is not a hash and this makes
    // no statistical assertion. It only catches a selector that ignores the key
    // entirely, which every other test in this file would still pass.
    let all = cells();
    let mut chosen: Vec<&'static str> = [
        b"refs/heads/main".as_slice(),
        b"refs/heads/next".as_slice(),
        b"refs/tags/v1".as_slice(),
        b"refs/heads/release".as_slice(),
        b"refs/heads/topic".as_slice(),
        b"refs/notes/commits".as_slice(),
    ]
    .into_iter()
    .map(|key| {
        let scored = scorer(key);
        preferred_candidate(&all, scored).expect("a preference").0
    })
    .collect();
    chosen.sort_unstable();
    chosen.dedup();
    assert!(
        chosen.len() > 1,
        "every key chose the same cell, so the key is being ignored"
    );
}
