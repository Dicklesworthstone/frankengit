//! Turning hints off changes latency, not answers. `frankengit-fg036a`, line 1.
//!
//! # What this is, stated precisely, because the acceptance line asks for more
//!
//! Acceptance line 1 wants a differential over N real cell processes sharing
//! one authority backend. This is **not** that. It is a differential over the
//! *hint layer* — routing preference, gossip, and the [`Hint`] discipline — run
//! against a modelled authority in one process.
//!
//! It is worth having on its own because it isolates the claim to the machinery
//! that could actually break it. If a hint ever decides an outcome, it does so
//! in this layer, and no amount of process separation would fix it. The
//! multi-process differential adds the things this cannot see — scheduling,
//! partition, concurrent heads — and is still outstanding.
//!
//! # The three arms
//!
//! Same workload, three hint configurations: none, accurate, and **poisoned**.
//! The third is the one that matters. An accurate-hint arm agreeing with a
//! no-hint arm is consistent with hints being load-bearing and merely correct;
//! only a lying hint separates "the hint was right" from "the hint did not
//! decide".

use fgit_types::gossip::GossipView;
use fgit_types::hint::{Hint, HintSource};
use fgit_types::routing::{
    PlacementCandidate, PlacementScore, placement_order, preferred_candidate,
};

/// The only thing in this model that is allowed to be right.
struct Authority {
    entries: Vec<(&'static str, u64)>,
}

impl Authority {
    fn resolve(&self, key: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| *value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cell(&'static str);

impl PlacementCandidate for Cell {
    fn placement_key(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

fn score_for(key: &str) -> impl Fn(&Cell) -> PlacementScore + '_ {
    move |cell: &Cell| {
        let mut bytes = [0_u8; 32];
        let mut accumulator: u8 = 17;
        for (index, byte) in cell.0.as_bytes().iter().chain(key.as_bytes()).enumerate() {
            accumulator = accumulator
                .wrapping_mul(31)
                .wrapping_add(*byte)
                .wrapping_add(u8::try_from(index % 256).unwrap_or_default());
        }
        bytes[0] = accumulator;
        PlacementScore::from_bytes(bytes)
    }
}

/// What a read returned, plus how much work it took to get there.
///
/// The answer is what must match across arms. The cell probes are what may
/// differ, and separating them is the whole experiment: comparing only answers
/// could not show hints doing anything, and comparing only work could not show
/// them doing no harm.
#[derive(Debug, PartialEq, Eq)]
struct Served {
    answer: Option<u64>,
    cell_probes: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct HintRejected;

/// Which cells hold which keys.
///
/// This is what a location hint is ABOUT, and modelling it is what makes the
/// latency half of the acceptance line measurable. Without a hint a reader
/// probes cells in placement order until one holds the key; with a hint it goes
/// straight to the claimed holder. Either way the value it returns comes from
/// the authority, so the hint can save probes and cannot move the answer.
fn holdings(cell: Cell, key: &str) -> bool {
    // Only the last cell holds anything, so a scan is maximally expensive and
    // an accurate hint is maximally useful. A uniform layout would make the
    // two arms cost the same by accident and hide a real difference.
    cell == Cell("cell-c") && key != "refs/heads/absent"
}

/// Serve one key, optionally consulting gossip for its location first.
///
/// The rule under test is in one place: a gossiped location is only ever used
/// after `verified_by` confirms that cell really holds the key, and the value
/// returned always comes from the authority.
fn serve(
    authority: &Authority,
    cells: &[Cell],
    gossip: Option<&GossipView<&'static str, &'static str>>,
    key: &'static str,
    probes: &mut usize,
) -> Option<u64> {
    // Routing decides the scan order. It cannot change the answer, because one
    // authority stands behind every cell -- the deployment shape fg036a
    // specifies.
    let order = placement_order(cells, score_for(key));

    if let Some(view) = gossip
        && let Some(claimed) = view.claim_of(&key)
    {
        let verified: Result<&&str, HintRejected> = claimed.verified_by(|candidate| {
            *probes += 1;
            let named = cells.iter().find(|cell| cell.0 == **candidate);
            match named {
                Some(cell) if holdings(*cell, key) => Ok(()),
                _ => Err(HintRejected),
            }
        });
        if verified.is_ok() {
            // The hint was good: one probe instead of a scan. The VALUE still
            // comes from the authority, never from the peer.
            return authority.resolve(key);
        }
        // A rejected hint costs the probe above and falls through to the scan.
        // It must not poison the answer.
    }

    for cell in order {
        *probes += 1;
        if holdings(*cell, key) {
            return authority.resolve(key);
        }
    }
    None
}

fn authority() -> Authority {
    Authority {
        entries: vec![
            ("refs/heads/main", 100),
            ("refs/heads/next", 200),
            ("refs/tags/v1", 300),
        ],
    }
}

fn cells() -> Vec<Cell> {
    vec![Cell("cell-a"), Cell("cell-b"), Cell("cell-c")]
}

const WORKLOAD: [&str; 4] = [
    "refs/heads/main",
    "refs/heads/next",
    "refs/tags/v1",
    "refs/heads/absent",
];

fn run(gossip: Option<&GossipView<&'static str, &'static str>>) -> Vec<Served> {
    let authority = authority();
    let cells = cells();
    WORKLOAD
        .iter()
        .map(|key| {
            let mut cell_probes = 0;
            let answer = serve(&authority, &cells, gossip, key, &mut cell_probes);
            Served {
                answer,
                cell_probes,
            }
        })
        .collect()
}

fn accurate_gossip() -> GossipView<&'static str, &'static str> {
    let mut view = GossipView::with_capacity(8);
    for key in ["refs/heads/main", "refs/heads/next", "refs/tags/v1"] {
        view.observe(key, "cell-c").expect("fits");
    }
    view
}

fn poisoned_gossip() -> GossipView<&'static str, &'static str> {
    let mut view = GossipView::with_capacity(8);
    // Every claim a lie: a cell that does not hold the key, a cell that does
    // not exist, and a location for a key nothing holds.
    view.observe("refs/heads/main", "cell-a").expect("fits");
    view.observe("refs/heads/next", "cell-nowhere")
        .expect("fits");
    view.observe("refs/tags/v1", "cell-b").expect("fits");
    view.observe("refs/heads/absent", "cell-a").expect("fits");
    view
}

fn answers(served: &[Served]) -> Vec<Option<u64>> {
    served.iter().map(|entry| entry.answer).collect()
}

fn work(served: &[Served]) -> usize {
    served.iter().map(|entry| entry.cell_probes).sum()
}

#[test]
fn disabling_gossip_entirely_changes_no_answer() {
    let without = run(None);
    let accurate = accurate_gossip();
    let with = run(Some(&accurate));

    assert_eq!(
        answers(&without),
        answers(&with),
        "the same workload must produce the same answers with and without hints"
    );
    assert_eq!(
        answers(&without),
        vec![Some(100), Some(200), Some(300), None],
        "and those answers must be the authority's, including the absent key"
    );
}

#[test]
fn poisoned_gossip_changes_no_answer_either() {
    // The arm that carries the claim. An accurate hint agreeing with no hint is
    // also consistent with hints being load-bearing and merely correct; only a
    // lying hint separates "the hint was right" from "the hint did not decide".
    let without = run(None);
    let poisoned = poisoned_gossip();
    let with = run(Some(&poisoned));

    assert_eq!(
        answers(&without),
        answers(&with),
        "a lying peer must not change a single answer"
    );
    assert_eq!(
        answers(&with),
        vec![Some(100), Some(200), Some(300), None],
        "the authority's values, and still None for the key nothing holds — a peer \
         claiming a location for it must not conjure one into existence"
    );
}

#[test]
fn the_experiment_can_actually_detect_a_hint_that_decides() {
    // Guard against the differential being vacuous. If `serve` ignored gossip
    // altogether the two tests above would pass for the wrong reason, so this
    // shows the poisoned values ARE reaching the code path and being rejected
    // there rather than never arriving.
    let poisoned = poisoned_gossip();
    let mut probes = 0;
    let answer = serve(
        &authority(),
        &cells(),
        Some(&poisoned),
        "refs/heads/main",
        &mut probes,
    );

    assert_eq!(answer, Some(100), "the authority's value either way");
    assert!(
        probes > 1,
        "rejecting the lie must cost a probe and then still scan: at 1 probe the \
         hint path was never entered and the differential would prove nothing, \
         got {probes}"
    );

    // And the same call with a truthful hint costs one probe, which is the
    // latency difference hints exist to buy.
    let accurate = accurate_gossip();
    let mut cheap_probes = 0;
    let cheap = serve(
        &authority(),
        &cells(),
        Some(&accurate),
        "refs/heads/main",
        &mut cheap_probes,
    );
    assert_eq!(cheap, Some(100));
    assert_eq!(
        cheap_probes, 1,
        "a correct location hint goes straight to the holder, skipping the scan"
    );
    assert!(
        cheap_probes < probes,
        "and it must be strictly cheaper than rejecting a lie"
    );
}

#[test]
fn hints_change_work_even_though_they_change_no_answer() {
    // The other half of the acceptance line: "degrades latency". If enabling
    // gossip changed nothing measurable at all, the hint layer would be dead
    // code and its correctness would be uninteresting.
    let accurate = accurate_gossip();
    assert!(
        work(&run(Some(&accurate))) < work(&run(None)),
        "accurate hints must reduce authority probes, or they buy nothing"
    );
    let poisoned = poisoned_gossip();
    assert!(
        work(&run(Some(&poisoned))) > work(&run(None)),
        "poisoned hints must cost extra probes, which is the price of verifying"
    );
}

#[test]
fn routing_preference_is_stable_and_does_not_touch_the_answer() {
    // Routing chose a cell on every call above. Since one authority stands
    // behind every cell, that choice cannot move an answer — this pins the
    // premise rather than assuming it.
    for key in WORKLOAD {
        let chosen = preferred_candidate(&cells(), score_for(key)).copied();
        assert!(chosen.is_some());
        let mut probes = 0;
        let direct = authority().resolve(key);
        let routed = serve(&authority(), &cells(), None, key, &mut probes);
        assert_eq!(
            direct, routed,
            "{key}: the answer must not depend on which cell was preferred"
        );
    }
}

#[test]
fn a_hint_is_never_reported_as_a_verified_reading() {
    let poisoned = poisoned_gossip();
    let claim: Hint<&&str> = poisoned.claim_of(&"refs/heads/main").expect("present");
    assert_eq!(claim.source(), HintSource::Gossip);
    assert_eq!(**claim.peek(), "cell-a", "the lie is visible to a peek");
    assert!(
        claim
            .verified_by(|candidate| {
                if **candidate == "cell-c" {
                    Ok(())
                } else {
                    Err(HintRejected)
                }
            })
            .is_err(),
        "and it cannot be taken past a check"
    );
}
