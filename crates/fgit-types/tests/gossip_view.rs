//! Bounded, ordered, non-authoritative gossip. `frankengit-fg036a`.

use fgit_types::gossip::{GossipRefusal, GossipView};
use fgit_types::hint::HintSource;

#[derive(Debug, PartialEq, Eq)]
struct Rejected;

const fn view(capacity: usize) -> GossipView<&'static str, u64> {
    GossipView::with_capacity(capacity)
}

#[test]
fn a_new_peer_past_the_bound_is_refused_before_it_is_stored() {
    // Gossip is peer-supplied, so an unbounded map is a peer-controlled
    // allocation. The refusal names the bound so an operator can act on it.
    let mut gossip = view(2);
    gossip.observe("cell-a", 1).expect("first fits");
    gossip.observe("cell-b", 2).expect("second fits");

    let refusal = gossip
        .observe("cell-c", 3)
        .expect_err("a third peer passes the bound");
    assert_eq!(refusal, GossipRefusal::CapacityExceeded { capacity: 2 });

    assert_eq!(
        gossip.len(),
        2,
        "the refused peer must not have been stored"
    );
    assert!(
        gossip.claim_of(&"cell-c").is_none(),
        "a refused claim must not be readable"
    );
}

#[test]
fn replacing_an_existing_peer_is_admitted_even_at_capacity() {
    // The permitted twin of the refusal above, and the case that separates a
    // bound on MEMORY from a bound on FRESHNESS. A full view that refused
    // updates would freeze at whatever it held when it filled.
    let mut gossip = view(2);
    gossip.observe("cell-a", 1).expect("fits");
    gossip.observe("cell-b", 2).expect("fits");
    assert_eq!(gossip.len(), gossip.capacity());

    gossip
        .observe("cell-a", 99)
        .expect("replacing a known peer consumes no new slot");
    assert_eq!(gossip.len(), 2);
    let claim = gossip.claim_of(&"cell-a").expect("still present");
    assert_eq!(**claim.peek(), 99, "the newer claim must have replaced it");
}

#[test]
fn a_zero_capacity_view_accepts_nothing() {
    // The degenerate bound. Worth pinning because `len() >= capacity` and
    // `len() > capacity` differ exactly here, and the wrong one would let a
    // "hold nothing" configuration hold one.
    let mut gossip = view(0);
    assert_eq!(
        gossip.observe("cell-a", 1),
        Err(GossipRefusal::CapacityExceeded { capacity: 0 })
    );
    assert!(gossip.is_empty());
}

#[test]
fn a_capacity_of_one_holds_exactly_one() {
    // The other boundary the same comparison controls.
    let mut gossip = view(1);
    gossip.observe("cell-a", 1).expect("exactly one fits");
    assert_eq!(gossip.len(), 1);
    assert!(gossip.observe("cell-b", 2).is_err());
    gossip
        .observe("cell-a", 2)
        .expect("but replacement still works");
    assert_eq!(gossip.len(), 1);
}

#[test]
fn iteration_order_does_not_depend_on_the_order_peers_were_heard() {
    // Two cells holding the same gossip must make the same routing choices,
    // and they cannot if one of them enumerates in hash order.
    let mut heard_forward = view(4);
    for (peer, claim) in [("cell-a", 1), ("cell-b", 2), ("cell-c", 3)] {
        heard_forward.observe(peer, claim).expect("fits");
    }
    let mut heard_backward = view(4);
    for (peer, claim) in [("cell-c", 3), ("cell-b", 2), ("cell-a", 1)] {
        heard_backward.observe(peer, claim).expect("fits");
    }

    let forward: Vec<&str> = heard_forward.peers().copied().collect();
    let backward: Vec<&str> = heard_backward.peers().copied().collect();
    assert_eq!(forward, vec!["cell-a", "cell-b", "cell-c"]);
    assert_eq!(
        forward, backward,
        "iteration must not depend on arrival order"
    );

    let pairs: Vec<(&str, u64)> = heard_backward
        .claims()
        .map(|(peer, claim)| (*peer, **claim.peek()))
        .collect();
    assert_eq!(pairs, vec![("cell-a", 1), ("cell-b", 2), ("cell-c", 3)]);
}

#[test]
fn every_claim_comes_back_marked_as_peer_influenced() {
    // The whole point of routing this through Hint: a caller cannot obtain the
    // value without a check, and cannot mistake its provenance.
    let mut gossip = view(2);
    gossip.observe("cell-a", 7).expect("fits");

    let claim = gossip.claim_of(&"cell-a").expect("present");
    assert_eq!(claim.source(), HintSource::Gossip);
    assert!(
        claim.source().is_peer_influenced(),
        "gossip must be marked as attacker-influenced input"
    );

    for (_, hinted) in gossip.claims() {
        assert_eq!(hinted.source(), HintSource::Gossip);
    }

    // And ownership still requires passing a check.
    let taken = gossip
        .claim_of(&"cell-a")
        .expect("present")
        .verified_by(|_| Ok::<(), Rejected>(()))
        .expect("the check passed");
    assert_eq!(*taken, 7);
}

#[test]
fn forgetting_a_peer_frees_its_slot() {
    let mut gossip = view(2);
    gossip.observe("cell-a", 1).expect("fits");
    gossip.observe("cell-b", 2).expect("fits");
    assert!(gossip.observe("cell-c", 3).is_err());

    assert!(gossip.forget(&"cell-a"), "forgetting reports what it did");
    assert!(
        !gossip.forget(&"cell-a"),
        "forgetting an absent peer reports that too"
    );
    gossip
        .observe("cell-c", 3)
        .expect("the freed slot is usable");
    assert_eq!(
        gossip.peers().copied().collect::<Vec<_>>(),
        vec!["cell-b", "cell-c"]
    );
}

#[test]
fn discarding_everything_is_always_available() {
    // None of this was evidence, so a cell that suspects poisoned gossip can
    // drop all of it and lose only speed.
    let mut gossip = view(3);
    gossip.observe("cell-a", 1).expect("fits");
    gossip.observe("cell-b", 2).expect("fits");
    gossip.forget_all();
    assert!(gossip.is_empty());
    assert_eq!(gossip.capacity(), 3, "the bound survives a purge");
    gossip
        .observe("cell-a", 5)
        .expect("and the view is reusable");
}
