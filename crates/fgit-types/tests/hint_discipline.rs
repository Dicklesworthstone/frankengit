//! Hints guide work; they never decide it. `frankengit-fg036a`.
//!
//! These cases pin the mechanism acceptance line 1 depends on. If a hint can
//! only become an owned value by passing a check, then a path that consults no
//! hints and a path that consults every hint reach the same answer, and turning
//! routing and gossip off can cost latency without changing outcomes.

use fgit_types::hint::{Hint, HintSource};
use fgit_types::numeric::HeadGeneration;

#[derive(Debug, PartialEq, Eq)]
struct Rejected;

#[test]
fn peeking_never_yields_ownership_but_verifying_does() {
    let hint = Hint::new(HeadGeneration::FIRST, HintSource::Gossip);
    assert_eq!(*hint.peek(), HeadGeneration::FIRST);
    assert_eq!(hint.source(), HintSource::Gossip);

    let taken: HeadGeneration = hint
        .verified_by(|_| Ok::<(), Rejected>(()))
        .expect("the check passed");
    assert_eq!(taken, HeadGeneration::FIRST);
}

#[test]
fn a_failed_check_yields_no_value_at_all() {
    // The property that matters: there is no path from a rejected hint to the
    // value it carried. A verifier that returned the value anyway on failure
    // would make the whole type decorative.
    let hint = Hint::new(HeadGeneration::FIRST, HintSource::Gossip);
    let outcome: Result<HeadGeneration, Rejected> = hint.verified_by(|_| Err(Rejected));
    assert_eq!(outcome, Err(Rejected));
}

#[test]
fn the_check_sees_the_value_it_is_checking() {
    // A verifier that could not read the candidate could only ever be a
    // rubber stamp, and the type would enforce the existence of a check while
    // guaranteeing it was uninformed.
    let hint = Hint::new(HeadGeneration::FIRST, HintSource::LocalProjection);
    let mut observed = None;
    let taken = hint
        .verified_by(|candidate| {
            observed = Some(*candidate);
            Ok::<(), Rejected>(())
        })
        .expect("passes");
    assert_eq!(observed, Some(HeadGeneration::FIRST));
    assert_eq!(taken, HeadGeneration::FIRST);
}

#[test]
fn mapping_keeps_the_value_a_hint_and_preserves_its_source() {
    // Transforming a hint must not launder it. If `map` returned a bare value,
    // the cheapest way around the discipline would be a no-op transform.
    let hint = Hint::new(HeadGeneration::FIRST, HintSource::Gossip);
    let mapped: Hint<u64> = hint.map(|_| 7_u64);
    assert_eq!(*mapped.peek(), 7);
    assert_eq!(
        mapped.source(),
        HintSource::Gossip,
        "a transform must not turn peer-influenced input into something else"
    );
    assert!(mapped.verified_by(|_| Ok::<(), Rejected>(())).is_ok());
}

#[test]
fn only_gossip_is_peer_influenced() {
    // The distinction exists because the mitigations differ: a stale local
    // projection is a latency problem, a gossiped value is attacker-influenced
    // input, and a path treating them alike has misjudged one of them.
    let peer: Vec<HintSource> = HintSource::ALL
        .into_iter()
        .filter(|source| source.is_peer_influenced())
        .collect();
    assert_eq!(peer, vec![HintSource::Gossip]);
    assert_eq!(HintSource::ALL.len(), 3, "every source is listed");
}

#[test]
fn the_debug_rendering_cannot_be_mistaken_for_a_verified_reading() {
    // An incident log is exactly where someone reads a value quickly and draws
    // a conclusion. The rendering says what it is.
    let rendered = format!("{:?}", Hint::new(HeadGeneration::FIRST, HintSource::Gossip));
    assert!(
        rendered.contains("Hint") && rendered.contains("unverified"),
        "a hint must not debug-print as a bare value, got {rendered}"
    );
}
