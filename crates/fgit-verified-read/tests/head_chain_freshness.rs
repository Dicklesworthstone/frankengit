#![forbid(unsafe_code)]
//! A genuine proof about the wrong moment must be refused. `frankengit-fg037b`.
//!
//! Every head built here is **well-formed and internally valid**. That is the
//! whole point: nothing in this file is a forgery the existing verifier could
//! catch, so anything caught here is caught by freshness and by nothing else.

use fgit_authority::authority_head_identity;
use fgit_codec::RepositoryAuthorityHeadBody;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{RepositoryAuthorityHeadId, RepositoryId};
use fgit_types::numeric::{HeadGeneration, PolicyEpoch, RegistryEpoch};
use fgit_verified_read::freshness::{FreshnessRefusal, FreshnessVerdict, HeadChainFloor};

fn generation(value: u64) -> HeadGeneration {
    HeadGeneration::try_new(value).expect("a positive generation")
}

fn digest(byte: u8) -> Digest {
    Digest::new(
        fgit_crypto::IdentityDomain::RefTransaction.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

/// A well-formed head. `marker` changes its bytes without changing its shape,
/// so two heads can share a generation and differ in identity.
fn head(
    generation_value: u64,
    predecessor: Option<RepositoryAuthorityHeadId>,
    marker: u8,
) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x22; 16]),
        generation: generation(generation_value),
        predecessor_head_id: predecessor,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: digest(marker),
        forge_position_root: digest(0),
        outcome_index_root: digest(0),
        retention_root: digest(0),
        outbox_root: digest(0),
        configuration_root: digest(0),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn identity_of(body: &RepositoryAuthorityHeadBody) -> RepositoryAuthorityHeadId {
    authority_head_identity(body).expect("a well-formed head has an identity")
}

/// A three-generation chain, each head naming its true predecessor.
fn chain() -> [RepositoryAuthorityHeadBody; 3] {
    let first = head(1, None, 0x11);
    let second = head(2, Some(identity_of(&first)), 0x22);
    let third = head(3, Some(identity_of(&second)), 0x33);
    [first, second, third]
}

#[test]
fn a_replayed_older_head_is_refused_even_though_it_is_perfectly_valid() {
    // THE attack. The client has accepted generation 3. A mirror now offers
    // generation 1 — a real head, correctly formed, one this client itself
    // trusted earlier. No existing check in the crate fires: there is no
    // mismatch, no bad path, no unidentifiable configuration. Only the floor
    // knows the client has moved on.
    let [first, second, third] = chain();
    let mut floor = HeadChainFloor::anchored_to(&first).expect("anchors");
    floor.accept(&second).expect("advances to 2");
    floor.accept(&third).expect("advances to 3");
    assert_eq!(floor.generation(), generation(3));

    let refusal = floor
        .judge(&first)
        .expect_err("a head older than the floor must be refused");
    assert_eq!(
        refusal,
        FreshnessRefusal::StaleHead {
            floor: generation(3),
            offered: generation(1),
        }
    );

    // And the refusal must not have lowered the floor — otherwise one replayed
    // answer would open the door for the rest.
    assert_eq!(floor.generation(), generation(3));
    let after = floor.accept(&first);
    assert!(
        after.is_err(),
        "accept must refuse it too, not merely judge it"
    );
    assert_eq!(
        floor.generation(),
        generation(3),
        "a refused head must leave the floor exactly where it was"
    );
}

#[test]
fn the_same_head_offered_twice_is_permitted_and_moves_nothing() {
    // The permitted twin of the refusal above. A client must be able to poll
    // twice; if re-offering the current head were refused as "not newer", the
    // policy would break ordinary operation while calling it security.
    let [first, second, _third] = chain();
    let mut floor = HeadChainFloor::anchored_to(&first).expect("anchors");
    floor.accept(&second).expect("advances");

    let verdict = floor.accept(&second).expect("the same head again is fine");
    assert_eq!(verdict, FreshnessVerdict::Reaffirms);
    assert!(!verdict.moves_the_floor());
    assert!(verdict.continuity_established());
    assert_eq!(floor.generation(), generation(2));
}

#[test]
fn two_heads_claiming_one_generation_are_a_fork_and_not_staleness() {
    // A distinction that is easy to collapse and expensive to get wrong. The
    // offered head is NOT older, so "stale" would be the wrong word; it is a
    // second head at the same height, which is a split-brain or a forgery. An
    // operator reading "stale" would look at caching. Reading "forked" they
    // look at the authority.
    let [first, second, _third] = chain();
    let rival = head(2, Some(identity_of(&first)), 0xEE);
    assert_ne!(
        identity_of(&second),
        identity_of(&rival),
        "the two rivals must genuinely differ, or this test proves nothing"
    );

    let mut floor = HeadChainFloor::anchored_to(&first).expect("anchors");
    floor
        .accept(&second)
        .expect("advances to the real generation 2");

    let refusal = floor.judge(&rival).expect_err("a rival at the same height");
    assert_eq!(
        refusal,
        FreshnessRefusal::ForkedAtGeneration {
            generation: generation(2)
        }
    );
    assert!(
        !matches!(refusal, FreshnessRefusal::StaleHead { .. }),
        "a fork must not be reported as staleness"
    );
}

#[test]
fn a_forged_head_at_a_higher_generation_is_caught_by_continuity() {
    // The case a generation-only monotonicity check waves straight through.
    // This head is NEWER than the floor, so any "must be strictly greater" rule
    // accepts it. Its predecessor names something that is not the accepted
    // head, which is the only evidence available that it is not a descendant.
    let [first, second, _third] = chain();
    let mut floor = HeadChainFloor::anchored_to(&first).expect("anchors");
    floor.accept(&second).expect("advances to 2");

    let orphan_parent = head(1, None, 0x77);
    let grafted = head(3, Some(identity_of(&orphan_parent)), 0x33);
    assert!(
        grafted.generation.get() > floor.generation().get(),
        "the graft must be strictly newer, or it would be caught as stale instead"
    );

    let refusal = floor.judge(&grafted).expect_err("a graft must be refused");
    let FreshnessRefusal::ChainBreak { offered } = refusal else {
        panic!("expected a chain break, got {refusal:?}");
    };
    assert_eq!(
        *offered,
        identity_of(&orphan_parent),
        "the refusal must name the predecessor actually claimed"
    );
    assert_ne!(
        *offered,
        floor.identity(),
        "and it must differ from the floor, which is what makes it a break"
    );

    // The permitted twin: the real generation 3, differing only in which
    // predecessor it names, is accepted.
    let [_, _, real_third] = chain();
    assert_eq!(
        floor.judge(&real_third).expect("the true successor"),
        FreshnessVerdict::Advances { to: generation(3) }
    );
}

#[test]
fn a_gap_is_reported_as_unverified_rather_than_quietly_accepted() {
    // Two generations on, the intervening head is absent, so continuity cannot
    // be checked from these two bodies. That is neither proof of a graft nor
    // proof of a chain. Folding it into Advances would make the permissive
    // choice on every caller's behalf.
    let [first, _second, third] = chain();
    let floor = HeadChainFloor::anchored_to(&first).expect("anchors");

    let verdict = floor.judge(&third).expect("a gap is not a refusal");
    assert_eq!(
        verdict,
        FreshnessVerdict::AdvancesAcrossUnverifiedGap {
            from: generation(1),
            to: generation(3),
        }
    );
    assert!(verdict.moves_the_floor(), "it is still forward progress");
    assert!(
        !verdict.continuity_established(),
        "but continuity was NOT established, and a caller that needs it must be able to tell"
    );
}

#[test]
fn a_successor_that_records_no_predecessor_is_a_break_not_a_genesis() {
    // Generation 2 with no predecessor claims to be a genesis head while
    // sitting above one. Accepting it would let a mirror reset a client's chain
    // by simply omitting a field.
    let [first, _second, _third] = chain();
    let floor = HeadChainFloor::anchored_to(&first).expect("anchors");
    let rootless = head(2, None, 0x22);

    assert_eq!(
        floor.judge(&rootless).expect_err("must be refused"),
        FreshnessRefusal::PredecessorAbsent {
            generation: generation(2)
        }
    );
}

#[test]
fn the_floor_only_ever_moves_forward_across_a_whole_sequence() {
    // The property in aggregate, since the per-case tests could each pass while
    // the floor still wandered. Offer the chain forwards, then every earlier
    // head again, and assert the floor never decreases.
    let [first, second, third] = chain();
    let mut floor = HeadChainFloor::anchored_to(&first).expect("anchors");
    let mut observed = vec![floor.generation().get()];

    for offered in [&second, &third, &first, &second, &third] {
        let _ = floor.accept(offered);
        observed.push(floor.generation().get());
    }

    assert!(
        observed.windows(2).all(|pair| pair[1] >= pair[0]),
        "the floor decreased somewhere in {observed:?}"
    );
    assert_eq!(
        *observed.last().expect("non-empty"),
        3,
        "and it must end at the newest head it ever accepted"
    );
    assert!(
        observed.contains(&3),
        "the sequence must actually have reached generation 3, or monotonicity is trivial"
    );
}
