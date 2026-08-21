//! Row counts become contract outcomes, and the four zero-row cases stay apart.

use fgit_authority::{
    AuthorityRefusal, AuthorityVersionToken, CasOutcome, HeadGeneration, PutOutcome,
    StoreInstanceId,
};
use fgit_authority_fsqlite::{
    CasStep, DisambiguationRefusal, HeadInitStep, IssuanceSequence, ObservedHead, PutStep,
    compare_stored_body, disambiguate_compare_exchange, interpret_compare_exchange,
    interpret_head_create, interpret_put_if_absent, mint_token,
};

fn token(sequence: u64) -> AuthorityVersionToken {
    mint_token(
        StoreInstanceId::from_raw(7),
        IssuanceSequence::new(sequence).expect("a positive sequence"),
    )
}

fn generation(raw: u64) -> HeadGeneration {
    HeadGeneration::try_new(raw).expect("a positive generation")
}

const HEAD: &[u8] = b"repo/head";
const OTHER: &[u8] = b"repo/other";

#[test]
fn a_conditional_insert_that_changed_a_row_created_the_slot() {
    assert_eq!(interpret_put_if_absent(1), PutStep::Created);
    assert_eq!(interpret_head_create(1), HeadInitStep::Created);
}

#[test]
fn a_conditional_insert_that_changed_nothing_needs_the_stored_bytes() {
    assert_eq!(
        interpret_put_if_absent(0),
        PutStep::OccupiedNeedsComparison,
        "an occupied slot is not yet a conflict; it may be an idempotent retry"
    );
    assert_eq!(
        interpret_head_create(0),
        HeadInitStep::OccupiedNeedsComparison
    );
}

#[test]
fn an_occupied_immutable_slot_is_a_retry_or_a_conflict_and_never_a_replacement() {
    assert_eq!(
        compare_stored_body(b"seal-body", b"seal-body"),
        PutOutcome::IdenticalRetry
    );
    assert_eq!(
        compare_stored_body(b"seal-body", b"other-body"),
        PutOutcome::Conflict
    );
}

#[test]
fn a_replacement_that_changed_a_row_published() {
    assert_eq!(interpret_compare_exchange(1), CasStep::Published);
    assert_eq!(
        interpret_compare_exchange(0),
        CasStep::UnchangedNeedsDisambiguation
    );
}

#[test]
fn a_token_the_store_never_issued_is_refused_before_anything_else() {
    // The ordering is the point. This token also fails to match the current
    // head, so an implementation that checked staleness first would report a
    // mere lost race and tell a forger its token was simply out of date.
    let refusal = disambiguate_compare_exchange(
        token(99),
        generation(2),
        None,
        HEAD,
        Some(ObservedHead {
            token: token(1),
            generation: generation(1),
        }),
    )
    .expect_err("an unissued token is refused, not raced");
    assert_eq!(
        refusal,
        DisambiguationRefusal::Contract(AuthorityRefusal::UnknownVersionToken)
    );
}

#[test]
fn a_token_issued_for_another_slot_is_refused() {
    let refusal = disambiguate_compare_exchange(
        token(1),
        generation(2),
        Some(OTHER),
        HEAD,
        Some(ObservedHead {
            token: token(1),
            generation: generation(1),
        }),
    )
    .expect_err("a token minted for another head must not move this one");
    assert_eq!(
        refusal,
        DisambiguationRefusal::Contract(AuthorityRefusal::TokenKeyMismatch)
    );
}

#[test]
fn an_absent_head_is_refused_rather_than_raced() {
    let refusal = disambiguate_compare_exchange(token(1), generation(2), Some(HEAD), HEAD, None)
        .expect_err("there is no race to lose against a slot that does not exist");
    assert_eq!(
        refusal,
        DisambiguationRefusal::Contract(AuthorityRefusal::HeadAbsent)
    );
}

#[test]
fn a_genuine_but_superseded_token_loses_the_race_rather_than_erroring() {
    let outcome = disambiguate_compare_exchange(
        token(1),
        generation(3),
        Some(HEAD),
        HEAD,
        Some(ObservedHead {
            token: token(2),
            generation: generation(2),
        }),
    )
    .expect("a stale but issued token loses; losing is an outcome, not an error");
    assert_eq!(outcome, CasOutcome::PredecessorMismatch);
}

#[test]
fn a_non_advancing_generation_is_refused_once_the_token_is_current() {
    for proposed in [1_u64, 2] {
        let refusal = disambiguate_compare_exchange(
            token(2),
            generation(proposed),
            Some(HEAD),
            HEAD,
            Some(ObservedHead {
                token: token(2),
                generation: generation(2),
            }),
        )
        .expect_err("the head must not move sideways or backwards");
        assert_eq!(
            refusal,
            DisambiguationRefusal::Contract(AuthorityRefusal::NonMonotoneGeneration {
                current: generation(2),
                proposed: generation(proposed),
            })
        );
    }
}

#[test]
fn the_four_zero_row_causes_produce_four_different_answers() {
    // Collapsing these into one "failed" is the defect this function exists to
    // prevent, so the test asserts they stay distinct rather than each being
    // individually correct.
    let current = Some(ObservedHead {
        token: token(2),
        generation: generation(2),
    });

    let unissued =
        disambiguate_compare_exchange(token(99), generation(3), None, HEAD, current).unwrap_err();
    let wrong_slot =
        disambiguate_compare_exchange(token(1), generation(3), Some(OTHER), HEAD, current)
            .unwrap_err();
    let absent =
        disambiguate_compare_exchange(token(1), generation(3), Some(HEAD), HEAD, None).unwrap_err();
    let stale = disambiguate_compare_exchange(token(1), generation(3), Some(HEAD), HEAD, current)
        .expect("a stale token loses");
    let backwards =
        disambiguate_compare_exchange(token(2), generation(1), Some(HEAD), HEAD, current)
            .unwrap_err();

    assert_ne!(unissued, wrong_slot);
    assert_ne!(unissued, absent);
    assert_ne!(unissued, backwards);
    assert_ne!(wrong_slot, absent);
    assert_ne!(absent, backwards);
    assert_eq!(stale, CasOutcome::PredecessorMismatch);
}

#[test]
fn a_current_token_with_an_advancing_generation_should_have_changed_a_row() {
    // Reaching the disambiguation with a current token and an advancing
    // generation means the row count disagreed with what a read reports. That
    // is an engine inconsistency, not a client-visible condition, and it must
    // not be dressed up as a lost race.
    let refusal = disambiguate_compare_exchange(
        token(2),
        generation(3),
        Some(HEAD),
        HEAD,
        Some(ObservedHead {
            token: token(2),
            generation: generation(2),
        }),
    )
    .expect_err("this combination should have published");
    assert_eq!(
        refusal,
        DisambiguationRefusal::RowCountContradictsState,
        "an engine inconsistency must not be dressed up as a contract refusal"
    );
}
