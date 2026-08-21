//! Version tokens: never content-derived, never reused, surviving kill/reopen.

use fgit_authority::{HeadGeneration, StoreInstanceId};
use fgit_authority_fsqlite::{
    IssuanceRecord, IssuanceSequence, TokenMintError, mint_token, next_issuance_after,
    token_instance,
};

const fn instance(raw: u64) -> StoreInstanceId {
    StoreInstanceId::from_raw(raw)
}

fn sequence(raw: u64) -> IssuanceSequence {
    IssuanceSequence::new(raw).expect("a positive sequence")
}

fn generation(raw: u64) -> HeadGeneration {
    HeadGeneration::try_new(raw).expect("a positive generation")
}

#[test]
fn the_empty_ledger_yields_the_first_sequence() {
    assert_eq!(
        next_issuance_after(None).expect("the empty ledger is admissible"),
        IssuanceSequence::FIRST
    );
    assert_eq!(IssuanceSequence::FIRST.get(), 1);
}

#[test]
fn the_next_sequence_follows_the_committed_maximum() {
    for last in [1_u64, 2, 41, 1_000_000] {
        assert_eq!(
            next_issuance_after(Some(last))
                .expect("a successor exists")
                .get(),
            last + 1,
            "the next sequence must follow the ledger, not a counter in memory"
        );
    }
}

#[test]
fn an_exhausted_sequence_space_refuses_rather_than_wrapping() {
    let refusal = next_issuance_after(Some(u64::MAX)).expect_err("wrapping would reuse a token");
    assert_eq!(
        refusal,
        TokenMintError::SequenceExhausted { last: u64::MAX }
    );
}

#[test]
fn sequence_zero_is_reserved_and_one_is_admissible() {
    assert_eq!(
        IssuanceSequence::new(0).expect_err("zero means the empty ledger"),
        TokenMintError::SequenceReserved
    );
    assert_eq!(
        IssuanceSequence::new(1)
            .expect("one is the first real sequence")
            .get(),
        1
    );
}

#[test]
fn a_token_is_not_a_function_of_the_body_it_names() {
    // The whole ABA defence rests on this. Two different bodies published at
    // the same position get the same token, and one body published at two
    // positions gets two tokens -- which is precisely backwards from a content
    // hash, and precisely right for a version token.
    let at_one = mint_token(instance(7), sequence(1));
    let also_at_one = mint_token(instance(7), sequence(1));
    assert_eq!(
        at_one, also_at_one,
        "the token is a function of the issuance coordinate alone"
    );

    let at_two = mint_token(instance(7), sequence(2));
    assert_ne!(
        at_one, at_two,
        "a second write must not reuse the first write's token"
    );
}

#[test]
fn a_byte_identical_restore_gets_a_third_distinct_token() {
    // state A at 1, state B at 2, byte-identical A again at 3.
    let first = mint_token(instance(7), sequence(1));
    let second = mint_token(instance(7), sequence(2));
    let third = mint_token(instance(7), sequence(3));

    assert_ne!(first, second);
    assert_ne!(second, third);
    assert_ne!(
        first, third,
        "restoring the original bytes must not resurrect the original token"
    );
}

#[test]
fn tokens_stay_unique_across_a_kill_and_reopen() {
    // Before the kill: the ledger committed sequences 1 through 3.
    let before: Vec<_> = (1..=3)
        .map(|n| mint_token(instance(7), sequence(n)))
        .collect();

    // The kill loses everything in memory. On reopen the next sequence is
    // recovered from the committed ledger maximum, not from a counter.
    let recovered = next_issuance_after(Some(3)).expect("a successor exists");
    let after_reopen = mint_token(instance(7), recovered);

    assert_eq!(recovered.get(), 4);
    assert!(
        !before.contains(&after_reopen),
        "a token minted after reopen must not repeat one minted before the kill"
    );

    // And an interrupted mint is harmless: if the transaction that would have
    // recorded sequence 4 never committed, the ledger maximum is still 3, so
    // the retry mints the same unused token rather than skipping to 5 and
    // leaving a gap that later looks like a lost write.
    let retried = next_issuance_after(Some(3)).expect("a successor exists");
    assert_eq!(retried, recovered);
}

#[test]
fn a_token_carries_the_instance_that_minted_it() {
    for raw in [1_u64, 11, 12, u64::MAX] {
        let token = mint_token(instance(raw), sequence(5));
        assert_eq!(token_instance(token), instance(raw));
    }
}

#[test]
fn two_instances_never_mint_the_same_token_at_the_same_position() {
    let left = mint_token(instance(11), sequence(5));
    let right = mint_token(instance(12), sequence(5));
    assert_ne!(
        left, right,
        "the instance is part of the token, so one endpoint's token cannot be another's"
    );
    assert_ne!(token_instance(left), token_instance(right));
}

#[test]
fn a_token_round_trips_through_its_transport_form() {
    let token = mint_token(instance(7), sequence(9));
    let transported =
        fgit_authority::AuthorityVersionToken::from_opaque_bytes(token.to_opaque_bytes());
    assert_eq!(transported, token);
    assert_eq!(token_instance(transported), instance(7));
}

#[test]
fn an_issuance_record_accepts_only_the_triple_it_recorded() {
    let record = IssuanceRecord {
        token: mint_token(instance(7), sequence(1)),
        sequence: sequence(1),
        head_key: b"repo/head".to_vec(),
        generation: generation(3),
        body_bytes: b"head-3".to_vec(),
    };

    assert!(
        record.matches(b"repo/head", generation(3), b"head-3"),
        "the genuine triple must verify"
    );
    assert!(
        !record.matches(b"repo/other", generation(3), b"head-3"),
        "a receipt pointed at another slot must not verify"
    );
    assert!(
        !record.matches(b"repo/head", generation(4), b"head-3"),
        "an altered generation must not verify"
    );
    assert!(
        !record.matches(b"repo/head", generation(3), b"head-forged"),
        "altered bytes must not verify"
    );
}
