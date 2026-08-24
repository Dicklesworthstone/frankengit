//! Membership proofs against the outcome index a head actually publishes.
//!
//! FG-037 verified reads need to hand a client one terminal decision plus a
//! proof, rather than the whole index. That is only sound if the proof is
//! against the *same* tree [`outcome_index_root`] commits to — same leaves,
//! same order, same shape. Both now go through one construction in
//! `fgit-crypto`, and these tests hold them to it.
//!
//! # The boundary this file does not cross
//!
//! An outcome-index leaf is built from the canonical outcome encoding, which is
//! `fgit-authority`'s. So a verifier for it cannot be dependency-free the way
//! `fgit_crypto::verify_ref_state_membership` is. That asymmetry is a property
//! of the two leaf shapes rather than an oversight, and moving the encoder into
//! a crypto crate to fake symmetry would be worse than stating it.

use fgit_authority::{
    OutcomeFailure, TerminalOutcome, outcome_index_proof, outcome_index_root,
    verify_outcome_index_membership,
};
use fgit_crypto::IdentityDomain;
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::DigestBytes;
use fgit_types::identity::{RefusalRecordId, RepositoryCommitId, TxId};
use fgit_types::numeric::DecisionSequence;
use fgit_types::vocabulary::{DecisionOutcome, RefusalCode};

fn tx(byte: u8) -> TxId {
    TxId::from_digest(
        IdentityDomain::RefTransaction.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn commit_id(byte: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        IdentityDomain::RepositoryCommitRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn refusal_id(byte: u8) -> RefusalRecordId {
    RefusalRecordId::from_digest(
        IdentityDomain::RefusalRecord.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("a bounded digest"),
    )
}

fn committed(sequence: u64, commit: u8) -> TerminalOutcome {
    TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(sequence).expect("positive"),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: commit_id(commit),
        },
    }
}

fn refused(sequence: u64, record: u8) -> TerminalOutcome {
    TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(sequence).expect("positive"),
        outcome: DecisionOutcome::Refused {
            code: RefusalCode::QuotaExceeded,
            refusal_record_id: refusal_id(record),
        },
    }
}

/// A five-decision index carrying both terminal shapes.
fn index() -> Vec<(TxId, TerminalOutcome)> {
    vec![
        (tx(0xA1), committed(1, 0x51)),
        (tx(0xB2), refused(2, 0x52)),
        (tx(0xC3), committed(3, 0x53)),
        (tx(0xD4), refused(4, 0x54)),
        (tx(0xE5), committed(5, 0x55)),
    ]
}

#[test]
fn every_decision_in_the_index_proves_against_the_root_the_head_publishes() {
    let entries = index();
    let root = outcome_index_root(&entries).expect("a root");

    for (tx_id, outcome) in &entries {
        let proof = outcome_index_proof(&entries, *tx_id, outcome).expect("a proof");
        assert!(
            verify_outcome_index_membership(&root, *tx_id, outcome, &proof)
                .expect("verification completes"),
            "{tx_id} must verify against the root its own index published"
        );
    }
}

#[test]
fn a_decision_the_index_does_not_hold_is_refused_rather_than_given_an_empty_proof() {
    // An empty proof verifies vacuously. Refusing is the only answer that
    // cannot be mistaken for membership.
    let entries = index();
    let failure = outcome_index_proof(&entries, tx(0xFF), &committed(9, 0x99))
        .expect_err("an absent decision has no proof");
    assert!(
        matches!(failure, OutcomeFailure::OutcomeNotIndexed(_)),
        "absence must be its own refusal; got {failure:?}"
    );
}

#[test]
fn the_same_identity_with_a_different_outcome_is_not_a_member() {
    // The index commits to (identity, outcome) pairs, not to identities. A
    // decision that was refused cannot be proven committed by reusing its
    // transaction identity — which is the forgery that matters for §5.2, since
    // it would let a caller claim a commit the repository never made.
    let entries = index();
    let root = outcome_index_root(&entries).expect("a root");
    let honest = outcome_index_proof(&entries, tx(0xB2), &refused(2, 0x52)).expect("a proof");

    assert!(
        verify_outcome_index_membership(&root, tx(0xB2), &refused(2, 0x52), &honest)
            .expect("verification completes"),
        "the honest case must hold first, or the refusal below proves nothing"
    );
    assert!(
        !verify_outcome_index_membership(&root, tx(0xB2), &committed(2, 0x52), &honest)
            .expect("verification completes"),
        "a refused decision must not verify as committed under the same identity"
    );
    assert!(
        outcome_index_proof(&entries, tx(0xB2), &committed(2, 0x52)).is_err(),
        "and no proof should be obtainable for the pair the index does not hold"
    );
}

#[test]
fn a_proof_does_not_verify_against_the_root_of_a_different_index() {
    let entries = index();
    let mut moved = index();
    moved.push((tx(0x77), committed(6, 0x56)));

    let root = outcome_index_root(&entries).expect("a root");
    let other_root = outcome_index_root(&moved).expect("a root");
    assert_ne!(
        root, other_root,
        "the two indices must differ, or this test is vacuous"
    );

    let proof = outcome_index_proof(&entries, tx(0xA1), &committed(1, 0x51)).expect("a proof");
    assert!(
        verify_outcome_index_membership(&root, tx(0xA1), &committed(1, 0x51), &proof)
            .expect("verification completes")
    );
    assert!(
        !verify_outcome_index_membership(&other_root, tx(0xA1), &committed(1, 0x51), &proof)
            .expect("verification completes"),
        "a proof is bound to the index that produced it, even for a decision present in both"
    );
}

#[test]
fn the_index_root_does_not_depend_on_the_order_entries_are_offered_in() {
    // The root sorts leaves by digest, so it commits to a multiset. Two callers
    // assembling the same decisions in different orders must publish the same
    // root, which is what lets the synchronous and asynchronous surfaces agree
    // without coordinating.
    let forward = index();
    let mut reversed = index();
    reversed.reverse();

    assert_eq!(
        outcome_index_root(&forward).expect("a root"),
        outcome_index_root(&reversed).expect("a root"),
        "the outcome-index root must depend on the decisions, not on their offered order"
    );
}

#[test]
fn a_single_decision_index_and_an_empty_one_are_distinct_and_both_usable() {
    // The boundary sizes. An empty index still has a root; it just has no
    // members, and asking for one is refused rather than answered.
    let empty = outcome_index_root(&[]).expect("an empty index has a root");
    let single = vec![(tx(0xA1), committed(1, 0x51))];
    let one = outcome_index_root(&single).expect("a root");
    assert_ne!(empty, one, "empty and single-decision indices must differ");

    let proof = outcome_index_proof(&single, tx(0xA1), &committed(1, 0x51)).expect("a proof");
    assert_eq!(proof.leaf_count(), 1);
    assert!(proof.siblings().is_empty(), "a lone leaf has no sibling");
    assert!(
        verify_outcome_index_membership(&one, tx(0xA1), &committed(1, 0x51), &proof)
            .expect("verification completes")
    );

    assert!(
        outcome_index_proof(&[], tx(0xA1), &committed(1, 0x51)).is_err(),
        "the empty index has no members to prove"
    );
}

#[test]
fn a_root_from_a_foreign_algorithm_does_not_verify() {
    // The root carries an algorithm code point. A digest from another
    // construction must be refused on sight rather than folded against, since
    // comparing bytes across algorithms is meaningless.
    //
    // THE FOREIGN ALGORITHM HAS TO BE A DIFFERENT ALGORITHM, not a different
    // identity domain. The first version of this test built its "foreign" root
    // from IdentityDomain::RefTransaction.algorithm().id() and failed, because
    // EVERY identity domain in this workspace is SHA-256 — so that id is
    // byte-identical to MerkleNode's and the guard correctly did not fire. The
    // test asserted a discrimination the workspace cannot exercise; the code
    // was right and the premise was false.
    //
    // SHA-1 is code point 1 and is genuinely a different construction, so this
    // is the only foreign root available to build today.
    let entries = index();
    let root = outcome_index_root(&entries).expect("a root");
    let proof = outcome_index_proof(&entries, tx(0xA1), &committed(1, 0x51)).expect("a proof");

    let sha1 = fgit_types::hash::DigestAlgorithmId::try_new(1).expect("code point one is SHA-1");
    assert_ne!(
        sha1,
        IdentityDomain::MerkleNode.algorithm().id(),
        "the two algorithms must actually differ, or this test cannot exercise the guard"
    );
    let foreign = fgit_types::hash::Digest::new(sha1, *root.bytes());
    assert!(
        !verify_outcome_index_membership(&foreign, tx(0xA1), &committed(1, 0x51), &proof)
            .expect("verification completes"),
        "the same bytes under another algorithm must not verify"
    );
    assert!(
        verify_outcome_index_membership(&root, tx(0xA1), &committed(1, 0x51), &proof)
            .expect("verification completes"),
        "and the permitted twin must still hold"
    );
}
