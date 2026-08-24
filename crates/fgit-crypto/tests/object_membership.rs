//! A decoded object-closure absence proof is a claim, and an impossible claim
//! must be refused rather than computed with.
//!
//! [`MerkleProof::new`] says outright that nothing it carries is trusted:
//! `index`, `leaf_count` and `siblings` all arrive over the wire. The ordered
//! absence verifier has to reason about adjacency, which means adding one to a
//! decoded index — and an addition on an attacker's number is the attacker's
//! arithmetic. At `usize::MAX` the unchecked form panics under the overflow
//! checks that debug and test builds enable by default, and wraps to zero under
//! the release profile, which sets none. A verifier that aborts on input it
//! exists to reject has let that input decide the outcome.
//!
//! Every refusal below is paired with the honest proof it was derived from, and
//! the honest one is asserted to verify in the same test. A file that only
//! showed forgeries failing would pass just as well against a verifier that
//! refused everything.

use fgit_crypto::{
    MerkleProof, ObjectClosureNeighbour, ObjectClosureNonMembershipProof,
    object_closure_merkle_root, object_closure_non_membership_proof,
    verify_object_closure_non_membership,
};
use fgit_types::native::{GitOid, GitOidSha1};

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

/// A closure whose members sort in seed order, so the query positions below are
/// chosen rather than discovered.
fn closure() -> [GitOid; 3] {
    [oid(0x10), oid(0x20), oid(0x30)]
}

#[test]
fn after_last_refuses_a_saturated_index_instead_of_overflowing() {
    let objects = closure();
    let root = object_closure_merkle_root(&objects).expect("a root over three objects");
    let absent = oid(0xF0);

    let honest = object_closure_non_membership_proof(&objects, &absent)
        .expect("an object past the last member is absent");
    assert!(
        matches!(honest, ObjectClosureNonMembershipProof::AfterLast { .. }),
        "the query was chosen to land past the last leaf"
    );
    assert!(
        verify_object_closure_non_membership(&root, &absent, &honest),
        "the honest absence proof must verify, or this test proves only that \
         the verifier refuses things"
    );

    // The same shape with the adjacency claim saturated. `leaf_count` is zero so
    // that a wrapping `usize::MAX + 1` would compare equal to it and carry on.
    let forged = ObjectClosureNonMembershipProof::AfterLast {
        last: Box::new(ObjectClosureNeighbour::new(
            oid(0x30),
            MerkleProof::new(usize::MAX, 0, Vec::new()),
        )),
    };
    assert!(
        !verify_object_closure_non_membership(&root, &absent, &forged),
        "a saturated last-position claim must be refused"
    );
}

#[test]
fn between_refuses_a_saturated_predecessor_index_instead_of_overflowing() {
    let objects = closure();
    let root = object_closure_merkle_root(&objects).expect("a root over three objects");
    let absent = oid(0x25);

    let honest = object_closure_non_membership_proof(&objects, &absent)
        .expect("an object inside the gap is absent");
    assert!(
        matches!(honest, ObjectClosureNonMembershipProof::Between { .. }),
        "the query was chosen to land strictly inside a gap"
    );
    assert!(
        verify_object_closure_non_membership(&root, &absent, &honest),
        "the honest absence proof must verify"
    );

    // Equal leaf counts so the first conjunct passes and the adjacency check is
    // genuinely the condition under test, rather than being short-circuited.
    let forged = ObjectClosureNonMembershipProof::Between {
        predecessor: Box::new(ObjectClosureNeighbour::new(
            oid(0x20),
            MerkleProof::new(usize::MAX, 3, Vec::new()),
        )),
        successor: Box::new(ObjectClosureNeighbour::new(
            oid(0x30),
            MerkleProof::new(0, 3, Vec::new()),
        )),
    };
    assert!(
        !verify_object_closure_non_membership(&root, &absent, &forged),
        "a saturated predecessor index must be refused"
    );
}
