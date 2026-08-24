//! Saturated positions in decoded ref-absence proofs refuse without arithmetic.
//!
//! `MerkleProof::new` is the constructor used at the wire-decoder boundary, and
//! explicitly treats `index`, `leaf_count`, and `siblings` as untrusted claims.
//! The adjacency checks must therefore reject `usize::MAX`, rather than panic in
//! checked builds or compare against a wrapped zero in release builds.
//!
//! Each hostile proof is paired with the honest proof for the same query and
//! state. That permitted twin prevents an always-false verifier from satisfying
//! the refusal assertion.

use fgit_crypto::{
    MerkleProof, RefStateNeighbour, RefStateNonMembershipProof, ref_state_merkle_root,
    ref_state_non_membership_proof, verify_ref_state_non_membership,
};
use fgit_types::native::{GitOid, GitOidSha1};
use fgit_types::refs::RefName;

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("an admissible ref name")
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn state() -> Vec<(RefName, GitOid)> {
    vec![
        (name("refs/heads/beta"), oid(0x10)),
        (name("refs/heads/delta"), oid(0x20)),
        (name("refs/tags/v2"), oid(0x30)),
    ]
}

#[test]
fn after_last_refuses_a_saturated_index_instead_of_overflowing() {
    let entries = state();
    let root = ref_state_merkle_root(&entries).expect("a root over three refs");
    let absent = name("refs/tags/v9");

    let honest =
        ref_state_non_membership_proof(&entries, &absent).expect("a ref past the last is absent");
    assert!(
        matches!(honest, RefStateNonMembershipProof::AfterLast { .. }),
        "the query was chosen to land past the last leaf"
    );
    assert!(
        verify_ref_state_non_membership(&root, &absent, &honest),
        "the honest absence proof must verify"
    );

    // `leaf_count` is zero so an unchecked release-build wrap from MAX to zero
    // would satisfy the adjacency comparison and continue through the verifier.
    let hostile = RefStateNonMembershipProof::AfterLast {
        last: Box::new(RefStateNeighbour::new(
            name("refs/tags/v2"),
            oid(0x30),
            MerkleProof::new(usize::MAX, 0, Vec::new()),
        )),
    };
    assert!(
        !verify_ref_state_non_membership(&root, &absent, &hostile),
        "a saturated last-position claim must be refused"
    );
}

#[test]
fn between_refuses_a_saturated_predecessor_index_instead_of_overflowing() {
    let entries = state();
    let root = ref_state_merkle_root(&entries).expect("a root over three refs");
    let absent = name("refs/heads/charlie");

    let honest = ref_state_non_membership_proof(&entries, &absent)
        .expect("a ref strictly inside the gap is absent");
    assert!(
        matches!(honest, RefStateNonMembershipProof::Between { .. }),
        "the query was chosen to land strictly inside a gap"
    );
    assert!(
        verify_ref_state_non_membership(&root, &absent, &honest),
        "the honest absence proof must verify"
    );

    // Equal leaf counts make the adjacency condition the first discriminating
    // check. With unchecked arithmetic, MAX either panics or wraps to the
    // successor's claimed index zero.
    let hostile = RefStateNonMembershipProof::Between {
        predecessor: Box::new(RefStateNeighbour::new(
            name("refs/heads/beta"),
            oid(0x10),
            MerkleProof::new(usize::MAX, 3, Vec::new()),
        )),
        successor: Box::new(RefStateNeighbour::new(
            name("refs/heads/delta"),
            oid(0x20),
            MerkleProof::new(0, 3, Vec::new()),
        )),
    };
    assert!(
        !verify_ref_state_non_membership(&root, &absent, &hostile),
        "a saturated predecessor index must be refused"
    );
}
