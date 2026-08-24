#![forbid(unsafe_code)]
//! What a proof costs, bounded rather than benchmarked. `frankengit-fg037b`.
//!
//! # Claim class, stated first because it decides what this file may say
//!
//! Everything here is an **invariant or a structural property**, never a
//! timing. Per the claim lattice an invariant outranks a benchmark, and a
//! wall-clock number measured on one contended machine would be the weakest
//! possible evidence for the strongest-sounding claim. So: no `Instant`, no
//! throughput, no "fast". What is asserted is the *shape* of the cost —
//! how much a proof carries, and what a client may compute once per head
//! instead of once per answer.
//!
//! # The relation was measured before it was asserted
//!
//! `siblings.len() == ceil(log2(leaf_count))` is not a bound derived on paper
//! and hoped for. It was measured across sizes 1..33 first, including every
//! odd size where the fold's promote-the-last-element rule could have made it
//! differ, and it held with equality at each one. Asserting equality rather
//! than `<=` is deliberate: a `<=` bound stays green if proofs silently start
//! carrying fewer siblings than they need, which is a soundness change wearing
//! an efficiency costume.

use fgit_codec::{CryptoBodyIdentity, RepositoryConfigurationBody, body_id};
use fgit_crypto::{
    RefStateNonMembershipProof, ref_state_membership_proof, ref_state_non_membership_proof,
};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::refs::RefName;

fn name(index: usize) -> RefName {
    RefName::try_new(format!("refs/heads/b{index:04}").as_bytes()).expect("an admissible name")
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn state(leaves: usize) -> Vec<(RefName, GitOid)> {
    (0..leaves)
        .map(|index| {
            (
                name(index),
                oid(u8::try_from(index % 256).unwrap_or_default()),
            )
        })
        .collect()
}

/// Smallest `k` with `2^k >= n`. Zero for a single leaf, which is its own root.
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        usize::try_from((n - 1).ilog2()).unwrap_or(usize::MAX) + 1
    }
}

/// The sizes under test, chosen to include every shape the fold treats
/// differently: powers of two, one past a power of two, and odd counts where
/// the last element is promoted rather than paired.
const SIZES: [usize; 13] = [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 32, 33];

#[test]
fn a_membership_proof_carries_exactly_ceil_log2_siblings() {
    for leaves in SIZES {
        let entries = state(leaves);
        let (_, proof) =
            ref_state_membership_proof(&entries, &name(0)).expect("a membership proof");
        assert_eq!(
            proof.siblings().len(),
            ceil_log2(leaves),
            "{leaves} leaves: proof carried {} siblings, expected exactly {}",
            proof.siblings().len(),
            ceil_log2(leaves)
        );
        assert_eq!(
            proof.leaf_count(),
            leaves,
            "and the proof must declare the tree it was cut from"
        );
    }
}

#[test]
fn the_cost_actually_grows_with_the_tree_so_the_relation_is_not_a_constant() {
    // Guard against the assertion above being satisfied by a formula that
    // happens to match a constant proof size. If siblings never grew, ceil_log2
    // would be wrong rather than the proofs.
    let smallest = ref_state_membership_proof(&state(2), &name(0))
        .expect("proof")
        .1
        .siblings()
        .len();
    let largest = ref_state_membership_proof(&state(33), &name(0))
        .expect("proof")
        .1
        .siblings()
        .len();
    assert!(
        largest > smallest,
        "proof size must grow with the tree: 2 leaves gave {smallest}, 33 gave {largest}"
    );
    // And it must grow logarithmically, not linearly: 33 leaves is 16x the
    // leaves of 2 and must cost far less than 16x the siblings.
    assert!(
        largest < smallest * 16,
        "proof size grew faster than logarithmically: {smallest} -> {largest}"
    );
}

#[test]
fn an_absence_proof_costs_two_paths_in_the_middle_and_one_at_an_edge() {
    // Non-membership is the more expensive shape and it is worth pinning why:
    // it exhibits neighbours. Between two leaves that is two membership paths;
    // at an edge there is only one neighbour to exhibit. A caller sizing a
    // response budget needs that difference, and it is a property of the shape
    // rather than of any measurement.
    let leaves = 16;
    let entries = state(leaves);
    let expected_path = ceil_log2(leaves);

    // A name sorting strictly inside the range.
    let inside = RefName::try_new(b"refs/heads/b0004a").expect("a name inside the range");
    let middle = ref_state_non_membership_proof(&entries, &inside).expect("an absence proof");
    let RefStateNonMembershipProof::Between {
        predecessor,
        successor,
    } = &middle
    else {
        panic!("a name inside the range must be proved by a neighbour pair, got {middle:?}");
    };
    assert_eq!(predecessor.proof().siblings().len(), expected_path);
    assert_eq!(successor.proof().siblings().len(), expected_path);

    // A name sorting below everything: one neighbour, one path.
    let below = RefName::try_new(b"refs/heads/a").expect("a name below the range");
    let edge = ref_state_non_membership_proof(&entries, &below).expect("an absence proof");
    let RefStateNonMembershipProof::BeforeFirst { first } = &edge else {
        panic!("a name below the range must take the left edge, got {edge:?}");
    };
    assert_eq!(
        first.proof().siblings().len(),
        expected_path,
        "the single edge path is the same length as either middle path"
    );
}

#[test]
fn the_configuration_identity_is_a_pure_function_which_is_what_makes_it_cacheable_per_head() {
    // "Cacheable per head" is a claim about determinism, so that is what is
    // asserted. The configuration identity depends only on the configuration
    // body, so a client verifying many answers against one pinned head may
    // compute it ONCE. Nothing here claims a client currently does.
    let configuration = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: vec![b"refs/secret".to_vec()],
    };

    let first = body_id(&CryptoBodyIdentity, &configuration).expect("an identity");
    for _ in 0..8 {
        let again = body_id(&CryptoBodyIdentity, &configuration).expect("an identity");
        assert_eq!(
            (first.algorithm(), first.digest()),
            (again.algorithm(), again.digest()),
            "recomputation must be identical, or the value is not cacheable at all"
        );
    }

    // And it must actually DEPEND on the body, or "cache per head" would be
    // caching a constant. Changing the hidden-ref rules alone changes it, which
    // is also why a substituted configuration cannot pass the head's root.
    let stripped = RepositoryConfigurationBody {
        hidden_ref_rules: Vec::new(),
        ..configuration
    };
    let other = body_id(&CryptoBodyIdentity, &stripped).expect("an identity");
    assert_ne!(
        first.digest(),
        other.digest(),
        "the identity must distinguish configurations, or it secures nothing"
    );
}

#[test]
fn per_answer_cost_is_independent_of_how_many_refs_the_repository_holds() {
    // The property that makes verified reads usable at scale, and the reason
    // the log relation above matters rather than being trivia: growing the ref
    // set by 32x must not grow a single answer's proof by 32x.
    let small = ref_state_membership_proof(&state(2), &name(0))
        .expect("proof")
        .1;
    let large = ref_state_membership_proof(&state(32), &name(0))
        .expect("proof")
        .1;

    let ratio_leaves = 16;
    let growth = large
        .siblings()
        .len()
        .saturating_sub(small.siblings().len());
    assert!(
        growth < ratio_leaves,
        "a {ratio_leaves}x larger ref set added {growth} siblings, which is not logarithmic"
    );
    assert_eq!(
        large.siblings().len(),
        ceil_log2(32),
        "and the larger proof is exactly the logarithmic size"
    );
}
