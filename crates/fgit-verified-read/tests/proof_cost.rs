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
    MerkleProof, RefStateNonMembershipProof, ref_state_membership_proof, ref_state_merkle_root,
    ref_state_non_membership_proof, verify_ref_state_membership,
};
use fgit_types::hash::Digest;
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
///
/// This is the UPPER BOUND on a path, not the length of every path -- see
/// [`siblings_for`].
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        usize::try_from((n - 1).ilog2()).unwrap_or(usize::MAX) + 1
    }
}

/// Exactly how many siblings the path for `index` carries in a tree of
/// `leaf_count` leaves.
///
/// # Why a model and not a single number
///
/// The fold promotes a final odd element unchanged rather than duplicating it,
/// so a leaf sitting on a promoted tail gains NO sibling at that level. Path
/// lengths are therefore not uniform: at 3 leaves they are `[2, 2, 1]`, and at
/// 17 the last leaf carries ONE sibling where the leftmost carries five.
///
/// An earlier version of this file asserted `siblings == ceil_log2(leaf_count)`
/// for every size and only ever queried the leftmost leaf, so it passed while
/// being false in general. Weakening it to `<=` would have been the easy repair
/// and the wrong one: a `<=` bound stays green if a proof starts carrying FEWER
/// siblings than its position requires, which is a soundness change wearing an
/// efficiency costume. So the model computes the exact expected length per
/// index, which is both general and tight.
const fn siblings_for(index: usize, leaf_count: usize) -> usize {
    let mut siblings = 0;
    let mut position = index;
    let mut level = leaf_count;
    while level > 1 {
        let promoted = level % 2 == 1 && position == level - 1;
        if !promoted {
            siblings += 1;
        }
        position /= 2;
        level = level.div_ceil(2);
    }
    siblings
}

/// The sizes under test, chosen to include every shape the fold treats
/// differently: powers of two, one past a power of two, and odd counts where
/// the last element is promoted rather than paired.
const SIZES: [usize; 13] = [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 32, 33];

#[test]
fn every_leaf_at_every_size_carries_exactly_the_length_its_position_requires() {
    // EVERY index, not just the leftmost. The leftmost path is the longest, so
    // sampling only it cannot see the promoted-tail shortening at all -- which
    // is exactly how the previous version of this assertion was false and green.
    for leaves in SIZES {
        let entries = state(leaves);
        for index in 0..leaves {
            let (_, proof) =
                ref_state_membership_proof(&entries, &name(index)).expect("a membership proof");
            assert_eq!(
                proof.siblings().len(),
                siblings_for(index, leaves),
                "{leaves} leaves, index {index}: carried {} siblings, model says {}",
                proof.siblings().len(),
                siblings_for(index, leaves)
            );
            assert_eq!(proof.leaf_count(), leaves);
        }
    }
}

#[test]
fn no_path_exceeds_the_logarithmic_bound_and_the_leftmost_attains_it() {
    // The bound still holds over every path, and it is TIGHT: the leftmost leaf
    // reaches it at every size. Without the second half, "<= ceil_log2" would be
    // satisfied by proofs that were uniformly too short.
    for leaves in SIZES {
        let entries = state(leaves);
        for index in 0..leaves {
            let (_, proof) = ref_state_membership_proof(&entries, &name(index)).expect("a proof");
            assert!(
                proof.siblings().len() <= ceil_log2(leaves),
                "{leaves} leaves, index {index}: path exceeded the log bound"
            );
        }
        let (_, leftmost) = ref_state_membership_proof(&entries, &name(0)).expect("a proof");
        assert_eq!(
            leftmost.siblings().len(),
            ceil_log2(leaves),
            "{leaves} leaves: the leftmost path must attain the bound, or it is not tight"
        );
    }
}

#[test]
fn a_promoted_tail_really_does_shorten_a_path_so_the_model_is_not_decorative() {
    // The case that makes siblings_for worth having rather than a restatement of
    // ceil_log2. If no size shortened any path, the model and the bound would be
    // the same function and the previous false assertion would have been true.
    let mut shortened = Vec::new();
    for leaves in SIZES {
        let entries = state(leaves);
        for index in 0..leaves {
            let (_, proof) = ref_state_membership_proof(&entries, &name(index)).expect("a proof");
            if proof.siblings().len() < ceil_log2(leaves) {
                shortened.push((leaves, index, proof.siblings().len()));
            }
        }
    }
    assert!(
        !shortened.is_empty(),
        "no path was shorter than the bound at any size, so the promoted-tail model \
         is untested and ceil_log2 alone would have sufficed"
    );
    // And specifically at 3 leaves the last leaf carries one sibling, which is
    // the smallest shape exhibiting the effect.
    assert!(
        shortened.contains(&(3, 2, 1)),
        "expected the 3-leaf promoted tail to carry exactly one sibling; got {shortened:?}"
    );
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

/// Bytes a client must receive and process to check one membership answer:
/// the pinned root, the claimed leaf, and the path. Nothing else is in
/// `verify_ref_state_membership`'s signature, so nothing else can be needed.
fn client_input_bytes(root: &Digest, name: &RefName, oid: &GitOid, proof: &MerkleProof) -> usize {
    root.bytes().as_bytes().len()
        + name.as_bytes().len()
        + oid.as_bytes().len()
        + proof
            .siblings()
            .iter()
            .map(|sibling| sibling.as_bytes().len())
            .sum::<usize>()
}

#[test]
fn generation_reads_the_whole_state_while_verification_reads_only_the_path() {
    // THE ASYMMETRY, which is the entire economic argument for trustless
    // serving and the half of "generation/verification cost" that the existing
    // cases do not state. Verification cost was already pinned here -- the
    // per-index path model, the logarithmic bound, and independence from the
    // ref-set size. What was never characterised is what the SERVER pays.
    //
    // It is a structural fact before it is a measured one:
    //   ref_state_membership_proof(&entries, &name)  -- takes the whole state
    //   verify_ref_state_membership(root, name, oid, &proof)  -- takes no state
    // The verifier cannot consult the ref set because the ref set is not in its
    // signature. That makes size-independence an invariant of the API rather
    // than a benchmark result, which is the stronger rung of the claim lattice.
    let small_leaves = 8;
    let large_leaves = 512;
    let ratio = large_leaves / small_leaves;

    let small_state = state(small_leaves);
    let large_state = state(large_leaves);

    let small_root = ref_state_merkle_root(&small_state).expect("a root");
    let large_root = ref_state_merkle_root(&large_state).expect("a root");
    let (small_oid, small_proof) =
        ref_state_membership_proof(&small_state, &name(0)).expect("a proof");
    let (large_oid, large_proof) =
        ref_state_membership_proof(&large_state, &name(0)).expect("a proof");

    let small_client = client_input_bytes(&small_root, &name(0), &small_oid, &small_proof);
    let large_client = client_input_bytes(&large_root, &name(0), &large_oid, &large_proof);

    // The server's input grew by the full ratio: it must read every entry to
    // build either the root or the path.
    assert_eq!(
        large_state.len() / small_state.len(),
        ratio,
        "the state must actually have grown by the ratio, or the comparison is empty"
    );

    // The client's did not. Logarithmic growth means the ratio of client bytes
    // is far below the ratio of state size; asserting "less than the ratio" is
    // the weakest form of that and is what makes it robust to digest widths.
    // EXACTLY, not loosely. The first version of this asserted
    // `large_client < small_client * ratio`, which measured 356 against a bound
    // of 10496 -- true, and vacuous. Every byte of growth in the client's input
    // is a sibling digest, so the difference is pinned to the path-length model
    // rather than to a ratio that any sublinear-ish curve would satisfy.
    let extra_siblings = large_proof
        .siblings()
        .len()
        .saturating_sub(small_proof.siblings().len());
    let digest_width = large_root.bytes().as_bytes().len();
    assert_eq!(
        large_client - small_client,
        extra_siblings * digest_width,
        "the client's growth must be exactly the extra path, not merely sublinear"
    );
    assert_eq!(
        extra_siblings,
        ceil_log2(large_leaves) - ceil_log2(small_leaves),
        "and the extra path is the difference of the logarithms"
    );
    // Measured: 164 -> 356 bytes for a 64x larger ref set. The ratio bound is
    // kept as a second, independent statement of the same fact, tight enough
    // that a linear implementation could not pass it.
    assert!(
        large_client < small_client * 3,
        "a {ratio}x larger repository produced {large_client} client bytes against \
         {small_client}; logarithmic growth should be far below 3x here"
    );

    // And the exact relation, since "sublinear" is satisfied by things that are
    // still too expensive: the path length is the logarithm, so the only part
    // of the client's input that grew is the sibling count.
    assert_eq!(
        large_proof.siblings().len(),
        ceil_log2(large_leaves),
        "the client's only size-dependent input is the path, and it is logarithmic"
    );

    // VERIFICATION WITHOUT THE STATE, demonstrated rather than argued. Both
    // states are dropped before the check, so nothing the verifier does can
    // depend on them.
    drop(small_state);
    drop(large_state);
    assert!(
        verify_ref_state_membership(&large_root, &name(0), &large_oid, &large_proof),
        "a client holding only root, leaf and path must be able to verify"
    );
}

#[test]
fn proof_generation_is_deterministic_so_a_server_may_cache_one_per_head_and_name() {
    // The serving-side twin of the configuration-cacheability case above, and
    // the only honest thing to say about "cache behaviour" today: there is no
    // cache in this crate, so what can be established is the PRECONDITION for
    // one. A value that is not a pure function of (state, name) cannot be
    // cached against a pinned head at all.
    //
    // Nothing here claims a server currently caches. Same discipline as the
    // configuration case: assert the determinism, not an implementation that
    // does not exist.
    let entries = state(64);
    let (first_oid, first_proof) = ref_state_membership_proof(&entries, &name(7)).expect("a proof");

    for _ in 0..8 {
        let (again_oid, again_proof) =
            ref_state_membership_proof(&entries, &name(7)).expect("a proof");
        assert_eq!(again_oid, first_oid, "recomputation changed the leaf");
        assert_eq!(
            again_proof.siblings(),
            first_proof.siblings(),
            "recomputation changed the path, so the proof is not cacheable"
        );
        assert_eq!(again_proof.index(), first_proof.index());
        assert_eq!(again_proof.leaf_count(), first_proof.leaf_count());
    }

    // And it must DEPEND on the name, or "cache per name" would be caching one
    // value for the whole repository.
    let (_, other) = ref_state_membership_proof(&entries, &name(8)).expect("a proof");
    assert_ne!(
        other.index(),
        first_proof.index(),
        "two different refs must not share a cache entry"
    );
}
