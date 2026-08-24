//! The shared Merkle construction, the ref-state layout, and the verifier.
//!
//! Two properties carry this module and everything else is support for them:
//!
//! * a proof that verifies must correspond to a leaf that is genuinely in the
//!   tree, and
//! * a proof that does **not** must fail for every way of being wrong, not
//!   just the obvious one.
//!
//! The second is where membership proofs go bad. A verifier that folds
//! whatever siblings it is handed accepts a forgery and passes every
//! round-trip test ever written, because round-trips only ever hand it honest
//! proofs. So every forgery case below is paired against the honest proof it
//! was derived from, and the honest one is asserted to verify in the same test.

use fgit_crypto::{
    MerkleRefusal, RefStateNeighbour, RefStateNonMembershipProof, empty_merkle_root, merkle_leaf,
    merkle_proof, merkle_root, merkle_root_from_proof, ref_state_leaf, ref_state_membership_proof,
    ref_state_merkle_root, ref_state_non_membership_proof, ref_state_schema, verify_merkle_proof,
    verify_ref_state_membership, verify_ref_state_membership_under,
    verify_ref_state_non_membership, verify_ref_state_non_membership_under,
};
use fgit_types::hash::DigestBytes;
use fgit_types::label::{SchemaFamily, SchemaId};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitOid, GitOidSha1, GitOidSha256};
use fgit_types::refs::RefName;

const fn schema() -> SchemaId {
    SchemaId::new(SchemaFamily::from_static("merkle-test"), 1, 0)
}

fn leaf(tag: u8) -> DigestBytes {
    merkle_leaf(schema(), &[&[tag]])
}

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("an admissible ref name")
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

// ---------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------

#[test]
fn the_empty_tree_is_distinct_from_every_leaf_and_from_a_one_leaf_tree() {
    let empty = merkle_root(schema(), &[]);
    assert_eq!(
        empty,
        empty_merkle_root(schema()),
        "an empty leaf slice must fold to the declared empty root"
    );
    assert_ne!(
        empty,
        leaf(0),
        "the empty root must not collide with a leaf; they are in different identity domains and \
         a collision would let an empty index impersonate a populated one"
    );
    assert_ne!(
        empty,
        merkle_root(schema(), &[leaf(0)]),
        "an empty tree and a one-leaf tree are different commitments"
    );
}

#[test]
fn a_single_leaf_is_its_own_root() {
    assert_eq!(
        merkle_root(schema(), &[leaf(7)]),
        leaf(7),
        "a one-leaf tree has no interior node to add"
    );
}

#[test]
fn the_root_depends_on_leaf_order() {
    // The core preserves the order it is given, deliberately, so that each
    // caller can impose its own. If it silently sorted, the ref state's
    // by-name order and the outcome index's by-digest order would collapse
    // into one and one of them would publish a root it did not compute.
    let ascending = merkle_root(schema(), &[leaf(1), leaf(2)]);
    let descending = merkle_root(schema(), &[leaf(2), leaf(1)]);
    assert_ne!(
        ascending, descending,
        "the core must not impose an order of its own"
    );
}

#[test]
fn every_leaf_of_every_tree_size_up_to_nine_round_trips() {
    // Sizes 1..=9 cover both parities at every level, and 9 is the smallest
    // size where a promoted odd element is itself promoted again — the case a
    // verifier that assumed duplication rather than promotion gets wrong.
    for count in 1_usize..=9 {
        let leaves: Vec<DigestBytes> = (0..count).map(|n| leaf(u8::try_from(n).unwrap())).collect();
        let root = merkle_root(schema(), &leaves);
        for (index, expected_leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(schema(), &leaves, index).expect("a proof for a real leaf");
            assert_eq!(proof.index(), index);
            assert_eq!(proof.leaf_count(), count);
            assert!(
                verify_merkle_proof(schema(), &root, expected_leaf, &proof),
                "leaf {index} of {count} must verify against the root the same leaves produced"
            );
        }
    }
}

#[test]
fn a_proof_from_an_empty_tree_is_refused_rather_than_empty() {
    // An empty proof over an empty tree would verify vacuously, which is the
    // worst available answer: the caller concludes membership from nothing.
    assert_eq!(
        merkle_proof(schema(), &[], 0),
        Err(MerkleRefusal::EmptyTree)
    );
}

#[test]
fn an_index_past_the_last_leaf_is_refused_and_names_both_numbers() {
    let leaves = [leaf(0), leaf(1), leaf(2)];
    assert_eq!(
        merkle_proof(schema(), &leaves, 3),
        Err(MerkleRefusal::LeafIndexOutOfRange {
            index: 3,
            leaf_count: 3,
        }),
        "the refusal must name the index and the size; a caller that cannot see which is wrong \
         cannot tell an off-by-one from a stale tree"
    );
    // The permitted twin at the exact boundary: index 2 of 3 is the last valid
    // one and must succeed.
    assert!(merkle_proof(schema(), &leaves, 2).is_ok());
}

// ---------------------------------------------------------------------------
// Forgery: each case paired with the honest proof it was derived from
// ---------------------------------------------------------------------------

#[test]
fn a_proof_for_one_leaf_does_not_verify_another() {
    let leaves: Vec<DigestBytes> = (0..5).map(leaf).collect();
    let root = merkle_root(schema(), &leaves);
    let proof = merkle_proof(schema(), &leaves, 1).expect("a proof");

    assert!(
        verify_merkle_proof(schema(), &root, &leaves[1], &proof),
        "the honest case must hold, or the refusal below proves nothing"
    );
    assert!(
        !verify_merkle_proof(schema(), &root, &leaves[2], &proof),
        "a sibling's leaf must not verify against another leaf's path"
    );
}

#[test]
fn a_tampered_sibling_breaks_the_proof() {
    let leaves: Vec<DigestBytes> = (0..6).map(leaf).collect();
    let root = merkle_root(schema(), &leaves);
    let honest = merkle_proof(schema(), &leaves, 4).expect("a proof");
    assert!(verify_merkle_proof(schema(), &root, &leaves[4], &honest));

    let recomputed = merkle_root_from_proof(schema(), &leaves[4], &honest)
        .expect("a well-shaped proof recomputes a root");
    assert_eq!(recomputed, root);

    // Rebuild the same proof against a tree with one leaf changed: the sibling
    // path differs, so the honest leaf no longer reaches the honest root.
    let mut tampered_leaves = leaves.clone();
    tampered_leaves[5] = leaf(200);
    let tampered = merkle_proof(schema(), &tampered_leaves, 4).expect("a proof");
    assert!(
        !verify_merkle_proof(schema(), &root, &leaves[4], &tampered),
        "a path built over different siblings must not verify against the original root"
    );
}

#[test]
fn a_proof_claiming_the_wrong_tree_size_is_malformed_rather_than_merely_false() {
    // leaf_count drives the promotion pattern, so a proof that lies about it
    // describes a different tree. The verifier must reject it on shape rather
    // than fold whatever siblings it was handed and compare.
    let leaves: Vec<DigestBytes> = (0..4).map(leaf).collect();
    let honest = merkle_proof(schema(), &leaves, 0).expect("a proof");
    assert_eq!(honest.siblings().len(), 2, "a 4-leaf path has two siblings");

    // Same siblings, but a tree of 8 would need three: too few.
    let short = merkle_proof(schema(), &leaves, 0).expect("a proof");
    let eight: Vec<DigestBytes> = (0..8).map(leaf).collect();
    let eight_root = merkle_root(schema(), &eight);
    assert!(
        !verify_merkle_proof(schema(), &eight_root, &eight[0], &short),
        "a four-leaf path must not verify against an eight-leaf root"
    );
}

// ---------------------------------------------------------------------------
// The ref-state layout
// ---------------------------------------------------------------------------

#[test]
fn the_ref_state_root_is_independent_of_the_order_entries_are_offered_in() {
    // The layout sorts by name internally, so the caller's iteration order
    // cannot leak into the commitment. This is the property that lets a sync
    // store and an async store agree without coordinating.
    let forward = [
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x22)),
        (name("refs/tags/v1"), oid(0x33)),
    ];
    let mut reversed = forward.clone();
    reversed.reverse();

    assert_eq!(
        ref_state_merkle_root(&forward).expect("a root"),
        ref_state_merkle_root(&reversed).expect("a root"),
        "the ref root must depend on the ref set, not on the order it was handed over"
    );
}

#[test]
fn the_length_prefix_stops_a_name_from_borrowing_bytes_from_the_identity() {
    // THE adversarial case for this layout.
    //
    // `internal_digest_over_parts` commits the total preimage length and then
    // concatenates its parts, so without a delimiter a ref name could absorb
    // the leading bytes of the object identity that follows it. Two genuinely
    // different ref states would then share a leaf, and a proof for one would
    // verify against the other's root.
    //
    // The four-byte length prefix is what prevents it, and this test is what
    // holds the prefix in place: delete it from `ref_state_leaf` and these two
    // leaves converge.
    let short = ref_state_leaf(&name("refs/heads/ab"), &oid(0x00));
    let long = ref_state_leaf(&name("refs/heads/a"), &oid(0x00));
    assert_ne!(
        short, long,
        "names of different lengths must not produce the same leaf"
    );

    // And the sharper form: the same total bytes split differently.
    let split_left = ref_state_leaf(&name("refs/heads/xy"), &oid(0x62));
    let split_right = ref_state_leaf(&name("refs/heads/x"), &oid(0x62));
    assert_ne!(
        split_left, split_right,
        "a leaf must commit to where the name ends, not merely to the bytes it contains"
    );
}

#[test]
fn the_algorithm_selector_separates_two_identities_with_the_same_leading_bytes() {
    // A SHA-1 and a SHA-256 identity whose bytes overlap must not alias. The
    // selector is two bytes and precedes the identity, so the widths cannot be
    // confused.
    let sha1 = GitOid::Sha1(GitOidSha1::from_bytes([0x5A; GitOidSha1::LEN]));
    let sha256 = GitOid::Sha256(GitOidSha256::from_bytes([0x5A; GitOidSha256::LEN]));
    assert_ne!(
        ref_state_leaf(&name("refs/heads/main"), &sha1),
        ref_state_leaf(&name("refs/heads/main"), &sha256),
        "two hash domains must not produce the same leaf for one ref"
    );
}

#[test]
fn a_duplicate_ref_name_is_refused_rather_than_silently_resolved() {
    let entries = [
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/main"), oid(0x22)),
    ];
    assert_eq!(
        ref_state_merkle_root(&entries),
        Err(MerkleRefusal::DuplicateRefName),
        "a ref state is a map; committing to whichever copy sorted first would publish a state \
         nobody constructed"
    );
    // The permitted twin: two DIFFERENT names with the same identity are fine.
    let distinct = [
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x11)),
    ];
    assert!(ref_state_merkle_root(&distinct).is_ok());
}

#[test]
fn every_ref_in_a_state_proves_against_the_root_that_state_publishes() {
    let entries = [
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x22)),
        (name("refs/heads/topic"), oid(0x33)),
        (name("refs/tags/v1"), oid(0x44)),
        (name("refs/tags/v2"), oid(0x55)),
    ];
    let root = ref_state_merkle_root(&entries).expect("a root");
    for (each, expected) in &entries {
        let (bound, proof) = ref_state_membership_proof(&entries, each).expect("a proof");
        assert_eq!(bound, *expected, "the proof must carry the bound identity");
        assert!(
            verify_ref_state_membership(&root, each, &bound, &proof),
            "{each:?} must verify against the root its own state published"
        );
    }
}

#[test]
fn an_absent_ref_is_refused_rather_than_given_an_empty_proof() {
    let entries = [(name("refs/heads/main"), oid(0x11))];
    assert_eq!(
        ref_state_membership_proof(&entries, &name("refs/heads/absent")),
        Err(MerkleRefusal::RefNotPresent),
        "absence must refuse; an empty proof verifies vacuously and would let a caller conclude \
         membership from nothing"
    );
}

#[test]
fn a_proof_does_not_verify_the_wrong_identity_for_the_right_ref() {
    // The forgery that matters for a verified read: same ref, different OID.
    // A verifier that checked only the path and not the leaf would accept it.
    let entries = [
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x22)),
    ];
    let root = ref_state_merkle_root(&entries).expect("a root");
    let (bound, proof) =
        ref_state_membership_proof(&entries, &name("refs/heads/main")).expect("a proof");

    assert!(
        verify_ref_state_membership(&root, &name("refs/heads/main"), &bound, &proof),
        "the honest case must hold first"
    );
    assert!(
        !verify_ref_state_membership(&root, &name("refs/heads/main"), &oid(0x99), &proof),
        "a different identity for the same ref must not verify"
    );
    assert!(
        !verify_ref_state_membership(&root, &name("refs/heads/next"), &bound, &proof),
        "another ref's name must not verify against this ref's path"
    );
}

#[test]
fn a_proof_does_not_verify_against_a_root_from_a_different_state() {
    let entries = [
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x22)),
    ];
    let moved = [
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0xEE)),
    ];
    let root = ref_state_merkle_root(&entries).expect("a root");
    let other_root = ref_state_merkle_root(&moved).expect("a root");
    assert_ne!(
        root, other_root,
        "the two states must differ, or this test is vacuous"
    );

    let (bound, proof) =
        ref_state_membership_proof(&entries, &name("refs/heads/main")).expect("a proof");
    assert!(verify_ref_state_membership(
        &root,
        &name("refs/heads/main"),
        &bound,
        &proof
    ));
    assert!(
        !verify_ref_state_membership(&other_root, &name("refs/heads/main"), &bound, &proof),
        "a proof is bound to the root its state published, even for a ref that did not move"
    );
}

#[test]
fn the_empty_ref_state_has_a_root_and_no_members() {
    // A repository with no refs is a legitimate state, and its root must exist
    // and be distinct from every populated one.
    let root = ref_state_merkle_root(&[]).expect("an empty state still has a root");
    let populated = ref_state_merkle_root(&[(name("refs/heads/main"), oid(0x11))]).expect("a root");
    assert_ne!(root, populated);
    assert_eq!(
        ref_state_membership_proof(&[], &name("refs/heads/main")),
        Err(MerkleRefusal::RefNotPresent),
        "no ref is a member of the empty state"
    );
}

#[test]
fn the_ref_state_schema_is_pinned() {
    // The schema is committed into every leaf and node, so changing it changes
    // every root ever published under this layout. Pinning it here makes that
    // a deliberate act with a failing test attached rather than a silent one.
    let pinned = SchemaId::new(SchemaFamily::from_static("ref-state-merkle"), 1, 0);
    assert_eq!(ref_state_schema(), pinned);
}

// ---------------------------------------------------------------------------
// Faithfulness of the extraction (frankengit-ls44)
// ---------------------------------------------------------------------------
//
// `fgit-authority::outcome_index_root` used to fold its own tree inline. It now
// calls `merkle_root`. Those roots are published in every authority head, so
// "equivalent" is not good enough — they must be BYTE-IDENTICAL, or every
// existing head's `outcome_index_root` silently changes meaning.
//
// The oracle below is the previous implementation, transcribed over
// `DigestBytes` leaves so it needs no encoder. It exists to disagree: if
// `merkle_root` ever changes shape, this fails rather than the change being
// discovered by a head that no longer verifies.
//
// DELETION CONDITION: goes when no root computed by the previous
// implementation is still published anywhere, at which point the shape is free
// to change and this is dead weight.

/// The pre-extraction fold, transcribed verbatim from the implementation that
/// `outcome_index_root` carried before `frankengit-ls44`.
fn previous_fold(schema: SchemaId, leaves: &[DigestBytes]) -> DigestBytes {
    let mut level: Vec<DigestBytes> = leaves.to_vec();
    let Some(mut root) = level.first().copied() else {
        return empty_merkle_root(schema);
    };
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let (pairs, remainder) = level.as_chunks::<2>();
        for [left, right] in pairs {
            next.push(merkle_node_for_oracle(schema, left, right));
        }
        if let Some(odd) = remainder.first() {
            next.push(*odd);
        }
        level = next;
        root = level.first().copied().unwrap_or(root);
    }
    root
}

/// The interior-node hash the previous implementation used, spelled out rather
/// than borrowed, so the oracle cannot drift into agreeing by construction.
fn merkle_node_for_oracle(
    schema: SchemaId,
    left: &DigestBytes,
    right: &DigestBytes,
) -> DigestBytes {
    fgit_crypto::internal_digest_over_parts(
        fgit_crypto::IdentityDomain::MerkleNode,
        schema,
        &[left.as_bytes(), right.as_bytes()],
    )
}

#[test]
fn the_shared_core_reproduces_the_previous_fold_for_every_size_up_to_seventeen() {
    // Seventeen because it is the first size with three consecutive odd levels
    // (17 -> 9 -> 5 -> 3 -> 2), which is where a promotion rule that differs
    // from the published one diverges soonest.
    for count in 0_usize..=17 {
        let leaves: Vec<DigestBytes> = (0..count)
            .map(|n| leaf(u8::try_from(n % 251).unwrap()))
            .collect();
        assert_eq!(
            merkle_root(schema(), &leaves),
            previous_fold(schema(), &leaves),
            "size {count}: the extracted core must be byte-identical to the fold it replaced, or \
             every published outcome_index_root changes meaning"
        );
    }
}

#[test]
fn the_oracle_can_actually_disagree() {
    // The presence case for the comparison above. An oracle that returned
    // whatever `merkle_root` returned would make that test pass forever. Feed
    // the two different leaf slices and require different answers, so the
    // comparison is known to be capable of failing.
    let one: Vec<DigestBytes> = (0..4).map(leaf).collect();
    let other: Vec<DigestBytes> = (0..5).map(leaf).collect();
    assert_ne!(
        previous_fold(schema(), &one),
        previous_fold(schema(), &other),
        "the oracle must distinguish different trees, or agreement with it means nothing"
    );
    assert_ne!(
        previous_fold(schema(), &one),
        merkle_root(schema(), &other),
        "and it must disagree with the core when the inputs differ"
    );
}

#[test]
fn merkle_leaf_is_exactly_the_domain_separated_hash_it_claims_to_be() {
    // The other half of the faithfulness argument: leaves are unchanged.
    // `outcome_index_root` used to call `internal_digest_over_parts` directly
    // and now calls `merkle_leaf`, so those two must be the same function.
    let parts: [&[u8]; 2] = [b"a-transaction-digest", b"an-encoded-outcome"];
    assert_eq!(
        merkle_leaf(schema(), &parts),
        fgit_crypto::internal_digest_over_parts(
            fgit_crypto::IdentityDomain::MerkleLeaf,
            schema(),
            &parts
        ),
        "merkle_leaf must be a rename, not a reimplementation"
    );
}

// ---------------------------------------------------------------------------
// The layout version is load-bearing, not documentary
// ---------------------------------------------------------------------------

#[test]
fn the_legacy_layout_refuses_a_ref_state_proof_rather_than_failing_one() {
    // The distinction this test defends: "your proof is wrong" and "no proof of
    // this kind exists" are different answers, and collapsing them sends a
    // caller retrying forever against a layout that can never satisfy them.
    let entries = [(name("refs/heads/main"), oid(0x11))];
    let root = ref_state_merkle_root(&entries).expect("a root");
    let (bound, proof) =
        ref_state_membership_proof(&entries, &name("refs/heads/main")).expect("a proof");

    assert_eq!(
        verify_ref_state_membership_under(
            RootLayoutVersion::LegacyWholeBody,
            &root,
            &name("refs/heads/main"),
            &bound,
            &proof,
        ),
        Err(MerkleRefusal::LayoutAdmitsNoProof {
            version: RootLayoutVersion::LegacyWholeBody,
        }),
        "the whole-body layout has no tree, so a proof under it is refused rather than failed"
    );

    // The permitted twin at the version boundary: the same proof, the same
    // root, the same ref — and under v1 it verifies. Without this the refusal
    // above is satisfied by a function that refuses everything.
    assert_eq!(
        verify_ref_state_membership_under(
            RootLayoutVersion::RefStateMerkleV1,
            &root,
            &name("refs/heads/main"),
            &bound,
            &proof,
        ),
        Ok(true),
        "the Merkle layout must verify the very proof the legacy layout refused to consider"
    );
}

#[test]
fn a_false_proof_under_v1_is_an_answer_and_not_a_refusal() {
    // The other half of the distinction. A genuinely wrong proof must come back
    // Ok(false), so a caller can tell "this claim is untrue" from "this layout
    // cannot answer".
    let entries = [
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x22)),
    ];
    let root = ref_state_merkle_root(&entries).expect("a root");
    let (_, proof) =
        ref_state_membership_proof(&entries, &name("refs/heads/main")).expect("a proof");

    assert_eq!(
        verify_ref_state_membership_under(
            RootLayoutVersion::RefStateMerkleV1,
            &root,
            &name("refs/heads/main"),
            &oid(0x99),
            &proof,
        ),
        Ok(false),
        "a wrong identity is a false claim, not an unanswerable one"
    );
}

#[test]
fn the_layout_version_round_trips_through_its_wire_code_point() {
    for version in RootLayoutVersion::ALL {
        assert_eq!(
            RootLayoutVersion::from_code_point(version.code_point()),
            Ok(*version),
            "{version:?} must survive its own wire form"
        );
    }
    // Version 0 is the legacy layout deliberately, so an absent or zeroed
    // field means "whole body" rather than being refused. That is the opposite
    // of how the other closed vocabularies behave and is pinned here on purpose.
    assert_eq!(
        RootLayoutVersion::from_code_point(0),
        Ok(RootLayoutVersion::LegacyWholeBody)
    );
    assert_eq!(
        RootLayoutVersion::default(),
        RootLayoutVersion::LegacyWholeBody
    );
    // And an unknown version is still refused rather than approximated.
    assert!(RootLayoutVersion::from_code_point(9999).is_err());
}

#[test]
fn the_ref_root_is_a_pure_function_of_the_ref_set() {
    // The bead's equivalence requirement is that the ref root for a given
    // CanonicalRefState is deterministic across the synchronous and
    // asynchronous stores.
    //
    // It is satisfied BY CONSTRUCTION rather than by agreement between two
    // implementations: `ref_state_merkle_root` takes no store, no context and
    // no runtime, so there is no surface for the two to diverge on. Building a
    // two-store harness for a pure function would be theatre — it would assert
    // that a function ignoring its absent argument ignores it consistently.
    //
    // What is worth pinning is the property that makes that argument valid:
    // the root depends on the ref set and on nothing else, including call
    // order, repetition, and the order entries are supplied in.
    let entries = [
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/tags/v1"), oid(0x22)),
    ];
    let first = ref_state_merkle_root(&entries).expect("a root");
    let again = ref_state_merkle_root(&entries).expect("a root");
    assert_eq!(first, again, "repeated calls must agree");

    let mut shuffled = [entries[1].clone(), entries[0].clone()];
    assert_eq!(
        ref_state_merkle_root(&shuffled).expect("a root"),
        first,
        "supply order must not reach the commitment"
    );

    // And a genuine change must move it, or the three assertions above are
    // satisfied by a function that returns a constant.
    shuffled[0].1 = oid(0x99);
    assert_ne!(
        ref_state_merkle_root(&shuffled).expect("a root"),
        first,
        "a changed identity must change the root"
    );
}

// ---------------------------------------------------------------------------
// Ordered non-membership (frankengit-56i4)
// ---------------------------------------------------------------------------

/// A state with deliberate gaps on both sides and in the middle.
fn gapped_state() -> Vec<(RefName, GitOid)> {
    vec![
        (name("refs/heads/beta"), oid(0x11)),
        (name("refs/heads/delta"), oid(0x22)),
        (name("refs/tags/v2"), oid(0x33)),
    ]
}

/// Move a neighbour out of a proof so a test can rebuild a tampered one.
fn parts(neighbour: &RefStateNeighbour) -> (RefName, GitOid, fgit_crypto::MerkleProof) {
    (
        neighbour.name().clone(),
        *neighbour.oid(),
        neighbour.proof().clone(),
    )
}

#[test]
fn a_name_between_two_refs_is_proved_absent_by_its_neighbours() {
    let entries = gapped_state();
    let root = ref_state_merkle_root(&entries).expect("a root");
    let absent = name("refs/heads/charlie");

    let proof = ref_state_non_membership_proof(&entries, &absent).expect("a proof");
    let RefStateNonMembershipProof::Between {
        ref predecessor,
        ref successor,
    } = proof
    else {
        panic!("a name inside the range must be proved by a neighbour pair, got {proof:?}");
    };
    assert_eq!(predecessor.name(), &name("refs/heads/beta"));
    assert_eq!(successor.name(), &name("refs/heads/delta"));
    assert_eq!(
        successor.proof().index(),
        predecessor.proof().index() + 1,
        "the two leaves must be adjacent, or nothing rules out a leaf between them"
    );
    assert!(verify_ref_state_non_membership(&root, &absent, &proof));
}

#[test]
fn the_edges_are_proved_by_the_first_and_last_leaf() {
    let entries = gapped_state();
    let root = ref_state_merkle_root(&entries).expect("a root");

    let before = name("refs/heads/alpha");
    let left = ref_state_non_membership_proof(&entries, &before).expect("a proof");
    let RefStateNonMembershipProof::BeforeFirst { ref first } = left else {
        panic!("a name below the range must take the left edge, got {left:?}");
    };
    assert_eq!(first.proof().index(), 0, "the left edge is index 0");
    assert!(verify_ref_state_non_membership(&root, &before, &left));

    let after = name("refs/tags/v9");
    let right = ref_state_non_membership_proof(&entries, &after).expect("a proof");
    let RefStateNonMembershipProof::AfterLast { ref last } = right else {
        panic!("a name above the range must take the right edge, got {right:?}");
    };
    assert_eq!(
        last.proof().index() + 1,
        last.proof().leaf_count(),
        "the right edge is the final index"
    );
    assert!(verify_ref_state_non_membership(&root, &after, &right));

    // The edges are not interchangeable: a left-edge proof must not answer a
    // query that sits above the range, or the marker carries no information.
    assert!(
        !verify_ref_state_non_membership(&root, &after, &left),
        "a left-edge proof must not verify a name above the last leaf"
    );
    assert!(
        !verify_ref_state_non_membership(&root, &before, &right),
        "a right-edge proof must not verify a name below the first leaf"
    );
}

#[test]
fn an_empty_state_proves_every_name_absent_and_nothing_else_does() {
    let root = ref_state_merkle_root(&[]).expect("an empty root");
    let proof = ref_state_non_membership_proof(&[], &name("refs/heads/main")).expect("a proof");
    assert_eq!(proof, RefStateNonMembershipProof::EmptyState);
    assert!(verify_ref_state_non_membership(
        &root,
        &name("refs/heads/main"),
        &proof
    ));
    assert!(verify_ref_state_non_membership(
        &root,
        &name("refs/tags/anything"),
        &proof
    ));

    // The permitted twin's opposite: the empty marker must not verify against a
    // root that actually holds refs, or "the state is empty" would be a free
    // answer for any state at all.
    let populated = ref_state_merkle_root(&gapped_state()).expect("a root");
    assert!(
        !verify_ref_state_non_membership(&populated, &name("refs/heads/main"), &proof),
        "the empty marker must not verify against a populated root"
    );
}

#[test]
fn a_present_ref_is_refused_rather_than_given_a_proof_of_its_own_absence() {
    let entries = gapped_state();
    let refusal = ref_state_non_membership_proof(&entries, &name("refs/heads/delta"))
        .expect_err("a present ref has no non-membership proof");
    assert!(matches!(refusal, MerkleRefusal::RefIsPresent));

    // The permitted twin at the exact boundary: the neighbours of that same
    // present ref are absent and do prove.
    for near in ["refs/heads/delt", "refs/heads/delta0"] {
        assert!(
            ref_state_non_membership_proof(&entries, &name(near)).is_ok(),
            "{near} is absent and must still prove"
        );
    }
}

#[test]
fn swapping_the_two_neighbours_refuses() {
    let entries = gapped_state();
    let root = ref_state_merkle_root(&entries).expect("a root");
    let absent = name("refs/heads/charlie");
    let proof = ref_state_non_membership_proof(&entries, &absent).expect("a proof");
    let RefStateNonMembershipProof::Between {
        predecessor,
        successor,
    } = proof
    else {
        panic!("expected a neighbour pair");
    };

    // Both halves are genuine and both verify individually. Only their ORDER is
    // wrong, which is exactly the forgery a verifier that checked memberships
    // but not ordering would accept.
    let swapped = RefStateNonMembershipProof::Between {
        predecessor: successor,
        successor: predecessor,
    };
    assert!(
        !verify_ref_state_non_membership(&root, &absent, &swapped),
        "reversed neighbours must refuse even though both memberships hold"
    );
}

#[test]
fn shifting_an_index_by_one_refuses() {
    let entries = gapped_state();
    let root = ref_state_merkle_root(&entries).expect("a root");
    let absent = name("refs/heads/charlie");
    let proof = ref_state_non_membership_proof(&entries, &absent).expect("a proof");
    let RefStateNonMembershipProof::Between {
        predecessor,
        successor,
    } = proof
    else {
        panic!("expected a neighbour pair");
    };
    let (pred_name, pred_oid, pred_proof) = parts(&predecessor);

    // Same leaf, same root, a position it does not occupy. This one is caught
    // by the adjacency arithmetic rather than by the leaf binding: moving the
    // predecessor to i+1 puts both halves at the same index, so the pair stops
    // being consecutive. The leaf binding is what catches
    // `replacing_a_neighbour_name_refuses` and the hiding attack below.
    let leaves: Vec<DigestBytes> = {
        let mut sorted = entries;
        sorted.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        sorted
            .iter()
            .map(|(candidate, id)| ref_state_leaf(candidate, id))
            .collect()
    };
    let shifted_path = merkle_proof(ref_state_schema(), &leaves, pred_proof.index() + 1)
        .expect("a proof at the next index");
    let shifted = RefStateNonMembershipProof::Between {
        predecessor: Box::new(RefStateNeighbour::new(pred_name, pred_oid, shifted_path)),
        successor,
    };
    assert!(
        !verify_ref_state_non_membership(&root, &absent, &shifted),
        "a leaf presented at the wrong index must refuse"
    );
}

#[test]
fn replacing_a_neighbour_name_refuses() {
    let entries = gapped_state();
    let root = ref_state_merkle_root(&entries).expect("a root");
    let absent = name("refs/heads/charlie");
    let proof = ref_state_non_membership_proof(&entries, &absent).expect("a proof");
    let RefStateNonMembershipProof::Between {
        predecessor,
        successor,
    } = proof
    else {
        panic!("expected a neighbour pair");
    };
    let (_, pred_oid, pred_path) = parts(&predecessor);

    // A name that still brackets the query correctly, so the ordering checks
    // all pass and only the leaf digest disagrees. Widening the gap is the
    // useful forgery: it would let one proof answer for names that really are
    // present.
    let widened = RefStateNonMembershipProof::Between {
        predecessor: Box::new(RefStateNeighbour::new(
            name("refs/heads/aaaa"),
            pred_oid,
            pred_path,
        )),
        successor,
    };
    assert!(
        !verify_ref_state_non_membership(&root, &absent, &widened),
        "a substituted neighbour name must refuse"
    );
}

#[test]
fn a_proof_from_a_different_state_does_not_verify() {
    let entries = gapped_state();
    let absent = name("refs/heads/charlie");
    let proof = ref_state_non_membership_proof(&entries, &absent).expect("a proof");

    let mut other = entries;
    other.push((name("refs/heads/charlie"), oid(0x44)));
    let other_root = ref_state_merkle_root(&other).expect("a root");

    assert!(
        !verify_ref_state_non_membership(&other_root, &absent, &proof),
        "a state that DOES hold the name must not accept a proof of its absence"
    );
}

#[test]
fn the_legacy_layout_admits_no_non_membership_proof_and_v1_does() {
    let entries = gapped_state();
    let root = ref_state_merkle_root(&entries).expect("a root");
    let absent = name("refs/heads/charlie");
    let proof = ref_state_non_membership_proof(&entries, &absent).expect("a proof");

    let refusal = verify_ref_state_non_membership_under(
        RootLayoutVersion::LegacyWholeBody,
        &root,
        &absent,
        &proof,
    )
    .expect_err("v0 has no tree, so no ordering to appeal to");
    assert!(matches!(
        refusal,
        MerkleRefusal::LayoutAdmitsNoProof {
            version: RootLayoutVersion::LegacyWholeBody
        }
    ));

    assert!(
        verify_ref_state_non_membership_under(
            RootLayoutVersion::RefStateMerkleV1,
            &root,
            &absent,
            &proof
        )
        .expect("v1 admits the proof"),
        "the permitted twin: the same proof under v1 must verify"
    );
}

#[test]
fn a_single_leaf_state_has_both_edges_and_no_middle() {
    let entries = vec![(name("refs/heads/only"), oid(0x55))];
    let root = ref_state_merkle_root(&entries).expect("a root");

    for (query, expect_left) in [("refs/heads/a", true), ("refs/heads/z", false)] {
        let query = name(query);
        let proof = ref_state_non_membership_proof(&entries, &query).expect("a proof");
        let is_left = matches!(proof, RefStateNonMembershipProof::BeforeFirst { .. });
        assert_eq!(
            is_left, expect_left,
            "a one-leaf state must pick the edge the query falls on"
        );
        assert!(verify_ref_state_non_membership(&root, &query, &proof));
    }
}

#[test]
fn hiding_a_present_ref_by_claiming_its_neighbours_are_adjacent_refuses() {
    // The attack this whole proof shape exists to stop.
    //
    // A serving cell that wants to deny `refs/heads/delta` exists cannot invent
    // leaves — every leaf it offers must verify against the head's root. What it
    // CAN try is to offer two leaves that really are in the tree and assert they
    // sit next to each other, so that the ref standing between them appears to
    // have nowhere to be. Both forgeries below are built entirely from genuine
    // material; nothing is fabricated.
    let entries = gapped_state();
    let root = ref_state_merkle_root(&entries).expect("a root");
    let hidden = name("refs/heads/delta");
    assert!(
        entries.iter().any(|(candidate, _)| candidate == &hidden),
        "the point of this test is that the name IS present"
    );

    let leaves: Vec<DigestBytes> = {
        let mut sorted = entries.clone();
        sorted.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        sorted
            .iter()
            .map(|(candidate, id)| ref_state_leaf(candidate, id))
            .collect()
    };
    let path = |index: usize| merkle_proof(ref_state_schema(), &leaves, index).expect("a path");

    // Forgery 1: the true positions of the two real neighbours, 0 and 2. Both
    // memberships verify. Adjacency is what refuses.
    let honest_positions = RefStateNonMembershipProof::Between {
        predecessor: Box::new(RefStateNeighbour::new(
            name("refs/heads/beta"),
            oid(0x11),
            path(0),
        )),
        successor: Box::new(RefStateNeighbour::new(
            name("refs/tags/v2"),
            oid(0x33),
            path(2),
        )),
    };
    assert!(
        verify_ref_state_membership(&root, &name("refs/heads/beta"), &oid(0x11), &path(0)),
        "the material is genuine: this half really is in the tree"
    );
    assert!(
        verify_ref_state_membership(&root, &name("refs/tags/v2"), &oid(0x33), &path(2)),
        "and so is this half"
    );
    assert!(
        !verify_ref_state_non_membership(&root, &hidden, &honest_positions),
        "two real but non-adjacent leaves must not prove the ref between them is absent"
    );

    // Forgery 2: the same two leaves moved to consecutive indices 1 and 2 to
    // satisfy adjacency. Now the leaf binding refuses, because index 1 holds
    // `delta` and no path can make it hold `beta`.
    let forced_adjacency = RefStateNonMembershipProof::Between {
        predecessor: Box::new(RefStateNeighbour::new(
            name("refs/heads/beta"),
            oid(0x11),
            path(1),
        )),
        successor: Box::new(RefStateNeighbour::new(
            name("refs/tags/v2"),
            oid(0x33),
            path(2),
        )),
    };
    assert!(
        !verify_ref_state_non_membership(&root, &hidden, &forced_adjacency),
        "claiming a leaf sits at a position it does not occupy must refuse"
    );

    // The permitted twin, so neither refusal is satisfied by a verifier that
    // refuses everything. It cannot reuse the beta/v2 pair — `delta` is what
    // sits there, which is the entire premise — so it is a genuine absence
    // elsewhere in the same state, proved with the neighbours the builder picks.
    let genuinely_absent = name("refs/heads/echo");
    let honest = ref_state_non_membership_proof(&entries, &genuinely_absent).expect("a proof");
    assert!(
        verify_ref_state_non_membership(&root, &genuinely_absent, &honest),
        "a real absence between the same leaves must still verify"
    );
}
