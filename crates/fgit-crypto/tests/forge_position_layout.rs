//! Forge-position Merkle layout and adversarial proof checks.
//!
//! Every rejection is paired with an honest proof derived from the same state,
//! so a verifier that simply rejects every input cannot satisfy this suite.

use fgit_crypto::{
    ForgePositionRefusal, MerkleProof, forge_position_leaf, forge_position_membership_proof,
    forge_position_merkle_root, verify_forge_position_membership,
};
use fgit_types::hash::{Digest, DigestAlgorithmId};
use fgit_types::label::AsciiSlug;

fn stream(value: &str) -> AsciiSlug {
    AsciiSlug::try_new("forge_stream", value.as_bytes()).expect("valid stream label")
}

fn state() -> Vec<(AsciiSlug, u64)> {
    vec![
        (stream("pull-request/17"), 4),
        (stream("pull-request/3"), 9),
        (stream("release/stable"), 2),
        (stream("team/core"), 11),
    ]
}

#[test]
fn root_depends_on_the_map_not_the_offered_order() {
    let forward = state();
    let mut reverse = forward.clone();
    reverse.reverse();

    assert_eq!(
        forge_position_merkle_root(&forward).expect("root"),
        forge_position_merkle_root(&reverse).expect("root"),
        "caller iteration order must not become authenticated state"
    );

    let mut changed = forward;
    changed[0].1 += 1;
    assert_ne!(
        forge_position_merkle_root(&changed).expect("changed root"),
        forge_position_merkle_root(&reverse).expect("original root"),
        "the root must commit to the exact logical position"
    );
}

#[test]
fn duplicate_streams_are_refused_instead_of_resolved_by_sort_order() {
    let duplicate = vec![
        (stream("pull-request/17"), 4),
        (stream("pull-request/17"), 5),
    ];
    assert_eq!(
        forge_position_merkle_root(&duplicate),
        Err(ForgePositionRefusal::DuplicateStream)
    );
    assert_eq!(
        forge_position_membership_proof(&duplicate, &stream("pull-request/17")),
        Err(ForgePositionRefusal::DuplicateStream)
    );
}

#[test]
fn every_stream_proves_the_exact_position_the_root_commits_to() {
    let entries = state();
    let root = forge_position_merkle_root(&entries).expect("root");

    for (name, expected_position) in &entries {
        let (bound_position, proof) =
            forge_position_membership_proof(&entries, name).expect("membership proof");
        assert_eq!(bound_position, *expected_position);
        assert!(
            verify_forge_position_membership(&root, name, bound_position, &proof),
            "honest proof for {name} must verify"
        );
        assert!(
            !verify_forge_position_membership(
                &root,
                name,
                bound_position.saturating_add(1),
                &proof
            ),
            "the same path must not authorize a different position"
        );
    }
}

#[test]
fn a_real_path_cannot_be_relabelled_as_another_stream() {
    let entries = state();
    let root = forge_position_merkle_root(&entries).expect("root");
    let (position, proof) = forge_position_membership_proof(&entries, &stream("pull-request/17"))
        .expect("membership proof");

    assert!(verify_forge_position_membership(
        &root,
        &stream("pull-request/17"),
        position,
        &proof
    ));
    assert!(!verify_forge_position_membership(
        &root,
        &stream("pull-request/18"),
        position,
        &proof
    ));
}

#[test]
fn an_absent_stream_gets_no_vacuous_proof() {
    let entries = state();
    assert_eq!(
        forge_position_membership_proof(&entries, &stream("pull-request/99")),
        Err(ForgePositionRefusal::StreamNotPresent)
    );
    assert_eq!(
        forge_position_membership_proof(&[], &stream("pull-request/99")),
        Err(ForgePositionRefusal::StreamNotPresent)
    );
}

#[test]
fn proof_shape_and_root_algorithm_are_both_authenticated() {
    let entries = state();
    let root = forge_position_merkle_root(&entries).expect("root");
    let name = stream("release/stable");
    let (position, honest) =
        forge_position_membership_proof(&entries, &name).expect("membership proof");
    assert!(verify_forge_position_membership(
        &root, &name, position, &honest
    ));

    let malformed = MerkleProof::new(
        honest.index(),
        honest.leaf_count().saturating_add(1),
        honest.siblings().to_vec(),
    );
    assert!(!verify_forge_position_membership(
        &root, &name, position, &malformed
    ));

    let foreign_algorithm = Digest::new(
        DigestAlgorithmId::try_new(1).expect("SHA-1 code point"),
        *root.bytes(),
    );
    assert!(!verify_forge_position_membership(
        &foreign_algorithm,
        &name,
        position,
        &honest
    ));
}

#[test]
fn length_delimited_stream_names_produce_distinct_leaves() {
    assert_ne!(
        forge_position_leaf(&stream("stream/a"), 0x6200_0000_0000_0000),
        forge_position_leaf(&stream("stream/ab"), 0),
        "a variable-length stream name cannot borrow bytes from the position"
    );
}
