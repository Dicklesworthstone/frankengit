//! Head-selected proofs that a ref is **absent** from the ref state.
//!
//! `frankengit-56i4`. The verifier core lives in `fgit-crypto` and is exercised
//! against the tree there; what these cases pin is the authority-side entry:
//! whether a proof may be emitted at all is a question about the head, and the
//! answer is asymmetric with verification in the same way `root_layout_for_proof`
//! already is.
//!
//! # Why absence needs the head and membership does not
//!
//! A membership proof either reproduces the root or it does not, so a client can
//! check one against a root obtained by any means. Absence concludes that
//! *nothing sorts between two adjacent leaves*, which is only meaningful if
//! there is a tree with an order. Under `RootLayoutVersion::LegacyWholeBody`
//! there is no tree, so emitting a proof would be inventing a shape the
//! published root does not have.
//!
//! These live in their own file rather than beside the layout cases because
//! `head_selected_layout.rs` was being edited by another agent at the time.

use fgit_authority::{
    MemoryAuthorityStore, OutcomeFailure, StoreInstanceId, head_selected_ref_state_absence_proof,
    head_selected_ref_state_absence_proof_with_head, stage_repository_configuration,
};
use fgit_codec::RepositoryConfigurationBody;
use fgit_crypto::{
    MerkleRefusal, ref_state_merkle_root, ref_state_merkle_root_v2,
    verify_ref_state_non_membership_under,
};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::refs::RefName;

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(1))
}

fn name(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).expect("an admissible ref name")
}

const fn oid(seed: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
}

fn entries() -> Vec<(RefName, GitOid)> {
    vec![
        (name("refs/heads/main"), oid(0x11)),
        (name("refs/heads/next"), oid(0x22)),
        (name("refs/tags/v1"), oid(0x33)),
    ]
}

const fn configuration(layout: RootLayoutVersion) -> RepositoryConfigurationBody {
    RepositoryConfigurationBody {
        root_layout: layout,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: Vec::new(),
    }
}

#[test]
fn a_head_selecting_v1_emits_an_absence_proof_and_a_v0_head_refuses_one() {
    let backing = store();
    let entries = entries();
    let absent = name("refs/heads/other");

    let v1 = stage_repository_configuration(
        &backing,
        &configuration(RootLayoutVersion::RefStateMerkleV1),
    )
    .expect("stages");
    let proof = head_selected_ref_state_absence_proof(&backing, &v1, &entries, &absent)
        .expect("a v1 head can emit an absence proof");
    let ref_root = ref_state_merkle_root(&entries).expect("a ref root");
    assert!(
        verify_ref_state_non_membership_under(
            RootLayoutVersion::RefStateMerkleV1,
            &ref_root,
            &absent,
            &proof
        )
        .expect("v1 admits the proof"),
        "the emitted proof must verify against the root the same entries publish"
    );

    // The v0 twin: same store, same entries, same query. Only the head differs.
    let v0 = stage_repository_configuration(
        &backing,
        &configuration(RootLayoutVersion::LegacyWholeBody),
    )
    .expect("stages");
    let failure = head_selected_ref_state_absence_proof(&backing, &v0, &entries, &absent)
        .expect_err("a legacy head has no tree to take neighbours from");
    let OutcomeFailure::MerkleShape(shape) = failure else {
        panic!("a layout with no tree must refuse as a merkle shape, got {failure:?}");
    };
    assert!(matches!(
        *shape,
        MerkleRefusal::LayoutAdmitsNoProof {
            version: RootLayoutVersion::LegacyWholeBody
        }
    ));
}

#[test]
fn asking_a_v1_head_to_prove_a_present_ref_absent_is_refused() {
    let backing = store();
    let entries = entries();
    let v1 = stage_repository_configuration(
        &backing,
        &configuration(RootLayoutVersion::RefStateMerkleV1),
    )
    .expect("stages");

    let present = name("refs/heads/main");
    let failure = head_selected_ref_state_absence_proof(&backing, &v1, &entries, &present)
        .expect_err("a present ref has no proof of its own absence");
    let OutcomeFailure::MerkleShape(shape) = failure else {
        panic!("expected a merkle-shape refusal, got {failure:?}");
    };
    assert!(matches!(*shape, MerkleRefusal::RefIsPresent));

    // The permitted twin at the boundary: a name one byte short of the present
    // one is absent, and the same head emits for it.
    assert!(
        head_selected_ref_state_absence_proof(&backing, &v1, &entries, &name("refs/heads/mai"))
            .is_ok(),
        "a near-miss name is genuinely absent and must still emit"
    );
}

#[test]
fn v2_producers_require_explicit_head_data_and_prove_the_exact_root() {
    let backing = store();
    let target = name("refs/heads/unborn");
    let query = name("refs/heads/other");
    for layout in [
        RootLayoutVersion::RefStateMerkleV2,
        RootLayoutVersion::RefStateAndObjectClosureMerkleV2,
    ] {
        let configuration_root =
            stage_repository_configuration(&backing, &configuration(layout)).unwrap();
        for state in [Vec::new(), entries()] {
            assert!(matches!(
                head_selected_ref_state_absence_proof(&backing, &configuration_root, &state, &query),
                Err(OutcomeFailure::RefHeadTargetRequired { layout: selected }) if selected == layout
            ));
            for head_target in [None, Some(&target)] {
                let proof = head_selected_ref_state_absence_proof_with_head(
                    &backing,
                    &configuration_root,
                    &state,
                    head_target,
                    &query,
                )
                .unwrap();
                let root = ref_state_merkle_root_v2(&state, head_target).unwrap();
                assert_eq!(
                    verify_ref_state_non_membership_under(layout, &root, &query, &proof),
                    Ok(true)
                );
                let changed_target = if head_target.is_some() {
                    None
                } else {
                    Some(&target)
                };
                let changed = ref_state_merkle_root_v2(&state, changed_target).unwrap();
                assert_eq!(
                    verify_ref_state_non_membership_under(layout, &changed, &query, &proof),
                    Ok(false)
                );
            }
        }
    }
}

#[test]
fn explicit_head_producer_preserves_v1_and_refuses_invalid_v2_head_or_present_ref() {
    let backing = store();
    let state = entries();
    let query = name("refs/heads/other");
    let target = name("refs/heads/main");
    let legacy_root = stage_repository_configuration(
        &backing,
        &configuration(RootLayoutVersion::RefStateMerkleV1),
    )
    .unwrap();
    let original =
        head_selected_ref_state_absence_proof(&backing, &legacy_root, &state, &query).unwrap();
    assert_eq!(
        head_selected_ref_state_absence_proof_with_head(
            &backing,
            &legacy_root,
            &state,
            Some(&target),
            &query
        )
        .unwrap(),
        original
    );

    let root = stage_repository_configuration(
        &backing,
        &configuration(RootLayoutVersion::RefStateMerkleV2),
    )
    .unwrap();
    for (head_target, query, expected) in [
        (
            name("refs/tags/v1"),
            query.clone(),
            MerkleRefusal::InvalidHeadTarget,
        ),
        (target.clone(), target.clone(), MerkleRefusal::RefIsPresent),
    ] {
        assert!(matches!(
            head_selected_ref_state_absence_proof_with_head(&backing, &root, &state, Some(&head_target), &query),
            Err(OutcomeFailure::MerkleShape(refusal)) if *refusal == expected
        ));
    }
    assert!(
        head_selected_ref_state_absence_proof_with_head(
            &backing,
            &root,
            &state,
            Some(&target),
            &query
        )
        .is_ok()
    );
}
