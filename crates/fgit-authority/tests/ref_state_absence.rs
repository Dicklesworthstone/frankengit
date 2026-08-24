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
    stage_repository_configuration,
};
use fgit_codec::RepositoryConfigurationBody;
use fgit_crypto::{MerkleRefusal, ref_state_merkle_root, verify_ref_state_non_membership_under};
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
