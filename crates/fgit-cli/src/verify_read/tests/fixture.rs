//! Independent native bytes and a real Merkle proof for command-layer tests.
use fgit_codec::{CryptoBodyIdentity, RepositoryConfigurationBody, body_id, harness::genesis_head};
use fgit_crypto::{
    GitObjectKind, git_object_id, ref_state_membership_proof, ref_state_merkle_root,
};
use fgit_types::{Digest, GitHashAlgorithm, RefName, RootLayoutVersion};
use fgit_verified_read::blob::VerifiedBlobEnvelope;
use fgit_verified_read::{VerifiedReadAnswer, VerifiedReadEnvelope};

pub(super) fn envelope(format: GitHashAlgorithm, bytes: &[u8]) -> VerifiedBlobEnvelope {
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let blob = git_object_id(format, GitObjectKind::Blob, bytes);
    let tree = [b"100644 file\0".as_slice(), blob.as_bytes()].concat();
    let tree_id = git_object_id(format, GitObjectKind::Tree, &tree);
    let commit = format!("tree {tree_id}\nauthor Fixture <test@example.invalid> 1 +0000\ncommitter Fixture <test@example.invalid> 1 +0000\n\nproof command\n").into_bytes();
    let tip = git_object_id(format, GitObjectKind::Commit, &commit);
    let configuration = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: format,
        hidden_ref_rules: vec![],
    };
    let configuration_id = body_id(&CryptoBodyIdentity, &configuration).unwrap();
    let mut head = genesis_head();
    head.configuration_root = Digest::new(configuration_id.algorithm(), *configuration_id.digest());
    let entries = vec![(reference.clone(), tip)];
    head.ref_root = ref_state_merkle_root(&entries).unwrap();
    let (_, proof) = ref_state_membership_proof(&entries, &reference).unwrap();
    let proof = VerifiedReadEnvelope::new(
        head,
        Some(configuration),
        VerifiedReadAnswer::RefMembership {
            name: reference,
            oid: tip,
            proof: Box::new(proof),
        },
    );
    VerifiedBlobEnvelope::from_parts(proof, b"file".to_vec(), commit, vec![tree], bytes.to_vec())
        .unwrap()
}
