#![forbid(unsafe_code)]
//! Exact schema-major-2 configuration binding for verified ref answers.

use fgit_codec::{
    CryptoBodyIdentity, RepositoryIncarnationConfigurationBody, body_id, harness::genesis_head,
};
use fgit_crypto::{ref_state_membership_proof, ref_state_merkle_root};
use fgit_types::hash::Digest;
use fgit_types::identity::RepositoryIncarnationId;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::refs::RefName;
use fgit_verified_read::{
    PinnedAuthorityHead, VerifiedMembership, VerifiedReadAnswer, VerifiedReadConfiguration,
    VerifiedReadEnvelope, VerifiedReadRefusal, verify_envelope,
};

fn name(value: &[u8]) -> RefName {
    RefName::try_new(value).expect("fixture ref name is valid")
}

const fn oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; GitOidSha1::LEN]))
}

const fn configuration(incarnation: u8) -> RepositoryIncarnationConfigurationBody {
    RepositoryIncarnationConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([incarnation; 16]),
    }
}

fn configuration_root(configuration: &RepositoryIncarnationConfigurationBody) -> Digest {
    let identity = body_id(&CryptoBodyIdentity, configuration)
        .expect("the exact schema-major-2 configuration has an identity");
    Digest::new(identity.algorithm(), *identity.digest())
}

#[test]
fn an_incarnation_configuration_verifies_only_under_its_exact_authority_head_root() {
    let main = name(b"refs/heads/main");
    let entries = vec![(main.clone(), oid(0xA1))];
    let (bound_oid, proof) =
        ref_state_membership_proof(&entries, &main).expect("the named ref is present");
    let selected = configuration(0x71);
    let mut head = genesis_head();
    head.ref_root = ref_state_merkle_root(&entries).expect("the ref map is canonical");
    head.configuration_root = configuration_root(&selected);

    let envelope = VerifiedReadEnvelope::new_with_exact_configuration(
        head.clone(),
        Some(VerifiedReadConfiguration::RepositoryIncarnationV2(selected)),
        VerifiedReadAnswer::RefMembership {
            name: main,
            oid: bound_oid,
            proof: Box::new(proof),
        },
    );
    let pinned = PinnedAuthorityHead::new(head);
    assert_eq!(
        verify_envelope(&pinned, &envelope),
        Ok(VerifiedMembership::Ref),
        "schema-major-2 configuration identity must bind the V1 ref layout to the served head"
    );

    let mismatched = VerifiedReadEnvelope::new_with_exact_configuration(
        envelope.head().clone(),
        Some(VerifiedReadConfiguration::RepositoryIncarnationV2(
            configuration(0x72),
        )),
        envelope.answer().clone(),
    );
    assert_eq!(
        verify_envelope(&pinned, &mismatched),
        Err(VerifiedReadRefusal::ConfigurationRootMismatch),
        "a different repository incarnation must not impersonate the head-selected configuration"
    );
}
