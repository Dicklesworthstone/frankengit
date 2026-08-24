#![forbid(unsafe_code)]
//! Exact schema-2.1 configuration binding for verified-read envelopes.

use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, RepositoryIncarnationConfigurationBody,
    RepositoryIncarnationConfigurationBodyV2_1, body_id, harness::genesis_head,
};
use fgit_crypto::{ref_state_membership_proof, ref_state_merkle_root};
use fgit_types::hash::Digest;
use fgit_types::identity::RepositoryIncarnationId;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::refs::RefName;
use fgit_verified_read::{
    PinnedAuthorityHead, VerifiedMembership, VerifiedReadAnswer, VerifiedReadConfiguration,
    VerifiedReadEnvelope, VerifiedReadRefusal, decode_verified_read_envelope,
    encode_verified_read_envelope, verify_envelope,
};

fn name(value: &[u8]) -> RefName {
    RefName::try_new(value).expect("fixture ref name is valid")
}

const fn oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; GitOidSha1::LEN]))
}

const fn v2_0_configuration() -> RepositoryIncarnationConfigurationBody {
    RepositoryIncarnationConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x73; 16]),
    }
}

const fn v2_1_configuration() -> RepositoryIncarnationConfigurationBodyV2_1 {
    RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x73; 16]),
        policy_root: None,
    }
}

fn configuration_root(configuration: &RepositoryIncarnationConfigurationBodyV2_1) -> Digest {
    let identity = body_id(&CryptoBodyIdentity, configuration)
        .expect("the exact schema-2.1 configuration has an identity");
    Digest::new(identity.algorithm(), *identity.digest())
}

#[test]
fn v2_1_configuration_roundtrips_and_cannot_alias_v2_0_without_a_policy_root() {
    let main = name(b"refs/heads/main");
    let entries = vec![(main.clone(), oid(0xA2))];
    let (bound_oid, proof) =
        ref_state_membership_proof(&entries, &main).expect("the named ref is present");
    let selected = v2_1_configuration();
    let mut head = genesis_head();
    head.ref_root = ref_state_merkle_root(&entries).expect("the ref map is canonical");
    head.configuration_root = configuration_root(&selected);
    let pinned = PinnedAuthorityHead::new(head.clone());

    let envelope = VerifiedReadEnvelope::new_with_exact_configuration(
        head.clone(),
        Some(VerifiedReadConfiguration::RepositoryIncarnationV2_1(
            selected,
        )),
        VerifiedReadAnswer::RefMembership {
            name: main.clone(),
            oid: bound_oid,
            proof: Box::new(proof.clone()),
        },
    );
    let wire = encode_verified_read_envelope(&envelope).expect("schema-2.1 envelope encodes");
    let decoded = decode_verified_read_envelope(&wire, DecodeLimits::DEFAULT)
        .expect("schema-2.1 envelope decodes");
    assert_eq!(
        decoded, envelope,
        "the exact 2.1 body survives wire transport"
    );
    assert_eq!(
        verify_envelope(&pinned, &decoded),
        Ok(VerifiedMembership::Ref),
        "the exact 2.1 body must bind the ref layout to the selected head"
    );
    assert_eq!(
        encode_verified_read_envelope(&decoded).expect("decoded envelope re-encodes"),
        wire,
        "strict decoding must preserve the exact configuration bytes"
    );

    let v2_0_alias = VerifiedReadEnvelope::new_with_exact_configuration(
        head,
        Some(VerifiedReadConfiguration::RepositoryIncarnationV2(
            v2_0_configuration(),
        )),
        VerifiedReadAnswer::RefMembership {
            name: main,
            oid: bound_oid,
            proof: Box::new(proof),
        },
    );
    assert_eq!(
        verify_envelope(&pinned, &v2_0_alias),
        Err(VerifiedReadRefusal::ConfigurationRootMismatch),
        "a 2.0 body must not impersonate a 2.1 body merely because both normalize to no policy root"
    );
}
