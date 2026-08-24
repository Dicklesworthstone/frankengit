#![forbid(unsafe_code)]
//! Canonical vectors for the incarnation-aware repository configuration.
//!
//! Schema major 2 is a deliberately separate body from the older
//! configuration. A resolver that requires an incarnation must never decode a
//! v1 body as though it carried one.

use fgit_codec::{
    CanonicalBody, DecodeLimits, RepositoryConfigurationBody,
    RepositoryIncarnationConfigurationBody, decode_body, encode_body,
};
use fgit_types::identity::RepositoryIncarnationId;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitHashAlgorithm;

fn incarnation_configuration() -> RepositoryIncarnationConfigurationBody {
    RepositoryIncarnationConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0xA5; 16]),
    }
}

#[test]
fn v2_incarnation_configuration_round_trips_its_exact_identity_binding() {
    let expected = incarnation_configuration();
    let encoded = encode_body(&expected).expect("the bounded v2 body encodes");

    assert_eq!(
        RepositoryIncarnationConfigurationBody::schema_id().major(),
        2,
        "incarnation binding is a major schema boundary, not a minor append"
    );
    assert_eq!(
        decode_body::<RepositoryIncarnationConfigurationBody>(&encoded, DecodeLimits::DEFAULT)
            .expect("the exact v2 body decodes"),
        expected,
        "the selected configuration retains the minted incarnation bytes"
    );
}

#[test]
fn v1_configuration_cannot_be_decoded_as_an_incarnation_configuration() {
    let legacy = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        hidden_ref_rules: Vec::new(),
    };
    let encoded = encode_body(&legacy).expect("the predecessor body encodes");

    assert!(
        decode_body::<RepositoryIncarnationConfigurationBody>(&encoded, DecodeLimits::DEFAULT)
            .is_err(),
        "a configuration without an incarnation binding must not impersonate v2"
    );
}
