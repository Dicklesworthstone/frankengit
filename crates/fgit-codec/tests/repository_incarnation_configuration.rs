#![forbid(unsafe_code)]
//! Canonical vectors for the incarnation-aware repository configuration.
//!
//! Schema major 2 is a deliberately separate body from the older
//! configuration. A resolver that requires an incarnation must never decode a
//! v1 body as though it carried one.
//!
//! The frame below is written directly from the frame and payload
//! specification, not produced by the encoder under test. That matters: a
//! round-trip through `encode_body` and back cannot see a SYMMETRIC defect,
//! because a field mis-encoded and mis-decoded the same way still compares
//! equal. Only an independently written vector pins the bytes.

use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, RepositoryConfigurationBody,
    RepositoryIncarnationConfigurationBody, RepositoryIncarnationConfigurationBodyV2_1,
    canonical_body_bytes, decode_body, encode_body, read_frame_header,
};
use fgit_crypto::DigestAlgorithm;
use fgit_types::error::TypeRefusal;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::RepositoryIncarnationId;
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitHashAlgorithm;

const fn incarnation_configuration() -> RepositoryIncarnationConfigurationBody {
    RepositoryIncarnationConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0xA5; 16]),
    }
}

fn incarnation_configuration_v2_1(
    policy_root: Option<Digest>,
) -> RepositoryIncarnationConfigurationBodyV2_1 {
    RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0xA5; 16]),
        policy_root,
    }
}

/// The v2 body at schema 2.0: two big-endian `u16` code points, `root_layout`
/// then `object_format`, followed by the sixteen raw incarnation bytes with no
/// length prefix of their own.
const INCARNATION_CONFIGURATION_GOLDEN: &[u8] = b"FGC1\
    \x00\x01\x00\x00\
    \x00\x00\x00\x26frankengit/repository-configuration/v1\
    \x00\x00\x00\x18repository-configuration\
    \x00\x02\x00\x00\
    \x00\x00\x00\x14\x00\x01\x00\x02\
    \xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5";

/// Schema 2.1 is the byte-stable 2.0 prefix followed by the explicit absent
/// policy-root tag.  This vector is independently written so a symmetric
/// encoder/decoder defect cannot turn a missing policy pointer into success.
const INCARNATION_CONFIGURATION_V2_1_NO_POLICY_GOLDEN: &[u8] = b"FGC1\
    \x00\x01\x00\x00\
    \x00\x00\x00\x26frankengit/repository-configuration/v1\
    \x00\x00\x00\x18repository-configuration\
    \x00\x02\x00\x01\
    \x00\x00\x00\x15\x00\x01\x00\x02\
    \xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\
    \x00";

#[test]
fn schema_two_zero_incarnation_configuration_matches_the_independent_golden() {
    let expected = incarnation_configuration();
    let (header, _) = read_frame_header(INCARNATION_CONFIGURATION_GOLDEN, DecodeLimits::DEFAULT)
        .expect("the independently written incarnation frame is structurally valid");
    assert_eq!(
        header.schema,
        RepositoryIncarnationConfigurationBody::schema_id()
    );
    assert_eq!(header.schema.major(), 2);
    assert_eq!(header.schema.minor(), 0);
    assert_eq!(
        canonical_body_bytes(&expected).expect("the fixed incarnation body encodes"),
        [
            0, 1, 0, 2, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
            0xA5, 0xA5, 0xA5, 0xA5,
        ],
        "the payload is root-layout, object-format, then the raw incarnation bytes"
    );
    assert_eq!(
        decode_body::<RepositoryIncarnationConfigurationBody>(
            INCARNATION_CONFIGURATION_GOLDEN,
            DecodeLimits::DEFAULT
        )
        .expect("the golden must decode"),
        expected
    );
    assert_eq!(
        encode_body(&expected).expect("the fixed incarnation body re-encodes"),
        INCARNATION_CONFIGURATION_GOLDEN,
        "the encoder must reproduce the independently written schema-2.0 frame"
    );
}

#[test]
fn schema_two_one_configuration_has_the_v2_prefix_and_explicit_absent_policy_root() {
    let expected = incarnation_configuration_v2_1(None);
    let (header, _) = read_frame_header(
        INCARNATION_CONFIGURATION_V2_1_NO_POLICY_GOLDEN,
        DecodeLimits::DEFAULT,
    )
    .expect("the independently written v2.1 frame is structurally valid");
    assert_eq!(
        header.schema,
        RepositoryIncarnationConfigurationBodyV2_1::schema_id()
    );
    assert_eq!(header.schema.major(), 2);
    assert_eq!(header.schema.minor(), 1);
    assert_eq!(
        canonical_body_bytes(&expected).expect("the v2.1 payload encodes"),
        [
            0, 1, 0, 2, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
            0xA5, 0xA5, 0xA5, 0xA5, 0,
        ],
        "v2.1 appends exactly the explicit absent-policy tag to the v2.0 payload"
    );
    assert_eq!(
        decode_body::<RepositoryIncarnationConfigurationBodyV2_1>(
            INCARNATION_CONFIGURATION_V2_1_NO_POLICY_GOLDEN,
            DecodeLimits::DEFAULT,
        )
        .expect("the v2.1 golden decodes"),
        expected
    );
    assert_eq!(
        encode_body(&expected).expect("the v2.1 body re-encodes"),
        INCARNATION_CONFIGURATION_V2_1_NO_POLICY_GOLDEN,
        "the v2.1 encoder reproduces the independently written frame"
    );
}

#[test]
fn schema_two_one_configuration_commits_to_a_present_policy_root() {
    let policy_root = Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&[0xC1; 32]).expect("the fixed SHA-256 digest has its width"),
    );
    let expected = incarnation_configuration_v2_1(Some(policy_root));
    let encoded = encode_body(&expected).expect("the v2.1 policy-bearing body encodes");

    assert_eq!(
        decode_body::<RepositoryIncarnationConfigurationBodyV2_1>(&encoded, DecodeLimits::DEFAULT)
            .expect("the exact v2.1 body decodes"),
        expected,
        "the policy root is part of the authenticated configuration identity"
    );
    assert_ne!(
        encoded,
        encode_body(&incarnation_configuration_v2_1(None))
            .expect("the policy-absent v2.1 body encodes"),
        "a policy-bearing configuration cannot alias the no-policy configuration"
    );
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
fn unknown_v2_object_format_is_refused_while_the_known_twin_decodes() {
    assert_eq!(
        decode_body::<RepositoryIncarnationConfigurationBody>(
            INCARNATION_CONFIGURATION_GOLDEN,
            DecodeLimits::DEFAULT
        )
        .expect("the known SHA-256 v2 code point decodes"),
        incarnation_configuration(),
        "the permitted v2 twin proves this test is about the object-format code point"
    );

    let mut unknown = INCARNATION_CONFIGURATION_GOLDEN.to_vec();
    let length = unknown.len();
    // The v2 payload is the final twenty bytes: root-layout, object-format,
    // then the fixed-width incarnation. Mutating the second scalar reaches the
    // exact current object-format field rather than either frame metadata or
    // the incarnation binding.
    unknown[length - 18..length - 16].copy_from_slice(&u16::MAX.to_be_bytes());
    let refusal =
        decode_body::<RepositoryIncarnationConfigurationBody>(&unknown, DecodeLimits::DEFAULT)
            .expect_err("an unknown v2 object-format code point must not become SHA-1");
    assert!(matches!(
        refusal,
        CodecRefusal::Type(TypeRefusal::CodePointUnknown {
            field: "GitHashAlgorithm",
            observed: 65_535,
        })
    ));
}

#[test]
fn v1_configuration_cannot_be_decoded_as_an_incarnation_configuration() {
    let legacy = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        hidden_ref_rules: Vec::new(),
    };
    let encoded = encode_body(&legacy).expect("the predecessor body encodes");

    // is_err() alone would pass for the wrong reason: a v1 body now differs from
    // a v2 body in payload shape AND schema minor as well as major, so several
    // guards could fire. The property under test is specifically that the MAJOR
    // boundary refuses, so the refusal is named.
    let refusal =
        decode_body::<RepositoryIncarnationConfigurationBody>(&encoded, DecodeLimits::DEFAULT)
            .expect_err("a configuration without an incarnation binding must not impersonate v2");
    assert!(
        matches!(
            refusal,
            CodecRefusal::SchemaMajorUnsupported {
                observed: 1,
                supported: 2,
                ..
            }
        ),
        "the major boundary must be what refuses, got {refusal:?}"
    );
}
