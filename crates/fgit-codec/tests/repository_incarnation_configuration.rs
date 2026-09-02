#![forbid(unsafe_code)]
//! Canonical vectors for incarnation-aware repository configuration.
//!
//! Schema major 2 is separate from the older configuration. Minor 1 appends
//! the hidden-ref policy root; minor 2 appends the capability-revocation root.
//! Published 2.0 and 2.1 bytes remain unchanged.
//!
//! The vectors below are written directly from the frame and payload
//! specification rather than produced by the encoder under test. A round-trip
//! alone cannot detect a symmetric encoder/decoder defect.

use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, RepositoryConfigurationBody,
    RepositoryIncarnationConfigurationBody, RepositoryIncarnationConfigurationBodyV2_1,
    RepositoryIncarnationConfigurationBodyV2_2, canonical_body_bytes, decode_body, encode_body,
    read_frame_header,
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

const fn incarnation_configuration_v2_1(
    policy_root: Option<Digest>,
) -> RepositoryIncarnationConfigurationBodyV2_1 {
    RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0xA5; 16]),
        policy_root,
    }
}

const fn incarnation_configuration_v2_2(
    policy_root: Option<Digest>,
    capability_revocation_root: Option<Digest>,
) -> RepositoryIncarnationConfigurationBodyV2_2 {
    RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0xA5; 16]),
        policy_root,
        capability_revocation_root,
    }
}

const INCARNATION_CONFIGURATION_GOLDEN: &[u8] = b"FGC1\
    \x00\x01\x00\x00\
    \x00\x00\x00\x26frankengit/repository-configuration/v1\
    \x00\x00\x00\x18repository-configuration\
    \x00\x02\x00\x00\
    \x00\x00\x00\x14\x00\x01\x00\x02\
    \xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5";

const INCARNATION_CONFIGURATION_V2_1_NO_POLICY_GOLDEN: &[u8] = b"FGC1\
    \x00\x01\x00\x00\
    \x00\x00\x00\x26frankengit/repository-configuration/v1\
    \x00\x00\x00\x18repository-configuration\
    \x00\x02\x00\x01\
    \x00\x00\x00\x15\x00\x01\x00\x02\
    \xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\
    \x00";

/// Schema 2.2 preserves the complete 2.1 payload and appends one explicit
/// absent capability-revocation-root tag.
const INCARNATION_CONFIGURATION_V2_2_NO_ROOTS_GOLDEN: &[u8] = b"FGC1\
    \x00\x01\x00\x00\
    \x00\x00\x00\x26frankengit/repository-configuration/v1\
    \x00\x00\x00\x18repository-configuration\
    \x00\x02\x00\x02\
    \x00\x00\x00\x16\x00\x01\x00\x02\
    \xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5\
    \x00\x00";

fn sha256_digest(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed SHA-256 digest"),
    )
}

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
    );
}

#[test]
fn schema_two_one_has_v2_prefix_and_explicit_absent_policy_root() {
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
    );
}

#[test]
fn schema_two_two_matches_the_independent_absent_roots_golden() {
    let expected = incarnation_configuration_v2_2(None, None);
    let (header, _) = read_frame_header(
        INCARNATION_CONFIGURATION_V2_2_NO_ROOTS_GOLDEN,
        DecodeLimits::DEFAULT,
    )
    .expect("the independently written v2.2 frame is structurally valid");
    assert_eq!(
        header.schema,
        RepositoryIncarnationConfigurationBodyV2_2::schema_id()
    );
    assert_eq!(header.schema.major(), 2);
    assert_eq!(header.schema.minor(), 2);
    assert_eq!(
        canonical_body_bytes(&expected).expect("the v2.2 payload encodes"),
        [
            0, 1, 0, 2, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
            0xA5, 0xA5, 0xA5, 0xA5, 0, 0,
        ],
    );
    assert_eq!(
        decode_body::<RepositoryIncarnationConfigurationBodyV2_2>(
            INCARNATION_CONFIGURATION_V2_2_NO_ROOTS_GOLDEN,
            DecodeLimits::DEFAULT,
        )
        .expect("the v2.2 golden decodes"),
        expected
    );
    assert_eq!(
        encode_body(&expected).expect("the v2.2 body re-encodes"),
        INCARNATION_CONFIGURATION_V2_2_NO_ROOTS_GOLDEN,
    );
}

#[test]
fn schema_two_one_policy_root_is_identity_bearing() {
    let policy_root = sha256_digest(0xC1);
    let expected = incarnation_configuration_v2_1(Some(policy_root));
    let encoded = encode_body(&expected).expect("the v2.1 policy-bearing body encodes");

    assert_eq!(
        decode_body::<RepositoryIncarnationConfigurationBodyV2_1>(&encoded, DecodeLimits::DEFAULT)
            .expect("the exact v2.1 body decodes"),
        expected,
    );
    assert_ne!(
        encoded,
        encode_body(&incarnation_configuration_v2_1(None))
            .expect("the policy-absent v2.1 body encodes"),
    );
}

#[test]
fn schema_two_two_roots_are_independent_identity_fields() {
    let policy_root = sha256_digest(0xC1);
    let revocation_root = sha256_digest(0xC2);
    let both = incarnation_configuration_v2_2(Some(policy_root), Some(revocation_root));
    let policy_only = incarnation_configuration_v2_2(Some(policy_root), None);
    let revocation_only = incarnation_configuration_v2_2(None, Some(revocation_root));

    let encoded = encode_body(&both).expect("the v2.2 body encodes");
    assert_eq!(
        decode_body::<RepositoryIncarnationConfigurationBodyV2_2>(&encoded, DecodeLimits::DEFAULT,)
            .expect("the v2.2 body decodes"),
        both,
    );
    assert_ne!(
        encoded,
        encode_body(&policy_only).expect("policy-only body")
    );
    assert_ne!(
        encoded,
        encode_body(&revocation_only).expect("revocation-only body")
    );
    assert_ne!(
        encode_body(&policy_only).expect("policy-only body"),
        encode_body(&revocation_only).expect("revocation-only body")
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
    );

    let mut unknown = INCARNATION_CONFIGURATION_GOLDEN.to_vec();
    let length = unknown.len();
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
