#![forbid(unsafe_code)]
//! The production incarnation-configuration reader refuses unknown formats.
//!
//! The reader is the surface a repository opener uses after authenticating the
//! head. These tests store deliberately malformed or future bodies at exact
//! selected roots rather than relying on a legacy-v1 mismatch.

use fgit_authority::{
    AuthorityStore, MemoryAuthorityStore, OutcomeFailure, RepositoryIncarnationConfiguration,
    RepositoryIncarnationConfigurationEvidence, StoreInstanceId, body_key, canonical_body_id,
    read_repository_incarnation_configuration, read_repository_incarnation_configuration_evidence,
    stage_latest_repository_incarnation_configuration, stage_repository_incarnation_configuration,
    stage_revocation_aware_repository_incarnation_configuration,
};
use fgit_codec::{
    CanonicalBody, CodecRefusal, Decoder, Encoder, RepositoryIncarnationConfigurationBody,
    RepositoryIncarnationConfigurationBodyV2_1, RepositoryIncarnationConfigurationBodyV2_2,
    encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::error::TypeRefusal;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::RepositoryIncarnationId;
use fgit_types::label::{DomainTag, SchemaFamily};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitHashAlgorithm;

fn store() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(60))
}

const fn known_configuration() -> RepositoryIncarnationConfigurationBody {
    RepositoryIncarnationConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x60; 16]),
    }
}

const fn v2_one_configuration() -> RepositoryIncarnationConfigurationBodyV2_1 {
    RepositoryIncarnationConfigurationBodyV2_1 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x61; 16]),
        policy_root: None,
    }
}

fn digest(byte: u8) -> Digest {
    Digest::new(
        IdentityDomain::Generation.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).expect("fixed digest"),
    )
}

fn v2_two_configuration() -> RepositoryIncarnationConfigurationBodyV2_2 {
    RepositoryIncarnationConfigurationBodyV2_2 {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x62; 16]),
        policy_root: Some(digest(0x71)),
        capability_revocation_root: Some(digest(0x72)),
    }
}

/// Encoder-only adversarial body with the exact domain and major the production
/// reader selects, but an unallocated object-format code point.
struct UnknownV2ObjectFormatConfiguration;

impl CanonicalBody for UnknownV2ObjectFormatConfiguration {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/repository-configuration/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("repository-configuration");
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(RootLayoutVersion::RefStateMerkleV1.code_point());
        out.write_scalar(u16::MAX);
        out.write_opaque_id(&[0xD4; 16]);
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let _ = input.read_scalar::<u16>("root_layout")?;
        let _ = input.read_scalar::<u16>("object_format")?;
        let _ = input.read_opaque_id("repository_incarnation_id")?;
        Ok(Self)
    }
}

/// A framed schema-2.3 body is deliberately not a compatibility fallback. The
/// production union implements exactly 2.0, 2.1, and 2.2.
struct FutureV2Configuration;

impl CanonicalBody for FutureV2Configuration {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/repository-configuration/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("repository-configuration");
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 3;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(RootLayoutVersion::RefStateMerkleV1.code_point());
        out.write_scalar(GitHashAlgorithm::Sha256.code_point());
        out.write_opaque_id(&[0xE3; 16]);
        out.write_option(None::<&Digest>, Encoder::write_digest)?;
        out.write_option(None::<&Digest>, Encoder::write_digest)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let _ = input.read_scalar::<u16>("root_layout")?;
        let _ = input.read_scalar::<u16>("object_format")?;
        let _ = input.read_opaque_id("repository_incarnation_id")?;
        let _ = input.read_option("policy_root", Decoder::read_digest)?;
        let _ = input.read_option("capability_revocation_root", Decoder::read_digest)?;
        Ok(Self)
    }
}

#[test]
fn production_reader_refuses_unknown_v2_object_format_with_a_known_twin() {
    let backing = store();
    let known = known_configuration();
    let known_root = stage_repository_incarnation_configuration(&backing, &known)
        .expect("the known v2 configuration stages at its selected root");
    assert_eq!(
        read_repository_incarnation_configuration(&backing, &known_root)
            .expect("the known v2 configuration resolves through the production reader"),
        RepositoryIncarnationConfiguration {
            root_layout: known.root_layout,
            object_format: known.object_format,
            repository_incarnation_id: known.repository_incarnation_id,
            policy_root: None,
            capability_revocation_root: None,
        },
        "the permitted twin proves the selected-slot reader works for v2 bodies"
    );

    let malformed = UnknownV2ObjectFormatConfiguration;
    let key = body_key(IdentityDomain::RepositoryConfiguration, &malformed)
        .expect("the malformed current-v2 bytes still occupy a canonical configuration slot");
    backing
        .put_if_absent(
            &key,
            &encode_body(&malformed).expect("the adversarial current-v2 frame encodes"),
        )
        .expect("the immutable malformed fixture stages");
    let identity = canonical_body_id(
        IdentityDomain::RepositoryConfiguration,
        CANONICAL_CODEC_VERSION,
        &malformed,
    )
    .expect("the selected root derives from the exact malformed body bytes");
    let malformed_root = Digest::new(identity.algorithm(), *identity.digest());

    assert!(matches!(
        read_repository_incarnation_configuration(&backing, &malformed_root),
        Err(OutcomeFailure::Codec(CodecRefusal::Type(
            TypeRefusal::CodePointUnknown {
                field: "GitHashAlgorithm",
                observed: 65_535,
            }
        )))
    ));
}

#[test]
fn production_reader_refuses_an_unknown_v2_minor_without_fallback() {
    let backing = store();
    let future = FutureV2Configuration;
    let key = body_key(IdentityDomain::RepositoryConfiguration, &future)
        .expect("the future frame still occupies the configuration identity domain");
    backing
        .put_if_absent(
            &key,
            &encode_body(&future).expect("the encoder-only future frame encodes"),
        )
        .expect("the immutable future fixture stages");
    let identity = canonical_body_id(
        IdentityDomain::RepositoryConfiguration,
        CANONICAL_CODEC_VERSION,
        &future,
    )
    .expect("the selected root derives from the exact future body bytes");
    let future_root = Digest::new(identity.algorithm(), *identity.digest());

    assert!(matches!(
        read_repository_incarnation_configuration(&backing, &future_root),
        Err(OutcomeFailure::Codec(
            CodecRefusal::SchemaMinorUnsupported {
                observed: 3,
                supported: 2,
                ..
            }
        ))
    ));
}

#[test]
fn exact_evidence_reader_preserves_every_supported_v2_minor() {
    let backing = store();
    let historical = known_configuration();
    let historical_root = stage_repository_incarnation_configuration(&backing, &historical)
        .expect("the byte-stable v2.0 configuration stages");
    assert_eq!(
        read_repository_incarnation_configuration_evidence(&backing, &historical_root)
            .expect("the exact evidence reader retains v2.0"),
        RepositoryIncarnationConfigurationEvidence::V2_0(historical),
    );

    let v2_one = v2_one_configuration();
    let v2_one_root = stage_latest_repository_incarnation_configuration(&backing, &v2_one)
        .expect("the v2.1 configuration stages");
    let v2_one_evidence =
        read_repository_incarnation_configuration_evidence(&backing, &v2_one_root)
            .expect("the exact evidence reader retains v2.1");
    assert_eq!(
        v2_one_evidence,
        RepositoryIncarnationConfigurationEvidence::V2_1(v2_one),
    );
    assert_eq!(
        v2_one_evidence.normalized(),
        read_repository_incarnation_configuration(&backing, &v2_one_root)
            .expect("the normalized reader agrees"),
    );

    let v2_two = v2_two_configuration();
    let v2_two_root =
        stage_revocation_aware_repository_incarnation_configuration(&backing, &v2_two)
            .expect("the v2.2 configuration stages");
    let v2_two_evidence =
        read_repository_incarnation_configuration_evidence(&backing, &v2_two_root)
            .expect("the exact evidence reader retains v2.2");
    assert_eq!(
        v2_two_evidence,
        RepositoryIncarnationConfigurationEvidence::V2_2(v2_two),
    );
    assert_eq!(
        v2_two_evidence.normalized(),
        read_repository_incarnation_configuration(&backing, &v2_two_root)
            .expect("the normalized reader agrees"),
    );
}
