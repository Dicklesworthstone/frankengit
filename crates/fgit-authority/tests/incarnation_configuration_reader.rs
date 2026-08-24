#![forbid(unsafe_code)]
//! The production incarnation-configuration reader refuses an unknown format.
//!
//! The reader is the surface `OneNode::open_existing` uses after authenticating
//! the head. This test stores a deliberately malformed *current-v2* body at
//! its canonical selected root, rather than relying on a legacy-v1 mismatch.

use fgit_authority::{
    AuthorityStore, MemoryAuthorityStore, OutcomeFailure, RepositoryIncarnationConfiguration,
    StoreInstanceId, body_key, canonical_body_id, read_repository_incarnation_configuration,
    stage_repository_incarnation_configuration,
};
use fgit_codec::{
    CanonicalBody, CodecRefusal, Decoder, Encoder, RepositoryIncarnationConfigurationBody,
    encode_body,
};
use fgit_crypto::IdentityDomain;
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::error::TypeRefusal;
use fgit_types::hash::Digest;
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

/// An encoder-only adversarial body with the precise domain and schema the
/// production reader selects, but an unallocated object-format code point.
/// It permits testing the real immutable-slot lookup without accepting the
/// malformed value into the typed configuration vocabulary.
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

/// A framed schema-2.2 body is deliberately not a compatibility fallback. The
/// production union implements exactly 2.0 and 2.1, so this encoder-only
/// future minor must be refused before its payload can acquire a local meaning.
struct FutureV2Configuration;

impl CanonicalBody for FutureV2Configuration {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/repository-configuration/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("repository-configuration");
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 2;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(RootLayoutVersion::RefStateMerkleV1.code_point());
        out.write_scalar(GitHashAlgorithm::Sha256.code_point());
        out.write_opaque_id(&[0xE2; 16]);
        out.write_option(None::<&fgit_types::hash::Digest>, Encoder::write_digest)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let _ = input.read_scalar::<u16>("root_layout")?;
        let _ = input.read_scalar::<u16>("object_format")?;
        let _ = input.read_opaque_id("repository_incarnation_id")?;
        let _ = input.read_option("policy_root", Decoder::read_digest)?;
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
        },
        "the permitted twin proves the selected-slot reader works for current v2 bodies"
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
fn production_reader_refuses_an_unknown_v2_minor_without_a_legacy_fallback() {
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
                observed: 2,
                supported: 1,
                ..
            }
        ))
    ));
}
