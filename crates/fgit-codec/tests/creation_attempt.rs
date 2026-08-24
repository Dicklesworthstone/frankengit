#![forbid(unsafe_code)]
//! Independent canonical vectors for repository-creation idempotency bodies.
//!
//! The vector is written directly from the frame and payload layout. It does
//! not use the encoder under test, so a symmetric encode/decode mistake cannot
//! turn an altered creation request into an accepted retry.

use fgit_codec::{
    CanonicalBody, CreationAttemptBody, CryptoBodyIdentity, DecodeLimits, body_id,
    canonical_body_bytes, decode_body, encode_body, read_frame_header,
};
use fgit_crypto::{DigestAlgorithm, IdentityDomain};
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{RepositoryId, RepositoryIncarnationId, TenantId};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::GitHashAlgorithm;

fn creation_attempt() -> CreationAttemptBody {
    CreationAttemptBody {
        tenant_id: TenantId::from_bytes([0x11; 16]),
        repository_id: RepositoryId::from_bytes([0x22; 16]),
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha256,
        idempotency_key_digest: Digest::new(
            DigestAlgorithm::Sha256.id(),
            DigestBytes::try_new(&[0x33; 32]).expect("the fixed SHA-256 digest has its width"),
        ),
        repository_incarnation_id: RepositoryIncarnationId::from_bytes([0x44; 16]),
    }
}

/// Schema 1.0 payload: tenant, repository, root layout, object format,
/// idempotency-key digest, then the first-writer incarnation.
const CREATION_ATTEMPT_GOLDEN: &[u8] = b"FGC1\
    \x00\x01\x00\x00\
    \x00\x00\x00\x29frankengit/repository-creation-attempt/v1\
    \x00\x00\x00\x1brepository-creation-attempt\
    \x00\x01\x00\x00\
    \x00\x00\x00\x5a\
    \x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\
    \x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22\
    \x00\x01\x00\x02\
    \x00\x02\x00\x00\x00\x20\
    \x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\
    \x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33\
    \x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44\x44";

#[test]
fn creation_attempt_matches_the_independent_schema_one_golden() {
    let expected = creation_attempt();
    let (header, _) = read_frame_header(CREATION_ATTEMPT_GOLDEN, DecodeLimits::DEFAULT)
        .expect("the independently written creation frame is structurally valid");

    assert_eq!(header.schema, CreationAttemptBody::schema_id());
    assert_eq!(header.schema.major(), 1);
    assert_eq!(header.schema.minor(), 0);
    assert_eq!(
        body_id(&CryptoBodyIdentity, &expected)
            .expect("the creation body domain is registered for canonical identity")
            .domain(),
        IdentityDomain::RepositoryCreationAttempt.domain_tag(),
        "the independently pinned body resolves through its dedicated identity-domain row"
    );
    assert_eq!(
        decode_body::<CreationAttemptBody>(CREATION_ATTEMPT_GOLDEN, DecodeLimits::DEFAULT)
            .expect("the independently written golden decodes"),
        expected
    );
    assert_eq!(
        encode_body(&expected).expect("the bounded creation body encodes"),
        CREATION_ATTEMPT_GOLDEN,
        "the encoder must reproduce the independently written creation frame"
    );
}

#[test]
fn fixed_request_projection_excludes_only_the_winning_incarnation() {
    let expected = creation_attempt();
    assert_eq!(
        expected
            .fixed_request_bytes()
            .expect("the fixed request projection encodes"),
        canonical_body_bytes(&expected).expect("the full creation payload encodes")[..74].to_vec(),
        "the retry comparison is byte-for-byte over every request field and excludes only the mint"
    );

    let mut retry = expected;
    retry.repository_incarnation_id = RepositoryIncarnationId::from_bytes([0x55; 16]);
    assert_eq!(
        retry
            .fixed_request_bytes()
            .expect("the retry projection encodes"),
        expected
            .fixed_request_bytes()
            .expect("the original projection encodes"),
        "a retry may present a different local mint; it must recover the stored one"
    );

    retry.object_format = GitHashAlgorithm::Sha1;
    assert_ne!(
        retry
            .fixed_request_bytes()
            .expect("the changed request projection encodes"),
        expected
            .fixed_request_bytes()
            .expect("the original projection encodes"),
        "a fixed creation fact cannot be normalized into the original request"
    );
}
