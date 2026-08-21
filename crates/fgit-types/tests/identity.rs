// Identity behaviour: domain pinning, cross-domain refusal, and the
// assigned-versus-derived split. Every forbidden case below is paired with a
// near-identical permitted case that proceeds.

use std::collections::BTreeSet;

use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{
    AuthorityVersionToken, DERIVED_ID_DOMAINS, InternalObjectId, PrincipalId,
    RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId, RequestId, TenantId,
    TransactionSealId, TxId,
};
use fgit_types::numeric::CodecVersion;
use fgit_types::{CANONICAL_CODEC_VERSION, TypeRefusal};

fn algorithm() -> DigestAlgorithmId {
    DigestAlgorithmId::try_new(1).expect("code point 1 is a valid algorithm slot")
}

fn digest(fill: u8) -> DigestBytes {
    DigestBytes::try_new(&[fill; 32]).expect("32 bytes is inside 16..=64")
}

#[test]
fn derived_id_domains_are_unique() {
    let unique: BTreeSet<&&str> = DERIVED_ID_DOMAINS.iter().collect();
    assert_eq!(
        unique.len(),
        DERIVED_ID_DOMAINS.len(),
        "two schemas share a domain separation tag, which would let one body's digest be read as another's identity: {DERIVED_ID_DOMAINS:?}"
    );
}

#[test]
fn tx_id_pins_the_normative_ref_transaction_domain() {
    assert_eq!(TxId::DOMAIN, "frankengit/ref-txn/v2");
    let id = TxId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(0xaa));
    assert_eq!(id.as_internal_object_id().domain(), TxId::DOMAIN_TAG);
}

#[test]
fn a_derived_id_adopts_an_internal_id_from_its_own_domain() {
    // Permitted case, paired with the refusal below.
    let internal = InternalObjectId::new(
        algorithm(),
        TxId::DOMAIN_TAG,
        CANONICAL_CODEC_VERSION,
        digest(0x11),
    );
    let adopted = TxId::from_internal_object_id(internal).expect("same domain must be adopted");
    assert_eq!(adopted.into_internal_object_id(), internal);
}

#[test]
fn a_derived_id_refuses_an_internal_id_from_another_domain() {
    let batch =
        RepositoryDecisionBatchId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, digest(0x11));
    let refusal = TxId::from_internal_object_id(batch.into_internal_object_id())
        .expect_err("a decision-batch digest must not become a transaction identity");
    assert_eq!(
        refusal,
        TypeRefusal::DomainMismatch {
            field: "TxId",
            expected: "frankengit/ref-txn/v2",
        }
    );
}

#[test]
fn identical_digest_bytes_in_different_domains_are_different_identities() {
    let bytes = digest(0x5c);
    let commit = RepositoryCommitId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, bytes);
    let head = RepositoryAuthorityHeadId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, bytes);
    assert_ne!(
        commit.as_internal_object_id(),
        head.as_internal_object_id(),
        "domain separation must survive identical digest bytes"
    );
}

#[test]
fn codec_version_participates_in_internal_identity() {
    let bytes = digest(0x77);
    let first = TransactionSealId::from_digest(algorithm(), CodecVersion::new(1, 0), bytes);
    let second = TransactionSealId::from_digest(algorithm(), CodecVersion::new(2, 0), bytes);
    assert_ne!(
        first, second,
        "a codec major bump must not silently reuse an identity"
    );
}

#[test]
fn algorithm_participates_in_internal_identity() {
    let bytes = digest(0x77);
    let first = TransactionSealId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid slot"),
        CANONICAL_CODEC_VERSION,
        bytes,
    );
    let second = TransactionSealId::from_digest(
        DigestAlgorithmId::try_new(2).expect("valid slot"),
        CANONICAL_CODEC_VERSION,
        bytes,
    );
    assert_ne!(
        first, second,
        "a digest migration must not silently alias identities"
    );
}

#[test]
fn opaque_identities_round_trip_through_lowercase_hex() {
    let bytes = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let tenant = TenantId::from_bytes(bytes);
    let text = tenant.to_string();
    assert_eq!(text, "00112233445566778899aabbccddeeff");
    assert_eq!(TenantId::from_hex(&text).expect("round trip"), tenant);
}

#[test]
fn opaque_identities_refuse_uppercase_hex_and_wrong_length() {
    let uppercase = PrincipalId::from_hex("00112233445566778899AABBCCDDEEFF")
        .expect_err("uppercase must not be a second canonical form");
    assert!(matches!(
        uppercase,
        TypeRefusal::ByteNotPermitted {
            field: "PrincipalId",
            ..
        }
    ));
    let short =
        RequestId::from_hex("00112233").expect_err("a truncated identity must not be accepted");
    assert!(matches!(
        short,
        TypeRefusal::LengthOutOfRange {
            field: "RequestId",
            observed: 8,
            minimum: 32,
            maximum: 32,
        }
    ));
    // Permitted counterpart to both refusals above.
    assert!(RequestId::from_hex("00112233445566778899aabbccddeeff").is_ok());
}

#[test]
fn authority_version_tokens_are_bounded_and_never_empty() {
    let permitted = AuthorityVersionToken::try_new(b"etag-91af").expect("ordinary token");
    assert_eq!(permitted.as_bytes(), b"etag-91af");
    assert_eq!(permitted.len(), 9);
    assert!(!permitted.is_empty());

    let empty = AuthorityVersionToken::try_new(b"")
        .expect_err("an empty token cannot make a write conditional");
    assert!(matches!(
        empty,
        TypeRefusal::LengthOutOfRange {
            field: "AuthorityVersionToken",
            observed: 0,
            ..
        }
    ));

    let oversized = AuthorityVersionToken::try_new(&[b'x'; 513])
        .expect_err("a token above the bound must be refused before allocation");
    assert!(matches!(
        oversized,
        TypeRefusal::LengthOutOfRange {
            field: "AuthorityVersionToken",
            observed: 513,
            maximum: 512,
            ..
        }
    ));
    // Permitted counterpart: exactly at the bound.
    assert!(AuthorityVersionToken::try_new(&[b'x'; 512]).is_ok());
}

#[test]
fn internal_identity_display_names_all_four_components() {
    let id = InternalObjectId::new(
        algorithm(),
        TxId::DOMAIN_TAG,
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0xab; 16]).expect("16 bytes is the minimum"),
    );
    assert_eq!(
        id.to_string(),
        "frankengit/ref-txn/v2/v1.0/alg:1/abababababababababababababababab"
    );
}
