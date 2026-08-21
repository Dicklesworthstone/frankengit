// Native Git identity: the two hash domains stay separate, and there is one
// canonical text form.

use fgit_types::TypeRefusal;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256};

const SHA1_HEX: &str = "0123456789abcdef0123456789abcdef01234567";
const SHA256_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn each_domain_round_trips_its_own_hex() {
    let sha1 = GitOidSha1::from_hex(SHA1_HEX).expect("40 lowercase hex digits");
    assert_eq!(sha1.to_string(), SHA1_HEX);
    assert_eq!(sha1.algorithm(), GitHashAlgorithm::Sha1);

    let sha256 = GitOidSha256::from_hex(SHA256_HEX).expect("64 lowercase hex digits");
    assert_eq!(sha256.to_string(), SHA256_HEX);
    assert_eq!(sha256.algorithm(), GitHashAlgorithm::Sha256);
}

#[test]
fn a_domain_refuses_the_other_domain_digest_length() {
    let refusal =
        GitOidSha1::from_hex(SHA256_HEX).expect_err("a 64-digit value is not a SHA-1 identity");
    assert!(matches!(
        refusal,
        TypeRefusal::LengthOutOfRange {
            field: "GitOidSha1",
            observed: 64,
            minimum: 40,
            maximum: 40,
        }
    ));
    // Permitted counterpart: the same 64-digit value in its own domain.
    assert!(GitOidSha256::from_hex(SHA256_HEX).is_ok());
}

#[test]
fn uppercase_hex_is_refused_so_there_is_one_canonical_text_form() {
    let upper = SHA1_HEX.to_ascii_uppercase();
    let refusal = GitOidSha1::from_hex(&upper).expect_err("uppercase must not be a second form");
    assert!(matches!(
        refusal,
        TypeRefusal::ByteNotPermitted {
            field: "GitOidSha1",
            ..
        }
    ));
    // Permitted counterpart: the identical value in lowercase.
    assert!(GitOidSha1::from_hex(SHA1_HEX).is_ok());
}

#[test]
fn overlapping_bytes_in_different_domains_are_not_equal_identities() {
    // The SHA-256 value's first twenty bytes are exactly the SHA-1 value's
    // bytes. The two identities must still not compare equal.
    let sha1 = GitOidSha1::from_hex(SHA1_HEX).expect("valid");
    let mut wide = [0_u8; GitOidSha256::LEN];
    wide[..GitOidSha1::LEN].copy_from_slice(sha1.as_bytes());
    let sha256 = GitOidSha256::from_bytes(wide);

    let left = GitOid::from(sha1);
    let right = GitOid::from(sha256);
    assert_ne!(left, right);
    assert_ne!(left.algorithm(), right.algorithm());
    assert_eq!(&right.as_bytes()[..GitOidSha1::LEN], left.as_bytes());
}

#[test]
fn crossing_a_domain_is_a_typed_refusal_and_staying_in_one_is_not() {
    let sha1 = GitOid::from(GitOidSha1::from_hex(SHA1_HEX).expect("valid"));
    assert!(sha1.require_sha1().is_ok());
    let refusal = sha1
        .require_sha256()
        .expect_err("a SHA-1 identity must not satisfy a SHA-256 requirement");
    assert_eq!(
        refusal,
        TypeRefusal::HashDomainMismatch {
            expected: GitHashAlgorithm::Sha256,
            observed: GitHashAlgorithm::Sha1,
        }
    );

    let sha256 = GitOid::from(GitOidSha256::from_hex(SHA256_HEX).expect("valid"));
    assert!(sha256.require_sha256().is_ok());
    assert!(sha256.require_sha1().is_err());
}

#[test]
fn the_all_zero_identity_is_recognised_in_both_domains() {
    assert!(GitOidSha1::ZERO.is_zero());
    assert!(GitOidSha256::ZERO.is_zero());
    assert!(GitOid::from(GitOidSha1::ZERO).is_zero());
    assert!(!GitOid::from(GitOidSha1::from_hex(SHA1_HEX).expect("valid")).is_zero());
    assert_eq!(GitOidSha1::ZERO.to_string(), "0".repeat(40));
}

#[test]
fn algorithm_code_points_round_trip_and_unknown_ones_are_refused() {
    for algorithm in GitHashAlgorithm::ALL {
        let recovered = GitHashAlgorithm::from_code_point(algorithm.code_point())
            .expect("every member round trips");
        assert_eq!(recovered, *algorithm);
        assert_eq!(recovered.digest_len(), algorithm.digest_len());
    }
    assert_eq!(GitHashAlgorithm::Sha1.digest_len(), GitOidSha1::LEN);
    assert_eq!(GitHashAlgorithm::Sha256.digest_len(), GitOidSha256::LEN);

    let refusal = GitHashAlgorithm::from_code_point(9)
        .expect_err("an unknown algorithm must be refused, not defaulted");
    assert_eq!(
        refusal,
        TypeRefusal::CodePointUnknown {
            field: "GitHashAlgorithm",
            observed: 9,
        }
    );
}

#[test]
fn parsing_by_algorithm_selects_the_matching_domain() {
    let sha1 = GitOid::from_hex(GitHashAlgorithm::Sha1, SHA1_HEX).expect("valid");
    assert!(matches!(sha1, GitOid::Sha1(_)));
    let sha256 = GitOid::from_hex(GitHashAlgorithm::Sha256, SHA256_HEX).expect("valid");
    assert!(matches!(sha256, GitOid::Sha256(_)));
    assert!(GitOid::from_hex(GitHashAlgorithm::Sha256, SHA1_HEX).is_err());
}
