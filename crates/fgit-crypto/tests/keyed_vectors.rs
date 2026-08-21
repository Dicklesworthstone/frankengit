//! RFC 4231 (HMAC-SHA-256) and RFC 5869 (HKDF-SHA-256) known-answer vectors.
//!
//! Every expected value in `goldens/mac_vectors.tsv` and
//! `goldens/derive_vectors.tsv` was derived with Python's `hmac`/`hashlib`, an
//! implementation unrelated to the Rust under test, and the published RFC
//! cases are included so the oracle itself is checked against the standard.
//! Nothing here is regenerated from this crate's output.

use fgit_crypto::{
    HmacSha256, MAX_OUTPUT_BYTES, TAG_BYTES, derive, derive_key, expand, extract, hmac_sha256,
    lowercase_hex, verify_mac,
};

const MAC_VECTORS: &str = include_str!("../goldens/mac_vectors.tsv");
const DERIVE_VECTORS: &str = include_str!("../goldens/derive_vectors.tsv");

fn data_rows(text: &str) -> Vec<Vec<&str>> {
    text.lines()
        .skip(2)
        .filter(|line| !line.is_empty())
        .map(|line| line.split('\t').collect())
        .collect()
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex input has an even length");
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        other => panic!("`{}` is not a lowercase hex digit", char::from(other)),
    }
}

#[test]
fn rfc_4231_hmac_sha256_known_answer_vectors() {
    let rows = data_rows(MAC_VECTORS);
    assert!(rows.len() >= 10, "the MAC corpus must not shrink silently");
    for row in rows {
        assert_eq!(row.len(), 5, "a MAC vector row has five columns");
        let (identifier, key, message, expected) =
            (row[0], decode_hex(row[1]), decode_hex(row[2]), row[3]);
        assert_eq!(
            lowercase_hex(&hmac_sha256(&key, &message)),
            expected,
            "{identifier}: one-shot tag"
        );
    }
}

#[test]
fn streaming_hmac_matches_one_shot_for_every_chunk_width() {
    for row in data_rows(MAC_VECTORS) {
        let (key, message, expected) = (decode_hex(row[1]), decode_hex(row[2]), row[3]);
        for width in [1_usize, 7, 31, 64, 65, 200] {
            let mut mac = HmacSha256::new(&key);
            for chunk in message.chunks(width) {
                mac.update(chunk);
            }
            assert_eq!(
                lowercase_hex(&mac.finish()),
                expected,
                "{}: streamed in {width}-byte chunks",
                row[0]
            );
        }
    }
}

#[test]
fn rfc_5869_hkdf_sha256_known_answer_vectors() {
    let rows = data_rows(DERIVE_VECTORS);
    assert!(
        rows.len() >= 6,
        "the derivation corpus must not shrink silently"
    );
    for row in rows {
        assert_eq!(row.len(), 8, "a derivation vector row has eight columns");
        let (identifier, ikm, salt, info) = (
            row[0],
            decode_hex(row[1]),
            decode_hex(row[2]),
            decode_hex(row[3]),
        );
        let length: usize = row[4].parse().expect("a corpus length is a number");
        let (expected_prk, expected_okm) = (row[5], row[6]);

        let pseudorandom_key = extract(&salt, &ikm);
        assert_eq!(
            lowercase_hex(&pseudorandom_key),
            expected_prk,
            "{identifier}: extract"
        );

        let mut output = vec![0_u8; length];
        expand(&pseudorandom_key, &info, &mut output).expect("a corpus length is in range");
        assert_eq!(lowercase_hex(&output), expected_okm, "{identifier}: expand");

        let mut combined = vec![0_u8; length];
        derive(&salt, &ikm, &info, &mut combined).expect("a corpus length is in range");
        assert_eq!(combined, output, "{identifier}: extract-then-expand");
    }
}

#[test]
fn one_root_secret_derives_unrelated_keys_per_domain() {
    // The property the encryption domains depend on: same secret, different
    // domain string, keys that share nothing.
    let root = b"root secret";
    let tenant = derive_key(b"", root, b"frankengit/tenant-encryption/v1");
    let capsule = derive_key(b"", root, b"frankengit/capsule-signature/v1");
    assert_ne!(tenant, capsule);
    // And a one-bit change in the domain string changes the key.
    let nudged = derive_key(b"", root, b"frankengit/tenant-encryption/v2");
    assert_ne!(tenant, nudged);
}

#[test]
fn an_output_longer_than_the_construction_allows_is_refused() {
    let mut too_long = vec![0_u8; MAX_OUTPUT_BYTES + 1];
    let refusal = expand(&[0_u8; TAG_BYTES], b"", &mut too_long)
        .expect_err("255 blocks is the documented ceiling");
    assert_eq!(refusal.requested, MAX_OUTPUT_BYTES + 1);
    assert_eq!(refusal.maximum, MAX_OUTPUT_BYTES);

    // The permitted counterpart: exactly the ceiling proceeds.
    let mut at_ceiling = vec![0_u8; MAX_OUTPUT_BYTES];
    assert_eq!(expand(&[0_u8; TAG_BYTES], b"", &mut at_ceiling), Ok(()));
}

#[test]
fn tag_verification_accepts_the_true_tag_and_rejects_every_single_bit_forgery() {
    let tag = hmac_sha256(b"key", b"message");
    assert!(verify_mac(&tag, &tag));
    for bit in 0..TAG_BYTES * 8 {
        let mut forged = tag;
        forged[bit / 8] ^= 1 << (bit % 8);
        assert!(!verify_mac(&tag, &forged), "bit {bit} must not verify");
    }
}

#[test]
fn a_wrong_key_produces_a_different_tag() {
    assert_ne!(
        hmac_sha256(b"key-a", b"message"),
        hmac_sha256(b"key-b", b"message")
    );
    assert_ne!(
        hmac_sha256(b"key", b"message-a"),
        hmac_sha256(b"key", b"message-b")
    );
}
