//! Byte-preserving reference coordinates shared by candidate construction,
//! inspection and review publication. Decoding never supplies authority.

use super::super::issues::ApiError;
use fgit_types::{MAX_REF_NAME_LEN, RefName};
use std::collections::BTreeMap;

/// Exactly one spelling is accepted per reference. Hex is canonical lowercase
/// and bounded before allocation; neither spelling normalizes native bytes.
pub(super) fn reference(
    fields: &mut BTreeMap<String, String>,
    plain: &str,
    encoded: &str,
) -> Result<RefName, ApiError> {
    let bytes = match (fields.remove(plain), fields.remove(encoded)) {
        (Some(value), None) if value.len() <= MAX_REF_NAME_LEN => value.into_bytes(),
        (None, Some(value))
            if !value.is_empty()
                && value.len() <= MAX_REF_NAME_LEN * 2
                && value.len().is_multiple_of(2)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            let digit = |byte: u8| {
                if byte.is_ascii_digit() {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(value.len() / 2)
                .map_err(|_| ApiError::unavailable())?;
            for pair in value.as_bytes().chunks_exact(2) {
                bytes.push((digit(pair[0]) << 4) | digit(pair[1]));
            }
            bytes
        }
        _ => return Err(ApiError::bad("exactly_one_ref_encoding_required")),
    };
    RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_ref"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(text: Option<&str>, hex: Option<&str>) -> Result<RefName, ApiError> {
        let mut fields = BTreeMap::new();
        if let Some(text) = text {
            fields.insert("source_ref".into(), text.into());
        }
        if let Some(hex) = hex {
            fields.insert("source_ref_hex".into(), hex.into());
        }
        reference(&mut fields, "source_ref", "source_ref_hex")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn native_bytes_have_no_unicode_or_hex_normalization() {
        for name in ["refs/heads/topic", "refs/heads/é", "refs/heads/e\u{301}"] {
            assert_eq!(
                decode(Some(name), None).unwrap(),
                decode(None, Some(&hex(name.as_bytes()))).unwrap()
            );
        }
        assert_ne!(
            decode(Some("refs/heads/é"), None).unwrap(),
            decode(Some("refs/heads/e\u{301}"), None).unwrap()
        );
        let bytes = b"refs/heads/raw-\xff";
        assert_eq!(decode(None, Some(&hex(bytes))).unwrap().as_bytes(), bytes);
    }

    #[test]
    fn ambiguous_noncanonical_and_forbidden_references_refuse() {
        let good = hex(b"refs/heads/topic");
        for (text, encoded) in [
            (None, None),
            (Some("refs/heads/topic"), Some(good.as_str())),
            (None, Some("")),
            (None, Some("0")),
            (None, Some("FF")),
            (None, Some("gg")),
            (Some("refs/heads/../topic"), None),
            (Some("refs/heads/topic.lock"), None),
        ] {
            assert!(decode(text, encoded).is_err());
        }
        for bytes in [
            b"refs/heads/a\0b".as_slice(),
            b"refs/heads/a b",
            b"refs/heads/a..b",
            b"refs/heads/a@{b",
            b"refs/heads/a\\b",
        ] {
            assert!(decode(None, Some(&hex(bytes))).is_err());
        }
    }

    #[test]
    fn both_encodings_enforce_the_same_decoded_byte_limit() {
        let mut bytes = b"refs/heads/".to_vec();
        bytes.resize(MAX_REF_NAME_LEN, b'x');
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(decode(Some(text), None).is_ok());
        assert!(decode(None, Some(&hex(&bytes))).is_ok());
        bytes.push(b'x');
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(decode(Some(text), None).is_err());
        assert!(decode(None, Some(&hex(&bytes))).is_err());
    }
}
