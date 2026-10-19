#![forbid(unsafe_code)]
//! Explicit byte cursor mode preserves legacy UTF-8 response semantics.
use super::super::super::issues::ApiError;
use fgit_types::RefName;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CursorEncoding {
    Utf8,
    Hex,
}
impl CursorEncoding {
    pub(super) fn parse(value: Option<&str>) -> Result<Self, ApiError> {
        match value {
            None | Some("utf8") => Ok(Self::Utf8),
            Some("hex") => Ok(Self::Hex),
            _ => Err(ApiError::bad("invalid_cursor_encoding")),
        }
    }
    pub(super) fn reference(self, value: &str, prefix: &[u8]) -> Result<RefName, ApiError> {
        let bytes = match self {
            Self::Utf8 => {
                if value.len() > 4096 {
                    return Err(ApiError::bad("invalid_reference"));
                }
                value.as_bytes().to_vec()
            }
            Self::Hex => {
                if value.is_empty()
                    || value.len() > 8192
                    || !value.len().is_multiple_of(2)
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(ApiError::bad("invalid_cursor_hex"));
                }
                let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(value.len() / 2)
                    .map_err(|_| ApiError::unavailable())?;
                for pair in value.as_bytes().chunks_exact(2) {
                    bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
                }
                bytes
            }
        };
        if !bytes.starts_with(prefix) {
            return Err(ApiError::bad("invalid_reference_namespace"));
        }
        RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_reference"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    #[test]
    fn byte_names_round_trip_without_loss_and_respect_selected_namespace() {
        let raw = b"refs/heads/a\xff";
        let bytes = hex(raw);
        assert_eq!(
            CursorEncoding::Hex
                .reference(&bytes, b"refs/heads/")
                .unwrap()
                .as_bytes(),
            raw
        );
        assert!(
            CursorEncoding::Hex
                .reference(&bytes, b"refs/tags/")
                .is_err()
        );
        assert!(
            CursorEncoding::Hex
                .reference(&hex(b"refs/tags/v1"), b"refs/tags/")
                .is_ok()
        );
        let normal = "refs/heads/main";
        assert_eq!(
            CursorEncoding::Utf8.reference(normal, b"refs/").unwrap(),
            CursorEncoding::Hex
                .reference(&hex(normal.as_bytes()), b"refs/")
                .unwrap()
        );
    }
    #[test]
    fn encodings_and_hex_bytes_have_closed_bounded_grammar() {
        assert_eq!(CursorEncoding::parse(None).unwrap(), CursorEncoding::Utf8);
        assert_eq!(
            CursorEncoding::parse(Some("utf8")).unwrap(),
            CursorEncoding::Utf8
        );
        assert_eq!(
            CursorEncoding::parse(Some("hex")).unwrap(),
            CursorEncoding::Hex
        );
        for bad in ["", "HEX", "bytes", "base64"] {
            assert!(CursorEncoding::parse(Some(bad)).is_err());
        }
        for bad in [
            "".to_owned(),
            "abc".into(),
            "GG".into(),
            "aa".repeat(4097),
            hex(b"refs/heads/.."),
            hex(b"refs/heads/a\0"),
        ] {
            assert!(CursorEncoding::Hex.reference(&bad, b"refs/heads/").is_err());
        }
    }
}
