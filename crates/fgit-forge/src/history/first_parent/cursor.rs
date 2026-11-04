//! One canonical continuation spelling shared by CLI, HTTP and MCP. Tokens
//! carry selection preconditions only; consumers still authorize the current
//! reference and re-walk its first-parent prefix through the native reader.

use super::{FirstParentCursor, HistoryError, HistoryLimits};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid, RefName,
    RepositoryAuthorityHeadId,
};

const MAX_TOKEN_BYTES: usize = 4096;

impl FirstParentCursor {
    /// Encode the existing `fgfp1` continuation profile, preserving raw ref
    /// bytes and the native hash domain. This token grants no read authority.
    #[must_use]
    pub fn encode(&self) -> String {
        let head = self.source_head.as_internal_object_id();
        format!(
            "fgfp1/alg:{}:{}/{}/{}/{}/{}",
            head.algorithm().code_point(),
            hex(head.digest().as_bytes()),
            hex(self.reference.as_bytes()),
            self.tip.algorithm().as_str(),
            self.tip,
            self.after,
        )
    }

    /// Decode a bounded, canonical `fgfp1` selection. The receiving node must
    /// additionally check the exact head, reference and tip against its own
    /// authenticated current selection; decoding does not prove ancestry.
    pub fn decode(value: &str) -> Result<Self, HistoryError> {
        if value.len() > MAX_TOKEN_BYTES {
            return Err(HistoryError::InvalidOptions);
        }
        let mut fields = value.split('/');
        if fields.next() != Some("fgfp1") {
            return Err(HistoryError::InvalidOptions);
        }
        let head = fields.next().ok_or(HistoryError::InvalidOptions)?;
        let reference = fields.next().ok_or(HistoryError::InvalidOptions)?;
        let format = match fields.next() {
            Some("sha1") => GitHashAlgorithm::Sha1,
            Some("sha256") => GitHashAlgorithm::Sha256,
            _ => return Err(HistoryError::InvalidOptions),
        };
        let tip = fields.next().ok_or(HistoryError::InvalidOptions)?;
        let after = fields
            .next()
            .ok_or(HistoryError::InvalidOptions)?
            .parse::<usize>()
            .map_err(|_| HistoryError::InvalidOptions)?;
        if fields.next().is_some() || after == 0 || after > HistoryLimits::default().max_commits {
            return Err(HistoryError::InvalidOptions);
        }
        let (algorithm, digest) = head
            .strip_prefix("alg:")
            .and_then(|head| head.split_once(':'))
            .ok_or(HistoryError::InvalidOptions)?;
        let algorithm = algorithm
            .parse::<u16>()
            .ok()
            .and_then(|id| DigestAlgorithmId::try_new(id).ok())
            .ok_or(HistoryError::InvalidOptions)?;
        let digest =
            DigestBytes::try_new(&unhex(digest, 64)?).map_err(|_| HistoryError::InvalidOptions)?;
        let cursor = Self {
            source_head: RepositoryAuthorityHeadId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                digest,
            ),
            reference: RefName::try_new(&unhex(reference, fgit_types::MAX_REF_NAME_LEN)?)
                .map_err(|_| HistoryError::InvalidOptions)?,
            tip: GitOid::from_hex(format, tip).map_err(|_| HistoryError::InvalidOptions)?,
            after,
        };
        if cursor.tip.is_zero() || cursor.encode() != value {
            return Err(HistoryError::InvalidOptions);
        }
        Ok(cursor)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>, HistoryError> {
    if value.is_empty()
        || value.len() > maximum.saturating_mul(2)
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HistoryError::InvalidOptions);
    }
    let digit = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    Ok(value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(format: GitHashAlgorithm) -> FirstParentCursor {
        FirstParentCursor {
            source_head: RepositoryAuthorityHeadId::from_digest(
                DigestAlgorithmId::try_new(1).unwrap(),
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[0xab; 32]).unwrap(),
            ),
            reference: RefName::try_new(b"refs/heads/\xff").unwrap(),
            tip: GitOid::from_hex(format, &"12".repeat(format.digest_len())).unwrap(),
            after: 20,
        }
    }

    #[test]
    fn existing_cli_tokens_round_trip_without_reinterpreting_ref_bytes() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let cursor = sample(format);
            let token = format!(
                "fgfp1/alg:1:{}/726566732f68656164732fff/{}/{}/20",
                "ab".repeat(32),
                format.as_str(),
                "12".repeat(format.digest_len()),
            );
            assert_eq!(cursor.encode(), token);
            assert_eq!(FirstParentCursor::decode(&token).unwrap(), cursor);
            let edge = FirstParentCursor {
                after: 4096,
                ..cursor
            };
            assert_eq!(FirstParentCursor::decode(&edge.encode()).unwrap(), edge);
        }
    }

    #[test]
    fn malformed_aliases_and_out_of_budget_offsets_are_not_cursors() {
        let cursor = sample(GitHashAlgorithm::Sha1);
        let token = cursor.encode();
        for invalid in [
            token.replacen("fgfp1/", "fgfp2/", 1),
            token.replacen("alg:1:", "alg:01:", 1),
            token.replacen("alg:1:", "head:alg:1:", 1),
            token.replacen("alg:1:", "alg:65536:", 1),
            token.replacen("ab", "AB", 1),
            token.replacen("/sha1/", "/sha256/", 1),
            token.replace("/20", "/020"),
            token.replace("/20", "/+20"),
            token.replace("/20", "/0"),
            token.replace("/20", "/4097"),
            token.replace("/20", "/18446744073709551616"),
            format!("{token}/extra"),
            token.replace("726566732f68656164732fff", "726566732f2e2e2f6865616473"),
            token.replace(&"12".repeat(20), &"00".repeat(20)),
            "x".repeat(MAX_TOKEN_BYTES + 1),
        ] {
            assert_eq!(
                FirstParentCursor::decode(&invalid),
                Err(HistoryError::InvalidOptions)
            );
        }
    }
}
