//! Complete, bounded parsing of an operator-maintained deploy-key table.
//!
//! This module performs no I/O and creates no authorization cache. A caller
//! receives bindings only after every row has been validated successfully.

use std::collections::BTreeMap;

use fgit_crypto::{PUBLIC_KEY_BYTES, VerifyingKey};
use fgit_types::{OPAQUE_ID_LEN, PrincipalId, RepositoryId};

use super::{DeployKeyBinding, DeployKeyRefusal, DeployKeyScope};

/// Maximum complete deploy-key table size, including whitespace and comments.
pub const MAX_DEPLOY_KEY_TABLE_BYTES: usize = 64 * 1024;

/// Maximum logical key registrations, before repository-route alias expansion.
pub const MAX_DEPLOY_KEY_TABLE_ROWS: usize = 256;

/// A deploy-key table is unusable as a whole, never a partially accepted grant.
/// Diagnostics name positions and limits without retaining key or file contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeployKeyTableRefusal {
    /// The complete byte slice exceeds the fixed input envelope.
    ByteLimitExceeded { observed: usize, limit: usize },
    /// Any part of the table, including a comment, is not UTF-8.
    InvalidUtf8,
    /// A non-comment registration exceeds the logical row envelope.
    RowLimitExceeded { line: usize, limit: usize },
    /// A registration omits its public key, principal or scope column.
    MissingFields { line: usize },
    /// A fourth field is present and does not begin a trailing `#` comment.
    UnexpectedField { line: usize },
    /// The key is not 32 hex-encoded bytes or a usable Ed25519 public key.
    InvalidPublicKey { line: usize },
    /// The principal is not exactly one hex-encoded opaque principal identity.
    InvalidPrincipal { line: usize },
    /// The scope column contains an unknown or empty comma-separated scope.
    InvalidScopes { line: usize },
    /// A logical public key was registered more than once, even identically.
    DuplicateKey { first_line: usize, line: usize },
    /// The canonical deploy-key registration predicate refused the row.
    Registration {
        line: usize,
        refusal: DeployKeyRefusal,
    },
}

impl std::fmt::Display for DeployKeyTableRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ByteLimitExceeded { observed, limit } => {
                write!(
                    out,
                    "deploy-key table has {observed} bytes; limit is {limit}"
                )
            }
            Self::InvalidUtf8 => out.write_str("deploy-key table is not valid UTF-8"),
            Self::RowLimitExceeded { line, limit } => {
                write!(
                    out,
                    "deploy-key table line {line} exceeds the {limit}-row limit"
                )
            }
            Self::MissingFields { line } => write!(
                out,
                "deploy-key table line {line} requires a public key, principal and scopes"
            ),
            Self::UnexpectedField { line } => write!(
                out,
                "deploy-key table line {line} has an unexpected field after scopes"
            ),
            Self::InvalidPublicKey { line } => {
                write!(
                    out,
                    "deploy-key table line {line} has an invalid public key"
                )
            }
            Self::InvalidPrincipal { line } => {
                write!(out, "deploy-key table line {line} has an invalid principal")
            }
            Self::InvalidScopes { line } => {
                write!(out, "deploy-key table line {line} has invalid scopes")
            }
            Self::DuplicateKey { first_line, line } => write!(
                out,
                "deploy-key table line {line} repeats the public key from line {first_line}"
            ),
            Self::Registration { line, refusal } => {
                write!(
                    out,
                    "deploy-key table line {line} cannot register its key: {refusal}"
                )
            }
        }
    }
}

impl std::error::Error for DeployKeyTableRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Registration { refusal, .. } => Some(refusal),
            _ => None,
        }
    }
}

/// Parse a complete deploy-key table for one repository and its SSH route alias.
///
/// Each registration is `<pubkey-hex> <principal-hex> <scopes>`, separated by
/// whitespace. The public key is exactly 64 hexadecimal characters; the
/// principal is exactly 32. Hexadecimal is case-insensitive. Blank lines and
/// lines whose first non-whitespace character is `#` are ignored. After the
/// three columns, only whitespace or a whitespace-separated `#` comment is
/// permitted. Comments may contain arbitrary UTF-8 text.
///
/// Scopes are `read`, `write`, or a comma-separated combination. The historical
/// unambiguous order and repetition forms (`write,read`, `read,read`) normalize
/// to the same canonical grants. Unknown and empty components are refused.
///
/// Every logical public key may occur only once, regardless of principal,
/// scopes, hex case, or textual equality. Each valid row supplies one binding
/// for `repository_id`, plus one for `route_repository_id` when they differ;
/// those deliberate aliases are not duplicate registrations.
///
/// Empty and comment-only tables return no bindings, allowing a live source to
/// revoke every key. Any malformed row refuses the entire table, including
/// valid rows before it. The byte limit is checked before UTF-8 parsing or
/// allocation, and the row limit before constructing the next registration.
pub fn parse_deploy_key_table(
    bytes: &[u8],
    repository_id: RepositoryId,
    route_repository_id: RepositoryId,
) -> Result<Vec<DeployKeyBinding>, DeployKeyTableRefusal> {
    if bytes.len() > MAX_DEPLOY_KEY_TABLE_BYTES {
        return Err(DeployKeyTableRefusal::ByteLimitExceeded {
            observed: bytes.len(),
            limit: MAX_DEPLOY_KEY_TABLE_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| DeployKeyTableRefusal::InvalidUtf8)?;
    let mut bindings = Vec::new();
    let mut keys = BTreeMap::new();
    for (index, row) in text.lines().enumerate() {
        let line = index + 1;
        let mut fields = row.split_whitespace();
        let Some(public_key) = fields.next() else {
            continue;
        };
        if public_key.starts_with('#') {
            continue;
        }
        if keys.len() == MAX_DEPLOY_KEY_TABLE_ROWS {
            return Err(DeployKeyTableRefusal::RowLimitExceeded {
                line,
                limit: MAX_DEPLOY_KEY_TABLE_ROWS,
            });
        }
        let principal = fields
            .next()
            .ok_or(DeployKeyTableRefusal::MissingFields { line })?;
        let scopes = fields
            .next()
            .ok_or(DeployKeyTableRefusal::MissingFields { line })?;
        if fields.next().is_some_and(|field| !field.starts_with('#')) {
            return Err(DeployKeyTableRefusal::UnexpectedField { line });
        }
        let public_bytes = hex::<PUBLIC_KEY_BYTES>(public_key)
            .ok_or(DeployKeyTableRefusal::InvalidPublicKey { line })?;
        let checked_key = ed25519_dalek::VerifyingKey::from_bytes(&public_bytes)
            .map_err(|_| DeployKeyTableRefusal::InvalidPublicKey { line })?;
        if checked_key.is_weak() {
            return Err(DeployKeyTableRefusal::InvalidPublicKey { line });
        }
        let principal = PrincipalId::from_bytes(
            hex::<OPAQUE_ID_LEN>(principal)
                .ok_or(DeployKeyTableRefusal::InvalidPrincipal { line })?,
        );
        let scopes = parse_scopes(scopes).ok_or(DeployKeyTableRefusal::InvalidScopes { line })?;
        if let Some(first_line) = keys.insert(public_bytes, line) {
            return Err(DeployKeyTableRefusal::DuplicateKey { first_line, line });
        }
        let key = VerifyingKey::from_bytes(public_bytes);
        let register = |repository_id| {
            DeployKeyBinding::register(repository_id, principal, key, &scopes)
                .map_err(|refusal| DeployKeyTableRefusal::Registration { line, refusal })
        };
        bindings.push(register(repository_id)?);
        if route_repository_id != repository_id {
            bindings.push(register(route_repository_id)?);
        }
    }
    Ok(bindings)
}

fn hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.as_bytes();
    if text.len() != N * 2 {
        return None;
    }
    let mut decoded = [0; N];
    for (byte, pair) in decoded.iter_mut().zip(text.chunks_exact(2)) {
        *byte = hex_digit(pair[0])? * 16 + hex_digit(pair[1])?;
    }
    Some(decoded)
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_scopes(text: &str) -> Option<Vec<DeployKeyScope>> {
    let (mut read, mut write) = (false, false);
    for scope in text.split(',') {
        match scope {
            "read" => read = true,
            "write" => write = true,
            _ => return None,
        }
    }
    let mut scopes = Vec::with_capacity(2);
    if read {
        scopes.push(DeployKeyScope::Read);
    }
    if write {
        scopes.push(DeployKeyScope::Write);
    }
    Some(scopes)
}
