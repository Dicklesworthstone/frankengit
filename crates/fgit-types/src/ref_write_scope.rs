//! A transport-authenticated ceiling on code-reference writes.
//!
//! This is neither repository policy nor a read-disclosure filter. A request
//! must satisfy this ceiling AND ordinary canonical admission. Scope never
//! enters the transaction identity: credential rotation does not change the
//! principal's original retry key or historical outcome.

use std::collections::BTreeSet;

use crate::RefName;

const MAX_SELECTORS: usize = 64;
const MAX_REFERENCE_BYTES: usize = 4096;
const MAX_FIELD_BYTES: usize = 2 * MAX_REFERENCE_BYTES + 8 * MAX_SELECTORS;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Selector {
    Exact(RefName),
    Prefix(Vec<u8>),
}

/// A credential ref-write selector is malformed or exceeds the fixed envelope.
/// The refusal deliberately retains no untrusted field or reference bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefWriteScopeRefusal;

impl std::fmt::Display for RefWriteScopeRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("invalid or excessive ref-write scope")
    }
}

impl std::error::Error for RefWriteScopeRefusal {}

/// Validated finite union of exact refs and slash-terminated namespaces.
/// An empty union denies every code-reference write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefWriteScope(BTreeSet<Selector>);

impl RefWriteScope {
    /// Parse the v2 credential field. `all` preserves the unrestricted v1
    /// ceiling; `none` explicitly grants no reference writes. Names are hex so
    /// every Git-valid byte, including non-UTF-8 bytes, remains lossless.
    pub fn parse(field: &str) -> Result<Option<Self>, RefWriteScopeRefusal> {
        if field == "all" {
            return Ok(None);
        }
        if field == "none" {
            return Ok(Some(Self(BTreeSet::new())));
        }
        if field.is_empty() || field.len() > MAX_FIELD_BYTES {
            return Err(RefWriteScopeRefusal);
        }
        let mut selectors = BTreeSet::new();
        let mut bytes_used = 0usize;
        for entry in field.split(',') {
            if selectors.len() == MAX_SELECTORS {
                return Err(RefWriteScopeRefusal);
            }
            let (kind, hex) = entry.split_once(':').ok_or(RefWriteScopeRefusal)?;
            if !matches!(kind, "exact" | "prefix")
                || hex.is_empty()
                || !hex.len().is_multiple_of(2)
                || !hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(RefWriteScopeRefusal);
            }
            bytes_used = bytes_used
                .checked_add(hex.len() / 2)
                .ok_or(RefWriteScopeRefusal)?;
            if bytes_used > MAX_REFERENCE_BYTES {
                return Err(RefWriteScopeRefusal);
            }
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            let bytes: Vec<_> = hex
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| (digit(pair[0]) << 4) | digit(pair[1]))
                .collect();
            if !bytes.starts_with(b"refs/") {
                return Err(RefWriteScopeRefusal);
            }
            let selector = if kind == "exact" {
                Selector::Exact(RefName::try_new(&bytes).map_err(|_| RefWriteScopeRefusal)?)
            } else {
                // Validate the complete namespace root as a native ref, then
                // retain its slash. `agent/` must never match `agents/x` or
                // grant the distinct ref `agent` itself.
                let root = bytes.strip_suffix(b"/").ok_or(RefWriteScopeRefusal)?;
                RefName::try_new(root).map_err(|_| RefWriteScopeRefusal)?;
                Selector::Prefix(bytes)
            };
            if !selectors.insert(selector) {
                return Err(RefWriteScopeRefusal);
            }
        }
        Ok(Some(Self(selectors)))
    }

    /// Tests an already validated native ref against this credential ceiling.
    /// The caller remains responsible for native syntax and canonical policy.
    #[must_use]
    pub fn permits(&self, reference: &[u8]) -> bool {
        self.0.iter().any(|selector| match selector {
            Selector::Exact(allowed) => reference == allowed.as_bytes(),
            Selector::Prefix(prefix) => reference.starts_with(prefix),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn exact_and_namespace_grants_preserve_native_bytes_and_boundaries() {
        let field = format!(
            "exact:{},prefix:{}",
            hex(b"refs/tags/release-\xff"),
            hex(b"refs/heads/agent/")
        );
        let scope = RefWriteScope::parse(&field).unwrap().unwrap();
        for permitted in [
            b"refs/tags/release-\xff".as_slice(),
            b"refs/heads/agent/one",
            b"refs/heads/agent/nested/two",
        ] {
            assert!(scope.permits(permitted));
        }
        for denied in [
            b"refs/tags/release-\xff/child".as_slice(),
            b"refs/heads/agent",
            b"refs/heads/agents/one",
            b"refs/heads/main",
            b"refs/tags/agent/one",
        ] {
            assert!(!scope.permits(denied));
        }
        assert_eq!(RefWriteScope::parse("all"), Ok(None));
        assert!(
            !RefWriteScope::parse("none")
                .unwrap()
                .unwrap()
                .permits(b"refs/heads/main")
        );
    }

    #[test]
    fn malformed_empty_duplicate_and_pseudoref_selectors_fail_closed() {
        for field in [
            String::new(),
            "*".to_owned(),
            "exact:".to_owned(),
            "exact:0".to_owned(),
            "exact:GG".to_owned(),
            "all,none".to_owned(),
            format!("glob:{}", hex(b"refs/heads/*")),
            format!("exact:{}", hex(b"HEAD")),
            format!("exact:{}", hex(b"FETCH_HEAD")),
            format!("exact:{}", hex(b"refs/heads/a.lock")),
            format!("exact:{}", hex(b"refs/heads/a/../b")),
            format!("prefix:{}", hex(b"refs/heads/agent")),
            format!("prefix:{}", hex(b"refs/heads//")),
            format!("prefix:{}", hex(b"refs/heads/bad.lock/")),
            format!("exact:{0},exact:{0}", hex(b"refs/heads/a")),
            format!("prefix:{0},prefix:{0}", hex(b"refs/heads/a/")),
            format!("exact:{},", hex(b"refs/heads/a")),
        ] {
            assert!(RefWriteScope::parse(&field).is_err(), "{field}");
        }
    }

    #[test]
    fn both_selector_count_and_total_native_bytes_are_bounded() {
        let field = |count| {
            (0..count)
                .map(|n| format!("exact:{}", hex(format!("refs/heads/a{n}").as_bytes())))
                .collect::<Vec<_>>()
                .join(",")
        };
        assert!(RefWriteScope::parse(&field(MAX_SELECTORS)).is_ok());
        assert!(RefWriteScope::parse(&field(MAX_SELECTORS + 1)).is_err());
        let longest = (0..4)
            .map(|n| {
                format!(
                    "exact:{}",
                    hex(format!("refs/heads/{n}{}", "a".repeat(1012)).as_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        assert!(RefWriteScope::parse(&longest).is_ok());
        assert!(
            RefWriteScope::parse(&format!("{longest},exact:{}", hex(b"refs/heads/extra"))).is_err()
        );
    }
}
