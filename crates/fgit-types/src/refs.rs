//! Validated Git reference names.
//!
//! The rules implemented here are the ones `git check-ref-format` enforces, so
//! a name this type accepts is a name ordinary Git accepts. They live in
//! `fgit-types` because the reference model, the object engine, and the
//! authority store all need the same domain, and two implementations of
//! "is this a legal ref name" would eventually disagree.
//!
//! One deliberate addition to the upstream rules: a total length bound. A
//! resource limit is compatibility behaviour in this project, not an
//! afterthought, so the bound is part of the type and is refused before
//! allocation rather than after.

use core::fmt;

use crate::error::TypeRefusal;

/// Largest accepted reference name, in bytes.
pub const MAX_REF_NAME_LEN: usize = 1024;

/// Bytes that may never appear anywhere in a reference name.
const fn byte_is_forbidden(byte: u8) -> bool {
    byte < 0x20
        || byte == 0x7f
        || matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
}

/// A validated Git reference name.
///
/// Ordering is byte order over the name, which is the order refs are listed
/// and advertised in, so a sorted collection of these is already canonical.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RefName {
    bytes: Vec<u8>,
}

impl RefName {
    /// Builds a full reference name, which must have at least two
    /// slash-separated components, for example `refs/heads/main`.
    pub fn try_new(source: &[u8]) -> Result<Self, TypeRefusal> {
        Self::validate(source, false)
    }

    /// Builds a reference name that may be one level, for example `HEAD`.
    ///
    /// This is the equivalent of `git check-ref-format --allow-onelevel` and
    /// exists for the pseudo-refs that legitimately have no slash.
    pub fn try_new_one_level(source: &[u8]) -> Result<Self, TypeRefusal> {
        Self::validate(source, true)
    }

    fn validate(source: &[u8], allow_one_level: bool) -> Result<Self, TypeRefusal> {
        if source.is_empty() || source.len() > MAX_REF_NAME_LEN {
            return Err(TypeRefusal::LengthOutOfRange {
                field: "RefName",
                observed: u32::try_from(source.len()).unwrap_or(u32::MAX),
                minimum: 1,
                maximum: u32::try_from(MAX_REF_NAME_LEN).unwrap_or(u32::MAX),
            });
        }
        for (offset, byte) in source.iter().copied().enumerate() {
            if byte_is_forbidden(byte) {
                return Err(TypeRefusal::ByteNotPermitted {
                    field: "RefName",
                    offset: at(offset),
                    byte,
                });
            }
        }
        if source == b"@" {
            return Err(structure("name_is_bare_at_sign", 0));
        }
        for (offset, pair) in source.windows(2).enumerate() {
            if pair == b".." {
                return Err(structure("double_dot", at(offset + 1)));
            }
            if pair == b"@{" {
                return Err(structure("at_brace_sequence", at(offset + 1)));
            }
        }
        if source[source.len() - 1] == b'.' {
            return Err(structure("name_ends_with_dot", at(source.len() - 1)));
        }
        if source[source.len() - 1] == b'/' {
            return Err(structure("name_ends_with_slash", at(source.len() - 1)));
        }
        if source[0] == b'/' {
            return Err(structure("name_starts_with_slash", 0));
        }

        let mut component_start = 0;
        let mut components = 0;
        for component in source.split(|byte| *byte == b'/') {
            let component_end = component_start + component.len();
            if component.is_empty() {
                return Err(structure("empty_component", at(component_end)));
            }
            if component.starts_with(b".") {
                return Err(structure("component_starts_with_dot", at(component_start)));
            }
            if component.ends_with(b".lock") {
                return Err(structure(
                    "component_ends_with_dot_lock",
                    at(component_end.saturating_sub(5)),
                ));
            }
            components += 1;
            component_start = component_end + 1;
        }
        if components < 2 && !allow_one_level {
            return Err(structure("name_is_one_level", 0));
        }

        Ok(Self {
            bytes: source.to_vec(),
        })
    }

    /// The reference name bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The reference name as a string slice, when it is valid text.
    ///
    /// Git permits bytes that are not valid text in a reference name, so this
    /// returns `None` rather than lying about the content.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.bytes).ok()
    }

    /// Reference name length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always false: a reference name is never empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// The slash-separated components, in order.
    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.bytes.split(|byte| *byte == b'/')
    }

    /// True when this name sits under the given prefix.
    ///
    /// The prefix must match on a component boundary, so `refs/heads` does not
    /// match `refs/headsup/x`.
    #[must_use]
    pub fn is_under(&self, prefix: &[u8]) -> bool {
        let prefix = prefix.strip_suffix(b"/").unwrap_or(prefix);
        self.bytes.len() > prefix.len()
            && self.bytes.starts_with(prefix)
            && self.bytes[prefix.len()] == b'/'
    }
}

impl fmt::Display for RefName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&String::from_utf8_lossy(&self.bytes))
    }
}

/// Narrows an offset to the width the refusal carries.
fn at(offset: usize) -> u32 {
    u32::try_from(offset).unwrap_or(u32::MAX)
}

/// Builds a structural refusal.
const fn structure(reason: &'static str, offset: u32) -> TypeRefusal {
    TypeRefusal::RefNameStructureInvalid { reason, offset }
}
