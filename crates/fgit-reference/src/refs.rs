//! Ref admission policy and expected-old semantics.
//!
//! The ref *name domain* is [`fgit_types::refs::RefName`], owned by
//! `fgit-types`, so the reference model, the object engine, and the authority
//! store all decide "is this a legal ref name" the same way. This module adds
//! only what is the model's own: which of those legal names the canonical
//! repository state admits, and how an expected-old precondition is compared
//! against a pinned basis.
//!
//! ## Declared subset
//!
//! The model admits the `refs/` namespace only. `HEAD` and other one-level
//! pseudo-refs are legal names — `fgit-types` builds them through
//! [`fgit_types::refs::RefName::try_new_one_level`] — but symbolic-ref
//! resolution is not part of this slice. A request naming one is refused with
//! [`fgit_types::vocabulary::RefusalCode::RefNameInvalid`] rather than being
//! silently reinterpreted as the branch it points at. That is an explicit
//! non-claim, not an oversight.

use fgit_types::native::GitOid;
use fgit_types::refs::RefName;

/// The one namespace prefix canonical repository state admits.
pub const CANONICAL_REF_PREFIX: &[u8] = b"refs";

/// True when `name` is inside the canonical `refs/` namespace.
///
/// A bare `refs` is not admitted: there is no ref there, only the namespace.
#[must_use]
pub fn is_canonical(name: &RefName) -> bool {
    name.is_under(CANONICAL_REF_PREFIX)
}

/// The protection and capability scope a canonical ref belongs to.
///
/// `refs/heads/main` scopes to `heads`. Policy is written against the scope
/// rather than the exact name so a protection rule covers a namespace without
/// enumerating its members.
///
/// Returns `None` for a name outside the canonical namespace, which
/// [`is_canonical`] rejects before policy ever runs.
#[must_use]
pub fn scope_of(name: &RefName) -> Option<&[u8]> {
    if !is_canonical(name) {
        return None;
    }
    name.components().nth(1)
}

/// What a ref is expected to hold before an intent applies.
///
/// This is the expected-old semantics of `docs/NORMATIVE_PROTOCOL_CONTRACTS.md`
/// §16.2: a caller states a precondition, and the model compares it against the
/// pinned basis. The comparison never consults a value the caller computed, and
/// there is no variant meaning "whatever the caller last saw".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExpectedRefState {
    /// The ref must not exist.
    Absent,
    /// The ref must hold exactly this object.
    Exact(GitOid),
    /// No precondition is asserted.
    Any,
}

impl ExpectedRefState {
    /// True when `actual` satisfies this expectation.
    #[must_use]
    pub fn is_satisfied_by(self, actual: Option<&GitOid>) -> bool {
        match (self, actual) {
            (Self::Any, _) | (Self::Absent, None) => true,
            (Self::Absent, Some(_)) | (Self::Exact(_), None) => false,
            (Self::Exact(expected), Some(found)) => expected == *found,
        }
    }

    /// True when this expectation asserts nothing about the basis.
    ///
    /// An unconditional expectation and a forced update are independent: a
    /// caller may pair a force with an exact expected-old value, which is the
    /// "force with lease" shape, and the model checks both. This predicate
    /// exists so a caller can tell the two apart, not to forbid the pairing.
    #[must_use]
    pub const fn is_unconditional(self) -> bool {
        matches!(self, Self::Any)
    }
}

#[cfg(test)]
mod tests {
    use super::{ExpectedRefState, is_canonical, scope_of};
    use fgit_types::native::{GitOid, GitOidSha1};
    use fgit_types::refs::RefName;

    fn name(text: &str) -> RefName {
        RefName::try_new(text.as_bytes())
            .unwrap_or_else(|error| panic!("{text} rejected by fgit-types: {error}"))
    }

    fn oid(seed: u8) -> GitOid {
        GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
    }

    #[test]
    fn canonical_namespace_admits_ordinary_refs() {
        for text in [
            "refs/heads/main",
            "refs/heads/feature/deep/nesting",
            "refs/tags/v1.0.0",
            "refs/pull/17/head",
        ] {
            assert!(is_canonical(&name(text)), "{text} must be admitted");
        }
    }

    #[test]
    fn canonical_namespace_excludes_names_outside_it() {
        // The permitted twin of each of these is in the test above: the same
        // shape under `refs/` is admitted, so exclusion here is a namespace
        // decision and not an inability to handle the shape.
        for text in ["heads/main", "refsx/heads/main", "notrefs/heads/main"] {
            assert!(!is_canonical(&name(text)), "{text} must not be admitted");
        }
    }

    #[test]
    fn one_level_pseudo_refs_are_outside_the_canonical_namespace() {
        let head = RefName::try_new_one_level(b"HEAD").expect("HEAD is a legal one-level name");
        assert!(!is_canonical(&head));
        assert_eq!(scope_of(&head), None);
    }

    #[test]
    fn scope_is_the_component_after_the_prefix() {
        for (text, expected) in [
            ("refs/heads/main", &b"heads"[..]),
            ("refs/tags/v1.0.0", &b"tags"[..]),
            ("refs/pull/17/head", &b"pull"[..]),
        ] {
            assert_eq!(scope_of(&name(text)), Some(expected), "scope of {text}");
        }
    }

    #[test]
    fn expected_state_compares_against_the_basis_only() {
        let present = oid(1);
        let other = oid(2);
        assert!(ExpectedRefState::Absent.is_satisfied_by(None));
        assert!(!ExpectedRefState::Absent.is_satisfied_by(Some(&present)));
        assert!(ExpectedRefState::Exact(present).is_satisfied_by(Some(&present)));
        assert!(!ExpectedRefState::Exact(present).is_satisfied_by(Some(&other)));
        assert!(!ExpectedRefState::Exact(present).is_satisfied_by(None));
        assert!(ExpectedRefState::Any.is_satisfied_by(None));
        assert!(ExpectedRefState::Any.is_satisfied_by(Some(&present)));
    }

    #[test]
    fn only_the_unconditional_expectation_reports_itself_as_such() {
        assert!(ExpectedRefState::Any.is_unconditional());
        assert!(!ExpectedRefState::Absent.is_unconditional());
        assert!(!ExpectedRefState::Exact(oid(3)).is_unconditional());
    }

    #[test]
    fn ref_names_order_byte_lexicographically() {
        let mut names = [
            name("refs/tags/v1"),
            name("refs/heads/main"),
            name("refs/heads/dev"),
        ];
        names.sort();
        let ordered = names
            .iter()
            .map(|entry| entry.as_str().unwrap_or_default())
            .collect::<Vec<&str>>();
        assert_eq!(
            ordered,
            vec!["refs/heads/dev", "refs/heads/main", "refs/tags/v1"]
        );
    }
}
