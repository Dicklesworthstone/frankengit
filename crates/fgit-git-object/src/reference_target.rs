//! Native ref-target kind semantics, independent of access or publication.
//!
//! Callers validate the ref name and verify the object identity/body before
//! using its actual kind. This module neither peels tags nor authorizes reads.
use crate::ObjectType;

/// Required direct native kind for an already-validated ref name. Branches
/// name commits; tags, notes and other namespaces can name any native kind.
/// The byte-exact, slash-terminated prefix intentionally does not capture
/// `refs/heads-other/*`, case variants or remote-tracking refs.
#[must_use]
pub fn required_ref_target_kind(name: &[u8]) -> Option<ObjectType> {
    name.starts_with(b"refs/heads/")
        .then_some(ObjectType::Commit)
}

/// A branch cannot directly name a tree, blob or annotated tag, even when
/// that tag ultimately refers to a commit. Force is not an exception.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceTargetKindMismatch {
    pub expected: ObjectType,
    pub actual: ObjectType,
}
impl std::fmt::Display for ReferenceTargetKindMismatch {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "reference target requires {}, found {}",
            self.expected.label(),
            self.actual.label()
        )
    }
}
impl std::error::Error for ReferenceTargetKindMismatch {}

/// Enforce native kind only. This does not implement fast-forward, deletion,
/// signature, review, access-control or other repository policy decisions.
pub fn validate_reference_target_kind(
    name: &[u8],
    actual: ObjectType,
) -> Result<(), ReferenceTargetKindMismatch> {
    if let Some(expected) = required_ref_target_kind(name) {
        if expected != actual {
            return Err(ReferenceTargetKindMismatch { expected, actual });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const KINDS: [ObjectType; 4] = [
        ObjectType::Commit,
        ObjectType::Tree,
        ObjectType::Blob,
        ObjectType::Tag,
    ];
    #[test]
    fn every_native_kind_is_checked_for_raw_branch_names() {
        for name in [
            b"refs/heads/main".as_slice(),
            b"refs/heads/team/topic",
            b"refs/heads/\xff",
        ] {
            for actual in KINDS {
                let result = validate_reference_target_kind(name, actual);
                if actual == ObjectType::Commit {
                    assert_eq!(result, Ok(()));
                } else {
                    assert_eq!(
                        result,
                        Err(ReferenceTargetKindMismatch {
                            expected: ObjectType::Commit,
                            actual
                        })
                    );
                }
            }
        }
    }
    #[test]
    fn nonbranch_namespaces_allow_every_native_kind_without_reinterpretation() {
        for name in [
            b"refs/tags/v1".as_slice(),
            b"refs/notes/data",
            b"refs/remotes/origin/main",
            b"refs/heads-other/main",
            b"refs/Heads/main",
            b"refs/heads",
        ] {
            assert_eq!(required_ref_target_kind(name), None);
            for actual in KINDS {
                assert_eq!(validate_reference_target_kind(name, actual), Ok(()));
            }
        }
    }
    #[test]
    fn kind_error_does_not_echo_a_ref_name_or_identity() {
        let error = validate_reference_target_kind(b"refs/heads/private-name", ObjectType::Tag)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "reference target requires commit, found tag"
        );
        assert!(!error.to_string().contains("private-name"));
    }
}
