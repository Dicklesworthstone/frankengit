#![forbid(unsafe_code)]
//! Caller-supplied backup identities, separate from native validity and authority.
//! No pin, hash domain, trust source or exact-set policy is inferred from input.
use std::collections::BTreeMap;
use std::fmt;

use fgit_crypto::{DigestHasher, Sha256Hasher, lowercase_hex};
use fgit_pack::full_bundle::FullBundleInput;
use fgit_pack::BundleReference;
use fgit_types::{GitHashAlgorithm, GitOid, RefName};

use super::{BundleVerifyError, BundleVerifyLimits, VerifiedGitBundle, checkpoint};

pub const MAX_EXPECTED_REFS: usize = 4096;
const MAX_EXPECTED_NAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleExpectationError {
    MissingAnchor,
    MissingFormat,
    ExactWithoutReferences,
    Limit(&'static str),
    InvalidReference,
    ZeroReferenceTarget,
    ReferenceFormat,
    DuplicateReference(RefName),
    FormatMismatch {
        expected: GitHashAlgorithm,
        actual: GitHashAlgorithm,
    },
    MissingReference(RefName),
    ChangedReference {
        name: RefName,
        expected: GitOid,
        actual: GitOid,
    },
    ReferenceSetMismatch {
        expected: usize,
        actual: usize,
    },
    ArtifactMismatch,
}
impl fmt::Display for BundleExpectationError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAnchor => out.write_str("expected_bundle_identity_required"),
            Self::MissingFormat => out.write_str("expected_reference_format_required"),
            Self::ExactWithoutReferences => out.write_str("exact_expected_references_required"),
            Self::Limit(field) => write!(out, "bundle_expectation_limit: {field}"),
            Self::InvalidReference => out.write_str("invalid_expected_reference"),
            Self::ZeroReferenceTarget => out.write_str("zero_expected_object_identity"),
            Self::ReferenceFormat => out.write_str("expected_reference_hash_domain_mismatch"),
            Self::DuplicateReference(name) => write!(
                out,
                "duplicate_expected_reference: ref_hex={}",
                lowercase_hex(name.as_bytes())
            ),
            Self::FormatMismatch { expected, actual } => write!(
                out,
                "expected_bundle_format_mismatch: expected={}, actual={}",
                expected.as_str(),
                actual.as_str()
            ),
            Self::MissingReference(name) => write!(
                out,
                "expected_reference_missing: ref_hex={}",
                lowercase_hex(name.as_bytes())
            ),
            Self::ChangedReference { name, expected, actual } => write!(
                out,
                "expected_reference_mismatch: ref_hex={}, expected={expected}, actual={actual}",
                lowercase_hex(name.as_bytes())
            ),
            Self::ReferenceSetMismatch { expected, actual } => write!(
                out,
                "expected_reference_set_mismatch: expected={expected}, actual={actual}"
            ),
            Self::ArtifactMismatch => out.write_str("expected_bundle_artifact_mismatch"),
        }
    }
}
impl std::error::Error for BundleExpectationError {}

/// Immutable validated expectations. A format alone is not a backup identity.
/// References name direct refs; HEAD is bound only by a whole-artifact hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleExpectations {
    sha256: Option<[u8; 32]>,
    format: Option<GitHashAlgorithm>,
    references: BTreeMap<RefName, GitOid>,
    exact: bool,
    name_bytes: usize,
}
impl BundleExpectations {
    /// Validate before opening an input. Accept a list, not a map whose earlier
    /// duplicate values might already have been silently overwritten.
    pub fn new(
        sha256: Option<[u8; 32]>,
        format: Option<GitHashAlgorithm>,
        references: &[(RefName, GitOid)],
        exact: bool,
    ) -> Result<Self, BundleExpectationError> {
        if exact && references.is_empty() {
            return Err(BundleExpectationError::ExactWithoutReferences);
        }
        if sha256.is_none() && references.is_empty() {
            return Err(BundleExpectationError::MissingAnchor);
        }
        if !references.is_empty() && format.is_none() {
            return Err(BundleExpectationError::MissingFormat);
        }
        if references.len() > MAX_EXPECTED_REFS {
            return Err(BundleExpectationError::Limit("references"));
        }
        let mut names = BTreeMap::new();
        let mut name_bytes = 0_usize;
        for (name, id) in references {
            let bytes = name.as_bytes();
            if !bytes.starts_with(b"refs/") || bytes.len() > 4096 {
                return Err(BundleExpectationError::InvalidReference);
            }
            name_bytes = name_bytes
                .checked_add(bytes.len())
                .filter(|count| *count <= MAX_EXPECTED_NAME_BYTES)
                .ok_or(BundleExpectationError::Limit("reference bytes"))?;
            if id.is_zero() {
                return Err(BundleExpectationError::ZeroReferenceTarget);
            }
            if Some(id.algorithm()) != format {
                return Err(BundleExpectationError::ReferenceFormat);
            }
            if names.insert(name.clone(), *id).is_some() {
                return Err(BundleExpectationError::DuplicateReference(name.clone()));
            }
        }
        Ok(Self { sha256, format, references: names, exact, name_bytes })
    }

    pub fn validate_limits(&self, limits: &BundleVerifyLimits) -> Result<(), BundleExpectationError> {
        if self.references.len() > limits.envelope.max_references.min(limits.graph.max_references) {
            return Err(BundleExpectationError::Limit("references"));
        }
        if self.name_bytes > limits.envelope.max_header_bytes {
            return Err(BundleExpectationError::Limit("reference bytes"));
        }
        Ok(())
    }
    #[must_use]
    pub const fn sha256(&self) -> Option<&[u8; 32]> {
        self.sha256.as_ref()
    }
    #[must_use]
    pub const fn format(&self) -> Option<GitHashAlgorithm> {
        self.format
    }
    #[must_use]
    pub fn references(&self) -> &BTreeMap<RefName, GitOid> {
        &self.references
    }
    #[must_use]
    pub const fn exact_references(&self) -> bool {
        self.exact
    }

    pub(super) fn check(
        &self,
        input: &[u8],
        envelope: &FullBundleInput<'_>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Option<[u8; 32]>, BundleVerifyError> {
        self.check_selection(envelope.format(), envelope.references(), live)?;
        let digest = match self.sha256 {
            None => None,
            Some(expected) => {
                // One native digest, retained for the final report. Chunked
                // checkpoints share the verifier's sticky cancellation owner.
                let mut hash = Sha256Hasher::new();
                for chunk in input.chunks(64 * 1024) {
                    checkpoint(live)?;
                    hash.update(chunk);
                }
                let actual = hash.finish();
                checkpoint(live)?;
                if actual != expected {
                    return Err(BundleVerifyError::Expectation(BundleExpectationError::ArtifactMismatch));
                }
                Some(actual)
            }
        };
        checkpoint(live)?;
        Ok(digest)
    }

    pub(super) fn check_selection(
        &self,
        format: GitHashAlgorithm,
        references: &[BundleReference],
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        let refuse = BundleVerifyError::Expectation;
        checkpoint(live)?;
        if let Some(expected) = self.format {
            if format != expected {
                return Err(refuse(BundleExpectationError::FormatMismatch {
                    expected,
                    actual: format,
                }));
            }
        }
        for (name, expected) in &self.references {
            checkpoint(live)?;
            let rows = references;
            let at = rows
                .binary_search_by(|row| row.name().cmp(name))
                .map_err(|_| refuse(BundleExpectationError::MissingReference(name.clone())))?;
            let actual = *rows[at].target();
            if actual != *expected {
                return Err(refuse(BundleExpectationError::ChangedReference {
                    name: name.clone(), expected: *expected, actual,
                }));
            }
        }
        if self.exact && self.references.len() != references.len() {
            return Err(refuse(BundleExpectationError::ReferenceSetMismatch {
                expected: self.references.len(), actual: references.len(),
            }));
        }
        checkpoint(live)?;
        Ok(())
    }
}

/// No constructor exposes a header/hash-only match as complete verification.
/// The exact immutable caller expectations outlive this content evidence.
#[derive(Debug)]
pub struct MatchedGitBundle<'a> {
    verified: VerifiedGitBundle,
    expectations: &'a BundleExpectations,
}
impl MatchedGitBundle<'_> {
    #[must_use]
    pub const fn verified(&self) -> &VerifiedGitBundle {
        &self.verified
    }
    #[must_use]
    pub const fn expectations(&self) -> &BundleExpectations {
        self.expectations
    }
}

/// Reject the wrong backup before decompression, then perform all existing
/// native pack/object/graph checks on the same bytes under the same deadline.
/// Matching caller pins is not signature, origin, freshness or authority proof.
pub fn verify_git_bundle_against<'a>(
    input: &[u8],
    limits: &BundleVerifyLimits,
    expectations: &'a BundleExpectations,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<MatchedGitBundle<'a>, BundleVerifyError> {
    let verified = super::verify_git_bundle_inner(input, limits, Some(expectations), allow_work)?;
    Ok(MatchedGitBundle { verified, expectations })
}
