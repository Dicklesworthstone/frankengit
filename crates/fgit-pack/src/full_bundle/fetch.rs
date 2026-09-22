//! Exact ref selection for offline fetch. This is a request, not an admission proof.
use super::{FullBundleError, FullBundleInput, FullBundleLimits};
use crate::{Deadline, ObjectId, checkpoint};
use fgit_types::RefName;
use std::collections::BTreeMap;

/// Fetch one advertised source into an exact destination. `None` requires an
/// absent destination; `Some` requires that exact previous native identity.
/// There is no wildcard, deletion, force, or implicit current-tip lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleRefMapping {
    pub source: RefName,
    pub destination: RefName,
    pub expected_old: Option<ObjectId>,
}

/// Derived from the supplied bundle header and explicit mapping. Only native
/// quarantine and ordinary authority admission can validate or publish it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleRefUpdate {
    pub source: RefName,
    pub destination: RefName,
    pub expected_old: Option<ObjectId>,
    pub target: ObjectId,
}

impl FullBundleInput<'_> {
    /// Resolve explicit mappings in deterministic destination-byte order.
    /// Unselected advertisements never become destination updates. One source
    /// may feed multiple destinations, but no destination can occur twice.
    pub fn select_updates(
        &self,
        mappings: &[BundleRefMapping],
        limits: FullBundleLimits,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<BundleRefUpdate>, FullBundleError> {
        checkpoint(deadline)?;
        if mappings.is_empty() || mappings.len() > limits.max_references {
            return Err(FullBundleError::Limit("fetch mappings"));
        }
        let mut updates = BTreeMap::new();
        let mut bytes = 0usize;
        for mapping in mappings {
            checkpoint(deadline)?;
            bytes = bytes
                .checked_add(mapping.source.as_bytes().len())
                .and_then(|n| n.checked_add(mapping.destination.as_bytes().len()))
                .filter(|n| *n <= limits.max_header_bytes)
                .ok_or(FullBundleError::Limit("fetch mapping bytes"))?;
            let name = mapping.destination.as_bytes();
            if ![b"refs/heads/".as_slice(), b"refs/remotes/", b"refs/tags/"]
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                return Err(FullBundleError::Unsupported("fetch destination namespace"));
            }
            if mapping
                .expected_old
                .is_some_and(|old| old.is_zero() || old.algorithm() != self.format())
            {
                return Err(FullBundleError::FormatMismatch);
            }
            let index = self
                .references()
                .binary_search_by(|reference| reference.name().cmp(&mapping.source))
                .map_err(|_| FullBundleError::Invalid("unadvertised fetch source"))?;
            let update = BundleRefUpdate {
                source: mapping.source.clone(),
                destination: mapping.destination.clone(),
                expected_old: mapping.expected_old,
                target: *self.references()[index].target(),
            };
            if updates
                .insert(mapping.destination.clone(), update)
                .is_some()
            {
                return Err(FullBundleError::Invalid("duplicate fetch destination"));
            }
        }
        checkpoint(deadline)?;
        Ok(updates.into_values().collect())
    }
}
