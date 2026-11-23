//! Request-local membership without changing first-seen wire order.

use std::collections::HashSet;
use std::fmt;

use crate::{AnyGitOid, WireError};

/// The vector is the only ordering authority. The randomized standard-library
/// hash table is a private membership accelerator, never an output iterator.
/// Its per-instance hash keys resist client-chosen collision sets; the existing
/// distinct-ID limit bounds both collections, including duplicate-heavy input.
#[derive(Clone, Default)]
pub(super) struct RequestObjectIds {
    ordered: Vec<AnyGitOid>,
    members: HashSet<AnyGitOid>,
}

impl RequestObjectIds {
    pub(super) fn as_slice(&self) -> &[AnyGitOid] {
        &self.ordered
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }

    pub(super) fn contains(&self, oid: &AnyGitOid) -> bool {
        self.members.contains(oid)
    }

    /// Repeated wants/haves/shallow cutoffs are idempotent even at the limit.
    /// Reserve both bounded collections before changing either membership or
    /// order, so an allocation failure cannot leave their contents divergent.
    pub(super) fn insert(
        &mut self,
        field: &'static str,
        oid: AnyGitOid,
        limit: usize,
    ) -> Result<(), WireError> {
        if self.contains(&oid) {
            return Ok(());
        }
        if self.ordered.len() >= limit {
            return Err(WireError::TooManyObjectIds { field, limit });
        }
        self.ordered
            .try_reserve(1)
            .map_err(|_| WireError::AllocationFailure)?;
        self.members
            .try_reserve(1)
            .map_err(|_| WireError::AllocationFailure)?;
        self.members.insert(oid);
        self.ordered.push(oid);
        Ok(())
    }
}

// Public upload-pack machines derive Debug. Keep even that view independent
// of the private randomized table's iteration order.
impl fmt::Debug for RequestObjectIds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.ordered.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GitObjectFormat;

    fn oid(format: GitObjectFormat, value: u64) -> AnyGitOid {
        let width = format.digest_len() * 2;
        AnyGitOid::from_hex(format, &format!("{value:0width$x}")).expect("bounded fixture identity")
    }

    #[test]
    fn membership_order_and_refusals_match_a_linear_oracle_in_both_domains() {
        for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
            for limit in [1, 7, 32, 127] {
                let mut indexed = RequestObjectIds::default();
                let mut reference = Vec::new();
                let mut state = 0x3243_f6a8_885a_308d_u64;
                for _ in 0..2_048 {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let next = oid(format, state % 193 + 1);
                    let expected = if reference.contains(&next) {
                        Ok(())
                    } else if reference.len() == limit {
                        Err(WireError::TooManyObjectIds {
                            field: "have",
                            limit,
                        })
                    } else {
                        reference.push(next);
                        Ok(())
                    };
                    assert_eq!(indexed.insert("have", next, limit), expected);
                    assert_eq!(indexed.as_slice(), reference);
                    assert_eq!(indexed.contains(&next), reference.contains(&next));
                }
                assert_eq!(format!("{indexed:?}"), format!("{reference:?}"));
            }
        }
    }

    #[test]
    fn cloned_membership_is_independent_and_native_domains_remain_distinct() {
        let first = oid(GitObjectFormat::Sha1, 1);
        let other_domain = oid(GitObjectFormat::Sha256, 1);
        let mut original = RequestObjectIds::default();
        original.insert("want", first, 2).expect("first identity");
        let mut clone = original.clone();
        clone
            .insert("want", other_domain, 2)
            .expect("a distinct native domain");
        assert_eq!(original.as_slice(), &[first]);
        assert_eq!(clone.as_slice(), &[first, other_domain]);
        assert!(!original.contains(&other_domain));
        clone.insert("want", first, 2).expect("duplicate at limit");
        assert_eq!(clone.as_slice(), &[first, other_domain]);
    }
}
