//! Exact native source deltas and the additional reviewer quorums they select.
//! The object verifier is the sole producer of `VerifiedMergePaths`; path
//! projections, caller assertions and a PR's source diff cannot replace it.

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_forge::event::{NativeMerge, protection::PathReviewRule};
use fgit_types::{PolicyEpoch, PrincipalId, RefusalCode};

use super::super::NativeMergeIntent;
use crate::ProjectionFailure;

mod objects;
pub use objects::verify_merge_paths;

pub const MAX_MERGE_PATH_BYTES: usize = 4096;
pub const MAX_MERGE_PATH_DEPTH: usize = 64;
pub const MAX_MERGE_CHANGED_PATHS: usize = 4096;
pub const MAX_MERGE_CHANGED_PATH_BYTES: usize = 1024 * 1024;

/// Complete structural change evidence bound to the independently verified
/// exact merge coordinates. This is content evidence, not publication authority.
/// Only `verify_merge_paths` can construct a value from canonical Git bytes.
#[derive(Debug)]
pub struct VerifiedMergePaths {
    merge: NativeMerge,
    changed_paths: Vec<Vec<u8>>,
}
impl VerifiedMergePaths {
    #[must_use]
    pub fn merge(&self) -> &NativeMerge {
        &self.merge
    }

    #[must_use]
    pub fn changed_paths(&self) -> &[Vec<u8>] {
        &self.changed_paths
    }
}

fn matching_rules<'a>(
    merge: &NativeMerge,
    rules: &'a [PathReviewRule],
    paths: Option<&VerifiedMergePaths>,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<Vec<&'a PathReviewRule>, ProjectionFailure> {
    let live = || super::live(cancelled).map_err(super::infrastructure);
    live()?;
    if rules.is_empty() {
        return Ok(Vec::new());
    }
    let paths = paths.ok_or(ProjectionFailure::Refuse(RefusalCode::EvidenceMissing))?;
    if paths.merge != *merge {
        return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceStale));
    }
    let mut matched = Vec::new();
    for rule in rules {
        live()?;
        for changed in &paths.changed_paths {
            live()?;
            if rule.matches(changed) {
                matched.push(rule);
                break;
            }
        }
    }
    live()?;
    Ok(matched)
}

pub(super) async fn verify_at<S, C>(
    store: &S,
    cx: &S::Context,
    basis: &PublicationBasis,
    intent: &NativeMergeIntent,
    submitter: PrincipalId,
    epoch: PolicyEpoch,
    rules: &[PathReviewRule],
    paths: Option<&VerifiedMergePaths>,
    cancelled: &C,
) -> Result<(), ProjectionFailure>
where
    S: AsyncAuthorityStore + ?Sized,
    C: Fn() -> bool + Sync,
{
    let merge = intent.merge().map_err(super::infrastructure)?;
    for rule in matching_rules(merge, rules, paths, cancelled)? {
        // Independent votes retain the exact current PR, base, candidate and
        // policy epoch binding. A matching rule never waives any other rule.
        super::super::pull_request::reviews::gate::verify_quorum_at(
            store,
            cx,
            basis,
            intent,
            submitter,
            epoch,
            &rule.reviewers,
            rule.required_approvals,
            cancelled,
        )
        .await?;
    }
    super::live(cancelled).map_err(super::infrastructure)
}

#[cfg(test)]
mod tests;
