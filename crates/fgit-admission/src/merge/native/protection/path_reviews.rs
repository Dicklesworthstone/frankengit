//! Exact native source deltas and the additional reviewer quorums they select.
//! The object verifier is the sole producer of `VerifiedMergePaths`; path
//! projections, caller assertions and a PR's source diff cannot replace it.

use fgit_authority::AsyncAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_forge::event::{NativeMerge, protection::PathReviewRule};
use fgit_types::{PolicyEpoch, PrincipalId, RefusalCode};

use super::super::{NativeMergeIntent, NativeMergeMethod};
use crate::ProjectionFailure;

mod objects;
pub use objects::{verify_merge_paths, verify_rebase_paths, verify_source_paths};

/// Complete native path delta of one single-parent source candidate. Only the
/// object verifier can construct this witness; submitted path lists cannot.
#[derive(Debug)]
pub struct VerifiedSourcePaths {
    before: fgit_types::GitOid,
    after: fgit_types::GitOid,
    changed_paths: Vec<Vec<u8>>,
}

impl VerifiedSourcePaths {
    #[must_use]
    pub const fn before(&self) -> fgit_types::GitOid {
        self.before
    }
    #[must_use]
    pub const fn after(&self) -> fgit_types::GitOid {
        self.after
    }
    #[must_use]
    pub fn changed_paths(&self) -> &[Vec<u8>] {
        &self.changed_paths
    }
}

pub const MAX_MERGE_PATH_BYTES: usize = 4096;
pub const MAX_MERGE_PATH_DEPTH: usize = 64;
pub const MAX_MERGE_CHANGED_PATHS: usize = 4096;
pub const MAX_MERGE_CHANGED_PATH_BYTES: usize = 1024 * 1024;

/// Complete structural change evidence bound to the independently verified
/// exact merge coordinates. This is content evidence, not publication authority.
/// Only the native path verifiers can construct this from canonical Git bytes.
#[derive(Debug)]
pub struct VerifiedMergePaths {
    merge: NativeMerge,
    changed_paths: Vec<Vec<u8>>,
    /// Rebase requires every intermediate delta, never only the final tree.
    rebase_series: bool,
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

    fn verify_method(&self, method: NativeMergeMethod) -> Result<(), ProjectionFailure> {
        if self.rebase_series != (method == NativeMergeMethod::Rebase) {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
        }
        Ok(())
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
    if let Some(paths) = paths {
        paths.verify_method(intent.method())?;
    }
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
