//! Exact-subject PR rebase preparation. The artifact names the target branch;
//! source history remains unchanged and publication is a separate native merge.

use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::PreparationLimits;
use fgit_forge::preparation::rebase::{EmptyCommitPolicy, RebaseCommitter, RebaseRequest};
use fgit_types::{GitOid, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;

use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode, PreparedRebaseBundle};

/// A complete review artifact or an explicit stop, never publication authority.
#[derive(Debug)]
pub struct PreparedPullRequestRebaseBundle {
    pub source_head: RepositoryAuthorityHeadId,
    pub subject: ReviewSubject,
    pub preparation: PreparedRebaseBundle,
}

impl OneNode {
    /// Replay an exact existing open PR's linear source suffix onto its target.
    /// The caller chooses the original common base, committer and empty-change
    /// policy explicitly. Original authors, messages and encoding are retained
    /// by the existing native planner. Both original and rewritten series are
    /// bounded to 256 commits; merge commits and an entirely dropped series
    /// refuse. Conflicts return no partial bundle or staged objects.
    ///
    /// PR metadata, current policy and both branch tips must agree at one head.
    /// The returned bundle has only the target tip as a prerequisite and names
    /// the target ref. Native merge admission later revalidates every exact
    /// coordinate, candidate, review and policy before publishing the ref and
    /// PR event together. Preparation does not rewrite the source branch.
    pub async fn prepare_pull_request_rebase_bundle_in(
        &self,
        request: &NodeRequestContext,
        subject: &ReviewSubject,
        visibility: &RefVisibility,
        upstream: GitOid,
        committer: &RebaseCommitter,
        mut limits: PreparationLimits,
        empty_policy: EmptyCommitPolicy,
    ) -> Result<PreparedPullRequestRebaseBundle, NodeWorkspaceRefusal> {
        limits
            .validate()
            .map_err(NodeWorkspaceRefusal::MergePreparation)?;
        if upstream.is_zero()
            || upstream.algorithm() != subject.source_tip.algorithm()
            || upstream == subject.source_tip
        {
            return Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate(
                "PR rebase requires a nonempty original suffix and at most 256 commits",
            ));
        }
        limits.max_commits = limits
            .max_commits
            .min(fgit_admission::merge::native::objects::MAX_REBASE_MERGE_COMMITS);
        let head = self
            .validate_pull_request_preparation_in(request, subject, visibility)
            .await?;
        let (preparation, _) = self
            .prepare_resolved_rebase_bundle_for_reference_in(
                request,
                &subject.source_ref,
                &subject.target_ref,
                &subject.target_ref,
                RebaseRequest {
                    source_tip: subject.source_tip,
                    upstream,
                    onto: subject.target_tip,
                    empty: empty_policy,
                },
                visibility,
                Some(head),
                committer,
                limits,
                &[],
            )
            .await
            .map_err(|error| NodeWorkspaceRefusal::RebasePreparation(Box::new(error)))?;
        if preparation.source_head != head {
            return Err(NodeWorkspaceRefusal::StaleWorkspaceBase);
        }
        if !super::super::workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        Ok(PreparedPullRequestRebaseBundle {
            source_head: head,
            subject: subject.clone(),
            preparation,
        })
    }
}
