//! Full target-before -> actual-candidate inspection at one authenticated PR
//! basis. This is a derived read, not a vote, object import or publication.

use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::review::{ComparisonMode, ReviewOptions, SourceReview};
use fgit_types::GitOid;
use fgit_wire::visibility::RefVisibility;

use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode};
pub(crate) use super::publication::BundleInspectionRefusal;

/// Transport measurements from the native inspector, not a closure proof or
/// a claim that objects were admitted to this repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectedBundle {
    pub sha256: [u8; 32],
    pub bytes: usize,
    pub pack_bytes: usize,
    pub pack_objects: usize,
    pub expanded_bytes: usize,
    pub closure_objects: usize,
    pub transport_only_objects: usize,
}

/// A complete bounded comparison with the exact submitted PR coordinates.
/// Binary/object-only entries remain explicitly non-textual; they are never
/// represented as an empty textual change. Original commit metadata is retained.
#[derive(Debug)]
pub struct PullRequestInspection {
    pub subject: ReviewSubject,
    pub candidate: CandidateBinding,
    pub review: SourceReview,
    pub candidate_commit_body: Vec<u8>,
    pub parents: Vec<GitOid>,
    pub prerequisites: Vec<GitOid>,
    pub bundle: InspectedBundle,
}

#[derive(Debug)]
pub enum PullRequestInspectionRefusal {
    Selection(Box<NodeWorkspaceRefusal>),
    Candidate(Box<BundleInspectionRefusal>),
}
impl std::fmt::Display for PullRequestInspectionRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Selection(error) => write!(out, "PR inspection selection refused: {error}"),
            Self::Candidate(error) => write!(out, "PR candidate inspection refused: {error}"),
        }
    }
}
impl std::error::Error for PullRequestInspectionRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Selection(error) => Some(error.as_ref()),
            Self::Candidate(error) => Some(error.as_ref()),
        }
    }
}
impl From<NodeWorkspaceRefusal> for PullRequestInspectionRefusal {
    fn from(error: NodeWorkspaceRefusal) -> Self { Self::Selection(Box::new(error)) }
}
impl From<BundleInspectionRefusal> for PullRequestInspectionRefusal {
    fn from(error: BundleInspectionRefusal) -> Self { Self::Candidate(Box::new(error)) }
}

impl OneNode {
    /// Inspect the ACTUAL merge result, including all changed paths and the
    /// complete native commit body, without staging uploaded objects.
    ///
    /// The caller supplies independent source/base/candidate coordinates and
    /// authenticated disclosure policy. Both native parent closures are selected
    /// by the existing inspector before any uploaded delta can read originals.
    /// A PR from one head cannot be combined with inspection at another head.
    ///
    /// This full-candidate profile rejects path filters and merge-base diffs.
    /// Callers may narrow work limits, but exhaustion returns an error rather
    /// than a successful partial report. An inspection never grants approval;
    /// review and merge admission still check their own exact current basis.
    pub async fn inspect_pull_request_bundle_in(
        &self,
        request: &NodeRequestContext,
        subject: &ReviewSubject,
        candidate: CandidateBinding,
        input: &[u8],
        visibility: &RefVisibility,
        options: &ReviewOptions,
    ) -> Result<PullRequestInspection, PullRequestInspectionRefusal> {
        options.validate().map_err(|error| BundleInspectionRefusal::Review(Box::new(error)))?;
        if options.mode != ComparisonMode::Direct || !options.paths.is_empty() {
            return Err(BundleInspectionRefusal::InvalidCandidate("full candidate inspection requires an unfiltered direct comparison").into());
        }
        candidate.validate(subject).map_err(|_| BundleInspectionRefusal::InvalidCandidate("invalid exact candidate coordinates"))?;
        let head = self.validate_pull_request_preparation_in(request, subject, visibility).await?;
        let mut inspected = self.inspect_merge_bundle_in(request, &candidate.merge(subject), input,
            visibility, Some(head), options).await?;
        if inspected.review.source_head != head
            || inspected.review.comparison.requested_before != subject.target_tip
            || inspected.review.comparison.requested_after != candidate.commit
            || inspected.parents != [subject.target_tip, subject.source_tip]
            || inspected.merge_base != Some(candidate.merge_base)
        {
            return Err(BundleInspectionRefusal::SnapshotMoved.into());
        }
        if !super::workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None }.into());
        }
        inspected.review.pull_request = Some((subject.pull_request, subject.pull_request_version));
        Ok(PullRequestInspection {
            subject: subject.clone(), candidate, review: inspected.review,
            candidate_commit_body: inspected.candidate_commit_body,
            parents: inspected.parents, prerequisites: inspected.prerequisites,
            bundle: InspectedBundle {
                sha256: inspected.bundle_sha256, bytes: inspected.bundle_bytes,
                pack_bytes: inspected.pack_bytes, pack_objects: inspected.pack_objects,
                expanded_bytes: inspected.expanded_bytes, closure_objects: inspected.closure_objects,
                transport_only_objects: inspected.transport_only_objects,
            },
        })
    }
}
