//! Source review composed with the exact same verified source as merge
//! preparation. This module is a child of merge_prepare to share its private
//! object owner, not a second parser, object cache, or repository authority.

use super::{Cell, MergeObjectSource, MergeSourceError, ParseLimits, RefVisibility,
    SelectedSource, VerifiedFabricPackSource};
use fgit_admission::merge::native::pull_request;
use fgit_forge::event::ForgeEventPayload;
use fgit_forge::review::{ReviewError, ReviewOptions, ReviewSelection, SourceReview, compare_source};
use fgit_types::{RefName, RepositoryAuthorityHeadId};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use crate::{AdmissionMaterializationRefusal, NodeRequestContext, OneNode};

/// An unsuccessful review never returns a successful partial/empty comparison.
#[derive(Debug)]
pub enum NodeReviewRefusal {
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    History(Box<fgit_admission::AdmissionError>),
    Review(Box<ReviewError>),
    SnapshotMoved,
    VersionMoved,
    /// Missing and hidden branches/PRs intentionally have the same result.
    Unavailable,
}
impl std::fmt::Display for NodeReviewRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source review unavailable: {self:?}")
    }
}
impl std::error::Error for NodeReviewRefusal {}
fn failed(error: ReviewError) -> NodeReviewRefusal { NodeReviewRefusal::Review(Box::new(error)) }
fn source_failed(error: MergeSourceError) -> NodeReviewRefusal { failed(ReviewError::Source(error)) }

impl OneNode {
    /// Review current branches or the exact tips recorded by a native PR.
    ///
    /// One authenticated head supplies refs, PR frontier, canonical visibility,
    /// and permitted object history. A PR's compared tips do not float with its
    /// branches: a later push/delete leaves the recorded comparison intact.
    /// Optional head/version preconditions refuse mixed or silently moved reads.
    ///
    /// This is a trusted local/ref-authorized read boundary. `paths` narrows
    /// output and traversal, not authority; it is not a path-capability broker.
    /// No objects are staged, no seal is created, and no repository root moves.
    /// Symlink payloads are data, gitlinks are opaque, and no driver executes.
    pub async fn review_source_in(
        &self,
        request: &NodeRequestContext,
        selection: &ReviewSelection,
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        options: &ReviewOptions,
    ) -> Result<SourceReview, NodeReviewRefusal> {
        options.validate().map_err(failed)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeReviewRefusal::Cell)?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|error| NodeReviewRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(NodeReviewRefusal::SnapshotMoved);
        }
        let visible = |a: &RefName, b: &RefName| {
            [a, b].iter().all(|name| !visibility.hides(name.as_bytes())
                && !selected.snapshot().hidden_refs.hides(name.as_bytes()))
        };
        let (before_reference, after_reference, before, after, pull_request) = match selection {
            ReviewSelection::References { before, after } => {
                if !visible(before, after) { return Err(NodeReviewRefusal::Unavailable); }
                let a = *selected.snapshot().refs.get(before).ok_or(NodeReviewRefusal::Unavailable)?;
                let b = *selected.snapshot().refs.get(after).ok_or(NodeReviewRefusal::Unavailable)?;
                (before.clone(), after.clone(), a, b, None)
            }
            ReviewSelection::PullRequest { number, expected_version } => {
                // Do not call read_pull_requests_in here: that would select a
                // second head and could splice metadata from another snapshot.
                let page = pull_request::read_page_at(
                    &self.authority, request.authority(), selected.basis(), number.get() - 1, 1,
                    &visible, &|| !super::super::workspace_request_live(request),
                ).await.map_err(|error| NodeReviewRefusal::History(Box::new(error)))?;
                let view = page.pull_requests.first().filter(|view| view.number == *number)
                    .ok_or(NodeReviewRefusal::Unavailable)?;
                if expected_version.is_some_and(|version| version != view.event.version) {
                    return Err(NodeReviewRefusal::VersionMoved);
                }
                let (a_ref, b_ref, a, b) = match &view.event.payload {
                    ForgeEventPayload::PullRequestChangedNative(change) => (
                        change.data.target_ref.clone(), change.data.source_ref.clone(),
                        change.data.target_tip, change.data.source_tip),
                    ForgeEventPayload::MergeCommittedNative(merge) => (
                        merge.target_ref.clone(), merge.source_ref.clone(),
                        merge.target_tip_before, merge.source_tip),
                    _ => return Err(NodeReviewRefusal::Unavailable),
                };
                (a_ref, b_ref, a, b, Some((*number, view.event.version)))
            }
        };
        let exhaustion = Cell::new(None);
        let source = SelectedSource {
            inner: VerifiedFabricPackSource {
                fabric: &self.fabric, object_format: self.object_format,
                maximum_object_bytes: usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)
                    .min(32 * 1024 * 1024),
                database_context: request.authority(), database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected: selected.selected_closure(),
            limits: ParseLimits {
                tree_reference_bytes: self.object_format.digest_len(),
                max_tree_entries: options.limits.max_tree_entries,
                max_header_lines: 16_384,
                max_object_bytes: usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)
                    .min(32 * 1024 * 1024),
                ..ParseLimits::default()
            },
            read_bytes: Cell::new(0), budget_failed: Cell::new(false),
        };
        let comparison = compare_source(&source, self.object_format, before, after, options);
        source.checkpoint().map_err(source_failed)?;
        let comparison = comparison.map_err(failed)?;
        Ok(SourceReview { repository_id: self.repository_id, source_head: selected.basis().id(),
            before_reference, after_reference, pull_request, comparison })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_authority::IdempotencyKey;
    use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
    use fgit_forge::review::{ComparisonMode, ReviewContent};
    use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
    use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId};
    use crate::LoopbackReceiveSession;
    use super::super::tests::{fixture, metadata};

    #[test]
    fn both_hash_formats_review_real_objects_without_changing_authority() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let (_scratch, node, a, b) = fixture(format, false);
            let request = node.request_context();
            let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
            let a_ref = RefName::try_new(b"refs/heads/main").unwrap();
            let b_ref = RefName::try_new(b"refs/heads/topic").unwrap();
            let selection = ReviewSelection::References { before: a_ref, after: b_ref.clone() };
            let options = ReviewOptions { mode: ComparisonMode::MergeBase, ..ReviewOptions::default() };
            let result = node.runtime().block_on(node.review_source_in(
                &request, &selection, &RefVisibility::new(), Some(before.basis().id()), &options,
            )).unwrap();
            assert_eq!(result.comparison.requested_before, a);
            assert_eq!(result.comparison.requested_after, b);
            assert_eq!(result.comparison.entries.len(), 1);
            assert_eq!(result.comparison.entries[0].path, b"text");
            assert!(matches!(&result.comparison.entries[0].content,
                ReviewContent::Text { additions: 1, deletions: 1, .. }));
            let mut hidden = RefVisibility::new();
            hidden.push_rule(b_ref.as_bytes(), &Default::default()).unwrap();
            assert!(matches!(node.runtime().block_on(node.review_source_in(
                &request, &selection, &hidden, None, &options,
            )), Err(NodeReviewRefusal::Unavailable)));
            let mut bounded = options.clone(); bounded.limits.max_blob_bytes = 1;
            assert!(node.runtime().block_on(node.review_source_in(
                &request, &selection, &RefVisibility::new(), None, &bounded,
            )).is_err());
            assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
            node.shutdown().unwrap();
        }
    }

    #[test]
    fn pr_review_uses_recorded_tips_after_merge_and_enforces_both_pins() {
        let (_scratch, node, a, b) = fixture(GitHashAlgorithm::Sha256, false);
        let request = node.request_context();
        let a_ref = RefName::try_new(b"refs/heads/main").unwrap();
        let b_ref = RefName::try_new(b"refs/heads/topic").unwrap();
        let actor = PrincipalId::from_bytes([0x73; 16]);
        let command = PullRequestCommand {
            number: PullRequestNumber::FIRST, expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData { source_ref: b_ref.clone(), target_ref: a_ref.clone(),
                source_tip: b, target_tip: a, title: "Review original tips".into(), body: String::new() },
        };
        let session = LoopbackReceiveSession::authenticated(actor, IdempotencyKey::new(b"review-open".to_vec()).unwrap());
        let terminal = node.runtime().block_on(node.admit_pull_request_durable_in(&request, &session, &command, Default::default())).unwrap();
        assert!(matches!(terminal.1.outcome, DecisionOutcome::Committed { .. }));
        let selection = ReviewSelection::PullRequest { number: command.number, expected_version: Some(AggregateVersion::FIRST) };
        let options = ReviewOptions { mode: ComparisonMode::MergeBase, ..ReviewOptions::default() };
        let original = node.runtime().block_on(node.review_source_in(&request, &selection, &RefVisibility::new(), None, &options)).unwrap();
        let prepared = node.runtime().block_on(node.prepare_merge_bundle_in(&request, &a_ref, &b_ref,
            &RefVisibility::new(), &metadata(), Default::default())).unwrap();
        let fgit_forge::preparation::MergePreparation::Clean(plan) = prepared.outcome else { panic!("clean"); };
        let merge = fgit_forge::event::NativeMerge { source_ref: b_ref, source_tip: b,
            target_ref: a_ref, target_tip_before: a, base_tip: plan.base, merge_commit: plan.commit };
        let result = node.runtime().block_on(node.apply_merge_bundle_durable_in(&request, actor, b"review-merge",
            command.number, ExpectedVersion::Exactly(AggregateVersion::FIRST), &merge, &prepared.bundle.unwrap())).unwrap();
        assert!(matches!(result.1.outcome, DecisionOutcome::Committed { .. }));
        assert!(matches!(node.runtime().block_on(node.review_source_in(&request, &selection,
            &RefVisibility::new(), Some(original.source_head), &options)), Err(NodeReviewRefusal::SnapshotMoved)));
        assert!(matches!(node.runtime().block_on(node.review_source_in(&request, &selection,
            &RefVisibility::new(), None, &options)), Err(NodeReviewRefusal::VersionMoved)));
        let selection = ReviewSelection::PullRequest { number: command.number, expected_version: None };
        let merged = node.runtime().block_on(node.review_source_in(&request, &selection, &RefVisibility::new(), None, &options)).unwrap();
        assert_eq!(merged.comparison, original.comparison);
        assert_eq!(merged.pull_request.unwrap().1.get(), 2);
        assert_ne!(merged.source_head, original.source_head);
        node.shutdown().unwrap();
    }
}
