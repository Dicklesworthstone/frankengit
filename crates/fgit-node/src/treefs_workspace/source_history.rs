//! Authenticated commit history and line provenance over the same private
//! native object owner as source review and merge preparation. Read-only.

use super::{Cell, MergeObjectSource, MergeSourceError, ObjectType, ParseLimits,
    RefVisibility, SelectedSource, VerifiedFabricPackSource};
use fgit_forge::history::{BlameOptions, BlameResult, HistoryError, HistoryLimits,
    HistoryPage, HistorySource, LogOptions, blame, commit_history};
use fgit_types::cell::{CellRefusal, ReadMode, admits_read};
use fgit_types::{GitOid, RefName, RepositoryAuthorityHeadId};
use crate::{AdmissionMaterializationRefusal, NodeRequestContext, OneNode};

#[derive(Debug)]
pub enum NodeHistoryRefusal {
    Cell(CellRefusal),
    Authority(Box<AdmissionMaterializationRefusal>),
    History(Box<HistoryError>),
    SnapshotMoved,
    UnpinnedContinuation,
    /// A hidden ref and a missing ref intentionally have the same response.
    Unavailable,
}
impl std::fmt::Display for NodeHistoryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source history unavailable: {self:?}")
    }
}
impl std::error::Error for NodeHistoryRefusal {}
fn failed(error: HistoryError) -> NodeHistoryRefusal { NodeHistoryRefusal::History(Box::new(error)) }
impl HistorySource for SelectedSource<'_> {
    fn commit_body(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.read(id, Some(ObjectType::Commit)).map(|(_, body)| body)
    }
}

impl OneNode {
    /// Topologically ordered native history from one current, visible ref.
    /// Offset continuations require the first page's exact authority head.
    /// This is a local/ref-authorized boundary, not a remote credential verifier.
    pub async fn read_commit_history_in(
        &self, request: &NodeRequestContext, reference: &RefName, visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>, options: LogOptions,
    ) -> Result<(RepositoryAuthorityHeadId, HistoryPage), NodeHistoryRefusal> {
        options.validate().map_err(failed)?;
        if options.after != 0 && expected_head.is_none() {
            return Err(NodeHistoryRefusal::UnpinnedContinuation);
        }
        self.with_history_source_in(request, reference, visibility, expected_head, options.limits,
            |source, tip| commit_history(source, self.object_format, tip, options)).await
    }

    /// Exact same-path line ancestry, including second and later merge parents.
    /// A line range narrows returned data, never object authority. Missing or
    /// malformed history cannot be reinterpretedted as an attribution boundary.
    pub async fn blame_source_in(
        &self, request: &NodeRequestContext, reference: &RefName, visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>, options: &BlameOptions,
    ) -> Result<(RepositoryAuthorityHeadId, BlameResult), NodeHistoryRefusal> {
        options.validate().map_err(failed)?;
        self.with_history_source_in(request, reference, visibility, expected_head, options.limits,
            |source, tip| blame(source, self.object_format, tip, options)).await
    }

    async fn with_history_source_in<T>(
        &self, request: &NodeRequestContext, reference: &RefName, visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>, limits: HistoryLimits,
        operation: impl FnOnce(&SelectedSource<'_>, GitOid) -> Result<T, HistoryError>,
    ) -> Result<(RepositoryAuthorityHeadId, T), NodeHistoryRefusal> {
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeHistoryRefusal::Cell)?;
        if visibility.hides(reference.as_bytes()) { return Err(NodeHistoryRefusal::Unavailable); }
        let selected = self.materialize_admission_in(request).await
            .map_err(|error| NodeHistoryRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) {
            return Err(NodeHistoryRefusal::SnapshotMoved);
        }
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeHistoryRefusal::Unavailable);
        }
        let tip = *selected.snapshot().refs.get(reference).ok_or(NodeHistoryRefusal::Unavailable)?;
        let exhaustion = Cell::new(None);
        let max_bytes = usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX).min(32 * 1024 * 1024);
        let source = SelectedSource {
            inner: VerifiedFabricPackSource {
                fabric: &self.fabric, object_format: self.object_format, maximum_object_bytes: max_bytes,
                database_context: request.authority(), database_exhaustion: &exhaustion, session_is_live: None,
            },
            selected: selected.selected_closure(),
            limits: ParseLimits { tree_reference_bytes: self.object_format.digest_len(),
                max_tree_entries: limits.max_tree_entries, max_header_lines: limits.max_edges,
                max_object_bytes: max_bytes, ..ParseLimits::default() },
            read_bytes: Cell::new(0), budget_failed: Cell::new(false),
        };
        let answer = operation(&source, tip).map_err(failed)?;
        source.checkpoint().map_err(|error| failed(HistoryError::Source(error)))?;
        Ok((selected.basis().id(), answer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm};

    #[test]
    fn authenticated_history_and_blame_are_read_only_in_both_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let (_scratch, node, target, incoming) = super::super::tests::fixture(format, false);
            let request = node.request_context();
            let reference = RefName::try_new(b"refs/heads/main").unwrap();
            let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
            let (head, first) = node.runtime().block_on(node.read_commit_history_in(&request, &reference,
                &RefVisibility::new(), None, LogOptions { limit: 1, ..LogOptions::default() })).unwrap();
            assert_eq!(head, before.basis().id()); assert_eq!(first.tip, target);
            assert_eq!(first.total_commits, 2); assert_eq!(first.next_after, Some(1));
            assert_eq!(first.commits[0].id, target);
            let (_, last) = node.runtime().block_on(node.read_commit_history_in(&request, &reference,
                &RefVisibility::new(), Some(head), LogOptions { after: 1, ..LogOptions::default() })).unwrap();
            let base = last.commits[0].id; assert_ne!(base, incoming); assert_eq!(last.next_after, None);
            let options = BlameOptions { path: b"text".to_vec(), first_line: 0, end_line: None,
                limits: HistoryLimits::default() };
            let (blame_head, lines) = node.runtime().block_on(node.blame_source_in(&request, &reference,
                &RefVisibility::new(), Some(head), &options)).unwrap();
            assert_eq!(blame_head, head); assert_eq!(lines.content, b"A\nb\nc\nd\ne\n");
            assert_eq!(lines.lines[0].origin_commit, target);
            assert!(lines.lines[1..].iter().all(|line| line.origin_commit == base));
            assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
            node.shutdown().unwrap();
        }
    }

    #[test]
    fn hidden_refs_unpinned_pages_stale_heads_and_resource_limits_refuse() {
        let (_scratch, node, _, _) = super::super::tests::fixture(GitHashAlgorithm::Sha1, false);
        let request = node.request_context(); let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let page = LogOptions { after: 1, ..LogOptions::default() };
        assert!(matches!(node.runtime().block_on(node.read_commit_history_in(&request, &reference,
            &RefVisibility::new(), None, page)), Err(NodeHistoryRefusal::UnpinnedContinuation)));
        let mut hidden = RefVisibility::new();
        hidden.push_rule(b"refs/heads/main", &fgit_wire::WireLimits::default()).unwrap();
        assert!(matches!(node.runtime().block_on(node.read_commit_history_in(&request, &reference,
            &hidden, None, LogOptions::default())), Err(NodeHistoryRefusal::Unavailable)));
        let wrong = RepositoryAuthorityHeadId::from_digest(DigestAlgorithmId::try_new(1).unwrap(),
            CANONICAL_CODEC_VERSION, DigestBytes::try_new(&[123; 32]).unwrap());
        assert!(matches!(node.runtime().block_on(node.read_commit_history_in(&request, &reference,
            &RefVisibility::new(), Some(wrong), LogOptions::default())), Err(NodeHistoryRefusal::SnapshotMoved)));
        let options = BlameOptions { path: b"text".to_vec(), first_line: 0, end_line: None,
            limits: HistoryLimits { max_commits: 1, ..HistoryLimits::default() } };
        assert!(matches!(node.runtime().block_on(node.blame_source_in(&request, &reference,
            &RefVisibility::new(), None, &options)), Err(NodeHistoryRefusal::History(_))));
        node.shutdown().unwrap();
    }
}
