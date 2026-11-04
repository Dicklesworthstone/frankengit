//! Exact current-tip metadata without ancestry or tree-body traversal.

use super::{error, live};
use crate::{
    ClosureSelectionSource, NodeRequestContext, NodeWorkspaceRefusal, OneNode,
    VerifiedFabricPackSource,
};
use fgit_forge::source_browse::{MAX_SOURCE_COMMIT_BYTES, SourceBrowseError, SourceCommitReport};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, parse_commit};
use fgit_pack::{PackError, PackWriteError};
use fgit_treefs::ObjectSourceError;
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use std::cell::Cell;

impl OneNode {
    /// Read the exact commit selected by one current visible ref. This explicit
    /// local-owner boundary requires a remote host to supply its independently
    /// authenticated repository source-read grant and original request context.
    /// Expected identities only compare the current selection; they cannot
    /// select another admitted object, a historical commit or a hidden ref.
    pub async fn read_source_commit_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
    ) -> Result<SourceCommitReport, NodeWorkspaceRefusal> {
        if expected_commit.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format) {
            return Err(error(SourceBrowseError::InvalidRequest(
                "invalid expected commit domain",
            )));
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        live(request)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|cause| NodeWorkspaceRefusal::Authority(Box::new(cause)))?;
        live(request)?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let commit = *selected
            .snapshot()
            .refs
            .get(reference)
            .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let head = selected.basis().id();
        if expected_head.is_some_and(|expected| expected != head) {
            return Err(error(SourceBrowseError::SnapshotMoved));
        }
        if expected_commit.is_some_and(|expected| expected != commit) {
            return Err(error(SourceBrowseError::CommitMoved));
        }
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr)
            | ClosureSelectionSource::CumulativeHistory { latest: rcr, .. }
            | ClosureSelectionSource::CapsuleCheckpoint {
                latest: Some(rcr), ..
            } => rcr,
            ClosureSelectionSource::EmptyGenesis
            | ClosureSelectionSource::CapsuleCheckpoint { latest: None, .. } => {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
        };
        if !selected
            .selected_closure()
            .closure()
            .objects()
            .contains(&commit)
        {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let exhaustion = Cell::new(None);
        let source = VerifiedFabricPackSource {
            fabric: &self.fabric,
            object_format: self.object_format,
            maximum_object_bytes: MAX_SOURCE_COMMIT_BYTES
                .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)),
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: None,
        };
        // The verified source bounds the complete payload BEFORE allocating it.
        // No root tree or parent body is needed to disclose this selected tip.
        let read = source.read_object(&commit);
        if !request.is_live() {
            return Err(NodeWorkspaceRefusal::Cancelled {
                exhaustion: exhaustion.get(),
            });
        }
        let (kind, body) = read.map_err(|cause| match cause {
            PackWriteError::Pack(PackError::ObjectSizeLimit { .. }) => {
                error(SourceBrowseError::Budget("current commit bytes"))
            }
            PackWriteError::Pack(PackError::DeadlineExceeded) => NodeWorkspaceRefusal::Cancelled {
                exhaustion: exhaustion.get(),
            },
            _ => NodeWorkspaceRefusal::Object(ObjectSourceError::Refused {
                reason: cause.to_string(),
            }),
        })?;
        if kind != ObjectType::Commit {
            return Err(NodeWorkspaceRefusal::CommitRequired);
        }
        let (tree, parents) = commit_metadata(self.object_format, &body)?;
        live(request)?;
        Ok(SourceCommitReport {
            repository_id: self.repository_id(),
            source_head: head,
            source_rcr: rcr,
            source_commit: commit,
            root_tree: tree,
            parents,
            body,
        })
    }
}

fn commit_metadata(
    format: GitHashAlgorithm,
    body: &[u8],
) -> Result<(GitOid, Vec<GitOid>), NodeWorkspaceRefusal> {
    if body.len() > MAX_SOURCE_COMMIT_BYTES {
        return Err(error(SourceBrowseError::Budget("current commit bytes")));
    }
    let parsed = parse_commit(
        body,
        AcceptanceProfile::GitCompatibleImport,
        &ParseLimits {
            max_object_bytes: MAX_SOURCE_COMMIT_BYTES,
            tree_reference_bytes: format.digest_len(),
            ..ParseLimits::default()
        },
    )
    .map_err(|_| NodeWorkspaceRefusal::CommitRequired)?;
    // Import parsing preserves bytes, including non-UTF-8 messages and opaque
    // signature headers. It does not itself require unambiguous native edges.
    let mut trees = parsed
        .headers()
        .iter()
        .filter(|header| header.name == b"tree");
    let tree = trees.next().ok_or(NodeWorkspaceRefusal::CommitRequired)?;
    if trees.next().is_some() || !tree.continuations.is_empty() {
        return Err(NodeWorkspaceRefusal::CommitRequired);
    }
    let oid = |raw: &[u8]| {
        std::str::from_utf8(raw)
            .ok()
            .and_then(|text| GitOid::from_hex(format, &text.to_ascii_lowercase()).ok())
            .filter(|id| !id.is_zero())
            .ok_or(NodeWorkspaceRefusal::CommitRequired)
    };
    let tree = oid(&tree.value)?;
    let mut parents = Vec::new();
    for header in parsed
        .headers()
        .iter()
        .filter(|header| header.name == b"parent")
    {
        if !header.continuations.is_empty() {
            return Err(NodeWorkspaceRefusal::CommitRequired);
        }
        parents.push(oid(&header.value)?);
    }
    Ok((tree, parents))
}

#[cfg(test)]
mod tests;
