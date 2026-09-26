#![forbid(unsafe_code)]
//! Revalidate one immutable lexical generation against current native source.
//!
//! Repository metadata may advance without changing a branch's Git commit.
//! That does not change its complete path/blob inventory or lexical postings.
//! This explicit profile preserves the index's ORIGINAL provenance and returns
//! the independently authenticated current source separately. It neither
//! rewrites a generation stamp nor relaxes the existing exact-source readers.

use crate::{
    ClosureSelectionSource, NodeRequestContext, NodeWorkspaceRefusal, OneNode,
    PackContextCheckpoint, checkpoint_pack_context,
};
use fgit_forge::source_browse::{SourceBrowseAction, SourceBrowseError, SourceBrowseQuery};
use fgit_graph::GenerationActivation;
use fgit_graph::lexical::{
    IndexError, IndexedLexicalReport, LexicalError, LexicalIndexStore, LexicalNamespace,
    LexicalQuery, LexicalQueryLimits, LexicalReadLimits, LexicalSource,
};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_types::{GitOid, RefName, RepositoryAuthorityHeadId};

pub const PROFILE: &str = "source-lexical-revalidated-v1";

/// Read permission must already cover the whole repository. Terms, path
/// prefixes, source pins and generation checkpoints never grant permission.
/// A continuation must repeat its query, exact current-source pins and original
/// generation; a head change between pages is still a typed refusal.
#[derive(Clone, Debug)]
pub struct RevalidatedIndexRequest<'a> {
    pub reference: &'a RefName,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_commit: Option<GitOid>,
    pub generation: Option<&'a GenerationActivation>,
    pub minimum: Option<&'a GenerationActivation>,
    pub query: &'a LexicalQuery,
    pub after: Option<u64>,
    pub query_limits: LexicalQueryLimits,
    pub read_limits: LexicalReadLimits,
}

impl<'a> RevalidatedIndexRequest<'a> {
    #[must_use]
    pub fn new(reference: &'a RefName, query: &'a LexicalQuery) -> Self {
        Self {
            reference,
            expected_head: None,
            expected_commit: None,
            generation: None,
            minimum: None,
            query,
            after: None,
            query_limits: LexicalQueryLimits::default(),
            read_limits: LexicalReadLimits::default(),
        }
    }
}

/// One checked generation and two explicitly distinct source observations.
/// The source in `index()` is still exactly the one committed by the original
/// generation. `current_source()` is the authority basis used to authorize this
/// invocation and verify the same native commit/tree. It is not a promise of
/// freshness at response time, a retention pin, or a new generation activation.
#[derive(Clone, Debug)]
pub struct RevalidatedIndexReport {
    current_source: LexicalSource,
    index: IndexedLexicalReport,
}

impl RevalidatedIndexReport {
    #[must_use]
    pub const fn current_source(&self) -> &LexicalSource {
        &self.current_source
    }

    #[must_use]
    pub const fn index(&self) -> &IndexedLexicalReport {
        &self.index
    }

    #[must_use]
    pub fn has_distinct_provenance(&self) -> bool {
        self.current_source != self.index.source
    }
}

fn index_error(error: impl Into<IndexError>) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::SourceIndex(Box::new(error.into()))
}

fn live(request: &NodeRequestContext) -> Result<(), NodeWorkspaceRefusal> {
    match checkpoint_pack_context(request.authority()) {
        PackContextCheckpoint::Stopped { budget_exhaustion } => {
            Err(NodeWorkspaceRefusal::Cancelled {
                exhaustion: budget_exhaustion,
            })
        }
        _ => Ok(()),
    }
}

// Equality of a bare tree or repository ID is insufficient. In particular a
// recreated repository, another ref or another native hash domain cannot reuse
// the generation. Both sources have already been verified by their owners.
fn same_native_source(
    indexed: &LexicalSource,
    current: &LexicalSource,
) -> Result<(), NodeWorkspaceRefusal> {
    if indexed.namespace != current.namespace || indexed.reference != current.reference {
        return Err(index_error(IndexError::SourceMismatch));
    }
    if indexed.commit != current.commit || indexed.tree != current.tree {
        return Err(NodeWorkspaceRefusal::SourceIndexStale);
    }
    if indexed.source_head == current.source_head
        && (indexed.source_rcr != current.source_rcr
            || indexed.forge_position_root != current.forge_position_root)
    {
        // Equal head identities cannot legitimately select contradictory roots.
        return Err(index_error(IndexError::SourceMismatch));
    }
    Ok(())
}

impl OneNode {
    /// Query persisted postings for the currently authorized native commit even
    /// when unrelated repository metadata changed since index construction.
    /// This is an explicit trusted-local/independently-authorized transport
    /// boundary, NOT authentication or a grant derived from an old index.
    ///
    /// The current head/visibility are selected first. The existing native
    /// browser then verifies the commit and root tree under those EXACT pins,
    /// before any historical index metadata is read. A concurrent change
    /// between those observations refuses; neither observation is retried.
    /// Both reads share this request's budget and cancellation context.
    ///
    /// Only exact namespace/ref/commit/tree equality permits reuse. The selected
    /// generation, its ancestry/checkpoints, catalogs and visited posting
    /// payloads retain their ordinary commitment/resource checks. No source
    /// blobs are scanned, no generation is built, and nothing is published.
    pub async fn search_source_index_revalidated_local_in(
        &self,
        request: &NodeRequestContext,
        query: RevalidatedIndexRequest<'_>,
    ) -> Result<RevalidatedIndexReport, NodeWorkspaceRefusal> {
        live(request)?;
        query.query_limits.validate().map_err(index_error)?;
        if query.after.is_some()
            && (query.generation.is_none()
                || query.expected_head.is_none()
                || query.expected_commit.is_none())
        {
            return Err(index_error(LexicalError::Invalid(
                "continuation requires exact source and generation",
            )));
        }
        if query
            .expected_commit
            .is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format)
        {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        live(request)?;
        if selected.snapshot().hidden_refs.hides(query.reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let commit = *selected
            .snapshot()
            .refs
            .get(query.reference)
            .ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
        let head = selected.basis().id();
        if query.expected_head.is_some_and(|expected| expected != head) {
            return Err(NodeWorkspaceRefusal::SourceBrowse(Box::new(
                SourceBrowseError::SnapshotMoved,
            )));
        }
        if query.expected_commit.is_some_and(|expected| expected != commit) {
            return Err(NodeWorkspaceRefusal::SourceBrowse(Box::new(
                SourceBrowseError::CommitMoved,
            )));
        }
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr)
            | ClosureSelectionSource::CumulativeHistory { latest: rcr, .. } => rcr,
            ClosureSelectionSource::EmptyGenesis => {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
        };
        let forge_position_root = selected.basis().body().forge_position_root;
        drop(selected);
        let browse = self
            .browse_source_local_in(
                request,
                query.reference,
                &SourceBrowseQuery {
                    path: None,
                    expected_head: Some(head),
                    expected_commit: Some(commit),
                    action: SourceBrowseAction::List { after: None, limit: 1 },
                },
            )
            .await?;
        live(request)?;
        if browse.repository_id != self.repository_id
            || browse.source_head != head
            || browse.source_commit != commit
            || browse.source_rcr != rcr
            || browse.object_id != browse.root_tree
            || browse.path.is_some()
        {
            return Err(index_error(IndexError::SourceMismatch));
        }
        let current_source = LexicalSource {
            namespace: LexicalNamespace {
                tenant: self.tenant_id,
                repository: self.repository_id,
                incarnation: self.repository_incarnation_id(),
                object_format: self.object_format,
            },
            reference: query.reference.clone(),
            source_head: head,
            source_rcr: rcr,
            forge_position_root,
            commit,
            tree: browse.root_tree,
        };
        drop(browse);
        let store = LexicalIndexStore::new(
            &self.authority,
            current_source.namespace,
            query.reference.clone(),
        )
        .map_err(index_error)?;
        let mut request_live = || live(request).is_ok();
        let selected_index = store
            .select_async(
                request.authority(),
                query.generation,
                query.minimum,
                query.read_limits,
                &mut request_live,
            )
            .await
            .map_err(index_error)?;
        same_native_source(selected_index.source(), &current_source)?;
        let index = store
            .search_async(
                request.authority(),
                &selected_index,
                query.query,
                query.after,
                query.read_limits,
                query.query_limits,
                &mut request_live,
            )
            .await
            .map_err(index_error)?;
        live(request)?;
        Ok(RevalidatedIndexReport { current_source, index })
    }
}

#[cfg(test)]
mod tests;
