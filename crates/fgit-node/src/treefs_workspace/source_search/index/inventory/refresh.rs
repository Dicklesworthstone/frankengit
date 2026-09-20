//! Native delta intake: fully enumerate the new tree, read only changed blobs,
//! and reuse checked postings for exact prior path/blob pairs. Neither the
//! previous index nor a caller supplies the new tree's membership or grants.
use super::*;
use super::super::{index_error, live};
use super::super::super::{search_error, workspace_request_live};
use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode};
use fgit_crypto::{Sha1, Sha256};
use fgit_forge::source_browse::SourceBrowseError;
use fgit_forge::source_search::SearchCase;
use fgit_graph::{GenerationActivation, GenerationAuthorityError, GraphGenerationId};
use fgit_graph::lexical::{LexicalError, LexicalIndexStore, LexicalReadLimits,
    LexicalRefreshStats, LexicalReuse, LexicalSource, RefreshDocument};
use fgit_types::{RefName, RepositoryAuthorityHeadId};
use fgit_types::cell::{ReadMode, admits_read, admits_staging_intake};

struct Row { path: Vec<u8>, blob: GitOid, bytes: Option<Vec<u8>> }
struct Inventory { source: SourceSearchReport, rows: Vec<Row> }
struct Request<'a> { scope: SourceQuery, reuse: &'a LexicalReuse }

impl LocalSearch for Request<'_> {
    type Report = Inventory;
    fn scope(&self) -> &SourceQuery { &self.scope }
    fn empty(&self, source: SourceSearchReport) -> Inventory {
        Inventory { source, rows: Vec::new() }
    }
    fn run<A: GitHashAlgorithm, S: ObjectSource<A>>(&self,
        base: &BaseView<A>, source: &S, capability: &mut TreeCapability, now: u64,
        limits: SearchLimits, cancelled: &dyn Fn() -> bool,
    ) -> Result<Inventory, SearchError> {
        limits.validate()?;
        check(cancelled)?;
        capability.authorize_root(now).map_err(SearchError::Capability)?;
        // Shared full-tree walker, including file mode, scope, depth, path,
        // entry and symlink/gitlink handling. A match limit is not an inventory limit.
        let mut discovery = Discovery { files: BTreeMap::new(), entries: 0, path_bytes: 0, excluded: 0 };
        discover(base, source, capability, now, limits, cancelled, None, 0, &mut discovery)?;
        let mut result = self.empty(SourceSearchReport {
            repository: base.repository_id(), source_rcr: base.base_rcr_id(),
            source_commit: native::<A>(base.base_commit_oid())?, source_tree: native::<A>(base.base_tree_oid())?,
            matches: Vec::new(), completion: SearchCompletion::Complete,
            files_selected: discovery.files.len(), files_read: 0, bytes_read: 0,
            bytes_searched: 0, non_regular_entries: discovery.excluded,
        });
        let mut corpus_bytes = 0usize;
        for (path, oid) in discovery.files {
            check(cancelled)?;
            // Reuse never bypasses the independently selected path grant.
            let grant = capability.authorize_read(&path, now).map_err(SearchError::Capability)?;
            let blob = native::<A>(&oid)?;
            let (bytes, length) = if let Some(length) = self.reuse.document_bytes(path.as_bytes(), blob) {
                (None, length)
            } else {
                let body = base.read_object(source, &oid, GitObjectKind::Blob, &grant)
                    .map_err(|error| SearchError::Source(Box::new(error)))?;
                check(cancelled)?;
                capability.charge_fetch(body.len() as u64).map_err(SearchError::Capability)?;
                result.source.files_read += 1;
                result.source.bytes_read = result.source.bytes_read.checked_add(body.len())
                    .filter(|n| *n <= limits.max_total_bytes).ok_or(SearchError::Budget("index source bytes"))?;
                let length = body.len();
                (Some(body), length)
            };
            // Source-size ceilings include reused rows, even though fetch
            // counters and capability fetch charges include only actual I/O.
            if length > limits.max_file_bytes { return Err(SearchError::Budget("index file bytes")); }
            corpus_bytes = corpus_bytes.checked_add(length).filter(|n| *n <= limits.max_total_bytes)
                .ok_or(SearchError::Budget("index source bytes"))?;
            result.rows.push(Row { path: path.as_bytes().to_vec(), blob, bytes });
        }
        check(cancelled)?;
        result.rows.sort_unstable_by(|a, b| a.path.cmp(&b.path));
        check(cancelled)?;
        Ok(result)
    }
}

impl OneNode {
    /// Refresh a complete persistent index while avoiding source reads and
    /// tokenization for unchanged raw-path/native-blob pairs. Trusted local
    /// operator API, never an HTTP read capability or an automatic query effect.
    ///
    /// `predecessor` must name the current index exactly. Source is authorized
    /// before index disclosure, then pinned through the complete tree selection.
    /// Every previous segment verifies before reuse, every new path comes from
    /// TreeFS, and deleted rows are absent from the complete successor manifest.
    /// A concurrent writer cannot refresh either source/index precondition.
    ///
    /// The receipt names the source selected for the build, which may become
    /// stale while it runs. Publication ambiguity retains the original candidate;
    /// no post-confirmation cancellation probe converts success into an error.
    #[expect(clippy::too_many_arguments, reason = "source pins, required index predecessor and independent build/read budgets are separate contracts")]
    pub async fn refresh_source_index_local_in(
        &self, request: &NodeRequestContext, reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>, expected_commit: Option<GitOid>,
        predecessor: GraphGenerationId, limits: SearchLimits, read_limits: LexicalReadLimits,
    ) -> Result<(LexicalSource, GenerationActivation, LexicalRefreshStats), NodeWorkspaceRefusal> {
        self.refresh_source_index_guarded_local_in(request, reference, expected_head,
            expected_commit, predecessor, limits, read_limits, &mut |_| Ok(())).await
    }

    /// Refresh with the same pre-staging write-ahead barrier as
    /// `build_source_index_guarded_local_in`. Every old segment and the complete
    /// new inventory are checked before the original candidate is handed out.
    /// A failed barrier stages nothing; after it succeeds, only recovery can
    /// determine publication. Existing explicit-predecessor APIs remain intact.
    #[expect(clippy::too_many_arguments, reason = "write-ahead barrier, source pins, predecessor and resource budgets are independent")]
    pub async fn refresh_source_index_guarded_local_in(
        &self, request: &NodeRequestContext, reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>, expected_commit: Option<GitOid>,
        predecessor: GraphGenerationId, limits: SearchLimits, read_limits: LexicalReadLimits,
        before_publish: &mut (impl FnMut(GraphGenerationId) -> Result<(), NodeWorkspaceRefusal> + Send),
    ) -> Result<(LexicalSource, GenerationActivation, LexicalRefreshStats), NodeWorkspaceRefusal> {
        limits.validate().map_err(search_error)?;
        live(request)?;
        admits_staging_intake(self.cell_state()).map_err(NodeWorkspaceRefusal::Cell)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        if expected_commit.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format) {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        // Authorize before reading old paths, postings or corpus counters. The
        // subsequent native selector MUST use these exact pins, not reread and
        // silently accept a different head after loading the old index.
        let (source_head, source_commit) = {
            let selected = self.materialize_admission_in(request).await
                .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
            live(request)?;
            if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
            let commit = *selected.snapshot().refs.get(reference).ok_or(NodeWorkspaceRefusal::RefUnavailable)?;
            let head = selected.basis().id();
            if expected_head.is_some_and(|expected| expected != head) {
                return Err(NodeWorkspaceRefusal::SourceBrowse(Box::new(SourceBrowseError::SnapshotMoved)));
            }
            if expected_commit.is_some_and(|expected| expected != commit) {
                return Err(NodeWorkspaceRefusal::SourceBrowse(Box::new(SourceBrowseError::CommitMoved)));
            }
            (head, commit)
        };
        let store = LexicalIndexStore::new(&self.authority, self.lexical_namespace(), reference.clone()).map_err(index_error)?;
        let mut request_live = || workspace_request_live(request);
        let previous = store.select_async(request.authority(), None, None, read_limits, &mut request_live)
            .await.map_err(index_error)?;
        if previous.activation().generation_id != predecessor {
            return Err(index_error(GenerationAuthorityError::PredecessorMismatch {
                expected: Box::new(previous.activation().generation_id), supplied: Some(Box::new(predecessor)),
            }));
        }
        let reuse = store.load_refresh_base_async(request.authority(), &previous, read_limits, &mut request_live)
            .await.map_err(index_error)?;
        drop(previous);
        let query = Request { scope: SourceQuery::new(b"index", SearchCase::Exact, &[]).map_err(search_error)?, reuse: &reuse };
        let (head, forge_position_root, inventory) = match self.object_format {
            Format::Sha1 => self.select_source_local_format::<Sha1, _>(request, reference,
                Some(source_head), Some(source_commit), &query, limits).await?,
            Format::Sha256 => self.select_source_local_format::<Sha256, _>(request, reference,
                Some(source_head), Some(source_commit), &query, limits).await?,
        };
        live(request)?;
        let source = LexicalSource { namespace: self.lexical_namespace(), reference: reference.clone(),
            source_head: head, source_rcr: inventory.source.source_rcr, forge_position_root,
            commit: inventory.source.source_commit, tree: inventory.source.source_tree };
        let rows: Vec<_> = inventory.rows.iter().map(|row| RefreshDocument {
            path: &row.path, blob: row.blob, content: row.bytes.as_deref(),
        }).collect();
        let (prepared, stats) = reuse.prepare(source.clone(), &rows, inventory.source.non_regular_entries, &mut request_live)
            .map_err(index_error)?;
        if stats.rebuilt_documents != inventory.source.files_read || stats.rebuilt_source_bytes != inventory.source.bytes_read
            || stats.rebuilt_documents + stats.reused_documents != inventory.source.files_selected
        { return Err(index_error(LexicalError::Invalid("native refresh accounting"))); }
        drop(rows);
        drop(inventory);
        drop(query);
        drop(reuse); // No old posting buffers or fresh source buffers across staging.
        let candidate = store.candidate_id(&prepared, Some(predecessor)).map_err(index_error)?;
        live(request)?;
        before_publish(candidate)?; // Checked original identity, before all successor puts.
        let activation = store.publish_async(request.authority(), &prepared, Some(predecessor), &mut request_live).await
            .map_err(|error| NodeWorkspaceRefusal::SourceIndexPublication { candidate, error: Box::new(error) })?;
        Ok((source, activation, stats))
    }
}
