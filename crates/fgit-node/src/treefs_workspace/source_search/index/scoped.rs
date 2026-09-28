//! Native path-scoped lexical indexing. Whole-repository index entrypoints
//! remain unchanged; these methods require explicit immutable coverage and
//! use separately identified generation heads. Caller must already have
//! trusted-local repository authority. Coverage never grants source access.
use super::*;
use fgit_graph::lexical::scoped::{
    LexicalScope, PreparedScopedLexicalIndex, ScopedLexicalIndexStore, ScopedLexicalReport,
};

impl OneNode {
    /// Build EVERY regular file in the explicit scope, not the entire tree.
    /// Separate scope identity prevents replacement of an unscoped index.
    /// None requires an uninitialized scoped head; a rebuild requires its exact
    /// predecessor. Source pins and finite build budgets retain their meaning.
    #[expect(clippy::too_many_arguments, reason = "explicit coverage, source pins and predecessor")]
    pub async fn build_scoped_source_index_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        scope: &LexicalScope,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        predecessor: Option<GraphGenerationId>,
        limits: SearchLimits,
    ) -> Result<(LexicalSource, GenerationActivation), NodeWorkspaceRefusal> {
        self.build_scoped_source_index_guarded_local_in(
            request,
            reference,
            scope,
            expected_head,
            expected_commit,
            predecessor,
            limits,
            &mut |_| Ok(()),
        )
        .await
    }

    /// Build with a caller-owned write-ahead publication barrier. After complete
    /// native preparation, call `before_publish` exactly once with the original
    /// candidate BEFORE this invocation stages any index payload or attempts a
    /// root write. An error from the barrier prevents those effects entirely.
    ///
    /// The callback owns durable recording and must finish it before returning
    /// Ok. It cannot change source, predecessor, or candidate. This synchronous
    /// local callback must be bounded; it is not a remote authorization grant.
    /// After Ok, interruptions require original-candidate recovery, even when
    /// cancellation or a backend refusal happens before the root write.
    #[expect(
        clippy::too_many_arguments,
        reason = "write-ahead barrier is independent of source pins and build budgets"
    )]
    pub async fn build_scoped_source_index_guarded_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        scope: &LexicalScope,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        predecessor: Option<GraphGenerationId>,
        limits: SearchLimits,
        before_publish: &mut (impl FnMut(GraphGenerationId) -> Result<(), NodeWorkspaceRefusal> + Send),
    ) -> Result<(LexicalSource, GenerationActivation), NodeWorkspaceRefusal> {
        live(request)?;
        fgit_types::cell::admits_staging_intake(self.cell_state())
            .map_err(NodeWorkspaceRefusal::Cell)?;
        if expected_commit.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format) {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        // SourceQuery supplies explicit inventory coverage, not a literal scan.
        // No literal matcher runs and no search result limit truncates intake.
        let query = InventoryRequest(
            SourceQuery::new(b"index", SearchCase::Exact, scope.prefixes()).map_err(search_error)?,
        );
        let (head, forge_position_root, inventory) = match self.object_format {
            Format::Sha1 => {
                self.select_source_local_format::<Sha1, _>(
                    request,
                    reference,
                    expected_head,
                    expected_commit,
                    &query,
                    limits,
                )
                .await?
            }
            Format::Sha256 => {
                self.select_source_local_format::<Sha256, _>(
                    request,
                    reference,
                    expected_head,
                    expected_commit,
                    &query,
                    limits,
                )
                .await?
            }
        };
        live(request)?;
        let source = LexicalSource {
            namespace: self.lexical_namespace(),
            reference: reference.clone(),
            source_head: head,
            source_rcr: inventory.source.source_rcr,
            forge_position_root,
            commit: inventory.source.source_commit,
            tree: inventory.source.source_tree,
        };
        let mut request_live = || workspace_request_live(request);
        let parts = segments(source.namespace, &inventory.documents, &mut request_live)
            .map_err(index_error)?;
        let excluded = inventory.source.non_regular_entries;
        drop(inventory); // Source file buffers are not retained during async staging.
        let prepared =
            PreparedScopedLexicalIndex::new(source.clone(), scope.clone(), parts, excluded, &mut request_live)
                .map_err(index_error)?;
        let store = ScopedLexicalIndexStore::new(&self.authority, source.namespace, reference.clone(), scope.clone())
            .map_err(index_error)?;
        let candidate = store
            .candidate_id(&prepared, predecessor)
            .map_err(index_error)?;
        live(request)?;
        before_publish(candidate)?; // No index staging has occurred in this invocation.
        let activation = store
            .publish_async(
                request.authority(),
                &prepared,
                predecessor,
                &mut request_live,
            )
            .await
            .map_err(|error| NodeWorkspaceRefusal::SourceIndexPublication {
                candidate,
                error: Box::new(error),
            })?;
        // No await or cancellation probe after confirmed generation publication.
        Ok((source, activation))
    }

    /// Query only the explicit persisted coverage after selecting current source
    /// and visibility. An old generation is usable only when it describes that
    /// same exact source head/commit/RCR/forge position. No rebuild, old-source
    /// fallback, substring scan, arbitrary object read or repository write.
    #[expect(
        clippy::too_many_arguments,
        reason = "source pins, index pins, pagination and independent resource budgets are distinct contracts"
    )]
    pub async fn search_scoped_source_index_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        scope: &LexicalScope,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        generation: Option<&GenerationActivation>,
        minimum: Option<&GenerationActivation>,
        query: &LexicalQuery,
        after: Option<u64>,
        query_limits: LexicalQueryLimits,
        read_limits: LexicalReadLimits,
    ) -> Result<ScopedLexicalReport, NodeWorkspaceRefusal> {
        live(request)?;
        // A bare document ID is not a stable continuation without its original
        // source and index. The query is repeated explicitly, not changed here.
        if after.is_some()
            && (generation.is_none() || expected_head.is_none() || expected_commit.is_none())
        {
            return Err(index_error(LexicalError::Invalid(
                "continuation requires exact source and generation",
            )));
        }
        if expected_commit.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format) {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
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
            return Err(NodeWorkspaceRefusal::SourceBrowse(Box::new(
                fgit_forge::source_browse::SourceBrowseError::SnapshotMoved,
            )));
        }
        if expected_commit.is_some_and(|expected| expected != commit) {
            return Err(NodeWorkspaceRefusal::SourceBrowse(Box::new(
                fgit_forge::source_browse::SourceBrowseError::CommitMoved,
            )));
        }
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr)
            | ClosureSelectionSource::CumulativeHistory { latest: rcr, .. } => rcr,
            ClosureSelectionSource::EmptyGenesis => {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
        };
        let store =
            ScopedLexicalIndexStore::new(&self.authority, self.lexical_namespace(), reference.clone(), scope.clone())
                .map_err(index_error)?;
        let mut request_live = || workspace_request_live(request);
        let index = store
            .select_async(
                request.authority(),
                generation,
                minimum,
                read_limits,
                &mut request_live,
            )
            .await
            .map_err(index_error)?;
        let source = index.source();
        if source.source_head != head
            || source.commit != commit
            || source.source_rcr != rcr
            || source.forge_position_root != selected.basis().body().forge_position_root
        {
            return Err(NodeWorkspaceRefusal::SourceIndexStale);
        }
        let report = store
            .search_async(
                request.authority(),
                &index,
                query,
                after,
                read_limits,
                query_limits,
                &mut request_live,
            )
            .await
            .map_err(index_error)?;
        live(request)?;
        Ok(report)
    }

    /// Observe an interrupted SCOPED activation, without retrying the
    /// build or creating a repository transaction. Current ref visibility is
    /// checked before any historical index metadata can be returned.
    pub async fn recover_scoped_source_index_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        scope: &LexicalScope,
        candidate: GraphGenerationId,
        minimum: Option<&GenerationActivation>,
        limits: GenerationReadLimits,
    ) -> Result<GenerationRecovery, NodeWorkspaceRefusal> {
        live(request)?;
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        live(request)?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes())
            || !selected.snapshot().refs.contains_key(reference)
        {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        let store =
            ScopedLexicalIndexStore::new(&self.authority, self.lexical_namespace(), reference.clone(), scope.clone())
                .map_err(index_error)?;
        store
            .recover_async(request.authority(), candidate, minimum, limits, &mut || {
                workspace_request_live(request)
            })
            .await
            .map_err(index_error)
    }
}
