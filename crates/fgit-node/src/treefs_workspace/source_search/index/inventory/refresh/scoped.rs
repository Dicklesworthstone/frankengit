//! Refresh the exact scoped generation from authenticated native TreeFS.
//! Reuse, discovery and payload publication stay on their existing paths;
//! coverage is never inferred from query hits or promoted to whole-tree truth.
use super::*;
use fgit_graph::lexical::scoped::{LexicalScope, ScopedLexicalIndexStore};

impl OneNode {
    /// Refresh every regular file in the explicit persistent coverage, avoiding
    /// reads and tokenization for unchanged raw-path/native-blob pairs. Trusted local
    /// operator API, never an HTTP read capability or an automatic query effect.
    ///
    /// `predecessor` must name the current index exactly. Source is authorized
    /// before index disclosure, then pinned through the complete tree selection.
    /// Every previous segment verifies before reuse, every new path comes from
    /// TreeFS. Deleted and out-of-scope renamed rows leave the successor manifest.
    /// Newly covered paths must supply native bytes, even for a previously seen blob.
    /// A concurrent writer cannot refresh either source/index precondition.
    ///
    /// The receipt names the source selected for the build, which may become
    /// stale while it runs. Publication ambiguity retains the original candidate;
    /// no post-confirmation cancellation probe converts success into an error.
    #[expect(
        clippy::too_many_arguments,
        reason = "source pins, required index predecessor and independent build/read budgets are separate contracts"
    )]
    pub async fn refresh_scoped_source_index_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        scope: &LexicalScope,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        predecessor: GraphGenerationId,
        limits: SearchLimits,
        read_limits: LexicalReadLimits,
    ) -> Result<(LexicalSource, GenerationActivation, LexicalRefreshStats), NodeWorkspaceRefusal>
    {
        self.refresh_scoped_source_index_guarded_local_in(
            request,
            reference,
            scope,
            expected_head,
            expected_commit,
            predecessor,
            limits,
            read_limits,
            &mut |_| Ok(()),
        )
        .await
    }

    /// Refresh with the same pre-staging write-ahead barrier as
    /// `build_scoped_source_index_guarded_local_in`. Every old segment and the complete
    /// new inventory are checked before the original candidate is handed out.
    /// A failed barrier stages nothing; after it succeeds, only recovery can
    /// determine publication. Existing explicit-predecessor APIs remain intact.
    #[expect(
        clippy::too_many_arguments,
        reason = "write-ahead barrier, source pins, predecessor and resource budgets are independent"
    )]
    pub async fn refresh_scoped_source_index_guarded_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        scope: &LexicalScope,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        predecessor: GraphGenerationId,
        limits: SearchLimits,
        read_limits: LexicalReadLimits,
        before_publish: &mut (impl FnMut(GraphGenerationId) -> Result<(), NodeWorkspaceRefusal> + Send),
    ) -> Result<(LexicalSource, GenerationActivation, LexicalRefreshStats), NodeWorkspaceRefusal>
    {
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
                    SourceBrowseError::SnapshotMoved,
                )));
            }
            if expected_commit.is_some_and(|expected| expected != commit) {
                return Err(NodeWorkspaceRefusal::SourceBrowse(Box::new(
                    SourceBrowseError::CommitMoved,
                )));
            }
            (head, commit)
        };
        let store = ScopedLexicalIndexStore::new(
            &self.authority,
            self.lexical_namespace(),
            reference.clone(),
            scope.clone(),
        )
        .map_err(index_error)?;
        let mut request_live = || workspace_request_live(request);
        let previous = store
            .select_async(
                request.authority(),
                None,
                None,
                read_limits,
                &mut request_live,
            )
            .await
            .map_err(index_error)?;
        if previous.activation().generation_id != predecessor {
            return Err(index_error(GenerationAuthorityError::PredecessorMismatch {
                expected: Box::new(previous.activation().generation_id),
                supplied: Some(Box::new(predecessor)),
            }));
        }
        let reuse = store
            .load_refresh_base_async(
                request.authority(),
                &previous,
                read_limits,
                &mut request_live,
            )
            .await
            .map_err(index_error)?;
        drop(previous);
        let query = Request {
            scope: SourceQuery::new(b"index", SearchCase::Exact, reuse.scope().prefixes())
                .map_err(search_error)?,
            reuse: Reuse::Scoped(&reuse),
        };
        let (head, forge_position_root, inventory) = match self.object_format {
            Format::Sha1 => {
                self.select_source_local_format::<Sha1, _>(
                    request,
                    reference,
                    Some(source_head),
                    Some(source_commit),
                    &query,
                    limits,
                )
                .await?
            }
            Format::Sha256 => {
                self.select_source_local_format::<Sha256, _>(
                    request,
                    reference,
                    Some(source_head),
                    Some(source_commit),
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
        let rows: Vec<_> = inventory
            .rows
            .iter()
            .map(|row| RefreshDocument {
                path: &row.path,
                blob: row.blob,
                content: row.bytes.as_deref(),
            })
            .collect();
        let (prepared, stats) = reuse
            .prepare(
                source.clone(),
                &rows,
                inventory.source.non_regular_entries,
                &mut request_live,
            )
            .map_err(index_error)?;
        if stats.rebuilt_documents != inventory.source.files_read
            || stats.rebuilt_source_bytes != inventory.source.bytes_read
            || stats.rebuilt_documents + stats.reused_documents != inventory.source.files_selected
        {
            return Err(index_error(LexicalError::Invalid(
                "native scoped refresh accounting",
            )));
        }
        drop(rows);
        drop(inventory);
        drop(query);
        drop(reuse); // No old posting buffers or fresh source buffers across staging.
        let candidate = store
            .candidate_id(&prepared, Some(predecessor))
            .map_err(index_error)?;
        live(request)?;
        before_publish(candidate)?; // Checked original identity, before all successor puts.
        let activation = store
            .publish_async(
                request.authority(),
                &prepared,
                Some(predecessor),
                &mut request_live,
            )
            .await
            .map_err(|error| NodeWorkspaceRefusal::SourceIndexPublication {
                candidate,
                error: Box::new(error),
            })?;
        Ok((source, activation, stats))
    }
}
