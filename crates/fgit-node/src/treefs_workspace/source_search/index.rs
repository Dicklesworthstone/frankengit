//! Native lexical indexing of one authority-selected source tree. Only the
//! trusted local build entrypoint writes; queries and recovery never build.
mod inventory;
use super::*;
use fgit_forge::source_search::SearchCase;
use fgit_graph::lexical::{
    IndexError, IndexedLexicalReport, LexicalError, LexicalIndexStore, LexicalNamespace,
    LexicalQuery, LexicalQueryLimits, LexicalReadLimits, LexicalSegment, LexicalSource,
    MAX_DOCUMENTS, PreparedLexicalIndex, SourceDocument,
};
use fgit_graph::{
    GenerationActivation, GenerationReadLimits, GenerationRecovery, GraphGenerationId,
};
use inventory::{Document, InventoryRequest};

fn index_error(error: impl Into<IndexError>) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::SourceIndex(Box::new(error.into()))
}
fn live(request: &NodeRequestContext) -> Result<(), NodeWorkspaceRefusal> {
    if workspace_request_live(request) {
        Ok(())
    } else {
        Err(search_error(SearchError::Cancelled))
    }
}

/// Split only segment-capacity failures, never malformed content or missing
/// source. Tree bytes are read once. Bisection is deterministic; its additional
/// hashing/tokenization is independently bounded and cancellable.
fn segments(
    namespace: LexicalNamespace,
    documents: &[Document],
    request_live: &mut impl FnMut() -> bool,
) -> Result<Vec<LexicalSegment>, IndexError> {
    if !request_live() {
        return Err(LexicalError::Cancelled.into());
    }
    let mut output = Vec::new();
    let mut attempts = 0usize;
    let mut rescanned = 0usize;
    let mut encoded_bytes = 0usize;
    for (group, chunk) in documents.chunks(MAX_DOCUMENTS).enumerate() {
        let first = group * MAX_DOCUMENTS;
        let mut pending = vec![(first, chunk)];
        while let Some((offset, inputs)) = pending.pop() {
            if !request_live() {
                return Err(LexicalError::Cancelled.into());
            }
            attempts += 1;
            if attempts > 256 {
                return Err(LexicalError::Limit("segment build attempts").into());
            }
            let bytes: usize = inputs
                .iter()
                .map(|input| input.bytes.len() + input.path.len())
                .sum();
            rescanned = rescanned
                .checked_add(bytes)
                .filter(|n| *n <= 256 * 1024 * 1024)
                .ok_or(LexicalError::Limit("segment build byte work"))?;
            let built = LexicalSegment::build(
                namespace,
                offset as u64 + 1,
                inputs.iter().map(|input| SourceDocument {
                    path: &input.path,
                    blob: input.blob,
                    content: &input.bytes,
                }),
                request_live,
            );
            match built {
                Ok(segment) => {
                    if output.len() == 128 {
                        return Err(LexicalError::Limit("index segments").into());
                    }
                    encoded_bytes = encoded_bytes
                        .checked_add(segment.encode(request_live)?.len())
                        .filter(|n| *n <= 32 * 1024 * 1024)
                        .ok_or(LexicalError::Limit("index bytes"))?;
                    output.push(segment);
                }
                Err(LexicalError::Limit(
                    "documents" | "dictionary terms" | "postings" | "segment bytes",
                )) if inputs.len() > 1 => {
                    let middle = inputs.len() / 2;
                    pending.push((offset + middle, &inputs[middle..]));
                    pending.push((offset, &inputs[..middle]));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(output)
}

impl OneNode {
    const fn lexical_namespace(&self) -> LexicalNamespace {
        LexicalNamespace {
            tenant: self.tenant_id,
            repository: self.repository_id,
            incarnation: self.repository_incarnation_id(),
            object_format: self.object_format,
        }
    }

    /// Build and activate an index of EVERY regular file in one visible ref's
    /// verified tree. Trusted-local operator API: not a remote read permission.
    /// No caller-supplied documents, source stamps, root keys or payloads enter.
    /// The predecessor is explicit; None requires an uninitialized index.
    ///
    /// Source can advance while this derived build runs. The receipt names the
    /// original source, never claims freshness at completion, and queries refuse
    /// an index not matching their own current source selection. A failed root
    /// publication preserves its candidate ID for read-only recovery.
    pub async fn build_source_index_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        predecessor: Option<GraphGenerationId>,
        limits: SearchLimits,
    ) -> Result<(LexicalSource, GenerationActivation), NodeWorkspaceRefusal> {
        self.build_source_index_guarded_local_in(
            request,
            reference,
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
    pub async fn build_source_index_guarded_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
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
        // SourceQuery is used only for its shared top-level scope selector.
        // No literal matcher runs and no search result limit truncates intake.
        let query = InventoryRequest(
            SourceQuery::new(b"index", SearchCase::Exact, &[]).map_err(search_error)?,
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
            PreparedLexicalIndex::new(source.clone(), parts, excluded, &mut request_live)
                .map_err(index_error)?;
        let store = LexicalIndexStore::new(&self.authority, source.namespace, reference.clone())
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

    /// Query a persisted index only after selecting canonical current source
    /// and visibility. An old generation is usable only when it describes that
    /// same exact source head/commit/RCR/forge position. No rebuild, old-source
    /// fallback, substring scan, arbitrary object read or repository write.
    #[expect(
        clippy::too_many_arguments,
        reason = "source pins, index pins, pagination and independent resource budgets are distinct contracts"
    )]
    pub async fn search_source_index_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        expected_head: Option<RepositoryAuthorityHeadId>,
        expected_commit: Option<GitOid>,
        generation: Option<&GenerationActivation>,
        minimum: Option<&GenerationActivation>,
        query: &LexicalQuery,
        after: Option<u64>,
        query_limits: LexicalQueryLimits,
        read_limits: LexicalReadLimits,
    ) -> Result<IndexedLexicalReport, NodeWorkspaceRefusal> {
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
            LexicalIndexStore::new(&self.authority, self.lexical_namespace(), reference.clone())
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

    /// Observe an interrupted derived-index activation, without retrying the
    /// build or creating a repository transaction. Current ref visibility is
    /// checked before any historical index metadata can be returned.
    pub async fn recover_source_index_local_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
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
            LexicalIndexStore::new(&self.authority, self.lexical_namespace(), reference.clone())
                .map_err(index_error)?;
        store
            .recover_async(request.authority(), candidate, minimum, limits, &mut || {
                workspace_request_live(request)
            })
            .await
            .map_err(index_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_crypto::{GitObjectKind, git_object_id};
    fn namespace() -> LexicalNamespace {
        LexicalNamespace {
            tenant: fgit_types::TenantId::from_bytes([1; 16]),
            repository: fgit_types::RepositoryId::from_bytes([2; 16]),
            incarnation: fgit_types::RepositoryIncarnationId::from_bytes([3; 16]),
            object_format: fgit_types::GitHashAlgorithm::Sha256,
        }
    }
    fn document(path: &[u8], bytes: Vec<u8>) -> Document {
        Document {
            path: path.to_vec(),
            blob: git_object_id(namespace().object_format, GitObjectKind::Blob, &bytes),
            bytes,
        }
    }
    #[test]
    fn partitioning_preserves_every_document_and_absolute_id_under_dictionary_pressure() {
        let documents: Vec<_> = (0..3)
            .map(|n| {
                document(
                    format!("file{n}").as_bytes(),
                    (0..20_000)
                        .map(|i| format!("word{:05} ", n * 20_000 + i))
                        .collect::<String>()
                        .into_bytes(),
                )
            })
            .collect();
        let parts = segments(namespace(), &documents, &mut || true).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            parts
                .iter()
                .flat_map(|p| p.documents())
                .map(|d| d.id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        for (part, original) in parts.iter().zip(&documents) {
            assert_eq!(part.documents()[0].blob, original.blob);
            assert_eq!(part.documents()[0].path, original.path);
        }
        let again = segments(namespace(), &documents, &mut || true).unwrap();
        for (left, right) in parts.iter().zip(again) {
            assert_eq!(
                left.encode(&mut || true).unwrap(),
                right.encode(&mut || true).unwrap()
            );
        }
    }
    #[test]
    fn long_words_keep_documents_but_invalid_native_content_still_refuses() {
        let docs = vec![
            document(b"a", b"small".to_vec()),
            document(b"b", vec![b'x'; 129]),
        ];
        let parts = segments(namespace(), &docs, &mut || true).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].documents().len(), 2);
        for (indexed, original) in parts[0].documents().iter().zip(&docs) {
            assert_eq!(indexed.path, original.path);
            assert_eq!(indexed.blob, original.blob);
            assert_eq!(indexed.content_bytes as usize, original.bytes.len());
        }
        let mut docs = vec![document(b"a", b"small".to_vec())];
        docs[0].bytes[0] = b'S';
        assert!(matches!(
            segments(namespace(), &docs, &mut || true),
            Err(IndexError::Lexical(LexicalError::NativeIdentityMismatch))
        ));
    }
    #[test]
    fn empty_inventory_is_distinct_from_cancelled_build() {
        assert!(segments(namespace(), &[], &mut || true).unwrap().is_empty());
        let docs = vec![document(b"a", Vec::new())];
        assert!(matches!(
            segments(namespace(), &docs, &mut || false),
            Err(IndexError::Lexical(LexicalError::Cancelled))
        ));
        assert_eq!(
            segments(namespace(), &docs, &mut || true).unwrap()[0]
                .documents()
                .len(),
            1
        );
    }
}
