//! Exact-predecessor refresh. Current visibility precedes predecessor reads;
//! reused blobs never carry an old path or source stamp into the new manifest.
use super::*;

impl OneNode {
    /// Refresh an existing derived generation, fetching/scanning only current
    /// Rust blobs absent from its verified predecessor. No genesis/latest/force
    /// inference, no canonical write, and no read-triggered maintenance.
    pub async fn refresh_source_symbol_index_local_in(&self, request: &NodeRequestContext,
        reference: &RefName, expected_head: Option<RepositoryAuthorityHeadId>, expected_commit: Option<GitOid>,
        predecessor: GraphGenerationId, limits: SearchLimits,
    ) -> Result<(data::Source, GenerationActivation, data::RefreshStats), Failure> {
        self.refresh_source_symbol_index_guarded_local_in(request,reference,expected_head,expected_commit,
            predecessor,limits,&mut |_| Ok(())).await
    }

    /// The same original-candidate write-ahead barrier as a full build. All
    /// predecessor verification and complete current-tree preparation precede
    /// it; every later failure retains that exact candidate for recovery.
    pub async fn refresh_source_symbol_index_guarded_local_in(&self, request: &NodeRequestContext,
        reference: &RefName, expected_head: Option<RepositoryAuthorityHeadId>, expected_commit: Option<GitOid>,
        predecessor: GraphGenerationId, limits: SearchLimits,
        barrier: &mut (impl FnMut(GraphGenerationId) -> Result<(), NodeWorkspaceRefusal> + Send),
    ) -> Result<(data::Source, GenerationActivation, data::RefreshStats), Failure> {
        live(request)?;
        limits.validate().map_err(|e| Failure::Index(e.into()))?;
        admits_staging_intake(self.cell_state()).map_err(|e| Failure::Source(NodeWorkspaceRefusal::Cell(e)))?;
        if expected_commit.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format) {
            return Err(Failure::Source(NodeWorkspaceRefusal::ObjectFormatMismatch));
        }
        let selected = self.materialize_admission_in(request).await
            .map_err(|e| Failure::Source(NodeWorkspaceRefusal::Authority(Box::new(e))))?;
        live(request)?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(Failure::Source(NodeWorkspaceRefusal::RefUnavailable));
        }
        let commit = *selected.snapshot().refs.get(reference)
            .ok_or(Failure::Source(NodeWorkspaceRefusal::RefUnavailable))?;
        let head = selected.basis().id();
        if expected_head.is_some_and(|expected| expected != head) {
            return Err(Failure::Source(NodeWorkspaceRefusal::SourceBrowse(Box::new(
                fgit_forge::source_browse::SourceBrowseError::SnapshotMoved))));
        }
        if expected_commit.is_some_and(|expected| expected != commit) {
            return Err(Failure::Source(NodeWorkspaceRefusal::SourceBrowse(Box::new(
                fgit_forge::source_browse::SourceBrowseError::CommitMoved))));
        }
        drop(selected);

        let generation = GenerationAuthority::new(&self.authority,self.symbol_head_key(reference)?)
            .read_active_async(request.authority(),view()?,None,GenerationReadLimits::default(),
                &mut || workspace_request_live(request))
            .await.map_err(Failure::Generation)?.ok_or(Failure::Uninitialized)?;
        if generation.activation().generation_id != predecessor {
            return Err(Failure::Stale);
        }
        let body = generation.body();
        let root = symbol_manifest_root(body)?;
        let mut stats = data::RefreshStats::default();
        let raw = self.read_symbol_payload(request,root,&mut stats.predecessor_payload_bytes,data::MAX_INDEX_BYTES).await?;
        let cancelled = || !workspace_request_live(request);
        let manifest = data::Manifest::decode(&raw,root,&cancelled).map_err(Failure::Index)?;
        self.validate_symbol_source(manifest.source(),body,reference)?;
        // Older source head/RCR/forge/commit values are intentional here. Only
        // its verified per-blob tables, not its old visibility, are reusable.
        let mut verifier = data::ReuseVerifier::new(&manifest,&cancelled).map_err(Failure::Index)?;
        drop(raw);
        drop(manifest);
        drop(generation);
        while let Some(doc) = verifier.next_document().cloned() {
            live(request)?;
            if stats.predecessor_payload_bytes.checked_add(doc.encoded_bytes)
                .is_none_or(|bytes| bytes > data::MAX_INDEX_BYTES) {
                return Err(Failure::Index(data::Error::Limit("predecessor table bytes")));
            }
            let raw = self.read_symbol_payload(request,doc.root,&mut stats.predecessor_payload_bytes,data::MAX_INDEX_BYTES).await?;
            verifier.verify_next(&raw,&cancelled).map_err(Failure::Index)?;
            stats.predecessor_tables_read += 1;
        }
        let reuse = verifier.finish(&cancelled).map_err(Failure::Index)?;
        let query = Build(SourceQuery::new(b"symbols",SearchCase::Exact,&[])
            .map_err(|e| Failure::Index(e.into()))?,Some(reuse));
        // Reauthenticate after predecessor I/O, requiring the exact snapshot
        // admitted above. A concurrent source/policy change cannot be relabeled.
        let (head,forge,result) = match self.object_format {
            Format::Sha1 => self.select_source_local_format::<Sha1,_>(request,reference,Some(head),Some(commit),&query,limits).await,
            Format::Sha256 => self.select_source_local_format::<Sha256,_>(request,reference,Some(head),Some(commit),&query,limits).await,
        }.map_err(Failure::Source)?;
        let corpus = result.map_err(Failure::Index)?;
        stats.reused_files = corpus.reused_files();
        stats.source_blobs_read = corpus.source().files_read;
        stats.source_bytes_read = corpus.source().bytes_read;
        let (source,activation) = self.publish_symbol_corpus_in(request,reference,(head,forge,corpus),Some(predecessor),barrier).await?;
        // Confirmed publication wins; no await or cancellation probe follows.
        Ok((source,activation,stats))
    }
}
