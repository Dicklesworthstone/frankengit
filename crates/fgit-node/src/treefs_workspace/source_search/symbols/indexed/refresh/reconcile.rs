//! Explicit maintenance, never a query fallback. Select one canonical source
//! and one authenticated index predecessor; do not retry on a changed basis.
use super::*;

impl OneNode {
    /// Observe a current symbol index, build a genuinely uninitialized index,
    /// or refresh the exact observed predecessor. The caller explicitly owns
    /// local maintenance authority. An HTTP read cannot invoke this operation.
    ///
    /// A current-index no-op verifies generation, manifest and directory metadata;
    /// it does not read source blobs, audit every table, or advance the index.
    /// `minimum` is an independently retained checkpoint, not a suggested head.
    /// An unresolved checkpoint can never be converted into a new genesis.
    pub async fn reconcile_source_symbol_index_local_in(&self, request: &NodeRequestContext,
        reference: &RefName, expected_head: Option<RepositoryAuthorityHeadId>,
        minimum: Option<&GenerationActivation>, limits: SearchLimits, read_limits: GenerationReadLimits,
    ) -> Result<(data::Source, GenerationActivation), Failure> {
        self.reconcile_source_symbol_index_guarded_local_in(request,reference,expected_head,
            minimum,limits,read_limits,&mut |_| Ok(())).await
    }

    /// The existing build/refresh write-ahead barrier protects every possible
    /// publication. No-op observations never call it. A controller must recover
    /// any unresolved ORIGINAL candidate before starting another invocation.
    pub async fn reconcile_source_symbol_index_guarded_local_in(&self, request: &NodeRequestContext,
        reference: &RefName, expected_head: Option<RepositoryAuthorityHeadId>,
        minimum: Option<&GenerationActivation>, limits: SearchLimits, read_limits: GenerationReadLimits,
        barrier: &mut (impl FnMut(GraphGenerationId) -> Result<(), NodeWorkspaceRefusal> + Send),
    ) -> Result<(data::Source, GenerationActivation), Failure> {
        live(request)?;
        limits.validate().map_err(|e| Failure::Index(e.into()))?;
        admits_read(self.cell_state(),ReadMode::Current)
            .map_err(|e| Failure::Source(NodeWorkspaceRefusal::Cell(e)))?;
        admits_staging_intake(self.cell_state())
            .map_err(|e| Failure::Source(NodeWorkspaceRefusal::Cell(e)))?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|e| Failure::Source(NodeWorkspaceRefusal::Authority(Box::new(e))))?;
        live(request)?;
        // Visibility always precedes index selection, even with a checkpoint.
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
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr)
            | ClosureSelectionSource::CumulativeHistory { latest:rcr,.. } => rcr,
            ClosureSelectionSource::EmptyGenesis => return Err(Failure::Source(NodeWorkspaceRefusal::RefUnavailable)),
        };
        let forge = selected.basis().body().forge_position_root;
        let generation = GenerationAuthority::new(&self.authority,self.symbol_head_key(reference)?)
            .read_active_async(request.authority(),view()?,minimum,read_limits,
                &mut || workspace_request_live(request)).await.map_err(Failure::Generation)?;
        live(request)?;
        let predecessor = if let Some(generation) = generation {
            let body = generation.body();
            let root = symbol_manifest_root(body)?;
            let mut bytes = 0;
            let raw = self.read_symbol_payload(request,root,&mut bytes,data::MAX_INDEX_BYTES).await?;
            let manifest = data::Manifest::decode(&raw,root,&|| !workspace_request_live(request))
                .map_err(Failure::Index)?;
            let source = manifest.source();
            self.validate_symbol_source(source,body,reference)?;
            self.verify_symbol_directory_in(request,body,&manifest,&mut bytes,data::MAX_INDEX_BYTES).await?;
            if source.head == head && source.commit == commit && source.rcr == rcr && source.forge == forge {
                live(request)?;
                return Ok((source.clone(),generation.activation().clone()));
            }
            Some(generation.activation().generation_id)
        } else {
            // Defense in depth: absence is admissible only without a floor.
            if minimum.is_some() { return Err(Failure::Generation(GenerationAuthorityError::CheckpointUnresolved)); }
            None
        };
        drop(selected);
        // The native builders reauthenticate the SAME source pins. A source or
        // generation race refuses this attempt; it never selects a newer basis.
        match predecessor {
            None => self.build_source_symbol_index_guarded_local_in(request,reference,Some(head),Some(commit),
                None,limits,barrier).await,
            Some(predecessor) => self.refresh_source_symbol_index_guarded_local_in(request,reference,Some(head),Some(commit),
                predecessor,limits,barrier).await.map(|(source,activation,_)| (source,activation)),
        }
        // Confirmed root publication wins; no cancellation probe follows.
    }
}
