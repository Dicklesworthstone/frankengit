//! Native persistent symbols. Only explicit trusted-local builds publish a
//! derived generation; search validates canonical visibility before disclosure.
use super::*;
use fgit_authority::{AsyncAuthorityStore, HeadKey, ImmutableKey, ImmutableRead, PutOutcome};
use fgit_forge::source_search::SearchCase;
use fgit_forge::source_symbols::index as data;
use fgit_graph::{BuilderProfileId, GenerationActivation, GenerationAuthority,
    GenerationAuthorityError, GenerationReadLimits, GenerationRecovery, GraphAuthorityClass,
    GraphGenerationBody, GraphGenerationId, GraphSourceStamp, GraphViewId};
use fgit_types::{SchemaFamily, SchemaId};
use fgit_types::cell::admits_staging_intake;

mod refresh;
mod directory;
use directory::{generation_body, symbol_manifest_root, symbol_directory_root};

type Failure = data::AccessError<NodeWorkspaceRefusal, GenerationAuthorityError>;
fn live(request: &NodeRequestContext) -> Result<(), Failure> {
    if workspace_request_live(request) { Ok(()) } else { Err(Failure::Index(data::Error::Cancelled)) }
}
fn view() -> Result<GraphViewId, Failure> {
    GraphViewId::try_new(b"source-rust-symbols").map_err(|e| Failure::Index(e.into()))
}
struct Build(SourceQuery, Option<data::VerifiedReuse>);
impl LocalSearch for Build {
    type Report = Result<data::Corpus, data::Error>;
    fn scope(&self) -> &SourceQuery { &self.0 }
    fn empty(&self, source: SourceSearchReport) -> Self::Report { Ok(data::Corpus::empty(source)) }
    fn run<A: GitHashAlgorithm, S: ObjectSource<A>>(&self, base: &BaseView<A>, source: &S,
        capability: &mut TreeCapability, now: u64, limits: SearchLimits, cancelled: &dyn Fn() -> bool,
    ) -> Result<Self::Report, SearchError> { Ok(data::prepare_with_reuse(base,source,capability,now,limits,cancelled,self.1.as_ref())) }
}
impl OneNode {
    fn symbol_key_prefix(&self, kind: &[u8]) -> Vec<u8> {
        let mut key = b"fgit-symbol-index/v1/".to_vec();
        key.extend_from_slice(self.tenant_id.as_bytes()); key.extend_from_slice(self.repository_id.as_bytes());
        key.extend_from_slice(self.repository_incarnation_id().as_bytes());
        key.push(match self.object_format { Format::Sha1 => 1, Format::Sha256 => 2 });
        key.extend_from_slice(kind); key.push(b'/'); key
    }
    fn symbol_head_key(&self, reference: &RefName) -> Result<HeadKey, Failure> {
        let mut key = self.symbol_key_prefix(b"head");
        key.extend_from_slice(&fgit_crypto::sha256_digest(reference.as_bytes()));
        HeadKey::new(key).map_err(Failure::Key)
    }
    fn symbol_payload_key(&self, root: Digest) -> Result<ImmutableKey, Failure> {
        let mut key = self.symbol_key_prefix(b"payload");
        key.extend_from_slice(&root.algorithm().code_point().to_be_bytes()); key.extend_from_slice(root.bytes().as_bytes());
        ImmutableKey::new(key).map_err(Failure::Key)
    }
    /// Explicit operator build; None requires genesis, otherwise the exact
    /// predecessor is mandatory. No HTTP read grant permits this operation.
    pub async fn build_source_symbol_index_local_in(&self, request: &NodeRequestContext,
        reference: &RefName, expected_head: Option<RepositoryAuthorityHeadId>, expected_commit: Option<GitOid>,
        predecessor: Option<GraphGenerationId>, limits: SearchLimits,
    ) -> Result<(data::Source, GenerationActivation), Failure> {
        self.build_source_symbol_index_guarded_local_in(request,reference,expected_head,expected_commit,
            predecessor,limits,&mut |_| Ok(())).await
    }
    /// Record the immutable candidate before staging any table/manifest or
    /// changing the derived root. Barrier failure prevents those effects.
    pub async fn build_source_symbol_index_guarded_local_in(&self, request: &NodeRequestContext,
        reference: &RefName, expected_head: Option<RepositoryAuthorityHeadId>, expected_commit: Option<GitOid>,
        predecessor: Option<GraphGenerationId>, limits: SearchLimits,
        barrier: &mut (impl FnMut(GraphGenerationId) -> Result<(), NodeWorkspaceRefusal> + Send),
    ) -> Result<(data::Source, GenerationActivation), Failure> {
        live(request)?;
        admits_staging_intake(self.cell_state()).map_err(|e| Failure::Source(NodeWorkspaceRefusal::Cell(e)))?;
        if expected_commit.is_some_and(|id| id.is_zero() || id.algorithm() != self.object_format) {
            return Err(Failure::Source(NodeWorkspaceRefusal::ObjectFormatMismatch));
        }
        let query = Build(SourceQuery::new(b"symbols",SearchCase::Exact,&[]).map_err(|e| Failure::Index(e.into()))?,None);
        let (head,forge,result) = match self.object_format {
            Format::Sha1 => self.select_source_local_format::<Sha1,_>(request,reference,expected_head,expected_commit,&query,limits).await,
            Format::Sha256 => self.select_source_local_format::<Sha256,_>(request,reference,expected_head,expected_commit,&query,limits).await,
        }.map_err(Failure::Source)?;
        let corpus = result.map_err(Failure::Index)?;
        self.publish_symbol_corpus_in(request,reference,(head,forge,corpus),predecessor,barrier).await
    }
    /// Shared by rebuild and refresh: one write-ahead barrier and one root-last
    /// publication implementation, including original-candidate uncertainty.
    async fn publish_symbol_corpus_in(&self, request: &NodeRequestContext, reference: &RefName,
        selected: (RepositoryAuthorityHeadId, Digest, data::Corpus), predecessor: Option<GraphGenerationId>,
        barrier: &mut (impl FnMut(GraphGenerationId) -> Result<(), NodeWorkspaceRefusal> + Send),
    ) -> Result<(data::Source, GenerationActivation), Failure> {
        live(request)?;
        let (head,forge,corpus) = selected;
        let selected = corpus.source();
        let source = data::Source { tenant:self.tenant_id,repository:self.repository_id,
            incarnation:self.repository_incarnation_id(),format:self.object_format,reference:reference.clone(),head,
            rcr:selected.source_rcr,forge,commit:selected.source_commit,tree:selected.source_tree };
        let cancelled = || !workspace_request_live(request);
        let (manifest,tables,directory) = corpus.finish_with_directory(source.clone(),&cancelled).map_err(Failure::Index)?;
        let manifest = manifest.encode(&cancelled).map_err(Failure::Index)?;
        // The additional lookup is optional only at build time. A smaller host
        // ceiling retains an explicitly identified legacy generation layout.
        let directory = directory.filter(|p| p.bytes.len() <= self.authority.limits().body_bytes);
        if tables.iter().chain(std::iter::once(&manifest)).any(|p| p.bytes.len() > self.authority.limits().body_bytes) {
            return Err(Failure::Index(data::Error::Limit("authority body bytes")));
        }
        let body = generation_body(&source,manifest.root,directory.as_ref().map(|p| p.root),predecessor)?;
        let candidate = body.generation_id().map_err(Failure::Generation)?;
        let head_key = self.symbol_head_key(reference)?;
        live(request)?; barrier(candidate).map_err(Failure::Source)?;
        let result: Result<GenerationActivation,Failure> = async {
            for payload in tables.iter().chain(directory.iter()).chain(std::iter::once(&manifest)) {
                live(request)?;
                match AsyncAuthorityStore::put_if_absent(&self.authority,request.authority(),&self.symbol_payload_key(payload.root)?,&payload.bytes)
                    .await.map_err(Failure::Authority)?
                {
                    PutOutcome::Created | PutOutcome::IdenticalRetry => {},
                    PutOutcome::Conflict => return Err(Failure::Conflict(payload.root)),
                }
            }
            live(request)?;
            GenerationAuthority::new(&self.authority,head_key).stage_and_activate_async(request.authority(),&body)
                .await.map_err(Failure::Generation)
        }.await;
        let activated = result.map_err(|cause| Failure::Publication {
            candidate:*candidate.as_internal_object_id(),cause:Box::new(cause) })?;
        // Confirmed publication wins; no cancellation probe/await follows it.
        Ok((source,activated))
    }
    /// Persisted read only. Current source and hidden-ref policy precede index
    /// metadata. Staleness, missing backing and failed checkpoints never scan
    /// source, rebuild, fall back, or disclose a different generation.
    pub async fn search_source_symbols_index_snapshot_local_in(&self, request:&NodeRequestContext,
        reference:&RefName, expected_head:Option<RepositoryAuthorityHeadId>, expected_commit:Option<GitOid>,
        minimum:Option<&GenerationActivation>, query:&SymbolQuery, limits:SearchLimits, maximum_payload_bytes:usize,
    ) -> Result<data::Report,Failure> {
        live(request)?; limits.validate().map_err(|e|Failure::Index(e.into()))?;
        if maximum_payload_bytes == 0 || maximum_payload_bytes > data::MAX_INDEX_BYTES {
            return Err(Failure::Index(data::Error::Limit("index read bytes")));
        }
        if expected_commit.is_some_and(|id|id.is_zero() || id.algorithm()!=self.object_format) {
            return Err(Failure::Source(NodeWorkspaceRefusal::ObjectFormatMismatch));
        }
        admits_read(self.cell_state(),ReadMode::Current).map_err(|e|Failure::Source(NodeWorkspaceRefusal::Cell(e)))?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|e|Failure::Source(NodeWorkspaceRefusal::Authority(Box::new(e))))?;
        live(request)?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) {return Err(Failure::Source(NodeWorkspaceRefusal::RefUnavailable));}
        let commit = *selected.snapshot().refs.get(reference).ok_or(Failure::Source(NodeWorkspaceRefusal::RefUnavailable))?;
        let head = selected.basis().id();
        if expected_head.is_some_and(|expected|expected!=head) {
            return Err(Failure::Source(NodeWorkspaceRefusal::SourceBrowse(Box::new(fgit_forge::source_browse::SourceBrowseError::SnapshotMoved))));
        }
        if expected_commit.is_some_and(|expected|expected!=commit) {
            return Err(Failure::Source(NodeWorkspaceRefusal::SourceBrowse(Box::new(fgit_forge::source_browse::SourceBrowseError::CommitMoved))));
        }
        let rcr = match selected.selected_closure().source() {
            ClosureSelectionSource::RepositoryCommit(rcr) | ClosureSelectionSource::CumulativeHistory {latest:rcr,..} => rcr,
            ClosureSelectionSource::EmptyGenesis => return Err(Failure::Source(NodeWorkspaceRefusal::RefUnavailable)),
        };
        let mut is_live = || workspace_request_live(request);
        let generation = GenerationAuthority::new(&self.authority,self.symbol_head_key(reference)?)
            .read_active_async(request.authority(),view()?,minimum,GenerationReadLimits::default(),&mut is_live)
            .await.map_err(Failure::Generation)?.ok_or(Failure::Uninitialized)?;
        let body = generation.body(); let root = symbol_manifest_root(body)?;
        let mut bytes = 0;
        let raw = self.read_symbol_payload(request,root,&mut bytes,maximum_payload_bytes).await?;
        let cancelled = || !workspace_request_live(request);
        let manifest = data::Manifest::decode(&raw,root,&cancelled).map_err(Failure::Index)?;
        let source = manifest.source();
        self.validate_symbol_source(source,body,reference)?;
        if source.head!=head || source.commit!=commit || source.rcr!=rcr || source.forge!=selected.basis().body().forge_position_root {
            return Err(Failure::Stale);
        }
        drop(raw);
        let mut search = data::Query::new(query,limits.max_matches).map_err(Failure::Index)?;
        let candidates = if let Some(root) = symbol_directory_root(body)? {
            let raw = self.read_symbol_payload(request,root,&mut bytes,maximum_payload_bytes).await?;
            search.directory_candidates(&manifest,&raw,root,&cancelled).map_err(Failure::Index)?
        } else {
            manifest.documents().iter().enumerate().filter_map(|(i, doc)| search.includes(doc).then_some(i)).collect()
        };
        let mut source_bytes = 0usize;
        let mut files = 0usize;
        for ordinal in candidates {
            live(request)?;
            let doc = &manifest.documents()[ordinal];
            files += 1;
            if files > limits.max_files {return Err(Failure::Index(data::Error::Limit("table reads")));}
            source_bytes = source_bytes.checked_add(doc.source_bytes).filter(|n|*n<=limits.max_total_bytes)
                .ok_or(Failure::Index(data::Error::Limit("referenced source bytes")))?;
            if doc.source_bytes>limits.max_file_bytes || bytes.checked_add(doc.encoded_bytes).is_none_or(|n|n>maximum_payload_bytes) {
                return Err(Failure::Index(data::Error::Limit("table/source read budget")));
            }
            let raw = self.read_symbol_payload(request,doc.root,&mut bytes,maximum_payload_bytes).await?;
            if search.observe(doc,&raw,&cancelled).map_err(Failure::Index)? {break;}
        }
        live(request)?;
        Ok(search.finish(&manifest,*generation.activation().generation_id.as_internal_object_id(),
            generation.activation().authority_generation.get(),bytes))
    }
    fn validate_symbol_source(&self, source: &data::Source, body: &GraphGenerationBody,
        reference: &RefName,
    ) -> Result<(), Failure> {
        if source.tenant!=self.tenant_id || source.repository!=self.repository_id || source.incarnation!=self.repository_incarnation_id()
            || source.format!=self.object_format || source.reference!=*reference
            || source.rcr!=body.source().source_rcr_id || source.forge!=body.source().source_forge_position_root
        {return Err(Failure::Index(data::Error::Invalid("index namespace/source")));}
        Ok(())
    }
    async fn read_symbol_payload(&self, request:&NodeRequestContext,root:Digest,bytes:&mut usize,maximum:usize) -> Result<Vec<u8>,Failure> {
        live(request)?;
        if *bytes>=maximum {return Err(Failure::Index(data::Error::Limit("index read bytes")));}
        let raw = AsyncAuthorityStore::read_immutable(&self.authority,request.authority(),&self.symbol_payload_key(root)?).await.map_err(Failure::Authority)?;
        live(request)?;
        let ImmutableRead::Present(raw)=raw else {return Err(Failure::Missing(root));};
        if raw.len()>data::MAX_PAYLOAD {return Err(Failure::Index(data::Error::Limit("payload bytes")));}
        *bytes=bytes.checked_add(raw.len()).filter(|n|*n<=maximum).ok_or(Failure::Index(data::Error::Limit("index read bytes")))?;
        Ok(raw)
    }
    /// Original-candidate observation, not a retry or an inference from staged tables.
    pub async fn recover_source_symbol_index_local_in(&self,request:&NodeRequestContext,reference:&RefName,
        candidate:GraphGenerationId,minimum:Option<&GenerationActivation>,limits:GenerationReadLimits,
    ) -> Result<GenerationRecovery,Failure> {
        live(request)?;
        admits_read(self.cell_state(),ReadMode::Current).map_err(|e|Failure::Source(NodeWorkspaceRefusal::Cell(e)))?;
        let selected=self.materialize_admission_in(request).await
            .map_err(|e|Failure::Source(NodeWorkspaceRefusal::Authority(Box::new(e))))?;
        live(request)?;
        if selected.snapshot().hidden_refs.hides(reference.as_bytes()) || !selected.snapshot().refs.contains_key(reference) {
            return Err(Failure::Source(NodeWorkspaceRefusal::RefUnavailable));
        }
        GenerationAuthority::new(&self.authority,self.symbol_head_key(reference)?)
            .recover_activation_async(request.authority(),view()?,candidate,minimum,limits,&mut ||workspace_request_live(request))
            .await.map_err(Failure::Generation)
    }
}
