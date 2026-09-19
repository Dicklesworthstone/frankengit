//! Persistent lexical generations over the existing authority store. Index
//! payloads are staged before the shared generation root is activated. The
//! selected manifest, catalogs and posting segments are checked on reads;
//! neither object existence nor an interrupted write implies publication.

mod manifest;
#[cfg(test)]
mod tests;

use super::*;
use crate::{BuilderProfileId, GenerationActivation, GenerationAuthority, GenerationAuthorityError,
    GenerationReadLimits, GraphAuthorityClass, GraphGenerationBody, GraphGenerationId,
    GraphSourceStamp, GraphViewId};
use fgit_authority::{AsyncAuthorityStore, AuthorityFailure, AuthorityStore, HeadKey, ImmutableKey,
    ImmutableRead, KeyError, PutOutcome, StoreInstanceId};
use fgit_types::{RefName, RepositoryAuthorityHeadId, RepositoryCommitId, SchemaFamily, SchemaId, TypeRefusal};
use manifest::{Manifest, Payload, SegmentRef};

pub const MAX_SEGMENTS: usize = 128;
pub const MAX_INDEX_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_INDEX_DOCUMENTS: usize = 20_000;
const VIEW: &[u8] = b"source-lexical";

/// Exact source facts supplied by the owning, authorized tree enumerator. This
/// is not a proof that arbitrary caller-supplied documents exhaust that tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalSource {
    pub namespace: LexicalNamespace,
    pub reference: RefName,
    pub source_head: RepositoryAuthorityHeadId,
    pub source_rcr: RepositoryCommitId,
    pub forge_position_root: Digest,
    pub commit: GitOid,
    pub tree: GitOid,
}

#[derive(Debug)]
pub enum IndexError {
    Lexical(LexicalError),
    Generation(GenerationAuthorityError),
    Authority(AuthorityFailure),
    Key(KeyError),
    Type(TypeRefusal),
    Uninitialized,
    MissingPayload(Digest),
    PayloadConflict(Digest),
    SourceMismatch,
}
impl From<LexicalError> for IndexError { fn from(e: LexicalError) -> Self { Self::Lexical(e) } }
impl From<fgit_codec::CodecRefusal> for IndexError { fn from(e: fgit_codec::CodecRefusal) -> Self { Self::Lexical(e.into()) } }
impl From<GenerationAuthorityError> for IndexError { fn from(e: GenerationAuthorityError) -> Self { Self::Generation(e) } }
impl From<AuthorityFailure> for IndexError { fn from(e: AuthorityFailure) -> Self { Self::Authority(e) } }
impl From<KeyError> for IndexError { fn from(e: KeyError) -> Self { Self::Key(e) } }
impl From<TypeRefusal> for IndexError { fn from(e: TypeRefusal) -> Self { Self::Type(e) } }
impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "stored lexical index refused: {self:?}") }
}
impl std::error::Error for IndexError {}

/// A bounded complete set of encoded segment/catalog/manifest payloads. Creating
/// this value does not stage anything or activate a generation.
#[derive(Debug)]
pub struct PreparedLexicalIndex {
    manifest: Manifest,
    metadata: Vec<Payload>,
    segments: Vec<Payload>,
}
impl PreparedLexicalIndex {
    pub fn new(source: LexicalSource, segments: Vec<LexicalSegment>, non_regular_entries: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, IndexError> {
        check(live)?;
        if segments.len() > MAX_SEGMENTS { return Err(LexicalError::Limit("index segments").into()); }
        let mut refs = Vec::with_capacity(segments.len());
        let mut payloads = Vec::with_capacity(segments.len());
        let mut total = 0usize;
        for segment in segments {
            check(live)?;
            if segment.namespace() != source.namespace { return Err(LexicalError::NamespaceMismatch.into()); }
            let bytes = segment.encode(live)?;
            let root = segment.root(live)?;
            bounded_add(&mut total, bytes.len(), MAX_INDEX_BYTES, "index bytes")?;
            refs.push(SegmentRef::new(&segment, root, bytes.len())?);
            payloads.push(Payload { kind: "segment", root, bytes });
        }
        let manifest = Manifest::new(source, refs, non_regular_entries)?;
        let metadata = manifest.payloads(live)?;
        for payload in &metadata { bounded_add(&mut total, payload.bytes.len(), MAX_INDEX_BYTES, "index bytes")?; }
        check(live)?;
        Ok(Self { manifest, metadata, segments: payloads })
    }
    #[must_use]
    pub fn source(&self) -> &LexicalSource { &self.manifest.source }
    #[must_use]
    pub fn document_count(&self) -> usize { self.manifest.document_count() }
    #[must_use]
    pub fn segment_count(&self) -> usize { self.segments.len() }
    #[must_use]
    pub fn encoded_bytes(&self) -> usize { self.metadata.iter().chain(&self.segments).map(|p| p.bytes.len()).sum() }
}

/// Metadata and segment reads share one byte allowance. Generation ancestry
/// additionally retains its existing independently bounded verification budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LexicalReadLimits {
    pub max_segments: usize,
    pub max_payload_bytes: usize,
    pub generation: GenerationReadLimits,
}
impl Default for LexicalReadLimits {
    fn default() -> Self { Self { max_segments: MAX_SEGMENTS, max_payload_bytes: MAX_INDEX_BYTES, generation: Default::default() } }
}
impl LexicalReadLimits {
    fn validate(self) -> Result<(), IndexError> {
        self.generation.validate()?;
        if self.max_segments == 0 || self.max_segments > MAX_SEGMENTS || self.max_payload_bytes == 0 || self.max_payload_bytes > MAX_INDEX_BYTES {
            return Err(LexicalError::Invalid("index read limits").into());
        }
        Ok(())
    }
}

/// An authenticated generation plus its checked, immutable index metadata.
/// Retaining it neither grants access nor creates a retention/GC pin.
#[derive(Clone, Debug)]
pub struct LexicalSelection {
    activation: GenerationActivation,
    selected_head: GenerationActivation,
    manifest: Manifest,
    payload_bytes: usize,
    generation_bytes: usize,
    store_instance: StoreInstanceId,
}
impl LexicalSelection {
    #[must_use]
    pub fn source(&self) -> &LexicalSource { &self.manifest.source }
    #[must_use]
    pub const fn activation(&self) -> &GenerationActivation { &self.activation }
    #[must_use]
    pub const fn selected_head(&self) -> &GenerationActivation { &self.selected_head }
}

#[derive(Clone, Debug)]
pub struct IndexedLexicalReport {
    pub source: LexicalSource,
    pub generation: GenerationActivation,
    pub selected_generation_head: GenerationActivation,
    pub query: LexicalQuery,
    pub results: LexicalReport,
    pub indexed_documents: usize,
    pub indexed_source_bytes: usize,
    pub non_regular_entries: usize,
    pub segments_read: usize,
    pub payload_bytes_read: usize,
    pub generation_bytes_read: usize,
}

/// Exactly one tenant/repository/incarnation/ref index. Head and payload keys
/// are derived internally; callers cannot supply a foreign key as a query.
/// The caller must authorize this complete namespace before constructing it.
pub struct LexicalIndexStore<'a, S> {
    store: &'a S,
    namespace: LexicalNamespace,
    reference: RefName,
    head_key: HeadKey,
    view: GraphViewId,
}
impl<'a, S> LexicalIndexStore<'a, S> {
    pub fn new(store: &'a S, namespace: LexicalNamespace, reference: RefName) -> Result<Self, IndexError> {
        let mut key = key_prefix(namespace, "head");
        // Ref bytes remain in the manifest and are checked exactly on reads.
        // This digest is a bounded key component, not an authentication token.
        key.extend_from_slice(&fgit_crypto::sha256_digest(reference.as_bytes()));
        Ok(Self { store, namespace, reference, head_key: HeadKey::new(key)?, view: GraphViewId::try_new(VIEW)? })
    }
    fn check_source(&self, source: &LexicalSource) -> Result<(), IndexError> {
        if source.namespace != self.namespace || source.reference != self.reference { return Err(IndexError::SourceMismatch); }
        Ok(())
    }
    fn generation(&self, prepared: &PreparedLexicalIndex, predecessor: Option<GraphGenerationId>) -> Result<GraphGenerationBody, IndexError> {
        self.check_source(prepared.source())?;
        let source = prepared.source();
        let root = |kind| prepared.metadata.iter().find(|p| p.kind == kind).map(|p| p.root)
            .ok_or(LexicalError::Invalid("missing prepared metadata"));
        Ok(GraphGenerationBody::new(self.view, manifest::schema(), GraphAuthorityClass::DeterministicDerived,
            GraphSourceStamp { source_rcr_id: source.source_rcr, source_forge_position_root: source.forge_position_root,
                builder_profile: BuilderProfileId::try_new(PROFILE.as_bytes())?, parser_model_root: manifest::profile_root()? },
            root("documents")?, root("postings")?, root("manifest")?, root("evidence")?, predecessor))
    }
    /// Save this ID with the exact source/predecessor before publication when
    /// the caller needs to recover an interrupted reply.
    pub fn candidate_id(&self, prepared: &PreparedLexicalIndex, predecessor: Option<GraphGenerationId>) -> Result<GraphGenerationId, IndexError> {
        Ok(self.generation(prepared, predecessor)?.generation_id()?)
    }
    fn check_intake(&self, prepared: &PreparedLexicalIndex, maximum: usize) -> Result<(), IndexError> {
        self.check_source(prepared.source())?;
        if prepared.metadata.iter().chain(&prepared.segments).any(|p| p.bytes.len() > maximum) {
            return Err(LexicalError::Limit("authority payload ceiling").into());
        }
        Ok(())
    }
    fn begin_selection(&self, body: &GraphGenerationBody, raw: &[u8], live: &mut impl FnMut() -> bool) -> Result<(Manifest, Vec<Payload>), IndexError> {
        if body.graph_view_id() != self.view || body.graph_schema_id() != manifest::schema()
            || body.authority_class() != GraphAuthorityClass::DeterministicDerived
            || body.source().builder_profile != BuilderProfileId::try_new(PROFILE.as_bytes())?
            || body.source().parser_model_root != manifest::profile_root()?
        { return Err(LexicalError::Invalid("index generation profile").into()); }
        let manifest = Manifest::decode(raw, *body.index_manifest_root(), self.namespace, live)?;
        self.check_source(&manifest.source)?;
        if body.source().source_rcr_id != manifest.source.source_rcr
            || body.source().source_forge_position_root != manifest.source.forge_position_root
        { return Err(IndexError::SourceMismatch); }
        let metadata = manifest.payloads(live)?;
        for (kind, root) in [("documents", *body.vertices_root()), ("postings", *body.edges_root()),
            ("manifest", *body.index_manifest_root()), ("evidence", *body.evidence_root())]
        {
            if !metadata.iter().any(|p| p.kind == kind && p.root == root) { return Err(LexicalError::CommitmentMismatch.into()); }
        }
        Ok((manifest, metadata))
    }
}

fn key_prefix(namespace: LexicalNamespace, kind: &str) -> Vec<u8> {
    let mut out = b"fgit-lexical/v1/".to_vec();
    out.extend_from_slice(namespace.tenant.as_bytes()); out.extend_from_slice(namespace.repository.as_bytes());
    out.extend_from_slice(namespace.incarnation.as_bytes());
    out.push(match namespace.object_format { GitHashAlgorithm::Sha1 => 1, GitHashAlgorithm::Sha256 => 2 });
    out.extend_from_slice(kind.as_bytes()); out.push(b'/'); out
}
fn payload_key(namespace: LexicalNamespace, kind: &str, root: Digest) -> Result<ImmutableKey, IndexError> {
    let mut bytes = key_prefix(namespace, kind);
    bytes.extend_from_slice(&root.algorithm().code_point().to_be_bytes()); bytes.extend_from_slice(root.bytes().as_bytes());
    Ok(ImmutableKey::new(bytes)?)
}
fn accepted_put(outcome: PutOutcome, root: Digest) -> Result<(), IndexError> {
    match outcome { PutOutcome::Created | PutOutcome::IdenticalRetry => Ok(()), PutOutcome::Conflict => Err(IndexError::PayloadConflict(root)) }
}
fn payload(read: ImmutableRead, root: Digest, bytes: &mut usize, limits: LexicalReadLimits) -> Result<Vec<u8>, IndexError> {
    let ImmutableRead::Present(body) = read else { return Err(IndexError::MissingPayload(root)); };
    if body.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("payload bytes").into()); }
    bounded_add(bytes, body.len(), limits.max_payload_bytes, "index read bytes")?;
    Ok(body)
}
fn before_read(bytes: usize, limits: LexicalReadLimits, live: &mut impl FnMut() -> bool) -> Result<(), IndexError> {
    check(live)?;
    if bytes >= limits.max_payload_bytes { return Err(LexicalError::Limit("index read bytes").into()); }
    Ok(())
}

impl<S: AuthorityStore> LexicalIndexStore<'_, S> {
    /// Resolve the saved candidate ID on this scoped selected history. This
    /// never stages, retries, or infers publication from index payload bytes.
    pub fn recover(&self, candidate: GraphGenerationId, minimum: Option<&GenerationActivation>,
        limits: GenerationReadLimits, live: &mut impl FnMut() -> bool,
    ) -> Result<crate::GenerationRecovery, IndexError> {
        Ok(GenerationAuthority::new(self.store, self.head_key.clone())
            .recover_activation(self.view, candidate, minimum, limits, live)?)
    }
    pub fn publish(&self, prepared: &PreparedLexicalIndex, predecessor: Option<GraphGenerationId>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<GenerationActivation, IndexError> {
        check(live)?; self.check_intake(prepared, self.store.limits().body_bytes)?;
        let generation = self.generation(prepared, predecessor)?;
        for body in prepared.segments.iter().chain(&prepared.metadata) {
            check(live)?;
            accepted_put(self.store.put_if_absent(&payload_key(self.namespace, body.kind, body.root)?, &body.bytes)?, body.root)?;
        }
        check(live)?;
        // No local cancellation check after canonical generation confirmation.
        Ok(GenerationAuthority::new(self.store, self.head_key.clone()).stage_and_activate(&generation)?)
    }
    pub fn select(&self, expected: Option<&GenerationActivation>, minimum: Option<&GenerationActivation>,
        limits: LexicalReadLimits, live: &mut impl FnMut() -> bool,
    ) -> Result<LexicalSelection, IndexError> {
        limits.validate()?; check(live)?;
        let authority = GenerationAuthority::new(self.store, self.head_key.clone());
        let (activation, selected_head, body, generation_bytes) = if let Some(expected) = expected {
            let selected = authority.read_at(self.view, expected, minimum, limits.generation, live)?;
            (selected.activation().clone(), selected.selected_head().clone(), selected.body().clone(), selected.bytes_read())
        } else {
            let selected = authority.read_active(self.view, minimum, limits.generation, live)?.ok_or(IndexError::Uninitialized)?;
            (selected.activation().clone(), selected.activation().clone(), selected.body().clone(), selected.bytes_read())
        };
        let mut bytes = 0;
        before_read(bytes, limits, live)?;
        let raw = payload(self.store.read_immutable(&payload_key(self.namespace, "manifest", *body.index_manifest_root())?)?,
            *body.index_manifest_root(), &mut bytes, limits)?;
        let (manifest, metadata) = self.begin_selection(&body, &raw, live)?;
        for expected in metadata.iter().filter(|p| p.kind != "manifest") {
            before_read(bytes, limits, live)?;
            let raw = payload(self.store.read_immutable(&payload_key(self.namespace, expected.kind, expected.root)?)?, expected.root, &mut bytes, limits)?;
            if raw != expected.bytes { return Err(LexicalError::CommitmentMismatch.into()); }
        }
        check(live)?;
        Ok(LexicalSelection { activation, selected_head, manifest, payload_bytes: bytes, generation_bytes,
            store_instance: self.store.instance_id() })
    }
    pub fn search(&self, selection: &LexicalSelection, query: &LexicalQuery, after: Option<u64>,
        read_limits: LexicalReadLimits, query_limits: LexicalQueryLimits, live: &mut impl FnMut() -> bool,
    ) -> Result<IndexedLexicalReport, IndexError> {
        let mut scan = Scan::new(selection, read_limits, query_limits)?; self.check_source(selection.source())?;
        if selection.store_instance != self.store.instance_id() { return Err(IndexError::SourceMismatch); }
        for reference in &selection.manifest.segments {
            if after.is_some_and(|id| reference.last_id <= id) { continue; }
            scan.before(read_limits, live)?;
            let bytes = payload(self.store.read_immutable(&payload_key(self.namespace, "segment", reference.root)?)?,
                reference.root, &mut scan.bytes, read_limits)?;
            if scan.observe(reference, &bytes, self.namespace, query, after, live)? { break; }
        }
        check(live)?; Ok(scan.finish(selection, query))
    }
}

impl<S: AsyncAuthorityStore> LexicalIndexStore<'_, S> {
    /// Production recovery retains per-invocation context and ambiguity.
    pub async fn recover_async(&self, cx: &S::Context, candidate: GraphGenerationId,
        minimum: Option<&GenerationActivation>, limits: GenerationReadLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<crate::GenerationRecovery, IndexError> {
        Ok(GenerationAuthority::new(self.store, self.head_key.clone())
            .recover_activation_async(cx, self.view, candidate, minimum, limits, live).await?)
    }
    pub async fn publish_async(&self, cx: &S::Context, prepared: &PreparedLexicalIndex,
        predecessor: Option<GraphGenerationId>, live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<GenerationActivation, IndexError> {
        check(live)?; self.check_intake(prepared, self.store.limits().body_bytes)?;
        let generation = self.generation(prepared, predecessor)?;
        for body in prepared.segments.iter().chain(&prepared.metadata) {
            check(live)?;
            accepted_put(self.store.put_if_absent(cx, &payload_key(self.namespace, body.kind, body.root)?, &body.bytes).await?, body.root)?;
        }
        check(live)?;
        Ok(GenerationAuthority::new(self.store, self.head_key.clone()).stage_and_activate_async(cx, &generation).await?)
    }
    pub async fn select_async(&self, cx: &S::Context, expected: Option<&GenerationActivation>,
        minimum: Option<&GenerationActivation>, limits: LexicalReadLimits, live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<LexicalSelection, IndexError> {
        limits.validate()?; check(live)?;
        let authority = GenerationAuthority::new(self.store, self.head_key.clone());
        let (activation, selected_head, body, generation_bytes) = if let Some(expected) = expected {
            let selected = authority.read_at_async(cx, self.view, expected, minimum, limits.generation, live).await?;
            (selected.activation().clone(), selected.selected_head().clone(), selected.body().clone(), selected.bytes_read())
        } else {
            let selected = authority.read_active_async(cx, self.view, minimum, limits.generation, live).await?.ok_or(IndexError::Uninitialized)?;
            (selected.activation().clone(), selected.activation().clone(), selected.body().clone(), selected.bytes_read())
        };
        let mut bytes = 0;
        before_read(bytes, limits, live)?;
        let raw = payload(self.store.read_immutable(cx, &payload_key(self.namespace, "manifest", *body.index_manifest_root())?).await?,
            *body.index_manifest_root(), &mut bytes, limits)?;
        let (manifest, metadata) = self.begin_selection(&body, &raw, live)?;
        for expected in metadata.iter().filter(|p| p.kind != "manifest") {
            before_read(bytes, limits, live)?;
            let raw = payload(self.store.read_immutable(cx, &payload_key(self.namespace, expected.kind, expected.root)?).await?, expected.root, &mut bytes, limits)?;
            if raw != expected.bytes { return Err(LexicalError::CommitmentMismatch.into()); }
        }
        check(live)?;
        Ok(LexicalSelection { activation, selected_head, manifest, payload_bytes: bytes, generation_bytes,
            store_instance: self.store.instance_id() })
    }
    pub async fn search_async(&self, cx: &S::Context, selection: &LexicalSelection, query: &LexicalQuery,
        after: Option<u64>, read_limits: LexicalReadLimits, query_limits: LexicalQueryLimits,
        live: &mut (impl FnMut() -> bool + Send),
    ) -> Result<IndexedLexicalReport, IndexError> {
        let mut scan = Scan::new(selection, read_limits, query_limits)?; self.check_source(selection.source())?;
        if selection.store_instance != self.store.instance_id() { return Err(IndexError::SourceMismatch); }
        for reference in &selection.manifest.segments {
            if after.is_some_and(|id| reference.last_id <= id) { continue; }
            scan.before(read_limits, live)?;
            let bytes = payload(self.store.read_immutable(cx, &payload_key(self.namespace, "segment", reference.root)?).await?,
                reference.root, &mut scan.bytes, read_limits)?;
            if scan.observe(reference, &bytes, self.namespace, query, after, live)? { break; }
        }
        check(live)?; Ok(scan.finish(selection, query))
    }
}

struct Scan { hits: Vec<LexicalHit>, budget: QueryBudget, bytes: usize, segments: usize, more: bool }
impl Scan {
    fn new(selection: &LexicalSelection, limits: LexicalReadLimits, query: LexicalQueryLimits) -> Result<Self, IndexError> {
        limits.validate()?;
        if selection.payload_bytes > limits.max_payload_bytes { return Err(LexicalError::Limit("index read bytes").into()); }
        Ok(Self { hits: Vec::new(), budget: QueryBudget::new(query)?, bytes: selection.payload_bytes, segments: 0, more: false })
    }
    fn before(&mut self, limits: LexicalReadLimits, live: &mut impl FnMut() -> bool) -> Result<(), IndexError> {
        before_read(self.bytes, limits, live)?;
        if self.segments == limits.max_segments { return Err(LexicalError::Limit("index segment reads").into()); }
        self.segments += 1; Ok(())
    }
    fn observe(&mut self, reference: &SegmentRef, bytes: &[u8], namespace: LexicalNamespace,
        query: &LexicalQuery, after: Option<u64>, live: &mut impl FnMut() -> bool,
    ) -> Result<bool, IndexError> {
        let segment = LexicalSegment::decode(bytes, reference.root, namespace, live)?;
        if SegmentRef::new(&segment, reference.root, bytes.len())? != *reference { return Err(LexicalError::CommitmentMismatch.into()); }
        self.more = segment.search_into(query, after, &mut self.budget, &mut self.hits, live)?;
        Ok(self.more)
    }
    fn finish(self, selection: &LexicalSelection, query: &LexicalQuery) -> IndexedLexicalReport {
        IndexedLexicalReport { source: selection.source().clone(), generation: selection.activation.clone(),
            selected_generation_head: selection.selected_head.clone(), query: query.clone(),
            results: LexicalReport { next_after: if self.more { self.hits.last().map(|h| h.document_id) } else { None },
                hits: self.hits, complete: !self.more, work_units: self.budget.work },
            indexed_documents: selection.manifest.document_count(), indexed_source_bytes: selection.manifest.source_bytes(),
            non_regular_entries: selection.manifest.non_regular_entries, segments_read: self.segments,
            payload_bytes_read: self.bytes, generation_bytes_read: selection.generation_bytes }
    }
}
