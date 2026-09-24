//! Persisted declaration tables and source-bound manifests. A manifest's root
//! must come from authenticated generation selection, not from these bytes.
//! The native owner supplies complete verified TreeFS enumeration and publishes
//! the manifest only after staging all tables. Queries never read source blobs.
use super::{SymbolMatch, SymbolMatchMode, SymbolQuery, engine, table};
use crate::source_search::{
    Discovery, DiscoveryContext, SearchCase, SearchCompletion, SearchError, SearchLimits,
    SourceMatch, SourceQuery, SourceSearchReport, discover,
};
use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, Decoder, Encoder, body_id,
    decode_body, encode_body,
};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, git_object_id};
use fgit_treefs::{BaseView, ObjectSource, TreeCapability, TreePath};
use fgit_types::{
    Digest, DomainTag, GitHashAlgorithm as Format, GitOid, GitOidSha1, GitOidSha256,
    InternalObjectId, RefName, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryId,
    RepositoryIncarnationId, SchemaFamily, TenantId, TypeRefusal,
};
use std::collections::BTreeMap;

pub use super::table::Error as TableError;
#[path = "index_reuse.rs"]
mod reuse;
pub use directory::{DIRECTORY_PROFILE, NameDirectory};
pub use reuse::{RefreshStats, ReuseVerifier, VerifiedReuse};

pub const INDEX_PROFILE: &str = "rust-declaration-tables-v1";
pub const MAX_PAYLOAD: usize = 1024 * 1024;
pub const MAX_INDEX_BYTES: usize = 32 * 1024 * 1024;
#[derive(Debug)]
pub enum Error {
    Source(SearchError),
    Table(table::Error),
    Codec(CodecRefusal),
    Type(TypeRefusal),
    Invalid(&'static str),
    Limit(&'static str),
    Cancelled,
    CommitmentMismatch,
}
impl From<SearchError> for Error {
    fn from(e: SearchError) -> Self {
        Self::Source(e)
    }
}
impl From<table::Error> for Error {
    fn from(e: table::Error) -> Self {
        Self::Table(e)
    }
}
impl From<CodecRefusal> for Error {
    fn from(e: CodecRefusal) -> Self {
        Self::Codec(e)
    }
}
impl From<TypeRefusal> for Error {
    fn from(e: TypeRefusal) -> Self {
        Self::Type(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "symbol index refused: {self:?}")
    }
}
impl std::error::Error for Error {}
/// Keeps source, storage, generation, and publication-uncertainty failures
/// separate without making this L2 crate depend on the generation owner.
#[derive(Debug)]
pub enum AccessError<S, G> {
    Source(S),
    Index(Error),
    Generation(G),
    Authority(fgit_authority::AuthorityFailure),
    Key(fgit_authority::KeyError),
    Uninitialized,
    Stale,
    Missing(Digest),
    Conflict(Digest),
    Publication {
        candidate: InternalObjectId,
        cause: Box<Self>,
    },
}
impl<S: std::fmt::Debug, G: std::fmt::Debug> std::fmt::Display for AccessError<S, G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "persistent symbols refused: {self:?}")
    }
}
impl<S: std::error::Error + 'static, G: std::error::Error + 'static> std::error::Error
    for AccessError<S, G>
{
}
fn check(cancelled: &dyn Fn() -> bool) -> Result<(), Error> {
    if cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}
fn add(total: &mut usize, n: usize, maximum: usize, label: &'static str) -> Result<(), Error> {
    *total = total
        .checked_add(n)
        .filter(|n| *n <= maximum)
        .ok_or(Error::Limit(label))?;
    Ok(())
}
macro_rules! frame {
    ($name:ident, $family:literal) => {
        struct $name(Vec<u8>);
        impl CanonicalBody for $name {
            const DOMAIN: DomainTag = DomainTag::from_static("frankengit/generation/v1");
            const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static($family);
            const SCHEMA_MAJOR: u16 = 1;
            const SCHEMA_MINOR: u16 = 0;
            fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
                out.write_bytes($family, &self.0)
            }
            fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
                Ok(Self(input.read_bytes($family)?.to_vec()))
            }
        }
    };
}
frame!(TableFrame, "source-symbol-table");
frame!(ManifestFrame, "source-symbol-manifest");
frame!(ProfileFrame, "source-symbol-profile");
const fn decode_limits() -> DecodeLimits {
    DecodeLimits {
        frame_bytes: MAX_PAYLOAD as u64,
        byte_string_bytes: MAX_PAYLOAD as u64,
        elements: 100_000,
        depth: 8,
    }
}
fn root<B: CanonicalBody>(body: &B) -> Result<Digest, Error> {
    let id = body_id(&CryptoBodyIdentity, body)?;
    Ok(Digest::new(id.algorithm(), *id.digest()))
}
pub fn profile_root() -> Result<Digest, Error> {
    root(&ProfileFrame(
        [
            INDEX_PROFILE.as_bytes(),
            b"\0",
            super::PROFILE.as_bytes(),
            b"\0exact-byte-spans\0raw-path-order\0case-sensitive-name-directory",
        ]
        .concat(),
    ))
}
#[derive(Clone, Debug)]
pub struct Payload {
    pub root: Digest,
    pub bytes: Vec<u8>,
}
fn payload<B: CanonicalBody>(body: &B) -> Result<Payload, Error> {
    let bytes = encode_body(body)?;
    if bytes.len() > MAX_PAYLOAD {
        return Err(Error::Limit("payload bytes"));
    }
    Ok(Payload {
        root: root(body)?,
        bytes,
    })
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Source {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub format: Format,
    pub reference: RefName,
    pub head: RepositoryAuthorityHeadId,
    pub rcr: RepositoryCommitId,
    pub forge: Digest,
    pub commit: GitOid,
    pub tree: GitOid,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Document {
    pub path: Vec<u8>,
    pub blob: GitOid,
    pub root: Digest,
    pub encoded_bytes: usize,
    pub source_bytes: usize,
    pub declarations: usize,
    pub macros: usize,
    pub attributes: usize,
}
#[derive(Clone, Debug)]
pub struct Manifest {
    source: Source,
    documents: Vec<Document>,
    unsupported: usize,
    non_regular: usize,
}
impl Manifest {
    #[must_use]
    pub const fn source(&self) -> &Source {
        &self.source
    }
    #[must_use]
    pub fn documents(&self) -> &[Document] {
        &self.documents
    }
    #[must_use]
    pub const fn unsupported_files(&self) -> usize {
        self.unsupported
    }
    #[must_use]
    pub const fn non_regular_entries(&self) -> usize {
        self.non_regular
    }
    #[must_use]
    pub fn source_bytes(&self) -> usize {
        self.documents.iter().map(|d| d.source_bytes).sum()
    }
    #[must_use]
    pub fn declarations(&self) -> usize {
        self.documents.iter().map(|d| d.declarations).sum()
    }
    fn validate(&self, cancelled: &dyn Fn() -> bool) -> Result<(), Error> {
        check(cancelled)?;
        if self.documents.len() + self.unsupported > 20_000
            || self.non_regular > 50_000
            || [self.source.commit, self.source.tree]
                .iter()
                .any(|id| id.is_zero() || id.algorithm() != self.source.format)
        {
            return Err(Error::Invalid("manifest source/counters"));
        }
        let (mut bytes, mut declarations, mut encoded) = (0, 0, 0);
        let mut previous: Option<&[u8]> = None;
        for doc in &self.documents {
            check(cancelled)?;
            if !doc.path.ends_with(b".rs")
                || TreePath::parse_default(&doc.path).is_err()
                || previous.is_some_and(|p| p >= doc.path.as_slice())
                || doc.blob.is_zero()
                || doc.blob.algorithm() != self.source.format
                || doc.source_bytes > engine::MAX_FILE_BYTES
                || doc.macros > doc.source_bytes
                || doc.attributes > doc.source_bytes
                || doc.encoded_bytes == 0
                || doc.encoded_bytes > MAX_PAYLOAD
            {
                return Err(Error::Invalid("document catalog"));
            }
            add(
                &mut bytes,
                doc.source_bytes,
                64 * 1024 * 1024,
                "source bytes",
            )?;
            add(
                &mut declarations,
                doc.declarations,
                engine::MAX_DECLARATIONS,
                "declarations",
            )?;
            add(
                &mut encoded,
                doc.encoded_bytes,
                MAX_INDEX_BYTES,
                "index bytes",
            )?;
            previous = Some(&doc.path);
        }
        Ok(())
    }
    pub fn encode(&self, cancelled: &dyn Fn() -> bool) -> Result<Payload, Error> {
        self.validate(cancelled)?;
        let mut out = Encoder::new();
        write_source(&mut out, &self.source)?;
        out.write_digest(&profile_root()?)?;
        out.write_scalar(self.unsupported as u32);
        out.write_scalar(self.non_regular as u32);
        out.write_scalar(self.documents.len() as u32);
        for doc in &self.documents {
            check(cancelled)?;
            out.write_bytes("path", &doc.path)?;
            out.write_raw(doc.blob.as_bytes());
            out.write_digest(&doc.root)?;
            for n in [
                doc.encoded_bytes,
                doc.source_bytes,
                doc.declarations,
                doc.macros,
                doc.attributes,
            ] {
                out.write_scalar(n as u32);
            }
            if out.len() > MAX_PAYLOAD {
                return Err(Error::Limit("manifest bytes"));
            }
        }
        let result = payload(&ManifestFrame(out.into_bytes()))?;
        let total: usize = self.documents.iter().map(|d| d.encoded_bytes).sum();
        if total + result.bytes.len() > MAX_INDEX_BYTES {
            return Err(Error::Limit("index bytes"));
        }
        check(cancelled)?;
        Ok(result)
    }
    pub fn decode(
        raw: &[u8],
        expected: Digest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, Error> {
        check(cancelled)?;
        let body = decode_body::<ManifestFrame>(raw, decode_limits())?;
        if root(&body)? != expected || encode_body(&body)? != raw {
            return Err(Error::CommitmentMismatch);
        }
        let mut input = Decoder::new(&body.0, decode_limits());
        let source = read_source(&mut input)?;
        if input.read_digest()? != profile_root()? {
            return Err(Error::Invalid("parser/index profile"));
        }
        let unsupported = input.read_scalar::<u32>("unsupported files")? as usize;
        let non_regular = input.read_scalar::<u32>("non-regular entries")? as usize;
        let count = input.read_scalar::<u32>("documents")? as usize;
        if count > 20_000 || count > input.remaining() / 48 {
            return Err(Error::Limit("document count"));
        }
        let mut documents = Vec::with_capacity(count);
        for _ in 0..count {
            check(cancelled)?;
            let path = input.read_bytes("path")?.to_vec();
            let blob = read_oid(&mut input, source.format)?;
            let root = input.read_digest()?;
            documents.push(Document {
                path,
                blob,
                root,
                encoded_bytes: input.read_scalar::<u32>("table bytes")? as usize,
                source_bytes: input.read_scalar::<u32>("source bytes")? as usize,
                declarations: input.read_scalar::<u32>("declarations")? as usize,
                macros: input.read_scalar::<u32>("macros")? as usize,
                attributes: input.read_scalar::<u32>("attributes")? as usize,
            });
        }
        input.finish()?;
        let manifest = Self {
            source,
            documents,
            unsupported,
            non_regular,
        };
        if manifest.encode(cancelled)?.bytes != raw {
            return Err(Error::CommitmentMismatch);
        }
        Ok(manifest)
    }
}
fn write_source(out: &mut Encoder, s: &Source) -> Result<(), Error> {
    out.write_opaque_id(s.tenant.as_bytes());
    out.write_opaque_id(s.repository.as_bytes());
    out.write_opaque_id(s.incarnation.as_bytes());
    out.write_scalar(match s.format {
        Format::Sha1 => 1u8,
        Format::Sha256 => 2u8,
    });
    out.write_bytes("reference", s.reference.as_bytes())?;
    out.write_internal_object_id(s.head.as_internal_object_id())?;
    out.write_internal_object_id(s.rcr.as_internal_object_id())?;
    out.write_digest(&s.forge)?;
    out.write_raw(s.commit.as_bytes());
    out.write_raw(s.tree.as_bytes());
    Ok(())
}
fn read_oid(input: &mut Decoder<'_>, format: Format) -> Result<GitOid, Error> {
    Ok(match format {
        Format::Sha1 => {
            let mut b = [0; 20];
            b.copy_from_slice(input.take("OID", 20)?);
            GitOidSha1::from_bytes(b).into()
        }
        Format::Sha256 => {
            let mut b = [0; 32];
            b.copy_from_slice(input.take("OID", 32)?);
            GitOidSha256::from_bytes(b).into()
        }
    })
}
fn read_source(input: &mut Decoder<'_>) -> Result<Source, Error> {
    let tenant = TenantId::from_bytes(input.read_opaque_id("tenant")?);
    let repository = RepositoryId::from_bytes(input.read_opaque_id("repository")?);
    let incarnation = RepositoryIncarnationId::from_bytes(input.read_opaque_id("incarnation")?);
    let format = match input.read_scalar::<u8>("object format")? {
        1 => Format::Sha1,
        2 => Format::Sha256,
        _ => return Err(Error::Invalid("object format")),
    };
    let reference = input.read_ref_name()?;
    let head =
        RepositoryAuthorityHeadId::from_internal_object_id(input.read_internal_object_id()?)?;
    let rcr = RepositoryCommitId::from_internal_object_id(input.read_internal_object_id()?)?;
    let forge = input.read_digest()?;
    let commit = read_oid(input, format)?;
    let tree = read_oid(input, format)?;
    Ok(Source {
        tenant,
        repository,
        incarnation,
        format,
        reference,
        head,
        rcr,
        forge,
        commit,
        tree,
    })
}
fn table_payload(
    blob: GitOid,
    table: &table::Table,
    cancelled: &dyn Fn() -> bool,
) -> Result<Payload, Error> {
    let mut out = Encoder::new();
    out.write_scalar(match blob.algorithm() {
        Format::Sha1 => 1u8,
        Format::Sha256 => 2u8,
    });
    out.write_raw(blob.as_bytes());
    out.write_bytes("table", &table.encode(cancelled)?)?;
    payload(&TableFrame(out.into_bytes()))
}
fn decode_table(
    doc: &Document,
    raw: &[u8],
    cancelled: &dyn Fn() -> bool,
) -> Result<table::Table, Error> {
    check(cancelled)?;
    if raw.len() != doc.encoded_bytes {
        return Err(Error::CommitmentMismatch);
    }
    let frame = decode_body::<TableFrame>(raw, decode_limits())?;
    if root(&frame)? != doc.root || encode_body(&frame)? != raw {
        return Err(Error::CommitmentMismatch);
    }
    let mut input = Decoder::new(&frame.0, decode_limits());
    let format = match input.read_scalar::<u8>("format")? {
        1 => Format::Sha1,
        2 => Format::Sha256,
        _ => return Err(Error::Invalid("object format")),
    };
    if read_oid(&mut input, format)? != doc.blob {
        return Err(Error::CommitmentMismatch);
    }
    let table = table::Table::decode(input.read_bytes("table")?, cancelled)?;
    input.finish()?;
    if table.source_bytes != doc.source_bytes
        || table.rows().len() != doc.declarations
        || table.macros != doc.macros
        || table.attributes != doc.attributes
    {
        return Err(Error::CommitmentMismatch);
    }
    Ok(table)
}

/// Complete scanner inventory. It cannot be truncated by max_matches.
pub struct Corpus {
    source: SourceSearchReport,
    documents: Vec<Document>,
    tables: Vec<Payload>,
    unsupported: usize,
    reused: usize,
    reuse_scope: Option<Source>,
    names: Vec<directory::Names>,
}
impl Corpus {
    #[must_use]
    pub const fn empty(source: SourceSearchReport) -> Self {
        Self {
            source,
            documents: Vec::new(),
            tables: Vec::new(),
            unsupported: 0,
            reused: 0,
            reuse_scope: None,
            names: Vec::new(),
        }
    }
    pub fn finish(
        self,
        source: Source,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(Manifest, Vec<Payload>), Error> {
        if source.repository != self.source.repository
            || source.rcr != self.source.source_rcr
            || source.commit != self.source.source_commit
            || source.tree != self.source.source_tree
        {
            return Err(Error::Invalid("native source binding"));
        }
        if self
            .reuse_scope
            .as_ref()
            .is_some_and(|prior| !reuse::same_namespace(prior, &source))
        {
            return Err(Error::Invalid("reuse namespace"));
        }
        let manifest = Manifest {
            source,
            documents: self.documents,
            unsupported: self.unsupported,
            non_regular: self.source.non_regular_entries,
        };
        manifest.encode(cancelled)?;
        Ok((manifest, self.tables))
    }
    /// Add the optional accelerated layout without changing v1 table/manifest
    /// identity or reducing its admitted corpus. Only directory-size overflow
    /// selects legacy layout; integrity, source and cancellation errors refuse.
    pub fn finish_with_directory(
        mut self,
        source: Source,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(Manifest, Vec<Payload>, Option<Payload>), Error> {
        let names = std::mem::take(&mut self.names);
        let (manifest, tables) = self.finish(source, cancelled)?;
        let directory = NameDirectory::build(&manifest, &names, cancelled)?;
        let directory = match directory.encode(&manifest, cancelled) {
            Ok(payload) => Some(payload),
            Err(Error::Limit("directory bytes")) => None,
            Err(error) => return Err(error),
        };
        check(cancelled)?;
        Ok((manifest, tables, directory))
    }
    #[must_use]
    pub const fn source(&self) -> &SourceSearchReport {
        &self.source
    }
    /// Current paths whose tables were reused without fetching/scanning blobs.
    #[must_use]
    pub const fn reused_files(&self) -> usize {
        self.reused
    }
}
pub fn prepare<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>,
    source: &S,
    capability: &mut TreeCapability,
    now: u64,
    limits: SearchLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<Corpus, Error> {
    prepare_with_reuse(base, source, capability, now, limits, cancelled, None)
}
/// Enumerate the complete CURRENT tree and authorize each path before reuse.
/// Resource ceilings apply to the whole resulting corpus, not just changed
/// blobs. Only newly scanned tables are returned for body-first publication.
pub fn prepare_with_reuse<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>,
    source: &S,
    capability: &mut TreeCapability,
    now: u64,
    limits: SearchLimits,
    cancelled: &dyn Fn() -> bool,
    reuse: Option<&VerifiedReuse>,
) -> Result<Corpus, Error> {
    limits.validate()?;
    check(cancelled)?;
    let format = super::oid::<A>(base.base_commit_oid())?.algorithm();
    if reuse.is_some_and(|prior| {
        prior.source().repository != base.repository_id() || prior.source().format != format
    }) {
        return Err(Error::Invalid("reuse source format/repository"));
    }
    capability
        .authorize_root(now)
        .map_err(SearchError::Capability)?;
    let scope = SourceQuery::new(b"symbols", SearchCase::Exact, &[])?;
    let mut found = Discovery {
        files: BTreeMap::new(),
        entries: 0,
        excluded: 0,
    };
    let mut context = DiscoveryContext {
        base,
        source,
        capability,
        now,
        query: &scope,
        limits,
        cancelled,
    };
    discover(&mut context, None, 0, &mut found)?;
    let mut corpus = Corpus::empty(SourceSearchReport {
        repository: base.repository_id(),
        source_rcr: base.base_rcr_id(),
        source_commit: super::oid::<A>(base.base_commit_oid())?,
        source_tree: super::oid::<A>(base.base_tree_oid())?,
        matches: Vec::new(),
        completion: SearchCompletion::Complete,
        files_selected: found.files.len(),
        files_read: 0,
        bytes_read: 0,
        bytes_searched: 0,
        non_regular_entries: found.excluded,
    });
    let mut files: Vec<_> = found.files.into_iter().collect();
    files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut budget =
        engine::Budget::new(engine::MAX_WORK).map_err(|e| Error::Table(table::Error::Syntax(e)))?;
    corpus.reuse_scope = reuse.map(|prior| prior.source().clone());
    let (mut encoded, mut referenced, mut declarations) = (0, 0, 0);
    for (path, blob) in files {
        check(cancelled)?;
        if !path.as_bytes().ends_with(b".rs") {
            corpus.unsupported += 1;
            continue;
        }
        let grant = capability
            .authorize_read(&path, now)
            .map_err(SearchError::Capability)?;
        let native = super::oid::<A>(&blob)?;
        if let Some((prior, previous)) =
            reuse.and_then(|prior| prior.document(&native).map(|doc| (prior, doc)))
        {
            if previous.source_bytes > limits.max_file_bytes {
                return Err(Error::Limit("source file bytes"));
            }
            add(
                &mut referenced,
                previous.source_bytes,
                limits.max_total_bytes,
                "source bytes",
            )?;
            add(
                &mut encoded,
                previous.encoded_bytes,
                MAX_INDEX_BYTES,
                "index bytes",
            )?;
            add(
                &mut declarations,
                previous.declarations,
                engine::MAX_DECLARATIONS,
                "declarations",
            )?;
            let mut doc = previous.clone();
            doc.path = path.as_bytes().to_vec();
            corpus.names.push(prior.names(&native)?.clone());
            corpus.documents.push(doc);
            corpus.reused += 1;
            continue;
        }
        let bytes = base
            .read_object(source, &blob, GitObjectKind::Blob, &grant)
            .map_err(|e| SearchError::Source(Box::new(e)))?;
        capability
            .charge_fetch(bytes.len() as u64)
            .map_err(SearchError::Capability)?;
        if bytes.len() > limits.max_file_bytes {
            return Err(Error::Limit("source file bytes"));
        }
        add(
            &mut referenced,
            bytes.len(),
            limits.max_total_bytes,
            "source bytes",
        )?;
        add(
            &mut corpus.source.bytes_read,
            bytes.len(),
            limits.max_total_bytes,
            "source bytes",
        )?;
        let blob = native;
        if git_object_id(blob.algorithm(), GitObjectKind::Blob, &bytes) != blob {
            return Err(Error::CommitmentMismatch);
        }
        let table = table::Table::build(&bytes, &mut budget, cancelled)?;
        add(
            &mut declarations,
            table.rows().len(),
            engine::MAX_DECLARATIONS,
            "declarations",
        )?;
        let payload = table_payload(blob, &table, cancelled)?;
        add(
            &mut encoded,
            payload.bytes.len(),
            MAX_INDEX_BYTES,
            "index bytes",
        )?;
        corpus.names.push(directory::summarize(&table, cancelled)?);
        corpus.documents.push(Document {
            path: path.as_bytes().to_vec(),
            blob,
            root: payload.root,
            encoded_bytes: payload.bytes.len(),
            source_bytes: bytes.len(),
            declarations: table.rows().len(),
            macros: table.macros,
            attributes: table.attributes,
        });
        corpus.tables.push(payload);
        corpus.source.files_read += 1;
        corpus.source.bytes_searched += bytes.len();
    }
    check(cancelled)?;
    Ok(corpus)
}

#[derive(Clone, Debug)]
pub struct Report {
    pub source: Source,
    pub matches: Vec<SymbolMatch>,
    pub complete: bool,
    pub generation: InternalObjectId,
    pub generation_number: u64,
    pub indexed_files: usize,
    pub indexed_declarations: usize,
    pub indexed_source_bytes: usize,
    pub unsupported_language_files: usize,
    pub non_regular_entries: usize,
    pub tables_read: usize,
    pub payload_bytes_read: usize,
    pub work_units: u64,
}
/// One shared query budget and result buffer across verified per-blob tables.
pub struct Query {
    query: SymbolQuery,
    maximum_results: usize,
    work: table::Work,
    matches: Vec<SymbolMatch>,
    result_bytes: usize,
    more: bool,
    tables: usize,
}
impl Query {
    pub fn new(query: &SymbolQuery, maximum_results: usize) -> Result<Self, Error> {
        if maximum_results == 0 || maximum_results > 4096 {
            return Err(Error::Limit("results"));
        }
        Ok(Self {
            query: query.clone(),
            maximum_results,
            work: table::Work::new(query.maximum_work())?,
            matches: Vec::new(),
            result_bytes: 0,
            more: false,
            tables: 0,
        })
    }
    #[must_use]
    pub fn includes(&self, doc: &Document) -> bool {
        let prefixes = self.query.source_scope().prefixes();
        prefixes.is_empty()
            || prefixes.iter().any(|prefix| {
                doc.path == prefix.as_bytes()
                    || (doc.path.starts_with(prefix.as_bytes())
                        && doc.path.get(prefix.as_bytes().len()) == Some(&b'/'))
            })
    }
    /// Returns true only after observing one extra matching declaration.
    pub fn observe(
        &mut self,
        doc: &Document,
        raw: &[u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<bool, Error> {
        self.work.charge(raw.len() as u64, cancelled)?;
        let table = decode_table(doc, raw, cancelled)?;
        self.tables += 1;
        let positions = table.lookup(
            self.query.name(),
            self.query.mode() == SymbolMatchMode::Prefix,
            self.query.kinds(),
            &mut self.work,
            cancelled,
        )?;
        for position in positions {
            check(cancelled)?;
            if self.matches.len() == self.maximum_results {
                self.more = true;
                return Ok(true);
            }
            let row = &table.rows()[position];
            add(
                &mut self.result_bytes,
                doc.path.len() + row.name.len() + row.excerpt.len() + 96,
                2 * 1024 * 1024,
                "result bytes",
            )?;
            self.matches.push(SymbolMatch {
                name: row.name.clone(),
                kind: row.kind,
                raw_identifier: row.raw,
                location: SourceMatch {
                    path: doc.path.clone(),
                    blob: doc.blob,
                    byte_offset: row.offset,
                    line: row.line,
                    byte_column: row.column,
                    match_length: row.name.len(),
                    excerpt_offset: row.excerpt_offset,
                    excerpt: row.excerpt.clone(),
                },
            });
        }
        Ok(false)
    }
    #[must_use]
    pub fn finish(
        self,
        manifest: &Manifest,
        generation: InternalObjectId,
        generation_number: u64,
        payload_bytes: usize,
    ) -> Report {
        Report {
            source: manifest.source.clone(),
            matches: self.matches,
            complete: !self.more,
            generation,
            generation_number,
            indexed_files: manifest.documents.len(),
            indexed_declarations: manifest.declarations(),
            indexed_source_bytes: manifest.source_bytes(),
            unsupported_language_files: manifest.unsupported,
            non_regular_entries: manifest.non_regular,
            tables_read: self.tables,
            payload_bytes_read: payload_bytes,
            work_units: self.work.used,
        }
    }
}
#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;

#[path = "index_directory.rs"]
mod directory;
