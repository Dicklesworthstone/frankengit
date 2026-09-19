use super::*;
use crate::lexical::encoding::{count, decode_limits, namespace_read, namespace_write, oid_read, payload_root};
use fgit_codec::{CanonicalBody, CodecRefusal, Decoder, Encoder, decode_body, encode_body};
use fgit_types::DomainTag;

macro_rules! frame {
    ($name:ident, $family:literal) => {
        struct $name(Vec<u8>);
        impl CanonicalBody for $name {
            const DOMAIN: DomainTag = DomainTag::from_static("frankengit/generation/v1");
            const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static($family);
            const SCHEMA_MAJOR: u16 = 1;
            const SCHEMA_MINOR: u16 = 0;
            fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> { out.write_bytes($family, &self.0) }
            fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> { Ok(Self(input.read_bytes($family)?.to_vec())) }
        }
    };
}
frame!(ManifestFrame, "source-lexical-manifest");
frame!(DocumentsFrame, "source-lexical-documents");
frame!(PostingsFrame, "source-lexical-postings");
frame!(EvidenceFrame, "source-lexical-evidence");
frame!(ProfileFrame, "source-lexical-profile");

pub(super) fn schema() -> SchemaId { SchemaId::new(SchemaFamily::from_static("source-lexical-index"), 1, 0) }
pub(super) fn profile_root() -> Result<Digest, LexicalError> {
    payload_root(&ProfileFrame(b"ascii-word-postings-v1\0ASCII-alnum-underscore\0ASCII-fold\0first-byte-span\0content,path\0AND\0absolute-document-id-order".to_vec()))
}
#[derive(Clone, Debug)]
pub(super) struct Payload { pub kind: &'static str, pub root: Digest, pub bytes: Vec<u8> }
fn payload<B: CanonicalBody>(kind: &'static str, body: B) -> Result<Payload, IndexError> {
    let bytes = encode_body(&body)?;
    if bytes.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("metadata bytes").into()); }
    Ok(Payload { kind, root: payload_root(&body)?, bytes })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SegmentRef {
    pub root: Digest,
    pub bytes: u32,
    pub first_id: u64,
    pub last_id: u64,
    first_path: Vec<u8>,
    last_path: Vec<u8>,
    documents: u32,
    source_bytes: u64,
    terms: u32,
    postings: u32,
}
impl SegmentRef {
    pub(super) fn new(segment: &LexicalSegment, root: Digest, bytes: usize) -> Result<Self, IndexError> {
        let first = segment.documents().first().ok_or(LexicalError::Invalid("empty segment"))?;
        let last = segment.documents().last().ok_or(LexicalError::Invalid("empty segment"))?;
        Ok(Self { root, bytes: bytes as u32, first_id: first.id, last_id: last.id,
            first_path: first.path.clone(), last_path: last.path.clone(), documents: segment.documents().len() as u32,
            source_bytes: segment.documents().iter().map(|d| u64::from(d.content_bytes)).sum(),
            terms: segment.term_count() as u32, postings: segment.posting_count() as u32 })
    }
    fn write(&self, out: &mut Encoder) -> Result<(), IndexError> {
        out.write_digest(&self.root)?; out.write_scalar(self.bytes);
        out.write_scalar(self.first_id); out.write_scalar(self.last_id);
        out.write_bytes("first path", &self.first_path)?; out.write_bytes("last path", &self.last_path)?;
        out.write_scalar(self.documents); out.write_scalar(self.source_bytes);
        out.write_scalar(self.terms); out.write_scalar(self.postings); Ok(())
    }
    fn read(input: &mut Decoder<'_>) -> Result<Self, IndexError> {
        Ok(Self { root: input.read_digest()?, bytes: input.read_scalar("segment bytes")?,
            first_id: input.read_scalar("first ID")?, last_id: input.read_scalar("last ID")?,
            first_path: input.read_bytes("first path")?.to_vec(), last_path: input.read_bytes("last path")?.to_vec(),
            documents: input.read_scalar("document count")?, source_bytes: input.read_scalar("source bytes")?,
            terms: input.read_scalar("term count")?, postings: input.read_scalar("posting count")? })
    }
}

#[derive(Clone, Debug)]
pub(super) struct Manifest {
    pub source: LexicalSource,
    pub segments: Vec<SegmentRef>,
    pub non_regular_entries: usize,
}
impl Manifest {
    pub(super) fn new(source: LexicalSource, segments: Vec<SegmentRef>, non_regular_entries: usize) -> Result<Self, IndexError> {
        if [source.commit, source.tree].iter().any(|id| id.is_zero() || id.algorithm() != source.namespace.object_format) {
            return Err(LexicalError::NativeIdentityMismatch.into());
        }
        if segments.len() > MAX_SEGMENTS || non_regular_entries > 50_000 { return Err(LexicalError::Limit("index entries").into()); }
        let (mut documents, mut bytes, mut source_bytes) = (0usize, 0usize, 0usize);
        let mut previous: Option<&SegmentRef> = None;
        for entry in &segments {
            if entry.bytes == 0 || entry.bytes as usize > MAX_SEGMENT_BYTES || entry.documents == 0 || entry.documents as usize > MAX_DOCUMENTS
                || entry.first_id == 0 || entry.first_id > entry.last_id
                || entry.last_id - entry.first_id < u64::from(entry.documents - 1)
                || !path_valid(&entry.first_path) || !path_valid(&entry.last_path) || entry.first_path > entry.last_path
                || entry.terms as usize > MAX_TERMS || entry.postings as usize > MAX_POSTINGS || entry.terms > entry.postings
                || entry.source_bytes > MAX_SOURCE_BYTES as u64
                || previous.is_some_and(|old| old.last_id >= entry.first_id || old.last_path >= entry.first_path)
            { return Err(LexicalError::Invalid("segment catalog").into()); }
            bounded_add(&mut documents, entry.documents as usize, MAX_INDEX_DOCUMENTS, "indexed documents")?;
            bounded_add(&mut bytes, entry.bytes as usize, MAX_INDEX_BYTES, "index bytes")?;
            bounded_add(&mut source_bytes, entry.source_bytes as usize, MAX_SOURCE_BYTES, "source bytes")?;
            previous = Some(entry);
        }
        Ok(Self { source, segments, non_regular_entries })
    }
    pub(super) fn document_count(&self) -> usize { self.segments.iter().map(|s| s.documents as usize).sum() }
    pub(super) fn source_bytes(&self) -> usize { self.segments.iter().map(|s| s.source_bytes as usize).sum() }
    pub(super) fn payloads(&self, live: &mut impl FnMut() -> bool) -> Result<Vec<Payload>, IndexError> {
        check(live)?;
        let mut documents = Encoder::new(); namespace_write(&mut documents, self.source.namespace);
        documents.write_scalar(self.segments.len() as u32);
        let mut postings = Encoder::new(); namespace_write(&mut postings, self.source.namespace);
        postings.write_scalar(self.segments.len() as u32);
        for segment in &self.segments {
            check(live)?;
            // The catalogs identify two projections of the SAME immutable
            // segment bodies; each has a distinct canonical schema/root.
            documents.write_digest(&segment.root)?; documents.write_scalar(segment.documents);
            documents.write_scalar(segment.first_id); documents.write_scalar(segment.last_id);
            documents.write_bytes("first path", &segment.first_path)?; documents.write_bytes("last path", &segment.last_path)?;
            postings.write_digest(&segment.root)?; postings.write_scalar(segment.terms); postings.write_scalar(segment.postings);
            if documents.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("document catalog bytes").into()); }
        }
        let mut evidence = Encoder::new(); source_write(&mut evidence, &self.source)?;
        evidence.write_digest(&profile_root()?)?; evidence.write_scalar(self.document_count() as u64);
        evidence.write_scalar(self.source_bytes() as u64); evidence.write_scalar(self.non_regular_entries as u64);
        evidence.write_scalar(self.segments.len() as u32);
        let mut manifest = Encoder::new(); source_write(&mut manifest, &self.source)?;
        manifest.write_scalar(self.non_regular_entries as u32); manifest.write_scalar(self.segments.len() as u32);
        for segment in &self.segments {
            check(live)?; segment.write(&mut manifest)?;
            if manifest.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("manifest bytes").into()); }
        }
        let result = vec![payload("documents", DocumentsFrame(documents.into_bytes()))?,
            payload("postings", PostingsFrame(postings.into_bytes()))?, payload("evidence", EvidenceFrame(evidence.into_bytes()))?,
            payload("manifest", ManifestFrame(manifest.into_bytes()))?];
        check(live)?; Ok(result)
    }
    pub(super) fn decode(raw: &[u8], expected: Digest, namespace: LexicalNamespace,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, IndexError> {
        check(live)?;
        if raw.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("manifest bytes").into()); }
        let frame = decode_body::<ManifestFrame>(raw, decode_limits())?;
        if payload_root(&frame)? != expected || encode_body(&frame)? != raw { return Err(LexicalError::CommitmentMismatch.into()); }
        let mut input = Decoder::new(&frame.0, decode_limits());
        let source = source_read(&mut input)?;
        if source.namespace != namespace { return Err(LexicalError::NamespaceMismatch.into()); }
        let non_regular_entries = input.read_scalar::<u32>("non-regular entries")? as usize;
        let n = count(&mut input, MAX_SEGMENTS, 48, "segments")?;
        let mut segments = Vec::with_capacity(n);
        for _ in 0..n { check(live)?; segments.push(SegmentRef::read(&mut input)?); }
        input.finish()?;
        let manifest = Self::new(source, segments, non_regular_entries)?;
        check(live)?; Ok(manifest)
    }
}
fn source_write(out: &mut Encoder, source: &LexicalSource) -> Result<(), IndexError> {
    namespace_write(out, source.namespace); out.write_bytes("source ref", source.reference.as_bytes())?;
    out.write_internal_object_id(source.source_head.as_internal_object_id())?;
    out.write_internal_object_id(source.source_rcr.as_internal_object_id())?;
    out.write_digest(&source.forge_position_root)?;
    out.write_raw(source.commit.as_bytes()); out.write_raw(source.tree.as_bytes()); Ok(())
}
fn source_read(input: &mut Decoder<'_>) -> Result<LexicalSource, IndexError> {
    let namespace = namespace_read(input)?;
    let reference = input.read_ref_name()?;
    let source_head = RepositoryAuthorityHeadId::from_internal_object_id(input.read_internal_object_id()?)?;
    let source_rcr = RepositoryCommitId::from_internal_object_id(input.read_internal_object_id()?)?;
    let forge_position_root = input.read_digest()?;
    let commit = oid_read(input, namespace.object_format)?; let tree = oid_read(input, namespace.object_format)?;
    Ok(LexicalSource { namespace, reference, source_head, source_rcr, forge_position_root, commit, tree })
}
