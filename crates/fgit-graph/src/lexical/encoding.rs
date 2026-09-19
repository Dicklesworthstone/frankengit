//! One registered identity domain, distinct versioned payload families. The
//! inner payload uses the same canonical scalar/byte codec, not ambient serde.
use super::*;
use fgit_codec::{CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits,
    Decoder, Encoder, body_id, decode_body, encode_body};
use fgit_types::{DomainTag, GitOidSha1, GitOidSha256, SchemaFamily};

#[derive(Clone, Debug)]
struct SegmentFrame(Vec<u8>);
impl CanonicalBody for SegmentFrame {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/generation/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("source-lexical-segment");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;
    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> { out.write_bytes("lexical.segment", &self.0) }
    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self(input.read_bytes("lexical.segment")?.to_vec()))
    }
}

pub(super) const fn decode_limits() -> DecodeLimits {
    DecodeLimits { frame_bytes: MAX_SEGMENT_BYTES as u64, byte_string_bytes: MAX_SEGMENT_BYTES as u64,
        elements: MAX_POSTINGS as u64, depth: 8 }
}
pub(super) fn namespace_write(out: &mut Encoder, scope: LexicalNamespace) {
    out.write_opaque_id(scope.tenant.as_bytes()); out.write_opaque_id(scope.repository.as_bytes());
    out.write_opaque_id(scope.incarnation.as_bytes());
    out.write_scalar(match scope.object_format { GitHashAlgorithm::Sha1 => 1u8, GitHashAlgorithm::Sha256 => 2u8 });
}
pub(super) fn namespace_read(input: &mut Decoder<'_>) -> Result<LexicalNamespace, LexicalError> {
    let tenant = TenantId::from_bytes(input.read_opaque_id("lexical.tenant")?);
    let repository = RepositoryId::from_bytes(input.read_opaque_id("lexical.repository")?);
    let incarnation = RepositoryIncarnationId::from_bytes(input.read_opaque_id("lexical.incarnation")?);
    let object_format = match input.read_scalar::<u8>("lexical.object_format")? {
        1 => GitHashAlgorithm::Sha1, 2 => GitHashAlgorithm::Sha256,
        _ => return Err(LexicalError::Invalid("object format")),
    };
    Ok(LexicalNamespace { tenant, repository, incarnation, object_format })
}
pub(super) fn oid_read(input: &mut Decoder<'_>, format: GitHashAlgorithm) -> Result<GitOid, LexicalError> {
    let oid = match format {
        GitHashAlgorithm::Sha1 => {
            let mut bytes = [0; 20]; bytes.copy_from_slice(input.take("lexical.oid", 20)?);
            GitOidSha1::from_bytes(bytes).into()
        }
        GitHashAlgorithm::Sha256 => {
            let mut bytes = [0; 32]; bytes.copy_from_slice(input.take("lexical.oid", 32)?);
            GitOidSha256::from_bytes(bytes).into()
        }
    };
    Ok(oid)
}
pub(super) fn count(input: &mut Decoder<'_>, maximum: usize, minimum_bytes: usize,
    name: &'static str,
) -> Result<usize, LexicalError> {
    let n = input.read_scalar::<u32>(name)? as usize;
    if n > maximum || n > input.remaining() / minimum_bytes { return Err(LexicalError::Limit(name)); }
    Ok(n)
}
pub(super) fn payload_root<B: CanonicalBody>(body: &B) -> Result<Digest, LexicalError> {
    let id = body_id(&CryptoBodyIdentity, body)?;
    Ok(Digest::new(id.algorithm(), *id.digest()))
}

fn frame(segment: &LexicalSegment, live: &mut impl FnMut() -> bool) -> Result<SegmentFrame, LexicalError> {
    check(live)?;
    let mut out = Encoder::new(); namespace_write(&mut out, segment.namespace);
    out.write_scalar(segment.documents.len() as u32);
    let mut total = 0usize;
    for document in &segment.documents {
        check(live)?;
        bounded_add(&mut total, document.content_bytes as usize, MAX_SOURCE_BYTES, "source bytes")?;
        out.write_scalar(document.id); out.write_bytes("lexical.path", &document.path)?;
        out.write_raw(document.blob.as_bytes()); out.write_scalar(document.content_bytes);
        if out.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("segment bytes")); }
    }
    out.write_scalar(segment.terms.len() as u32);
    for (term, columns) in &segment.terms {
        check(live)?;
        out.write_scalar(match term.channel { LexicalChannel::Content => 0u8, LexicalChannel::Path => 1u8 });
        out.write_bytes("lexical.term", &term.bytes)?; out.write_scalar(columns.documents.len() as u32);
        for chunk in columns.documents.chunks(256) {
            check(live)?; for id in chunk { out.write_scalar(*id); }
        }
        for chunk in columns.offsets.chunks(256) {
            check(live)?; for offset in chunk { out.write_scalar(*offset); }
        }
        if out.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("segment bytes")); }
    }
    check(live)?;
    Ok(SegmentFrame(out.into_bytes()))
}
pub(super) fn encode(segment: &LexicalSegment, live: &mut impl FnMut() -> bool) -> Result<Vec<u8>, LexicalError> {
    let bytes = encode_body(&frame(segment, live)?)?;
    if bytes.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("segment bytes")); }
    check(live)?;
    Ok(bytes)
}
pub(super) fn root(segment: &LexicalSegment, live: &mut impl FnMut() -> bool) -> Result<Digest, LexicalError> {
    let frame = frame(segment, live)?;
    if encode_body(&frame)?.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("segment bytes")); }
    let root = payload_root(&frame)?; check(live)?; Ok(root)
}
pub(super) fn decode(bytes: &[u8], expected: Digest, namespace: LexicalNamespace,
    live: &mut impl FnMut() -> bool,
) -> Result<LexicalSegment, LexicalError> {
    check(live)?;
    if bytes.len() > MAX_SEGMENT_BYTES { return Err(LexicalError::Limit("segment bytes")); }
    let frame = decode_body::<SegmentFrame>(bytes, decode_limits())?;
    if payload_root(&frame)? != expected || encode_body(&frame)? != bytes { return Err(LexicalError::CommitmentMismatch); }
    check(live)?;
    let mut input = Decoder::new(&frame.0, decode_limits());
    if namespace_read(&mut input)? != namespace { return Err(LexicalError::NamespaceMismatch); }
    let n = count(&mut input, MAX_DOCUMENTS, 17 + namespace.object_format.digest_len(), "document count")?;
    if n == 0 { return Err(LexicalError::Invalid("empty segment")); }
    let mut documents: Vec<IndexedDocument> = Vec::with_capacity(n);
    let mut total_source = 0usize;
    for _ in 0..n {
        check(live)?;
        let id = input.read_scalar::<u64>("document ID")?;
        let path = input.read_bytes("document path")?;
        if id == 0 || !path_valid(path) || documents.last().is_some_and(|d| d.id >= id || d.path.as_slice() >= path) {
            return Err(LexicalError::Invalid("document order"));
        }
        let blob = oid_read(&mut input, namespace.object_format)?;
        if blob.is_zero() { return Err(LexicalError::Invalid("zero blob")); }
        let content_bytes = input.read_scalar::<u32>("content length")?;
        if content_bytes as usize > MAX_FILE_BYTES { return Err(LexicalError::Limit("file bytes")); }
        bounded_add(&mut total_source, content_bytes as usize, MAX_SOURCE_BYTES, "source bytes")?;
        documents.push(IndexedDocument { id, path: path.to_vec(), blob, content_bytes });
    }
    let n = count(&mut input, MAX_TERMS, 22, "term count")?;
    let mut terms: BTreeMap<Term, Postings> = BTreeMap::new();
    let mut total_postings = 0usize;
    for _ in 0..n {
        check(live)?;
        let channel = match input.read_scalar::<u8>("term channel")? {
            0 => LexicalChannel::Content, 1 => LexicalChannel::Path,
            _ => return Err(LexicalError::Invalid("term channel")),
        };
        let bytes = input.read_bytes("term bytes")?;
        if bytes.is_empty() || bytes.len() > MAX_TERM_BYTES || bytes.iter().any(|b| !word(*b) || b.is_ascii_uppercase()) {
            return Err(LexicalError::Invalid("term bytes"));
        }
        let term = Term { channel, bytes: bytes.to_vec() };
        if terms.last_key_value().is_some_and(|(last, _)| last >= &term) { return Err(LexicalError::Invalid("dictionary order")); }
        let n = count(&mut input, MAX_POSTINGS - total_postings, 12, "posting count")?;
        if n == 0 { return Err(LexicalError::Invalid("empty posting list")); }
        total_postings += n;
        let mut columns = Postings { documents: Vec::with_capacity(n), offsets: Vec::with_capacity(n) };
        for _ in 0..n {
            check(live)?;
            let id = input.read_scalar::<u64>("posting document")?;
            if columns.documents.last().is_some_and(|last| *last >= id)
                || documents.binary_search_by_key(&id, |d| d.id).is_err()
            { return Err(LexicalError::Invalid("posting document order")); }
            columns.documents.push(id);
        }
        for id in &columns.documents {
            check(live)?;
            let offset = input.read_scalar::<u32>("posting offset")?;
            let at = documents.binary_search_by_key(id, |d| d.id).map_err(|_| LexicalError::Invalid("posting document"))?;
            let length = match channel { LexicalChannel::Content => documents[at].content_bytes as usize,
                LexicalChannel::Path => documents[at].path.len() };
            if (offset as usize).checked_add(term.bytes.len()).is_none_or(|end| end > length) {
                return Err(LexicalError::Invalid("posting span"));
            }
            columns.offsets.push(offset);
        }
        terms.insert(term, columns);
    }
    input.finish()?; check(live)?;
    Ok(LexicalSegment { namespace, documents, terms })
}
