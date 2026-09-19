//! Immutable document/term graphs for bounded, model-free source retrieval.
//!
//! `ascii-word-postings-v1` indexes complete ASCII alphanumeric/underscore
//! tokens, folding A-Z only. Content and path are separate channels. A posting
//! retains the first original byte span for a term in a document, not a claim
//! about symbol identity, substring matches, Unicode words or phrase positions.
//! Documents and results have increasing absolute IDs and raw-byte path order.
//! This derived graph cannot authorize a read or publish repository state.

mod encoding;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, btree_map::Entry};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{Digest, GitHashAlgorithm, GitOid, RepositoryId, RepositoryIncarnationId, TenantId};

pub const PROFILE: &str = "ascii-word-postings-v1";
pub const MAX_SEGMENT_BYTES: usize = 1024 * 1024;
pub const MAX_DOCUMENTS: usize = 2048;
pub const MAX_POSTINGS: usize = 65_536;
pub const MAX_TERMS: usize = 32_768;
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TERM_BYTES: usize = 128;
pub const MAX_QUERY_TERMS: usize = 32;
pub const MAX_RESULTS: usize = 4096;
pub const MAX_WORK: u64 = 16 * 1024 * 1024;
pub const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;

/// Isolation binding of every immutable payload. The caller must authorize this
/// entire namespace before accessing index data; path filters only narrow it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LexicalNamespace {
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: RepositoryIncarnationId,
    pub object_format: GitHashAlgorithm,
}

/// Bytes from an already authorized source selection. The builder independently
/// checks the native blob ID; it cannot prove that a caller enumerated a tree
/// completely or was authorized to read it.
pub struct SourceDocument<'a> {
    pub path: &'a [u8],
    pub blob: GitOid,
    pub content: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LexicalChannel { Content, Path }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedDocument {
    pub id: u64,
    pub path: Vec<u8>,
    pub blob: GitOid,
    pub content_bytes: u32,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Term { channel: LexicalChannel, bytes: Vec<u8> }

/// Parallel, equally sized columns, strictly ordered by absolute document ID.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Postings { documents: Vec<u64>, offsets: Vec<u32> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalSegment {
    namespace: LexicalNamespace,
    documents: Vec<IndexedDocument>,
    terms: BTreeMap<Term, Postings>,
}

#[derive(Debug)]
pub enum LexicalError {
    Invalid(&'static str),
    Limit(&'static str),
    Cancelled,
    NativeIdentityMismatch,
    NamespaceMismatch,
    CommitmentMismatch,
    Codec(fgit_codec::CodecRefusal),
}
impl From<fgit_codec::CodecRefusal> for LexicalError {
    fn from(error: fgit_codec::CodecRefusal) -> Self { Self::Codec(error) }
}
impl std::fmt::Display for LexicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "lexical index refused: {self:?}") }
}
impl std::error::Error for LexicalError {}

fn check(live: &mut impl FnMut() -> bool) -> Result<(), LexicalError> {
    if live() { Ok(()) } else { Err(LexicalError::Cancelled) }
}
fn bounded_add(value: &mut usize, added: usize, limit: usize, name: &'static str) -> Result<(), LexicalError> {
    *value = value.checked_add(added).filter(|n| *n <= limit).ok_or(LexicalError::Limit(name))?;
    Ok(())
}
fn path_valid(path: &[u8]) -> bool {
    !path.is_empty() && path.len() <= 4096 && !path.contains(&0)
        && path.split(|byte| *byte == b'/').all(|part| !part.is_empty() && part != b"." && part != b"..")
}
fn under(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/'))
}
fn word(byte: u8) -> bool { byte.is_ascii_alphanumeric() || byte == b'_' }
fn tokens(bytes: &[u8], live: &mut impl FnMut() -> bool,
    mut consume: impl FnMut(&[u8], u32) -> Result<(), LexicalError>,
) -> Result<(), LexicalError> {
    let mut start = None;
    for (at, byte) in bytes.iter().copied().enumerate() {
        if at % 4096 == 0 { check(live)?; }
        if word(byte) {
            let from = *start.get_or_insert(at);
            if at - from >= MAX_TERM_BYTES { return Err(LexicalError::Limit("token bytes")); }
        } else if let Some(from) = start.take() {
            consume(&bytes[from..at], from as u32)?;
        }
    }
    if let Some(from) = start { consume(&bytes[from..], from as u32)?; }
    check(live)
}

impl LexicalSegment {
    /// Build one complete segment from raw-path-sorted documents. IDs are
    /// assigned consecutively from `first_id`, never renumbered by compaction.
    /// Oversized/unsupported input refuses the whole segment, not an omitted
    /// document or a successful but incomplete index.
    pub fn build<'a>(namespace: LexicalNamespace, first_id: u64,
        documents: impl IntoIterator<Item = SourceDocument<'a>>, live: &mut impl FnMut() -> bool,
    ) -> Result<Self, LexicalError> {
        check(live)?;
        if first_id == 0 { return Err(LexicalError::Invalid("zero document ID")); }
        let mut result = Self { namespace, documents: Vec::new(), terms: BTreeMap::new() };
        let (mut source_bytes, mut postings, mut encoded_bound) = (0usize, 0usize, 128usize);
        for document in documents {
            check(live)?;
            if result.documents.len() == MAX_DOCUMENTS { return Err(LexicalError::Limit("documents")); }
            if !path_valid(document.path) || result.documents.last().is_some_and(|last| last.path.as_slice() >= document.path) {
                return Err(LexicalError::Invalid("document path order"));
            }
            if document.content.len() > MAX_FILE_BYTES { return Err(LexicalError::Limit("file bytes")); }
            bounded_add(&mut source_bytes, document.content.len(), MAX_SOURCE_BYTES, "source bytes")?;
            if document.blob.algorithm() != namespace.object_format || document.blob.is_zero()
                || git_object_id(namespace.object_format, GitObjectKind::Blob, document.content) != document.blob
            { return Err(LexicalError::NativeIdentityMismatch); }
            check(live)?;
            let id = first_id.checked_add(result.documents.len() as u64).ok_or(LexicalError::Limit("document IDs"))?;
            bounded_add(&mut encoded_bound, 64 + document.path.len(), MAX_SEGMENT_BYTES, "segment bytes")?;
            result.documents.push(IndexedDocument { id, path: document.path.to_vec(), blob: document.blob,
                content_bytes: document.content.len() as u32 });
            for (channel, bytes) in [(LexicalChannel::Content, document.content), (LexicalChannel::Path, document.path)] {
                tokens(bytes, live, |token, offset| {
                    let term = Term { channel, bytes: token.iter().map(u8::to_ascii_lowercase).collect() };
                    let count = result.terms.len();
                    let list = match result.terms.entry(term) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => {
                            if count == MAX_TERMS { return Err(LexicalError::Limit("dictionary terms")); }
                            bounded_add(&mut encoded_bound, 13 + token.len(), MAX_SEGMENT_BYTES, "segment bytes")?;
                            entry.insert(Postings::default())
                        }
                    };
                    if list.documents.last() != Some(&id) {
                        bounded_add(&mut postings, 1, MAX_POSTINGS, "postings")?;
                        bounded_add(&mut encoded_bound, 12, MAX_SEGMENT_BYTES, "segment bytes")?;
                        list.documents.push(id); list.offsets.push(offset);
                    }
                    Ok(())
                })?;
            }
        }
        check(live)?;
        if result.documents.is_empty() { return Err(LexicalError::Invalid("empty segment")); }
        result.encode(live)?;
        Ok(result)
    }

    #[must_use]
    pub const fn namespace(&self) -> LexicalNamespace { self.namespace }
    #[must_use]
    pub fn documents(&self) -> &[IndexedDocument] { &self.documents }
    #[must_use]
    pub fn term_count(&self) -> usize { self.terms.len() }
    #[must_use]
    pub fn posting_count(&self) -> usize { self.terms.values().map(|p| p.documents.len()).sum() }

    /// Concatenate disjoint ordered ID/path ranges without renumbering a single
    /// posting. Equal dictionary keys merge their already sorted columns. No
    /// document overwrite, deduplication, clock, or hash-map ordering is used.
    pub fn concatenate(segments: &[Self], live: &mut impl FnMut() -> bool) -> Result<Self, LexicalError> {
        check(live)?;
        let first = segments.first().ok_or(LexicalError::Invalid("empty compaction"))?;
        let mut result = Self { namespace: first.namespace, documents: Vec::new(), terms: BTreeMap::new() };
        let (mut postings, mut encoded_bound) = (0usize, 128usize);
        for segment in segments {
            check(live)?;
            if segment.namespace != result.namespace { return Err(LexicalError::NamespaceMismatch); }
            if result.documents.len() + segment.documents.len() > MAX_DOCUMENTS { return Err(LexicalError::Limit("documents")); }
            if let (Some(left), Some(right)) = (result.documents.last(), segment.documents.first()) {
                if left.id >= right.id || left.path >= right.path { return Err(LexicalError::Invalid("overlapping segment ranges")); }
            }
            for document in &segment.documents {
                check(live)?;
                bounded_add(&mut encoded_bound, 64 + document.path.len(), MAX_SEGMENT_BYTES, "segment bytes")?;
                result.documents.push(document.clone());
            }
            for (term, columns) in &segment.terms {
                check(live)?;
                bounded_add(&mut postings, columns.documents.len(), MAX_POSTINGS, "postings")?;
                let count = result.terms.len();
                let into = match result.terms.entry(term.clone()) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        if count == MAX_TERMS { return Err(LexicalError::Limit("dictionary terms")); }
                        bounded_add(&mut encoded_bound, 13 + term.bytes.len(), MAX_SEGMENT_BYTES, "segment bytes")?;
                        entry.insert(Postings::default())
                    }
                };
                bounded_add(&mut encoded_bound, 12 * columns.documents.len(), MAX_SEGMENT_BYTES, "segment bytes")?;
                into.documents.extend_from_slice(&columns.documents); into.offsets.extend_from_slice(&columns.offsets);
            }
        }
        result.encode(live)?;
        check(live)?;
        Ok(result)
    }

    /// Canonical frame and domain-separated root. The encoded body contains
    /// metadata and posting columns, not retained source file contents.
    pub fn encode(&self, live: &mut impl FnMut() -> bool) -> Result<Vec<u8>, LexicalError> { encoding::encode(self, live) }
    pub fn root(&self, live: &mut impl FnMut() -> bool) -> Result<Digest, LexicalError> { encoding::root(self, live) }
    pub fn decode(bytes: &[u8], expected_root: Digest, namespace: LexicalNamespace,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, LexicalError> { encoding::decode(bytes, expected_root, namespace, live) }

    pub fn search(&self, query: &LexicalQuery, after: Option<u64>, limits: LexicalQueryLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<LexicalReport, LexicalError> {
        let mut budget = QueryBudget::new(limits)?;
        let mut hits = Vec::new();
        let more = self.search_into(query, after, &mut budget, &mut hits, live)?;
        check(live)?;
        Ok(LexicalReport { next_after: if more { hits.last().map(|hit| hit.document_id) } else { None },
            complete: !more, hits, work_units: budget.work })
    }

    fn search_into(&self, query: &LexicalQuery, after: Option<u64>, budget: &mut QueryBudget,
        hits: &mut Vec<LexicalHit>, live: &mut impl FnMut() -> bool,
    ) -> Result<bool, LexicalError> {
        check(live)?;
        let mut lists = Vec::with_capacity(query.terms.len());
        for bytes in &query.terms {
            budget.charge(1 + bytes.len() as u64, live)?;
            let Some(list) = self.terms.get(&Term { channel: query.channel, bytes: bytes.clone() }) else { return Ok(false); };
            lists.push(list);
        }
        // Fixed tie break: smallest posting list, then normalized query index.
        let pivot = lists.iter().enumerate().min_by_key(|(i, list)| (list.documents.len(), *i))
            .map(|(i, _)| i).ok_or(LexicalError::Invalid("empty query"))?;
        let mut cursor = lower_bound(&lists[pivot].documents, after.unwrap_or(0), budget, live)?;
        while cursor < lists[pivot].documents.len() {
            let id = lists[pivot].documents[cursor]; cursor += 1;
            if after.is_some_and(|value| id <= value) { continue; }
            budget.charge(1, live)?;
            let mut spans = Vec::with_capacity(lists.len());
            for (query_index, list) in lists.iter().enumerate() {
                let at = lower_bound(&list.documents, id, budget, live)?;
                if list.documents.get(at) != Some(&id) { break; }
                spans.push(LexicalSpan { query_index, byte_offset: list.offsets[at],
                    byte_length: query.terms[query_index].len() as u16 });
            }
            if spans.len() != lists.len() { continue; }
            let document = self.documents.binary_search_by_key(&id, |d| d.id).ok()
                .and_then(|at| self.documents.get(at)).ok_or(LexicalError::Invalid("posting document"))?;
            let mut included = query.prefixes.is_empty();
            for prefix in &query.prefixes {
                budget.charge(prefix.len() as u64 + 1, live)?;
                if under(&document.path, prefix) { included = true; break; }
            }
            if !included { continue; }
            if hits.len() == budget.limits.max_results { return Ok(true); }
            bounded_add(&mut budget.result_bytes, document.path.len() + spans.len() * 24 + 64,
                MAX_RESULT_BYTES, "result bytes")?;
            hits.push(LexicalHit { document_id: id, path: document.path.clone(), blob: document.blob,
                content_bytes: document.content_bytes, spans });
        }
        check(live)?;
        Ok(false)
    }
}

/// AND of 1-32 complete tokens, with a single content/path channel. Terms are
/// ASCII-folded, sorted and deduplicated; returned span indices refer to that
/// normalized list. Query prefixes confer no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalQuery { channel: LexicalChannel, terms: Vec<Vec<u8>>, prefixes: Vec<Vec<u8>> }
impl LexicalQuery {
    pub fn new(channel: LexicalChannel, terms: &[Vec<u8>], prefixes: &[Vec<u8>]) -> Result<Self, LexicalError> {
        if terms.is_empty() || terms.len() > MAX_QUERY_TERMS || terms.iter().any(|term|
            term.is_empty() || term.len() > MAX_TERM_BYTES || !term.iter().all(|b| word(*b)))
        { return Err(LexicalError::Invalid("query tokens")); }
        if prefixes.len() > 128 || prefixes.iter().any(|p| !path_valid(p))
            || prefixes.iter().map(Vec::len).sum::<usize>() > 32 * 1024
        { return Err(LexicalError::Invalid("query prefixes")); }
        let mut terms: Vec<Vec<u8>> = terms.iter().map(|term| term.iter().map(u8::to_ascii_lowercase).collect()).collect();
        terms.sort(); terms.dedup();
        let mut prefixes = prefixes.to_vec(); prefixes.sort(); prefixes.dedup();
        Ok(Self { channel, terms, prefixes })
    }
    #[must_use]
    pub const fn channel(&self) -> LexicalChannel { self.channel }
    #[must_use]
    pub fn terms(&self) -> &[Vec<u8>] { &self.terms }
    #[must_use]
    pub fn prefixes(&self) -> &[Vec<u8>] { &self.prefixes }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LexicalQueryLimits { pub max_results: usize, pub max_work: u64 }
impl Default for LexicalQueryLimits { fn default() -> Self { Self { max_results: 100, max_work: MAX_WORK } } }
impl LexicalQueryLimits {
    pub fn validate(self) -> Result<(), LexicalError> {
        if self.max_results == 0 || self.max_results > MAX_RESULTS || self.max_work == 0 || self.max_work > MAX_WORK {
            return Err(LexicalError::Invalid("query limits"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalSpan { pub query_index: usize, pub byte_offset: u32, pub byte_length: u16 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalHit {
    pub document_id: u64,
    pub path: Vec<u8>,
    pub blob: GitOid,
    pub content_bytes: u32,
    pub spans: Vec<LexicalSpan>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalReport { pub hits: Vec<LexicalHit>, pub complete: bool, pub next_after: Option<u64>, pub work_units: u64 }
struct QueryBudget { limits: LexicalQueryLimits, work: u64, result_bytes: usize }
impl QueryBudget {
    fn new(limits: LexicalQueryLimits) -> Result<Self, LexicalError> {
        limits.validate()?; Ok(Self { limits, work: 0, result_bytes: 0 })
    }
    fn charge(&mut self, amount: u64, live: &mut impl FnMut() -> bool) -> Result<(), LexicalError> {
        check(live)?;
        self.work = self.work.checked_add(amount).filter(|n| *n <= self.limits.max_work).ok_or(LexicalError::Limit("query work"))?;
        Ok(())
    }
}
fn lower_bound(values: &[u64], wanted: u64, budget: &mut QueryBudget,
    live: &mut impl FnMut() -> bool,
) -> Result<usize, LexicalError> {
    let (mut low, mut high) = (0, values.len());
    while low < high {
        budget.charge(1, live)?;
        let mid = low + (high - low) / 2;
        if values[mid] < wanted { low = mid + 1; } else { high = mid; }
    }
    Ok(low)
}
