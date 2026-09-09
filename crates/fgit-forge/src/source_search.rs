//! Bounded literal-byte search of an immutable, capability-visible source tree.
//!
//! This is a derived read, not an index, authority decision, regex engine or
//! Unicode case-folding service. A complete answer covers only regular files
//! inside BOTH the caller's capability and the query's slash-bounded prefixes.

use std::collections::BTreeMap;

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, NativeObjectIdentity};
use fgit_treefs::{BaseEntry, BaseError, BaseView, CapabilityRefusal, ObjectSource,
    ObjectSourceError, TreeCapability, TreePath};
use fgit_types::{GitHashAlgorithm as Format, GitOid, RepositoryCommitId, RepositoryId};

/// The only case transformations admitted by LiteralBytesV1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchCase { Exact, AsciiInsensitive }

/// Validated query. Empty prefixes mean all capability-visible regular files,
/// never additional authorization. Prefixes are raw repository path bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceQuery {
    needle: Vec<u8>,
    case: SearchCase,
    prefixes: Vec<TreePath>,
    failure: Vec<usize>,
}
impl SourceQuery {
    pub fn new(needle: &[u8], case: SearchCase, prefixes: &[Vec<u8>]) -> Result<Self, SearchError> {
        if needle.is_empty() || needle.len() > 256 || needle.contains(&b'\n') || prefixes.len() > 128 {
            return Err(SearchError::InvalidQuery);
        }
        let mut paths = Vec::new();
        let mut path_bytes = 0usize;
        for prefix in prefixes {
            path_bytes = path_bytes.checked_add(prefix.len()).filter(|n| *n <= 32 * 1024)
                .ok_or(SearchError::InvalidQuery)?;
            paths.push(TreePath::parse_default(prefix).map_err(|_| SearchError::InvalidQuery)?);
        }
        paths.sort();
        paths.dedup();
        let folded: Vec<_> = needle.iter().map(|byte| fold(*byte, case)).collect();
        let mut failure = vec![0; needle.len()];
        let mut matched = 0;
        for i in 1..folded.len() {
            while matched > 0 && folded[i] != folded[matched] { matched = failure[matched - 1]; }
            if folded[i] == folded[matched] { matched += 1; }
            failure[i] = matched;
        }
        Ok(Self { needle: needle.to_vec(), case, prefixes: paths, failure })
    }
    #[must_use]
    pub fn needle(&self) -> &[u8] { &self.needle }
    #[must_use]
    pub const fn case(&self) -> SearchCase { self.case }
    #[must_use]
    pub fn prefixes(&self) -> &[TreePath] { &self.prefixes }
    fn includes(&self, path: &TreePath) -> bool {
        self.prefixes.is_empty() || self.prefixes.iter().any(|prefix| path.starts_with(prefix))
    }
    fn descends(&self, path: &TreePath) -> bool {
        self.prefixes.is_empty() || self.prefixes.iter()
            .any(|prefix| path.starts_with(prefix) || prefix.starts_with(path))
    }
}
fn fold(byte: u8, case: SearchCase) -> u8 {
    match case { SearchCase::Exact => byte, SearchCase::AsciiInsensitive => byte.to_ascii_lowercase() }
}

/// Per-operation ceilings. They may be narrowed, not increased beyond v1.
/// Object sources separately enforce their per-read allocation ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    pub max_matches: usize,
    pub max_entries: usize,
    pub max_files: usize,
    pub max_depth: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
}
impl Default for SearchLimits {
    fn default() -> Self {
        Self { max_matches: 200, max_entries: 50_000, max_files: 20_000,
            max_depth: 64, max_file_bytes: 8 * 1024 * 1024, max_total_bytes: 64 * 1024 * 1024 }
    }
}
impl SearchLimits {
    pub fn validate(self) -> Result<(), SearchError> {
        let ceiling = Self::default();
        for (value, maximum) in [(self.max_matches, 4096),
            (self.max_entries, ceiling.max_entries), (self.max_files, ceiling.max_files),
            (self.max_depth, ceiling.max_depth), (self.max_file_bytes, ceiling.max_file_bytes),
            (self.max_total_bytes, ceiling.max_total_bytes)]
        {
            if value == 0 || value > maximum { return Err(SearchError::InvalidLimits); }
        }
        Ok(())
    }
}

/// Offsets and columns count original BYTES, not Unicode scalar values.
/// Lines are one-based and split on LF; overlapping matches are retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceMatch {
    pub path: Vec<u8>,
    pub blob: GitOid,
    pub byte_offset: usize,
    pub line: usize,
    pub byte_column: usize,
    /// At most 416 original bytes, with no decoding or terminal rendering.
    pub excerpt: Vec<u8>,
    pub excerpt_offset: usize,
    pub match_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchCompletion {
    /// Every selected regular file was searched; no implicit binary exclusion.
    Complete,
    /// At least one additional match exists beyond the returned bounded prefix.
    MatchLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSearchReport {
    pub repository: RepositoryId,
    pub source_rcr: RepositoryCommitId,
    pub source_commit: GitOid,
    pub source_tree: GitOid,
    pub matches: Vec<SourceMatch>,
    pub completion: SearchCompletion,
    pub files_selected: usize,
    pub files_read: usize,
    pub bytes_read: usize,
    /// Bytes actually passed through the matcher, including lookahead.
    pub bytes_searched: usize,
    /// Selected symlink/gitlink entries, whose payloads are never read.
    pub non_regular_entries: usize,
}

#[derive(Debug)]
pub enum SearchError {
    InvalidQuery,
    InvalidLimits,
    InvalidObjectFormat,
    Cancelled,
    Budget(&'static str),
    Base(Box<BaseError>),
    Source(Box<ObjectSourceError>),
    Capability(CapabilityRefusal),
}
impl std::fmt::Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source search refused: {self:?}")
    }
}
impl std::error::Error for SearchError {}

fn checkpoint(cancelled: &dyn Fn() -> bool) -> Result<(), SearchError> {
    if cancelled() { Err(SearchError::Cancelled) } else { Ok(()) }
}
fn oid<A: GitHashAlgorithm>(id: &fgit_crypto::GitOid<A>) -> Result<GitOid, SearchError> {
    let format = match A::DIGEST_LEN { 20 => Format::Sha1, 32 => Format::Sha256,
        _ => return Err(SearchError::InvalidObjectFormat) };
    let hex: String = id.digest_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
    GitOid::from_hex(format, &hex).map_err(|_| SearchError::InvalidObjectFormat)
}

/// Search one immutable base. The node must first authenticate its selection.
/// Every payload requires a fresh path grant and a shared fetch-budget charge.
/// A capability, source, traversal, cancellation or byte-budget failure returns
/// an error, NEVER a successful empty or silently incomplete answer.
pub fn search_source<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>, source: &S, capability: &mut TreeCapability, now: u64,
    query: &SourceQuery, limits: SearchLimits, cancelled: &dyn Fn() -> bool,
) -> Result<SourceSearchReport, SearchError> {
    limits.validate()?;
    checkpoint(cancelled)?;
    capability.authorize_root(now).map_err(SearchError::Capability)?;
    let mut discovery = Discovery { files: BTreeMap::new(), entries: 0, excluded: 0 };
    discover(base, source, capability, now, query, limits, cancelled, None, 0, &mut discovery)?;
    let mut report = SourceSearchReport {
        repository: base.repository_id(), source_rcr: base.base_rcr_id(),
        source_commit: oid(base.base_commit_oid())?, source_tree: oid(base.base_tree_oid())?,
        matches: Vec::new(), completion: SearchCompletion::Complete,
        files_selected: discovery.files.len(), files_read: 0, bytes_read: 0,
        bytes_searched: 0, non_regular_entries: discovery.excluded,
    };
    for (path, blob) in discovery.files {
        checkpoint(cancelled)?;
        let grant = capability.authorize_read(&path, now).map_err(SearchError::Capability)?;
        let body = base.read_object(source, &blob, GitObjectKind::Blob, &grant)
            .map_err(|e| SearchError::Source(Box::new(e)))?;
        capability.charge_fetch(body.len() as u64).map_err(SearchError::Capability)?;
        checkpoint(cancelled)?;
        if body.len() > limits.max_file_bytes { return Err(SearchError::Budget("file bytes")); }
        report.bytes_read = report.bytes_read.checked_add(body.len())
            .filter(|bytes| *bytes <= limits.max_total_bytes).ok_or(SearchError::Budget("total bytes"))?;
        report.files_read += 1;
        let blob = oid(&blob)?;
        let mut extra = false;
        let consumed = scan(&body, query, cancelled, |start, line, line_start| {
            if report.matches.len() == limits.max_matches { extra = true; return false; }
            let end = start + query.needle.len();
            let excerpt_offset = line_start.max(start.saturating_sub(80));
            let upper = body.len().min(end.saturating_add(80));
            let excerpt_end = body[end..upper].iter().position(|byte| *byte == b'\n')
                .map_or(upper, |offset| end + offset);
            report.matches.push(SourceMatch { path: path.as_bytes().to_vec(), blob,
                byte_offset: start, line, byte_column: start - line_start + 1,
                excerpt: body[excerpt_offset..excerpt_end].to_vec(), excerpt_offset,
                match_length: query.needle.len() });
            true
        })?;
        report.bytes_searched += consumed;
        if extra { report.completion = SearchCompletion::MatchLimit; break; }
    }
    checkpoint(cancelled)?;
    Ok(report)
}

struct Discovery<A: GitHashAlgorithm> {
    files: BTreeMap<TreePath, fgit_crypto::GitOid<A>>,
    entries: usize,
    excluded: usize,
}
#[allow(clippy::too_many_arguments)]
fn discover<A: GitHashAlgorithm, S: ObjectSource<A>>(
    base: &BaseView<A>, source: &S, capability: &mut TreeCapability, now: u64,
    query: &SourceQuery, limits: SearchLimits, cancelled: &dyn Fn() -> bool,
    directory: Option<&TreePath>, depth: usize, discovery: &mut Discovery<A>,
) -> Result<(), SearchError> {
    checkpoint(cancelled)?;
    if depth > limits.max_depth { return Err(SearchError::Budget("directory depth")); }
    let children = base.list(source, capability, directory, now)
        .map_err(|e| SearchError::Base(Box::new(e)))?;
    for (name, entry) in children {
        checkpoint(cancelled)?;
        discovery.entries += 1;
        if discovery.entries > limits.max_entries { return Err(SearchError::Budget("tree entries")); }
        let path = match directory {
            Some(parent) => parent.join(&name, base.path_policy()),
            None => TreePath::parse(&name, base.path_policy()),
        }.map_err(|e| SearchError::Base(Box::new(BaseError::Path(e))))?;
        match entry {
            BaseEntry::Directory { .. } if query.descends(&path) => {
                discover(base, source, capability, now, query, limits, cancelled,
                    Some(&path), depth + 1, discovery)?;
            }
            BaseEntry::File { oid, mode } if query.includes(&path) => {
                if mode != b"100644" && mode != b"100755" { return Err(SearchError::Budget("unsupported file mode")); }
                // An ancestor can be disclosable without granting its content.
                // A requested descendant under a FILE is not a readable file.
                if !capability.admits_disclosure(&path) { continue; }
                if discovery.files.len() == limits.max_files { return Err(SearchError::Budget("files")); }
                if discovery.files.insert(path, oid).is_some() { return Err(SearchError::Budget("duplicate path")); }
            }
            BaseEntry::Symlink { .. } | BaseEntry::Submodule { .. } if query.includes(&path) => {
                discovery.excluded += 1;
            }
            _ => {}
        }
    }
    Ok(())
}

/// KMP is linear in scanned bytes even for periodic inputs and overlapping hits.
/// Cancellation probes bound synchronous work between checks to 4 KiB.
fn scan(
    bytes: &[u8], query: &SourceQuery, cancelled: &dyn Fn() -> bool,
    mut found: impl FnMut(usize, usize, usize) -> bool,
) -> Result<usize, SearchError> {
    let (mut matched, mut line, mut line_start) = (0, 1, 0);
    for (i, raw) in bytes.iter().enumerate() {
        if i % 4096 == 0 { checkpoint(cancelled)?; }
        let byte = fold(*raw, query.case);
        while matched > 0 && byte != fold(query.needle[matched], query.case) {
            matched = query.failure[matched - 1];
        }
        if byte == fold(query.needle[matched], query.case) { matched += 1; }
        if matched == query.needle.len() {
            if !found(i + 1 - matched, line, line_start) { return Ok(i + 1); }
            matched = query.failure[matched - 1];
        }
        if *raw == b'\n' { line += 1; line_start = i + 1; }
    }
    checkpoint(cancelled)?;
    Ok(bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn hits(bytes: &[u8], needle: &[u8], case: SearchCase) -> Vec<(usize, usize, usize)> {
        let query = SourceQuery::new(needle, case, &[]).unwrap();
        let mut found = Vec::new();
        assert_eq!(scan(bytes, &query, &|| false, |a,b,c| { found.push((a,b,c)); true }).unwrap(), bytes.len());
        found
    }
    #[test]
    fn overlaps_empty_files_and_final_lines_are_exact() {
        assert_eq!(hits(b"aaaa\naa", b"aa", SearchCase::Exact), vec![(0,1,0),(1,1,0),(2,1,0),(5,2,5)]);
        assert!(hits(b"", b"x", SearchCase::Exact).is_empty());
        assert!(hits(b"x", b"long", SearchCase::Exact).is_empty());
    }
    #[test]
    fn utf8_binary_and_crlf_keep_original_byte_coordinates() {
        assert_eq!(hits("éX\r\n\0xX".as_bytes(), b"x", SearchCase::AsciiInsensitive), vec![(2,1,0),(6,2,5),(7,2,5)]);
        assert_eq!(hits(b"a\0b", b"\0", SearchCase::Exact), vec![(1,1,0)]);
        assert!(hits("É".as_bytes(), "é".as_bytes(), SearchCase::AsciiInsensitive).is_empty());
    }
    #[test]
    fn matcher_agrees_with_exhaustive_scalar_windows() {
        for n in 0..9 {
            for word in 0..(1usize << n) {
                let bytes: Vec<_> = (0..n).map(|i| if word & (1<<i) == 0 { b'a' } else { b'B' }).collect();
                for needle in [b"a".as_slice(), b"b", b"aa", b"AbA", b"BBBB"] {
                    for case in [SearchCase::Exact, SearchCase::AsciiInsensitive] {
                        let expected: Vec<_> = bytes.windows(needle.len()).enumerate()
                            .filter(|(_, window)| window.iter().zip(needle).all(|(a,b)| fold(*a,case)==fold(*b,case)))
                            .map(|(i,_)| (i,1,0)).collect();
                        assert_eq!(hits(&bytes, needle, case), expected);
                    }
                }
            }
        }
    }
    #[test]
    fn query_scope_uses_component_boundaries_and_preserves_bytes() {
        let query = SourceQuery::new(b"abc", SearchCase::Exact, &[b"src".to_vec(), b"src".to_vec()]).unwrap();
        assert_eq!(query.prefixes().len(), 1);
        assert!(query.includes(&TreePath::parse_default(b"src/a.rs").unwrap()));
        assert!(!query.includes(&TreePath::parse_default(b"src2/a.rs").unwrap()));
        for needle in [b"".as_slice(), b"a\nb", &[b'a';257]] {
            assert!(SourceQuery::new(needle, SearchCase::Exact, &[]).is_err());
        }
        for prefix in [b"../secret".as_slice(), b"/absolute", b".git/config"] {
            assert!(SourceQuery::new(b"a", SearchCase::Exact, &[prefix.to_vec()]).is_err());
        }
    }
    #[test]
    fn cancellation_and_lookahead_are_not_empty_success() {
        let query = SourceQuery::new(b"a", SearchCase::Exact, &[]).unwrap();
        assert!(matches!(scan(b"aaaa", &query, &|| true, |_,_,_| true), Err(SearchError::Cancelled)));
        let polls = Cell::new(0);
        let cancel = || { polls.set(polls.get()+1); polls.get() > 1 };
        assert!(matches!(scan(&vec![b'b';8192], &query, &cancel, |_,_,_| true), Err(SearchError::Cancelled)));
        let mut count = 0;
        assert_eq!(scan(b"aaaa", &query, &|| false, |_,_,_| { count+=1; count<3 }).unwrap(), 3);
        assert_eq!(count, 3);
    }
    #[test]
    fn limits_cannot_disable_or_widen_the_bounded_profile() {
        assert!(SearchLimits::default().validate().is_ok());
        assert!(SearchLimits { max_matches: 0, ..SearchLimits::default() }.validate().is_err());
        assert!(SearchLimits { max_matches: 4097, ..SearchLimits::default() }.validate().is_err());
        assert!(SearchLimits { max_total_bytes: usize::MAX, ..SearchLimits::default() }.validate().is_err());
    }
}
