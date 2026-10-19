//! Bounded exact-byte context from a previously joined Initial retrieval.
//! This is untrusted source material, not an Agent Protocol ContextPacket,
//! a capability, a retention pin, or a claim that source instructions are safe.
use super::{InitialReport, RetrievalError, SymbolChannel};
use fgit_types::GitOid;
use std::collections::BTreeMap;
use std::ops::Range;

pub mod ranked;

pub const PROFILE: &str = "source-initial-context-v1";
const MAX_FILES: usize = 32;
const MAX_ANCHORS: usize = 4096;
const MAX_WINDOWS: usize = 128;

/// Source decoding and retained excerpts have separate finite envelopes.
/// Before reads, source bytes are divided evenly among the selected paths.
/// Unused per-file shares are not borrowed; each native decode is bounded by
/// min(8 MiB, max_source_bytes / selected_files), including metadata-independent
/// blob allocation. Directory/authority work keeps the native reader's bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextLimits {
    pub max_files: usize,
    pub radius_bytes: usize,
    pub max_source_bytes: usize,
    pub max_excerpt_bytes: usize,
}
impl Default for ContextLimits {
    fn default() -> Self {
        Self {
            max_files: 8,
            radius_bytes: 128,
            max_source_bytes: 64 * 1024 * 1024,
            max_excerpt_bytes: 256 * 1024,
        }
    }
}
impl ContextLimits {
    pub fn validate(self) -> Result<(), RetrievalError> {
        if !(1..=MAX_FILES).contains(&self.max_files)
            || self.radius_bytes > 4096
            || self.max_source_bytes == 0
            || self.max_source_bytes > 64 * 1024 * 1024
            || self.max_excerpt_bytes == 0
            || self.max_excerpt_bytes > 1024 * 1024
        {
            return Err(RetrievalError::Invalid("context limits"));
        }
        Ok(())
    }
    pub(crate) fn file_limit(self, selected: usize) -> Result<usize, RetrievalError> {
        self.validate()?;
        let limit = (self.max_source_bytes / selected.max(1)).min(8 * 1024 * 1024);
        if limit == 0 {
            return Err(RetrievalError::Limit("context per-file source share"));
        }
        Ok(limit)
    }
}

/// A Path anchor addresses the raw path, never the source excerpt. The other
/// channels address original blob bytes; no Unicode column conversion occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ContextChannel {
    Content,
    Path,
    Symbol,
}
impl ContextChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Path => "path",
            Self::Symbol => "symbol",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ContextAnchor {
    pub channel: ContextChannel,
    pub byte_offset: usize,
    pub byte_length: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextExcerpt {
    offset: usize,
    bytes: Vec<u8>,
}
impl ContextExcerpt {
    pub const fn offset(&self) -> usize {
        self.offset
    }
    pub fn untrusted_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextFile {
    path: Vec<u8>,
    blob: GitOid,
    source_bytes: usize,
    anchors: Vec<ContextAnchor>,
    excerpts: Vec<ContextExcerpt>,
}
impl ContextFile {
    pub fn path(&self) -> &[u8] {
        &self.path
    }
    pub const fn blob(&self) -> GitOid {
        self.blob
    }
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }
    pub fn anchors(&self) -> &[ContextAnchor] {
        &self.anchors
    }
    pub fn excerpts(&self) -> &[ContextExcerpt] {
        &self.excerpts
    }
}

/// The original retrieval keeps its query, exact source, independent generation
/// vector, truncation, coverage omissions, and optional-channel status intact.
#[derive(Clone, Debug)]
pub struct InitialContext {
    retrieval: InitialReport,
    files: Vec<ContextFile>,
    candidate_files: usize,
    source_bytes_read: usize,
    excerpt_bytes: usize,
    source_file_limit: usize,
}
impl InitialContext {
    pub const fn retrieval(&self) -> &InitialReport {
        &self.retrieval
    }
    pub fn files(&self) -> &[ContextFile] {
        &self.files
    }
    pub const fn candidate_files(&self) -> usize {
        self.candidate_files
    }
    pub fn omitted_files(&self) -> usize {
        self.candidate_files - self.files.len()
    }
    pub fn source_blobs_read(&self) -> usize {
        self.files.len()
    }
    pub const fn source_bytes_read(&self) -> usize {
        self.source_bytes_read
    }
    pub const fn excerpt_bytes(&self) -> usize {
        self.excerpt_bytes
    }
    pub const fn source_file_limit(&self) -> usize {
        self.source_file_limit
    }
    /// All returned matches were hydrated AND retrieval itself had full
    /// coverage. This does not assert that excerpts contain whole source files.
    pub fn complete(&self) -> bool {
        self.omitted_files() == 0 && self.retrieval.complete()
    }
    pub(crate) fn finish(
        retrieval: InitialReport,
        plan: &Plan,
        assembly: Assembly,
        source_file_limit: usize,
    ) -> Result<Self, RetrievalError> {
        if assembly.files.len() != plan.files.len() {
            return Err(RetrievalError::Invalid("incomplete context hydration"));
        }
        Ok(Self {
            retrieval,
            files: assembly.files,
            candidate_files: plan.candidate_files,
            source_bytes_read: assembly.source_bytes,
            excerpt_bytes: assembly.excerpt_bytes,
            source_file_limit,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Witness {
    anchor: ContextAnchor,
    expected: Vec<u8>,
    raw_identifier: bool,
}
pub(crate) struct PlannedFile {
    pub(crate) path: Vec<u8>,
    pub(crate) blob: GitOid,
    source_bytes: Option<usize>,
    witnesses: Vec<Witness>,
}
pub(crate) struct Plan {
    pub(crate) files: Vec<PlannedFile>,
    candidate_files: usize,
}
fn check(cancelled: &dyn Fn() -> bool) -> Result<(), RetrievalError> {
    if cancelled() {
        Err(RetrievalError::Source(
            crate::NodeWorkspaceRefusal::Cancelled { exhaustion: None },
        ))
    } else {
        Ok(())
    }
}
fn identity(
    map: &mut BTreeMap<Vec<u8>, PlannedFile>,
    path: &[u8],
    blob: GitOid,
    size: Option<usize>,
) -> Result<(), RetrievalError> {
    use std::collections::btree_map::Entry;
    match map.entry(path.to_vec()) {
        Entry::Vacant(entry) => {
            entry.insert(PlannedFile {
                path: path.to_vec(),
                blob,
                source_bytes: size,
                witnesses: Vec::new(),
            });
        }
        Entry::Occupied(mut entry) => {
            let prior = entry.get_mut();
            if prior.blob != blob
                || matches!((prior.source_bytes, size), (Some(a), Some(b)) if a != b)
            {
                return Err(RetrievalError::MixedSource);
            }
            prior.source_bytes = prior.source_bytes.or(size);
        }
    }
    Ok(())
}
impl Plan {
    /// Select distinct paths in stable raw-byte order, independent of channel
    /// order and repeated matches. Only max_files is a deliberate omission;
    /// malformed evidence and exhausted byte/window limits are whole failures.
    pub(crate) fn new(
        report: &InitialReport,
        limits: ContextLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, RetrievalError> {
        Self::with_ranking(report, limits, None, cancelled)
    }
    pub(crate) fn ranked(
        report: &InitialReport,
        limits: ContextLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(Self, ranked::ContextRanking), RetrievalError> {
        let ranking = ranked::ContextRanking::build(report, limits, cancelled)?;
        let plan = Self::with_ranking(report, limits, Some(&ranking), cancelled)?;
        Ok((plan, ranking))
    }
    fn with_ranking(
        report: &InitialReport,
        limits: ContextLimits,
        ranking: Option<&ranked::ContextRanking>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, RetrievalError> {
        limits.validate()?;
        check(cancelled)?;
        let mut files = BTreeMap::new();
        for channel in [report.content(), report.path()] {
            for hit in &channel.results.hits {
                check(cancelled)?;
                identity(
                    &mut files,
                    &hit.path,
                    hit.blob,
                    Some(hit.content_bytes as usize),
                )?;
            }
        }
        if let SymbolChannel::Available(channel) = report.symbols() {
            for hit in &channel.matches {
                check(cancelled)?;
                identity(&mut files, &hit.location.path, hit.location.blob, None)?;
            }
        }
        let candidate_files = files.len();
        let mut files: BTreeMap<_, _> = if let Some(ranking) = ranking {
            if ranking.candidate_files() != candidate_files
                || ranking.selected().len() > limits.max_files
            {
                return Err(RetrievalError::Invalid("context ranking inventory"));
            }
            let mut selected = BTreeMap::new();
            for row in ranking.selected() {
                check(cancelled)?;
                let file = files
                    .remove(row.path())
                    .ok_or(RetrievalError::Invalid("context ranking path"))?;
                if file.blob != row.blob() {
                    return Err(RetrievalError::MixedSource);
                }
                selected.insert(file.path.clone(), file);
            }
            selected
        } else {
            files.into_iter().take(limits.max_files).collect()
        };
        let mut anchors = 0usize;
        for (channel, report) in [
            (ContextChannel::Content, report.content()),
            (ContextChannel::Path, report.path()),
        ] {
            for hit in &report.results.hits {
                check(cancelled)?;
                let Some(file) = files.get_mut(&hit.path) else {
                    continue;
                };
                for span in &hit.spans {
                    let expected = report
                        .query
                        .terms()
                        .get(span.query_index)
                        .ok_or(RetrievalError::Invalid("context query span"))?;
                    file.push(
                        ContextAnchor {
                            channel,
                            byte_offset: span.byte_offset as usize,
                            byte_length: usize::from(span.byte_length),
                        },
                        expected,
                        false,
                        &mut anchors,
                    )?;
                }
            }
        }
        if let SymbolChannel::Available(channel) = report.symbols() {
            for hit in &channel.matches {
                check(cancelled)?;
                if let Some(file) = files.get_mut(&hit.location.path) {
                    file.push(
                        ContextAnchor {
                            channel: ContextChannel::Symbol,
                            byte_offset: hit.location.byte_offset,
                            byte_length: hit.location.match_length,
                        },
                        &hit.name,
                        hit.raw_identifier,
                        &mut anchors,
                    )?;
                }
            }
        }
        for file in files.values_mut() {
            file.witnesses.sort();
            file.witnesses.dedup();
        }
        check(cancelled)?;
        Ok(Self {
            files: files.into_values().collect(),
            candidate_files,
        })
    }
}
impl PlannedFile {
    fn push(
        &mut self,
        anchor: ContextAnchor,
        expected: &[u8],
        raw_identifier: bool,
        count: &mut usize,
    ) -> Result<(), RetrievalError> {
        if *count >= MAX_ANCHORS {
            return Err(RetrievalError::Limit("context anchors"));
        }
        if expected.is_empty() || expected.len() > 128 || anchor.byte_length != expected.len() {
            return Err(RetrievalError::Invalid("context anchor length"));
        }
        *count += 1;
        self.witnesses.push(Witness {
            anchor,
            expected: expected.to_vec(),
            raw_identifier,
        });
        Ok(())
    }
}
fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
fn verify(witness: &Witness, source: &[u8]) -> Result<Range<usize>, RetrievalError> {
    let from = witness.anchor.byte_offset;
    let to = from
        .checked_add(witness.anchor.byte_length)
        .ok_or(RetrievalError::Invalid("context anchor range"))?;
    let actual = source
        .get(from..to)
        .ok_or(RetrievalError::Invalid("context anchor range"))?;
    let accepted = if witness.anchor.channel == ContextChannel::Symbol {
        actual == witness.expected.as_slice()
            && (!witness.raw_identifier || (from >= 2 && source.get(from - 2..from) == Some(b"r#")))
    } else {
        actual.eq_ignore_ascii_case(&witness.expected)
            && (from == 0 || !word(source[from - 1]))
            && (to == source.len() || !word(source[to]))
    };
    if !accepted {
        return Err(RetrievalError::Invalid("context anchor/source mismatch"));
    }
    Ok(from..to)
}

#[derive(Default)]
pub(crate) struct Assembly {
    files: Vec<ContextFile>,
    source_bytes: usize,
    excerpt_bytes: usize,
    windows: usize,
}
impl Assembly {
    pub(crate) fn observe(
        &mut self,
        file: &PlannedFile,
        bytes: &[u8],
        limits: ContextLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), RetrievalError> {
        check(cancelled)?;
        if file
            .source_bytes
            .is_some_and(|expected| expected != bytes.len())
        {
            return Err(RetrievalError::Invalid("context source length"));
        }
        let source_bytes = self
            .source_bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= limits.max_source_bytes)
            .ok_or(RetrievalError::Limit("context source bytes"))?;
        let mut ranges = Vec::new();
        for witness in &file.witnesses {
            check(cancelled)?;
            let is_path = witness.anchor.channel == ContextChannel::Path;
            let span = verify(witness, if is_path { &file.path } else { bytes })?;
            if !is_path {
                ranges.push(
                    span.start.saturating_sub(limits.radius_bytes)
                        ..span
                            .end
                            .saturating_add(limits.radius_bytes)
                            .min(bytes.len()),
                );
            }
        }
        // Path-only hits provide a bounded file preamble; path byte offsets
        // must NEVER become content offsets. Empty files remain real entries.
        if ranges.is_empty() {
            ranges.push(0..bytes.len().min(limits.radius_bytes.max(1) * 2));
        }
        ranges.sort_by_key(|range| (range.start, range.end));
        let mut merged: Vec<Range<usize>> = Vec::new();
        for range in ranges {
            check(cancelled)?;
            if let Some(last) = merged.last_mut().filter(|last| range.start <= last.end) {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        let windows = self
            .windows
            .checked_add(merged.len())
            .filter(|n| *n <= MAX_WINDOWS)
            .ok_or(RetrievalError::Limit("context windows"))?;
        let added: usize = merged.iter().map(|range| range.len()).sum();
        let excerpt_bytes = self
            .excerpt_bytes
            .checked_add(added)
            .filter(|n| *n <= limits.max_excerpt_bytes)
            .ok_or(RetrievalError::Limit("context excerpt bytes"))?;
        // All proofs and limits precede copying any excerpt from this blob.
        let mut excerpts = Vec::with_capacity(merged.len());
        for range in merged {
            check(cancelled)?;
            excerpts.push(ContextExcerpt {
                offset: range.start,
                bytes: bytes[range].to_vec(),
            });
        }
        self.files.push(ContextFile {
            path: file.path.clone(),
            blob: file.blob,
            source_bytes: bytes.len(),
            anchors: file.witnesses.iter().map(|w| w.anchor.clone()).collect(),
            excerpts,
        });
        self.source_bytes = source_bytes;
        self.excerpt_bytes = excerpt_bytes;
        self.windows = windows;
        check(cancelled)
    }
}

#[cfg(test)]
mod tests;
