//! Bounded exact-byte context from a previously joined Initial retrieval.
//! This is untrusted source material, not an Agent Protocol ContextPacket,
//! a capability, a retention pin, or a claim that source instructions are safe.
use super::{InitialReport, RetrievalError, SymbolChannel};
use fgit_crypto::{DigestHasher, Sha256Hasher};
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
    #[must_use]
    pub const fn position_domain(self) -> &'static str {
        match self {
            Self::Path => "raw-path-bytes",
            Self::Content | Self::Symbol => "source-blob-bytes",
        }
    }
    #[must_use]
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
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
    #[must_use]
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
    // Original retrieval-row commitments; these are not read capabilities.
    authorization_labels: Vec<[u8; 32]>,
    anchor_authorization_labels: Vec<[u8; 32]>,
    lineage_commitment: [u8; 32],
}
impl ContextFile {
    #[must_use]
    pub fn path(&self) -> &[u8] {
        &self.path
    }
    #[must_use]
    pub const fn blob(&self) -> GitOid {
        self.blob
    }
    #[must_use]
    pub const fn source_bytes(&self) -> usize {
        self.source_bytes
    }
    #[must_use]
    pub fn anchors(&self) -> &[ContextAnchor] {
        &self.anchors
    }
    #[must_use]
    pub fn excerpts(&self) -> &[ContextExcerpt] {
        &self.excerpts
    }
    /// Original row labels contributing to this file, in first-observed order.
    /// Every excerpt inherits this file's commitment and these references.
    #[must_use]
    pub fn authorization_labels(&self) -> &[[u8; 32]] {
        &self.authorization_labels
    }
    /// One original row label per anchor, in the unchanged anchor order.
    #[must_use]
    pub fn anchor_authorization_labels(&self) -> &[[u8; 32]] {
        &self.anchor_authorization_labels
    }
    /// Saved after verified hydration, never reminted by the renderer.
    #[must_use]
    pub const fn lineage_commitment(&self) -> &[u8; 32] {
        &self.lineage_commitment
    }
    fn commitment(
        &self,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<[u8; 32], RetrievalError> {
        fn number(hash: &mut Sha256Hasher, value: usize) {
            hash.update(&(value as u64).to_be_bytes());
        }
        fn field(hash: &mut Sha256Hasher, bytes: &[u8]) {
            number(hash, bytes.len());
            hash.update(bytes);
        }
        let mut hash = Sha256Hasher::new();
        hash.update(b"frankengit/source-context-lineage/v1\0");
        field(&mut hash, &self.path);
        field(&mut hash, self.blob.to_string().as_bytes());
        number(&mut hash, self.source_bytes);
        number(&mut hash, self.authorization_labels.len());
        for label in &self.authorization_labels {
            live()?;
            hash.update(label);
        }
        number(&mut hash, self.anchors.len());
        if self.anchors.len() != self.anchor_authorization_labels.len() {
            return Err(RetrievalError::Invalid("context anchor label count"));
        }
        for (anchor, label) in self.anchors.iter().zip(&self.anchor_authorization_labels) {
            live()?;
            field(&mut hash, anchor.channel.as_str().as_bytes());
            number(&mut hash, anchor.byte_offset);
            number(&mut hash, anchor.byte_length);
            hash.update(label);
        }
        number(&mut hash, self.excerpts.len());
        for excerpt in &self.excerpts {
            live()?;
            number(&mut hash, excerpt.offset);
            number(&mut hash, excerpt.bytes.len());
            for chunk in excerpt.bytes.chunks(4096) {
                live()?;
                hash.update(chunk);
            }
        }
        live()?;
        Ok(hash.finish())
    }
    fn validate_saved_lineage(
        &self,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<(), RetrievalError> {
        live()?;
        if self.authorization_labels.is_empty()
            || self.lineage_commitment != self.commitment(live)?
        {
            return Err(RetrievalError::Invalid("context lineage commitment"));
        }
        Ok(())
    }
    /// Check saved hydration evidence and its original retrieval membership.
    /// Callers must separately validate the report against their own read grant.
    pub(crate) fn validate_lineage(
        &self,
        report: &InitialReport,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<(), RetrievalError> {
        self.validate_saved_lineage(live)?;
        let mut observed = Vec::with_capacity(self.authorization_labels.len());
        for (results, labels) in [
            (
                report.content(),
                report
                    .authorization()
                    .lexical(fgit_graph::lexical::LexicalChannel::Content),
            ),
            (
                report.path(),
                report
                    .authorization()
                    .lexical(fgit_graph::lexical::LexicalChannel::Path),
            ),
        ] {
            for (row, label) in results.results.hits.iter().zip(labels) {
                live()?;
                if row.path != self.path {
                    continue;
                }
                if row.blob != self.blob || row.content_bytes as usize != self.source_bytes {
                    return Err(RetrievalError::MixedSource);
                }
                if !observed.contains(label) {
                    observed.push(*label);
                }
            }
        }
        if let SymbolChannel::Available(symbols) = report.symbols() {
            for (row, label) in symbols.matches.iter().zip(report.authorization().symbols()) {
                live()?;
                if row.location.path != self.path {
                    continue;
                }
                if row.location.blob != self.blob {
                    return Err(RetrievalError::MixedSource);
                }
                if !observed.contains(label) {
                    observed.push(*label);
                }
            }
        }
        if observed != self.authorization_labels {
            return Err(RetrievalError::Invalid("context original label membership"));
        }
        for (anchor, origin) in self.anchors.iter().zip(&self.anchor_authorization_labels) {
            live()?;
            let valid = match anchor.channel {
                ContextChannel::Content | ContextChannel::Path => {
                    let channel = if anchor.channel == ContextChannel::Content {
                        fgit_graph::lexical::LexicalChannel::Content
                    } else {
                        fgit_graph::lexical::LexicalChannel::Path
                    };
                    let results = if anchor.channel == ContextChannel::Content {
                        report.content()
                    } else {
                        report.path()
                    };
                    results
                        .results
                        .hits
                        .iter()
                        .zip(report.authorization().lexical(channel))
                        .any(|(row, label)| {
                            label == origin
                                && row.path == self.path
                                && row.blob == self.blob
                                && row.spans.iter().any(|span| {
                                    anchor.byte_offset == span.byte_offset as usize
                                        && anchor.byte_length == usize::from(span.byte_length)
                                })
                        })
                }
                ContextChannel::Symbol => match report.symbols() {
                    SymbolChannel::Available(symbols) => symbols
                        .matches
                        .iter()
                        .zip(report.authorization().symbols())
                        .any(|(row, label)| {
                            label == origin
                                && row.location.path == self.path
                                && row.location.blob == self.blob
                                && anchor.byte_offset == row.location.byte_offset
                                && anchor.byte_length == row.location.match_length
                        }),
                    _ => false,
                },
            };
            if !valid || !observed.contains(origin) {
                return Err(RetrievalError::Invalid(
                    "context anchor original label membership",
                ));
            }
        }
        live()
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
    lineage_metadata_bytes: usize,
}
impl InitialContext {
    #[must_use]
    pub const fn retrieval(&self) -> &InitialReport {
        &self.retrieval
    }
    #[must_use]
    pub fn files(&self) -> &[ContextFile] {
        &self.files
    }
    #[must_use]
    pub const fn candidate_files(&self) -> usize {
        self.candidate_files
    }
    #[must_use]
    pub const fn omitted_files(&self) -> usize {
        self.candidate_files - self.files.len()
    }
    #[must_use]
    pub const fn source_blobs_read(&self) -> usize {
        self.files.len()
    }
    #[must_use]
    pub const fn source_bytes_read(&self) -> usize {
        self.source_bytes_read
    }
    #[must_use]
    pub const fn excerpt_bytes(&self) -> usize {
        self.excerpt_bytes
    }
    #[must_use]
    pub const fn source_file_limit(&self) -> usize {
        self.source_file_limit
    }
    /// Additional conservative lineage reservation under the original Initial
    /// result allowance. The nested retrieval retains its own exact accounting.
    #[must_use]
    pub const fn lineage_metadata_bytes(&self) -> usize {
        self.lineage_metadata_bytes
    }
    /// All returned matches were hydrated AND retrieval itself had full
    /// coverage. This does not assert that excerpts contain whole source files.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.omitted_files() == 0 && self.retrieval.complete()
    }
    pub(crate) fn finish(
        retrieval: InitialReport,
        plan: &Plan,
        assembly: Assembly,
        source_file_limit: usize,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<Self, RetrievalError> {
        if assembly.files.len() != plan.files.len() {
            return Err(RetrievalError::Invalid("incomplete context hydration"));
        }
        for file in &assembly.files {
            file.validate_lineage(&retrieval, live)?;
        }
        Ok(Self {
            retrieval,
            files: assembly.files,
            candidate_files: plan.candidate_files,
            source_bytes_read: assembly.source_bytes,
            excerpt_bytes: assembly.excerpt_bytes,
            source_file_limit,
            lineage_metadata_bytes: plan.lineage_metadata_bytes()?,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Witness {
    anchor: ContextAnchor,
    expected: Vec<u8>,
    raw_identifier: bool,
    authorization_label: [u8; 32],
}
pub(crate) struct PlannedFile {
    pub(crate) path: Vec<u8>,
    pub(crate) blob: GitOid,
    source_bytes: Option<usize>,
    witnesses: Vec<Witness>,
    authorization_labels: Vec<[u8; 32]>,
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
                authorization_labels: Vec::new(),
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
        for (channel, report, labels) in [
            (
                ContextChannel::Content,
                report.content(),
                report
                    .authorization()
                    .lexical(fgit_graph::lexical::LexicalChannel::Content),
            ),
            (
                ContextChannel::Path,
                report.path(),
                report
                    .authorization()
                    .lexical(fgit_graph::lexical::LexicalChannel::Path),
            ),
        ] {
            for (ordinal, hit) in report.results.hits.iter().enumerate() {
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
                        *labels
                            .get(ordinal)
                            .ok_or(RetrievalError::Invalid("context lexical label count"))?,
                        &mut anchors,
                    )?;
                }
            }
        }
        if let SymbolChannel::Available(channel) = report.symbols() {
            for (ordinal, hit) in channel.matches.iter().enumerate() {
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
                        *report
                            .authorization()
                            .symbols()
                            .get(ordinal)
                            .ok_or(RetrievalError::Invalid("context symbol label count"))?,
                        &mut anchors,
                    )?;
                }
            }
        }
        for file in files.values_mut() {
            file.finish_witnesses();
        }
        check(cancelled)?;
        Ok(Self {
            files: files.into_values().collect(),
            candidate_files,
        })
    }
    /// Conservative binary + wire lineage reservation before native source I/O.
    /// Planning vectors are fitted once after dedup; original references,
    /// assembled copies and validation storage are all included.
    /// The window bound comes from the original selected witnesses, not bytes
    /// fetched later, and never widens the existing excerpt/window allowance.
    pub(crate) fn lineage_metadata_bytes(&self) -> Result<usize, RetrievalError> {
        let mut total = 0usize;
        let mut windows = 0usize;
        for file in &self.files {
            let origins = file.authorization_labels.len();
            let anchors = file.witnesses.len();
            let source_anchors = file
                .witnesses
                .iter()
                .filter(|w| w.anchor.channel != ContextChannel::Path)
                .count();
            windows = windows
                .checked_add(source_anchors.max(1))
                .ok_or(RetrievalError::Limit("context lineage bytes"))?;
            let amount = origins
                .checked_mul(256)
                .and_then(|n| anchors.checked_mul(256).and_then(|a| n.checked_add(a)))
                .and_then(|n| n.checked_add(1024))
                .ok_or(RetrievalError::Limit("context lineage bytes"))?;
            total = total
                .checked_add(amount)
                .ok_or(RetrievalError::Limit("context lineage bytes"))?;
        }
        windows
            .min(MAX_WINDOWS)
            .checked_mul(192)
            .and_then(|bytes| total.checked_add(bytes))
            .ok_or(RetrievalError::Limit("context lineage bytes"))
    }
}
impl PlannedFile {
    fn finish_witnesses(&mut self) {
        // Preserve the original observable order/dedup key. A row label
        // distinguishes provenance, never changes anchor selection/order.
        self.witnesses.sort_by(|left, right| {
            (&left.anchor, &left.expected, left.raw_identifier).cmp(&(
                &right.anchor,
                &right.expected,
                right.raw_identifier,
            ))
        });
        self.witnesses.dedup_by(|left, right| {
            (&left.anchor, &left.expected, left.raw_identifier)
                == (&right.anchor, &right.expected, right.raw_identifier)
        });
        // Fit retained planning storage so result-byte accounting depends on
        // deterministic lengths, never target-specific vector growth history.
        self.witnesses = std::mem::take(&mut self.witnesses)
            .into_boxed_slice()
            .into_vec();
        self.authorization_labels = std::mem::take(&mut self.authorization_labels)
            .into_boxed_slice()
            .into_vec();
    }
    fn push(
        &mut self,
        anchor: ContextAnchor,
        expected: &[u8],
        raw_identifier: bool,
        authorization_label: [u8; 32],
        count: &mut usize,
    ) -> Result<(), RetrievalError> {
        if *count >= MAX_ANCHORS {
            return Err(RetrievalError::Limit("context anchors"));
        }
        if expected.is_empty() || expected.len() > 128 || anchor.byte_length != expected.len() {
            return Err(RetrievalError::Invalid("context anchor length"));
        }
        *count += 1;
        if !self.authorization_labels.contains(&authorization_label) {
            self.authorization_labels.push(authorization_label);
        }
        self.witnesses.push(Witness {
            anchor,
            expected: expected.to_vec(),
            raw_identifier,
            authorization_label,
        });
        Ok(())
    }
}
const fn word(byte: u8) -> bool {
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
        let mut hydrated = ContextFile {
            path: file.path.clone(),
            blob: file.blob,
            source_bytes: bytes.len(),
            anchors: file.witnesses.iter().map(|w| w.anchor.clone()).collect(),
            excerpts,
            authorization_labels: file.authorization_labels.clone(),
            anchor_authorization_labels: file
                .witnesses
                .iter()
                .map(|w| w.authorization_label)
                .collect(),
            lineage_commitment: [0; 32],
        };
        // All native source and span checks above precede this immutable saved
        // commitment. Rendering compares against it; it never remints evidence.
        hydrated.lineage_commitment = hydrated.commitment(&mut || check(cancelled))?;
        self.files.push(hydrated);
        self.source_bytes = source_bytes;
        self.excerpt_bytes = excerpt_bytes;
        self.windows = windows;
        check(cancelled)
    }
}

#[cfg(test)]
mod tests;
