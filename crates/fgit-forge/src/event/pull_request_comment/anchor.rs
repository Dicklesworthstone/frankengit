//! Exact raw-source anchors. Tree membership, the comparison base, and complete
//! line boundaries are verified from immutable objects, never a supplied diff.

use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_diff::{
    DiffError, DiffLimits, DiffOptions, MergeBaseError, MergeBaseLimits, MergeBaseResult,
    diff_with_cancellation,
};
use fgit_types::{GitOid, RefName};

use crate::AggregateVersion;
use crate::event::{invalid_native, pull_request::PullRequestData};
use crate::preparation::{MergeEntry, MergeObjectSource, MergeSourceError, source_merge_bases};

pub const SOURCE_COMMENT_PROFILE: &str = "frankengit.source-comment.myers-lines.v1";
pub const MAX_SOURCE_COMMENT_BLOB_BYTES: u64 = 1024 * 1024;
pub const MAX_SOURCE_COMMENT_SPAN_BYTES: u64 = 65_536;
pub const MAX_SOURCE_COMMENT_LINES: u64 = 128;
const MAX_TREE_ENTRIES: usize = 100_000;
const MAX_PATH_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCommentComparison {
    Direct,
    MergeBase,
}
impl SourceCommentComparison {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::MergeBase => "merge_base",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCommentSide {
    Before,
    After,
}
impl SourceCommentSide {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

/// Presentation status at the comment page's selected PR metadata version.
/// Exact is not approval, current branch-tip equality, or a remapping claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCommentStatus {
    Exact,
    Outdated,
}
impl SourceCommentStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Outdated => "outdated",
        }
    }
}

/// Original Git coordinates plus whole LF-delimited source lines. Offsets are
/// zero-based; bytes are half-open, line_count is positive. LF belongs to its
/// line; CRLF and an unterminated last line are preserved without normalization.
/// A final LF does not create an additional empty source line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCommentAnchor {
    pub pull_request_version: AggregateVersion,
    pub source_ref: RefName,
    pub target_ref: RefName,
    pub source_tip: GitOid,
    pub target_tip: GitOid,
    pub compared_base: GitOid,
    pub comparison: SourceCommentComparison,
    pub path: Vec<u8>,
    pub side: SourceCommentSide,
    pub blob: GitOid,
    pub mode: u32,
    pub byte_start: u64,
    pub byte_end: u64,
    pub line_start: u64,
    pub line_count: u64,
}

impl SourceCommentAnchor {
    /// Structural validation only. Publication must also call verify_source
    /// through an authority-selected, identity-checking object owner.
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        let format = self.source_tip.algorithm();
        if self.source_ref == self.target_ref
            || [&self.source_ref, &self.target_ref]
                .iter()
                .any(|name| !name.as_bytes().starts_with(b"refs/heads/"))
            || [
                self.source_tip,
                self.target_tip,
                self.compared_base,
                self.blob,
            ]
            .iter()
            .any(|oid| oid.is_zero() || oid.algorithm() != format)
            || (self.comparison == SourceCommentComparison::Direct
                && self.compared_base != self.target_tip)
            || self.path.is_empty()
            || self.path.len() > 4096
            || self.path.contains(&0)
            || self.path.split(|byte| *byte == b'/').count() > MAX_PATH_DEPTH
            || self
                .path
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
            || !matches!(self.mode, 0o100644 | 0o100755 | 0o120000)
            || self.byte_start >= self.byte_end
            || self.byte_end > MAX_SOURCE_COMMENT_BLOB_BYTES
            || self.byte_end - self.byte_start > MAX_SOURCE_COMMENT_SPAN_BYTES
            || (self.byte_start == 0) != (self.line_start == 0)
            || self.line_start > self.byte_start
            || self.line_count > self.byte_end - self.byte_start
            || !(1..=MAX_SOURCE_COMMENT_LINES).contains(&self.line_count)
            || self
                .line_start
                .checked_add(self.line_count)
                .is_none_or(|end| end > MAX_SOURCE_COMMENT_BLOB_BYTES)
        {
            return Err(invalid_native("pull_request_comment.source_anchor"));
        }
        Ok(())
    }

    #[must_use]
    pub fn status(&self, version: AggregateVersion, data: &PullRequestData) -> SourceCommentStatus {
        if self.pull_request_version == version
            && self.source_ref == data.source_ref
            && self.target_ref == data.target_ref
            && self.source_tip == data.source_tip
            && self.target_tip == data.target_tip
        {
            SourceCommentStatus::Exact
        } else {
            SourceCommentStatus::Outdated
        }
    }

    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_scalar(self.pull_request_version.get());
        out.write_ref_name(&self.source_ref)?;
        out.write_ref_name(&self.target_ref)?;
        out.write_git_oid(&self.source_tip);
        out.write_git_oid(&self.target_tip);
        out.write_git_oid(&self.compared_base);
        out.write_scalar(match self.comparison {
            SourceCommentComparison::Direct => 0_u8,
            SourceCommentComparison::MergeBase => 1,
        });
        out.write_bytes("source_anchor.path", &self.path)?;
        out.write_scalar(match self.side {
            SourceCommentSide::Before => 0_u8,
            SourceCommentSide::After => 1,
        });
        out.write_git_oid(&self.blob);
        out.write_scalar(self.mode);
        out.write_scalar(self.byte_start);
        out.write_scalar(self.byte_end);
        out.write_scalar(self.line_start);
        out.write_scalar(self.line_count);
        Ok(())
    }

    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let pull_request_version = AggregateVersion::try_new(
            input.read_scalar::<u64>("source_anchor.pull_request_version")?,
        )
        .ok_or_else(|| invalid_native("source_anchor.pull_request_version"))?;
        let source_ref = input.read_ref_name()?;
        let target_ref = input.read_ref_name()?;
        let source_tip = input.read_git_oid()?;
        let target_tip = input.read_git_oid()?;
        let compared_base = input.read_git_oid()?;
        let comparison = match input.read_scalar::<u8>("source_anchor.comparison")? {
            0 => SourceCommentComparison::Direct,
            1 => SourceCommentComparison::MergeBase,
            _ => return Err(invalid_native("source_anchor.comparison")),
        };
        let path = input.read_bytes("source_anchor.path")?;
        if path.len() > 4096 {
            return Err(invalid_native("source_anchor.path"));
        }
        let path = path.to_vec();
        let side = match input.read_scalar::<u8>("source_anchor.side")? {
            0 => SourceCommentSide::Before,
            1 => SourceCommentSide::After,
            _ => return Err(invalid_native("source_anchor.side")),
        };
        let value = Self {
            pull_request_version,
            source_ref,
            target_ref,
            source_tip,
            target_tip,
            compared_base,
            comparison,
            path,
            side,
            blob: input.read_git_oid()?,
            mode: input.read_scalar::<u32>("source_anchor.mode")?,
            byte_start: input.read_scalar::<u64>("source_anchor.byte_start")?,
            byte_end: input.read_scalar::<u64>("source_anchor.byte_end")?,
            line_start: input.read_scalar::<u64>("source_anchor.line_start")?,
            line_count: input.read_scalar::<u64>("source_anchor.line_count")?,
        };
        value.validate()?;
        Ok(value)
    }

    /// Independently verify the comparison base, both path identities and the
    /// original complete source lines. The path must have changed identity or
    /// mode; comments may select any real line of that changed file, including
    /// context. A caller-provided rendered diff or excerpt is never consumed.
    pub fn verify_source(&self, source: &impl MergeObjectSource) -> Result<(), SourceCommentError> {
        self.validate().map_err(|_| SourceCommentError::Invalid)?;
        source.checkpoint()?;
        if self.comparison == SourceCommentComparison::MergeBase {
            let result = source_merge_bases(
                source,
                self.source_tip.algorithm(),
                self.target_tip,
                self.source_tip,
                MergeBaseLimits {
                    max_commits: 4096,
                    max_edges: 16_384,
                },
            );
            let bases = match result {
                Ok(MergeBaseResult::Bases(bases)) => bases,
                Ok(MergeBaseResult::NoCommonAncestor) => return Err(SourceCommentError::Invalid),
                Err(MergeBaseError::Source(error)) => return Err(error.into()),
                Err(
                    MergeBaseError::CommitLimitExceeded { .. }
                    | MergeBaseError::EdgeLimitExceeded { .. },
                ) => return Err(SourceCommentError::Budget),
                Err(_) => return Err(SourceCommentError::Invalid),
            };
            if bases.as_slice() != [self.compared_base] {
                return Err(SourceCommentError::Invalid);
            }
        }
        // Even when a direct comparison uses only one side's blob, both named
        // tips must parse as commits under the selected object authority.
        source.commit(self.target_tip)?;
        let before = source.commit(self.compared_base)?;
        let after = source.commit(self.source_tip)?;
        let mut entries = 0;
        let old = path_entry(source, before.tree, &self.path, &mut entries)?;
        let new = path_entry(source, after.tree, &self.path, &mut entries)?;
        if old == new {
            return Err(SourceCommentError::Invalid);
        }
        let selected = match self.side {
            SourceCommentSide::Before => old.as_ref(),
            SourceCommentSide::After => new.as_ref(),
        };
        let Some(entry) = selected else {
            return Err(SourceCommentError::Invalid);
        };
        if entry.oid != self.blob || entry.mode != self.mode {
            return Err(SourceCommentError::Invalid);
        }
        source.checkpoint()?;
        let old_bytes = blob(source, old.as_ref())?;
        let new_bytes = blob(source, new.as_ref())?;
        // The same closed Myers-line profile used by source review. No supplied
        // edit script, hunk, rendered text, attributes or external driver is trusted.
        let stopped = std::cell::Cell::new(None);
        let comparison = diff_with_cancellation(
            &old_bytes,
            &new_bytes,
            DiffOptions::myers_lines(DiffLimits {
                max_input_bytes: 2 * MAX_SOURCE_COMMENT_BLOB_BYTES as usize,
                max_units: 100_000,
                max_work: 1_000_000,
                max_trace_cells: 512_000,
            }),
            &|| match source.checkpoint() {
                Ok(()) => false,
                Err(error) => {
                    stopped.set(Some(error));
                    true
                }
            },
        );
        if let Some(error) = stopped.into_inner() {
            return Err(error.into());
        }
        source.checkpoint()?;
        comparison.map_err(|error| match error {
            DiffError::MalformedScript => SourceCommentError::Invalid,
            _ => SourceCommentError::Budget,
        })?;
        let bytes = match self.side {
            SourceCommentSide::Before => &old_bytes,
            SourceCommentSide::After => &new_bytes,
        };
        let mut line = 0_u64;
        let mut start = 0_usize;
        let mut selected_start = None;
        let mut selected_end = None;
        for (index, byte) in bytes.iter().enumerate() {
            if index % 4096 == 0 {
                source.checkpoint()?;
            }
            if *byte == b'\n' || index + 1 == bytes.len() {
                if line == self.line_start {
                    selected_start = Some(start as u64);
                }
                line += 1;
                if line == self.line_start + self.line_count {
                    selected_end = Some(index as u64 + 1);
                }
                start = index + 1;
            }
        }
        if selected_start != Some(self.byte_start) || selected_end != Some(self.byte_end) {
            return Err(SourceCommentError::Invalid);
        }
        source.checkpoint()?;
        Ok(())
    }
}

/// Refusal classification is retained through the native projection so that
/// cancellation, exhaustion and unavailable input never become fake corruption.
#[derive(Debug, Eq, PartialEq)]
pub enum SourceCommentError {
    Invalid,
    Budget,
    Source(MergeSourceError),
}
impl From<MergeSourceError> for SourceCommentError {
    fn from(value: MergeSourceError) -> Self {
        Self::Source(value)
    }
}

fn blob(
    source: &impl MergeObjectSource,
    entry: Option<&MergeEntry>,
) -> Result<Vec<u8>, SourceCommentError> {
    let Some(entry) = entry.filter(|entry| matches!(entry.mode, 0o100644 | 0o100755 | 0o120000))
    else {
        return Ok(Vec::new());
    };
    source.checkpoint()?;
    let bytes = source.blob(entry.oid)?;
    source.checkpoint()?;
    if bytes.len() as u64 > MAX_SOURCE_COMMENT_BLOB_BYTES {
        return Err(SourceCommentError::Budget);
    }
    if bytes.contains(&0) {
        return Err(SourceCommentError::Invalid);
    }
    Ok(bytes)
}

fn path_entry(
    source: &impl MergeObjectSource,
    mut tree: GitOid,
    path: &[u8],
    count: &mut usize,
) -> Result<Option<MergeEntry>, SourceCommentError> {
    let mut components = path.split(|byte| *byte == b'/').peekable();
    while let Some(component) = components.next() {
        source.checkpoint()?;
        let values = source.tree(tree)?;
        *count = count
            .checked_add(values.len())
            .filter(|n| *n <= MAX_TREE_ENTRIES)
            .ok_or(SourceCommentError::Budget)?;
        let mut names = std::collections::BTreeSet::new();
        let mut found = None;
        for entry in values {
            source.checkpoint()?;
            if entry.name.is_empty()
                || entry.name.contains(&0)
                || entry.name.contains(&b'/')
                || entry.name == b"."
                || entry.name == b".."
                || !names.insert(entry.name.clone())
                || entry.oid.is_zero()
                || entry.oid.algorithm() != tree.algorithm()
                || !matches!(
                    entry.mode,
                    0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000
                )
            {
                return Err(SourceCommentError::Invalid);
            }
            if entry.name == component {
                found = Some(entry);
            }
        }
        let Some(entry) = found else {
            return Ok(None);
        };
        if components.peek().is_none() {
            return Ok(Some(entry));
        }
        if entry.mode != 0o040000 {
            return Ok(None);
        }
        tree = entry.oid;
    }
    Err(SourceCommentError::Invalid)
}

#[cfg(test)]
mod tests;
