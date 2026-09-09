//! Byte-exact, bounded source review. This is a derived read, not a merge,
//! approval, patch application, or authorization mechanism. The object owner
//! supplies the same identity-verified source used by native merge preparation.

use std::collections::BTreeMap;
use fgit_diff::{CommitGraph, DiffAlgorithm, DiffError, DiffLimits, DiffOptions, Edit,
    MergeBaseError, MergeBaseLimits, MergeBaseResult, ParentSet, RenameProfile,
    TreeChange, TreeDiffLimits, TreeDiffOptions, TreeEntry, TreeMode, diff, diff_trees,
    merge_bases_all};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId, RepositoryId};
use crate::aggregate::{AggregateVersion, PullRequestNumber};
use crate::preparation::{MergeObjectSource, MergeSourceError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparisonMode { Direct, MergeBase }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewSelection {
    References { before: RefName, after: RefName },
    PullRequest { number: PullRequestNumber, expected_version: Option<AggregateVersion> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewOptions {
    pub mode: ComparisonMode,
    /// Raw path-component prefixes, never glob, shell or filesystem patterns.
    pub paths: Vec<Vec<u8>>,
    pub context_lines: usize,
    pub limits: ReviewLimits,
}
impl Default for ReviewOptions {
    fn default() -> Self {
        Self { mode: ComparisonMode::Direct, paths: Vec::new(), context_lines: 3,
            limits: ReviewLimits::default() }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewLimits {
    pub max_tree_entries: usize,
    pub max_changes: usize,
    pub max_text_files: usize,
    pub max_blob_bytes: usize,
    pub max_output_bytes: usize,
    pub max_hunks: usize,
    pub max_diff_work: usize,
}
impl Default for ReviewLimits {
    fn default() -> Self {
        Self { max_tree_entries: 100_000, max_changes: 512, max_text_files: 64,
            max_blob_bytes: 1024 * 1024, max_output_bytes: 8 * 1024 * 1024,
            max_hunks: 4096, max_diff_work: 1_000_000 }
    }
}
impl ReviewOptions {
    pub fn validate(&self) -> Result<(), ReviewError> {
        let max = ReviewLimits::default();
        let limits = self.limits;
        for (value, ceiling) in [(limits.max_tree_entries, max.max_tree_entries),
            (limits.max_changes, max.max_changes), (limits.max_text_files, max.max_text_files),
            (limits.max_blob_bytes, max.max_blob_bytes), (limits.max_output_bytes, max.max_output_bytes),
            (limits.max_hunks, max.max_hunks), (limits.max_diff_work, max.max_diff_work)]
        {
            if value == 0 || value > ceiling { return Err(ReviewError::InvalidOptions); }
        }
        if self.context_lines > 20 || self.paths.len() > 64
            || self.paths.iter().any(|path| !valid_path(path))
        { return Err(ReviewError::InvalidOptions); }
        Ok(())
    }
    fn selected(&self, path: &[u8]) -> bool {
        self.paths.is_empty() || self.paths.iter().any(|prefix| under(path, prefix))
    }
    fn descend(&self, path: &[u8]) -> bool {
        self.selected(path) || self.paths.iter().any(|prefix| under(prefix, path))
    }
}
fn under(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix || path.strip_prefix(prefix).is_some_and(|rest| rest.starts_with(b"/"))
}
fn valid_path(path: &[u8]) -> bool {
    !path.is_empty() && path.len() <= 4096 && !path.contains(&0)
        && path.split(|byte| *byte == b'/').all(|part| !part.is_empty() && part != b"." && part != b"..")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryIdentity { pub mode: u32, pub oid: GitOid }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind { Added, Deleted, Modified, ModeChanged, TypeChanged }

/// Half-open byte interval and zero-based line interval in the original blob.
/// Newlines belong to their lines; CRLF and missing final LF remain exact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewSpan {
    pub byte_start: usize, pub byte_end: usize,
    pub line_start: usize, pub line_count: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewHunk {
    pub old: ReviewSpan, pub new: ReviewSpan,
    pub before: Vec<u8>, pub after: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewContent {
    /// Mode-only change; no content bytes were read.
    Identical,
    /// Directory/submodule identities only. Submodules are never traversed.
    ObjectOnly,
    Binary { before_bytes: usize, after_bytes: usize },
    Text { algorithm: DiffAlgorithm, additions: usize, deletions: usize,
        before_bytes: usize, after_bytes: usize, hunks: Vec<ReviewHunk> },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedEntry {
    pub path: Vec<u8>, pub before: Option<EntryIdentity>, pub after: Option<EntryIdentity>,
    pub kind: ChangeKind, pub content: ReviewContent,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceComparison {
    pub mode: ComparisonMode,
    pub requested_before: GitOid,
    pub requested_after: GitOid,
    pub compared_before: GitOid,
    pub before_tree: GitOid,
    pub after_tree: GitOid,
    /// Directory records are explicit; this is not a regular-file count.
    pub entries: Vec<ReviewedEntry>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReview {
    pub repository_id: RepositoryId,
    pub source_head: RepositoryAuthorityHeadId,
    pub before_reference: RefName,
    pub after_reference: RefName,
    pub pull_request: Option<(PullRequestNumber, AggregateVersion)>,
    pub comparison: SourceComparison,
}

#[derive(Debug)]
pub enum ReviewError {
    InvalidOptions,
    InvalidObject(GitOid),
    InvalidTree,
    Source(MergeSourceError),
    Graph(MergeBaseError<GitOid, MergeSourceError>),
    NoCommonAncestor,
    MultipleMergeBases(Vec<GitOid>),
    Budget(&'static str),
    Diff(DiffError),
}
impl std::fmt::Display for ReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "source review refused: {self:?}")
    }
}
impl std::error::Error for ReviewError {}
impl From<MergeSourceError> for ReviewError {
    fn from(value: MergeSourceError) -> Self { Self::Source(value) }
}

struct Graph<'a, S>(&'a S, GitHashAlgorithm);
impl<S: MergeObjectSource> CommitGraph for Graph<'_, S> {
    type CommitId = GitOid;
    type Error = MergeSourceError;
    fn parents_of(&self, id: &GitOid) -> Result<ParentSet<GitOid>, MergeSourceError> {
        self.0.checkpoint()?;
        if id.is_zero() || id.algorithm() != self.1 { return Err(MergeSourceError::InvalidObject(*id)); }
        let commit = self.0.commit(*id)?;
        if commit.tree.is_zero() || commit.tree.algorithm() != self.1
            || commit.parents.iter().any(|id| id.is_zero() || id.algorithm() != self.1)
        { return Err(MergeSourceError::InvalidObject(*id)); }
        self.0.checkpoint()?;
        Ok(ParentSet::Complete(commit.parents))
    }
}

/// Compare exact immutable commits. MergeBase compares their unique best base
/// to `after`; Direct compares their trees without ancestry assumptions.
/// A budget/error returns no successful partial report. Paths narrow output
/// and traversal; they do not confer object access. No rename heuristics,
/// attributes, textconv, external drivers or whitespace normalization run.
pub fn compare_source<S: MergeObjectSource>(
    source: &S, format: GitHashAlgorithm, before: GitOid, after: GitOid, options: &ReviewOptions,
) -> Result<SourceComparison, ReviewError> {
    options.validate()?;
    source.checkpoint()?;
    for id in [before, after] {
        if id.is_zero() || id.algorithm() != format { return Err(ReviewError::InvalidObject(id)); }
    }
    let compared_before = match options.mode {
        ComparisonMode::Direct => before,
        ComparisonMode::MergeBase => match merge_bases_all(&Graph(source, format), before, after,
            MergeBaseLimits { max_commits: 4096, max_edges: 16_384 }).map_err(ReviewError::Graph)?
        {
            MergeBaseResult::Bases(bases) if bases.len() == 1 => bases[0],
            MergeBaseResult::Bases(bases) => return Err(ReviewError::MultipleMergeBases(bases)),
            MergeBaseResult::NoCommonAncestor => return Err(ReviewError::NoCommonAncestor),
        },
    };
    let before_tree = source.commit(compared_before)?.tree;
    let after_tree = source.commit(after)?.tree;
    for id in [before_tree, after_tree] {
        if id.is_zero() || id.algorithm() != format { return Err(ReviewError::InvalidObject(id)); }
    }
    let mut walker = Walker { source, format, options, entries: Vec::new(),
        trees: 0, text_files: 0, output_bytes: 0, hunks: 0 };
    walker.directory(Some(before_tree), Some(after_tree), &[], 0)?;
    walker.entries.sort_by(|a, b| a.path.cmp(&b.path));
    if walker.entries.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err(ReviewError::InvalidTree);
    }
    source.checkpoint()?;
    Ok(SourceComparison { mode: options.mode, requested_before: before, requested_after: after,
        compared_before, before_tree, after_tree, entries: walker.entries })
}

struct Walker<'a, S> {
    source: &'a S, format: GitHashAlgorithm, options: &'a ReviewOptions,
    entries: Vec<ReviewedEntry>, trees: usize, text_files: usize, output_bytes: usize, hunks: usize,
}
fn is_tree(mode: u32) -> bool { mode == 0o040000 }
fn is_blob(mode: u32) -> bool { matches!(mode, 0o100644 | 0o100755 | 0o120000) }
fn identity(entry: &TreeEntry<GitOid>) -> EntryIdentity { EntryIdentity { mode: entry.mode.0, oid: entry.object } }

impl<S: MergeObjectSource> Walker<'_, S> {
    fn tree(&mut self, id: Option<GitOid>) -> Result<Vec<TreeEntry<GitOid>>, ReviewError> {
        let Some(id) = id else { return Ok(Vec::new()); };
        self.source.checkpoint()?;
        let entries = self.source.tree(id)?;
        self.trees = self.trees.checked_add(entries.len()).filter(|n| *n <= self.options.limits.max_tree_entries)
            .ok_or(ReviewError::Budget("tree entries"))?;
        let mut names = std::collections::BTreeSet::new();
        for entry in &entries {
            if !valid_path(&entry.name) || entry.name.contains(&b'/') || !names.insert(&entry.name)
                || !matches!(entry.mode, 0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000)
                || entry.oid.is_zero() || entry.oid.algorithm() != self.format
            { return Err(ReviewError::InvalidTree); }
        }
        Ok(entries.into_iter().map(|entry| TreeEntry {
            path: entry.name, mode: TreeMode(entry.mode), object: entry.oid,
        }).collect())
    }
    fn directory(&mut self, old: Option<GitOid>, new: Option<GitOid>, parent: &[u8], depth: usize) -> Result<(), ReviewError> {
        self.source.checkpoint()?;
        if old == new { return Ok(()); }
        if depth > 64 { return Err(ReviewError::Budget("tree depth")); }
        let old_entries = self.tree(old)?;
        let new_entries = self.tree(new)?;
        let differences = diff_trees(old_entries, new_entries, TreeDiffOptions {
            rename: RenameProfile::Disabled,
            limits: TreeDiffLimits { max_entries_per_tree: self.options.limits.max_tree_entries,
                max_changes: self.options.limits.max_tree_entries },
        }).map_err(|_| ReviewError::InvalidTree)?;
        // Git's directory terminator can reorder a file->directory transition
        // around names such as `a.b`. Coalesce the two sides by exact raw name
        // before recursion; otherwise one path could be emitted twice.
        let mut pairs: BTreeMap<Vec<u8>, (Option<TreeEntry<GitOid>>, Option<TreeEntry<GitOid>>)> = BTreeMap::new();
        for change in differences.changes {
            let (old, new) = match change {
                TreeChange::Added(new) => (None, Some(new)),
                TreeChange::Deleted(old) => (Some(old), None),
                TreeChange::Modified { before, after } | TreeChange::ModeChanged { before, after, .. } => (Some(before), Some(after)),
                TreeChange::Renamed { .. } => return Err(ReviewError::InvalidTree),
            };
            let name = old.as_ref().or(new.as_ref()).ok_or(ReviewError::InvalidTree)?.path.clone();
            let pair = pairs.entry(name).or_default();
            if old.is_some() { if pair.0.is_some() { return Err(ReviewError::InvalidTree); } pair.0 = old; }
            if new.is_some() { if pair.1.is_some() { return Err(ReviewError::InvalidTree); } pair.1 = new; }
        }
        for (name, (old, new)) in pairs {
            self.source.checkpoint()?;
            if parent.len() + name.len() + usize::from(!parent.is_empty()) > 4096 {
                return Err(ReviewError::Budget("path bytes"));
            }
            let mut path = parent.to_vec();
            if !path.is_empty() { path.push(b'/'); }
            path.extend_from_slice(&name);
            let old_tree = old.as_ref().filter(|entry| is_tree(entry.mode.0)).map(|entry| entry.object);
            let new_tree = new.as_ref().filter(|entry| is_tree(entry.mode.0)).map(|entry| entry.object);
            if self.options.selected(&path) {
                self.entry(path.clone(), old.as_ref().map(identity), new.as_ref().map(identity))?;
            }
            if (old_tree.is_some() || new_tree.is_some()) && self.options.descend(&path) {
                self.directory(old_tree, new_tree, &path, depth + 1)?;
            }
        }
        Ok(())
    }
    fn blob(&self, entry: Option<EntryIdentity>) -> Result<Vec<u8>, ReviewError> {
        let Some(entry) = entry.filter(|entry| is_blob(entry.mode)) else { return Ok(Vec::new()); };
        self.source.checkpoint()?;
        let body = self.source.blob(entry.oid)?;
        if body.len() > self.options.limits.max_blob_bytes { return Err(ReviewError::Budget("blob bytes")); }
        self.source.checkpoint()?;
        Ok(body)
    }
    fn entry(&mut self, path: Vec<u8>, before: Option<EntryIdentity>, after: Option<EntryIdentity>) -> Result<(), ReviewError> {
        if self.entries.len() >= self.options.limits.max_changes { return Err(ReviewError::Budget("changed entries")); }
        self.charge(path.len())?;
        let kind = match (before, after) {
            (None, Some(_)) => ChangeKind::Added, (Some(_), None) => ChangeKind::Deleted,
            (Some(a), Some(b)) if a.mode & 0o170000 != b.mode & 0o170000 => ChangeKind::TypeChanged,
            (Some(a), Some(b)) if a.mode != b.mode => ChangeKind::ModeChanged,
            (Some(_), Some(_)) => ChangeKind::Modified, _ => return Err(ReviewError::InvalidTree),
        };
        let content = if before.zip(after).is_some_and(|(a, b)| a.oid == b.oid && is_blob(a.mode) && is_blob(b.mode)) {
            ReviewContent::Identical
        } else if !before.is_some_and(|e| is_blob(e.mode)) && !after.is_some_and(|e| is_blob(e.mode)) {
            ReviewContent::ObjectOnly
        } else {
            let old = self.blob(before)?;
            let new = self.blob(after)?;
            if old.contains(&0) || new.contains(&0) {
                ReviewContent::Binary { before_bytes: old.len(), after_bytes: new.len() }
            } else {
                self.text_files += 1;
                if self.text_files > self.options.limits.max_text_files { return Err(ReviewError::Budget("text files")); }
                self.text(&old, &new)?
            }
        };
        self.entries.push(ReviewedEntry { path, before, after, kind, content });
        Ok(())
    }
    fn charge(&mut self, bytes: usize) -> Result<(), ReviewError> {
        self.output_bytes = self.output_bytes.checked_add(bytes).filter(|n| *n <= self.options.limits.max_output_bytes)
            .ok_or(ReviewError::Budget("output bytes"))?;
        Ok(())
    }
    fn text(&mut self, old: &[u8], new: &[u8]) -> Result<ReviewContent, ReviewError> {
        self.source.checkpoint()?;
        let result = diff(old, new, DiffOptions::myers_lines(DiffLimits {
            max_input_bytes: 2 * self.options.limits.max_blob_bytes, max_units: 100_000,
            max_work: self.options.limits.max_diff_work, max_trace_cells: 512_000,
        })).map_err(ReviewError::Diff)?;
        // The existing synchronous diff is bounded per invocation. Cancellation
        // is checked before/after it, not falsely claimed inside every frontier.
        self.source.checkpoint()?;
        let old_lines = line_offsets(old);
        let new_lines = line_offsets(new);
        let (mut additions, mut deletions) = (0, 0);
        let mut ranges: Vec<(usize, usize, usize, usize)> = Vec::new();
        for edit in &result.edits {
            let a = edit.old_span(); let b = edit.new_span();
            match edit {
                Edit::Equal { .. } => continue,
                Edit::Delete { .. } => deletions += a.unit_end - a.unit_start,
                Edit::Insert { .. } => additions += b.unit_end - b.unit_start,
            }
            let context = self.options.context_lines;
            let range = (a.unit_start.saturating_sub(context), (a.unit_end + context).min(old_lines.len() - 1),
                b.unit_start.saturating_sub(context), (b.unit_end + context).min(new_lines.len() - 1));
            if let Some(last) = ranges.last_mut()
                && range.0 <= last.1 && range.2 <= last.3
            { last.1 = last.1.max(range.1); last.3 = last.3.max(range.3); continue; }
            if ranges.len() >= self.options.limits.max_hunks.saturating_sub(self.hunks) {
                return Err(ReviewError::Budget("hunks"));
            }
            ranges.push(range);
        }
        let mut hunks = Vec::with_capacity(ranges.len());
        for (a, b, c, d) in ranges {
            self.source.checkpoint()?;
            let old_span = span(&old_lines, a, b)?;
            let new_span = span(&new_lines, c, d)?;
            let before = old.get(old_span.byte_start..old_span.byte_end).ok_or(ReviewError::Diff(DiffError::MalformedScript))?;
            let after = new.get(new_span.byte_start..new_span.byte_end).ok_or(ReviewError::Diff(DiffError::MalformedScript))?;
            self.charge(before.len() + after.len())?;
            hunks.push(ReviewHunk { old: old_span, new: new_span, before: before.to_vec(), after: after.to_vec() });
        }
        self.hunks += hunks.len();
        Ok(ReviewContent::Text { algorithm: result.algorithm, additions, deletions,
            before_bytes: old.len(), after_bytes: new.len(), hunks })
    }
}
fn line_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = vec![0];
    for (index, byte) in bytes.iter().enumerate() { if *byte == b'\n' { offsets.push(index + 1); } }
    if offsets.last() != Some(&bytes.len()) { offsets.push(bytes.len()); }
    offsets
}
fn span(offsets: &[usize], start: usize, end: usize) -> Result<ReviewSpan, ReviewError> {
    if start > end { return Err(ReviewError::Diff(DiffError::MalformedScript)); }
    Ok(ReviewSpan { byte_start: *offsets.get(start).ok_or(ReviewError::Diff(DiffError::MalformedScript))?,
        byte_end: *offsets.get(end).ok_or(ReviewError::Diff(DiffError::MalformedScript))?,
        line_start: start, line_count: end - start })
}

#[cfg(test)]
mod tests;
