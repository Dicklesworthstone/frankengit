//! Bounded native ancestry and exact-line attribution. Derived data, never
//! author authentication, review approval, or repository publication authority.
//! Log order is child-before-parent, with native-ID order between ready nodes.
//! Blame follows exact line matches through all parents, in stored parent order.
//! It does not guess renames, copies, whitespace equivalence or human authorship.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_diff::{DiffAlgorithm, DiffError, DiffLimits, DiffOptions, Edit, diff};
use fgit_types::{GitHashAlgorithm, GitOid};
use crate::preparation::{CommitInput, MergeObjectSource, MergeSourceError};

/// The same verified object owner used by source review, plus exact commit
/// bytes. Bodies must be bounded before reading and correspond to `commit`.
pub trait HistorySource: MergeObjectSource {
    fn commit_body(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryLimits {
    pub max_commits: usize,
    pub max_edges: usize,
    pub max_tree_entries: usize,
    pub max_blob_bytes: usize,
    pub max_lines: usize,
    pub max_cached_bytes: usize,
    pub max_comparisons: usize,
    pub max_diff_work: usize,
    pub max_metadata_bytes: usize,
}
impl Default for HistoryLimits {
    fn default() -> Self {
        Self { max_commits: 4096, max_edges: 16_384, max_tree_entries: 100_000,
            max_blob_bytes: 1024 * 1024, max_lines: 20_000, max_cached_bytes: 32 * 1024 * 1024,
            max_comparisons: 128, max_diff_work: 1_000_000, max_metadata_bytes: 4 * 1024 * 1024 }
    }
}
impl HistoryLimits {
    pub fn validate(self) -> Result<(), HistoryError> {
        let ceiling = Self::default();
        for (value, max) in [(self.max_commits, ceiling.max_commits), (self.max_edges, ceiling.max_edges),
            (self.max_tree_entries, ceiling.max_tree_entries), (self.max_blob_bytes, ceiling.max_blob_bytes),
            (self.max_lines, ceiling.max_lines), (self.max_cached_bytes, ceiling.max_cached_bytes),
            (self.max_comparisons, ceiling.max_comparisons), (self.max_diff_work, ceiling.max_diff_work),
            (self.max_metadata_bytes, ceiling.max_metadata_bytes)]
        { if value == 0 || value > max { return Err(HistoryError::InvalidOptions); } }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryCommit {
    pub id: GitOid,
    pub tree: GitOid,
    /// Original parent order, not the topological display order.
    pub parents: Vec<GitOid>,
    /// Exact native body; author/signature headers remain untrusted claims.
    pub body: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogOptions { pub after: usize, pub limit: usize, pub limits: HistoryLimits }
impl Default for LogOptions {
    fn default() -> Self { Self { after: 0, limit: 50, limits: HistoryLimits::default() } }
}
impl LogOptions {
    pub fn validate(self) -> Result<(), HistoryError> {
        self.limits.validate()?;
        if self.limit == 0 || self.limit > 100 || self.after > self.limits.max_commits {
            return Err(HistoryError::InvalidOptions);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryPage {
    pub tip: GitOid,
    pub total_commits: usize,
    pub after: usize,
    pub next_after: Option<usize>,
    pub commits: Vec<HistoryCommit>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlameOptions {
    pub path: Vec<u8>,
    /// Zero-based half-open output line range. None means through the last line.
    pub first_line: usize,
    pub end_line: Option<usize>,
    pub limits: HistoryLimits,
}
impl BlameOptions {
    pub fn validate(&self) -> Result<(), HistoryError> {
        self.limits.validate()?;
        if !valid_path(&self.path) || self.first_line > self.limits.max_lines
            || self.end_line.is_some_and(|end| end < self.first_line || end > self.limits.max_lines)
        { return Err(HistoryError::InvalidOptions); }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlameLine {
    pub line: usize,
    pub byte_start: usize,
    pub byte_end: usize,
    pub origin_commit: GitOid,
    pub origin_blob: GitOid,
    pub origin_line: usize,
    pub origin_byte_start: usize,
    pub origin_byte_end: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlameResult {
    pub tip: GitOid,
    pub tree: GitOid,
    pub blob: GitOid,
    pub path: Vec<u8>,
    pub total_lines: usize,
    pub first_line: usize,
    pub end_line: usize,
    pub content_byte_start: usize,
    /// Only the requested lines, not an undisclosed full-file payload.
    pub content: Vec<u8>,
    pub lines: Vec<BlameLine>,
    /// Unique origin records in native-ID order. Identity is not authentication.
    pub origins: Vec<HistoryCommit>,
    pub graph_commits: usize,
    pub comparisons: usize,
    pub algorithms: Vec<DiffAlgorithm>,
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HistoryError {
    InvalidOptions,
    InvalidObject(GitOid),
    InvalidTree,
    CyclicHistory,
    PathUnavailable,
    LineRange,
    BinaryContent,
    Budget(&'static str),
    Source(MergeSourceError),
    Diff(DiffError),
    InconsistentAttribution,
}
impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native history refused: {self:?}")
    }
}
impl std::error::Error for HistoryError {}
impl From<MergeSourceError> for HistoryError {
    fn from(value: MergeSourceError) -> Self { Self::Source(value) }
}
fn valid_path(path: &[u8]) -> bool {
    !path.is_empty() && path.len() <= 4096 && !path.contains(&0)
        && path.split(|b| *b == b'/').count() <= 64
        && path.split(|b| *b == b'/').all(|part| !part.is_empty() && part != b"." && part != b"..")
}
fn check_oid(format: GitHashAlgorithm, id: GitOid) -> Result<(), HistoryError> {
    if id.is_zero() || id.algorithm() != format { Err(HistoryError::InvalidObject(id)) } else { Ok(()) }
}
fn charge(total: &mut usize, amount: usize, limit: usize, field: &'static str) -> Result<(), HistoryError> {
    *total = total.checked_add(amount).filter(|value| *value <= limit).ok_or(HistoryError::Budget(field))?;
    Ok(())
}

struct Graph { commits: BTreeMap<GitOid, CommitInput>, order: Vec<GitOid> }
fn graph(source: &impl HistorySource, format: GitHashAlgorithm, tip: GitOid, limits: HistoryLimits)
    -> Result<Graph, HistoryError>
{
    limits.validate()?;
    check_oid(format, tip)?;
    let mut seen = BTreeSet::from([tip]);
    let mut pending = BTreeSet::from([tip]);
    let mut commits = BTreeMap::new();
    let mut edges = 0;
    while let Some(id) = pending.pop_first() {
        source.checkpoint()?;
        let commit = source.commit(id)?;
        check_oid(format, commit.tree)?;
        charge(&mut edges, commit.parents.len(), limits.max_edges, "commit edges")?;
        for parent in &commit.parents {
            source.checkpoint()?;
            check_oid(format, *parent)?;
            if !seen.contains(parent) {
                if seen.len() >= limits.max_commits { return Err(HistoryError::Budget("commits")); }
                seen.insert(*parent); pending.insert(*parent);
            }
        }
        commits.insert(id, commit);
    }
    // Kahn's algorithm on child -> parent edges. Duplicate parent headers do
    // not turn one graph edge into multiple prerequisites; raw order is kept.
    let mut children: BTreeMap<_, usize> = commits.keys().map(|id| (*id, 0)).collect();
    for commit in commits.values() {
        source.checkpoint()?;
        for parent in commit.parents.iter().copied().collect::<BTreeSet<_>>() {
            *children.get_mut(&parent).ok_or(HistoryError::InvalidObject(parent))? += 1;
        }
    }
    let mut ready: BTreeSet<_> = children.iter().filter_map(|(id, count)| (*count == 0).then_some(*id)).collect();
    let mut order = Vec::with_capacity(commits.len());
    while let Some(id) = ready.pop_first() {
        source.checkpoint()?;
        order.push(id);
        for parent in commits[&id].parents.iter().copied().collect::<BTreeSet<_>>() {
            let count = children.get_mut(&parent).ok_or(HistoryError::InvalidObject(parent))?;
            *count = count.checked_sub(1).ok_or(HistoryError::CyclicHistory)?;
            if *count == 0 { ready.insert(parent); }
        }
    }
    if order.len() != commits.len() { return Err(HistoryError::CyclicHistory); }
    source.checkpoint()?;
    Ok(Graph { commits, order })
}
fn record(source: &impl HistorySource, graph: &Graph, id: GitOid, bytes: &mut usize, limit: usize)
    -> Result<HistoryCommit, HistoryError>
{
    source.checkpoint()?;
    let body = source.commit_body(id)?;
    if body.len() > 64 * 1024 { return Err(HistoryError::Budget("commit metadata")); }
    charge(bytes, body.len(), limit, "metadata bytes")?;
    if git_object_id(id.algorithm(), GitObjectKind::Commit, &body) != id { return Err(HistoryError::InvalidObject(id)); }
    let commit = graph.commits.get(&id).ok_or(HistoryError::InvalidObject(id))?;
    source.checkpoint()?;
    Ok(HistoryCommit { id, tree: commit.tree, parents: commit.parents.clone(), body })
}

/// Return a deterministic topological page of the entire selected commit DAG.
/// The node must pin offset continuations to the same authenticated authority
/// head. A missing ancestor or exceeded traversal bound is not a short page.
pub fn commit_history(source: &impl HistorySource, format: GitHashAlgorithm, tip: GitOid, options: LogOptions)
    -> Result<HistoryPage, HistoryError>
{
    options.validate()?;
    let graph = graph(source, format, tip, options.limits)?;
    if options.after > graph.order.len() { return Err(HistoryError::LineRange); }
    let end = (options.after + options.limit).min(graph.order.len());
    let mut commits = Vec::with_capacity(end - options.after);
    let mut metadata_bytes = 0;
    for id in &graph.order[options.after..end] {
        commits.push(record(source, &graph, *id, &mut metadata_bytes, options.limits.max_metadata_bytes)?);
    }
    source.checkpoint()?;
    Ok(HistoryPage { tip, total_commits: graph.order.len(), after: options.after,
        next_after: (end < graph.order.len()).then_some(end), commits })
}

struct Lines { body: Vec<u8>, spans: Vec<Range<usize>> }
struct Walker<'a, S> {
    source: &'a S, format: GitHashAlgorithm, path: &'a [u8], limits: HistoryLimits,
    paths: BTreeMap<GitOid, Option<GitOid>>, blobs: BTreeMap<GitOid, Lines>,
    entries: usize, cached: usize, comparisons: usize, algorithms: Vec<DiffAlgorithm>,
}
impl<S: HistorySource> Walker<'_, S> {
    fn file(&mut self, root: GitOid) -> Result<Option<GitOid>, HistoryError> {
        self.source.checkpoint()?;
        if let Some(found) = self.paths.get(&root) { return Ok(*found); }
        let parts: Vec<_> = self.path.split(|b| *b == b'/').collect();
        let mut tree = root;
        let mut found = None;
        for (depth, part) in parts.iter().enumerate() {
            self.source.checkpoint()?;
            let entries = self.source.tree(tree)?;
            charge(&mut self.entries, entries.len(), self.limits.max_tree_entries, "tree entries")?;
            let mut names = BTreeSet::new();
            let mut matching = None;
            for entry in entries {
                self.source.checkpoint()?;
                check_oid(self.format, entry.oid)?;
                if entry.name.is_empty() || entry.name.contains(&0) || entry.name.contains(&b'/')
                    || entry.name == b"." || entry.name == b".." || !names.insert(entry.name.clone())
                    || !matches!(entry.mode, 0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000)
                { return Err(HistoryError::InvalidTree); }
                if entry.name.as_slice() == *part { matching = Some(entry); }
            }
            let Some(entry) = matching else { break; };
            if depth + 1 == parts.len() {
                if matches!(entry.mode, 0o100644 | 0o100755) { found = Some(entry.oid); }
            } else if entry.mode == 0o040000 { tree = entry.oid; }
            else { break; }
        }
        self.paths.insert(root, found);
        Ok(found)
    }
    fn load(&mut self, id: GitOid) -> Result<(), HistoryError> {
        self.source.checkpoint()?;
        if self.blobs.contains_key(&id) { return Ok(()); }
        let body = self.source.blob(id)?;
        if body.len() > self.limits.max_blob_bytes { return Err(HistoryError::Budget("blob bytes")); }
        if git_object_id(self.format, GitObjectKind::Blob, &body) != id { return Err(HistoryError::InvalidObject(id)); }
        if body.contains(&0) { return Err(HistoryError::BinaryContent); }
        let count = body.iter().filter(|b| **b == b'\n').count()
            + usize::from(!body.is_empty() && body.last() != Some(&b'\n'));
        if count > self.limits.max_lines { return Err(HistoryError::Budget("line count")); }
        let cost = body.len().checked_add(count * std::mem::size_of::<Range<usize>>())
            .ok_or(HistoryError::Budget("blob cache"))?;
        charge(&mut self.cached, cost, self.limits.max_cached_bytes, "blob cache")?;
        let mut spans = Vec::with_capacity(count);
        let mut at = 0;
        for bytes in body.split_inclusive(|b| *b == b'\n') {
            self.source.checkpoint()?;
            spans.push(at..at + bytes.len()); at += bytes.len();
        }
        self.blobs.insert(id, Lines { body, spans });
        Ok(())
    }
    fn correspondence(&mut self, parent: GitOid, current: GitOid) -> Result<Vec<Option<usize>>, HistoryError> {
        self.load(parent)?; self.load(current)?;
        let old = &self.blobs[&parent]; let new = &self.blobs[&current];
        if parent == current { return Ok((0..new.spans.len()).map(Some).collect()); }
        charge(&mut self.comparisons, 1, self.limits.max_comparisons, "line comparisons")?;
        self.source.checkpoint()?;
        let comparison = diff(&old.body, &new.body, DiffOptions::myers_lines(DiffLimits {
            max_input_bytes: self.limits.max_blob_bytes * 2, max_units: self.limits.max_lines * 2,
            max_work: self.limits.max_diff_work, max_trace_cells: 512_000,
        })).map_err(HistoryError::Diff)?;
        self.source.checkpoint()?;
        if !self.algorithms.contains(&comparison.algorithm) { self.algorithms.push(comparison.algorithm); }
        let mut mapping = vec![None; new.spans.len()];
        for edit in comparison.edits {
            self.source.checkpoint()?;
            if let Edit::Equal { old, new } = edit {
                if old.unit_end - old.unit_start != new.unit_end - new.unit_start
                    || new.unit_end > mapping.len() { return Err(HistoryError::InconsistentAttribution); }
                for (i, slot) in mapping[new.unit_start..new.unit_end].iter_mut().enumerate() {
                    *slot = Some(old.unit_start + i);
                }
            }
        }
        Ok(mapping)
    }
}

/// Trace every requested line through the full ancestry DAG. At a merge, the
/// first stored parent with an exact matching line wins; unmatched lines belong
/// to the merge itself. All propagation is child-before-parent, so convergent
/// history is processed once. Same-path only, no rename/copy guesses. A missing
/// dependency is never interpreted as a root or an original author.
pub fn blame(source: &impl HistorySource, format: GitHashAlgorithm, tip: GitOid, options: &BlameOptions)
    -> Result<BlameResult, HistoryError>
{
    options.validate()?;
    let graph = graph(source, format, tip, options.limits)?;
    let tree = graph.commits[&tip].tree;
    let mut walker = Walker { source, format, path: &options.path, limits: options.limits,
        paths: BTreeMap::new(), blobs: BTreeMap::new(), entries: 0, cached: 0,
        comparisons: 0, algorithms: Vec::new() };
    let blob = walker.file(tree)?.ok_or(HistoryError::PathUnavailable)?;
    walker.load(blob)?;
    let total_lines = walker.blobs[&blob].spans.len();
    let end_line = options.end_line.unwrap_or(total_lines);
    if options.first_line > end_line || end_line > total_lines { return Err(HistoryError::LineRange); }
    let mut answers = vec![None; end_line - options.first_line];
    let mut pending = BTreeMap::from([(tip, (options.first_line..end_line)
        .map(|line| (line - options.first_line, line)).collect::<Vec<_>>())]);
    for current in &graph.order {
        source.checkpoint()?;
        let Some(mut active) = pending.remove(current) else { continue; };
        if active.is_empty() { continue; }
        let commit = &graph.commits[current];
        let current_blob = walker.file(commit.tree)?.ok_or(HistoryError::InconsistentAttribution)?;
        walker.load(current_blob)?;
        let mut parents_seen = BTreeSet::new();
        for parent in &commit.parents {
            source.checkpoint()?;
            if active.is_empty() { break; }
            if !parents_seen.insert(*parent) { continue; }
            let Some(parent_blob) = walker.file(graph.commits[parent].tree)? else { continue; };
            let mapping = walker.correspondence(parent_blob, current_blob)?;
            let mut unmatched = Vec::new();
            for (result, line) in active {
                source.checkpoint()?;
                match mapping.get(line).ok_or(HistoryError::InconsistentAttribution)? {
                    Some(origin) => pending.entry(*parent).or_default().push((result, *origin)),
                    None => unmatched.push((result, line)),
                }
            }
            active = unmatched;
        }
        for (result, line) in active {
            source.checkpoint()?;
            let origin = &walker.blobs[&current_blob];
            let span = origin.spans.get(line).ok_or(HistoryError::InconsistentAttribution)?;
            let target = &walker.blobs[&blob];
            let selected = &target.spans[result + options.first_line];
            if origin.body[span.clone()] != target.body[selected.clone()] || answers[result].is_some() {
                return Err(HistoryError::InconsistentAttribution);
            }
            answers[result] = Some(BlameLine { line: result + options.first_line,
                byte_start: selected.start, byte_end: selected.end, origin_commit: *current,
                origin_blob: current_blob, origin_line: line,
                origin_byte_start: span.start, origin_byte_end: span.end });
        }
    }
    if !pending.is_empty() { return Err(HistoryError::InconsistentAttribution); }
    let lines = answers.into_iter().collect::<Option<Vec<_>>>().ok_or(HistoryError::InconsistentAttribution)?;
    let mut origins = Vec::new(); let mut metadata_bytes = 0;
    for id in lines.iter().map(|line| line.origin_commit).collect::<BTreeSet<_>>() {
        origins.push(record(source, &graph, id, &mut metadata_bytes, options.limits.max_metadata_bytes)?);
    }
    let target = &walker.blobs[&blob];
    let start = target.spans.get(options.first_line).map_or(target.body.len(), |span| span.start);
    let end = target.spans.get(end_line).map_or(target.body.len(), |span| span.start);
    source.checkpoint()?;
    Ok(BlameResult { tip, tree, blob, path: options.path.clone(), total_lines,
        first_line: options.first_line, end_line, content_byte_start: start,
        content: target.body[start..end].to_vec(), lines, origins,
        graph_commits: graph.order.len(), comparisons: walker.comparisons, algorithms: walker.algorithms })
}

#[cfg(test)]
mod tests;
