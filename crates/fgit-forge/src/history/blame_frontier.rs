//! Exact same-path attribution without a mandatory complete ancestry walk.
//!
//! Every requested line has exactly one active route. At each commit the first
//! stored parent with an exact correspondence wins, as in the full-DAG oracle.
//! Different lines may reconverge at an already processed commit. A repeat of
//! the SAME requested line at that commit proves a cycle; the complete touched
//! graph is also checked before success. Ordered blob-pair mappings are shared
//! across routes, without changing diff tie breaking.

use super::{
    BlameLine, BlameOptions, BlameResult, BlameTraversal, CommitInput, DiffLimits, DiffOptions,
    Edit, GitHashAlgorithm, GitOid, Graph, HistoryError, HistorySource, Lines, MergeSourceError,
    Walker, charge, check_oid, record,
};
use fgit_diff::diff_with_cancellation_and_work;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::Arc;

type Assignments = Vec<(usize, usize)>;
type Correspondence = Arc<[Option<usize>]>;

struct Frontier<'a, S> {
    walker: Walker<'a, S>,
    commits: BTreeMap<GitOid, CommitInput>,
    edges: usize,
    mappings: BTreeMap<(GitOid, GitOid), Correspondence>,
    diff_work: usize,
    // One bit per output-line identity, not per original line. Two distinct
    // requested lines may legitimately converge on the same original line.
    visited: BTreeMap<GitOid, Vec<u64>>,
    requested_lines: usize,
}

impl<S: HistorySource> Frontier<'_, S> {
    fn cache(&mut self, bytes: usize, field: &'static str) -> Result<(), HistoryError> {
        charge(
            &mut self.walker.cached,
            bytes,
            self.walker.limits.max_cached_bytes,
            field,
        )
    }

    fn commit(&mut self, id: GitOid) -> Result<(), HistoryError> {
        self.walker.source.checkpoint()?;
        check_oid(self.walker.format, id)?;
        if self.commits.contains_key(&id) {
            return Ok(());
        }
        if self.commits.len() == self.walker.limits.max_commits {
            return Err(HistoryError::Budget("commits"));
        }
        let commit = self.walker.source.commit(id)?;
        check_oid(self.walker.format, commit.tree)?;
        // Every header of a touched commit is charged, including duplicates
        // and parents whose bodies the selected lines never need to read.
        charge(
            &mut self.edges,
            commit.parents.len(),
            self.walker.limits.max_edges,
            "commit edges",
        )?;
        for parent in &commit.parents {
            self.walker.source.checkpoint()?;
            check_oid(self.walker.format, *parent)?;
        }
        let bytes = commit
            .parents
            .len()
            .checked_mul(size_of::<GitOid>())
            .and_then(|bytes| bytes.checked_add(size_of::<(GitOid, CommitInput)>()))
            // Also bound the per-commit worklist, visited-map and cycle-check
            // logical payload. Container allocator overhead is independently
            // bounded by max_commits and max_edges, not claimed byte-exact.
            .and_then(|bytes| bytes.checked_add(2 * size_of::<(GitOid, Assignments)>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<(GitOid, usize)>()))
            .ok_or(HistoryError::Budget("commit cache"))?;
        self.cache(bytes, "commit cache")?;
        self.commits.insert(id, commit);
        Ok(())
    }

    fn file(&mut self, root: GitOid) -> Result<Option<GitOid>, HistoryError> {
        if !self.walker.paths.contains_key(&root) {
            self.cache(size_of::<(GitOid, Option<GitOid>)>(), "path cache")?;
        }
        self.walker.file(root)
    }

    fn load(&mut self, blob: GitOid) -> Result<(), HistoryError> {
        if !self.walker.blobs.contains_key(&blob) {
            self.cache(size_of::<(GitOid, Lines)>(), "blob cache")?;
        }
        self.walker.load(blob)
    }

    fn visit(&mut self, commit: GitOid, active: &Assignments) -> Result<(), HistoryError> {
        if !self.visited.contains_key(&commit) {
            let words = self.requested_lines.div_ceil(64);
            self.cache(
                words
                    .checked_mul(size_of::<u64>())
                    .ok_or(HistoryError::Budget("line routes"))?,
                "line routes",
            )?;
            self.visited.insert(commit, vec![0; words]);
        }
        let bits = self
            .visited
            .get_mut(&commit)
            .ok_or(HistoryError::InconsistentAttribution)?;
        for (result, _) in active {
            self.walker.source.checkpoint()?;
            if *result >= self.requested_lines {
                return Err(HistoryError::InconsistentAttribution);
            }
            let word = &mut bits[*result / 64];
            let bit = 1_u64 << (*result % 64);
            if *word & bit != 0 {
                return Err(HistoryError::CyclicHistory);
            }
            *word |= bit;
        }
        Ok(())
    }

    fn correspondence(
        &mut self,
        parent: GitOid,
        current: GitOid,
    ) -> Result<Correspondence, HistoryError> {
        self.walker.source.checkpoint()?;
        if let Some(mapping) = self.mappings.get(&(parent, current)) {
            return Ok(Arc::clone(mapping));
        }
        self.load(parent)?;
        self.load(current)?;
        charge(
            &mut self.walker.comparisons,
            1,
            self.walker.limits.max_comparisons,
            "line comparisons",
        )?;
        let count = self.walker.blobs[&current].spans.len();
        let bytes = count
            .checked_mul(size_of::<Option<usize>>())
            .and_then(|bytes| bytes.checked_add(size_of::<((GitOid, GitOid), Correspondence)>()))
            .ok_or(HistoryError::Budget("correspondence cache"))?;
        self.cache(bytes, "correspondence cache")?;
        let remaining = self
            .walker
            .limits
            .max_diff_work
            .checked_sub(self.diff_work)
            .ok_or(HistoryError::Budget("diff work"))?;
        // Preserve the first concrete source cancellation/budget error even if
        // the pure diff reports its generic cancellation variant.
        let interrupted = RefCell::new(None::<MergeSourceError>);
        let comparison = diff_with_cancellation_and_work(
            &self.walker.blobs[&parent].body,
            &self.walker.blobs[&current].body,
            DiffOptions::myers_lines(DiffLimits {
                max_input_bytes: self.walker.limits.max_blob_bytes * 2,
                max_units: self.walker.limits.max_lines * 2,
                max_work: remaining,
                max_trace_cells: 512_000,
            }),
            &|| {
                if interrupted.borrow().is_some() {
                    return true;
                }
                match self.walker.source.checkpoint() {
                    Ok(()) => false,
                    Err(error) => {
                        *interrupted.borrow_mut() = Some(error);
                        true
                    }
                }
            },
        );
        if let Some(error) = interrupted.into_inner() {
            return Err(HistoryError::Source(error));
        }
        let (comparison, work) = comparison.map_err(HistoryError::Diff)?;
        charge(
            &mut self.diff_work,
            work,
            self.walker.limits.max_diff_work,
            "diff work",
        )?;
        if !self.walker.algorithms.contains(&comparison.algorithm) {
            self.walker.algorithms.push(comparison.algorithm);
        }
        let mut mapping = vec![None; count];
        for edit in comparison.edits {
            self.walker.source.checkpoint()?;
            if let Edit::Equal { old, new } = edit {
                if old.unit_end - old.unit_start != new.unit_end - new.unit_start
                    || new.unit_end > mapping.len()
                    || old.unit_end > self.walker.blobs[&parent].spans.len()
                {
                    return Err(HistoryError::InconsistentAttribution);
                }
                for (i, slot) in mapping[new.unit_start..new.unit_end].iter_mut().enumerate() {
                    *slot = Some(old.unit_start + i);
                }
            }
        }
        let mapping: Correspondence = mapping.into();
        self.mappings
            .insert((parent, current), Arc::clone(&mapping));
        Ok(mapping)
    }

    /// Cycles in examined parent headers must also refuse when none of the
    /// requested lines happened to follow the offending edge. Unread ancestors
    /// remain outside this traversal's claim, never implicitly authenticated.
    fn verify_touched_graph(&self) -> Result<(), HistoryError> {
        let mut children: BTreeMap<_, usize> = self.commits.keys().map(|id| (*id, 0)).collect();
        for commit in self.commits.values() {
            for parent in &commit.parents {
                self.walker.source.checkpoint()?;
                if let Some(count) = children.get_mut(parent) {
                    *count += 1;
                }
            }
        }
        let mut ready: BTreeSet<_> = children
            .iter()
            .filter_map(|(id, count)| (*count == 0).then_some(*id))
            .collect();
        let mut ordered = 0;
        while let Some(id) = ready.pop_first() {
            self.walker.source.checkpoint()?;
            ordered += 1;
            for parent in &self.commits[&id].parents {
                self.walker.source.checkpoint()?;
                if let Some(count) = children.get_mut(parent) {
                    *count = count.checked_sub(1).ok_or(HistoryError::CyclicHistory)?;
                    if *count == 0 {
                        ready.insert(*parent);
                    }
                }
            }
        }
        if ordered != self.commits.len() {
            return Err(HistoryError::CyclicHistory);
        }
        Ok(())
    }
}

/// Attribute the selected lines through only the ancestry they actually need.
///
/// Matching, parent precedence, byte spans and origin records are identical to
/// [`super::blame`] whenever both traversals complete. This traversal does not
/// audit unrelated history or count unvisited ancestors. A parent required to
/// decide attribution must be readable and valid; failure is never an origin.
///
/// Limits are aggregate per call: distinct commit reads and all their parent
/// headers; examined tree entries; cached commit/path/blob/span/route/mapping
/// payload; distinct nonidentity blob comparisons; and consumed diff work over
/// every comparison. Per-blob byte/line limits and origin metadata bounds also
/// remain in force. An unchanged blob needs no comparison or mapping vector.
/// Missing dependencies, cancellation, cycles and exhaustion return no partial
/// report. The source owner retains all authorization and native-ID duties.
pub fn blame_frontier(
    source: &impl HistorySource,
    format: GitHashAlgorithm,
    tip: GitOid,
    options: &BlameOptions,
) -> Result<BlameResult, HistoryError> {
    options.validate()?;
    check_oid(format, tip)?;
    let mut frontier = Frontier {
        walker: Walker {
            source,
            format,
            path: &options.path,
            limits: options.limits,
            paths: BTreeMap::new(),
            blobs: BTreeMap::new(),
            entries: 0,
            cached: 0,
            comparisons: 0,
            algorithms: Vec::new(),
        },
        commits: BTreeMap::new(),
        edges: 0,
        mappings: BTreeMap::new(),
        diff_work: 0,
        visited: BTreeMap::new(),
        requested_lines: 0,
    };
    frontier.commit(tip)?;
    let tree = frontier.commits[&tip].tree;
    let blob = frontier.file(tree)?.ok_or(HistoryError::PathUnavailable)?;
    frontier.load(blob)?;
    let total_lines = frontier.walker.blobs[&blob].spans.len();
    let end_line = options.end_line.unwrap_or(total_lines);
    if options.first_line > end_line || end_line > total_lines {
        return Err(HistoryError::LineRange);
    }
    let requested = end_line - options.first_line;
    frontier.requested_lines = requested;
    frontier.cache(
        requested
            .checked_mul(size_of::<Option<BlameLine>>() + 2 * size_of::<(usize, usize)>())
            .ok_or(HistoryError::Budget("line routes"))?,
        "line routes",
    )?;
    let mut answers = vec![None; requested];
    let mut pending = BTreeMap::from([(
        tip,
        (options.first_line..end_line)
            .map(|line| (line - options.first_line, line))
            .collect::<Assignments>(),
    )]);
    while let Some((current, mut active)) = pending.pop_first() {
        source.checkpoint()?;
        if active.is_empty() {
            continue;
        }
        frontier.visit(current, &active)?;
        let commit = frontier.commits[&current].clone();
        let current_blob = frontier
            .file(commit.tree)?
            .ok_or(HistoryError::InconsistentAttribution)?;
        frontier.load(current_blob)?;
        let mut parents_seen = BTreeSet::new();
        for parent in &commit.parents {
            source.checkpoint()?;
            if active.is_empty() {
                break;
            }
            if !parents_seen.insert(*parent) {
                continue;
            }
            frontier.commit(*parent)?;
            let Some(parent_blob) = frontier.file(frontier.commits[parent].tree)? else {
                continue;
            };
            let mapping = if parent_blob == current_blob {
                None
            } else {
                Some(frontier.correspondence(parent_blob, current_blob)?)
            };
            let mut unmatched = Vec::new();
            for (result, line) in active {
                source.checkpoint()?;
                let origin = match &mapping {
                    None => Some(line),
                    Some(mapping) => *mapping
                        .get(line)
                        .ok_or(HistoryError::InconsistentAttribution)?,
                };
                match origin {
                    Some(origin) => pending.entry(*parent).or_default().push((result, origin)),
                    None => unmatched.push((result, line)),
                }
            }
            active = unmatched;
        }
        for (result, line) in active {
            source.checkpoint()?;
            let origin = &frontier.walker.blobs[&current_blob];
            let span = origin
                .spans
                .get(line)
                .ok_or(HistoryError::InconsistentAttribution)?;
            let target = &frontier.walker.blobs[&blob];
            let selected = &target.spans[result + options.first_line];
            if origin.body[span.clone()] != target.body[selected.clone()]
                || answers[result].is_some()
            {
                return Err(HistoryError::InconsistentAttribution);
            }
            answers[result] = Some(BlameLine {
                line: result + options.first_line,
                byte_start: selected.start,
                byte_end: selected.end,
                origin_commit: current,
                origin_blob: current_blob,
                origin_line: line,
                origin_byte_start: span.start,
                origin_byte_end: span.end,
            });
        }
    }
    frontier.verify_touched_graph()?;
    let lines = answers
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(HistoryError::InconsistentAttribution)?;
    let graph_commits = frontier.commits.len();
    let graph = Graph {
        commits: frontier.commits,
        order: Vec::new(),
    };
    let mut origins = Vec::new();
    let mut metadata_bytes = 0;
    for id in lines
        .iter()
        .map(|line| line.origin_commit)
        .collect::<BTreeSet<_>>()
    {
        origins.push(record(
            source,
            &graph,
            id,
            &mut metadata_bytes,
            options.limits.max_metadata_bytes,
        )?);
    }
    let target = &frontier.walker.blobs[&blob];
    let start = target
        .spans
        .get(options.first_line)
        .map_or(target.body.len(), |span| span.start);
    let end = target
        .spans
        .get(end_line)
        .map_or(target.body.len(), |span| span.start);
    source.checkpoint()?;
    Ok(BlameResult {
        traversal: BlameTraversal::LineFrontier,
        tip,
        tree,
        blob,
        path: options.path.clone(),
        total_lines,
        first_line: options.first_line,
        end_line,
        content_byte_start: start,
        content: target.body[start..end].to_vec(),
        lines,
        origins,
        graph_commits,
        comparisons: frontier.walker.comparisons,
        algorithms: frontier.walker.algorithms,
    })
}

#[cfg(test)]
mod tests;
