//! Exact-path change history over a verified, selected commit DAG.
//!
//! A root matches when the path exists. Other commits match when the path's
//! `(mode, native object ID)` differs from at least one stored parent. This is
//! unsimplified history: merges keep their real parents, and no rename, copy,
//! first-parent, timestamp, or human-authorship inference is performed.
//! Directories compare subtree IDs. Symlinks and gitlinks are opaque leaves;
//! neither their content nor their targets are read. Paths are raw Git bytes,
//! never host filesystem paths or additional object-disclosure capabilities.

use super::{
    HistoryError, HistoryLimits, HistoryPage, HistorySource, LogOptions, charge, check_oid, graph,
    record, valid_path,
};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::collections::{BTreeMap, BTreeSet};

/// Filter before applying `log.after` and `log.limit`. All graph limits still
/// cover the complete ancestry, including commits that do not match the path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathLogOptions {
    pub path: Vec<u8>,
    pub log: LogOptions,
}
impl PathLogOptions {
    pub fn validate(&self) -> Result<(), HistoryError> {
        self.log.validate()?;
        if !valid_path(&self.path) {
            return Err(HistoryError::InvalidOptions);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    mode: u32,
    oid: GitOid,
}

struct Paths<'a, S> {
    source: &'a S,
    format: GitHashAlgorithm,
    path: &'a [u8],
    limits: HistoryLimits,
    roots: BTreeMap<GitOid, Option<Entry>>,
    entries: usize,
    cached: usize,
}
impl<S: HistorySource> Paths<'_, S> {
    fn select(&mut self, root: GitOid) -> Result<Option<Entry>, HistoryError> {
        self.source.checkpoint()?;
        if let Some(entry) = self.roots.get(&root) {
            return Ok(*entry);
        }
        // Charge logical cache payload before insertion, just as blame charges
        // blob/span payload. Graph limits independently bound map cardinality.
        charge(
            &mut self.cached,
            std::mem::size_of::<(GitOid, Option<Entry>)>(),
            self.limits.max_cached_bytes,
            "path cache",
        )?;
        let mut tree = root;
        let mut components = self.path.split(|byte| *byte == b'/').peekable();
        let mut selected = None;
        while let Some(component) = components.next() {
            self.source.checkpoint()?;
            // The selected source MUST bound allocation and verify identity,
            // kind and disclosure before returning this tree (trait contract).
            let entries = self.source.tree(tree)?;
            charge(
                &mut self.entries,
                entries.len(),
                self.limits.max_tree_entries,
                "tree entries",
            )?;
            // Borrow names instead of copying arbitrarily large tree names.
            let mut names = BTreeSet::new();
            let mut matching = None;
            for entry in &entries {
                self.source.checkpoint()?;
                check_oid(self.format, entry.oid)?;
                if entry.name.is_empty()
                    || entry.name.contains(&0)
                    || entry.name.contains(&b'/')
                    || matches!(entry.name.as_slice(), b"." | b"..")
                    || !names.insert(entry.name.as_slice())
                    || !matches!(
                        entry.mode,
                        0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000
                    )
                {
                    return Err(HistoryError::InvalidTree);
                }
                if entry.name.as_slice() == component {
                    matching = Some(Entry {
                        mode: entry.mode,
                        oid: entry.oid,
                    });
                }
            }
            let Some(entry) = matching else {
                break;
            };
            if components.peek().is_none() {
                selected = Some(entry);
                break;
            }
            if entry.mode != 0o040000 {
                break;
            }
            tree = entry.oid;
        }
        self.source.checkpoint()?;
        self.roots.insert(root, selected);
        Ok(selected)
    }
}

/// Page exact file/directory changes in the full graph's deterministic
/// child-before-parent order. `HistoryPage::total_commits` counts MATCHES, not
/// traversed commits; `tip` remains the actual selected ref tip even when that
/// commit is absent from the page. No parents are rewritten by filtering.
///
/// An absent path can have deletion history; a never-present path has zero
/// matches. Missing/corrupt required objects, cancellation and exhausted bounds
/// return errors, never incomplete successful pages. The host must authorize
/// the ref and pin offset continuations to the same authority head and query.
pub fn path_history(
    source: &impl HistorySource,
    format: GitHashAlgorithm,
    tip: GitOid,
    options: &PathLogOptions,
) -> Result<HistoryPage, HistoryError> {
    options.validate()?;
    let log = options.log;
    let graph = graph(source, format, tip, log.limits)?;
    let mut paths = Paths {
        source,
        format,
        path: &options.path,
        limits: log.limits,
        roots: BTreeMap::new(),
        entries: 0,
        cached: 0,
    };
    let mut matches = Vec::new();
    for id in &graph.order {
        source.checkpoint()?;
        let commit = &graph.commits[id];
        let current = paths.select(commit.tree)?;
        let mut changed = commit.parents.is_empty() && current.is_some();
        for parent in &commit.parents {
            source.checkpoint()?;
            if current != paths.select(graph.commits[parent].tree)? {
                changed = true;
            }
        }
        if changed {
            matches.push(*id);
        }
    }
    if log.after > matches.len() {
        return Err(HistoryError::LineRange);
    }
    let end = log
        .after
        .checked_add(log.limit)
        .ok_or(HistoryError::InvalidOptions)?
        .min(matches.len());
    let mut commits = Vec::with_capacity(end - log.after);
    let mut metadata_bytes = 0;
    for id in &matches[log.after..end] {
        commits.push(record(
            source,
            &graph,
            *id,
            &mut metadata_bytes,
            log.limits.max_metadata_bytes,
        )?);
    }
    source.checkpoint()?;
    Ok(HistoryPage {
        tip,
        total_commits: matches.len(),
        after: log.after,
        next_after: (end < matches.len()).then_some(end),
        commits,
    })
}

#[cfg(test)]
mod tests;
