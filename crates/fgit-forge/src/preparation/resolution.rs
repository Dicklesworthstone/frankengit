//! Explicit, all-or-nothing resolution of an exact native merge's conflicts.
//! The automatic planner remains the conflict oracle and the tree builder.
//! User choices replace only reproduced conflicts, never clean paths or refs.

use super::{
    BTreeMap, GitHashAlgorithm, GitObjectKind, GitOid, Graph, MergeBaseLimits,
    MergeBaseResult, MergeConflict, MergeEntry, MergeMetadata, MergeObjectSource,
    MergeSourceError, Planner, PreparationError, PreparationLimits, PreparedMerge,
    finish_merge, git_object_id, merge_bases_all,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionInputs {
    pub base: GitOid,
    pub target: GitOid,
    pub source: GitOid,
}
impl ResolutionInputs {
    pub fn validate(self, format: GitHashAlgorithm) -> Result<(), ResolutionError> {
        if self.target == self.source || [self.base, self.target, self.source].iter()
            .any(|oid| oid.is_zero() || oid.algorithm() != format)
        { return Err(ResolutionError::InvalidInputs); }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionKind { Base, Ours, Theirs, Delete, File }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolutionChoice {
    Base,
    Ours,
    Theirs,
    Delete,
    /// Exact bytes, including binary content, with an explicit regular-file mode.
    /// No marker removal, newline normalization or external driver is implicit.
    File { mode: u32, bytes: Vec<u8> },
}
impl ResolutionChoice {
    #[must_use]
    pub const fn kind(&self) -> ResolutionKind {
        match self {
            Self::Base => ResolutionKind::Base,
            Self::Ours => ResolutionKind::Ours,
            Self::Theirs => ResolutionKind::Theirs,
            Self::Delete => ResolutionKind::Delete,
            Self::File { .. } => ResolutionKind::File,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConflictResolution {
    pub path: Vec<u8>,
    pub choice: ResolutionChoice,
}

/// Derived explanation, not an approval, capability or canonical review event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedPath {
    pub conflict: MergeConflict,
    pub choice: ResolutionKind,
    pub result: Option<MergeEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMerge {
    pub plan: PreparedMerge,
    pub resolutions: Vec<ResolvedPath>,
}

#[derive(Debug)]
pub enum ResolutionError {
    InvalidInputs,
    InvalidResolution { index: usize },
    DuplicatePath(Vec<u8>),
    OverlappingPaths,
    NonConflictPath(Vec<u8>),
    MissingSide { path: Vec<u8>, side: ResolutionKind },
    Unresolved(Vec<MergeConflict>),
    BaseMismatch { expected: GitOid, actual: GitOid },
    NoConflicts,
    ReconstructionMismatch,
    Budget,
    Preparation(PreparationError),
}
impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "explicit merge resolution refused: {self:?}")
    }
}
impl std::error::Error for ResolutionError {}
impl From<PreparationError> for ResolutionError {
    fn from(error: PreparationError) -> Self { Self::Preparation(error) }
}
impl From<MergeSourceError> for ResolutionError {
    fn from(error: MergeSourceError) -> Self { Self::Preparation(error.into()) }
}

pub(super) struct BoundResolution {
    pub(super) conflict: MergeConflict,
    pub(super) result: Option<MergeEntry>,
}

/// Validate shape and byte limits before touching a repository or allocating maps.
pub fn validate_resolutions(
    resolutions: &[ConflictResolution], limits: PreparationLimits,
) -> Result<(), ResolutionError> {
    limits.validate()?;
    if resolutions.len() > limits.max_conflicts { return Err(ResolutionError::Budget); }
    let mut bytes = 0_usize;
    for (index, resolution) in resolutions.iter().enumerate() {
        let path = &resolution.path;
        if path.is_empty() || path.len() > limits.max_path_bytes || path.contains(&0)
            || path.split(|byte| *byte == b'/').any(|part|
                part.is_empty() || part == b"." || part == b".." || part.eq_ignore_ascii_case(b".git"))
        { return Err(ResolutionError::InvalidResolution { index }); }
        bytes = bytes.checked_add(path.len()).ok_or(ResolutionError::Budget)?;
        if let ResolutionChoice::File { mode, bytes: content } = &resolution.choice {
            if !matches!(*mode, 0o100644 | 0o100755) || content.len() > limits.max_text_bytes {
                return Err(ResolutionError::InvalidResolution { index });
            }
            bytes = bytes.checked_add(content.len()).ok_or(ResolutionError::Budget)?;
        }
        if bytes > limits.max_output_bytes { return Err(ResolutionError::Budget); }
    }
    let mut paths: Vec<_> = resolutions.iter().map(|resolution| resolution.path.as_slice()).collect();
    paths.sort_unstable();
    // Check every component ancestor, not just the previous sorted name:
    // `a`, `a-`, `a/b` are ordered in that order but a still contains a/b.
    let paths_set: std::collections::BTreeSet<_> = paths.iter().copied().collect();
    for pair in paths.windows(2) {
        if pair[0] == pair[1] { return Err(ResolutionError::DuplicatePath(pair[0].to_vec())); }
    }
    for path in paths {
        for (index, byte) in path.iter().enumerate() {
            if *byte == b'/' && paths_set.contains(&path[..index]) {
                return Err(ResolutionError::OverlappingPaths);
            }
        }
    }
    Ok(())
}

/// Resolve every and only actual PathMergeV1 conflicts at exact input commits.
///
/// Graph discovery occurs once. The SAME planner, resource counters, generated
/// object map and caller-owned source are used for discovery and reconstruction.
/// This is at most two tree/content passes within one total preparation budget,
/// not two fresh budgets. Unresolved/extra/invalid choices never return a tree.
/// Selecting a missing side is not shorthand for deletion: use `Delete`.
pub fn prepare_resolved_merge<S: MergeObjectSource>(
    source: &S, format: GitHashAlgorithm, inputs: ResolutionInputs,
    resolutions: &[ConflictResolution], metadata: &MergeMetadata, limits: PreparationLimits,
) -> Result<ResolvedMerge, ResolutionError> {
    inputs.validate(format)?;
    validate_resolutions(resolutions, limits)?;
    metadata.validate()?;
    source.checkpoint()?;
    let graph = Graph { source, format };
    let bases = merge_bases_all(&graph, inputs.target, inputs.source, MergeBaseLimits {
        max_commits: limits.max_commits, max_edges: limits.max_edges,
    }).map_err(PreparationError::Graph)?;
    source.checkpoint()?;
    let base = match bases {
        MergeBaseResult::NoCommonAncestor => return Err(PreparationError::NoCommonAncestor.into()),
        MergeBaseResult::Bases(bases) if bases.len() == 1 => bases[0],
        MergeBaseResult::Bases(bases) => return Err(PreparationError::MultipleMergeBases(bases).into()),
    };
    if base != inputs.base { return Err(ResolutionError::BaseMismatch { expected: inputs.base, actual: base }); }
    if base == inputs.source { return Err(ResolutionError::NoConflicts); }
    let base_tree = source.commit(base)?.tree;
    let target_tree = source.commit(inputs.target)?.tree;
    let source_tree = source.commit(inputs.source)?.tree;
    let mut planner = Planner {
        source, format, limits, entries: 0, content_merges: 0, output_bytes: 0,
        objects: BTreeMap::new(), trees: BTreeMap::new(), conflicts: Vec::new(), resolutions: BTreeMap::new(),
    };
    planner.directory(Some(base_tree), target_tree, source_tree, &[], 0, false)?;
    source.checkpoint()?;
    let (tree, receipts) = resolve_discovered_conflicts(
        &mut planner, Some(base_tree), target_tree, source_tree, resolutions,
    )?;
    let plan = finish_merge(planner, base, inputs.target, inputs.source, tree, metadata)?;
    Ok(ResolvedMerge { plan, resolutions: receipts })
}

/// Resolve the conflicts already discovered by this same planner, then rebuild
/// the exact same three-tree comparison. Both callers validate choices before
/// source access. Counters, emitted objects, cancellation and source ownership
/// survive the second pass; replay never starts a fresh merge budget.
pub(super) fn resolve_discovered_conflicts<S: MergeObjectSource>(
    planner: &mut Planner<'_, S>, base_tree: Option<GitOid>,
    target_tree: GitOid, source_tree: GitOid, resolutions: &[ConflictResolution],
) -> Result<(GitOid, Vec<ResolvedPath>), ResolutionError> {
    if planner.conflicts.is_empty() { return Err(ResolutionError::NoConflicts); }
    let conflicts = std::mem::take(&mut planner.conflicts).into_iter()
        .map(|conflict| (conflict.path.clone(), conflict)).collect::<BTreeMap<_, _>>();
    let choices: BTreeMap<_, _> = resolutions.iter().map(|r| (r.path.as_slice(), &r.choice)).collect();
    for path in choices.keys() {
        if !conflicts.contains_key(*path) { return Err(ResolutionError::NonConflictPath(path.to_vec())); }
    }
    let unresolved: Vec<_> = conflicts.values().filter(|c| !choices.contains_key(c.path.as_slice())).cloned().collect();
    if !unresolved.is_empty() { return Err(ResolutionError::Unresolved(unresolved)); }
    let mut receipts = Vec::new();
    for (path, conflict) in conflicts {
        planner.source.checkpoint()?;
        let choice = choices.get(path.as_slice()).ok_or(ResolutionError::ReconstructionMismatch)?;
        let result = match choice {
            ResolutionChoice::Delete => None,
            ResolutionChoice::File { mode, bytes } => {
                let oid = git_object_id(planner.format, GitObjectKind::Blob, bytes);
                let reusable = [&conflict.base, &conflict.ours, &conflict.theirs].iter()
                    .filter_map(|entry| entry.as_ref()).any(|entry|
                        entry.oid == oid && matches!(entry.mode, 0o100644 | 0o100755 | 0o120000));
                if !reusable { planner.emit(GitObjectKind::Blob, bytes.clone())?; }
                Some(MergeEntry {
                    name: path.rsplit(|byte| *byte == b'/').next()
                        .ok_or(ResolutionError::ReconstructionMismatch)?.to_vec(),
                    mode: *mode, oid,
                })
            }
            side => {
                let entry = match side {
                    ResolutionChoice::Base => &conflict.base,
                    ResolutionChoice::Ours => &conflict.ours,
                    ResolutionChoice::Theirs => &conflict.theirs,
                    _ => return Err(ResolutionError::ReconstructionMismatch),
                };
                Some(entry.clone().ok_or_else(|| ResolutionError::MissingSide {
                    path: path.clone(), side: side.kind(),
                })?)
            }
        };
        planner.resolutions.insert(path, BoundResolution { conflict: conflict.clone(), result: result.clone() });
        receipts.push(ResolvedPath { conflict, choice: choice.kind(), result });
    }
    let tree = planner.directory(base_tree, target_tree, source_tree, &[], 0, false)?;
    planner.source.checkpoint()?;
    if !planner.conflicts.is_empty() || !planner.resolutions.is_empty() {
        return Err(ResolutionError::ReconstructionMismatch);
    }
    let tree = tree.ok_or(ResolutionError::ReconstructionMismatch)?;
    Ok((tree, receipts))
}

#[cfg(test)]
mod tests;
