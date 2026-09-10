//! Replay one selected commit's change, or its inverse, onto an exact target.
//! The path merge planner remains the only tree/content merge implementation.
//! A selected commit must be reachable from the caller's visible source tip;
//! no caller-selected merge base or invented commit graph is used.

use std::collections::{BTreeMap, BTreeSet};

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{GitHashAlgorithm, GitOid};

use super::{CommitInput, MergeConflict, MergeEntry, MergeMetadata, MergeObjectSource,
    MergeSourceError, PlannedMergeObject, Planner, PreparationError, PreparationLimits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDirection { CherryPick, Revert }

/// Exact immutable inputs. `source_tip` authorizes historical selection, not
/// the change being applied: later source commits are deliberately excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayRequest {
    pub direction: ReplayDirection,
    pub target: GitOid,
    pub source_tip: GitOid,
    pub selected_commit: GitOid,
    /// One-based stored parent position, required for a merge commit. A root
    /// has no mainline; a single-parent commit defaults to position one.
    pub mainline: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayCoordinates {
    pub request: ReplayRequest,
    pub selected_parent: Option<GitOid>,
    pub selected_mainline: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedReplay {
    pub coordinates: ReplayCoordinates,
    pub tree: GitOid,
    pub commit: GitOid,
    /// Constructed objects only. A bundle writer MUST also include borrowed
    /// source objects absent from the TARGET closure: the replayed commit is
    /// not a parent and cannot supply a bundle prerequisite implicitly.
    pub objects: Vec<PlannedMergeObject>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayPreparation {
    Clean(PreparedReplay),
    Conflicted { coordinates: ReplayCoordinates, conflicts: Vec<MergeConflict> },
    /// The resulting tree equals the current target tree. This is a content
    /// observation, not proof that this patch previously appeared in history.
    NoChange { coordinates: ReplayCoordinates },
}

#[derive(Debug)]
pub enum ReplayError {
    Preparation(PreparationError),
    MainlineRequired { parents: usize },
    InvalidMainline { requested: u16, parents: usize },
    CommitOutsideSourceHistory,
}
impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native commit replay refused: {self:?}")
    }
}
impl std::error::Error for ReplayError {}
impl From<PreparationError> for ReplayError {
    fn from(error: PreparationError) -> Self { Self::Preparation(error) }
}
impl From<MergeSourceError> for ReplayError {
    fn from(error: MergeSourceError) -> Self { Self::Preparation(error.into()) }
}

/// Construct one single-parent commit without staging objects or moving refs.
/// Cherry-pick merges `(parent, target, selected)` trees; revert merges
/// `(selected, target, parent)` trees. Root commits compare with the real
/// canonical empty tree. Unrelated target histories are permitted, but source
/// selection is always proven by a bounded walk from `source_tip`.
///
/// Merge commits require an explicit mainline. Conflicts carry actual base /
/// target / applied-side entries and no partial commit. No-op trees create no
/// empty commit. Attributes, binary conflicts and type conflicts retain the
/// existing path-v1 planner's refusal/conflict semantics.
pub fn prepare_replay<S: MergeObjectSource>(
    source: &S, format: GitHashAlgorithm, request: ReplayRequest,
    metadata: &MergeMetadata, limits: PreparationLimits,
) -> Result<ReplayPreparation, ReplayError> {
    limits.validate()?;
    metadata.validate()?;
    if [request.target, request.source_tip, request.selected_commit].iter()
        .any(|id| id.is_zero() || id.algorithm() != format)
    { return Err(PreparationError::ObjectFormat.into()); }
    if request.mainline == Some(0) {
        return Err(ReplayError::InvalidMainline { requested: 0, parents: 0 });
    }
    source.checkpoint()?;
    let mut history = History { source, format, limits, commits: BTreeMap::new(), edges: 0 };
    // Never read an arbitrary supplied commit before finding its identity in
    // the selected visible history. The target is not an alternative authority
    // for discovering a commit outside that history.
    let selected = history.find(request.source_tip, request.selected_commit)?;
    let (parent, mainline) = select_parent(&selected, request.mainline)?;
    let parent_tree = parent.map(|id| history.read(id).map(|commit| commit.tree)).transpose()?;
    let target_tree = history.read(request.target)?.tree;
    let coordinates = ReplayCoordinates { request, selected_parent: parent, selected_mainline: mainline };
    let empty = git_object_id(format, GitObjectKind::Tree, &[]);
    let source = EmptyTreeSource { source, empty };
    let mut planner = Planner {
        source: &source, format, limits, entries: 0, content_merges: 0, output_bytes: 0,
        objects: BTreeMap::new(), conflicts: Vec::new(), resolutions: BTreeMap::new(),
    };
    let (base, applied) = match request.direction {
        ReplayDirection::CherryPick => (parent_tree, selected.tree),
        ReplayDirection::Revert => (Some(selected.tree), parent_tree.unwrap_or(empty)),
    };
    let tree = planner.directory(base, target_tree, applied, &[], 0, false)?;
    source.checkpoint()?;
    if !planner.conflicts.is_empty() {
        planner.conflicts.sort_by(|a, b| a.path.cmp(&b.path));
        return Ok(ReplayPreparation::Conflicted { coordinates, conflicts: planner.conflicts });
    }
    let tree = tree.ok_or(PreparationError::InvalidTree)?;
    if tree == target_tree { return Ok(ReplayPreparation::NoChange { coordinates }); }
    if tree == empty { planner.emit(GitObjectKind::Tree, Vec::new())?; }
    let mut body = format!("tree {tree}\nparent {}\nauthor {} {} +0000\ncommitter {} {} +0000\n\n",
        request.target, metadata.author, metadata.timestamp, metadata.committer, metadata.timestamp).into_bytes();
    if body.len().checked_add(metadata.message.len()).is_none_or(|size| size > limits.max_output_bytes) {
        return Err(PreparationError::Budget("commit bytes").into());
    }
    body.extend_from_slice(&metadata.message);
    let commit = planner.emit(GitObjectKind::Commit, body)?;
    source.checkpoint()?;
    Ok(ReplayPreparation::Clean(PreparedReplay {
        coordinates, tree, commit, objects: planner.objects.into_values().collect(),
    }))
}

fn select_parent(commit: &CommitInput, mainline: Option<u16>) -> Result<(Option<GitOid>, Option<u16>), ReplayError> {
    let count = commit.parents.len();
    match (count, mainline) {
        (0, None) => Ok((None, None)),
        (1, None) => Ok((Some(commit.parents[0]), Some(1))),
        (_, Some(position)) if position > 0 && usize::from(position) <= count =>
            Ok((Some(commit.parents[usize::from(position) - 1]), Some(position))),
        (_, Some(requested)) => Err(ReplayError::InvalidMainline { requested, parents: count }),
        (_, None) => Err(ReplayError::MainlineRequired { parents: count }),
    }
}

/// The empty tree is constructed data with its actual Git identity, not a
/// fabricated source commit or a lookup that grants access to other objects.
struct EmptyTreeSource<'a, S> { source: &'a S, empty: GitOid }
impl<S: MergeObjectSource> MergeObjectSource for EmptyTreeSource<'_, S> {
    fn checkpoint(&self) -> Result<(), MergeSourceError> { self.source.checkpoint() }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> { self.source.commit(id) }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.checkpoint()?;
        if id == self.empty { Ok(Vec::new()) } else { self.source.tree(id) }
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> { self.source.blob(id) }
}

struct History<'a, S> {
    source: &'a S, format: GitHashAlgorithm, limits: PreparationLimits,
    commits: BTreeMap<GitOid, CommitInput>, edges: usize,
}
impl<S: MergeObjectSource> History<'_, S> {
    fn read(&mut self, id: GitOid) -> Result<CommitInput, ReplayError> {
        self.source.checkpoint()?;
        if let Some(commit) = self.commits.get(&id) { return Ok(commit.clone()); }
        if id.is_zero() || id.algorithm() != self.format { return Err(PreparationError::ObjectFormat.into()); }
        if self.commits.len() >= self.limits.max_commits { return Err(PreparationError::Budget("history commits").into()); }
        let commit = self.source.commit(id)?;
        self.source.checkpoint()?;
        if commit.tree.is_zero() || commit.tree.algorithm() != self.format
            || commit.parents.iter().any(|parent| parent.is_zero() || parent.algorithm() != self.format || *parent == id)
        { return Err(MergeSourceError::InvalidObject(id).into()); }
        self.edges = self.edges.checked_add(commit.parents.len()).filter(|n| *n <= self.limits.max_edges)
            .ok_or(PreparationError::Budget("history edges"))?;
        self.commits.insert(id, commit.clone());
        Ok(commit)
    }
    fn find(&mut self, tip: GitOid, selected: GitOid) -> Result<CommitInput, ReplayError> {
        let mut seen = BTreeSet::from([tip]);
        let mut pending = vec![tip];
        while let Some(id) = pending.pop() {
            let commit = self.read(id)?;
            if id == selected { return Ok(commit); }
            // Reverse push means the first stored parent is visited first.
            for parent in commit.parents.iter().rev() {
                self.source.checkpoint()?;
                if !seen.contains(parent) {
                    if seen.len() >= self.limits.max_commits {
                        return Err(PreparationError::Budget("history frontier").into());
                    }
                    seen.insert(*parent);
                    pending.push(*parent);
                }
            }
        }
        Err(ReplayError::CommitOutsideSourceHistory)
    }
}

#[cfg(test)]
mod tests;
