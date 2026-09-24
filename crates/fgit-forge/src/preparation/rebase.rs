//! Bounded linear rebase using the existing path/content merge planner.
//! This module constructs immutable candidates; it never moves a branch.
use super::{
    BTreeMap, BTreeSet, CommitInput, GitHashAlgorithm, GitObjectKind, GitOid, MergeConflict,
    MergeMetadata, MergeObjectSource, MergeSourceError, PlannedMergeObject, Planner,
    PreparationError, PreparationLimits, resolution,
};

pub mod resolutions;
use resolutions::{RebaseResolvedStep, ResolvedRebasePreparation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmptyCommitPolicy {
    Stop,
    Drop,
    Keep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebaseRequest {
    /// Replay the single-parent suffix (upstream, source_tip], oldest first.
    pub source_tip: GitOid,
    pub upstream: GitOid,
    pub onto: GitOid,
    /// Applies only to changes that become empty, not originally empty commits.
    pub empty: EmptyCommitPolicy,
}

/// Original native metadata, not an ambient identity or a lossy UTF-8 view.
/// The adapter must extract this from the identity-verified original commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebaseCommitMetadata {
    /// Complete author header value, including original time and timezone.
    pub author: Vec<u8>,
    pub encoding: Option<Vec<u8>>,
    pub message: Vec<u8>,
}

pub trait RebaseObjectSource: MergeObjectSource {
    fn rebase_metadata(&self, id: GitOid) -> Result<RebaseCommitMetadata, MergeSourceError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebaseCommitter {
    pub identity: String,
    pub timestamp: u64,
}
impl RebaseCommitter {
    pub fn validate(&self) -> Result<(), PreparationError> {
        MergeMetadata {
            author: self.identity.clone(),
            committer: self.identity.clone(),
            timestamp: self.timestamp,
            message: b"rebase".to_vec(),
        }
        .validate()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebaseStepKind {
    Replayed,
    PreservedEmpty,
    DroppedEmpty,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebaseStep {
    pub original: GitOid,
    pub rewritten: GitOid,
    pub tree: GitOid,
    pub kind: RebaseStepKind,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRebase {
    pub request: RebaseRequest,
    pub commit: GitOid,
    pub tree: GitOid,
    pub steps: Vec<RebaseStep>,
    /// Constructed objects only. Export must include source objects missing
    /// from onto history; the original source commits are not prerequisites.
    pub objects: Vec<PlannedMergeObject>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebaseStop {
    Conflicted(Vec<MergeConflict>),
    BecameEmpty,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebasePreparation {
    Clean(PreparedRebase),
    /// No partial objects or publishable candidate are returned on a stop.
    Stopped {
        request: RebaseRequest,
        original: GitOid,
        completed: Vec<RebaseStep>,
        reason: RebaseStop,
    },
}
#[derive(Debug)]
pub enum RebaseError {
    Preparation(PreparationError),
    UpstreamOutsideLinearHistory,
    MergeCommit {
        commit: GitOid,
        parents: usize,
    },
    CyclicHistory(GitOid),
    InvalidOriginalMetadata(GitOid),
    Resolution {
        original: GitOid,
        error: resolution::ResolutionError,
    },
    DuplicateResolutionCommit(GitOid),
    ResolutionOutsideSuffix(GitOid),
}
impl From<PreparationError> for RebaseError {
    fn from(error: PreparationError) -> Self {
        Self::Preparation(error)
    }
}
impl From<MergeSourceError> for RebaseError {
    fn from(error: MergeSourceError) -> Self {
        Self::Preparation(error.into())
    }
}
impl std::fmt::Display for RebaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native rebase refused: {self:?}")
    }
}
impl std::error::Error for RebaseError {}

/// Replay an explicitly selected linear suffix onto an independently selected
/// commit. Merge commits in the suffix refuse rather than flattening history.
/// One planner owns tree/content/object/byte counters for the ENTIRE series.
/// Original authors, messages and encoding are preserved; old signatures cannot
/// authenticate rewritten bytes and are not copied by the metadata adapter.
pub fn prepare_rebase<S: RebaseObjectSource>(
    source: &S,
    format: GitHashAlgorithm,
    request: RebaseRequest,
    committer: &RebaseCommitter,
    limits: PreparationLimits,
) -> Result<RebasePreparation, RebaseError> {
    resolutions::prepare_resolved_rebase(source, format, request, committer, limits, &[])
        .map(|resolved| resolved.preparation)
}

fn prepare_rebase_inner<S: RebaseObjectSource>(
    source: &S,
    format: GitHashAlgorithm,
    request: RebaseRequest,
    committer: &RebaseCommitter,
    limits: PreparationLimits,
    mut choices: BTreeMap<GitOid, &[resolution::ConflictResolution]>,
) -> Result<ResolvedRebasePreparation, RebaseError> {
    limits.validate()?;
    committer.validate()?;
    for id in [request.source_tip, request.upstream, request.onto] {
        if id.is_zero() || id.algorithm() != format {
            return Err(PreparationError::ObjectFormat.into());
        }
    }
    let mut history = History {
        source,
        format,
        limits,
        commits: BTreeMap::new(),
        edges: 0,
    };
    let mut suffix = Vec::new();
    let mut seen = BTreeSet::new();
    let mut next = request.source_tip;
    // Select the entire topology before constructing any candidate objects.
    // A caller cannot turn an unrelated upstream into an arbitrary range.
    while next != request.upstream {
        source.checkpoint()?;
        if !seen.insert(next) {
            return Err(RebaseError::CyclicHistory(next));
        }
        let input = history.read(next)?;
        match input.parents.as_slice() {
            [parent] => {
                suffix
                    .try_reserve(1)
                    .map_err(|_| PreparationError::Budget("rebase steps"))?;
                suffix.push((next, input.clone()));
                next = *parent;
            }
            [] => return Err(RebaseError::UpstreamOutsideLinearHistory),
            parents => {
                return Err(RebaseError::MergeCommit {
                    commit: next,
                    parents: parents.len(),
                });
            }
        }
    }
    for original in choices.keys() {
        if !seen.contains(original) {
            return Err(RebaseError::ResolutionOutsideSuffix(*original));
        }
    }
    let mut resolved_steps = Vec::new();
    history.read(request.upstream)?;
    let mut tree = history.read(request.onto)?.tree;
    let mut current = request.onto;
    let mut planner = Planner::new(source, format, limits);
    let mut steps = Vec::new();
    steps
        .try_reserve_exact(suffix.len())
        .map_err(|_| PreparationError::Budget("rebase steps"))?;
    for (original, input) in suffix.into_iter().rev() {
        source.checkpoint()?;
        let parent_tree = history.read(input.parents[0])?.tree;
        let result = planner.directory(Some(parent_tree), tree, input.tree, &[], 0, false)?;
        source.checkpoint()?;
        let merged = if planner.conflicts.is_empty() {
            if choices.remove(&original).is_some() {
                return Err(RebaseError::Resolution {
                    original,
                    error: resolution::ResolutionError::NoConflicts,
                });
            }
            result.ok_or(PreparationError::InvalidTree)?
        } else if let Some(resolutions) = choices.remove(&original) {
            let (resolved_tree, paths) = resolution::resolve_discovered_conflicts(
                &mut planner,
                Some(parent_tree),
                tree,
                input.tree,
                resolutions,
            )
            .map_err(|error| RebaseError::Resolution { original, error })?;
            resolved_steps.push(RebaseResolvedStep { original, paths });
            resolved_tree
        } else {
            planner.conflicts.sort_by(|a, b| a.path.cmp(&b.path));
            return Ok(ResolvedRebasePreparation {
                preparation: RebasePreparation::Stopped {
                    request,
                    original,
                    completed: steps,
                    reason: RebaseStop::Conflicted(planner.conflicts),
                },
                resolutions: resolved_steps,
            });
        };
        let originally_empty = input.tree == parent_tree;
        if merged == tree && !originally_empty {
            match request.empty {
                EmptyCommitPolicy::Stop => {
                    return Ok(ResolvedRebasePreparation {
                        preparation: RebasePreparation::Stopped {
                            request,
                            original,
                            completed: steps,
                            reason: RebaseStop::BecameEmpty,
                        },
                        resolutions: resolved_steps,
                    });
                }
                EmptyCommitPolicy::Drop => {
                    steps.push(RebaseStep {
                        original,
                        rewritten: current,
                        tree,
                        kind: RebaseStepKind::DroppedEmpty,
                    });
                    continue;
                }
                EmptyCommitPolicy::Keep => {}
            }
        }
        let metadata = source.rebase_metadata(original)?;
        source.checkpoint()?;
        validate_metadata(original, &metadata, limits)?;
        let mut body = format!("tree {merged}\nparent {current}\nauthor ").into_bytes();
        let tail = format!(
            "\ncommitter {} {} +0000\n",
            committer.identity, committer.timestamp
        );
        let size = body
            .len()
            .checked_add(metadata.author.len())
            .and_then(|n| n.checked_add(tail.len()))
            .and_then(|n| n.checked_add(metadata.encoding.as_ref().map_or(0, |e| e.len() + 10)))
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(metadata.message.len()))
            .filter(|n| *n <= limits.max_output_bytes)
            .ok_or(PreparationError::Budget("rebase commit bytes"))?;
        body.try_reserve_exact(size - body.len())
            .map_err(|_| PreparationError::Budget("rebase commit allocation"))?;
        body.extend_from_slice(&metadata.author);
        body.extend_from_slice(tail.as_bytes());
        if let Some(encoding) = metadata.encoding {
            body.extend_from_slice(b"encoding ");
            body.extend_from_slice(&encoding);
            body.push(b'\n');
        }
        body.push(b'\n');
        body.extend_from_slice(&metadata.message);
        current = planner.emit(GitObjectKind::Commit, body)?;
        tree = merged;
        steps.push(RebaseStep {
            original,
            rewritten: current,
            tree,
            kind: if originally_empty {
                RebaseStepKind::PreservedEmpty
            } else {
                RebaseStepKind::Replayed
            },
        });
    }
    source.checkpoint()?;
    // All supplied recipes belong to the suffix and must have been consumed
    // on actual conflicts before a publishable candidate can be returned.
    if let Some(original) = choices.keys().next() {
        return Err(RebaseError::ResolutionOutsideSuffix(*original));
    }
    Ok(ResolvedRebasePreparation {
        preparation: RebasePreparation::Clean(PreparedRebase {
            request,
            tree,
            commit: current,
            steps,
            objects: planner.objects.into_values().collect(),
        }),
        resolutions: resolved_steps,
    })
}

fn validate_metadata(
    id: GitOid,
    metadata: &RebaseCommitMetadata,
    limits: PreparationLimits,
) -> Result<(), RebaseError> {
    let valid_line =
        |bytes: &[u8]| !bytes.is_empty() && !bytes.iter().any(|byte| byte.is_ascii_control());
    let fields: Vec<_> = metadata.author.rsplitn(3, |byte| *byte == b' ').collect();
    let valid_author = fields.len() == 3
        && valid_line(&metadata.author)
        && metadata.author.len() <= 16_384
        && fields[0].len() == 5
        && matches!(fields[0][0], b'+' | b'-')
        && fields[0][1..].iter().all(u8::is_ascii_digit)
        && std::str::from_utf8(fields[1])
            .ok()
            .and_then(|text| text.parse::<i64>().ok())
            .is_some()
        && fields[2].ends_with(b">")
        && fields[2].contains(&b'<');
    if !valid_author
        || metadata.message.len() > limits.max_output_bytes
        || metadata
            .encoding
            .as_ref()
            .is_some_and(|e| e.len() > 128 || !valid_line(e))
    {
        return Err(RebaseError::InvalidOriginalMetadata(id));
    }
    Ok(())
}

struct History<'a, S> {
    source: &'a S,
    format: GitHashAlgorithm,
    limits: PreparationLimits,
    commits: BTreeMap<GitOid, CommitInput>,
    edges: usize,
}
impl<S: MergeObjectSource> History<'_, S> {
    fn read(&mut self, id: GitOid) -> Result<CommitInput, RebaseError> {
        self.source.checkpoint()?;
        if let Some(input) = self.commits.get(&id) {
            return Ok(input.clone());
        }
        if id.is_zero() || id.algorithm() != self.format {
            return Err(PreparationError::ObjectFormat.into());
        }
        if self.commits.len() == self.limits.max_commits {
            return Err(PreparationError::Budget("rebase history commits").into());
        }
        let input = self.source.commit(id)?;
        self.source.checkpoint()?;
        if input.tree.is_zero()
            || input.tree.algorithm() != self.format
            || input
                .parents
                .iter()
                .any(|p| p.is_zero() || p.algorithm() != self.format || *p == id)
        {
            return Err(MergeSourceError::InvalidObject(id).into());
        }
        self.edges = self
            .edges
            .checked_add(input.parents.len())
            .filter(|n| *n <= self.limits.max_edges)
            .ok_or(PreparationError::Budget("rebase history edges"))?;
        self.commits.insert(id, input.clone());
        Ok(input)
    }
}

#[cfg(test)]
mod tests;
