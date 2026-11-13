//! Bounded construction of an ordered two-parent merge prefix.
//!
//! The caller supplies source identities from one authenticated selection.
//! This pure planner knows no queue, PR, review, check or publication authority.
//! Every step merges onto the previous unpublished candidate; original queue
//! subjects must remain separate from these projected construction coordinates.

#[cfg(test)]
mod tests;

use super::{
    AncestryQueryWork, BTreeMap, CommitInput, GitHashAlgorithm, GitOid, Graph, MergeBaseLimits,
    MergeBaseResult, MergeCommitStyle, MergeConflict, MergeEntry, MergeMetadata, MergeObjectSource,
    MergeProfile, MergeSourceError, PlannedMergeObject, Planner, PreparationError,
    PreparationLimits, emit_merge_commit, frontier_merge_bases_all, renames,
};

/// An entire prefix shares the ordinary preparation ceilings; this count is
/// an additional bound on receipts and request-owned generated commit metadata.
pub const MAX_PREFIX_ENTRIES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefixInput<'a> {
    pub source: GitOid,
    pub metadata: &'a MergeMetadata,
}

/// Construction coordinates, not an original canonical PR review subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefixStep {
    pub source: GitOid,
    pub base: GitOid,
    pub projected_target: GitOid,
    pub tree: GitOid,
    pub commit: GitOid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPrefix {
    pub initial_target: GitOid,
    pub final_commit: GitOid,
    pub steps: Vec<PrefixStep>,
    /// New objects only, deduplicated across the ENTIRE prefix and ordered by
    /// native identity. Original histories remain the caller's prerequisites.
    pub objects: Vec<PlannedMergeObject>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrefixStop {
    Conflicted {
        base: GitOid,
        conflicts: Vec<MergeConflict>,
    },
    AlreadyIntegrated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrefixPreparation {
    Clean(PreparedPrefix),
    /// Stop at the first non-constructible entry, without exposing partial
    /// objects or a publishable candidate. Completed steps are diagnostics.
    Stopped {
        index: usize,
        source: GitOid,
        projected_target: GitOid,
        completed: Vec<PrefixStep>,
        reason: PrefixStop,
    },
}

/// Construct a complete ordered prefix, never a successful partial batch.
///
/// One planner owns all tree visits, content merges, objects and output bytes.
/// Exact merge-base queries spend the remaining aggregate commit/edge budget,
/// including repeated visits across steps. Generated commit metadata is local
/// to this request; generated trees/blobs stay in the existing shared planner.
/// Metadata and every requested identity are validated before object reads.
pub fn prepare_queue_prefix<S: MergeObjectSource>(
    source: &S,
    format: GitHashAlgorithm,
    initial_target: GitOid,
    inputs: &[PrefixInput<'_>],
    limits: PreparationLimits,
    profile: MergeProfile,
) -> Result<PrefixPreparation, PreparationError> {
    limits.validate()?;
    if inputs.is_empty() || inputs.len() > MAX_PREFIX_ENTRIES {
        return Err(PreparationError::InvalidPrefix);
    }
    if std::iter::once(initial_target)
        .chain(inputs.iter().map(|input| input.source))
        .any(|id| id.is_zero() || id.algorithm() != format)
    {
        return Err(PreparationError::ObjectFormat);
    }
    for input in inputs {
        input.metadata.validate()?;
    }
    source.checkpoint()?;

    let mut planner = Planner::new(source, format, limits);
    let mut generated = BTreeMap::new();
    let mut steps = Vec::new();
    steps
        .try_reserve_exact(inputs.len())
        .map_err(|_| PreparationError::Budget("queue prefix steps"))?;
    let mut target = initial_target;
    let mut work = AncestryQueryWork::default();
    // One shared attribute cache/work envelope spans the complete prefix.
    let attributes = super::attributes::Context::builtin();
    for (index, input) in inputs.iter().enumerate() {
        source.checkpoint()?;
        let overlay = CommitOverlay {
            original: source,
            generated: &generated,
        };
        let mut step_work = AncestryQueryWork::default();
        let bases = frontier_merge_bases_all(
            &Graph {
                source: &overlay,
                format,
            },
            target,
            input.source,
            MergeBaseLimits {
                max_commits: limits.max_commits - work.visited_commits,
                max_edges: limits.max_edges - work.examined_edges,
            },
            &mut step_work,
            || source.checkpoint(),
        );
        // The frontier resets its output counter on every query. Charge the
        // completed work before interpreting either its result or refusal.
        work.visited_commits += step_work.visited_commits;
        work.examined_edges += step_work.examined_edges;
        let bases = bases.map_err(PreparationError::Graph)?;
        source.checkpoint()?;
        let base = match bases {
            MergeBaseResult::NoCommonAncestor => return Err(PreparationError::NoCommonAncestor),
            MergeBaseResult::Bases(bases) if bases.len() == 1 => bases[0],
            MergeBaseResult::Bases(bases) => {
                return Err(PreparationError::MultipleMergeBases(bases));
            }
        };
        if base == input.source {
            return Ok(PrefixPreparation::Stopped {
                index,
                source: input.source,
                projected_target: target,
                completed: steps,
                reason: PrefixStop::AlreadyIntegrated,
            });
        }
        let base_tree = overlay.commit(base)?.tree;
        let our_tree = overlay.commit(target)?.tree;
        let their_tree = overlay.commit(input.source)?.tree;
        let tree = match profile {
            MergeProfile::PathMergeV1 => {
                planner.directory(Some(base_tree), our_tree, their_tree, &[], 0, false)?
            }
            MergeProfile::ExactRenamesV1 => {
                // Rename alignment discards temporary comparison trees. Prior
                // prefix objects remain dependencies of already-created parent
                // commits even when the next result no longer references them.
                let retained = planner.objects.keys().copied().collect();
                renames::merge_retaining(&mut planner, base_tree, our_tree, their_tree, &retained)?
            }
            MergeProfile::BuiltinAttributesV1 => planner.directory_context(
                Some(base_tree),
                our_tree,
                their_tree,
                &[],
                0,
                &attributes,
            )?,
        };
        source.checkpoint()?;
        if !planner.conflicts.is_empty() {
            planner
                .conflicts
                .sort_by(|left, right| left.path.cmp(&right.path));
            return Ok(PrefixPreparation::Stopped {
                index,
                source: input.source,
                projected_target: target,
                completed: steps,
                reason: PrefixStop::Conflicted {
                    base,
                    conflicts: planner.conflicts,
                },
            });
        }
        let tree = tree.ok_or(PreparationError::InvalidTree)?;
        let commit = emit_merge_commit(
            &mut planner,
            target,
            input.source,
            tree,
            input.metadata,
            MergeCommitStyle::TwoParent,
        )?;
        let record = (
            CommitInput {
                tree,
                parents: vec![target, input.source],
            },
            Some(
                i64::try_from(input.metadata.timestamp)
                    .map_err(|_| PreparationError::InvalidMetadata)?,
            ),
        );
        if let Some(previous) = generated.insert(commit, record.clone())
            && previous != record
        {
            return Err(PreparationError::InvalidTree);
        }
        steps.push(PrefixStep {
            source: input.source,
            base,
            projected_target: target,
            tree,
            commit,
        });
        target = commit;
    }
    source.checkpoint()?;
    Ok(PrefixPreparation::Clean(PreparedPrefix {
        initial_target,
        final_commit: target,
        steps,
        objects: planner.objects.into_values().collect(),
    }))
}

/// Only generated commit metadata is overlaid. This adapter cannot extend the
/// original source's object authority; the planner owns constructed tree/blob
/// bytes separately and never requests them through this source.
struct CommitOverlay<'a, S> {
    original: &'a S,
    generated: &'a BTreeMap<GitOid, (CommitInput, Option<i64>)>,
}

impl<S: MergeObjectSource> MergeObjectSource for CommitOverlay<'_, S> {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        self.original.checkpoint()
    }

    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.commit_with_date(id).map(|(commit, _)| commit)
    }

    fn commit_with_date(&self, id: GitOid) -> Result<(CommitInput, Option<i64>), MergeSourceError> {
        self.checkpoint()?;
        if let Some(commit) = self.generated.get(&id) {
            return Ok(commit.clone());
        }
        self.original.commit_with_date(id)
    }

    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.original.tree(id)
    }

    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.original.blob(id)
    }
}
