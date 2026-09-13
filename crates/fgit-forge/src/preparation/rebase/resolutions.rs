//! Explicit, original-commit-bound conflict choices for an entire rebase.
//!
//! Every retry reconstructs from the same original suffix. There is no mutable
//! sequencer, implicit branch movement, conflict-marker interpretation or
//! successful-prefix publication. Ours means the accumulated rebased tree;
//! theirs means the original commit being replayed, and base its sole parent.
use super::*;
use crate::preparation::resolution::{
    ConflictResolution, ResolutionChoice, ResolutionError, ResolvedPath, validate_resolutions,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebaseCommitResolution {
    /// Native identity of the original commit, never a generated step number.
    pub original: GitOid,
    pub paths: Vec<ConflictResolution>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebaseResolvedStep {
    pub original: GitOid,
    /// Byte-sorted decisions, with actual discovered sides and selected result.
    pub paths: Vec<ResolvedPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRebasePreparation {
    pub preparation: RebasePreparation,
    /// Diagnostic only on a stop. No objects or partial candidate are returned.
    pub resolutions: Vec<RebaseResolvedStep>,
}

/// Validate all recipes before reading source objects. Count and byte budgets
/// apply to the whole series, not independently to each conflicted commit.
pub fn validate_rebase_resolutions(
    format: GitHashAlgorithm,
    limits: PreparationLimits,
    resolutions: &[RebaseCommitResolution],
) -> Result<(), RebaseError> {
    limits.validate()?;
    if resolutions.len() > limits.max_commits {
        return Err(PreparationError::Budget("rebase resolution commits").into());
    }
    let mut originals = BTreeSet::new();
    let mut paths = 0_usize;
    let mut bytes = 0_usize;
    for binding in resolutions {
        if binding.original.is_zero() || binding.original.algorithm() != format {
            return Err(PreparationError::ObjectFormat.into());
        }
        if !originals.insert(binding.original) {
            return Err(RebaseError::DuplicateResolutionCommit(binding.original));
        }
        if binding.paths.is_empty() {
            return Err(RebaseError::Resolution {
                original: binding.original,
                error: ResolutionError::InvalidInputs,
            });
        }
        paths = paths
            .checked_add(binding.paths.len())
            .filter(|count| *count <= limits.max_conflicts)
            .ok_or(PreparationError::Budget("rebase resolution paths"))?;
        validate_resolutions(&binding.paths, limits).map_err(|error| RebaseError::Resolution {
            original: binding.original,
            error,
        })?;
        for resolution in &binding.paths {
            let content = match &resolution.choice {
                ResolutionChoice::File { bytes, .. } => bytes.len(),
                _ => 0,
            };
            bytes = bytes
                .checked_add(resolution.path.len())
                .and_then(|total| total.checked_add(content))
                .filter(|total| *total <= limits.max_output_bytes)
                .ok_or(PreparationError::Budget("rebase resolution bytes"))?;
        }
    }
    Ok(())
}

/// Replay a linear suffix with explicit conflict choices scoped to original
/// commit IDs. Unspecified conflicts stop without an artifact. Supplied choices
/// must cover every conflict at their step, cannot target a clean path/commit,
/// and cannot refer outside the suffix. Future-step recipes may remain unused
/// only in a stopped result, which carries no publishable objects.
///
/// Discovery and reconstruction use the existing resolution engine and the
/// same planner for the entire series. Tree traversal, content work, emitted
/// objects and bytes are never reset when resolving or advancing a step.
pub fn prepare_resolved_rebase<S: RebaseObjectSource>(
    source: &S,
    format: GitHashAlgorithm,
    request: RebaseRequest,
    committer: &RebaseCommitter,
    limits: PreparationLimits,
    resolutions: &[RebaseCommitResolution],
) -> Result<ResolvedRebasePreparation, RebaseError> {
    validate_rebase_resolutions(format, limits, resolutions)?;
    let choices = resolutions
        .iter()
        .map(|r| (r.original, r.paths.as_slice()))
        .collect();
    prepare_rebase_inner(source, format, request, committer, limits, choices)
}
