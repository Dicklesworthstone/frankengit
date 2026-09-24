//! Several direct comparisons under ONE review envelope. A failed later
//! comparison returns no successful prefix. The ordinary Walker remains the
//! only path/content/diff implementation.

use super::{
    ComparisonMode, GitHashAlgorithm, GitOid, MergeObjectSource, ReviewError, ReviewOptions,
    SourceComparison, Walker,
};

/// One final-tree comparison plus at most 256 rewritten commits.
pub const MAX_SERIES_COMPARISONS: usize = 257;

/// Compare the given immutable commit pairs in caller-specified order.
///
/// Tree entries, changed entries, text files, retained path/hunk bytes and
/// hunks are cumulative across the entire series, not reset for every pair.
/// Blob size and diff work remain per-blob/per-text limits, as in ordinary
/// review; cumulative text-file count bounds the number of diff invocations.
/// All pairs are validated before source reads. Only direct comparisons are
/// supported; callers select and authorize their immutable source separately.
/// An empty series is a valid empty read, but still observes cancellation.
pub fn compare_source_series<S: MergeObjectSource>(
    source: &S,
    format: GitHashAlgorithm,
    pairs: &[(GitOid, GitOid)],
    options: &ReviewOptions,
) -> Result<Vec<SourceComparison>, ReviewError> {
    options.validate()?;
    if options.mode != ComparisonMode::Direct {
        return Err(ReviewError::InvalidOptions);
    }
    if pairs.len() > MAX_SERIES_COMPARISONS {
        return Err(ReviewError::Budget("series comparisons"));
    }
    for id in pairs.iter().copied().flat_map(<[GitOid; 2]>::from) {
        if id.is_zero() || id.algorithm() != format {
            return Err(ReviewError::InvalidObject(id));
        }
    }
    source.checkpoint()?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(pairs.len())
        .map_err(|_| ReviewError::Budget("series allocation"))?;
    let (mut trees, mut changes, mut text_files, mut output_bytes, mut hunks) = (0, 0, 0, 0, 0);
    for &(before, after) in pairs {
        source.checkpoint()?;
        let before_tree = source.commit(before)?.tree;
        let after_tree = source.commit(after)?.tree;
        for id in [before_tree, after_tree] {
            if id.is_zero() || id.algorithm() != format {
                return Err(ReviewError::InvalidObject(id));
            }
        }
        let mut remaining = options.clone();
        remaining.limits.max_changes = options.limits.max_changes.saturating_sub(changes);
        // Zero remaining changes is intentional: an identical next tree still
        // succeeds, while Walker::entry refuses the first additional change.
        // Only this internal allowance may be zero; public options were checked.
        let mut walker = Walker {
            source,
            format,
            options: &remaining,
            entries: Vec::new(),
            trees,
            text_files,
            output_bytes,
            hunks,
        };
        walker.directory(Some(before_tree), Some(after_tree), &[], 0)?;
        walker.entries.sort_by(|a, b| a.path.cmp(&b.path));
        if walker
            .entries
            .windows(2)
            .any(|pair| pair[0].path == pair[1].path)
        {
            return Err(ReviewError::InvalidTree);
        }
        changes = changes
            .checked_add(walker.entries.len())
            .filter(|n| *n <= options.limits.max_changes)
            .ok_or(ReviewError::Budget("changed entries"))?;
        trees = walker.trees;
        text_files = walker.text_files;
        output_bytes = walker.output_bytes;
        hunks = walker.hunks;
        source.checkpoint()?;
        output.push(SourceComparison {
            mode: ComparisonMode::Direct,
            requested_before: before,
            requested_after: after,
            compared_before: before,
            before_tree,
            after_tree,
            entries: walker.entries,
        });
    }
    source.checkpoint()?;
    Ok(output)
}
