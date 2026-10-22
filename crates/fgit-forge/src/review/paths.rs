//! Complete structural changes for native trigger selection. No blob payloads.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePathChanges {
    pub requested_before: Option<GitOid>,
    pub compared_before: Option<GitOid>,
    pub after: GitOid,
    pub before_tree: Option<GitOid>,
    pub after_tree: GitOid,
    pub paths: Vec<Vec<u8>>,
}

/// Direct compares exact trees; None is an explicitly empty base.
/// MergeBase requires a unique common ancestor. No truncated list is returned.
/// Directory-only changes are omitted; type changes include both endpoints.
/// The source owner supplies identity verification, visibility and cancellation.
pub fn compare_source_paths<S: MergeObjectSource>(
    source: &S,
    format: GitHashAlgorithm,
    before: Option<GitOid>,
    after: GitOid,
    mode: ComparisonMode,
) -> Result<SourcePathChanges, ReviewError> {
    source.checkpoint()?;
    for id in before.into_iter().chain([after]) {
        if id.is_zero() || id.algorithm() != format {
            return Err(ReviewError::InvalidObject(id));
        }
    }
    let compared_before = match (mode, before) {
        (ComparisonMode::Direct, value) => value,
        (ComparisonMode::MergeBase, Some(before)) => match source_merge_bases(
            source,
            format,
            before,
            after,
            MergeBaseLimits {
                max_commits: 4096,
                max_edges: 16_384,
            },
        )
        .map_err(ReviewError::Graph)?
        {
            MergeBaseResult::Bases(bases) if bases.len() == 1 => Some(bases[0]),
            MergeBaseResult::Bases(bases) => return Err(ReviewError::MultipleMergeBases(bases)),
            MergeBaseResult::NoCommonAncestor => return Err(ReviewError::NoCommonAncestor),
        },
        (ComparisonMode::MergeBase, None) => return Err(ReviewError::InvalidOptions),
    };
    let before_tree = compared_before
        .map(|id| source.commit(id).map(|v| v.tree))
        .transpose()?;
    let after_tree = source.commit(after)?.tree;
    for id in before_tree.into_iter().chain([after_tree]) {
        if id.is_zero() || id.algorithm() != format {
            return Err(ReviewError::InvalidObject(id));
        }
    }
    let options = ReviewOptions::default();
    let mut walker = Walker {
        source,
        format,
        options: &options,
        entries: Vec::new(),
        trees: 0,
        text_files: 0,
        identities_only: true,
        output_bytes: 0,
        hunks: 0,
    };
    walker.directory(before_tree, Some(after_tree), &[], 0)?;
    let mut paths: Vec<_> = walker
        .entries
        .into_iter()
        .filter(|entry| {
            entry
                .before
                .into_iter()
                .chain(entry.after)
                .any(|id| !is_tree(id.mode))
        })
        .map(|entry| entry.path)
        .collect();
    paths.sort();
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ReviewError::InvalidTree);
    }
    source.checkpoint()?;
    Ok(SourcePathChanges {
        requested_before: before,
        compared_before,
        after,
        before_tree,
        after_tree,
        paths,
    })
}

#[cfg(test)]
mod tests;
