//! Reuse the selected native object owner, never a second snapshot or Git parser.
use super::{
    Cell, GitOid, MergeObjectSource, ParseLimits, SelectedSource, VerifiedFabricPackSource,
};
use fgit_forge::review::{ComparisonMode, SourcePathChanges, compare_source_paths};

pub(in crate::treefs_workspace) fn changed_paths(
    original: &super::super::NodeTreeSource<'_>,
    before: Option<GitOid>,
    after: GitOid,
    mode: ComparisonMode,
) -> Result<SourcePathChanges, fgit_forge::review::ReviewError> {
    let source = SelectedSource {
        inner: VerifiedFabricPackSource {
            fabric: original.inner.fabric,
            object_format: original.inner.object_format,
            maximum_object_bytes: original.inner.maximum_object_bytes.min(32 * 1024 * 1024),
            database_context: original.inner.database_context,
            database_exhaustion: original.inner.database_exhaustion,
            session_is_live: original.inner.session_is_live,
        },
        selected: original.selected,
        ancestry: None,
        limits: ParseLimits {
            tree_reference_bytes: original.inner.object_format.digest_len(),
            max_tree_entries: 100_000,
            max_header_lines: 16_384,
            max_object_bytes: original.inner.maximum_object_bytes.min(32 * 1024 * 1024),
            ..ParseLimits::default()
        },
        read_bytes: Cell::new(0),
        budget_failed: Cell::new(false),
    };
    let result = compare_source_paths(&source, original.inner.object_format, before, after, mode);
    source.checkpoint()?;
    result
}
