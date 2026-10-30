//! First-parent pages share current-ref selection and the verified native
//! object owner. A cursor never selects an arbitrary repository object.

use super::*;
use fgit_forge::history::first_parent::{
    FirstParentOptions, FirstParentPage, first_parent_history,
};

impl OneNode {
    /// Read a bounded recent first-parent page from one visible reference.
    ///
    /// A continuation binds the original authority head, exact reference and
    /// tip. Its offset is revalidated by walking from that tip on every call;
    /// no cursor-supplied object grants disclosure. Prefix and page work share
    /// the original history limits. This is not arbitrary-depth O(page) paging
    /// and does not compute the whole history's size.
    pub async fn read_first_parent_history_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        visibility: &RefVisibility,
        expected_head: Option<RepositoryAuthorityHeadId>,
        options: &FirstParentOptions,
    ) -> Result<(RepositoryAuthorityHeadId, FirstParentPage), NodeHistoryRefusal> {
        options.validate().map_err(failed)?;
        let mut pinned_head = expected_head;
        if let Some(cursor) = &options.cursor {
            if cursor.reference != *reference || cursor.tip.algorithm() != self.object_format {
                return Err(failed(HistoryError::InvalidOptions));
            }
            if pinned_head.is_some_and(|head| head != cursor.source_head) {
                return Err(NodeHistoryRefusal::SnapshotMoved);
            }
            pinned_head = Some(cursor.source_head);
        }
        self.with_history_source_in(
            request,
            reference,
            visibility,
            pinned_head,
            options.limits,
            |source, tip| {
                if options
                    .cursor
                    .as_ref()
                    .is_some_and(|cursor| cursor.tip != tip)
                {
                    return Err(HistoryError::InvalidOptions);
                }
                // Native history records are at most 64 KiB. Apply that bound
                // to the fabric read before allocating either metadata body.
                let maximum = source.inner.maximum_object_bytes.min(64 * 1024);
                let bounded = SelectedSource {
                    inner: VerifiedFabricPackSource {
                        fabric: source.inner.fabric,
                        object_format: source.inner.object_format,
                        maximum_object_bytes: maximum,
                        database_context: source.inner.database_context,
                        database_exhaustion: source.inner.database_exhaustion,
                        session_is_live: source.inner.session_is_live,
                    },
                    selected: source.selected,
                    ancestry: None,
                    limits: ParseLimits {
                        max_object_bytes: maximum,
                        ..source.limits.clone()
                    },
                    read_bytes: Cell::new(0),
                    budget_failed: Cell::new(false),
                };
                first_parent_history(&bounded, self.object_format, tip, options.log_options())
            },
        )
        .await
    }
}

#[cfg(test)]
#[path = "first_parent_tests.rs"]
mod tests;
