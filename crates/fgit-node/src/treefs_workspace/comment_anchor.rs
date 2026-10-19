//! Source-comment object validation under the existing verified source owner.
//! Called inside canonical admission at each CAS basis, not a transport precheck.

use super::{Cell, ParseLimits, SelectedSource, VerifiedFabricPackSource};
use crate::async_projection_unavailable;
use crate::treefs_workspace::native_merge::NodeNativeMergeProjection;
use fgit_admission::merge::native::NativeMergeProjection;
use fgit_admission::{ProjectionFailure, ValidatedClosure};
use fgit_authority::AuthenticatedHead;
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_chronicle::PublicationBasis;
use fgit_forge::event::pull_request_comment::{
    MAX_SOURCE_COMMENT_BLOB_BYTES, SourceCommentAnchor, SourceCommentError,
};
use fgit_forge::preparation::{MergeObjectSource, MergeSourceError};
use fgit_types::RefusalCode;
use fsqlite_types::cx::Cx;

impl NodeNativeMergeProjection<'_> {
    pub(in crate::treefs_workspace) async fn validate_source_comment_anchor_in(
        &self,
        authority: &FsqliteAuthorityStore,
        cx: &Cx,
        basis: &PublicationBasis,
        authenticated: &AuthenticatedHead,
        anchor: &SourceCommentAnchor,
    ) -> Result<ValidatedClosure, ProjectionFailure> {
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        let selected = self
            .inner
            .materializer
            .materialize_exact_in(
                authority,
                cx,
                self.node.repository_id,
                basis,
                authenticated,
                &|| self.merge_checkpoint(cx).is_err(),
            )
            .await
            .map_err(async_projection_unavailable)?;
        let closure = selected.selected_closure().closure();
        if closure.objects().len() > self.object_limits.max_objects {
            return Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded,
            ));
        }
        if anchor.source_tip.algorithm() != self.node.object_format {
            return Err(ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid));
        }
        let exhaustion = Cell::new(None);
        // Bound intake before storage/pack materialization can allocate a blob.
        // Commit/tree objects in this anchor profile meet the same fixed cap.
        let maximum = (MAX_SOURCE_COMMENT_BLOB_BYTES as usize)
            .min(self.object_limits.max_object_bytes)
            .min(usize::try_from(self.node.max_object_bytes).unwrap_or(usize::MAX));
        let source = SelectedSource {
            inner: VerifiedFabricPackSource {
                fabric: &self.node.fabric,
                object_format: self.node.object_format,
                maximum_object_bytes: maximum,
                database_context: cx,
                database_exhaustion: &exhaustion,
                session_is_live: None,
            },
            selected: selected.selected_closure(),
            limits: ParseLimits {
                tree_reference_bytes: self.node.object_format.digest_len(),
                max_tree_entries: 100_000,
                max_header_lines: 16_384,
                max_object_bytes: maximum,
                ..ParseLimits::default()
            },
            read_bytes: Cell::new(0),
            budget_failed: Cell::new(false),
        };
        let result = anchor.verify_source(&source);
        self.merge_checkpoint(cx)
            .map_err(ProjectionFailure::Unavailable)?;
        if exhaustion.get().is_some() {
            return Err(ProjectionFailure::Unavailable(
                RefusalCode::ResourceBudgetExceeded,
            ));
        }
        source
            .checkpoint()
            .map_err(|error| failure(SourceCommentError::Source(error)))?;
        result.map_err(failure)?;
        Ok(ValidatedClosure {
            object_closure_root: fgit_admission::permitted_object_closure_root(closure)
                .map_err(ProjectionFailure::Unavailable)?,
            objects: closure.objects().clone(),
        })
    }
}

fn failure(error: SourceCommentError) -> ProjectionFailure {
    match error {
        SourceCommentError::Invalid => ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid),
        SourceCommentError::Budget
        | SourceCommentError::Source(MergeSourceError::BudgetExceeded) => {
            ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
        }
        SourceCommentError::Source(MergeSourceError::Cancelled) => {
            ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress)
        }
        SourceCommentError::Source(MergeSourceError::OutsideSelection) => {
            ProjectionFailure::Refuse(RefusalCode::ObjectClosureIncomplete)
        }
        SourceCommentError::Source(MergeSourceError::Unavailable(_)) => {
            ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing)
        }
        SourceCommentError::Source(MergeSourceError::InvalidObject(_)) => {
            ProjectionFailure::Unavailable(RefusalCode::EvidenceInvalid)
        }
    }
}

// Explicit: this file is loaded through #[path], so a bare `mod tests;` would
// resolve beside it (treefs_workspace/tests.rs), not in comment_anchor/.
#[cfg(test)]
#[path = "comment_anchor/tests.rs"]
mod tests;
