//! A borrowed presentation view keeps each native context's lineage validator.
use super::super::view::InitialView;
use super::*;
use crate::source_retrieval::authorization::InitialAuthorization;
use crate::source_retrieval::context::ContextFile;

#[derive(Clone, Copy)]
pub(super) enum ContextView<'a> {
    Exact(&'a InitialContext),
    Current(&'a RevalidatedInitialContext),
}
impl<'a> ContextView<'a> {
    pub(super) fn matches(self, mode: IndexSource) -> bool {
        matches!(
            (self, mode),
            (Self::Exact(_), IndexSource::Exact) | (Self::Current(_), IndexSource::Current)
        )
    }
    pub(super) fn profile(self) -> &'static str {
        match self {
            Self::Exact(_) => CONTEXT_PROFILE,
            Self::Current(_) => REVALIDATED_PROFILE,
        }
    }
    pub(super) fn exact(self) -> Option<&'a InitialContext> {
        match self {
            Self::Exact(context) => Some(context),
            Self::Current(_) => None,
        }
    }
    pub(super) fn retrieval(self) -> InitialView<'a> {
        match self {
            Self::Exact(context) => InitialView::Exact(context.retrieval()),
            Self::Current(context) => InitialView::Current(context.retrieval()),
        }
    }
    pub(super) fn labels(self) -> &'a InitialAuthorization {
        match self {
            Self::Exact(context) => context.retrieval().authorization(),
            Self::Current(context) => context.retrieval().authorization(),
        }
    }
    pub(super) fn files(self) -> &'a [ContextFile] {
        match self {
            Self::Exact(context) => context.files(),
            Self::Current(context) => context.files(),
        }
    }
    pub(super) fn candidate_files(self) -> usize {
        match self {
            Self::Exact(context) => context.candidate_files(),
            Self::Current(context) => context.candidate_files(),
        }
    }
    pub(super) fn omitted_files(self) -> usize {
        match self {
            Self::Exact(context) => context.omitted_files(),
            Self::Current(context) => context.omitted_files(),
        }
    }
    pub(super) fn source_blobs_read(self) -> usize {
        match self {
            Self::Exact(context) => context.source_blobs_read(),
            Self::Current(context) => context.source_blobs_read(),
        }
    }
    pub(super) fn source_bytes_read(self) -> usize {
        match self {
            Self::Exact(context) => context.source_bytes_read(),
            Self::Current(context) => context.source_bytes_read(),
        }
    }
    pub(super) fn excerpt_bytes(self) -> usize {
        match self {
            Self::Exact(context) => context.excerpt_bytes(),
            Self::Current(context) => context.excerpt_bytes(),
        }
    }
    pub(super) fn source_file_limit(self) -> usize {
        match self {
            Self::Exact(context) => context.source_file_limit(),
            Self::Current(context) => context.source_file_limit(),
        }
    }
    pub(super) fn lineage_metadata_bytes(self) -> usize {
        match self {
            Self::Exact(context) => context.lineage_metadata_bytes(),
            Self::Current(context) => context.lineage_metadata_bytes(),
        }
    }
    pub(super) fn complete(self) -> bool {
        match self {
            Self::Exact(context) => context.complete(),
            Self::Current(context) => context.complete(),
        }
    }
    pub(super) fn validate_file(
        self,
        file: &ContextFile,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<(), RetrievalError> {
        match self {
            Self::Exact(context) => file.validate_lineage(context.retrieval(), live),
            Self::Current(context) => file.validate_revalidated_lineage(context.retrieval(), live),
        }
    }
}
