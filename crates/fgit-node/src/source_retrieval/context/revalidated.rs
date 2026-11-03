//! Exact native hydration with separate current-source and index provenance.
use super::{Assembly, ContextFile, Plan, RetrievalError, RevalidatedInitialReport};

/// Hydrated context from indexes revalidated against one current native source.
/// The original index sources, generations, rows and authorization labels are
/// retained unchanged. This is untrusted source material, not a read grant.
#[derive(Clone, Debug)]
pub struct RevalidatedInitialContext {
    retrieval: RevalidatedInitialReport,
    files: Vec<ContextFile>,
    candidate_files: usize,
    source_bytes_read: usize,
    excerpt_bytes: usize,
    source_file_limit: usize,
    lineage_metadata_bytes: usize,
}
impl RevalidatedInitialContext {
    #[must_use]
    pub const fn retrieval(&self) -> &RevalidatedInitialReport {
        &self.retrieval
    }
    #[must_use]
    pub fn files(&self) -> &[ContextFile] {
        &self.files
    }
    #[must_use]
    pub const fn candidate_files(&self) -> usize {
        self.candidate_files
    }
    #[must_use]
    pub const fn omitted_files(&self) -> usize {
        self.candidate_files - self.files.len()
    }
    #[must_use]
    pub const fn source_blobs_read(&self) -> usize {
        self.files.len()
    }
    #[must_use]
    pub const fn source_bytes_read(&self) -> usize {
        self.source_bytes_read
    }
    #[must_use]
    pub const fn excerpt_bytes(&self) -> usize {
        self.excerpt_bytes
    }
    #[must_use]
    pub const fn source_file_limit(&self) -> usize {
        self.source_file_limit
    }
    /// Conservative lineage reservation charged to the original Initial
    /// result-byte allowance before any native hydration I/O.
    #[must_use]
    pub const fn lineage_metadata_bytes(&self) -> usize {
        self.lineage_metadata_bytes
    }
    #[must_use]
    pub fn complete(&self) -> bool {
        self.omitted_files() == 0 && self.retrieval.complete()
    }
    pub(crate) fn finish(
        retrieval: RevalidatedInitialReport,
        plan: &Plan,
        assembly: Assembly,
        source_file_limit: usize,
        live: &mut impl FnMut() -> Result<(), RetrievalError>,
    ) -> Result<Self, RetrievalError> {
        if assembly.files.len() != plan.files.len() {
            return Err(RetrievalError::Invalid("incomplete context hydration"));
        }
        for file in &assembly.files {
            file.validate_revalidated_lineage(&retrieval, live)?;
        }
        live()?;
        Ok(Self {
            retrieval,
            files: assembly.files,
            candidate_files: plan.candidate_files,
            source_bytes_read: assembly.source_bytes,
            excerpt_bytes: assembly.excerpt_bytes,
            source_file_limit,
            lineage_metadata_bytes: plan.lineage_metadata_bytes()?,
        })
    }
}
