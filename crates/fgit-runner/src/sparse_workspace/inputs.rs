//! Explicit candidate provenance for the SAME sparse host writer.
//! This private sum type cannot turn an unpublished candidate into a canonical
//! SparseManifest. Candidate plans have no output-import authority.

use super::*;
use fgit_crypto::GitOid;
use fgit_treefs::{SparseCandidateManifest, SparseEntry};
use fgit_types::{RepositoryCommitId, RepositoryId};

#[derive(Clone, Debug)]
pub(super) enum WorkspaceManifest<A: GitHashAlgorithm> {
    Canonical(Arc<SparseManifest<A>>),
    Candidate(Arc<SparseCandidateManifest<A>>),
}
pub(super) struct SourceIdentity<'a, A: GitHashAlgorithm> {
    repository: RepositoryId,
    rcr: RepositoryCommitId,
    commit: &'a GitOid<A>,
    tree: &'a GitOid<A>,
    payload: usize,
}
impl<'a, A: GitHashAlgorithm> SourceIdentity<'a, A> {
    pub(super) fn repository_id(&self) -> RepositoryId { self.repository }
    pub(super) fn source_rcr_id(&self) -> RepositoryCommitId { self.rcr }
    pub(super) fn source_commit_oid(&self) -> &'a GitOid<A> { self.commit }
    pub(super) fn source_tree_oid(&self) -> &'a GitOid<A> { self.tree }
    pub(super) fn payload_bytes(&self) -> usize { self.payload }
}
impl<A: GitHashAlgorithm> WorkspaceManifest<A> {
    pub(super) fn entries(&self) -> &[SparseEntry<A>] {
        match self { Self::Canonical(m) => m.entries(), Self::Candidate(m) => m.entries() }
    }
    /// For a candidate these are BASE coordinates, not an admission assertion.
    pub(super) fn receipt(&self) -> SourceIdentity<'_, A> {
        match self {
            Self::Canonical(m) => SourceIdentity {
                repository: m.receipt().repository_id(), rcr: m.receipt().source_rcr_id(),
                commit: m.receipt().source_commit_oid(), tree: m.receipt().source_tree_oid(),
                payload: m.receipt().payload_bytes(),
            },
            Self::Candidate(m) => SourceIdentity {
                repository: m.repository_id(), rcr: m.base_rcr_id(), commit: m.base_commit_oid(),
                tree: m.base_tree_oid(), payload: m.payload_bytes(),
            },
        }
    }
    pub(super) fn is_candidate(&self) -> bool { matches!(self, Self::Candidate(_)) }
    pub(super) fn bind_candidate(&self, bytes: &mut Encoder) -> Result<(), HostRefusal> {
        if let Self::Candidate(m) = self {
            // Canonical plan bytes remain byte-for-byte unchanged. Candidate
            // plans additionally bind the exact unpublished native commit/tree,
            // including differences outside the selected input prefixes.
            frame(bytes, b"frankengit/sparse-host/unpublished-candidate/v1")?;
            frame(bytes, m.candidate_commit_oid().digest_bytes())?;
            frame(bytes, m.candidate_tree_oid().digest_bytes())?;
        }
        Ok(())
    }
}

impl<A: GitHashAlgorithm> SparseWorkspacePlan<A> {
    /// Materialize exact unpublished candidate inputs with the existing writer,
    /// capability checks and lease lifecycle. This is a trusted-tool input-only
    /// profile. No output declaration, candidate admission, or canonical source
    /// receipt is inferred, and SparseWorkspace::import refuses these plans.
    pub fn for_candidate(
        manifest: Arc<SparseCandidateManifest<A>>, capability: &TreeCapability,
        now: u64, limits: SparseLimits,
    ) -> Result<Self, HostRefusal> {
        Self::from_manifest(WorkspaceManifest::Candidate(manifest), Vec::new(), capability, now, limits)
    }
}
