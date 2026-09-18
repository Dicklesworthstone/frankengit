//! Sparse inputs from an unpublished, exact single-parent candidate.
//!
//! Candidate inputs are NOT a canonical SparseManifest. The authenticated base
//! and the executed candidate have separate identities, and no conversion to a
//! canonical manifest or receipt is exposed. The existing sparse discovery and
//! object verification engine is reused internally; this module does no I/O.

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body};
use fgit_types::{RepositoryCommitId, RepositoryId};
use crate::{BaseView, ObjectSource, ObjectSourceError, SparseEntry, SparseLimits,
    SparseManifest, SparseRefusal, TreeCapability};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateManifestRefusal {
    Source(ObjectSourceError),
    Sparse(SparseRefusal),
    InvalidCandidate(&'static str),
}
impl std::fmt::Display for CandidateManifestRefusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "candidate inputs refused: {self:?}")
    }
}
impl std::error::Error for CandidateManifestRefusal {}

/// Verified candidate-tree bytes with explicit, independently selected base
/// provenance. This is neither admission evidence nor an authority snapshot.
/// The source owner must restrict originals to the selected base's closure and
/// validate uploaded pack/closure completeness before calling this constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseCandidateManifest<A: GitHashAlgorithm> {
    base_rcr: RepositoryCommitId,
    base_commit: GitOid<A>,
    base_tree: GitOid<A>,
    // A private traversal result, never exported as a canonical source receipt.
    content: SparseManifest<A>,
}
impl<A: GitHashAlgorithm> SparseCandidateManifest<A> {
    /// Discover precisely the capability-visible part of the candidate tree.
    /// The candidate's native body is identity-checked, charged, and parsed;
    /// its sole parent must equal the independent canonical base. Callers
    /// cannot substitute a tree or metadata supplied by a preparation receipt.
    /// All sparse ordering, path, mode, symlink and payload limits remain native.
    pub fn build<S: ObjectSource<A>>(
        base: &BaseView<A>, source: &S, candidate: GitOid<A>,
        capability: &mut TreeCapability, now: u64, parse_limits: ParseLimits,
        limits: SparseLimits,
    ) -> Result<Self, CandidateManifestRefusal> {
        let invalid = CandidateManifestRefusal::InvalidCandidate;
        if candidate == *base.base_commit_oid() || capability.repository_id() != base.repository_id() {
            return Err(invalid("candidate must differ from its same-repository base"));
        }
        let grant = capability.authorize_root(now)
            .map_err(|e| CandidateManifestRefusal::Sparse(SparseRefusal::Capability(e)))?;
        let body = base.read_object(source, &candidate, GitObjectKind::Commit, &grant)
            .map_err(CandidateManifestRefusal::Source)?;
        capability.charge_fetch(u64::try_from(body.len()).map_err(|_| invalid("commit length overflow"))?)
            .map_err(|e| CandidateManifestRefusal::Sparse(SparseRefusal::Capability(e)))?;
        let ParsedObject::Commit(commit) = parse_object_body(ObjectType::Commit, &body,
            AcceptanceProfile::GitCompatibleImport, &parse_limits)
            .map_err(|_| invalid("candidate is not a bounded native commit"))?
        else { return Err(invalid("candidate is not a commit")); };
        if commit.headers().iter().filter(|h| h.name == b"tree").count() != 1
            || commit.headers().iter().any(|h| (h.name == b"tree" || h.name == b"parent") && !h.continuations.is_empty())
        { return Err(invalid("ambiguous candidate tree or parent headers")); }
        let parse = |bytes: &[u8]| {
            let text = std::str::from_utf8(bytes).map_err(|_| invalid("invalid native reference"))?;
            A::parse_hex(&text.to_ascii_lowercase()).map_err(|_| invalid("invalid native reference"))
        };
        let mut parents = commit.parent_references();
        let parent = parse(parents.next().ok_or_else(|| invalid("candidate has no parent"))?)?;
        if parents.next().is_some() || parent != *base.base_commit_oid() {
            return Err(invalid("candidate must have exactly the selected base as parent"));
        }
        let tree = parse(commit.tree_reference().ok_or_else(|| invalid("candidate has no tree"))?)?;
        // Use BaseView only as the private immutable traversal cursor. Its
        // candidate coordinates must never escape as an authenticated base:
        // the public result exposes the real base separately from the candidate.
        let cursor = BaseView::new(base.repository_id(), base.base_rcr_id(), candidate,
            tree, parse_limits, base.path_policy().clone());
        let content = SparseManifest::build(&cursor, source, capability, now, limits)
            .map_err(CandidateManifestRefusal::Sparse)?;
        Ok(Self { base_rcr: base.base_rcr_id(), base_commit: *base.base_commit_oid(),
            base_tree: *base.base_tree_oid(), content })
    }
    pub fn repository_id(&self) -> RepositoryId { self.content.receipt().repository_id() }
    /// Canonical RCR of the BASE, never a record admitting the candidate.
    pub fn base_rcr_id(&self) -> RepositoryCommitId { self.base_rcr }
    pub fn base_commit_oid(&self) -> &GitOid<A> { &self.base_commit }
    pub fn base_tree_oid(&self) -> &GitOid<A> { &self.base_tree }
    pub fn candidate_commit_oid(&self) -> &GitOid<A> { self.content.receipt().source_commit_oid() }
    pub fn candidate_tree_oid(&self) -> &GitOid<A> { self.content.receipt().source_tree_oid() }
    pub fn entries(&self) -> &[SparseEntry<A>] { self.content.entries() }
    pub fn payload_bytes(&self) -> usize { self.content.receipt().payload_bytes() }
}
