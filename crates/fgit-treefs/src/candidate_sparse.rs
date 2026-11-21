//! Sparse inputs from unpublished single-parent, merge and rebase candidates.
//!
//! Candidate inputs are NOT a canonical SparseManifest. The authenticated base
//! and executed candidate have separate identities. Native sparse discovery
//! and verification are shared; no conversion to a canonical receipt is exposed.

use crate::{
    BaseView, ObjectSource, ObjectSourceError, SparseEntry, SparseLimits, SparseManifest,
    SparseRefusal, TreeCapability,
};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity};
use fgit_git_object::{
    AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body,
};
use fgit_types::{RepositoryCommitId, RepositoryId};

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

/// Verified candidate-tree bytes with separately selected canonical provenance.
/// The source owner authenticates every selected parent and restricts originals
/// to their closures before calling either constructor. It also validates full
/// candidate closure, pack coverage and, for merges, common-base ancestry.
/// This manifest is neither admission evidence nor an authority snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseCandidateManifest<A: GitHashAlgorithm> {
    base_rcr: RepositoryCommitId,
    base_commit: GitOid<A>,
    base_tree: GitOid<A>,
    parents: Vec<GitOid<A>>,
    // A private traversal cursor, never exported as a canonical source receipt.
    content: SparseManifest<A>,
}
impl<A: GitHashAlgorithm> SparseCandidateManifest<A> {
    /// Discover candidate inputs after requiring exactly one parent: the
    /// independently selected base. The existing single-parent contract never
    /// silently accepts a merge; callers must explicitly select build_merge.
    pub fn build<S: ObjectSource<A>>(
        base: &BaseView<A>,
        source: &S,
        candidate: GitOid<A>,
        capability: &mut TreeCapability,
        now: u64,
        parse_limits: ParseLimits,
        limits: SparseLimits,
    ) -> Result<Self, CandidateManifestRefusal> {
        Self::build_bound(
            base,
            source,
            candidate,
            &[*base.base_commit_oid()],
            capability,
            now,
            parse_limits,
            limits,
        )
    }

    /// Discover the ACTUAL two-parent result, not either input branch's tree.
    /// Parent order must be target/base first, then the independently selected
    /// incoming tip. This layer verifies bytes and parent identity only; the
    /// host must prove incoming disclosure and common-base ancestry beforehand.
    /// Input-only host plans retain their ordinary import refusal and lifecycle.
    pub fn build_merge<S: ObjectSource<A>>(
        base: &BaseView<A>,
        source: &S,
        candidate: GitOid<A>,
        incoming: GitOid<A>,
        capability: &mut TreeCapability,
        now: u64,
        parse_limits: ParseLimits,
        limits: SparseLimits,
    ) -> Result<Self, CandidateManifestRefusal> {
        Self::build_bound(
            base,
            source,
            candidate,
            &[*base.base_commit_oid(), incoming],
            capability,
            now,
            parse_limits,
            limits,
        )
    }

    /// Discover the final tree of an explicitly selected linear rebase series.
    /// `commits` is the complete oldest-first rewritten chain, excluding the
    /// independently selected canonical base and including the candidate. Every
    /// supplied native commit is read and its single parent checked; selecting
    /// an already present intermediate commit never truncates this proof.
    ///
    /// The source owner still authenticates both original branches and validates
    /// original-source ancestry, complete intermediate object closures and pack
    /// coverage before calling this constructor. These inputs remain read-only
    /// and retain the canonical target's base RCR, commit and tree separately.
    pub fn build_rebase<S: ObjectSource<A>>(
        base: &BaseView<A>,
        source: &S,
        commits: &[GitOid<A>],
        capability: &mut TreeCapability,
        now: u64,
        parse_limits: ParseLimits,
        limits: SparseLimits,
    ) -> Result<Self, CandidateManifestRefusal> {
        let invalid = CandidateManifestRefusal::InvalidCandidate;
        if capability.repository_id() != base.repository_id() {
            return Err(invalid(
                "rebase capability belongs to a different repository",
            ));
        }
        if commits.is_empty() || commits.len() > 256 {
            return Err(invalid("rebase requires one through 256 rewritten commits"));
        }
        let grant = capability
            .authorize_root(now)
            .map_err(|e| CandidateManifestRefusal::Sparse(SparseRefusal::Capability(e)))?;
        let mut expected_parent = *base.base_commit_oid();
        let mut final_parent = expected_parent;
        let mut total = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        for id in commits {
            if *id == *base.base_commit_oid()
                || id.digest_bytes().iter().all(|byte| *byte == 0)
                || !seen.insert(id.digest_bytes().to_vec())
            {
                return Err(invalid(
                    "rebase commits must be distinct from the target and one another",
                ));
            }
            let body = base
                .read_object(source, id, GitObjectKind::Commit, &grant)
                .map_err(CandidateManifestRefusal::Source)?;
            total = total
                .checked_add(body.len())
                .filter(|length| *length <= 16 * 1024 * 1024)
                .ok_or_else(|| invalid("rebase commit bodies exceed the cumulative budget"))?;
            capability
                .charge_fetch(
                    u64::try_from(body.len()).map_err(|_| invalid("commit length overflow"))?,
                )
                .map_err(|e| CandidateManifestRefusal::Sparse(SparseRefusal::Capability(e)))?;
            let ParsedObject::Commit(commit) = parse_object_body(
                ObjectType::Commit,
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits,
            )
            .map_err(|_| invalid("rebase step is not a bounded native commit"))?
            else {
                return Err(invalid("rebase step is not a commit"));
            };
            if commit
                .headers()
                .iter()
                .filter(|header| header.name == b"tree")
                .count()
                != 1
                || commit.headers().iter().any(|header| {
                    (header.name == b"tree" || header.name == b"parent")
                        && !header.continuations.is_empty()
                })
            {
                return Err(invalid("ambiguous rebase tree or parent headers"));
            }
            let mut parents = commit.parent_references();
            let parent = parents
                .next()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .and_then(|text| A::parse_hex(&text.to_ascii_lowercase()).ok());
            if parent != Some(expected_parent) || parents.next().is_some() {
                return Err(invalid(
                    "rebase step must have the exact preceding single parent",
                ));
            }
            final_parent = expected_parent;
            expected_parent = *id;
        }
        Self::build_bound(
            base,
            source,
            expected_parent,
            &[final_parent],
            capability,
            now,
            parse_limits,
            limits,
        )
    }

    fn build_bound<S: ObjectSource<A>>(
        base: &BaseView<A>,
        source: &S,
        candidate: GitOid<A>,
        expected: &[GitOid<A>],
        capability: &mut TreeCapability,
        now: u64,
        parse_limits: ParseLimits,
        limits: SparseLimits,
    ) -> Result<Self, CandidateManifestRefusal> {
        let invalid = CandidateManifestRefusal::InvalidCandidate;
        let zero = |id: &GitOid<A>| id.digest_bytes().iter().all(|byte| *byte == 0);
        if capability.repository_id() != base.repository_id()
            || zero(&candidate)
            || expected.iter().any(|id| zero(id) || *id == candidate)
            || (expected.len() == 2 && expected[0] == expected[1])
        {
            return Err(invalid(
                "distinct nonzero candidate and selected same-repository parents required",
            ));
        }
        let grant = capability
            .authorize_root(now)
            .map_err(|e| CandidateManifestRefusal::Sparse(SparseRefusal::Capability(e)))?;
        let body = base
            .read_object(source, &candidate, GitObjectKind::Commit, &grant)
            .map_err(CandidateManifestRefusal::Source)?;
        capability
            .charge_fetch(u64::try_from(body.len()).map_err(|_| invalid("commit length overflow"))?)
            .map_err(|e| CandidateManifestRefusal::Sparse(SparseRefusal::Capability(e)))?;
        let ParsedObject::Commit(commit) = parse_object_body(
            ObjectType::Commit,
            &body,
            AcceptanceProfile::GitCompatibleImport,
            &parse_limits,
        )
        .map_err(|_| invalid("candidate is not a bounded native commit"))?
        else {
            return Err(invalid("candidate is not a commit"));
        };
        if commit
            .headers()
            .iter()
            .filter(|h| h.name == b"tree")
            .count()
            != 1
            || commit
                .headers()
                .iter()
                .any(|h| (h.name == b"tree" || h.name == b"parent") && !h.continuations.is_empty())
        {
            return Err(invalid("ambiguous candidate tree or parent headers"));
        }
        let parse = |bytes: &[u8]| {
            let text =
                std::str::from_utf8(bytes).map_err(|_| invalid("invalid native reference"))?;
            A::parse_hex(&text.to_ascii_lowercase())
                .map_err(|_| invalid("invalid native reference"))
        };
        let mut parents = commit.parent_references();
        for expected in expected {
            let actual = parse(
                parents
                    .next()
                    .ok_or_else(|| invalid("candidate parent missing"))?,
            )?;
            if actual != *expected {
                return Err(invalid("candidate parent order or identity differs"));
            }
        }
        if parents.next().is_some() {
            return Err(invalid("candidate has unexpected additional parents"));
        }
        let tree = parse(
            commit
                .tree_reference()
                .ok_or_else(|| invalid("candidate has no tree"))?,
        )?;
        // The traversal cursor is private. Its candidate coordinates never
        // escape as authenticated base provenance, even for a two-parent input.
        let cursor = BaseView::new(
            base.repository_id(),
            base.base_rcr_id(),
            candidate,
            tree,
            parse_limits,
            *base.path_policy(),
        );
        let content = SparseManifest::build(&cursor, source, capability, now, limits)
            .map_err(CandidateManifestRefusal::Sparse)?;
        Ok(Self {
            base_rcr: base.base_rcr_id(),
            base_commit: *base.base_commit_oid(),
            base_tree: *base.base_tree_oid(),
            parents: expected.to_vec(),
            content,
        })
    }
    pub const fn repository_id(&self) -> RepositoryId {
        self.content.receipt().repository_id()
    }
    /// Canonical RCR of the BASE, never a record admitting the candidate.
    pub const fn base_rcr_id(&self) -> RepositoryCommitId {
        self.base_rcr
    }
    pub const fn base_commit_oid(&self) -> &GitOid<A> {
        &self.base_commit
    }
    pub const fn base_tree_oid(&self) -> &GitOid<A> {
        &self.base_tree
    }
    pub const fn candidate_commit_oid(&self) -> &GitOid<A> {
        self.content.receipt().source_commit_oid()
    }
    pub const fn candidate_tree_oid(&self) -> &GitOid<A> {
        self.content.receipt().source_tree_oid()
    }
    /// Verified native order, not parent identities supplied by a report.
    pub fn parents(&self) -> &[GitOid<A>] {
        &self.parents
    }
    pub fn entries(&self) -> &[SparseEntry<A>] {
        self.content.entries()
    }
    pub const fn payload_bytes(&self) -> usize {
        self.content.receipt().payload_bytes()
    }
}
