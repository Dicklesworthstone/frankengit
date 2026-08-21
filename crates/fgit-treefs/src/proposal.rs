//! The proposed repository transaction a workspace may offer.
//!
//! `docs/GIT_TREE_FS.md` §6, AGENTS.md §5.1 and §5.3.
//!
//! # The whole point of this type
//!
//! A workspace **never gains publication authority**. It can compute objects
//! and it can describe what it would like a ref to become — that is all. Only a
//! successful conditional replacement of the exact predecessor
//! `RepositoryAuthorityHead` publishes repository state, and that happens in
//! the authority layer, not here.
//!
//! So [`ProposedTransaction`] is deliberately inert. It has:
//!
//! * no method that writes an object, moves a ref, or produces an authority
//!   head;
//! * no field that could be mistaken for a decision, an outcome, or a commit;
//! * an explicit [`ProposedTransaction::outcome`] that always refuses, because
//!   a proposal's outcome is not knowable from the proposal.
//!
//! # Object existence is not commit
//!
//! The plan's objects may already exist in a store — staged by this export, or
//! by an earlier one, or by an unrelated push. None of that implies the
//! proposal was accepted. Inferring commit from object existence is exactly
//! what AGENTS.md §5.1 forbids, and [`ProposalRefusal::ExistenceIsNotCommit`]
//! exists so the attempt has a name.

use crate::capability::WorkspaceId;
use crate::export::ExportPlan;
use crate::path::TreePath;
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{GitHashAlgorithm, GitOid, NativeObjectIdentity};
use fgit_types::{RepositoryCommitId, RepositoryId};

/// What the proposer asserts the ref currently holds.
///
/// The precondition travels with the proposal so the authority layer can
/// evaluate it against the real basis. A proposal that declines to state one
/// is not accepted: an unconditional ref move is how concurrent work is lost.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedRef<A: GitHashAlgorithm> {
    /// The ref must not exist.
    Absent,
    /// The ref must hold exactly this object.
    Exactly {
        /// The asserted current value.
        oid: GitOid<A>,
    },
}

/// One typed ref intent in a proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedRefIntent<A: GitHashAlgorithm> {
    /// The fully qualified ref name bytes.
    pub name: Vec<u8>,
    /// What the proposer asserts about the basis.
    pub expected: ExpectedRef<A>,
    /// The object the proposer would like the ref to hold.
    pub new: GitOid<A>,
}

/// The source-span receipt tying an exported path back to its lineage.
///
/// `docs/GIT_TREE_FS.md` §12: a span shown to an agent and the patch that edits
/// it must reference the same lineage, so review comments and workspace files
/// cannot drift into unrelated revisions undetected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PositionReceipt<A: GitHashAlgorithm> {
    /// The repository this proposal targets.
    pub repository_id: RepositoryId,
    /// The canonical RCR the workspace was pinned to.
    pub base_rcr_id: RepositoryCommitId,
    /// The base tree the workspace read.
    pub base_tree_oid: GitOid<A>,
    /// The root tree the export proposes.
    pub proposed_tree_oid: GitOid<A>,
    /// Every path the overlay touched, in canonical order.
    pub touched_paths: Vec<TreePath>,
}

/// Why a proposal was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalRefusal {
    /// A caller tried to read a commit outcome from a proposal.
    OutcomeNotKnowable,
    /// A caller tried to infer commit from the existence of objects.
    ExistenceIsNotCommit,
    /// The proposal names a tree the plan does not contain.
    TreeNotInPlan,
    /// A ref intent carried no precondition.
    MissingPrecondition {
        /// The ref name bytes.
        name: Vec<u8>,
    },
    /// Two intents target the same ref, so the proposal is not target-disjoint.
    DuplicateRefTarget {
        /// The contested ref name bytes.
        name: Vec<u8>,
    },
    /// The proposal carries no intent at all.
    Empty,
}

impl Display for ProposalRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutcomeNotKnowable => write!(
                formatter,
                "a proposal has no outcome: only the authority layer decides"
            ),
            Self::ExistenceIsNotCommit => write!(
                formatter,
                "objects existing does not mean the proposal was accepted"
            ),
            Self::TreeNotInPlan => {
                write!(formatter, "the proposed tree is not present in the plan")
            }
            Self::MissingPrecondition { name } => write!(
                formatter,
                "ref {} carries no precondition",
                String::from_utf8_lossy(name)
            ),
            Self::DuplicateRefTarget { name } => write!(
                formatter,
                "ref {} is targeted twice; a proposal must be target-disjoint",
                String::from_utf8_lossy(name)
            ),
            Self::Empty => write!(formatter, "a proposal must carry at least one intent"),
        }
    }
}

impl core::error::Error for ProposalRefusal {}

/// An inert, sealed proposal.
///
/// Construction is the only way to obtain one, construction validates, and
/// nothing about the value can be mutated afterwards. Handing one to the
/// transaction layer is the *only* thing a holder can do with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedTransaction<A: GitHashAlgorithm> {
    workspace_id: WorkspaceId,
    receipt: PositionReceipt<A>,
    ref_intents: Vec<ProposedRefIntent<A>>,
    object_count: usize,
}

impl<A: GitHashAlgorithm> ProposedTransaction<A> {
    /// Seals a proposal over an export plan.
    ///
    /// Validates that the proposed tree is actually in the plan, that every ref
    /// intent carries a precondition, and that no two intents target one ref.
    /// A proposal that fails any of those is not built at all rather than built
    /// and flagged.
    pub fn seal(
        workspace_id: WorkspaceId,
        plan: &ExportPlan<A>,
        receipt: PositionReceipt<A>,
        ref_intents: Vec<ProposedRefIntent<A>>,
    ) -> Result<Self, ProposalRefusal> {
        if ref_intents.is_empty() {
            return Err(ProposalRefusal::Empty);
        }
        if &receipt.proposed_tree_oid != plan.root_tree()
            || plan.get(&receipt.proposed_tree_oid).is_none()
        {
            return Err(ProposalRefusal::TreeNotInPlan);
        }

        let mut seen: Vec<&[u8]> = Vec::with_capacity(ref_intents.len());
        for intent in &ref_intents {
            if intent.name.is_empty() {
                return Err(ProposalRefusal::MissingPrecondition {
                    name: intent.name.clone(),
                });
            }
            if seen.contains(&intent.name.as_slice()) {
                return Err(ProposalRefusal::DuplicateRefTarget {
                    name: intent.name.clone(),
                });
            }
            seen.push(intent.name.as_slice());
        }

        Ok(Self {
            workspace_id,
            receipt,
            ref_intents,
            object_count: plan.object_count(),
        })
    }

    /// The workspace that produced this proposal.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// The position receipt.
    #[must_use]
    pub const fn receipt(&self) -> &PositionReceipt<A> {
        &self.receipt
    }

    /// The typed ref intents, in source order.
    #[must_use]
    pub fn ref_intents(&self) -> &[ProposedRefIntent<A>] {
        &self.ref_intents
    }

    /// How many objects the export would contribute.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.object_count
    }

    /// The outcome of this proposal.
    ///
    /// Always a refusal, deliberately. A proposal has no outcome; asking for
    /// one is a category error, and a method that could ever answer would be
    /// the seam through which a workspace starts believing it published
    /// something.
    pub const fn outcome(&self) -> Result<core::convert::Infallible, ProposalRefusal> {
        Err(ProposalRefusal::OutcomeNotKnowable)
    }

    /// Whether the presence of this proposal's objects in a store means it was
    /// accepted.
    ///
    /// Always a refusal. Objects may exist because this export staged them,
    /// because an earlier attempt did, or because an unrelated push did.
    pub const fn commit_from_object_existence(
        &self,
    ) -> Result<core::convert::Infallible, ProposalRefusal> {
        Err(ProposalRefusal::ExistenceIsNotCommit)
    }

    /// The canonical bytes a peer would digest to identify this proposal.
    ///
    /// Length-prefixed and field-ordered so two proposals differing anywhere
    /// differ here. This identifies a *request*, never a decision.
    #[must_use]
    pub fn canonical_request_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(b"frankengit.treefs.proposal.v1\0");
        out.extend_from_slice(self.workspace_id.as_bytes());
        out.extend_from_slice(self.receipt.repository_id.as_bytes());
        let tree = self.receipt.proposed_tree_oid.digest_bytes();
        out.extend_from_slice(&(tree.len() as u64).to_be_bytes());
        out.extend_from_slice(tree);
        let base = self.receipt.base_tree_oid.digest_bytes();
        out.extend_from_slice(&(base.len() as u64).to_be_bytes());
        out.extend_from_slice(base);
        out.extend_from_slice(&(self.ref_intents.len() as u64).to_be_bytes());
        for intent in &self.ref_intents {
            out.extend_from_slice(&(intent.name.len() as u64).to_be_bytes());
            out.extend_from_slice(&intent.name);
            match &intent.expected {
                ExpectedRef::Absent => out.push(0),
                ExpectedRef::Exactly { oid } => {
                    out.push(1);
                    let bytes = oid.digest_bytes();
                    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
                    out.extend_from_slice(bytes);
                }
            }
            let new = intent.new.digest_bytes();
            out.extend_from_slice(&(new.len() as u64).to_be_bytes());
            out.extend_from_slice(new);
        }
        out.extend_from_slice(&(self.receipt.touched_paths.len() as u64).to_be_bytes());
        for path in &self.receipt.touched_paths {
            out.extend_from_slice(&(path.as_bytes().len() as u64).to_be_bytes());
            out.extend_from_slice(path.as_bytes());
        }
        out
    }
}
