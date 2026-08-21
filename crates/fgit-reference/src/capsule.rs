//! Prepared transaction capsules and conflict witnesses.
//!
//! §6: validation emits an immutable capsule against **one** authority-head
//! basis, and "the capsule MUST bind all inputs needed to decide whether it
//! remains reusable after a lost CAS. It cannot authorize publication by
//! itself." Both halves are structural here. A capsule carries its basis head
//! identity and generation and a [`ConflictWitness`] over everything it read;
//! it carries a [`PreparedVerdict`], never a decision sequence, a repository
//! sequence, or a head — the things that would let it publish.
//!
//! ## Witness refinement can only remove false conflicts
//!
//! §12 and invariant `INV-010`. A [`ConflictWitness`] has two granularities
//! over the same reads:
//!
//! * [`WitnessGranularity::Coarse`] asks only whether the basis head
//!   generation is unchanged. It is always safe and frequently pessimistic:
//!   any concurrent commit invalidates it, including one that touched nothing
//!   this transaction read.
//! * [`WitnessGranularity::Refined`] compares the exact values that were read.
//!
//! The safety property is that refinement never *creates* reusability where
//! the truth is a conflict — every target the transaction read is compared
//! individually, so a refined witness that reports reusable has checked strictly
//! more than the generation check would have concluded. The direction that
//! matters is checkable and is asserted in the crate's tests: whenever the
//! coarse witness reports reusable, the refined one must agree, because an
//! unchanged head cannot have changed any target.

use std::collections::{BTreeMap, BTreeSet};

use fgit_types::hash::Digest;
use fgit_types::identity::{
    PreparationProfileId, PreparedTxnCapsuleId, PrincipalSnapshotId, RepositoryAuthorityHeadId,
    RepositoryCommitId, TransactionSealId, TxId,
};
use fgit_types::native::GitOid;
use fgit_types::numeric::{HeadGeneration, PolicyEpoch};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::RefusalCode;

use crate::effect::{IntentMapping, NetEffects};
use crate::intent::{
    DurabilityProfile, ForgeStreamId, ForgeStreamPosition, OutboxDeliveryKey, RetentionRoot,
};
use crate::state::RepositoryRoots;

/// How precisely a witness describes what a transaction read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WitnessGranularity {
    /// Only "the basis head generation is unchanged".
    Coarse,
    /// The exact value of every target that was read.
    Refined,
}

/// Everything one preparation read from the basis.
///
/// A witness records values, not merely the fact that a read happened, so
/// reusability after a lost compare-and-exchange is decided by comparing the
/// recorded value against the new head rather than by trusting a version
/// number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictWitness {
    /// Granularity this witness is evaluated at.
    pub granularity: WitnessGranularity,
    /// The head generation the reads were taken at.
    pub basis_generation: HeadGeneration,
    /// Ref values observed. `None` records "this ref was absent".
    pub refs: BTreeMap<RefName, Option<GitOid>>,
    /// Forge stream positions observed.
    pub forge_positions: BTreeMap<ForgeStreamId, ForgeStreamPosition>,
    /// Retention roots observed present.
    pub retention_present: BTreeSet<RetentionRoot>,
    /// Retention roots observed absent.
    pub retention_absent: BTreeSet<RetentionRoot>,
    /// Outbox bindings observed. `None` records "this key was unbound".
    pub outbox: BTreeMap<OutboxDeliveryKey, Option<Digest>>,
    /// The policy epoch the decision was evaluated against.
    pub policy_epoch: PolicyEpoch,
}

impl ConflictWitness {
    /// True when every recorded read still holds against `roots`.
    ///
    /// The coarse granularity ignores `roots` entirely and answers from the
    /// generation alone, which is exactly what makes it conservative.
    #[must_use]
    pub fn is_reusable_against(
        &self,
        roots: &RepositoryRoots,
        generation: HeadGeneration,
        policy_epoch: PolicyEpoch,
    ) -> bool {
        if self.policy_epoch != policy_epoch {
            return false;
        }
        // The coarse answer is the refined one *conjoined* with "the head has
        // not moved". Expressing it that way is what makes the safety property
        // hold by construction: coarse-reusable implies refined-reusable, so
        // refinement can only ever remove a false conflict (`INV-010`), never
        // admit a true one.
        match self.granularity {
            WitnessGranularity::Coarse => {
                self.basis_generation == generation && self.refined_reads_hold(roots)
            }
            WitnessGranularity::Refined => self.refined_reads_hold(roots),
        }
    }

    /// The refined comparison, exposed so a test can check it against the
    /// coarse answer without constructing two witnesses.
    #[must_use]
    pub fn refined_reads_hold(&self, roots: &RepositoryRoots) -> bool {
        let refs_hold = self
            .refs
            .iter()
            .all(|(name, observed)| roots.refs.get(name).copied() == *observed);
        let forge_holds = self.forge_positions.iter().all(|(stream, observed)| {
            roots
                .forge_positions
                .get(stream)
                .copied()
                .unwrap_or(ForgeStreamPosition::GENESIS)
                == *observed
        });
        let present_holds = self
            .retention_present
            .iter()
            .all(|root| roots.retention.contains(root));
        let absent_holds = self
            .retention_absent
            .iter()
            .all(|root| !roots.retention.contains(root));
        let outbox_holds = self
            .outbox
            .iter()
            .all(|(key, observed)| roots.outbox.get(key).copied() == *observed);
        refs_hold && forge_holds && present_holds && absent_holds && outbox_holds
    }

    /// The same reads, described at the coarse granularity.
    #[must_use]
    pub fn coarsened(&self) -> Self {
        Self {
            granularity: WitnessGranularity::Coarse,
            ..self.clone()
        }
    }

    /// The same reads, described at the refined granularity.
    #[must_use]
    pub fn refined(&self) -> Self {
        Self {
            granularity: WitnessGranularity::Refined,
            ..self.clone()
        }
    }
}

/// What preparation concluded, before any sequence or head exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreparedVerdict {
    /// The transaction should commit these target-disjoint effects.
    ///
    /// The effects are relative to the basis. The resulting roots are *not*
    /// here: they depend on which other transactions share the batch, and
    /// §10 step 14 computes them by executing candidates sequentially on
    /// scratch state.
    Commit(NetEffects),
    /// The transaction should be refused with this terminal code.
    Refuse(RefusalCode),
}

impl PreparedVerdict {
    /// True when this verdict would advance repository sequence.
    #[must_use]
    pub const fn is_commit(&self) -> bool {
        matches!(self, Self::Commit(_))
    }

    /// The refusal code, when the verdict is a refusal.
    #[must_use]
    pub const fn refusal_code(&self) -> Option<RefusalCode> {
        match self {
            Self::Refuse(code) => Some(*code),
            Self::Commit(_) => None,
        }
    }
}

/// Immutable validation, policy, and effect evidence against one basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTxnCapsule {
    /// Identity of this capsule body.
    pub id: PreparedTxnCapsuleId,
    /// The sealed transaction this capsule prepares.
    pub tx_id: TxId,
    /// The seal that fixed the transaction's identity.
    pub seal_id: TransactionSealId,
    /// The exact head this preparation read.
    pub basis_head: RepositoryAuthorityHeadId,
    /// That head's generation.
    pub basis_generation: HeadGeneration,
    /// The most recent committed record at the basis, if any.
    pub basis_rcr: Option<RepositoryCommitId>,
    /// The immutable principal and capability snapshot policy was evaluated
    /// against.
    pub principal_snapshot: PrincipalSnapshotId,
    /// Digest over every client-visible semantic field of the request.
    pub canonical_request_digest: Digest,
    /// One entry per source intent: plan §15.4's total intent map.
    pub intent_map: Vec<IntentMapping>,
    /// The exact object closure preparation validated.
    pub object_closure: BTreeSet<GitOid>,
    /// Everything preparation read.
    pub witness: ConflictWitness,
    /// What preparation concluded.
    pub verdict: PreparedVerdict,
    /// The durability profile this transaction's publication must satisfy.
    pub durability: DurabilityProfile,
    /// Which preparation implementation produced this capsule.
    pub profile: PreparationProfileId,
}

impl PreparedTxnCapsule {
    /// True when this capsule may still be used against the given head state.
    ///
    /// A capsule prepared against a head that is still current is trivially
    /// reusable. A capsule prepared against a superseded head is reusable only
    /// when its witness proves every input it read is unchanged — §6's "all
    /// inputs needed to decide whether it remains reusable after a lost CAS".
    #[must_use]
    pub fn is_reusable_against(
        &self,
        head: RepositoryAuthorityHeadId,
        generation: HeadGeneration,
        roots: &RepositoryRoots,
        policy_epoch: PolicyEpoch,
    ) -> bool {
        if self.basis_head == head {
            return true;
        }
        self.witness
            .is_reusable_against(roots, generation, policy_epoch)
    }

    /// The refusal this capsule would produce, when it is a refusal.
    #[must_use]
    pub const fn refusal_code(&self) -> Option<RefusalCode> {
        self.verdict.refusal_code()
    }

    /// The effects this capsule would publish, when it is a commit.
    #[must_use]
    pub const fn effects(&self) -> Option<&NetEffects> {
        match &self.verdict {
            PreparedVerdict::Commit(effects) => Some(effects),
            PreparedVerdict::Refuse(_) => None,
        }
    }
}
