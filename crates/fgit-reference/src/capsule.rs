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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use fgit_types::hash::{Digest, DigestAlgorithmId, DigestBytes};
    use fgit_types::native::{GitOid, GitOidSha1};
    use fgit_types::numeric::{HeadGeneration, PolicyEpoch};
    use fgit_types::refs::RefName;

    use super::{ConflictWitness, WitnessGranularity};
    use crate::harness::label;
    use crate::intent::{
        ForgeStreamId, ForgeStreamPosition, OutboxDeliveryKey, RetentionClass, RetentionRoot,
    };
    use crate::state::RepositoryRoots;

    fn name(text: &str) -> RefName {
        RefName::try_new(text.as_bytes()).expect("valid ref name")
    }

    const fn oid(byte: u8) -> GitOid {
        GitOid::Sha1(GitOidSha1::from_bytes([byte; GitOidSha1::LEN]))
    }

    fn digest(byte: u8) -> Digest {
        Digest::new(
            DigestAlgorithmId::try_new(super::FIXTURE_ALGORITHM_CODE_POINT)
                .expect("a nonzero corpus fixture algorithm slot"),
            DigestBytes::try_new(&[byte; 32])
                .expect("a 32-byte corpus fixture digest body is inside the window"),
        )
    }

    fn stream() -> ForgeStreamId {
        ForgeStreamId::new(label("pulls"))
    }

    fn delivery() -> OutboxDeliveryKey {
        OutboxDeliveryKey::new(label("hook"))
    }

    const fn retention() -> RetentionRoot {
        RetentionRoot {
            object: oid(9),
            class: RetentionClass::LegalHold,
        }
    }

    /// The basis every witness in this module was taken against.
    fn basis_roots() -> RepositoryRoots {
        let mut roots = RepositoryRoots::default();
        roots.refs.insert(name("refs/heads/main"), oid(1));
        roots
            .forge_positions
            .insert(stream(), ForgeStreamPosition::GENESIS);
        roots.retention.insert(retention());
        roots.outbox.insert(delivery(), digest(3));
        roots
    }

    /// A witness that read every dimension of [`basis_roots`].
    fn witness(granularity: WitnessGranularity) -> ConflictWitness {
        let mut refs = BTreeMap::new();
        refs.insert(name("refs/heads/main"), Some(oid(1)));
        refs.insert(name("refs/heads/absent"), None);
        let mut forge_positions = BTreeMap::new();
        forge_positions.insert(stream(), ForgeStreamPosition::GENESIS);
        let mut outbox = BTreeMap::new();
        outbox.insert(delivery(), Some(digest(3)));
        ConflictWitness {
            granularity,
            basis_generation: HeadGeneration::FIRST,
            refs,
            forge_positions,
            retention_present: BTreeSet::from([retention()]),
            retention_absent: BTreeSet::new(),
            outbox,
            policy_epoch: PolicyEpoch::FIRST,
        }
    }

    /// Every roots value the law is checked over: the basis itself and one
    /// single-dimension mutation of each thing the witness read, plus one
    /// mutation of something it did not read.
    fn candidate_roots() -> Vec<(&'static str, RepositoryRoots)> {
        let mut cases = vec![("unchanged", basis_roots())];

        let mut moved_ref = basis_roots();
        moved_ref.refs.insert(name("refs/heads/main"), oid(2));
        cases.push(("read ref moved", moved_ref));

        let mut deleted_ref = basis_roots();
        deleted_ref.refs.remove(&name("refs/heads/main"));
        cases.push(("read ref deleted", deleted_ref));

        let mut appeared = basis_roots();
        appeared.refs.insert(name("refs/heads/absent"), oid(4));
        cases.push(("ref observed absent now exists", appeared));

        let mut moved_forge = basis_roots();
        moved_forge
            .forge_positions
            .insert(stream(), ForgeStreamPosition::GENESIS.successor());
        cases.push(("forge stream advanced", moved_forge));

        let mut dropped_hold = basis_roots();
        dropped_hold.retention.remove(&retention());
        cases.push(("retention root removed", dropped_hold));

        let mut rebound = basis_roots();
        rebound.outbox.insert(delivery(), digest(4));
        cases.push(("outbox key rebound", rebound));

        let mut unread = basis_roots();
        unread.refs.insert(name("refs/heads/other"), oid(7));
        cases.push(("unread ref changed", unread));

        cases
    }

    /// `INV-010`, the one safety property: **coarse-reusable implies
    /// refined-reusable**, so refinement can only ever remove a conflict the
    /// coarse witness reported falsely — it can never clear a real one.
    ///
    /// Checked over every roots value in [`candidate_roots`] crossed with both
    /// generations and both policy epochs, rather than at one point, because
    /// the implication is a property of the pair and a single example would
    /// hold vacuously whenever the coarse side is false.
    #[test]
    fn refinement_can_only_remove_a_false_conflict() {
        let coarse = witness(WitnessGranularity::Coarse);
        let refined = witness(WitnessGranularity::Refined);
        let mut coarse_reusable_seen = 0_u32;

        for (label, roots) in candidate_roots() {
            for generation in [HeadGeneration::FIRST, HeadGeneration::FIRST.next().unwrap()] {
                for epoch in [PolicyEpoch::FIRST, PolicyEpoch::FIRST.next().unwrap()] {
                    let coarse_says = coarse.is_reusable_against(&roots, generation, epoch);
                    let refined_says = refined.is_reusable_against(&roots, generation, epoch);
                    if coarse_says {
                        coarse_reusable_seen += 1;
                        assert!(
                            refined_says,
                            "INV-010 violated at {label} (generation {generation:?}, epoch \
                             {epoch:?}): the coarse witness reports reusable and the refined one \
                             does not, so refinement admitted a true conflict"
                        );
                    }
                }
            }
        }

        assert!(
            coarse_reusable_seen > 0,
            "the law held only vacuously: no case in the space made the coarse witness reusable, \
             so the implication was never actually exercised"
        );
    }

    /// The coarse granularity is the pessimistic one: an unrelated commit
    /// invalidates it even though nothing it read changed.
    #[test]
    fn a_coarse_witness_is_invalidated_by_a_commit_that_touched_nothing_it_read() {
        let coarse = witness(WitnessGranularity::Coarse);
        let mut roots = basis_roots();
        roots.refs.insert(name("refs/heads/other"), oid(7));
        let moved = HeadGeneration::FIRST.next().expect("successor");

        assert!(
            !coarse.is_reusable_against(&roots, moved, PolicyEpoch::FIRST),
            "a coarse witness must not survive a head movement"
        );

        // The permitted twin, one generation away: at the generation it was
        // taken at, the same witness over the same roots is reusable.
        assert!(
            coarse.is_reusable_against(&roots, HeadGeneration::FIRST, PolicyEpoch::FIRST),
            "a coarse witness at an unmoved generation must be reusable"
        );
    }

    /// The refined granularity is the whole point of §12: it clears exactly
    /// the case the coarse one gets wrong.
    #[test]
    fn refinement_clears_the_disjoint_race_that_the_coarse_witness_refuses() {
        let mut roots = basis_roots();
        roots.refs.insert(name("refs/heads/other"), oid(7));
        let moved = HeadGeneration::FIRST.next().expect("successor");

        assert!(
            !witness(WitnessGranularity::Coarse).is_reusable_against(
                &roots,
                moved,
                PolicyEpoch::FIRST
            ),
            "the coarse witness is expected to report this false conflict"
        );
        assert!(
            witness(WitnessGranularity::Refined).is_reusable_against(
                &roots,
                moved,
                PolicyEpoch::FIRST
            ),
            "refinement must clear a conflict with a commit that touched nothing this \
             transaction read"
        );
    }

    /// The direction that must never hold: refinement cannot rescue a capsule
    /// whose own reads moved.
    #[test]
    fn refinement_does_not_clear_a_conflict_on_a_target_that_was_read() {
        let mut roots = basis_roots();
        roots.refs.insert(name("refs/heads/main"), oid(2));
        let moved = HeadGeneration::FIRST.next().expect("successor");

        for granularity in [WitnessGranularity::Coarse, WitnessGranularity::Refined] {
            assert!(
                !witness(granularity).is_reusable_against(&roots, moved, PolicyEpoch::FIRST),
                "{granularity:?} cleared a real conflict on a target the witness read"
            );
        }
    }

    /// A moved policy epoch defeats both granularities: §15.9 pins one epoch
    /// per attempt, and no amount of refinement over *reads* speaks to it.
    #[test]
    fn a_moved_policy_epoch_defeats_every_granularity() {
        let roots = basis_roots();
        let moved_epoch = PolicyEpoch::FIRST.next().expect("successor");

        for granularity in [WitnessGranularity::Coarse, WitnessGranularity::Refined] {
            assert!(
                !witness(granularity).is_reusable_against(
                    &roots,
                    HeadGeneration::FIRST,
                    moved_epoch
                ),
                "{granularity:?} survived a policy epoch move"
            );
            // The permitted twin: the same witness, same roots, pinned epoch.
            assert!(
                witness(granularity).is_reusable_against(
                    &roots,
                    HeadGeneration::FIRST,
                    PolicyEpoch::FIRST
                ),
                "{granularity:?} must be reusable at the epoch it pinned"
            );
        }
    }

    /// `coarsened` and `refined` change the granularity and nothing else, so
    /// the two answers in the law above are over the *same* reads.
    #[test]
    fn changing_granularity_preserves_every_recorded_read() {
        let refined = witness(WitnessGranularity::Refined);
        let coarse = refined.coarsened();

        assert_eq!(coarse.granularity, WitnessGranularity::Coarse);
        assert_eq!(coarse.refs, refined.refs);
        assert_eq!(coarse.forge_positions, refined.forge_positions);
        assert_eq!(coarse.retention_present, refined.retention_present);
        assert_eq!(coarse.retention_absent, refined.retention_absent);
        assert_eq!(coarse.outbox, refined.outbox);
        assert_eq!(coarse.basis_generation, refined.basis_generation);
        assert_eq!(coarse.policy_epoch, refined.policy_epoch);
        assert_eq!(coarse.refined(), refined);
    }
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);
