//! Terminal decisions, Repository Commit Records, and the decision batch that
//! publishes them.
//!
//! `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §5.3, §7, and §8.1 define the three
//! bodies here. Two of their invariants are enforced by construction rather
//! than by a runtime check:
//!
//! * **A sealed transaction appears at most once in a batch.**
//!   [`DecisionBatch`] has no public constructor. The only way to obtain one is
//!   [`DecisionBatchDraft::finish`], and [`DecisionBatchDraft::push`] refuses a
//!   `TxId` the draft already holds. There is therefore no value of type
//!   `DecisionBatch` anywhere in the program that carries two decisions for one
//!   `TxId`. The complementary cross-batch rule — a `TxId` already terminal in
//!   an earlier batch — cannot be decided from the batch alone and is enforced
//!   by [`crate::state::RepositoryState`] against the authenticated outcome
//!   index, which reports it as a typed invariant breach.
//!
//! * **A refusal cannot carry a repository sequence.**
//!   [`fgit_types::vocabulary::DecisionOutcome::Refused`] has nowhere to put
//!   one: the repository sequence lives on [`RepositoryCommitRecord`], which
//!   only a `Committed` outcome names. §8.3 — "refusals consume decision
//!   sequence but do not advance repository sequence" — is a property of the
//!   types, not of a code path that might be missed.

use std::collections::{BTreeMap, BTreeSet};

use fgit_types::hash::Digest;
use fgit_types::identity::{
    PrincipalSnapshotId, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId,
    RepositoryId, TxId,
};
use fgit_types::native::GitOid;
use fgit_types::numeric::{DecisionSequence, HeadGeneration, PolicyEpoch, RepositorySequence};
use fgit_types::vocabulary::DecisionOutcome;

use crate::effect::{NetEffects, RetentionEffect};
use crate::intent::{
    DurabilityProfile, ForgeStreamId, ForgeStreamPosition, OutboxDeliveryKey, RetentionRoot,
};
use fgit_types::refs::RefName;
use crate::state::{InvariantBreach, ModelResult, RepositoryRoots};

/// One terminal decision with the decision sequence it consumed.
///
/// Every terminal decision consumes a decision sequence, refusals included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublishedDecision {
    /// The sealed transaction this decision terminates.
    pub tx_id: TxId,
    /// The decision sequence this decision consumed.
    pub decision_sequence: DecisionSequence,
    /// The terminal outcome.
    pub outcome: DecisionOutcome,
}

impl PublishedDecision {
    /// True when this decision advanced repository sequence.
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        self.outcome.advances_repository_sequence()
    }
}

/// The canonical source and forge mutation record for one committed logical
/// transaction.
///
/// §7 keeps ref effects and their associated forge transitions in **one**
/// record, which is what makes "a pull-request merge cannot become visible
/// without its target ref update" a structural property: both live in
/// [`RepositoryCommitRecord::effects`] or neither does.
///
/// Where §7 names a digest root this model carries the root's *content*. The
/// model's job is to decide what the resulting roots are; binding content to a
/// digest is the canonical codec's job, and FG-003b does it over exactly these
/// values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryCommitRecord {
    /// Identity of this record.
    pub id: RepositoryCommitId,
    /// The repository this record belongs to.
    pub repository: RepositoryId,
    /// Position in the committed-only sequence.
    pub repository_sequence: RepositorySequence,
    /// The previously committed record, absent only for the first commit.
    pub parent: Option<RepositoryCommitId>,
    /// The sealed transaction this record commits.
    pub tx_id: TxId,
    /// The immutable principal and capability snapshot the decision used.
    pub principal_snapshot: PrincipalSnapshotId,
    /// Digest over every client-visible semantic field of the request.
    pub canonical_request_digest: Digest,
    /// The target-disjoint effects this record publishes.
    pub effects: NetEffects,
    /// Ref root after this record applied.
    pub resulting_refs: BTreeMap<RefName, GitOid>,
    /// Forge position root after this record applied.
    pub resulting_forge_positions: BTreeMap<ForgeStreamId, ForgeStreamPosition>,
    /// The exact object closure this record admitted.
    pub object_closure: BTreeSet<GitOid>,
    /// The policy epoch the decision was evaluated against.
    pub policy_epoch: PolicyEpoch,
    /// Retention roots this record added or removed.
    pub retention_delta: BTreeMap<RetentionRoot, RetentionEffect>,
    /// Outbox deliveries this record owes.
    pub outbox_delta: BTreeMap<OutboxDeliveryKey, Digest>,
}

/// An immutable ordered publication body.
///
/// The fields are private because the type's guarantee is about how it was
/// built: see the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionBatch {
    id: RepositoryDecisionBatchId,
    repository: RepositoryId,
    predecessor_head: RepositoryAuthorityHeadId,
    predecessor_generation: HeadGeneration,
    first_decision_sequence: DecisionSequence,
    decisions: Vec<PublishedDecision>,
    committed: Vec<RepositoryCommitRecord>,
    resulting: RepositoryRoots,
    resulting_policy_epoch: PolicyEpoch,
    durability: DurabilityProfile,
}

impl DecisionBatch {
    /// Identity of this batch.
    #[must_use]
    pub const fn id(&self) -> RepositoryDecisionBatchId {
        self.id
    }

    /// The repository this batch publishes into.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// The exact head this batch was staged against.
    #[must_use]
    pub const fn predecessor_head(&self) -> RepositoryAuthorityHeadId {
        self.predecessor_head
    }

    /// The generation of the head this batch was staged against.
    #[must_use]
    pub const fn predecessor_generation(&self) -> HeadGeneration {
        self.predecessor_generation
    }

    /// The decision sequence of the first decision in this batch.
    #[must_use]
    pub const fn first_decision_sequence(&self) -> DecisionSequence {
        self.first_decision_sequence
    }

    /// Every terminal decision, in batch order.
    #[must_use]
    pub fn decisions(&self) -> &[PublishedDecision] {
        &self.decisions
    }

    /// Every committed record, in repository-sequence order.
    #[must_use]
    pub fn committed(&self) -> &[RepositoryCommitRecord] {
        &self.committed
    }

    /// The roots that become canonical when this batch's head CAS wins.
    #[must_use]
    pub const fn resulting(&self) -> &RepositoryRoots {
        &self.resulting
    }

    /// The policy epoch in force after this batch.
    #[must_use]
    pub const fn resulting_policy_epoch(&self) -> PolicyEpoch {
        self.resulting_policy_epoch
    }

    /// The durability profile this batch's publication must satisfy.
    #[must_use]
    pub const fn durability(&self) -> DurabilityProfile {
        self.durability
    }

    /// The decision sequence of the last decision in this batch.
    #[must_use]
    pub fn last_decision_sequence(&self) -> Option<DecisionSequence> {
        self.decisions.last().map(|decision| decision.decision_sequence)
    }

    /// The last committed record's identity and sequence, when the batch
    /// committed anything.
    #[must_use]
    pub fn last_commit(&self) -> Option<(RepositoryCommitId, RepositorySequence)> {
        self.committed
            .last()
            .map(|record| (record.id, record.repository_sequence))
    }

    /// Every sealed transaction this batch terminates.
    pub fn terminated_transactions(&self) -> impl Iterator<Item = TxId> {
        self.decisions.iter().map(|decision| decision.tx_id)
    }
}

/// A batch under construction.
///
/// The draft is the only way to build a [`DecisionBatch`]. It assigns decision
/// and repository sequences itself so neither can be supplied inconsistently,
/// and it refuses a duplicate `TxId` at insertion time.
#[derive(Clone, Debug)]
pub struct DecisionBatchDraft {
    id: RepositoryDecisionBatchId,
    repository: RepositoryId,
    predecessor_head: RepositoryAuthorityHeadId,
    predecessor_generation: HeadGeneration,
    first_decision_sequence: DecisionSequence,
    next_decision_sequence: DecisionSequence,
    next_repository_sequence: RepositorySequence,
    parent_commit: Option<RepositoryCommitId>,
    seen: BTreeSet<TxId>,
    decisions: Vec<PublishedDecision>,
    committed: Vec<RepositoryCommitRecord>,
    durability: DurabilityProfile,
}

/// What a draft assigned to one decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SequenceAssignment {
    /// The decision sequence every terminal decision consumes.
    pub decision_sequence: DecisionSequence,
    /// The repository sequence, present only for a commit.
    pub repository_sequence: Option<RepositorySequence>,
}

/// A committed record without the sequences and parent the draft assigns.
///
/// Preparation produces this; the draft turns it into a
/// [`RepositoryCommitRecord`]. Splitting the two is what stops a caller from
/// choosing its own repository sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitCandidate {
    /// Identity the publisher assigned to the resulting record body.
    pub id: RepositoryCommitId,
    /// The repository this record belongs to.
    pub repository: RepositoryId,
    /// The sealed transaction this record commits.
    pub tx_id: TxId,
    /// The immutable principal and capability snapshot the decision used.
    pub principal_snapshot: PrincipalSnapshotId,
    /// Digest over every client-visible semantic field of the request.
    pub canonical_request_digest: Digest,
    /// The target-disjoint effects this record publishes.
    pub effects: NetEffects,
    /// Ref root after this record applied.
    pub resulting_refs: BTreeMap<RefName, GitOid>,
    /// Forge position root after this record applied.
    pub resulting_forge_positions: BTreeMap<ForgeStreamId, ForgeStreamPosition>,
    /// The exact object closure this record admitted.
    pub object_closure: BTreeSet<GitOid>,
    /// The policy epoch the decision was evaluated against.
    pub policy_epoch: PolicyEpoch,
    /// Retention roots this record added or removed.
    pub retention_delta: BTreeMap<RetentionRoot, RetentionEffect>,
    /// Outbox deliveries this record owes.
    pub outbox_delta: BTreeMap<OutboxDeliveryKey, Digest>,
}

impl DecisionBatchDraft {
    /// Opens a draft against an exact predecessor head.
    ///
    /// `first_decision_sequence` and `next_repository_sequence` are the
    /// successors of the predecessor head's positions; the caller obtains them
    /// from the head rather than choosing them.
    #[must_use]
    pub const fn open(
        id: RepositoryDecisionBatchId,
        repository: RepositoryId,
        predecessor_head: RepositoryAuthorityHeadId,
        predecessor_generation: HeadGeneration,
        first_decision_sequence: DecisionSequence,
        first_repository_sequence: RepositorySequence,
        parent_commit: Option<RepositoryCommitId>,
        durability: DurabilityProfile,
    ) -> Self {
        Self {
            id,
            repository,
            predecessor_head,
            predecessor_generation,
            first_decision_sequence,
            next_decision_sequence: first_decision_sequence,
            next_repository_sequence: first_repository_sequence,
            parent_commit,
            seen: BTreeSet::new(),
            decisions: Vec::new(),
            committed: Vec::new(),
            durability,
        }
    }

    /// True when this draft already holds a decision for `tx_id`.
    #[must_use]
    pub fn holds(&self, tx_id: TxId) -> bool {
        self.seen.contains(&tx_id)
    }

    /// How many decisions the draft holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.decisions.len()
    }

    /// True when the draft holds no decision.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    /// Appends one refusal.
    ///
    /// A refusal consumes decision sequence and leaves repository sequence
    /// untouched. That is not a rule this function applies; it is the only
    /// thing it *can* do, because it never reads `next_repository_sequence`.
    pub fn push_refusal(
        &mut self,
        tx_id: TxId,
        outcome: DecisionOutcome,
    ) -> ModelResult<SequenceAssignment> {
        if outcome.advances_repository_sequence() {
            return Err(Box::new(InvariantBreach::RefusalOutcomeExpected { tx_id }));
        }
        let decision_sequence = self.reserve_decision_sequence(tx_id)?;
        self.decisions.push(PublishedDecision {
            tx_id,
            decision_sequence,
            outcome,
        });
        Ok(SequenceAssignment {
            decision_sequence,
            repository_sequence: None,
        })
    }

    /// Appends one commit, assigning both sequences and the parent link.
    pub fn push_commit(
        &mut self,
        candidate: CommitCandidate,
    ) -> ModelResult<SequenceAssignment> {
        let tx_id = candidate.tx_id;
        let decision_sequence = self.reserve_decision_sequence(tx_id)?;
        let repository_sequence = self.next_repository_sequence;
        self.next_repository_sequence = repository_sequence
            .next()
            .map_err(|_| Box::new(InvariantBreach::SequenceExhausted { kind: "repository" }))?;

        let record = RepositoryCommitRecord {
            id: candidate.id,
            repository: candidate.repository,
            repository_sequence,
            parent: self.parent_commit,
            tx_id,
            principal_snapshot: candidate.principal_snapshot,
            canonical_request_digest: candidate.canonical_request_digest,
            effects: candidate.effects,
            resulting_refs: candidate.resulting_refs,
            resulting_forge_positions: candidate.resulting_forge_positions,
            object_closure: candidate.object_closure,
            policy_epoch: candidate.policy_epoch,
            retention_delta: candidate.retention_delta,
            outbox_delta: candidate.outbox_delta,
        };
        self.parent_commit = Some(record.id);
        self.decisions.push(PublishedDecision {
            tx_id,
            decision_sequence,
            outcome: DecisionOutcome::Committed {
                repository_commit_id: record.id,
            },
        });
        self.committed.push(record);
        Ok(SequenceAssignment {
            decision_sequence,
            repository_sequence: Some(repository_sequence),
        })
    }

    /// Seals the draft into an immutable batch.
    ///
    /// An empty batch is refused: a head transition that publishes nothing
    /// would consume a generation without a decision, which §8.1's gap-free
    /// decision sequence cannot express.
    pub fn finish(
        self,
        resulting: RepositoryRoots,
        resulting_policy_epoch: PolicyEpoch,
    ) -> ModelResult<DecisionBatch> {
        if self.decisions.is_empty() {
            return Err(Box::new(InvariantBreach::EmptyDecisionBatch { batch: self.id }));
        }
        Ok(DecisionBatch {
            id: self.id,
            repository: self.repository,
            predecessor_head: self.predecessor_head,
            predecessor_generation: self.predecessor_generation,
            first_decision_sequence: self.first_decision_sequence,
            decisions: self.decisions,
            committed: self.committed,
            resulting,
            resulting_policy_epoch,
            durability: self.durability,
        })
    }

    fn reserve_decision_sequence(
        &mut self,
        tx_id: TxId,
    ) -> ModelResult<DecisionSequence> {
        if !self.seen.insert(tx_id) {
            return Err(Box::new(InvariantBreach::SecondDecisionInBatch { tx_id }));
        }
        let assigned = self.next_decision_sequence;
        self.next_decision_sequence = assigned
            .next()
            .map_err(|_| Box::new(InvariantBreach::SequenceExhausted { kind: "decision" }))?;
        Ok(assigned)
    }
}
