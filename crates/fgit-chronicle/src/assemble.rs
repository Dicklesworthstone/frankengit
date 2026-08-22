//! The builder that cannot express an ill-formed publication.

use fgit_codec::attest::BodyIdentity;
use fgit_codec::schema::{
    RepositoryAuthorityHeadBody, RepositoryCommitRecord, RepositoryDecision,
    RepositoryDecisionBatchBody,
};
use fgit_types::{
    DecisionOutcome, DecisionSequence, RefusalCode, RefusalRecordId, RepositorySequence, TxId,
};

use std::collections::BTreeSet;

use crate::audit::{batch_identity, repository_commit_identity, verify_pair};
use crate::evidence::derive_batch_evidence_root;
use crate::origin::{PublicationBasis, ResultingRoots};
use crate::refusal::ChronicleRefusal;

/// A publication under construction.
///
/// The plan assigns every sequence position itself. A caller records *that* a
/// transaction was refused or committed and never *where* it lands, so a gap
/// or a repeat is not a rejected input — it is an unrepresentable one.
#[must_use = "a publication plan produces nothing until it is sealed"]
#[derive(Clone, Debug)]
pub struct PublicationPlan {
    basis: PublicationBasis,
    decisions: Vec<PlannedDecision>,
    next_decision: DecisionSequence,
    next_repository: RepositorySequence,
    decided: BTreeSet<TxId>,
    deferred: Option<ChronicleRefusal>,
}

impl PublicationPlan {
    /// Opens a plan against one authenticated predecessor head.
    pub fn open(basis: PublicationBasis) -> Result<Self, ChronicleRefusal> {
        let next_decision = basis.open_decision_sequence()?;
        let next_repository = basis.open_repository_sequence()?;
        Ok(Self {
            basis,
            decisions: Vec::new(),
            next_decision,
            next_repository,
            decided: BTreeSet::new(),
            deferred: None,
        })
    }

    /// The basis this plan is prepared against.
    #[must_use]
    pub const fn basis(&self) -> &PublicationBasis {
        &self.basis
    }

    /// How many terminal decisions the plan holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.decisions.len()
    }

    /// Whether the plan would refuse to seal for want of a decision.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    /// Records a refusal.
    ///
    /// A refusal consumes decision sequence. It takes no commit record, and
    /// there is no method on this path that could give it one.
    pub fn refuse(
        &mut self,
        tx_id: TxId,
        code: RefusalCode,
        refusal_record_id: RefusalRecordId,
    ) -> &mut Self {
        self.claim(tx_id);
        let sequence = self.take_decision_sequence();
        self.decisions.push(PlannedDecision {
            tx_id,
            decision_sequence: sequence,
            outcome: PlannedOutcome::Refused {
                code,
                refusal_record_id,
            },
        });
        self
    }

    /// Records a commit and the record that carries it.
    ///
    /// The plan stamps the record's repository sequence and parent, then
    /// derives its identity from those final bytes while sealing. The caller
    /// therefore cannot associate a pre-stamp identity with the post-stamp
    /// record that the batch actually carries.
    ///
    /// `record` is otherwise taken as given: this crate does not compute roots.
    pub fn commit(&mut self, mut record: RepositoryCommitRecord) -> &mut Self {
        self.claim(record.tx_id);
        let sequence = self.take_decision_sequence();
        let repository_sequence = self.take_repository_sequence();
        record.repository_sequence = repository_sequence;
        self.decisions.push(PlannedDecision {
            tx_id: record.tx_id,
            decision_sequence: sequence,
            outcome: PlannedOutcome::Committed(Box::new(record)),
        });
        self
    }

    /// Builds the batch and its successor head.
    ///
    /// The batch's identity is computed from the batch this call just built,
    /// never accepted from the caller, so the head cannot name somebody else's
    /// batch. That binding is worth enforcing here because `fgit-authority`
    /// does not check it: a head naming the wrong batch would otherwise reach
    /// the conditional replacement and become canonical.
    ///
    /// The result is verified by [`verify_pair`] before it is returned, so the
    /// builder and the total checker can never disagree about what well formed
    /// means.
    pub fn seal<I>(
        self,
        identity: &I,
        roots: ResultingRoots,
    ) -> Result<VerifiedPublication, ChronicleRefusal>
    where
        I: BodyIdentity + ?Sized,
    {
        if let Some(refusal) = self.deferred {
            return Err(refusal);
        }
        if self.decisions.is_empty() {
            return Err(ChronicleRefusal::EmptyBatch);
        }
        let previous = self.basis.body();
        let first_decision_sequence = self.basis.open_decision_sequence()?;
        let tail = self
            .decisions
            .last()
            .map(|decision| decision.decision_sequence)
            .ok_or(ChronicleRefusal::EmptyBatch)?;
        let mut parent_rcr = previous.latest_committed_rcr_id;
        let mut committed_rcrs = Vec::with_capacity(self.decisions.len());
        let mut decisions = Vec::with_capacity(self.decisions.len());
        for planned in self.decisions {
            let outcome = match planned.outcome {
                PlannedOutcome::Refused {
                    code,
                    refusal_record_id,
                } => DecisionOutcome::Refused {
                    code,
                    refusal_record_id,
                },
                PlannedOutcome::Committed(record) => {
                    let mut record = *record;
                    record.parent_rcr_id = parent_rcr;
                    let repository_commit_id = repository_commit_identity(identity, &record)?;
                    parent_rcr = Some(repository_commit_id);
                    committed_rcrs.push(record);
                    DecisionOutcome::Committed {
                        repository_commit_id,
                    }
                }
            };
            decisions.push(RepositoryDecision {
                tx_id: planned.tx_id,
                decision_sequence: planned.decision_sequence,
                outcome,
            });
        }
        let latest_repository_sequence = committed_rcrs
            .last()
            .map_or(previous.latest_repository_sequence, |record| {
                Some(record.repository_sequence)
            });

        let batch_evidence_root = derive_batch_evidence_root(&decisions, &committed_rcrs)?;
        let batch = RepositoryDecisionBatchBody {
            repository_id: previous.repository_id,
            predecessor_head_id: self.basis.id(),
            predecessor_head_generation: self.basis.generation(),
            first_decision_sequence,
            decisions,
            committed_rcrs,
            resulting_ref_root: roots.ref_root,
            resulting_forge_position_root: roots.forge_position_root,
            resulting_outcome_index_root: roots.outcome_index_root,
            resulting_retention_root: roots.retention_root,
            resulting_outbox_root: roots.outbox_root,
            resulting_policy_epoch: roots.policy_epoch,
            batch_evidence_root,
            compaction_generation_link: roots.compaction_generation_link,
        };

        let batch_id = batch_identity(identity, &batch)?;

        let head = RepositoryAuthorityHeadBody {
            repository_id: previous.repository_id,
            generation: self.basis.successor_generation()?,
            predecessor_head_id: Some(self.basis.id()),
            decision_tail_id: Some(batch_id),
            latest_decision_sequence: Some(tail),
            latest_committed_rcr_id: parent_rcr,
            latest_repository_sequence,
            ref_root: roots.ref_root,
            forge_position_root: roots.forge_position_root,
            outcome_index_root: roots.outcome_index_root,
            retention_root: roots.retention_root,
            outbox_root: roots.outbox_root,
            configuration_root: previous.configuration_root,
            policy_epoch: roots.policy_epoch,
            format_registry_epoch: previous.format_registry_epoch,
            last_checkpoint_id: previous.last_checkpoint_id,
        };

        verify_pair(identity, &self.basis, &batch, &head)?;
        Ok(VerifiedPublication {
            basis: self.basis,
            batch,
            head,
        })
    }

    /// Records the first refusal seen while building; later ones do not
    /// overwrite it, because the first is the one that explains the rest.
    const fn note(&mut self, refusal: ChronicleRefusal) {
        if self.deferred.is_none() {
            self.deferred = Some(refusal);
        }
    }

    /// Claims a transaction for this batch, refusing a second decision.
    ///
    /// Checked on the building path rather than only at seal so that the
    /// index in the refusal names the decision that collided.
    fn claim(&mut self, tx_id: TxId) {
        if !self.decided.insert(tx_id) {
            let index = self.decisions.len();
            self.note(ChronicleRefusal::DuplicateTransaction { index });
        }
    }

    fn take_decision_sequence(&mut self) -> DecisionSequence {
        let current = self.next_decision;
        match current.next() {
            Ok(next) => self.next_decision = next,
            Err(_) => {
                self.note(ChronicleRefusal::SequenceExhausted {
                    counter: "decision sequence",
                });
            }
        }
        current
    }

    fn take_repository_sequence(&mut self) -> RepositorySequence {
        let current = self.next_repository;
        match current.next() {
            Ok(next) => self.next_repository = next,
            Err(_) => {
                self.note(ChronicleRefusal::SequenceExhausted {
                    counter: "repository sequence",
                });
            }
        }
        current
    }
}

/// A terminal decision before an RCR has final bytes and therefore an identity.
#[derive(Clone, Debug)]
struct PlannedDecision {
    tx_id: TxId,
    decision_sequence: DecisionSequence,
    outcome: PlannedOutcome,
}

/// The outcome shape known while the plan is still mutable.
#[derive(Clone, Debug)]
enum PlannedOutcome {
    Refused {
        code: RefusalCode,
        refusal_record_id: RefusalRecordId,
    },
    Committed(Box<RepositoryCommitRecord>),
}

/// A batch and head pair that passed every chronicle invariant.
///
/// Holding one is the evidence a publisher needs; it cannot be constructed
/// except by sealing a plan, so a caller cannot fabricate the claim.
#[must_use = "a verified publication is evidence; publish it or drop the attempt deliberately"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPublication {
    basis: PublicationBasis,
    batch: RepositoryDecisionBatchBody,
    head: RepositoryAuthorityHeadBody,
}

impl VerifiedPublication {
    /// The basis this publication succeeds.
    #[must_use]
    pub const fn basis(&self) -> &PublicationBasis {
        &self.basis
    }

    /// The decision batch to stage.
    #[must_use]
    pub const fn batch(&self) -> &RepositoryDecisionBatchBody {
        &self.batch
    }

    /// The successor head to propose.
    #[must_use]
    pub const fn head(&self) -> &RepositoryAuthorityHeadBody {
        &self.head
    }

    /// Whether this publication commits anything.
    ///
    /// A refusal-only publication advances the decision sequence and leaves
    /// every committed root where it was.
    #[must_use]
    pub const fn is_refusal_only(&self) -> bool {
        self.batch.committed_rcrs.is_empty()
    }
}
