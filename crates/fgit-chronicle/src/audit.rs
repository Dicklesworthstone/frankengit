//! Total verification of a batch and head pair that arrives as data.

use fgit_codec::attest::{BodyIdentity, body_id};
use fgit_codec::schema::{RepositoryAuthorityHeadBody, RepositoryDecisionBatchBody};
use fgit_types::{
    DecisionOutcome, DecisionSequence, RepositoryDecisionBatchId, RepositorySequence,
};

use crate::origin::PublicationBasis;
use crate::refusal::ChronicleRefusal;

/// Checks every invariant that makes a pair publishable against `basis`.
///
/// Total: it never panics and never partially reports. The first violation
/// wins, because a caller acting on one broken position gains nothing from
/// knowing about a second.
///
/// `identity` recomputes the batch's identity from its bytes rather than
/// trusting what the head claims. That check matters most exactly where the
/// pair was not built here — a batch replayed from a journal or read back out
/// of the store — because `fgit-authority` does not verify that
/// `decision_tail_id` names the batch being published.
pub fn verify_pair<I>(
    identity: &I,
    basis: &PublicationBasis,
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
) -> Result<(), ChronicleRefusal>
where
    I: BodyIdentity + ?Sized,
{
    verify_identity(basis, batch, head)?;
    let tail = verify_decision_sequence(basis, batch)?;
    verify_commit_records(basis, batch)?;
    verify_successor(basis, batch, head, tail)?;
    verify_tail_binding(identity, batch, head)?;
    verify_roots(batch, head)?;
    verify_refusal_only(basis, batch)
}

/// Recomputes the batch identity and holds the head to it.
fn verify_tail_binding<I>(
    identity: &I,
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
) -> Result<(), ChronicleRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let computed = batch_identity(identity, batch)?;
    if head.decision_tail_id == Some(computed) {
        Ok(())
    } else {
        Err(ChronicleRefusal::DecisionTailMismatch)
    }
}

/// The identity of a decision batch, computed from its canonical bytes.
///
/// Public because anyone holding a batch and a head needs the same answer this
/// module checks against: a head is bound to a batch by the batch's bytes, not
/// by a label somebody chose. Mutating a batch changes its identity, so a
/// caller that edits one must rebind the head or the pair is stale.
pub fn batch_identity<I>(
    identity: &I,
    batch: &RepositoryDecisionBatchBody,
) -> Result<RepositoryDecisionBatchId, ChronicleRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let object =
        body_id(identity, batch).map_err(|_| ChronicleRefusal::BatchIdentityUnavailable)?;
    RepositoryDecisionBatchId::from_internal_object_id(object)
        .map_err(|_| ChronicleRefusal::BatchIdentityUnavailable)
}

fn verify_identity(
    basis: &PublicationBasis,
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
) -> Result<(), ChronicleRefusal> {
    if batch.repository_id != head.repository_id
        || batch.repository_id != basis.body().repository_id
    {
        return Err(ChronicleRefusal::RepositoryMismatch);
    }
    if batch.predecessor_head_id != basis.id() {
        return Err(ChronicleRefusal::PredecessorHeadMismatch);
    }
    if batch.predecessor_head_generation != basis.generation() {
        return Err(ChronicleRefusal::PredecessorGenerationMismatch {
            expected: basis.generation(),
            observed: batch.predecessor_head_generation,
        });
    }
    Ok(())
}

/// Returns the batch's last decision position.
fn verify_decision_sequence(
    basis: &PublicationBasis,
    batch: &RepositoryDecisionBatchBody,
) -> Result<DecisionSequence, ChronicleRefusal> {
    if batch.decisions.is_empty() {
        return Err(ChronicleRefusal::EmptyBatch);
    }
    let open = basis.open_decision_sequence()?;
    if batch.first_decision_sequence != open {
        return Err(ChronicleRefusal::DecisionSequenceNotContinuing {
            expected: open,
            observed: batch.first_decision_sequence,
        });
    }
    let mut expected = open;
    let mut last = open;
    for (index, decision) in batch.decisions.iter().enumerate() {
        if decision.decision_sequence != expected {
            return Err(ChronicleRefusal::DecisionSequenceNotContiguous {
                index,
                expected,
                observed: decision.decision_sequence,
            });
        }
        last = expected;
        if index + 1 < batch.decisions.len() {
            expected = expected
                .next()
                .map_err(|_| ChronicleRefusal::SequenceExhausted {
                    counter: "decision sequence",
                })?;
        }
    }
    Ok(last)
}

fn verify_commit_records(
    basis: &PublicationBasis,
    batch: &RepositoryDecisionBatchBody,
) -> Result<(), ChronicleRefusal> {
    let committed: Vec<(usize, &fgit_codec::schema::RepositoryDecision)> = batch
        .decisions
        .iter()
        .enumerate()
        .filter(|(_, decision)| matches!(decision.outcome, DecisionOutcome::Committed { .. }))
        .collect();
    if committed.len() != batch.committed_rcrs.len() {
        return Err(ChronicleRefusal::CommitRecordCountMismatch {
            committed_decisions: committed.len(),
            records: batch.committed_rcrs.len(),
        });
    }
    if batch.committed_rcrs.is_empty() {
        return Ok(());
    }
    let open = basis.open_repository_sequence()?;
    let mut expected = open;
    let mut parent = basis.body().latest_committed_rcr_id;
    for (index, record) in batch.committed_rcrs.iter().enumerate() {
        if index == 0 && record.repository_sequence != open {
            return Err(ChronicleRefusal::RepositorySequenceNotContinuing {
                expected: open,
                observed: record.repository_sequence,
            });
        }
        if record.repository_sequence != expected {
            return Err(ChronicleRefusal::RepositorySequenceNotContiguous {
                index,
                expected,
                observed: record.repository_sequence,
            });
        }
        if record.parent_rcr_id != parent {
            return Err(ChronicleRefusal::CommitRecordParentBroken { index });
        }
        let decision = committed
            .get(index)
            .ok_or(ChronicleRefusal::CommitRecordNotBound { index })?;
        if decision.1.tx_id != record.tx_id {
            return Err(ChronicleRefusal::CommitRecordNotBound { index: decision.0 });
        }
        parent = Some(
            commit_id_of(&decision.1.outcome)
                .ok_or(ChronicleRefusal::CommitRecordNotBound { index: decision.0 })?,
        );
        if index + 1 < batch.committed_rcrs.len() {
            expected = expected
                .next()
                .map_err(|_| ChronicleRefusal::SequenceExhausted {
                    counter: "repository sequence",
                })?;
        }
    }
    Ok(())
}

const fn commit_id_of(outcome: &DecisionOutcome) -> Option<fgit_types::RepositoryCommitId> {
    match *outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => Some(repository_commit_id),
        DecisionOutcome::Refused { .. } => None,
    }
}

fn verify_successor(
    basis: &PublicationBasis,
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
    tail: DecisionSequence,
) -> Result<(), ChronicleRefusal> {
    if head.generation <= basis.generation() {
        return Err(ChronicleRefusal::GenerationNotAdvancing {
            predecessor: basis.generation(),
            successor: head.generation,
        });
    }
    if head.predecessor_head_id != Some(basis.id()) {
        return Err(ChronicleRefusal::SuccessorPredecessorNotBound);
    }
    if head.decision_tail_id.is_none() {
        return Err(ChronicleRefusal::DecisionTailNotBound);
    }
    if head.latest_decision_sequence != Some(tail) {
        return Err(ChronicleRefusal::DecisionTailSequenceMismatch {
            expected: tail,
            observed: head.latest_decision_sequence,
        });
    }
    let expected_repository_sequence: Option<RepositorySequence> =
        batch.committed_rcrs.last().map_or_else(
            || basis.body().latest_repository_sequence,
            |record| Some(record.repository_sequence),
        );
    if head.latest_repository_sequence != expected_repository_sequence {
        return Err(ChronicleRefusal::ResultingRootMismatch {
            field: "latest_repository_sequence",
        });
    }
    Ok(())
}

fn verify_roots(
    batch: &RepositoryDecisionBatchBody,
    head: &RepositoryAuthorityHeadBody,
) -> Result<(), ChronicleRefusal> {
    let pairs: [(&'static str, bool); 6] = [
        ("ref_root", batch.resulting_ref_root == head.ref_root),
        (
            "forge_position_root",
            batch.resulting_forge_position_root == head.forge_position_root,
        ),
        (
            "outcome_index_root",
            batch.resulting_outcome_index_root == head.outcome_index_root,
        ),
        (
            "retention_root",
            batch.resulting_retention_root == head.retention_root,
        ),
        (
            "outbox_root",
            batch.resulting_outbox_root == head.outbox_root,
        ),
        (
            "policy_epoch",
            batch.resulting_policy_epoch == head.policy_epoch,
        ),
    ];
    for (field, agrees) in pairs {
        if !agrees {
            return Err(ChronicleRefusal::ResultingRootMismatch { field });
        }
    }
    Ok(())
}

/// A batch that committed nothing may consume decision sequence and nothing else.
fn verify_refusal_only(
    basis: &PublicationBasis,
    batch: &RepositoryDecisionBatchBody,
) -> Result<(), ChronicleRefusal> {
    if !batch.committed_rcrs.is_empty() {
        return Ok(());
    }
    let previous = basis.body();
    let unchanged: [(&'static str, bool); 4] = [
        (
            "resulting_ref_root",
            batch.resulting_ref_root == previous.ref_root,
        ),
        (
            "resulting_forge_position_root",
            batch.resulting_forge_position_root == previous.forge_position_root,
        ),
        (
            "resulting_retention_root",
            batch.resulting_retention_root == previous.retention_root,
        ),
        (
            "resulting_outbox_root",
            batch.resulting_outbox_root == previous.outbox_root,
        ),
    ];
    for (field, held) in unchanged {
        if !held {
            return Err(ChronicleRefusal::RefusalOnlyBatchAdvancedCommittedState { field });
        }
    }
    Ok(())
}
