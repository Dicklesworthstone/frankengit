//! Canonical per-batch evidence commitment.
//!
//! This module deliberately derives the root only from the final ordered
//! decisions and stamped commit records.  Those values first coexist at
//! chronicle sealing; accepting a provider-supplied digest here would let a
//! caller claim evidence that the batch does not actually carry.

use fgit_codec::schema::{RepositoryCommitRecord, RepositoryDecision, RepositoryDecisionBatchBody};
use fgit_codec::{Encoder, wire::CanonicalBody};
use fgit_crypto::{IdentityDomain, internal_digest_over_parts, internal_digest_value};
use fgit_types::{DecisionOutcome, Digest, SchemaFamily, SchemaId};

use crate::refusal::ChronicleRefusal;

const BATCH_EVIDENCE_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("decision-batch-evidence-merkle"),
    1,
    0,
);

/// Derives the Merkle commitment for a received decision batch.
///
/// The ordered input is part of the commitment.  A committed decision's leaf
/// includes the decision and the canonical payload of its matching RCR; a
/// refusal leaf includes its decision, which in turn binds its refusal code
/// and refusal-record identity.
pub fn batch_evidence_root(
    batch: &RepositoryDecisionBatchBody,
) -> Result<Digest, ChronicleRefusal> {
    derive_batch_evidence_root(&batch.decisions, &batch.committed_rcrs)
}

/// Derives the root while `PublicationPlan::seal` still owns the pre-body
/// decision and record vectors.
pub(crate) fn derive_batch_evidence_root(
    decisions: &[RepositoryDecision],
    committed_rcrs: &[RepositoryCommitRecord],
) -> Result<Digest, ChronicleRefusal> {
    if decisions.is_empty() {
        return Err(ChronicleRefusal::EmptyBatch);
    }

    let committed_decisions = decisions
        .iter()
        .filter(|decision| matches!(decision.outcome, DecisionOutcome::Committed { .. }))
        .count();
    if committed_decisions != committed_rcrs.len() {
        return Err(ChronicleRefusal::CommitRecordCountMismatch {
            committed_decisions,
            records: committed_rcrs.len(),
        });
    }

    let mut records = committed_rcrs.iter();
    let mut leaves = Vec::with_capacity(decisions.len());
    for decision in decisions {
        let mut leaf = Encoder::new();
        write_decision(&mut leaf, decision)?;
        if matches!(decision.outcome, DecisionOutcome::Committed { .. }) {
            let record = records
                .next()
                .ok_or(ChronicleRefusal::CommitRecordCountMismatch {
                    committed_decisions,
                    records: committed_rcrs.len(),
                })?;
            record
                .write_payload(&mut leaf)
                .map_err(|_| ChronicleRefusal::BatchEvidenceEncodingUnavailable)?;
        }
        leaves.push(internal_digest_value(
            IdentityDomain::MerkleLeaf,
            BATCH_EVIDENCE_SCHEMA,
            leaf.as_bytes(),
        ));
    }

    while leaves.len() > 1 {
        let mut parents = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            parents.push(internal_digest_over_parts(
                IdentityDomain::MerkleNode,
                BATCH_EVIDENCE_SCHEMA,
                &[left.as_bytes(), right.as_bytes()],
            ));
        }
        leaves = parents;
    }

    let root = leaves
        .first()
        .copied()
        .ok_or(ChronicleRefusal::EmptyBatch)?;
    Ok(Digest::new(
        IdentityDomain::MerkleLeaf.algorithm().id(),
        root,
    ))
}

fn write_decision(
    out: &mut Encoder,
    decision: &RepositoryDecision,
) -> Result<(), ChronicleRefusal> {
    out.write_internal_object_id(decision.tx_id.as_internal_object_id())
        .map_err(|_| ChronicleRefusal::BatchEvidenceEncodingUnavailable)?;
    out.write_scalar(decision.decision_sequence.get());
    out.write_raw_byte(decision.outcome.discriminant());
    match decision.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => out
            .write_internal_object_id(repository_commit_id.as_internal_object_id())
            .map_err(|_| ChronicleRefusal::BatchEvidenceEncodingUnavailable),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => {
            out.write_scalar(code.code_point());
            out.write_internal_object_id(refusal_record_id.as_internal_object_id())
                .map_err(|_| ChronicleRefusal::BatchEvidenceEncodingUnavailable)
        }
    }
}
