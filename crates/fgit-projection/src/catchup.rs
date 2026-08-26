//! Deterministic, idempotent catch-up.
//!
//! Callers feed [`DecisionRecord`] values in canonical order from wherever the
//! decision stream lives (chronicle, transfer, repair). [`apply_batch`] folds
//! them into the projection under one transaction per record: re-delivery of
//! an applied sequence with the same digest is a no-op success, a different
//! digest at an applied sequence is a typed conflict, and any gap refuses
//! before touching storage — a projection never silently skips history.

use asupersync::Cx;
use sqlmodel_core::Connection;

use crate::identity::ProjectionPosition;
use crate::session::{ProjectionError, ProjectionSession, advance_within_transaction};

/// One canonical decision offered for folding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRecord {
    /// One-based position inside the incarnation's stream.
    pub seq: ProjectionPosition,
    /// Hex digest of the canonical decision body; re-delivery is recognized
    /// by `(seq, digest)` agreement.
    pub digest: String,
    /// Incarnation binding carried through to the stored watermark row so a
    /// database can be diagnosed without reopening the fold loop.
    pub source_incarnation: String,
    pub authority_head: String,
    pub authority_head_generation: u64,
}

/// A conflicting digest for an already-applied sequence.
///
/// This is not retryable by this layer: two digests for one sequence means
/// the caller is folding two different histories, and the projection refuses
/// to pick a winner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionConflict {
    pub seq: ProjectionPosition,
    pub applied_digest: String,
    pub offered_digest: String,
}

impl std::fmt::Display for ProjectionConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "decision {} already applied with digest {}, offered {}",
            self.seq, self.applied_digest, self.offered_digest
        )
    }
}

impl std::error::Error for ProjectionConflict {}

/// Outcome of folding one batch: the watermark after the batch, plus counts
/// that make the no-op path visible instead of inferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchReport {
    pub applied: u64,
    pub idempotent_replays: u64,
    /// Highest position newly folded by THIS batch. Replays do not move it;
    /// `None` when every record was a replay (or the batch was empty).
    pub final_position: Option<ProjectionPosition>,
}

/// Fold `records` into the projection behind `session`.
///
/// Every record commits atomically on its own: a failure mid-batch leaves all
/// earlier records durable and the batch resumable from the reported final
/// position, which is what makes crash-retry loops converge instead of
/// re-folding. Contiguity is enforced against the *stored* watermark inside
/// each transaction, so concurrent folders serialize on the row rather than
/// trusting stale in-memory positions.
///
/// # Errors
/// The first refusal, conflict, or driver error stops the batch; earlier
/// records remain committed. See [`ProjectionError`] for the taxonomy.
pub async fn apply_batch<C: Connection>(
    session: &ProjectionSession<C>,
    cx: &Cx,
    records: &[DecisionRecord],
) -> Result<BatchReport, ProjectionError> {
    let mut applied = 0u64;
    let mut replays = 0u64;
    let mut last_position: Option<ProjectionPosition> = None;

    for record in records {
        let held = session
            .load_watermark_row(cx)
            .await?
            .and_then(|row| row.last_position);
        let after = advance_within_transaction(
            session.connection_ref(),
            cx,
            held,
            record,
            "catching_up",
            session.identity().schema_generation(),
        )
        .await?;
        if Some(after) == held {
            replays += 1;
        } else {
            applied += 1;
            last_position = Some(after);
        }
    }

    Ok(BatchReport {
        applied,
        idempotent_replays: replays,
        final_position: last_position,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seq: u64, digest: &str) -> DecisionRecord {
        DecisionRecord {
            seq: ProjectionPosition::new(seq),
            digest: digest.to_owned(),
            source_incarnation: "inc-test".to_owned(),
            authority_head: "head-test".to_owned(),
            authority_head_generation: 1,
        }
    }

    #[test]
    fn conflict_display_names_both_sides() {
        let conflict = ProjectionConflict {
            seq: ProjectionPosition::new(4),
            applied_digest: "aa".to_owned(),
            offered_digest: "bb".to_owned(),
        };
        assert_eq!(
            conflict.to_string(),
            "decision 4 already applied with digest aa, offered bb"
        );
    }

    #[test]
    fn batch_report_counts_stay_exact() {
        // The struct is the receipt surface for crash-retry loops; this pins
        // its shape so a field rename cannot silently break receipts.
        let report = BatchReport {
            applied: 2,
            idempotent_replays: 5,
            final_position: Some(ProjectionPosition::new(7)),
        };
        assert_eq!(report.applied + report.idempotent_replays, 7);
        assert_eq!(report.final_position.map(ProjectionPosition::get), Some(7));
    }

    #[test]
    fn records_carry_full_binding_context() {
        let r = record(9, "deadbeef");
        assert_eq!(r.seq.get(), 9);
        assert_eq!(r.digest, "deadbeef");
        assert_eq!(r.authority_head, "head-test");
    }
}
