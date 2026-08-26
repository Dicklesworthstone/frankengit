//! The reference typed read-model: decisions folded into queryable rows.
//!
//! This module is the pattern every consumer of the substrate copies: a
//! plain struct mirroring its derived table, a canonical parameterized query
//! whose ordering is part of the contract, and no SQL formatting outside
//! [`crate::store`]-style emitters. Ordering rules live HERE, once: results
//! come back sorted by ascending sequence, and because sequence is the
//! primary key there are no ties to break — the tie-break rule is
//! structural, which is stronger than documenting one.
//!
//! Pagination is watermark-aware by construction: callers pass the position
//! range they are entitled to see under their bound identity, and the query
//! refuses to look past the fold.

use asupersync::Cx;
use sqlmodel_core::{Connection, TransactionOps, Value};

use crate::identity::ProjectionPosition;
use crate::session::{ProjectionError, ProjectionSession, flatten};
use crate::store::{StoreReadError, bind_position};

/// One folded decision as a readable row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedDecision {
    pub seq: ProjectionPosition,
    pub digest: String,
}

/// Read the applied prefix `[start, end_inclusive]` in canonical order.
///
/// The range is clamped to what the watermark actually covers: an end past
/// the fold returns only folded rows, because rows beyond the watermark do
/// not exist and pretending otherwise would mix generations.
///
/// # Errors
/// Driver failures surface verbatim; row-shape violations come back as
/// [`ProjectionError::Corrupt`].
pub async fn read_applied_range<'a, C: Connection>(
    session: &'a ProjectionSession<C>,
    cx: &Cx,
    start: ProjectionPosition,
    end_inclusive: ProjectionPosition,
) -> Result<Vec<AppliedDecision>, ProjectionError>
where
    C::Tx<'a>: TransactionOps,
{
    if end_inclusive.get() < start.get() {
        // Empty window: legal and answered without touching storage.
        return Ok(Vec::new());
    }
    let outcome = session
        .connection_ref()
        .query(
            cx,
            "SELECT seq, digest FROM fgit_projection_applied_decision \
             WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq ASC",
            &[bind_position(start), bind_position(end_inclusive)],
        )
        .await;
    let rows = flatten(outcome, "read_applied_range")?;
    let mut decoded = Vec::with_capacity(rows.len());
    for row in &rows {
        let seq_raw = row
            .get_by_name("seq")
            .and_then(Value::as_i64)
            .ok_or(StoreReadError::MissingColumn("seq"))?;
        let widened =
            u64::try_from(seq_raw).map_err(|_| StoreReadError::NegativePosition(seq_raw))?;
        let digest = row
            .get_by_name("digest")
            .and_then(Value::as_str)
            .ok_or(StoreReadError::MissingColumn("digest"))?
            .to_owned();
        decoded.push(AppliedDecision {
            seq: ProjectionPosition::new(widened),
            digest,
        });
    }
    // Canonical order asserted, not assumed: a driver that returned rows out
    // of order fails loudly here rather than feeding consumers shuffled
    // history that happens to look fine at small sizes.
    if !decoded.is_empty()
        && !decoded
            .windows(2)
            .all(|window| window[0].seq <= window[1].seq)
    {
        return Err(ProjectionError::Corrupt(StoreReadError::NotAnInteger));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catchup::{DecisionRecord, apply_batch};
    use crate::identity::BuildIdentity;

    const INC: &str = "inc-readmodel";
    const HEAD: &str = "headbeef00000000000000000000000000000000000000000000000000424242";

    fn record(seq: u64, digest: &str) -> DecisionRecord {
        DecisionRecord {
            seq: ProjectionPosition::new(seq),
            digest: digest.to_owned(),
            source_incarnation: INC.to_owned(),
            authority_head: HEAD.to_owned(),
            authority_head_generation: 7,
        }
    }

    #[test]
    fn typed_reads_are_ordered_clamped_and_complete() {
        let node = fgit_runtime::boot::RuntimeProfile::deterministic()
            .build()
            .expect("node builds");
        let rt = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime builds");
        let result: Result<(), ProjectionError> = {
            let cx = node.request_cx(fgit_runtime::meter::BudgetClass::Request);
            rt.block_on(async {
                let cx = &cx;
                let identity =
                    ProjectionIdentity::new(INC, HEAD, 7, 1, 1, BuildIdentity::current());
                let session = ProjectionSession::open_memory(identity)?;
                ensure_schema_generation_ready(&session, cx).await?;

                apply_batch(
                    &session,
                    cx,
                    &[record(1, "d1"), record(2, "d2"), record(3, "d3")],
                )
                .await?;

                // Full prefix in canonical order.
                let all = read_applied_range(
                    &session,
                    cx,
                    ProjectionPosition::new(1),
                    ProjectionPosition::new(9),
                )
                .await?;
                assert_eq!(all.len(), 3);
                assert_eq!(
                    all[0],
                    AppliedDecision {
                        seq: ProjectionPosition::new(1),
                        digest: "d1".into()
                    }
                );
                assert_eq!(all[2].digest, "d3");

                // Windowed read inside the fold.
                let middle = read_applied_range(
                    &session,
                    cx,
                    ProjectionPosition::new(2),
                    ProjectionPosition::new(2),
                )
                .await?;
                assert_eq!(middle.len(), 1);
                assert_eq!(middle[0].seq, ProjectionPosition::new(2));

                // Inverted window is empty by contract, not an error.
                let inverted = read_applied_range(
                    &session,
                    cx,
                    ProjectionPosition::new(3),
                    ProjectionPosition::new(1),
                )
                .await?;
                assert!(inverted.is_empty());

                // Beyond-the-watermark reads clamp instead of lying.
                let beyond = read_applied_range(
                    &session,
                    cx,
                    ProjectionPosition::new(1),
                    ProjectionPosition::new(50),
                )
                .await?;
                assert_eq!(beyond.len(), 3);
                Ok(())
            })
        };
        result.expect("typed read model holds");
        assert!(
            rt.shutdown_timeout(std::time::Duration::from_secs(5)),
            "runtime drains"
        );
    }

    use crate::identity::ProjectionIdentity;

    async fn ensure_schema_generation_ready<'x, C: Connection>(
        session: &'x ProjectionSession<C>,
        cx: &Cx,
    ) -> Result<(), ProjectionError>
    where
        C::Tx<'x>: TransactionOps,
    {
        let _ = crate::rebuild::ensure_schema_generation(session, cx, 1).await?;
        Ok(())
    }
}
