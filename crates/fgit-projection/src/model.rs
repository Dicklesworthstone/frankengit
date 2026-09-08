//! Typed, watermark-bound reads of the derived decision prefix.
//!
//! The watermark and the requested rows are read by ONE statement. A separate
//! watermark lookup followed by a row query would race a fold or rebuild. A
//! row's presence alone is not proof that it belongs to the applied prefix.
//!
//! These are projection reads, not authorization decisions. The caller must
//! authorize the repository before handing its session to a consumer.

use std::num::NonZeroU16;

use asupersync::Cx;
use sqlmodel_core::{Connection, TransactionOps, Value};

use crate::identity::{IdentityAdvanceError, ProjectionIdentity, ProjectionPosition};
use crate::session::{ProjectionError, ProjectionSession, flatten};
use crate::store::{StoreReadError, StoredWatermarkRow, bind_position, decode_watermark_row};
use crate::watermark::WatermarkRefusal;

/// SQLite's largest exactly representable positive sequence.
const MAX_SQL_POSITION: u64 = 9_223_372_036_854_775_807;

/// The left join retains the watermark even when the requested window is empty.
/// A missing watermark, conversely, cannot disclose orphaned decision rows.
const READ_WINDOW: &str = "SELECT w.source_incarnation, w.authority_head, \
    w.authority_head_generation, w.last_position, w.state_text, w.schema_generation, \
    d.seq, d.digest FROM fgit_projection_watermark AS w \
    LEFT JOIN fgit_projection_applied_decision AS d \
    ON d.seq >= ?1 AND d.seq <= ?2 AND d.seq <= w.last_position \
    WHERE w.singleton = 1 ORDER BY d.seq ASC LIMIT ?3";

/// One folded decision as a readable row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedDecision {
    pub seq: ProjectionPosition,
    pub digest: String,
}

/// One bounded page and the completeness watermark observed in its snapshot.
///
/// Continue with `next_start`, the SAME session identity, and a fixed upper
/// bound no greater than the first page's watermark to traverse a stable
/// prefix. A cursor is a position, not a capability or an authorization token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedDecisionPage {
    pub decisions: Vec<AppliedDecision>,
    pub watermark: Option<ProjectionPosition>,
    pub next_start: Option<ProjectionPosition>,
}

/// Read at most `limit` decisions from `[start, end_inclusive]`.
///
/// The nonzero 16-bit limit bounds row allocation in the database query,
/// rather than truncating an already unbounded result. Sequence zero denotes
/// the empty prefix, not a decision; starting at zero therefore starts at one.
/// Ranges above SQLite's integer domain are empty rather than panicking.
///
/// # Errors
/// Foreign incarnation/head/generation/schema bindings fail before any rows
/// are returned. A hole or duplicate inside the claimed applied prefix is a
/// typed gap, not a successful short page. Driver and row-shape errors retain
/// their existing projection error classes.
pub async fn read_applied_page<C: Connection>(
    session: &ProjectionSession<C>,
    cx: &Cx,
    start: ProjectionPosition,
    end_inclusive: ProjectionPosition,
    limit: NonZeroU16,
) -> Result<AppliedDecisionPage, ProjectionError> {
    read_window(session, cx, start, end_inclusive, i64::from(limit.get())).await
}

/// Read the applied prefix `[start, end_inclusive]` in canonical order.
///
/// This compatibility API returns the whole intersecting range. Service
/// consumers should use [`read_applied_page`] to impose a per-request row
/// budget. Both APIs bind rows to the watermark in the same SQL snapshot.
///
/// # Errors
/// See [`read_applied_page`]. An upper bound of `u64::MAX` is supported: it is
/// intersected with the representable, actually folded prefix before binding.
pub async fn read_applied_range<'a, C: Connection>(
    session: &'a ProjectionSession<C>,
    cx: &Cx,
    start: ProjectionPosition,
    end_inclusive: ProjectionPosition,
) -> Result<Vec<AppliedDecision>, ProjectionError>
where
    C::Tx<'a>: TransactionOps,
{
    if end_inclusive < start {
        return Ok(Vec::new());
    }
    Ok(read_window(session, cx, start, end_inclusive, i64::MAX)
        .await?
        .decisions)
}

async fn read_window<C: Connection>(
    session: &ProjectionSession<C>,
    cx: &Cx,
    start: ProjectionPosition,
    end_inclusive: ProjectionPosition,
    row_limit: i64,
) -> Result<AppliedDecisionPage, ProjectionError> {
    let start = start.get().max(1);
    let end = end_inclusive.get().min(MAX_SQL_POSITION);
    // Even an empty window checks an existing watermark's binding. These
    // parameters make its LEFT JOIN produce only the metadata sentinel.
    let (sql_start, sql_end) = if start > end {
        (1, 0)
    } else {
        (start, end)
    };
    let rows = flatten(
        session
            .connection_ref()
            .query(
                cx,
                READ_WINDOW,
                &[
                    bind_position(ProjectionPosition::new(sql_start)),
                    bind_position(ProjectionPosition::new(sql_end)),
                    Value::BigInt(row_limit),
                ],
            )
            .await,
        "read_applied_window",
    )?;
    let Some(first) = rows.first() else {
        return Ok(AppliedDecisionPage {
            decisions: Vec::new(),
            watermark: None,
            next_start: None,
        });
    };
    let watermark = decode_watermark_row(first)?;
    check_binding(session.identity(), &watermark)?;
    let visible_end = watermark
        .last_position
        .map_or(0, ProjectionPosition::get)
        .min(end);
    if start > visible_end {
        if rows.len() != 1
            || !matches!(first.get_by_name("seq"), Some(Value::Null))
            || !matches!(first.get_by_name("digest"), Some(Value::Null))
        {
            return Err(StoreReadError::MissingColumn("empty-window sentinel").into());
        }
        return Ok(AppliedDecisionPage {
            decisions: Vec::new(),
            watermark: watermark.last_position,
            next_start: None,
        });
    }

    let limit = u64::try_from(row_limit).map_err(|_| StoreReadError::NotAnInteger)?;
    let expected_count = (visible_end - start + 1).min(limit);
    let page_end = start + expected_count - 1;
    let mut expected = start;
    let mut decisions = Vec::with_capacity(rows.len());
    for row in &rows {
        // The repeated metadata comes from the same statement snapshot. Check
        // it too so a malformed driver response cannot splice generations.
        if decode_watermark_row(row)? != watermark {
            return Err(StoreReadError::MissingColumn("consistent watermark snapshot").into());
        }
        let raw = row
            .get_by_name("seq")
            .and_then(Value::as_i64)
            .ok_or(StoreReadError::MissingColumn("seq"))?;
        let sequence = u64::try_from(raw).map_err(|_| StoreReadError::NegativePosition(raw))?;
        if sequence != expected || sequence > page_end {
            return Err(WatermarkRefusal::Gap {
                expected: ProjectionPosition::new(expected),
                offered: ProjectionPosition::new(sequence),
            }
            .into());
        }
        let digest = row
            .get_by_name("digest")
            .and_then(Value::as_str)
            .ok_or(StoreReadError::MissingColumn("digest"))?
            .to_owned();
        decisions.push(AppliedDecision {
            seq: ProjectionPosition::new(sequence),
            digest,
        });
        expected += 1;
    }
    if expected != page_end + 1 {
        return Err(WatermarkRefusal::Gap {
            expected: ProjectionPosition::new(expected),
            offered: ProjectionPosition::new(page_end + 1),
        }
        .into());
    }
    Ok(AppliedDecisionPage {
        decisions,
        watermark: watermark.last_position,
        next_start: (page_end < visible_end).then_some(ProjectionPosition::new(page_end + 1)),
    })
}

fn check_binding(
    identity: &ProjectionIdentity,
    watermark: &StoredWatermarkRow,
) -> Result<(), ProjectionError> {
    for (field, expected, observed) in [
        (
            "source_incarnation",
            identity.source_incarnation().to_owned(),
            watermark.source_incarnation.clone(),
        ),
        (
            "authority_head",
            identity.authority_head().to_owned(),
            watermark.authority_head.clone(),
        ),
        (
            "authority_head_generation",
            identity.authority_head_generation().to_string(),
            watermark.authority_head_generation.to_string(),
        ),
        (
            "schema_generation",
            identity.schema_generation().to_string(),
            watermark.schema_generation.to_string(),
        ),
    ] {
        if expected != observed {
            return Err(IdentityAdvanceError::BindingMismatch {
                field,
                expected,
                observed,
            }
            .into());
        }
    }
    Ok(())
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

                let middle = read_applied_range(
                    &session,
                    cx,
                    ProjectionPosition::new(2),
                    ProjectionPosition::new(2),
                )
                .await?;
                assert_eq!(middle.len(), 1);
                assert_eq!(middle[0].seq, ProjectionPosition::new(2));

                let inverted = read_applied_range(
                    &session,
                    cx,
                    ProjectionPosition::new(3),
                    ProjectionPosition::new(1),
                )
                .await?;
                assert!(inverted.is_empty());

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

    #[test]
    fn pages_are_bounded_and_orphan_rows_never_extend_the_watermark() {
        let node = fgit_runtime::boot::RuntimeProfile::deterministic()
            .build()
            .expect("node builds");
        let rt = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime builds");
        let result: Result<(), ProjectionError> = {
            let cx = node.request_cx(fgit_runtime::meter::BudgetClass::Request);
            rt.block_on(async {
                let identity =
                    ProjectionIdentity::new(INC, HEAD, 7, 1, 1, BuildIdentity::current());
                let session = ProjectionSession::open_memory(identity)?;
                session.install_schema(&cx).await?;
                apply_batch(
                    &session,
                    &cx,
                    &[record(1, "d1"), record(2, "d2"), record(3, "d3")],
                )
                .await?;
                // Simulate a damaged/imported projection with an unaccounted row.
                flatten(
                    session.connection_ref().execute(
                        &cx,
                        "INSERT INTO fgit_projection_applied_decision (seq, digest) VALUES (4, 'orphan')",
                        &[],
                    ).await,
                    "plant_orphan",
                )?;
                let limit = NonZeroU16::new(2).expect("nonzero");
                let first = read_applied_page(
                    &session, &cx, ProjectionPosition::genesis(),
                    ProjectionPosition::new(u64::MAX), limit,
                ).await?;
                assert_eq!(first.decisions.len(), 2);
                assert_eq!(first.decisions[0].seq.get(), 1);
                assert_eq!(first.watermark, Some(ProjectionPosition::new(3)));
                assert_eq!(first.next_start, Some(ProjectionPosition::new(3)));
                let second = read_applied_page(
                    &session, &cx, first.next_start.expect("next page"),
                    first.watermark.expect("folded"), limit,
                ).await?;
                assert_eq!(second.decisions, vec![AppliedDecision {
                    seq: ProjectionPosition::new(3), digest: "d3".to_owned(),
                }]);
                assert_eq!(second.next_start, None);
                assert_eq!(read_applied_range(
                    &session, &cx, ProjectionPosition::new(1),
                    ProjectionPosition::new(u64::MAX),
                ).await?.len(), 3);
                let beyond = read_applied_page(
                    &session, &cx, ProjectionPosition::new(u64::MAX),
                    ProjectionPosition::new(u64::MAX), limit,
                ).await?;
                assert!(beyond.decisions.is_empty());
                assert_eq!(beyond.watermark, first.watermark);
                flatten(session.connection_ref().execute(
                    &cx, "DELETE FROM fgit_projection_watermark", &[],
                ).await, "remove_watermark")?;
                let unbound = read_applied_page(
                    &session, &cx, ProjectionPosition::new(1),
                    ProjectionPosition::new(4), limit,
                ).await?;
                assert!(unbound.decisions.is_empty());
                assert_eq!(unbound.watermark, None);
                Ok(())
            })
        };
        result.expect("bounded watermark reads");
        assert!(rt.shutdown_timeout(std::time::Duration::from_secs(5)));
    }

    #[test]
    fn foreign_bindings_and_holes_refuse_without_laundering_rows() {
        let node = fgit_runtime::boot::RuntimeProfile::deterministic()
            .build()
            .expect("node builds");
        let rt = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime builds");
        let result: Result<(), ProjectionError> = {
            let cx = node.request_cx(fgit_runtime::meter::BudgetClass::Request);
            rt.block_on(async {
                let identity =
                    ProjectionIdentity::new(INC, HEAD, 7, 1, 1, BuildIdentity::current());
                let session = ProjectionSession::open_memory(identity)?;
                session.install_schema(&cx).await?;
                apply_batch(&session, &cx, &[record(1, "d1"), record(2, "d2")]).await?;
                for (sql, expected_field) in [
                    ("UPDATE fgit_projection_watermark SET source_incarnation = 'foreign'", "source_incarnation"),
                    ("UPDATE fgit_projection_watermark SET authority_head = 'foreign'", "authority_head"),
                    ("UPDATE fgit_projection_watermark SET authority_head_generation = 8", "authority_head_generation"),
                    ("UPDATE fgit_projection_watermark SET schema_generation = 2", "schema_generation"),
                ] {
                    flatten(session.connection_ref().execute(&cx, sql, &[]).await, "plant_binding")?;
                    let error = read_applied_range(
                        &session, &cx, ProjectionPosition::new(1), ProjectionPosition::new(2),
                    ).await.expect_err("foreign projection must refuse");
                    assert!(matches!(error, ProjectionError::Identity(
                        IdentityAdvanceError::BindingMismatch { field, .. }
                    ) if field == expected_field));
                    flatten(session.connection_ref().execute(
                        &cx,
                        "UPDATE fgit_projection_watermark SET source_incarnation = ?1, authority_head = ?2, authority_head_generation = 7, schema_generation = 1",
                        &[Value::Text(INC.to_owned()), Value::Text(HEAD.to_owned())],
                    ).await, "restore_binding")?;
                    assert_eq!(read_applied_range(
                        &session, &cx, ProjectionPosition::new(1), ProjectionPosition::new(2),
                    ).await?.len(), 2);
                }
                flatten(session.connection_ref().execute(
                    &cx, "DELETE FROM fgit_projection_applied_decision WHERE seq = 1", &[],
                ).await, "plant_gap")?;
                assert!(matches!(read_applied_range(
                    &session, &cx, ProjectionPosition::new(1), ProjectionPosition::new(2),
                ).await, Err(ProjectionError::Refusal(WatermarkRefusal::Gap { .. }))));
                Ok(())
            })
        };
        result.expect("binding and gap guards");
        assert!(rt.shutdown_timeout(std::time::Duration::from_secs(5)));
    }

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
