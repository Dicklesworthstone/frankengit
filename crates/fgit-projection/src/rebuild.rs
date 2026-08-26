//! Versioned derived-state rebuilds.
//!
//! Schema changes are rebuilds, never in-place history edits: the projection
//! carries a `schema_generation`, and when the requested generation differs
//! from the stored one the derived tables are dropped and reinstalled empty.
//! Canonical history is untouched by construction — everything dropped here
//! is reproducible from the decision stream, which is exactly why the bead's
//! recovery clause ("no projection file is required for recovery") holds.
//!
//! A database folded under a different incarnation or authority head is not
//! stale, it is FOREIGN: rebuilding it under this binding would launder one
//! repository's identity into another. That case is a typed refusal, never a
//! wipe.

use asupersync::Cx;
use sqlmodel_core::{Connection, TransactionOps};

use crate::identity::ProjectionPosition;
use crate::session::{ProjectionError, ProjectionSession, flatten};
use crate::store::teardown_statements;
use crate::watermark::WatermarkRefusal;

/// What [`ensure_schema_generation`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaReconciliation {
    /// The stored generation already matches; nothing was touched. Carries
    /// the fold position so callers can resume instead of re-deriving.
    Current {
        position: Option<ProjectionPosition>,
    },
    /// A fresh or wiped install: schema installed (reinstalled), receipt
    /// persisted, watermark empty. The caller folds from genesis via
    /// [`crate::catchup::apply_batch`].
    ReadyForFold,
}

/// Pure classification of a stored watermark row against this session's
/// binding and the requested schema generation. Split from I/O so the
/// foreign-binding refusal has direct unit coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoredClass {
    /// Same binding, matching schema generation.
    Current {
        position: Option<ProjectionPosition>,
    },
    /// Same binding, different schema generation: derived state is stale.
    Stale,
}

pub(crate) fn classify_stored<'a>(
    stored_incarnation: &'a str,
    stored_head: &'a str,
    stored_schema_generation: u32,
    requested_schema_generation: u32,
    expected_incarnation: &'a str,
    expected_head: &'a str,
) -> Result<StoredClass, WatermarkRefusal> {
    if stored_incarnation != expected_incarnation {
        return Err(WatermarkRefusal::HeadBindingMismatch {
            folded: stored_incarnation.to_owned(),
            observed: expected_incarnation.to_owned(),
        });
    }
    if stored_head != expected_head {
        return Err(WatermarkRefusal::HeadBindingMismatch {
            folded: stored_head.to_owned(),
            observed: expected_head.to_owned(),
        });
    }
    if stored_schema_generation == requested_schema_generation {
        Ok(StoredClass::Current { position: None })
    } else {
        Ok(StoredClass::Stale)
    }
}

/// Reconcile the projection's stored `schema_generation` against `requested`.
///
/// - Fresh database: installs the canonical schema and the identity receipt,
///   then reports [`SchemaReconciliation::ReadyForFold`].
/// - Matching generation: reports [`SchemaReconciliation::Current`] with the
///   stored fold position and touches nothing.
/// - Different generation: drops the derived tables, reinstalls the schema,
///   repersists the receipt, and reports [`SchemaReconciliation::ReadyForFold`].
///
/// # Errors
/// - [`WatermarkRefusal::HeadBindingMismatch`] when the stored row belongs
///   to a different incarnation or authority head than this session's
///   identity binds — foreign state is refused, never rebuilt.
/// - Driver failures surface verbatim as [`ProjectionError::Sql`];
///   interruption keeps its own variant.
pub async fn ensure_schema_generation<'a, C: Connection>(
    session: &'a ProjectionSession<C>,
    cx: &Cx,
    requested_schema_generation: u32,
) -> Result<SchemaReconciliation, ProjectionError>
where
    C::Tx<'a>: TransactionOps,
{
    let identity = session.identity();
    // Install first, unconditionally: `IF NOT EXISTS` makes this a no-op on
    // an existing projection and the bootstrap for a fresh one. Reading the
    // watermark before the schema exists would turn "empty" into "corrupt".
    session.install_schema(cx).await?;
    match session.load_watermark_row(cx).await? {
        None => {
            session.persist_identity_receipt(cx).await?;
            Ok(SchemaReconciliation::ReadyForFold)
        }
        Some(row) => {
            let position = row.last_position;
            match classify_stored(
                &row.source_incarnation,
                &row.authority_head,
                row.schema_generation,
                requested_schema_generation,
                identity.source_incarnation(),
                identity.authority_head(),
            )? {
                StoredClass::Current { .. } => Ok(SchemaReconciliation::Current { position }),
                StoredClass::Stale => {
                    let drops = teardown_statements()
                        .into_iter()
                        .map(|(sql, params)| (sql.to_owned(), params))
                        .collect::<Vec<_>>();
                    flatten(
                        session.connection_ref().batch(cx, &drops).await,
                        "wipe_derived_tables",
                    )?;
                    session.install_schema(cx).await?;
                    session.persist_identity_receipt(cx).await?;
                    Ok(SchemaReconciliation::ReadyForFold)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catchup::{DecisionRecord, apply_batch};
    use crate::identity::{BuildIdentity, ProjectionIdentity};
    use crate::session::ProjectionSession;

    const INC: &str = "inc-11111111111111111111111111111111";
    const HEAD: &str = "headbeef00000000000000000000000000000000000000000000000000009999";

    fn identity(schema_generation: u32) -> ProjectionIdentity {
        ProjectionIdentity::new(INC, HEAD, 7, 1, schema_generation, BuildIdentity::current())
    }

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
    fn foreign_incarnation_is_refused_not_wiped() {
        let class = classify_stored("other-inc", HEAD, 1, 1, INC, HEAD);
        assert!(matches!(
            class,
            Err(WatermarkRefusal::HeadBindingMismatch { .. })
        ));
    }

    #[test]
    fn foreign_head_is_refused_not_wiped() {
        let class = classify_stored(INC, "other-head", 1, 1, INC, HEAD);
        assert!(matches!(
            class,
            Err(WatermarkRefusal::HeadBindingMismatch { .. })
        ));
    }

    #[test]
    fn same_binding_splits_current_from_stale() {
        assert!(matches!(
            classify_stored(INC, HEAD, 3, 3, INC, HEAD),
            Ok(StoredClass::Current { .. })
        ));
        assert!(matches!(
            classify_stored(INC, HEAD, 3, 4, INC, HEAD),
            Ok(StoredClass::Stale)
        ));
    }

    #[test]
    fn reconciliation_and_refold_round_trip_on_real_driver() {
        use fgit_runtime::boot::RuntimeProfile;
        use fgit_runtime::meter::BudgetClass;

        let node = RuntimeProfile::deterministic()
            .build()
            .expect("deterministic node runtime builds");
        let runtime = asupersync::runtime::RuntimeBuilder::new()
            .blocking_threads(1, 2)
            .build()
            .expect("test runtime builds");
        let outcome: Result<(), ProjectionError> = {
            let cx = node.request_cx(BudgetClass::Request);
            runtime.block_on(async {
                let cx = &cx;
                let session = ProjectionSession::open_memory(identity(1))?;

                // Fresh database reconciles to ReadyForFold and installs schema.
                assert_eq!(
                    ensure_schema_generation(&session, cx, 1).await?,
                    SchemaReconciliation::ReadyForFold
                );

                // Fold three contiguous decisions.
                let records = [record(1, "d1"), record(2, "d2"), record(3, "d3")];
                let report = apply_batch(&session, cx, &records).await?;
                assert_eq!(report.applied, 3);
                assert_eq!(report.final_position, Some(ProjectionPosition::new(3)));

                // Same generation: Current, position preserved, nothing reset.
                assert_eq!(
                    ensure_schema_generation(&session, cx, 1).await?,
                    SchemaReconciliation::Current {
                        position: Some(ProjectionPosition::new(3))
                    }
                );
                assert_eq!(
                    session
                        .load_watermark_row(cx)
                        .await?
                        .and_then(|row| row.last_position),
                    Some(ProjectionPosition::new(3))
                );

                // Bumped generation: wipe-and-reinstall, watermark empty again.
                assert_eq!(
                    ensure_schema_generation(&session, cx, 2).await?,
                    SchemaReconciliation::ReadyForFold
                );
                assert_eq!(session.load_watermark_row(cx).await?, None);

                // The emptied projection folds the SAME stream to the SAME root:
                // determinism of rebuild, receipted by the returned report.
                let replay = apply_batch(&session, cx, &records).await?;
                assert_eq!(replay.applied, 3);
                assert_eq!(replay.final_position, Some(ProjectionPosition::new(3)));
                Ok(())
            })
        };
        outcome.expect("round trip holds");
        assert!(
            runtime.shutdown_timeout(std::time::Duration::from_secs(5)),
            "test runtime drains"
        );
        drop(node);
    }
}
