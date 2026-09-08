//! Atomic, versioned rebuilds of disposable projection state.
//!
//! Installation, classification, teardown, replacement schema, identity
//! receipt and empty watermark belong to one SQL transaction. A failure must
//! not strand half of the old generation beside half of its replacement.
//! Canonical repository history is never touched.
//!
//! An explicitly changed schema may rebuild the SAME source binding. A
//! foreign incarnation, head or head generation is refused rather than wiped.

use asupersync::Cx;
use sqlmodel_core::{Connection, TransactionOps, Value};

use crate::identity::{IdentityAdvanceError, ProjectionIdentity, ProjectionPosition};
use crate::session::{ProjectionError, ProjectionSession, flatten};
use crate::store::{
    StoreReadError, decode_watermark_row, install_schema_statements, teardown_statements,
};
use crate::watermark::WatermarkRefusal;

/// What [`ensure_schema_generation`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaReconciliation {
    /// The binding and schema already match. `None` is an installed, empty
    /// generation; a second bootstrap does not fail on its identity receipt.
    Current {
        position: Option<ProjectionPosition>,
    },
    /// The schema, identity receipt and position-zero watermark were installed
    /// together. The caller can now fold the canonical stream from genesis.
    ReadyForFold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoredClass {
    Current {
        position: Option<ProjectionPosition>,
    },
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

/// Reconcile a session with its requested schema generation.
///
/// The request must match the session's identity: changing the number in a
/// request does not change what subsequent folds write. Construct a session
/// with the new identity for a schema upgrade, or reconcile the owned
/// connection with [`ensure_schema_generation_on`] before constructing it.
///
/// # Errors
/// Foreign bindings and inconsistent requests refuse without destructive
/// changes. Transaction/cleanup failures preserve their typed outcomes.
pub async fn ensure_schema_generation<'a, C: Connection>(
    session: &'a ProjectionSession<C>,
    cx: &Cx,
    requested_schema_generation: u32,
) -> Result<SchemaReconciliation, ProjectionError>
where
    C::Tx<'a>: TransactionOps,
{
    if requested_schema_generation != session.identity().schema_generation() {
        return Err(IdentityAdvanceError::BindingMismatch {
            field: "schema_generation",
            expected: session.identity().schema_generation().to_string(),
            observed: requested_schema_generation.to_string(),
        }.into());
    }
    ensure_schema_generation_on(session.connection_ref(), cx, session.identity()).await
}

/// Reconcile a connection against one complete, explicitly supplied identity.
///
/// This is the same implementation used by the session entry point, exposed
/// so a caller can prepare an owned connection before placing it in a new
/// schema-bound session. All schema changes and metadata are transactional.
/// The installed position-zero watermark binds even an empty projection to
/// its source; an empty database is not a license to adopt another repository.
///
/// # Errors
/// Foreign source bindings, unknown current receipts and unaccounted rows
/// without a watermark refuse. A non-successful commit response remains
/// uncertain, and rollback failure is reported rather than hidden by Drop.
pub async fn ensure_schema_generation_on<'a, C: Connection>(
    connection: &'a C,
    cx: &Cx,
    identity: &ProjectionIdentity,
) -> Result<SchemaReconciliation, ProjectionError>
where
    C::Tx<'a>: TransactionOps,
{
    let head_generation = i64::try_from(identity.authority_head_generation())
        .map_err(|_| ProjectionError::OutOfRange {
            field: "authority head generation",
            value: identity.authority_head_generation(),
            maximum: 9_223_372_036_854_775_807,
        })?;
    let expected_receipt = identity.render_receipt();
    let tx = flatten(connection.begin(cx).await, "begin_schema_reconciliation")?;
    macro_rules! checked {
        ($result:expr) => {{
            let result = $result;
            match result {
                Ok(value) => value,
                Err(error) => return Err(rollback_schema(tx, cx, error.into()).await),
            }
        }};
    }
    macro_rules! abort {
        ($error:expr) => {{
            let error: ProjectionError = $error.into();
            return Err(rollback_schema(tx, cx, error).await);
        }};
    }

    for (sql, parameters) in install_schema_statements() {
        checked!(flatten(tx.execute(cx, sql, &parameters).await, "install_schema"));
    }
    let stored = checked!(flatten(tx.query_one(
        cx,
        "SELECT source_incarnation, authority_head, authority_head_generation, \
         last_position, state_text, schema_generation \
         FROM fgit_projection_watermark WHERE singleton = 1",
        &[],
    ).await, "read_schema_watermark"));
    let receipt_row = checked!(flatten(tx.query_one(
        cx, "SELECT receipt FROM fgit_projection_identity WHERE singleton = 1", &[],
    ).await, "read_schema_identity"));
    let receipt = match receipt_row.as_ref() {
        Some(row) => Some(checked!(row.get_by_name("receipt")
            .and_then(Value::as_str)
            .ok_or(StoreReadError::MissingColumn("receipt")))),
        None => None,
    };

    let reconciliation = match stored.as_ref() {
        None => {
            // Accept the old empty-install representation only when its
            // receipt matches exactly. Unknown empty identities are not wiped.
            if let Some(receipt) = receipt
                && receipt != expected_receipt
            {
                abort!(IdentityAdvanceError::BindingMismatch {
                    field: "projection_identity",
                    expected: expected_receipt.clone(),
                    observed: receipt.to_owned(),
                });
            }
            let orphan = checked!(flatten(tx.query_one(
                cx, "SELECT seq FROM fgit_projection_applied_decision ORDER BY seq ASC LIMIT 1", &[],
            ).await, "check_empty_projection"));
            if orphan.is_some() {
                abort!(StoreReadError::MissingColumn("watermark for existing decisions"));
            }
            SchemaReconciliation::ReadyForFold
        }
        Some(row) => {
            let row = checked!(decode_watermark_row(row));
            let class = checked!(classify_stored(
                &row.source_incarnation,
                &row.authority_head,
                row.schema_generation,
                identity.schema_generation(),
                identity.source_incarnation(),
                identity.authority_head(),
            ));
            if row.authority_head_generation != identity.authority_head_generation() {
                abort!(IdentityAdvanceError::BindingMismatch {
                    field: "authority_head_generation",
                    expected: identity.authority_head_generation().to_string(),
                    observed: row.authority_head_generation.to_string(),
                });
            }
            match class {
                StoredClass::Current { .. } => {
                    let receipt = checked!(receipt.ok_or(StoreReadError::MissingColumn("receipt")));
                    if receipt != expected_receipt {
                        abort!(IdentityAdvanceError::BindingMismatch {
                            field: "projection_identity",
                            expected: expected_receipt.clone(),
                            observed: receipt.to_owned(),
                        });
                    }
                    SchemaReconciliation::Current { position: row.last_position }
                }
                StoredClass::Stale => {
                    for (sql, parameters) in teardown_statements() {
                        checked!(flatten(tx.execute(cx, sql, &parameters).await, "drop_old_projection"));
                    }
                    for (sql, parameters) in install_schema_statements() {
                        checked!(flatten(tx.execute(cx, sql, &parameters).await, "install_replacement_projection"));
                    }
                    SchemaReconciliation::ReadyForFold
                }
            }
        }
    };

    if reconciliation == SchemaReconciliation::ReadyForFold {
        checked!(flatten(tx.execute(
            cx,
            "INSERT INTO fgit_projection_watermark (singleton, source_incarnation, \
             authority_head, authority_head_generation, last_position, state_text, \
             schema_generation) VALUES (1, ?1, ?2, ?3, 0, 'fresh', ?4)",
            &[
                Value::Text(identity.source_incarnation().to_owned()),
                Value::Text(identity.authority_head().to_owned()),
                Value::BigInt(head_generation),
                Value::BigInt(i64::from(identity.schema_generation())),
            ],
        ).await, "install_empty_watermark"));
        checked!(flatten(tx.execute(
            cx,
            "INSERT INTO fgit_projection_identity (singleton, receipt) VALUES (1, ?1) \
             ON CONFLICT(singleton) DO UPDATE SET receipt = excluded.receipt",
            &[Value::Text(expected_receipt)],
        ).await, "install_identity_receipt"));
    }
    match flatten(tx.commit(cx).await, "commit_schema_reconciliation") {
        Ok(()) => Ok(reconciliation),
        Err(failure) => Err(ProjectionError::CommitUncertain { failure: Box::new(failure) }),
    }
}

async fn rollback_schema<T: TransactionOps>(
    tx: T,
    cx: &Cx,
    cause: ProjectionError,
) -> ProjectionError {
    match flatten(tx.rollback(cx).await, "rollback_schema_reconciliation") {
        Ok(()) => cause,
        Err(failure) => ProjectionError::RollbackFailed {
            cause: Some(Box::new(cause)),
            failure: Box::new(failure),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catchup::{DecisionRecord, apply_batch};
    use crate::identity::BuildIdentity;
    use crate::session::advance_within_transaction;

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
        assert!(matches!(classify_stored("other-inc", HEAD, 1, 1, INC, HEAD),
            Err(WatermarkRefusal::HeadBindingMismatch { .. })));
    }

    #[test]
    fn foreign_head_is_refused_not_wiped() {
        assert!(matches!(classify_stored(INC, "other-head", 1, 1, INC, HEAD),
            Err(WatermarkRefusal::HeadBindingMismatch { .. })));
    }

    #[test]
    fn same_binding_splits_current_from_stale() {
        assert!(matches!(classify_stored(INC, HEAD, 3, 3, INC, HEAD),
            Ok(StoredClass::Current { .. })));
        assert!(matches!(classify_stored(INC, HEAD, 3, 4, INC, HEAD), Ok(StoredClass::Stale)));
    }

    #[test]
    fn reconciliation_and_refold_round_trip_on_real_driver() {
        let node = fgit_runtime::boot::RuntimeProfile::deterministic().build().expect("node");
        let runtime = asupersync::runtime::RuntimeBuilder::new()
            .blocking_threads(1, 2).build().expect("runtime");
        let outcome: Result<(), ProjectionError> = {
            let cx = node.request_cx(fgit_runtime::meter::BudgetClass::Request);
            runtime.block_on(async {
                let session = ProjectionSession::open_memory(identity(1))?;
                assert_eq!(ensure_schema_generation(&session, &cx, 1).await?, SchemaReconciliation::ReadyForFold);
                assert_eq!(ensure_schema_generation(&session, &cx, 1).await?, SchemaReconciliation::Current { position: None });
                let records = [record(1, "d1"), record(2, "d2"), record(3, "d3")];
                let report = apply_batch(&session, &cx, &records).await?;
                assert_eq!(report.applied, 3);
                assert_eq!(report.final_position, Some(ProjectionPosition::new(3)));
                assert_eq!(ensure_schema_generation(&session, &cx, 1).await?, SchemaReconciliation::Current {
                    position: Some(ProjectionPosition::new(3)),
                });
                // A changed request with an unchanged session was formerly
                // accepted, then silently folded the old schema again.
                assert!(matches!(ensure_schema_generation(&session, &cx, 2).await,
                    Err(ProjectionError::Identity(IdentityAdvanceError::BindingMismatch {
                        field: "schema_generation", ..
                    }))));
                assert_eq!(session.load_watermark_row(&cx).await?.expect("old watermark").last_position,
                    Some(ProjectionPosition::new(3)));

                let next_identity = identity(2);
                assert_eq!(ensure_schema_generation_on(session.connection_ref(), &cx, &next_identity).await?,
                    SchemaReconciliation::ReadyForFold);
                let empty = session.load_watermark_row(&cx).await?.expect("new generation is bound even when empty");
                assert_eq!(empty.schema_generation, 2);
                assert_eq!(empty.last_position, None);
                let mut held = None;
                for record in &records {
                    held = Some(advance_within_transaction(
                        session.connection_ref(), &cx, held, record, "catching_up", 2, &next_identity,
                    ).await?);
                }
                assert_eq!(held, Some(ProjectionPosition::new(3)));
                let rebuilt = session.load_watermark_row(&cx).await?.expect("refolded watermark");
                assert_eq!(rebuilt.schema_generation, 2);
                assert_eq!(rebuilt.last_position, Some(ProjectionPosition::new(3)));
                let rows = flatten(session.connection_ref().query(
                    &cx, "SELECT seq, digest FROM fgit_projection_applied_decision ORDER BY seq ASC", &[],
                ).await, "verify_refold")?;
                assert_eq!(rows.len(), records.len());
                for (row, expected) in rows.iter().zip(&records) {
                    assert_eq!(row.get_by_name("seq").and_then(Value::as_i64),
                        Some(i64::try_from(expected.seq.get()).expect("test sequence")));
                    assert_eq!(row.get_by_name("digest").and_then(Value::as_str), Some(expected.digest.as_str()));
                }
                // An old session cannot read through the replacement schema.
                assert!(matches!(crate::model::read_applied_range(
                    &session, &cx, ProjectionPosition::new(1), ProjectionPosition::new(3),
                ).await, Err(ProjectionError::Identity(IdentityAdvanceError::BindingMismatch {
                    field: "schema_generation", ..
                }))));
                session.close(&cx).await?;
                Ok(())
            })
        };
        outcome.expect("atomic rebuild and real generation-two refold");
        assert!(runtime.shutdown_timeout(std::time::Duration::from_secs(5)));
    }

    #[test]
    fn even_empty_generations_refuse_foreign_rebuilds_and_preserve_their_receipt() {
        let node = fgit_runtime::boot::RuntimeProfile::deterministic().build().expect("node");
        let rt = asupersync::runtime::RuntimeBuilder::current_thread().build().expect("runtime");
        let result: Result<(), ProjectionError> = {
            let cx = node.request_cx(fgit_runtime::meter::BudgetClass::Request);
            rt.block_on(async {
                let session = ProjectionSession::open_memory(identity(1))?;
                ensure_schema_generation(&session, &cx, 1).await?;
                for foreign in [
                    ProjectionIdentity::new("foreign-incarnation", HEAD, 7, 1, 2, BuildIdentity::current()),
                    ProjectionIdentity::new(INC, "foreign-head", 7, 1, 2, BuildIdentity::current()),
                    ProjectionIdentity::new(INC, HEAD, 8, 1, 2, BuildIdentity::current()),
                ] {
                    assert!(ensure_schema_generation_on(session.connection_ref(), &cx, &foreign).await.is_err());
                    let stored = session.load_watermark_row(&cx).await?.expect("original empty binding survives");
                    assert_eq!(stored.source_incarnation, INC);
                    assert_eq!(stored.authority_head, HEAD);
                    assert_eq!(stored.authority_head_generation, 7);
                    assert_eq!(stored.schema_generation, 1);
                    assert_eq!(stored.last_position, None);
                    let receipt = flatten(session.connection_ref().query_one(
                        &cx, "SELECT receipt FROM fgit_projection_identity WHERE singleton = 1", &[],
                    ).await, "verify_preserved_receipt")?.expect("receipt survives");
                    assert_eq!(receipt.get_by_name("receipt").and_then(Value::as_str),
                        Some(session.identity().render_receipt().as_str()));
                }
                assert_eq!(apply_batch(&session, &cx, &[record(1, "d1")]).await?.applied, 1);
                session.close(&cx).await?;
                Ok(())
            })
        };
        result.expect("foreign rebuild refuses without erasing an empty generation");
        assert!(rt.shutdown_timeout(std::time::Duration::from_secs(5)));
    }
}
