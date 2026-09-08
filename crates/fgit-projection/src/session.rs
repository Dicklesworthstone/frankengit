//! The transactional session envelope.
//!
//! Every operation inherits the caller's runtime-owned `&Cx`. A transaction
//! is finalized by an awaited commit or rollback, never by claiming that Drop
//! proved an abort. Failed commit responses retain uncertainty; failed cleanup
//! retains both failures so the owner can contain and retire the connection.

use asupersync::{CancelReason, Cx, PanicPayload};
use sqlmodel_core::{Connection, TransactionOps, Value};

use crate::catchup::ProjectionConflict;
use crate::identity::{IdentityAdvanceError, ProjectionIdentity, ProjectionPosition};
use crate::store::{
    StoreReadError, StoredWatermarkRow, bind_position, decode_watermark_row,
    install_schema_statements,
};
use crate::watermark::WatermarkRefusal;

/// Everything that can go wrong through the session surface.
#[derive(Debug)]
pub enum ProjectionError {
    /// The driver returned a structured failure before a commit response.
    Sql(sqlmodel_core::Error),
    /// Legacy compatibility variant. New runtime outcomes use the distinct
    /// `Cancelled` and `Panicked` variants below.
    Interrupted(&'static str),
    /// Cancellation retains the runtime's reason and the interrupted step.
    Cancelled {
        step: &'static str,
        reason: Box<CancelReason>,
    },
    /// A caught panic is not a cancellation or a retryable database error.
    Panicked {
        step: &'static str,
        payload: PanicPayload,
    },
    /// The driver consumed the transaction but did not acknowledge commit.
    /// Resolve the stored prefix using a healthy connection before deciding
    /// whether to replay; this is not evidence of non-commit.
    CommitUncertain {
        failure: Box<ProjectionError>,
    },
    /// Rollback did not acknowledge cleanup. `cause` is absent for a failed
    /// replay-only rollback. Do not reuse this connection as if it were clean.
    RollbackFailed {
        cause: Option<Box<ProjectionError>>,
        failure: Box<ProjectionError>,
    },
    /// A caller counter cannot be represented exactly by the storage schema.
    OutOfRange {
        field: &'static str,
        value: u64,
        maximum: u64,
    },
    /// A watermark invariant refused the transition.
    Refusal(WatermarkRefusal),
    /// Catch-up saw a conflicting digest for an applied sequence.
    Conflict(ProjectionConflict),
    /// Identity range advancement or generation binding refused.
    Identity(IdentityAdvanceError),
    /// Stored state violated its schema contract on read-back.
    Corrupt(StoreReadError),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sql(error) => write!(f, "projection sql: {error}"),
            Self::Interrupted(what) => write!(f, "projection interrupted: {what}"),
            Self::Cancelled { step, reason } => {
                write!(f, "projection cancelled at {step}: {reason:?}")
            }
            Self::Panicked { step, payload } => {
                write!(f, "projection panicked at {step}: {payload}")
            }
            Self::CommitUncertain { failure } => {
                write!(f, "projection commit outcome uncertain: {failure}")
            }
            Self::RollbackFailed { cause, failure } => {
                write!(f, "projection rollback failed: {failure}")?;
                if let Some(cause) = cause {
                    write!(f, "; original failure: {cause}")?;
                }
                Ok(())
            }
            Self::OutOfRange { field, value, maximum } => {
                write!(f, "projection {field} {value} exceeds storage maximum {maximum}")
            }
            Self::Refusal(refusal) => write!(f, "projection refusal: {refusal}"),
            Self::Conflict(conflict) => write!(f, "projection conflict: {conflict}"),
            Self::Identity(error) => write!(f, "projection identity: {error}"),
            Self::Corrupt(error) => write!(f, "projection store corrupt: {error}"),
        }
    }
}

impl std::error::Error for ProjectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sql(error) => Some(error),
            Self::CommitUncertain { failure } | Self::RollbackFailed { failure, .. } => {
                Some(failure.as_ref())
            }
            Self::Refusal(error) => Some(error),
            Self::Conflict(error) => Some(error),
            Self::Identity(error) => Some(error),
            Self::Corrupt(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WatermarkRefusal> for ProjectionError {
    fn from(value: WatermarkRefusal) -> Self {
        Self::Refusal(value)
    }
}

impl From<ProjectionConflict> for ProjectionError {
    fn from(value: ProjectionConflict) -> Self {
        Self::Conflict(value)
    }
}

impl From<IdentityAdvanceError> for ProjectionError {
    fn from(value: IdentityAdvanceError) -> Self {
        Self::Identity(value)
    }
}

impl From<StoreReadError> for ProjectionError {
    fn from(value: StoreReadError) -> Self {
        Self::Corrupt(value)
    }
}

/// Adapt a runtime outcome without discarding its four-way distinction.
/// Cancellation and panic remain typed and retain their original payloads.
pub fn flatten<T>(
    outcome: asupersync::Outcome<T, sqlmodel_core::Error>,
    step: &'static str,
) -> Result<T, ProjectionError> {
    match outcome {
        asupersync::Outcome::Ok(value) => Ok(value),
        asupersync::Outcome::Err(error) => Err(ProjectionError::Sql(error)),
        asupersync::Outcome::Cancelled(reason) => Err(ProjectionError::Cancelled {
            step,
            reason: Box::new(reason),
        }),
        asupersync::Outcome::Panicked(payload) => {
            Err(ProjectionError::Panicked { step, payload })
        }
    }
}

/// Transactional access to one projection database.
pub struct ProjectionSession<C: Connection> {
    connection: C,
    identity: ProjectionIdentity,
}

impl ProjectionSession<sqlmodel_frankensqlite::FrankenConnection> {
    /// Open an in-memory projection database bound to `identity`.
    ///
    /// # Errors
    /// Driver open failures surface as [`ProjectionError::Sql`].
    pub fn open_memory(identity: ProjectionIdentity) -> Result<Self, ProjectionError> {
        let connection = sqlmodel_frankensqlite::FrankenConnection::open_memory()
            .map_err(ProjectionError::Sql)?;
        Ok(Self { connection, identity })
    }
}

impl<C: Connection> ProjectionSession<C> {
    #[must_use]
    pub const fn new(connection: C, identity: ProjectionIdentity) -> Self {
        Self { connection, identity }
    }

    /// The installation binding. Query the stored watermark for progress.
    #[must_use]
    pub const fn identity(&self) -> &ProjectionIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn connection_ref(&self) -> &C {
        &self.connection
    }

    /// Consume the session and await the driver's explicit close operation.
    /// The driver owns worker teardown; this method does not manufacture a
    /// separate runtime or pretend that dropping a handle proves shutdown.
    ///
    /// # Errors
    /// The driver's close failure is preserved.
    pub async fn close(self, cx: &Cx) -> Result<(), ProjectionError> {
        self.connection.close(cx).await.map_err(ProjectionError::Sql)
    }

    /// Install the canonical meta-schema idempotently.
    ///
    /// # Errors
    /// Driver errors, cancellation and panic retain their distinct variants.
    pub async fn install_schema(&self, cx: &Cx) -> Result<(), ProjectionError> {
        let statements = install_schema_statements()
            .into_iter()
            .map(|(sql, params)| (sql.to_owned(), params))
            .collect::<Vec<_>>();
        flatten(self.connection.batch(cx, &statements).await, "install_schema").map(|_| ())
    }

    /// Read the stored singleton watermark. A fresh projection has no row.
    ///
    /// # Errors
    /// Driver failures and schema violations are distinct variants.
    pub async fn load_watermark_row(
        &self,
        cx: &Cx,
    ) -> Result<Option<StoredWatermarkRow>, ProjectionError> {
        let outcome = self.connection.query_one(
            cx,
            "SELECT source_incarnation, authority_head, authority_head_generation, \
             last_position, state_text, schema_generation \
             FROM fgit_projection_watermark WHERE singleton = 1",
            &[],
        ).await;
        match flatten(outcome, "load_watermark")? {
            Some(row) => Ok(Some(decode_watermark_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Persist the installation identity receipt.
    ///
    /// Its range is the installation range, not the current fold position;
    /// completeness is still answered by the transactional watermark.
    ///
    /// # Errors
    /// Driver failures surface verbatim.
    pub async fn persist_identity_receipt(&self, cx: &Cx) -> Result<(), ProjectionError> {
        let receipt = self.identity.render_receipt();
        flatten(
            self.connection.execute(
                cx,
                "INSERT INTO fgit_projection_identity (singleton, receipt) VALUES (1, ?1)",
                &[Value::Text(receipt)],
            ).await,
            "persist_identity",
        ).map(|_| ())
    }
}

/// Insert-or-verify one decision and advance its watermark atomically.
///
/// Every pre-commit exit awaits rollback, including no-op replays. Rollback
/// failures preserve the original cause and require connection containment.
/// A non-successful commit response is explicitly uncertain, never a claim
/// that the decision was not stored. There are no statement-level retries.
///
/// # Errors
/// Conflicts, stale snapshots, gaps, foreign bindings and unrepresentable
/// counters refuse. Driver errors, cancellation, panic, failed rollback and
/// commit uncertainty remain distinguishable.
pub async fn advance_within_transaction<'a, C: Connection>(
    connection: &'a C,
    cx: &Cx,
    expected_held: Option<ProjectionPosition>,
    record: &crate::catchup::DecisionRecord,
    new_state_text: &str,
    schema_generation: u32,
    identity: &ProjectionIdentity,
) -> Result<ProjectionPosition, ProjectionError>
where
    C::Tx<'a>: TransactionOps,
{
    check_record_binding(record, schema_generation, identity)?;
    if record.seq == ProjectionPosition::genesis() {
        return Err(WatermarkRefusal::Gap {
            expected: ProjectionPosition::new(1),
            offered: record.seq,
        }.into());
    }
    checked_sql_counter("decision sequence", record.seq.get())?;
    let head_generation = checked_sql_counter(
        "authority head generation", record.authority_head_generation,
    )?;
    let tx = flatten(connection.begin(cx).await, "begin")?;

    // Keeping ownership in this function avoids requiring TransactionOps to
    // be Sync. Every error after BEGIN must pass through the same awaited
    // finalizer; query futures are dropped before moving the transaction.
    macro_rules! checked {
        ($result:expr) => {{
            let result = $result;
            match result {
                Ok(value) => value,
                Err(error) => return Err(rollback_error(tx, cx, error.into()).await),
            }
        }};
    }
    macro_rules! abort {
        ($error:expr) => {{
            let error: ProjectionError = $error.into();
            return Err(rollback_error(tx, cx, error).await);
        }};
    }

    let held_row = checked!(flatten(tx.query_one(
        cx,
        "SELECT source_incarnation, authority_head, authority_head_generation, \
         last_position, state_text, schema_generation \
         FROM fgit_projection_watermark WHERE singleton = 1",
        &[],
    ).await, "select_watermark"));
    let held = match held_row.as_ref() {
        Some(row) => {
            let watermark = checked!(decode_watermark_row(row));
            checked!(check_watermark_binding(identity, &watermark));
            watermark.last_position
        }
        None => None,
    };
    // None is an expected empty snapshot, not permission to accept whatever
    // another folder installed since the caller read it.
    if expected_held != held {
        abort!(WatermarkRefusal::Gap {
            expected: held.unwrap_or(ProjectionPosition::genesis()),
            offered: record.seq,
        });
    }

    let existing = checked!(flatten(tx.query_one(
        cx,
        "SELECT digest FROM fgit_projection_applied_decision WHERE seq = ?1",
        &[bind_position(record.seq)],
    ).await, "select_applied"));
    if let Some(row) = existing {
        let applied_digest = checked!(row.get_by_name("digest")
            .and_then(Value::as_str)
            .ok_or(StoreReadError::MissingColumn("digest")));
        let Some(position) = held else {
            abort!(StoreReadError::MissingColumn("watermark for applied decision"));
        };
        if record.seq > position {
            abort!(WatermarkRefusal::Gap {
                expected: checked!(next_after(held)),
                offered: record.seq,
            });
        }
        if applied_digest != record.digest {
            abort!(ProjectionConflict {
                seq: record.seq,
                applied_digest: applied_digest.to_owned(),
                offered_digest: record.digest.clone(),
            });
        }
        return match flatten(tx.rollback(cx).await, "rollback_replay") {
            Ok(()) => Ok(position),
            Err(failure) => Err(ProjectionError::RollbackFailed {
                cause: None,
                failure: Box::new(failure),
            }),
        };
    }

    let required_next = checked!(next_after(held));
    if record.seq != required_next {
        abort!(WatermarkRefusal::Gap {
            expected: required_next,
            offered: record.seq,
        });
    }
    checked!(flatten(tx.execute(
        cx,
        "INSERT INTO fgit_projection_applied_decision (seq, digest) VALUES (?1, ?2)",
        &[bind_position(record.seq), Value::Text(record.digest.clone())],
    ).await, "insert_decision"));
    checked!(flatten(tx.execute(
        cx,
        "INSERT INTO fgit_projection_watermark (singleton, source_incarnation, \
         authority_head, authority_head_generation, last_position, state_text, \
         schema_generation) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(singleton) DO UPDATE SET last_position = excluded.last_position, \
         state_text = excluded.state_text",
        &[
            Value::Text(record.source_incarnation.clone()),
            Value::Text(record.authority_head.clone()),
            Value::BigInt(head_generation),
            bind_position(record.seq),
            Value::Text(new_state_text.to_owned()),
            Value::BigInt(i64::from(schema_generation)),
        ],
    ).await, "update_watermark"));
    match flatten(tx.commit(cx).await, "commit") {
        Ok(()) => Ok(record.seq),
        Err(failure) => Err(ProjectionError::CommitUncertain {
            failure: Box::new(failure),
        }),
    }
}

async fn rollback_error<T: TransactionOps>(
    tx: T,
    cx: &Cx,
    cause: ProjectionError,
) -> ProjectionError {
    match flatten(tx.rollback(cx).await, "rollback") {
        Ok(()) => cause,
        Err(failure) => ProjectionError::RollbackFailed {
            cause: Some(Box::new(cause)),
            failure: Box::new(failure),
        },
    }
}

fn checked_sql_counter(field: &'static str, value: u64) -> Result<i64, ProjectionError> {
    i64::try_from(value).map_err(|_| ProjectionError::OutOfRange {
        field,
        value,
        maximum: 9_223_372_036_854_775_807,
    })
}

fn next_after(held: Option<ProjectionPosition>) -> Result<ProjectionPosition, ProjectionError> {
    held.unwrap_or(ProjectionPosition::genesis())
        .successor()
        .ok_or_else(|| IdentityAdvanceError::Overflow.into())
}

fn check_record_binding(
    record: &crate::catchup::DecisionRecord,
    schema_generation: u32,
    identity: &ProjectionIdentity,
) -> Result<(), ProjectionError> {
    for (field, expected, observed) in [
        ("source_incarnation", identity.source_incarnation().to_owned(), record.source_incarnation.clone()),
        ("authority_head", identity.authority_head().to_owned(), record.authority_head.clone()),
        ("authority_head_generation", identity.authority_head_generation().to_string(), record.authority_head_generation.to_string()),
        ("schema_generation", identity.schema_generation().to_string(), schema_generation.to_string()),
    ] {
        if expected != observed {
            return Err(IdentityAdvanceError::BindingMismatch { field, expected, observed }.into());
        }
    }
    Ok(())
}

pub(crate) fn check_watermark_binding(
    identity: &ProjectionIdentity,
    watermark: &StoredWatermarkRow,
) -> Result<(), ProjectionError> {
    for (field, expected, observed) in [
        ("source_incarnation", identity.source_incarnation().to_owned(), watermark.source_incarnation.clone()),
        ("authority_head", identity.authority_head().to_owned(), watermark.authority_head.clone()),
        ("authority_head_generation", identity.authority_head_generation().to_string(), watermark.authority_head_generation.to_string()),
        ("schema_generation", identity.schema_generation().to_string(), watermark.schema_generation.to_string()),
    ] {
        if expected != observed {
            return Err(IdentityAdvanceError::BindingMismatch { field, expected, observed }.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catchup::{DecisionRecord, apply_batch};
    use crate::identity::BuildIdentity;

    #[test]
    fn build_identity_is_projection_scoped() {
        let identity = BuildIdentity::current();
        assert!(!identity.crate_version.is_empty());
        assert_eq!(std::mem::size_of::<BuildIdentity>(), 2 * size_of::<&str>());
    }

    #[test]
    fn runtime_outcomes_keep_their_distinct_payloads() {
        assert_eq!(flatten(asupersync::Outcome::Ok(42), "read").expect("success"), 42);
        let sql = flatten::<()>(
            asupersync::Outcome::Err(sqlmodel_core::Error::Custom("driver failure".to_owned())),
            "query",
        ).expect_err("SQL error");
        assert!(matches!(sql, ProjectionError::Sql(sqlmodel_core::Error::Custom(ref message))
            if message == "driver failure"));
        let reason = CancelReason::timeout();
        let cancelled = flatten::<()>(asupersync::Outcome::Cancelled(reason.clone()), "select")
            .expect_err("cancellation");
        assert!(matches!(cancelled, ProjectionError::Cancelled { step: "select", reason: actual }
            if *actual == reason));
        let payload = PanicPayload::new("worker panic");
        let panicked = flatten::<()>(asupersync::Outcome::Panicked(payload.clone()), "commit")
            .expect_err("panic");
        assert!(matches!(panicked, ProjectionError::Panicked { step: "commit", payload: actual }
            if actual == payload));
    }

    #[test]
    fn integer_bounds_never_saturate_or_wrap() {
        assert_eq!(checked_sql_counter("seq", 0).expect("zero"), 0);
        assert_eq!(checked_sql_counter("seq", 9_223_372_036_854_775_807).expect("max"), i64::MAX);
        assert!(matches!(checked_sql_counter("seq", u64::MAX),
            Err(ProjectionError::OutOfRange { field: "seq", value: u64::MAX, .. })));
        assert!(matches!(next_after(Some(ProjectionPosition::new(u64::MAX))),
            Err(ProjectionError::Identity(IdentityAdvanceError::Overflow))));
    }

    fn identity(schema: u32, generation: u64) -> ProjectionIdentity {
        ProjectionIdentity::new("inc-session", "head-session", generation, 1, schema, BuildIdentity::current())
    }

    fn record(seq: u64) -> DecisionRecord {
        DecisionRecord {
            seq: ProjectionPosition::new(seq),
            digest: format!("d{seq}"),
            source_incarnation: "inc-session".to_owned(),
            authority_head: "head-session".to_owned(),
            authority_head_generation: 7,
        }
    }

    #[test]
    fn failed_watermark_write_rolls_back_the_insert_and_connection_remains_usable() {
        let node = fgit_runtime::boot::RuntimeProfile::deterministic().build().expect("node");
        let rt = asupersync::runtime::RuntimeBuilder::current_thread().build().expect("runtime");
        let result: Result<(), ProjectionError> = {
            let cx = node.request_cx(fgit_runtime::meter::BudgetClass::Request);
            rt.block_on(async {
                let session = ProjectionSession::open_memory(identity(1, 7))?;
                session.install_schema(&cx).await?;
                flatten(session.connection_ref().execute(
                    &cx, "DROP TABLE fgit_projection_watermark", &[],
                ).await, "test_drop")?;
                flatten(session.connection_ref().execute(
                    &cx,
                    "CREATE TABLE fgit_projection_watermark (singleton INTEGER PRIMARY KEY, \
                     source_incarnation TEXT NOT NULL, authority_head TEXT NOT NULL, \
                     authority_head_generation INTEGER NOT NULL, last_position INTEGER NOT NULL, \
                     state_text TEXT NOT NULL CHECK (state_text = 'catching_up'), \
                     schema_generation INTEGER NOT NULL)",
                    &[],
                ).await, "test_schema")?;
                let error = advance_within_transaction(
                    session.connection_ref(), &cx, None, &record(1), "invalid-state", 1, session.identity(),
                ).await.expect_err("constraint fails after inserting the decision");
                assert!(matches!(error, ProjectionError::Sql(_)));
                let orphan = flatten(session.connection_ref().query_one(
                    &cx, "SELECT digest FROM fgit_projection_applied_decision WHERE seq = 1", &[],
                ).await, "check_rollback")?;
                assert!(orphan.is_none(), "failed fold must not leave an applied row");
                assert_eq!(session.load_watermark_row(&cx).await?, None);
                assert_eq!(apply_batch(&session, &cx, &[record(1)]).await?.applied, 1);
                assert_eq!(apply_batch(&session, &cx, &[record(1)]).await?.idempotent_replays, 1);
                assert_eq!(apply_batch(&session, &cx, &[record(2)]).await?.applied, 1);
                session.close(&cx).await?;
                Ok(())
            })
        };
        result.expect("rollback and replay finalize before the next transaction");
        assert!(rt.shutdown_timeout(std::time::Duration::from_secs(5)));
    }

    #[test]
    fn full_generations_and_stale_empty_snapshots_are_checked_under_the_transaction() {
        let node = fgit_runtime::boot::RuntimeProfile::deterministic().build().expect("node");
        let rt = asupersync::runtime::RuntimeBuilder::current_thread().build().expect("runtime");
        let result: Result<(), ProjectionError> = {
            let cx = node.request_cx(fgit_runtime::meter::BudgetClass::Request);
            rt.block_on(async {
                let session = ProjectionSession::open_memory(identity(u32::MAX, 7))?;
                session.install_schema(&cx).await?;
                apply_batch(&session, &cx, &[record(1)]).await?;
                assert_eq!(session.load_watermark_row(&cx).await?.expect("watermark").schema_generation, u32::MAX);
                let stale = advance_within_transaction(
                    session.connection_ref(), &cx, None, &record(2), "catching_up", u32::MAX, session.identity(),
                ).await.expect_err("another folder advanced an expected-empty snapshot");
                assert!(matches!(stale, ProjectionError::Refusal(WatermarkRefusal::Gap { .. })));
                let foreign = identity(u32::MAX, 8);
                let offered = DecisionRecord { authority_head_generation: 8, ..record(2) };
                let error = advance_within_transaction(
                    session.connection_ref(), &cx, Some(ProjectionPosition::new(1)), &offered,
                    "catching_up", u32::MAX, &foreign,
                ).await.expect_err("stored head generation must match, not just its text");
                assert!(matches!(error, ProjectionError::Identity(
                    IdentityAdvanceError::BindingMismatch { field: "authority_head_generation", .. }
                )));
                assert_eq!(apply_batch(&session, &cx, &[record(2)]).await?.applied, 1);
                let overflow = apply_batch(&session, &cx, &[record(u64::MAX)]).await.expect_err("typed range error");
                assert!(matches!(overflow, ProjectionError::OutOfRange { field: "decision sequence", .. }));
                assert_eq!(session.load_watermark_row(&cx).await?.expect("watermark").last_position, Some(ProjectionPosition::new(2)));
                session.close(&cx).await?;
                Ok(())
            })
        };
        result.expect("generation binding and exact integer storage");
        assert!(rt.shutdown_timeout(std::time::Duration::from_secs(5)));
    }
}
