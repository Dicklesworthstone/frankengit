//! The transactional session envelope.
//!
//! [`ProjectionSession`] is the only object that talks to the connection.
//! Every operation takes the caller's runtime-owned `&Cx` — the session never
//! mints contexts, so budget and cancellation policy stay with whoever owns
//! the request. Watermark advances happen inside one transaction together
//! with the rows they account for, which is what makes "rows without their
//! watermark" unobservable.

use asupersync::Cx;
use sqlmodel_core::{Connection, TransactionOps, Value};

use crate::catchup::ProjectionConflict;
use crate::identity::{ProjectionIdentity, ProjectionPosition};
use crate::store::{
    StoreReadError, StoredWatermarkRow, bind_position, decode_watermark_row,
    install_schema_statements,
};
use crate::watermark::WatermarkRefusal;

/// Everything that can go wrong through the session surface.
#[derive(Debug)]
pub enum ProjectionError {
    /// The driver returned a structured failure.
    Sql(sqlmodel_core::Error),
    /// The operation was cancelled or panicked through the runtime outcome.
    Interrupted(&'static str),
    /// A watermark invariant refused the transition.
    Refusal(WatermarkRefusal),
    /// Catch-up saw a conflicting digest for an applied sequence.
    Conflict(ProjectionConflict),
    /// Identity range advancement refused (gap or overflow).
    Identity(crate::identity::IdentityAdvanceError),
    /// Stored state violated its schema contract on read-back.
    Corrupt(StoreReadError),
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sql(error) => write!(f, "projection sql: {error}"),
            Self::Interrupted(what) => write!(f, "projection interrupted: {what}"),
            Self::Refusal(refusal) => write!(f, "projection refusal: {refusal}"),
            Self::Conflict(conflict) => write!(f, "projection conflict: {conflict}"),
            Self::Identity(error) => write!(f, "projection identity: {error}"),
            Self::Corrupt(error) => write!(f, "projection store corrupt: {error}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

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

impl From<crate::identity::IdentityAdvanceError> for ProjectionError {
    fn from(value: crate::identity::IdentityAdvanceError) -> Self {
        Self::Identity(value)
    }
}

impl From<StoreReadError> for ProjectionError {
    fn from(value: StoreReadError) -> Self {
        Self::Corrupt(value)
    }
}

/// Map a four-valued [`asupersync::Outcome`] to a usable result, naming the
/// non-Ok arms instead of flattening them into one error string.
pub fn flatten<T>(
    outcome: asupersync::Outcome<T, sqlmodel_core::Error>,
    step: &'static str,
) -> Result<T, ProjectionError> {
    match outcome {
        asupersync::Outcome::Ok(value) => Ok(value),
        asupersync::Outcome::Err(error) => Err(ProjectionError::Sql(error)),
        _ => Err(ProjectionError::Interrupted(step)),
    }
}

/// Transactional access to one projection database.
///
/// Generic over the admitted driver stack through
/// [`sqlmodel_core::Connection`]; construct with
/// [`ProjectionSession::open_memory`] for tests or wrap any connection that
/// implements the trait directly.
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
        Ok(Self {
            connection,
            identity,
        })
    }
}

impl<C: Connection> ProjectionSession<C> {
    #[must_use]
    pub const fn new(connection: C, identity: ProjectionIdentity) -> Self {
        Self {
            connection,
            identity,
        }
    }

    #[must_use]
    pub const fn identity(&self) -> &ProjectionIdentity {
        &self.identity
    }

    /// Named borrow of the driver connection for the catch-up loop.
    #[must_use]
    pub const fn connection_ref(&self) -> &C {
        &self.connection
    }

    /// Install the canonical meta-schema. Idempotent (`IF NOT EXISTS`).
    ///
    /// # Errors
    /// Any driver failure surfaces verbatim; statement text lives only in
    /// [`crate::store`].
    pub async fn install_schema(&self, cx: &Cx) -> Result<(), ProjectionError> {
        let statements = install_schema_statements()
            .into_iter()
            .map(|(sql, params)| (sql.to_owned(), params))
            .collect::<Vec<_>>();
        flatten(
            self.connection.batch(cx, &statements).await,
            "install_schema",
        )
        .map(|_| ())
    }

    /// Read the singleton watermark row, if the projection has advanced at
    /// least once. Fresh projections read `None`.
    ///
    /// # Errors
    /// Driver failures and schema violations are distinct variants; a missing
    /// row is `Ok(None)`, not an error.
    pub async fn load_watermark_row(
        &self,
        cx: &Cx,
    ) -> Result<Option<StoredWatermarkRow>, ProjectionError> {
        let outcome = self
            .connection
            .query_one(
                cx,
                "SELECT source_incarnation, authority_head, authority_head_generation, \
                 last_position, state_text, schema_generation \
                 FROM fgit_projection_watermark WHERE singleton = 1",
                &[],
            )
            .await;
        match flatten(outcome, "load_watermark")? {
            Some(row) => Ok(Some(decode_watermark_row(&row)?)),
            None => Ok(None),
        }
    }

    /// Persist the receipt of the current identity. Called during install so
    /// a reader can always answer "which generation am I looking at".
    ///
    /// The receipt carries the identity as constructed at install time: its
    /// closed decision range does not yet advance with folds (no caller
    /// drives [`crate::identity::ProjectionIdentity::advance_range`] yet).
    /// Until that lands with the FG-093c rebuild campaign, the authoritative
    /// completeness answer is the watermark row, not this receipt's range
    /// field.
    ///
    /// # Errors
    /// Driver failures surface verbatim.
    pub async fn persist_identity_receipt(&self, cx: &Cx) -> Result<(), ProjectionError> {
        let receipt = self.identity.render_receipt();
        flatten(
            self.connection
                .execute(
                    cx,
                    "INSERT INTO fgit_projection_identity (singleton, receipt) VALUES (1, ?1)",
                    &[Value::Text(receipt)],
                )
                .await,
            "persist_identity",
        )
        .map(|_| ())
    }
}

/// One atomic catch-up step shared by [`crate::catchup::apply_batch`]:
/// insert-or-verify the applied decision row and move the stored watermark,
/// inside a single transaction that rolls back completely on any failure.
///
/// Returns the watermark position AFTER this record: unchanged (`held`) when
/// the record was already applied with the same digest, `record.seq` when it
/// was newly folded.
///
/// # Errors
/// Driver errors, typed conflicts (digest disagreement), refusals (gap or
/// regression against the stored position), and corruption all abort the
/// transaction before commit.
///
/// The stale caller view arrives as `expected_held` purely to be re-checked
/// against what the row lock actually holds.
pub async fn advance_within_transaction<'a, C: Connection>(
    connection: &'a C,
    cx: &Cx,
    expected_held: Option<ProjectionPosition>,
    record: &crate::catchup::DecisionRecord,
    new_state_text: &str,
    schema_generation: u32,
    identity: &crate::identity::ProjectionIdentity,
) -> Result<ProjectionPosition, ProjectionError>
where
    C::Tx<'a>: TransactionOps,
{
    // The fold may only ever advance the identity it is bound to. A record
    // naming a different incarnation or head would mix two canonical streams
    // into one read model while every receipt kept claiming the original —
    // refused by name before any row moves.
    if record.source_incarnation != identity.source_incarnation() {
        return Err(crate::identity::IdentityAdvanceError::BindingMismatch {
            field: "source_incarnation",
            expected: identity.source_incarnation().to_owned(),
            observed: record.source_incarnation.clone(),
        }
        .into());
    }
    if record.authority_head != identity.authority_head() {
        return Err(crate::identity::IdentityAdvanceError::BindingMismatch {
            field: "authority_head",
            expected: identity.authority_head().to_owned(),
            observed: record.authority_head.clone(),
        }
        .into());
    }

    let tx = flatten(connection.begin(cx).await, "begin")?;

    // The stored watermark position is authoritative under the row lock;
    // callers pass their stale view only as an expectation to re-check.
    let held_row = flatten(
        tx.query_one(
            cx,
            "SELECT source_incarnation, authority_head, last_position \
             FROM fgit_projection_watermark WHERE singleton = 1",
            &[],
        )
        .await,
        "select_watermark",
    )?;
    // A stored watermark pins the binding it was folded under. This session's
    // identity must agree with it, or the database and the receipt describe
    // two different generations.
    if let Some(ref row) = held_row {
        for (field, observed) in [
            ("source_incarnation", row.get_by_name("source_incarnation")),
            ("authority_head", row.get_by_name("authority_head")),
        ] {
            let observed = observed
                .and_then(Value::as_str)
                .ok_or(StoreReadError::MissingColumn(field))?;
            let expected = match field {
                "source_incarnation" => identity.source_incarnation(),
                _ => identity.authority_head(),
            };
            if observed != expected {
                drop(tx);
                return Err(crate::identity::IdentityAdvanceError::BindingMismatch {
                    field,
                    expected: expected.to_owned(),
                    observed: observed.to_owned(),
                }
                .into());
            }
        }
    }
    let held = held_from_row(held_row.as_ref())?;
    if let Some(expected) = expected_held
        && held != Some(expected)
    {
        drop(tx);
        return Err(WatermarkRefusal::Gap {
            expected: held.unwrap_or(ProjectionPosition::genesis()),
            offered: record.seq,
        }
        .into());
    }

    // Idempotency and conflict detection against the applied prefix.
    let existing = flatten(
        tx.query_one(
            cx,
            "SELECT digest FROM fgit_projection_applied_decision WHERE seq = ?1",
            &[bind_position(record.seq)],
        )
        .await,
        "select_applied",
    )?;
    if let Some(row) = existing {
        let applied_digest = row
            .get_by_name("digest")
            .and_then(Value::as_str)
            .ok_or(StoreReadError::MissingColumn("digest"))?;
        if applied_digest == record.digest.as_str() {
            drop(tx);
            return held.ok_or(ProjectionError::Corrupt(StoreReadError::MissingColumn(
                "last_position",
            )));
        }
        drop(tx);
        return Err(ProjectionConflict {
            seq: record.seq,
            applied_digest: applied_digest.to_owned(),
            offered_digest: record.digest.clone(),
        }
        .into());
    }

    // Gap refusal against the true held position (fresh folds start at 1).
    let required_next = next_after(held);
    if record.seq != required_next {
        drop(tx);
        return Err(WatermarkRefusal::Gap {
            expected: required_next,
            offered: record.seq,
        }
        .into());
    }

    flatten(
        tx.execute(
            cx,
            "INSERT INTO fgit_projection_applied_decision (seq, digest) VALUES (?1, ?2)",
            &[
                bind_position(record.seq),
                Value::Text(record.digest.clone()),
            ],
        )
        .await,
        "insert_decision",
    )?;

    flatten(
        tx.execute(
            cx,
            "INSERT INTO fgit_projection_watermark (singleton, source_incarnation, \
             authority_head, authority_head_generation, last_position, state_text, \
             schema_generation) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(singleton) DO UPDATE SET last_position = excluded.last_position, \
             state_text = excluded.state_text",
            &[
                Value::Text(record.source_incarnation.clone()),
                Value::Text(record.authority_head.clone()),
                Value::from_u64_clamped(record.authority_head_generation),
                bind_position(record.seq),
                Value::Text(new_state_text.to_owned()),
                bind_schema_generation(schema_generation),
            ],
        )
        .await,
        "update_watermark",
    )?;

    match tx.commit(cx).await {
        asupersync::Outcome::Ok(()) => Ok(record.seq),
        asupersync::Outcome::Err(error) => Err(ProjectionError::Sql(error)),
        _ => Err(ProjectionError::Interrupted("commit")),
    }
}

fn held_from_row(
    row: Option<&sqlmodel_core::Row>,
) -> Result<Option<ProjectionPosition>, ProjectionError> {
    let Some(row) = row else {
        return Ok(None);
    };
    match row.get_by_name("last_position").and_then(Value::as_i64) {
        None | Some(0) => Ok(None),
        Some(raw) if raw > 0 => u64::try_from(raw)
            .map(|v| Some(ProjectionPosition::new(v)))
            .map_err(|_| ProjectionError::Corrupt(StoreReadError::NegativePosition(raw))),
        Some(raw) => Err(ProjectionError::Corrupt(StoreReadError::NegativePosition(
            raw,
        ))),
    }
}

#[must_use]
fn next_after(held: Option<ProjectionPosition>) -> ProjectionPosition {
    match held {
        None => ProjectionPosition::new(1),
        Some(position) => position.successor().unwrap_or(position),
    }
}

#[must_use]
fn bind_schema_generation(value: u32) -> Value {
    if let Ok(narrowed) = i32::try_from(value) {
        Value::Int(narrowed)
    } else {
        Value::Int(i32::MAX)
    }
}

/// Compile-surface note kept as a test so the boundary cannot rot silently:
/// the build identity stays a pair of static strings, and the crate carries
/// no dependency on any truth-process crate. The authority-negative boundary
/// is enforced structurally by `registries/crate_layers.tsv` plus review;
/// this pins the in-crate half where a future editor of BuildIdentity would
/// look first.
#[cfg(test)]
mod tests {
    use crate::identity::BuildIdentity;

    #[test]
    fn build_identity_is_projection_scoped() {
        let identity = BuildIdentity::current();
        assert!(!identity.crate_version.is_empty());
        assert_eq!(std::mem::size_of::<BuildIdentity>(), 2 * size_of::<&str>());
    }
}
