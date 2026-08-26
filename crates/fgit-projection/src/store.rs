//! The typed schema and parameter layer.
//!
//! All SQL this crate ever runs is emitted here, once, deterministically, and
//! golden-tested. There is no second path that formats SQL at a call site —
//! that is what "no handwritten raw-SQL side paths" means operationally for
//! the projection substrate.

use sqlmodel_core::Value;

/// One canonical statement: text plus the constant parameters it binds.
pub type CanonicalStatement = (&'static str, Vec<Value>);

/// The projection meta-schema, in install order.
///
/// `fgit_projection_watermark` is single-row by contract (`singleton = 1`);
/// `fgit_projection_applied_decision` carries the folded prefix keyed by the
/// one-based decision sequence, holding each decision's canonical digest so
/// re-delivery can be told from conflict.
#[must_use]
pub fn install_schema_statements() -> Vec<CanonicalStatement> {
    vec![
        (
            "CREATE TABLE IF NOT EXISTS fgit_projection_watermark (\
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
             source_incarnation TEXT NOT NULL,\
             authority_head TEXT NOT NULL,\
             authority_head_generation INTEGER NOT NULL,\
             last_position INTEGER NOT NULL,\
             state_text TEXT NOT NULL,\
             schema_generation INTEGER NOT NULL)",
            vec![],
        ),
        (
            "CREATE TABLE IF NOT EXISTS fgit_projection_identity (\
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),\
             receipt TEXT NOT NULL)",
            vec![],
        ),
        (
            "CREATE TABLE IF NOT EXISTS fgit_projection_applied_decision (\
             seq INTEGER PRIMARY KEY,\
             digest TEXT NOT NULL) WITHOUT ROWID",
            vec![],
        ),
    ]
}

/// The drop order for derived-state teardown. Derived tables only: nothing
/// here touches canonical history, which is what makes wipe-and-rebuild a
/// recovery strategy instead of a destructive act.
#[must_use]
pub fn teardown_statements() -> Vec<CanonicalStatement> {
    vec![
        (
            "DROP TABLE IF EXISTS fgit_projection_applied_decision",
            vec![],
        ),
        ("DROP TABLE IF EXISTS fgit_projection_watermark", vec![]),
        ("DROP TABLE IF EXISTS fgit_projection_identity", vec![]),
    ]
}

/// Bind a [`crate::identity::ProjectionPosition`] for storage.
///
/// # Panics
/// Only above `i64::MAX`, which no stream SQLite could index reaches; the
/// panic converts an impossible caller bug into loudness instead of a wrapped
/// position.
#[must_use]
pub fn bind_position(value: crate::identity::ProjectionPosition) -> Value {
    match i64::try_from(value.get()) {
        Ok(narrowed) => Value::BigInt(narrowed),
        Err(_) => panic!("projection position {} exceeds i64", value.get()),
    }
}

/// Read a position back out of a stored integer column.
///
/// # Errors
/// [`StoreReadError::NotAnInteger`] when the column does not carry an
/// integer, [`StoreReadError::NegativePosition`] when it is negative — both
/// schema violations, not data conditions.
pub fn unbind_position(
    value: &Value,
) -> Result<crate::identity::ProjectionPosition, StoreReadError> {
    let raw = value.as_i64().ok_or(StoreReadError::NotAnInteger)?;
    u64::try_from(raw)
        .map(crate::identity::ProjectionPosition::new)
        .map_err(|_| StoreReadError::NegativePosition(raw))
}

/// Typed failures of reading projection state back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreReadError {
    NotAnInteger,
    NegativePosition(i64),
    MissingColumn(&'static str),
}

impl std::fmt::Display for StoreReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnInteger => f.write_str("expected integer column"),
            Self::NegativePosition(raw) => write!(f, "negative position {raw}"),
            Self::MissingColumn(name) => write!(f, "missing column {name}"),
        }
    }
}

impl std::error::Error for StoreReadError {}

/// The singleton watermark row after a successful fold step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWatermarkRow {
    pub source_incarnation: String,
    pub authority_head: String,
    pub authority_head_generation: u64,
    /// `None` means "installed, nothing folded" (stored position 0).
    pub last_position: Option<crate::identity::ProjectionPosition>,
    pub state_text: String,
    pub schema_generation: u32,
}

/// Decode a watermark row returned by
/// [`super::session::ProjectionSession::load_watermark_row`].
///
/// # Errors
/// [`StoreReadError::MissingColumn`] when the row lacks a required column;
/// [`StoreReadError::NegativePosition`] when stored counters are negative.
pub fn decode_watermark_row(
    row: &sqlmodel_core::Row,
) -> Result<StoredWatermarkRow, StoreReadError> {
    let text = |name: &'static str| -> Result<String, StoreReadError> {
        row.get_by_name(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(StoreReadError::MissingColumn(name))
    };
    let int = |name: &'static str| -> Result<i64, StoreReadError> {
        row.get_by_name(name)
            .and_then(Value::as_i64)
            .ok_or(StoreReadError::MissingColumn(name))
    };

    let source_incarnation = text("source_incarnation")?;
    let authority_head = text("authority_head")?;

    let generation_raw = int("authority_head_generation")?;
    let authority_head_generation = u64::try_from(generation_raw)
        .map_err(|_| StoreReadError::NegativePosition(generation_raw))?;

    let last_raw = int("last_position")?;
    let last_position = match last_raw {
        0 => None,
        positive => {
            let widened =
                u64::try_from(positive).map_err(|_| StoreReadError::NegativePosition(positive))?;
            Some(crate::identity::ProjectionPosition::new(widened))
        }
    };

    let state_text = text("state_text")?;

    let schema_raw = int("schema_generation")?;
    let schema_generation =
        u32::try_from(schema_raw).map_err(|_| StoreReadError::NegativePosition(schema_raw))?;

    Ok(StoredWatermarkRow {
        source_incarnation,
        authority_head,
        authority_head_generation,
        last_position,
        state_text,
        schema_generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ProjectionPosition;

    #[test]
    fn schema_statements_are_canonical_and_unparameterized() {
        let statements = install_schema_statements();
        assert_eq!(statements.len(), 3);
        assert!(
            statements[0]
                .0
                .starts_with("CREATE TABLE IF NOT EXISTS fgit_projection_watermark")
        );
        assert!(statements[1].0.contains("receipt TEXT NOT NULL"));
        assert!(statements[2].0.ends_with("WITHOUT ROWID"));
        // Constant statements bind nothing; parameters live at call time only.
        assert!(statements.iter().all(|(_, params)| params.is_empty()));
    }

    #[test]
    fn teardown_drops_derived_tables_child_first() {
        let drops = teardown_statements();
        assert_eq!(drops.len(), 3);
        assert!(drops[0].0.contains("fgit_projection_applied_decision"));
        assert!(drops[2].0.contains("fgit_projection_identity"));
        assert!(drops.iter().all(|(_, params)| params.is_empty()));
    }

    #[test]
    fn positions_round_trip_and_refuse_junk() {
        let pos = ProjectionPosition::new(42);
        assert_eq!(unbind_position(&bind_position(pos)), Ok(pos));
        assert_eq!(
            unbind_position(&Value::Text("42".to_owned())),
            Err(StoreReadError::NotAnInteger)
        );
        assert_eq!(
            unbind_position(&Value::Int(-7)),
            Err(StoreReadError::NegativePosition(-7))
        );
    }
}
