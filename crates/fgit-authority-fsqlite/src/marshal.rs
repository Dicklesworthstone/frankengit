//! Moving authority values across the SQL boundary without losing any.
//!
//! This looks like boilerplate and contains one genuine hazard: **the authority
//! contract counts in `u64` and SQLite counts in `i64`.** Head generations and
//! issuance sequences are unsigned; `INTEGER` is signed. A value above
//! `i64::MAX` has no representation, and the two ways to paper over that — cast
//! and wrap, or clamp — are both silent corruption of an anti-rollback counter.
//! So the conversion refuses.
//!
//! The same applies coming back. A negative integer in a generation column
//! cannot have been written by this code, so reading one means the row was
//! written by something else or the file is damaged. That is refused rather
//! than reinterpreted as a large unsigned value, which is exactly what a naive
//! `as u64` would do.
//!
//! Bodies and keys cross as `BLOB` and never as `TEXT`: canonical bytes are not
//! text, they are not guaranteed valid UTF-8, and a `STRICT` table plus a blob
//! column is what stops the engine from ever deciding otherwise.

use std::sync::Arc;

use fsqlite::{Row, SqliteValue};

/// Why a value could not cross the SQL boundary intact.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MarshalError {
    /// An unsigned value exceeds what a signed `INTEGER` column can hold.
    ///
    /// Refused rather than wrapped: this is an anti-rollback counter, and a
    /// wrapped generation is a silent rollback.
    IntegerOutOfRange {
        /// The value that has no signed representation.
        observed: u64,
    },
    /// A column held a negative integer where an unsigned value belongs.
    ///
    /// Nothing this crate writes can produce one, so the row was written by
    /// something else or the file is damaged.
    IntegerNegative {
        /// The value read.
        observed: i64,
        /// Which column.
        column: usize,
    },
    /// A head-generation column held the reserved zero value.
    ///
    /// Zero is an `INTEGER` and therefore an unsigned value, but it is not a
    /// live [`fgit_types::HeadGeneration`].  Keep this distinct from a
    /// negative column so a damaged row is reported truthfully.
    HeadGenerationZero {
        /// Which column held the reserved value.
        column: usize,
    },
    /// A column was absent from the row.
    ColumnMissing {
        /// Which column.
        column: usize,
    },
    /// A column held a different SQL type than the schema declares.
    ColumnTypeUnexpected {
        /// Which column.
        column: usize,
        /// What the schema declares.
        expected: &'static str,
    },
}

impl core::fmt::Display for MarshalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::IntegerOutOfRange { observed } => write!(
                f,
                "{observed} exceeds the signed range an INTEGER column can hold; wrapping an \
                 anti-rollback counter would be a silent rollback"
            ),
            Self::IntegerNegative { observed, column } => write!(
                f,
                "column {column} holds {observed} where an unsigned value belongs; nothing \
                 this crate writes can produce it"
            ),
            Self::HeadGenerationZero { column } => write!(
                f,
                "column {column} holds zero where a live head generation belongs; zero is \
                 reserved and this crate never publishes it"
            ),
            Self::ColumnMissing { column } => write!(f, "column {column} is absent from the row"),
            Self::ColumnTypeUnexpected { column, expected } => {
                write!(f, "column {column} is not the declared {expected}")
            }
        }
    }
}

impl std::error::Error for MarshalError {}

/// Bind opaque bytes as a `BLOB`.
///
/// Canonical bytes are never bound as `TEXT`: they are not guaranteed valid
/// UTF-8, and a round trip through text encoding would change identity.
#[must_use]
pub fn blob(bytes: &[u8]) -> SqliteValue {
    SqliteValue::Blob(Arc::from(bytes))
}

/// Bind an unsigned counter as an `INTEGER`, refusing what will not fit.
pub fn unsigned(value: u64) -> Result<SqliteValue, MarshalError> {
    // The checked conversion rather than a guarded cast: a guarded `as` is
    // correct only while the guard is, and the guard is the thing a later edit
    // removes. This cannot be wrong.
    i64::try_from(value)
        .map(SqliteValue::Integer)
        .map_err(|_| MarshalError::IntegerOutOfRange { observed: value })
}

/// Decode a `BLOB` cell at a named row column.
///
/// `fsqlite::Row` deliberately has no public constructor: rows only arise from
/// an executed query. This value-level boundary keeps that engine invariant
/// while making malformed storage facts directly testable by callers. The row
/// adapters below are one-line delegations, so production unmarshalling and
/// public refusal probes use the same classifier.
pub fn decode_blob_column(
    value: Option<&SqliteValue>,
    column: usize,
) -> Result<&[u8], MarshalError> {
    match value {
        None => Err(MarshalError::ColumnMissing { column }),
        Some(SqliteValue::Blob(bytes)) => Ok(bytes),
        Some(_) => Err(MarshalError::ColumnTypeUnexpected {
            column,
            expected: "BLOB",
        }),
    }
}

/// Decode an unsigned counter from an `INTEGER` cell at a named row column.
pub fn decode_unsigned_column(
    value: Option<&SqliteValue>,
    column: usize,
) -> Result<u64, MarshalError> {
    match value {
        None => Err(MarshalError::ColumnMissing { column }),
        Some(SqliteValue::Integer(signed)) => {
            u64::try_from(*signed).map_err(|_| MarshalError::IntegerNegative {
                observed: *signed,
                column,
            })
        }
        Some(_) => Err(MarshalError::ColumnTypeUnexpected {
            column,
            expected: "INTEGER",
        }),
    }
}

/// Read a nullable `INTEGER` column.
///
/// This exists for exactly one statement: `SELECT MAX(issued_seq)` over an
/// empty issuance ledger returns `NULL`, and that `NULL` is the signal that the
/// store has never minted a token. Collapsing it to zero would make an empty
/// ledger indistinguishable from one whose first sequence is zero — which is
/// why zero is reserved in the first place.
pub fn decode_optional_unsigned_column(
    value: Option<&SqliteValue>,
    column: usize,
) -> Result<Option<u64>, MarshalError> {
    match value {
        None => Err(MarshalError::ColumnMissing { column }),
        Some(SqliteValue::Null) => Ok(None),
        Some(SqliteValue::Integer(signed)) => {
            u64::try_from(*signed)
                .map(Some)
                .map_err(|_| MarshalError::IntegerNegative {
                    observed: *signed,
                    column,
                })
        }
        Some(_) => Err(MarshalError::ColumnTypeUnexpected {
            column,
            expected: "INTEGER or NULL",
        }),
    }
}

/// Read a `BLOB` column from an engine row.
pub fn read_blob(row: &Row, column: usize) -> Result<&[u8], MarshalError> {
    decode_blob_column(row.get(column), column)
}

/// Read an unsigned counter from an engine `INTEGER` column.
pub fn read_unsigned(row: &Row, column: usize) -> Result<u64, MarshalError> {
    decode_unsigned_column(row.get(column), column)
}

/// Read a nullable `INTEGER` column from an engine row.
pub fn read_optional_unsigned(row: &Row, column: usize) -> Result<Option<u64>, MarshalError> {
    decode_optional_unsigned_column(row.get(column), column)
}
