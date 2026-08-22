#![forbid(unsafe_code)]
//! Public probes for malformed cells returned by a SQL row.
//!
//! `fsqlite::Row` has no public constructor; it can only come from a query.
//! These tests target the public cell-decoder boundary that the row adapters
//! delegate to. That proves the same typed refusals without adding a fake query
//! path or exposing engine-private row construction.

use std::sync::Arc;

use fgit_authority_fsqlite::{
    MarshalError, decode_blob_column, decode_optional_unsigned_column, decode_unsigned_column,
};
use fsqlite::SqliteValue;

#[test]
fn exact_blob_and_integer_cells_are_admitted() {
    let blob = SqliteValue::Blob(Arc::from(&b"canonical\0body"[..]));
    assert_eq!(
        decode_blob_column(Some(&blob), 2).expect("a BLOB cell is admitted"),
        b"canonical\0body"
    );

    let counter = SqliteValue::Integer(i64::MAX);
    assert_eq!(
        decode_unsigned_column(Some(&counter), 4).expect("a non-negative INTEGER is admitted"),
        u64::try_from(i64::MAX).expect("i64::MAX is non-negative")
    );

    assert_eq!(
        decode_optional_unsigned_column(Some(&SqliteValue::Null), 6)
            .expect("NULL is the permitted empty-ledger result"),
        None
    );
}

#[test]
fn absent_cell_is_refused_with_its_exact_column() {
    assert_eq!(
        decode_blob_column(None, 7),
        Err(MarshalError::ColumnMissing { column: 7 })
    );
}

#[test]
fn wrong_storage_classes_are_refused_at_the_public_decoder_boundary() {
    let integer = SqliteValue::Integer(9);
    assert_eq!(
        decode_blob_column(Some(&integer), 1),
        Err(MarshalError::ColumnTypeUnexpected {
            column: 1,
            expected: "BLOB",
        })
    );

    let blob = SqliteValue::Blob(Arc::from(&b"not-a-counter"[..]));
    assert_eq!(
        decode_unsigned_column(Some(&blob), 3),
        Err(MarshalError::ColumnTypeUnexpected {
            column: 3,
            expected: "INTEGER",
        })
    );
    assert_eq!(
        decode_optional_unsigned_column(Some(&blob), 5),
        Err(MarshalError::ColumnTypeUnexpected {
            column: 5,
            expected: "INTEGER or NULL",
        })
    );
}

#[test]
fn negative_counter_is_refused_instead_of_reinterpreted_as_a_large_generation() {
    let negative = SqliteValue::Integer(-1);
    assert_eq!(
        decode_unsigned_column(Some(&negative), 8),
        Err(MarshalError::IntegerNegative {
            observed: -1,
            column: 8,
        })
    );
}
