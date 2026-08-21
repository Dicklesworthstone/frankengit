//! The SQL boundary loses nothing, and refuses rather than wrapping.

use std::sync::Arc;

use fgit_authority_fsqlite::{MarshalError, blob, unsigned};
use fsqlite::SqliteValue;

#[test]
fn bytes_cross_as_blob_and_survive_exactly() {
    for payload in [
        &b""[..],
        &b"head-1"[..],
        // Canonical bytes are not text. A value that is not valid UTF-8 must
        // cross unchanged rather than being lossily re-encoded.
        &[0xFF, 0xFE, 0x00, 0x80][..],
    ] {
        let SqliteValue::Blob(bound) = blob(payload) else {
            panic!("canonical bytes must bind as BLOB, never TEXT");
        };
        assert_eq!(&*bound, payload, "the bytes changed crossing the boundary");
    }
}

#[test]
fn a_counter_within_the_signed_range_crosses_intact() {
    for value in [0_u64, 1, 2, 4096, u64::from(u32::MAX)] {
        let bound = unsigned(value).expect("within range");
        assert_eq!(
            bound,
            SqliteValue::Integer(i64::try_from(value).expect("within range")),
            "{value} did not bind to its own signed value"
        );
    }
}

#[test]
fn the_largest_representable_counter_is_admitted() {
    // The boundary itself, admitted rather than refused, so the refusal below
    // is shown to be about representability and not about a round number.
    let largest = u64::try_from(i64::MAX).expect("i64::MAX is non-negative");
    assert_eq!(
        unsigned(largest).expect("i64::MAX is representable"),
        SqliteValue::Integer(i64::MAX)
    );
}

#[test]
fn a_counter_past_the_signed_range_is_refused_rather_than_wrapped() {
    // This is the hazard the module exists for. `value as i64` would make
    // i64::MAX + 1 into i64::MIN — a generation of -9223372036854775808, which
    // compares *below* every real generation and would let any conditional
    // replacement win. A wrapped anti-rollback counter is a silent rollback.
    let past_the_end = u64::try_from(i64::MAX).expect("non-negative") + 1;
    assert_eq!(
        unsigned(past_the_end).expect_err("wrapping would invert the ordering"),
        MarshalError::IntegerOutOfRange {
            observed: past_the_end
        }
    );
    assert_eq!(
        unsigned(u64::MAX).expect_err("the extreme is refused too"),
        MarshalError::IntegerOutOfRange { observed: u64::MAX }
    );
}

#[test]
fn the_refusal_explains_why_rather_than_just_that() {
    let refusal = unsigned(u64::MAX).expect_err("out of range");
    let text = refusal.to_string();
    assert!(
        text.contains("rollback"),
        "an operator needs to know a wrapped counter is a rollback, not a formatting nit: {text}"
    );
}

#[test]
fn a_blob_binding_is_cheap_to_clone() {
    // SqliteValue::Blob is Arc-backed, so binding the same body to several
    // statements in one transaction does not copy it each time. Asserted
    // because the schema binds head bytes twice per publication.
    let SqliteValue::Blob(first) = blob(b"head-2") else {
        panic!("expected a blob");
    };
    let second = Arc::clone(&first);
    assert_eq!(&*first, &*second);
    assert_eq!(Arc::strong_count(&first), 2);
}
