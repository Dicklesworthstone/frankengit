//! The engine's real errors map onto the closed transient family correctly.
//!
//! These construct genuine `FrankenError` values rather than a stand-in, so the
//! mapping is tested against the type the adapter will actually receive. The
//! important half is the negative one: nothing outside §3.4's seven classes may
//! become a retry, because a corrupt database classified as "busy" is an
//! infinite loop rather than an error.

use std::path::PathBuf;

use fgit_authority_fsqlite::{TransientClass, classify_franken_error, is_retryable_engine_error};
use fsqlite::FrankenError;

#[test]
fn the_seven_admitted_classes_map_to_themselves_and_are_retryable() {
    let cases: Vec<(FrankenError, TransientClass)> = vec![
        (FrankenError::Busy, TransientClass::Busy),
        (FrankenError::BusyRecovery, TransientClass::BusyRecovery),
        (
            FrankenError::BusySnapshot {
                conflicting_pages: "3,4".to_owned(),
            },
            TransientClass::BusySnapshot,
        ),
        (
            FrankenError::DatabaseLocked {
                path: PathBuf::from("/tmp/authority.db"),
            },
            TransientClass::DatabaseLocked,
        ),
        (
            FrankenError::WriteConflict {
                page: 7,
                holder: 42,
            },
            TransientClass::WriteConflict,
        ),
        (
            FrankenError::SerializationFailure { page: 9 },
            TransientClass::SerializationFailure,
        ),
        (
            FrankenError::PageBufferCapacityExhausted {
                operation: "commit",
                page_size: 4096,
                max_buffers: 16,
                total_buffers: 16,
                available_buffers: 0,
                cached_clean: 4,
                cached_dirty: 12,
                successful_evictions: 0,
            },
            TransientClass::PageBufferCapacityExhausted,
        ),
    ];

    assert_eq!(
        cases.len(),
        TransientClass::RETRYABLE.len(),
        "every admitted class needs a case here"
    );

    for (error, expected) in cases {
        let observed = classify_franken_error(&error);
        assert_eq!(
            observed, expected,
            "{error:?} classified as {observed:?}, expected {expected:?}"
        );
        assert!(
            is_retryable_engine_error(&error),
            "{error:?} is one of the seven and must be retryable"
        );
    }
}

#[test]
fn a_stale_snapshot_is_its_own_class_and_is_not_retryable() {
    let error = FrankenError::SnapshotTooOld { txn_id: 11 };
    assert_eq!(
        classify_franken_error(&error),
        TransientClass::FreshSnapshotRequired,
        "SnapshotTooOld needs a fresh transaction, not a retry in place"
    );
    assert!(
        !is_retryable_engine_error(&error),
        "retrying a stale snapshot in place turns a stale read into an unbounded spin"
    );
}

#[test]
fn nothing_outside_the_family_is_ever_converted_into_busy() {
    // §3.4 names these explicitly as things that must not become "busy". Each
    // one here is a real engine error, and each must classify as permanent.
    let permanent: Vec<FrankenError> = vec![
        // corruption
        FrankenError::DatabaseCorrupt {
            detail: "page checksum mismatch".to_owned(),
        },
        // schema
        FrankenError::SchemaChanged,
        // constraint
        FrankenError::UniqueViolation {
            columns: "body_key".to_owned(),
        },
        FrankenError::CheckViolation {
            name: "singleton".to_owned(),
        },
        // invariant failure
        FrankenError::NestedTransaction,
        FrankenError::NoActiveTransaction,
        FrankenError::MultiProcessContractViolation {
            detail: "two writers, one file".to_owned(),
        },
        // permanent I/O
        FrankenError::IoWrite { page: 12 },
        // resource ceiling
        FrankenError::DatabaseFull,
    ];

    for error in permanent {
        let observed = classify_franken_error(&error);
        assert_eq!(
            observed,
            TransientClass::Permanent,
            "{error:?} must not be retried; it classified as {observed:?}"
        );
        assert!(!is_retryable_engine_error(&error));
    }
}

#[test]
fn an_unrecognised_error_defaults_to_permanent_rather_than_retryable() {
    // The direction of the default is the whole safety property: a variant this
    // build has never seen must stop the operation, not spin on it. Corrupt
    // stands in for "some error the mapping does not name".
    let unnamed = FrankenError::NotADatabase {
        path: std::path::PathBuf::from("/tmp/not-a-database"),
    };
    assert_eq!(classify_franken_error(&unnamed), TransientClass::Permanent);
    assert!(
        !is_retryable_engine_error(&unnamed),
        "the default must be permanent; a retryable catch-all turns corruption into a loop"
    );
}

#[test]
fn the_classifier_agrees_with_the_law_it_implements() {
    // The law (TransientClass::RETRYABLE) and the mapping are separate pieces
    // and could drift. Every class the classifier can produce for a retryable
    // engine error must be a member of the declared family.
    for error in [
        FrankenError::Busy,
        FrankenError::BusyRecovery,
        FrankenError::BusySnapshot {
            conflicting_pages: String::new(),
        },
        FrankenError::DatabaseLocked {
            path: PathBuf::new(),
        },
        FrankenError::WriteConflict { page: 0, holder: 0 },
        FrankenError::SerializationFailure { page: 0 },
        FrankenError::SnapshotTooOld { txn_id: 0 },
    ] {
        let class = classify_franken_error(&error);
        assert_eq!(
            class.is_retryable(),
            TransientClass::RETRYABLE.contains(&class),
            "{class:?} disagrees with the declared retryable family"
        );
    }
}

#[test]
fn an_indeterminate_publication_is_neither_retried_nor_called_a_failure() {
    // The engine says in its own documentation that this outcome "could not
    // prove either an exact rollback or a committed candidate", and its error
    // class tells callers to reconcile from fresh handles before retrying or
    // deleting. Retrying it may double-apply; calling it permanent claims a
    // non-commit the engine explicitly refused to claim.
    let error = FrankenError::DatabaseImagePublicationOutcomeIndeterminate {
        detail: "durability boundary crossed".to_owned(),
    };
    assert_eq!(
        classify_franken_error(&error),
        TransientClass::OutcomeIndeterminate,
        "an indeterminate outcome is an ambiguity, not a failure and not a retry"
    );
    assert!(
        !is_retryable_engine_error(&error),
        "retrying a transaction that may have committed would double-apply it"
    );
    assert_ne!(
        classify_franken_error(&error),
        TransientClass::Permanent,
        "permanent would tell the caller nothing happened when something may have"
    );
}

#[test]
fn a_definite_rollback_is_permanent_rather_than_indeterminate() {
    // The contrast that makes the previous test meaningful: when the engine can
    // prove the transaction did not apply, that is not an ambiguity.
    let error = FrankenError::TransactionRolledBack {
        reason: "explicit rollback".to_owned(),
    };
    assert_eq!(classify_franken_error(&error), TransientClass::Permanent);
    assert!(!is_retryable_engine_error(&error));
}
