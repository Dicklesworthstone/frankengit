#![forbid(unsafe_code)]

//! frankengit-nuox: `BatchBounds::try_new`'s zero guards and the order between them.
//!
//! A microbatch bound of zero is not a small batch, it is a combiner that can
//! never admit anything — the constructor refuses rather than letting a caller
//! build one. Two checks run in sequence (`combiner/mod.rs:45` and `:49`):
//!
//! ```text
//! :46  decision_limit == 0  -> ZeroDecisionLimit
//! :50  byte_ceiling  == 0   -> ZeroByteLimit
//! ```
//!
//! `ZeroDecisionLimit` is already covered — `combiner_determinism.rs:407` calls
//! `try_new(0, 1, 1)`. `ZeroByteLimit` is covered nowhere, and neither is the
//! order between them: the existing probe passes a NON-zero byte ceiling, so no
//! test in the workspace supplies an input that fails both checks at once.

use fgit_txn::combiner::{BatchBounds, BatchBoundsRefusal};

/// A zero byte ceiling is refused.
///
/// The decision limit is one — valid — so the earlier guard cannot be what
/// fires and the refusal is attributable to the byte ceiling alone.
#[test]
fn a_zero_byte_ceiling_is_refused() {
    assert_eq!(
        BatchBounds::try_new(1, 0, 0),
        Err(BatchBoundsRefusal::ZeroByteLimit),
    );
}

/// The permitted twin at the exact inclusive boundary: a ceiling of one byte is
/// accepted.
///
/// One is the smallest admissible ceiling, and the guard is `== 0`. Written
/// `<= 1` — or as any other "too small to be useful" heuristic — it would
/// refuse a legitimately tiny bound while the zero probe above still passed.
/// Both limits are at their minimum here, so this is the twin for each guard.
#[test]
fn limits_of_exactly_one_are_accepted() {
    BatchBounds::try_new(1, 1, 0)
        .expect("one decision and one byte is a bounded, admissible batch");
}

/// Ordering: when BOTH limits are zero, the decision limit is reported.
///
/// This is the input no existing test supplies. `combiner_determinism.rs`
/// passes `(0, 1, 1)` — zero decisions, a valid ceiling — so only one guard can
/// fire there. With both zero, both conditions hold and the answer is decided
/// purely by which `if` comes first.
///
/// The two refusals say different things to a caller who mis-configured a
/// combiner: how many decisions it may admit, versus how many bytes. Swapping
/// the checks changes that diagnosis while leaving every single-fault probe —
/// mine and the existing one — passing.
#[test]
fn both_limits_zero_reports_the_decision_limit_first() {
    assert_eq!(
        BatchBounds::try_new(0, 0, 0),
        Err(BatchBoundsRefusal::ZeroDecisionLimit),
        "the decision-limit check precedes the byte-ceiling check, so an input \
         failing both is diagnosed on the decision limit",
    );
}
