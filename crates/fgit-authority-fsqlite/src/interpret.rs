//! Turning what the engine reports into what the contract means.
//!
//! Both load-bearing statements are conditional, so the engine answers them
//! with a row count rather than a verdict. `ON CONFLICT DO NOTHING` changes one
//! row or none; the two-guard `UPDATE` changes one row or none. The mapping
//! from that count to a contract outcome is where a backend quietly goes wrong,
//! so it lives here as pure functions that can be enumerated in a test rather
//! than inline in a worker that needs a database to exercise.
//!
//! # The count is not the whole answer, and pretending otherwise is the bug
//!
//! Zero rows changed is *ambiguous at the SQL level*. A conditional replacement
//! that changed nothing may have lost the token race, may have been handed a
//! token this store never issued, may have proposed a generation that does not
//! advance, or may name a head that does not exist. Those are four different
//! contract outcomes — one of them an ordinary lost race, one of them a
//! forged-token refusal — and a backend that collapses them into "failed" has
//! destroyed the distinction FG-004c's campaign is built on.
//!
//! So the interpretation is deliberately two-stage: the count decides whether
//! there is anything to disambiguate, and [`disambiguate_compare_exchange`]
//! decides what actually happened from state the caller must go and read.
//!
//! # Why this is not shared code with the reference profile
//!
//! The in-memory reference profile makes the same distinctions in the same
//! order. That is not enforced by sharing a helper — it is enforced by both
//! backends passing the same conformance suite, which is what the suite is for.
//! A shared helper would make the two agree by construction and leave the suite
//! testing nothing.

use fgit_authority::{
    AuthorityRefusal, AuthorityVersionToken, CasOutcome, HeadGeneration, PutOutcome,
};

/// Whether a conditional insert stored the body or found the slot taken.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PutStep {
    /// The slot was empty and now holds exactly the supplied body.
    Created,
    /// The slot was occupied. Whether that is an idempotent retry or a
    /// conflict depends on bytes the caller must read.
    OccupiedNeedsComparison,
}

/// Interpret the row count of `body.put_if_absent`.
#[must_use]
pub const fn interpret_put_if_absent(rows_changed: u64) -> PutStep {
    if rows_changed == 0 {
        PutStep::OccupiedNeedsComparison
    } else {
        PutStep::Created
    }
}

/// Resolve an occupied immutable slot against the body the caller proposed.
///
/// Immutable means immutable: an occupied slot is never replaced, so the only
/// question is whether the caller is retrying the same write.
#[must_use]
pub fn compare_stored_body(stored: &[u8], proposed: &[u8]) -> PutOutcome {
    if stored == proposed {
        PutOutcome::IdenticalRetry
    } else {
        PutOutcome::Conflict
    }
}

/// Whether a conditional replacement published, or needs explaining.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CasStep {
    /// One row changed: the replacement published and this is the
    /// linearization point.
    Published,
    /// No row changed. Four different outcomes are still possible.
    UnchangedNeedsDisambiguation,
}

/// Interpret the row count of `head.compare_exchange`.
#[must_use]
pub const fn interpret_compare_exchange(rows_changed: u64) -> CasStep {
    if rows_changed == 0 {
        CasStep::UnchangedNeedsDisambiguation
    } else {
        CasStep::Published
    }
}

/// The head state a disambiguation needs, read after an unchanged replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedHead {
    /// The token the slot currently carries.
    pub token: AuthorityVersionToken,
    /// The generation the slot currently carries.
    pub generation: HeadGeneration,
}

/// Explain a conditional replacement that changed no rows.
///
/// The order of the checks is the contract's order and is not interchangeable:
///
/// 1. **A token this store never issued is refused**, before anything else.
///    Reporting it as a lost race would tell a forger that its token was
///    merely stale, which is exactly the conflation FG-004c hunts for.
/// 2. A token issued for a *different* head slot is refused.
/// 3. An absent head slot is refused; there is no race to lose.
/// 4. A genuine but superseded token **loses the race** — an outcome, not an
///    error.
/// 5. Only then can a non-advancing generation be the explanation.
///
/// Checking staleness before provenance would let a forged token that happens
/// not to match the current one be reported as a mere loser.
pub fn disambiguate_compare_exchange(
    expected: AuthorityVersionToken,
    proposed_generation: HeadGeneration,
    issued_for: Option<&[u8]>,
    head_key: &[u8],
    observed: Option<ObservedHead>,
) -> Result<CasOutcome, DisambiguationRefusal> {
    let Some(issued_key) = issued_for else {
        return Err(DisambiguationRefusal::Contract(
            AuthorityRefusal::UnknownVersionToken,
        ));
    };
    if issued_key != head_key {
        return Err(DisambiguationRefusal::Contract(
            AuthorityRefusal::TokenKeyMismatch,
        ));
    }
    let Some(head) = observed else {
        return Err(DisambiguationRefusal::Contract(
            AuthorityRefusal::HeadAbsent,
        ));
    };
    if head.token != expected {
        return Ok(CasOutcome::PredecessorMismatch);
    }
    if proposed_generation <= head.generation {
        return Err(DisambiguationRefusal::Contract(
            AuthorityRefusal::NonMonotoneGeneration {
                current: head.generation,
                proposed: proposed_generation,
            },
        ));
    }
    // The token is current and the generation advances, so the guarded UPDATE
    // should have matched. Every benign explanation is excluded: another writer
    // publishing would have changed the token, and generations never decrease.
    // This is an engine-level inconsistency, and it gets its own variant rather
    // than being dressed as a contract refusal -- calling it `Unavailable`
    // would tell the caller the endpoint never processed the request, which is
    // the opposite of what happened.
    Err(DisambiguationRefusal::RowCountContradictsState)
}

/// Why a zero-row replacement could not be explained as a contract outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisambiguationRefusal {
    /// An ordinary contract refusal.
    Contract(AuthorityRefusal),
    /// The engine reported no rows changed for a replacement whose guards a
    /// subsequent read says were all satisfied.
    ///
    /// Not a client-visible condition and not retryable: it means the row count
    /// and the state disagree, which is a bug in the engine or in this adapter,
    /// and it fails closed rather than being reported as a lost race.
    RowCountContradictsState,
}

impl core::fmt::Display for DisambiguationRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Contract(refusal) => write!(f, "{refusal}"),
            Self::RowCountContradictsState => f.write_str(
                "the conditional replacement changed no rows but a read reports every guard \
                 satisfied; the row count and the state disagree",
            ),
        }
    }
}

impl std::error::Error for DisambiguationRefusal {}

/// Whether a conditional head creation created the slot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HeadInitStep {
    /// The slot was empty and now holds the supplied head.
    Created,
    /// The slot was occupied; the caller must compare what is there.
    OccupiedNeedsComparison,
}

/// Interpret the row count of `head.create_if_absent`.
#[must_use]
pub const fn interpret_head_create(rows_changed: u64) -> HeadInitStep {
    if rows_changed == 0 {
        HeadInitStep::OccupiedNeedsComparison
    } else {
        HeadInitStep::Created
    }
}
