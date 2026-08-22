#![forbid(unsafe_code)]
//! Every bound `ScrubProfile::new` enforces, from both sides
//! (`frankengit-33ib`).
//!
//! One public constructor holds four refusals across six distinct axes, and no
//! test named any of them. This is the follow-on to `frankengit-bq4b`, which
//! covered three refusals elsewhere in the crate and explicitly did not close
//! the remainder.
//!
//! # The boundary that makes this worth doing
//!
//! `max_target_bytes` is checked against a limit derived from
//! `MicrosegmentRaptorProfile::MAX_SOURCE_BYTES`. The guard reads
//! `> profile_limit`, so a target of **exactly** the profile maximum is
//! admissible — and that is the largest target the profile can express. Written
//! `>=`, scrubbing a target at the profile limit would become impossible, and
//! no refusal-only test would notice, because a refusal test never offers the
//! boundary value.
//!
//! # The guards are ordered, and that changes how each probe is built
//!
//! `new` checks target count, then byte budget, then repair-budget grades, then
//! whether the worker budget can fund repair. **A probe for a later guard must
//! satisfy every earlier one**, or it trips the wrong wall and passes while
//! demonstrating nothing about the guard in its own name.
//!
//! That is why every probe here starts from [`valid_profile_args`] and varies
//! exactly one field. The refusal it asserts is then attributable to the field
//! it changed, and [`the_unmodified_fixture_is_admitted`] proves the base is
//! actually valid — without it, every refusal here could be the fixture failing
//! at the first guard.
//!
//! Each refusal asserts its **payload**, not just its variant, so a guard that
//! fires on the right condition while reporting the wrong `offered`/`maximum`
//! or the wrong `grade` is still caught.
//!
//! Every probe drives the public API; nothing here modifies
//! `crates/fgit-repair/src/**`.

use fgit_raptorq::MicrosegmentRaptorProfile;
use fgit_repair::{ScrubMode, ScrubProfile, ScrubRefusal};
use fgit_resource::{Grade, ResourceVector};

/// The largest target the microsegment profile can express, as
/// `ScrubProfile::new` derives it.
fn profile_limit() -> u64 {
    u64::try_from(MicrosegmentRaptorProfile::MAX_SOURCE_BYTES).unwrap_or(u64::MAX)
}

/// A repair budget with every graded resource the constructor requires.
fn funded_repair_budget() -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, 4_096), (Grade::CpuMicros, 2_000)])
}

/// A worker budget that comfortably covers [`funded_repair_budget`].
fn funding_worker_budget() -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, 64 * 1024), (Grade::CpuMicros, 10_000)])
}

/// Arguments that pass every guard, so a probe can vary exactly one.
struct ProfileArgs {
    mode: ScrubMode,
    max_targets: u16,
    max_target_bytes: u64,
    foreground_floor: ResourceVector,
    worker_budget: ResourceVector,
    repair_budget: ResourceVector,
}

fn valid_profile_args() -> ProfileArgs {
    ProfileArgs {
        mode: ScrubMode::sample(1, 2).expect("one half is a valid sample"),
        max_targets: 8,
        max_target_bytes: 1_024,
        foreground_floor: ResourceVector::ZERO,
        worker_budget: funding_worker_budget(),
        repair_budget: funded_repair_budget(),
    }
}

fn build(args: ProfileArgs) -> Result<ScrubProfile, ScrubRefusal> {
    ScrubProfile::new(
        args.mode,
        args.max_targets,
        args.max_target_bytes,
        args.foreground_floor,
        args.worker_budget,
        args.repair_budget,
    )
}

/// The base fixture passes every guard.
///
/// Without this, each refusal below could be the fixture tripping the *first*
/// guard while the test claims to be exercising a later one — the exact vacuity
/// this file is built to avoid.
#[test]
fn the_unmodified_fixture_is_admitted() {
    build(valid_profile_args()).expect("the base fixture must pass every guard");
}

// ---------------------------------------------------------------------------
// Guard 1 — max_targets
// ---------------------------------------------------------------------------

#[test]
fn a_zero_target_limit_is_refused() {
    let refusal = build(ProfileArgs {
        max_targets: 0,
        ..valid_profile_args()
    })
    .expect_err("a profile that may check no targets must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::ZeroTargetLimit,
        "a zero target limit must refuse as itself"
    );
}

/// The permitted twin: one target is the smallest schedule that does any work.
#[test]
fn the_smallest_non_zero_target_limit_is_admitted() {
    build(ProfileArgs {
        max_targets: 1,
        ..valid_profile_args()
    })
    .expect("a single-target profile must be expressible");
}

// ---------------------------------------------------------------------------
// Guard 2 — max_target_bytes, which has two refusing axes
// ---------------------------------------------------------------------------

#[test]
fn a_zero_target_byte_budget_is_refused() {
    let refusal = build(ProfileArgs {
        max_target_bytes: 0,
        ..valid_profile_args()
    })
    .expect_err("a profile that may read no bytes must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::TargetBytesOutOfProfile {
            offered: 0,
            maximum: profile_limit(),
        },
        "the refusal must report both the offered budget and the profile maximum"
    );
}

/// One byte above the profile limit — the boundary approached from the
/// forbidden side.
#[test]
fn a_target_byte_budget_above_the_profile_is_refused() {
    let offered = profile_limit() + 1;
    let refusal = build(ProfileArgs {
        max_target_bytes: offered,
        ..valid_profile_args()
    })
    .expect_err("a target budget larger than the profile can carry must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::TargetBytesOutOfProfile {
            offered,
            maximum: profile_limit(),
        },
        "the refusal must report both the offered budget and the profile maximum"
    );
}

/// **The permitted twin, at the exact boundary.** A target of exactly the
/// profile maximum is admissible.
///
/// This is the case a refusal-only corpus cannot see. The guard reads
/// `> profile_limit`; tightened to `>=` it would become impossible to scrub a
/// target at the profile limit — the largest the profile can express — while
/// every refusal assertion above continued to pass.
#[test]
fn a_target_byte_budget_at_exactly_the_profile_maximum_is_admitted() {
    build(ProfileArgs {
        max_target_bytes: profile_limit(),
        ..valid_profile_args()
    })
    .expect("a target at exactly the profile maximum must be expressible");
}

/// The other end of the same range, so the boundary case above is not passing
/// because the constructor accepts any non-zero budget it is handed.
#[test]
fn the_smallest_non_zero_target_byte_budget_is_admitted() {
    build(ProfileArgs {
        max_target_bytes: 1,
        ..valid_profile_args()
    })
    .expect("a one-byte target budget must be expressible");
}

// ---------------------------------------------------------------------------
// Guard 3 — repair budget grades, one axis per grade
// ---------------------------------------------------------------------------

/// A repair budget with no byte allowance is refused, naming the missing grade.
///
/// The guard loops over `[Bytes, CpuMicros]`, so each grade is its own axis: a
/// probe that only ever omitted one of them would leave the other unexercised
/// and could not tell a two-grade loop from a one-grade check.
#[test]
fn a_repair_budget_missing_its_byte_grade_is_refused() {
    let refusal = build(ProfileArgs {
        repair_budget: ResourceVector::from_grades(&[(Grade::CpuMicros, 2_000)]),
        ..valid_profile_args()
    })
    .expect_err("a repair budget that funds no bytes must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::RepairBudgetMissingGrade {
            grade: Grade::Bytes,
        },
        "the refusal must name the grade that was missing"
    );
}

/// The second axis of the same loop: no CPU allowance.
#[test]
fn a_repair_budget_missing_its_cpu_grade_is_refused() {
    let refusal = build(ProfileArgs {
        repair_budget: ResourceVector::from_grades(&[(Grade::Bytes, 4_096)]),
        ..valid_profile_args()
    })
    .expect_err("a repair budget that funds no CPU must be refused");
    assert_eq!(
        refusal,
        ScrubRefusal::RepairBudgetMissingGrade {
            grade: Grade::CpuMicros,
        },
        "the refusal must name the grade that was missing"
    );
}

/// The permitted twin: a repair budget carrying both graded resources is
/// admitted — covered by [`the_unmodified_fixture_is_admitted`], and restated
/// here at the minimum non-zero amount so the guard is known to check for
/// presence rather than for some larger threshold.
#[test]
fn a_repair_budget_with_one_unit_of_each_grade_is_admitted() {
    let repair = ResourceVector::from_grades(&[(Grade::Bytes, 1), (Grade::CpuMicros, 1)]);
    build(ProfileArgs {
        repair_budget: repair,
        ..valid_profile_args()
    })
    .expect("a repair budget with one unit of each required grade must be expressible");
}

// ---------------------------------------------------------------------------
// Guard 4 — the worker budget must fund the repair budget
// ---------------------------------------------------------------------------

/// A worker budget that cannot cover the repair budget is refused.
///
/// The payload is `ResourceError` from `fgit-resource`, whose internal shape
/// belongs to that crate; this asserts the variant and leaves the deficit's own
/// representation to its owner's tests rather than pinning another crate's
/// error layout from here.
#[test]
fn a_worker_budget_that_cannot_fund_repair_is_refused() {
    let refusal = build(ProfileArgs {
        worker_budget: ResourceVector::from_grades(&[(Grade::Bytes, 1), (Grade::CpuMicros, 1)]),
        repair_budget: funded_repair_budget(),
        ..valid_profile_args()
    })
    .expect_err("a worker budget smaller than the repair budget must be refused");
    assert!(
        matches!(refusal, ScrubRefusal::WorkerBudgetCannotFundRepair(_)),
        "expected a funding refusal, got {refusal:?}"
    );
}

/// **The permitted twin, at exact equality.** A worker budget that exactly
/// funds the repair budget is admitted.
///
/// `first_deficit` reports a shortfall, so equality is not a shortfall. If that
/// ever became a strict comparison, a profile whose worker budget precisely
/// covers its repair budget would stop being expressible — and the refusal
/// probe above would not notice, because it supplies a budget that is short by
/// a wide margin rather than by nothing at all.
#[test]
fn a_worker_budget_that_exactly_funds_repair_is_admitted() {
    build(ProfileArgs {
        worker_budget: funded_repair_budget(),
        repair_budget: funded_repair_budget(),
        ..valid_profile_args()
    })
    .expect("a worker budget that exactly funds repair must be expressible");
}
