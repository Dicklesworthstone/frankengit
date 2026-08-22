#![forbid(unsafe_code)]
//! The seal-and-attach identity refusals (`frankengit-j0oh`).
//!
//! §5.2 states the invariant these guards exist for: *"One seal body owns one
//! logical identity; key reuse with different semantics fails closed"* and
//! *"One sealed transaction has at most one terminal decision."* A duplicate
//! transaction in a lane, or a slot attached to the wrong lane, is exactly key
//! reuse with different semantics — so these refusals are constitutional
//! behaviour, not lane bookkeeping.
//!
//! Measured before writing, with a scan that reads **every** file under
//! `tests/` rather than only `.rs` sources: `LaneRefusal` has 11 constructed
//! variants, the crate has seven test files, and exactly one variant —
//! `SlotTransactionMismatch` — is named by any of them (`lanes_state.rs:158`).
//!
//! This file closes four variants across six construction sites, and adds the
//! **second site** of the one already covered:
//!
//! ```text
//! SlotCountMismatch         seal                    new
//! DuplicateSlotTransaction  seal                    new
//! DuplicateTransaction      append                  new
//!                           seal                    UNREACHABLE, see below
//! SlotLaneMismatch          seal                    new
//!                           DirectAttempt::try_new  new
//! SlotTransactionMismatch   seal                    covered at lanes_state.rs:158
//!                           DirectAttempt::try_new  new — second site
//! ```
//!
//! A refusal reached through `seal` says nothing about `DirectAttempt::try_new`
//! and vice versa, which is why the shared variants get one probe per site.
//!
//! # `seal`'s duplicate-capsule guard is unreachable, and that is a finding
//!
//! `seal` rescans its own capsules for a duplicate `transaction_id`
//! (`lanes/mod.rs:560`). It cannot fire through the public API, established by
//! reading every path that can populate a lane rather than by failing to build
//! a fixture:
//!
//! - `pending` is initialised empty in `WritableLane::new` and pushed at
//!   exactly one place, inside `append`.
//! - `append` refuses `DuplicateTransaction` on the same `transaction_id`
//!   comparison *before* it pushes.
//! - `SealFailure::abort_cancelled` returns the same lane with `pending`
//!   untouched, so a failed seal cannot add one.
//! - `RetiredLane::reopen` calls `WritableLane::new`, returning a **fresh empty**
//!   lane — it discards capsules rather than carrying them over.
//! - `DirectAttemptRefusal::abort_cancelled` hands back a bare `PreparedCapsule`,
//!   which can only re-enter a lane through `append` and its duplicate check.
//!
//! So every lane reaching `seal` was built exclusively by a constructor that
//! already enforces the invariant `seal` re-checks. It is **defensive**, and it
//! is documented here rather than given a manufactured fixture — building one
//! would require reaching past the public API, and a test that does that proves
//! something about the fixture rather than about the guard.
//!
//! This is the seventh defensive arm this sweep has surfaced, and the heuristic
//! continues to hold: a guard re-validating what a constructor already enforced
//! is protecting an invariant that is already guaranteed.
//!
//! # The five-stage precedence chain
//!
//! `seal` runs its checks in a fixed order, so an input wrong in two ways
//! reports the **earlier** fault:
//!
//! ```text
//! 1  capsule_count != slot_count            SlotCountMismatch
//! 2  duplicate slot transaction (sorted)    DuplicateSlotTransaction
//! 3  duplicate capsule transaction (sorted) DuplicateTransaction   (unreachable)
//! 4  slot lane != lane id                   SlotLaneMismatch
//! 5  zipped transaction mismatch            SlotTransactionMismatch
//! ```
//!
//! Two probes drive inputs that are wrong twice and pin different stages of
//! that chain. Without them, reordering the stages would leave every
//! single-fault probe green.
//!
//! # Non-claims
//!
//! Four of ten unnamed `LaneRefusal` variants, plus one second site. The
//! constructor-bounds cluster (`EmptyWitnessKey`, `WitnessKeyTooLarge`,
//! `CapsuleTooLarge`, `TooManyWitnesses`, `ZeroCapsuleCapacity`,
//! `ZeroByteCapacity`) is filed separately as `frankengit-nxdy` and left
//! unclaimed. LEAD count, not a remaining-work total.
//!
//! Nothing here modifies `crates/fgit-txn/src/**`.

use std::collections::BTreeSet;

use fgit_resource::kinds::{LaneSlot, PreparedTxnSlot};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionId, ReservedObligation, ResourceVector,
};
use fgit_txn::lanes::{
    AppendFailure, ConflictWitness, DirectAttempt, LaneCapacity, LaneId, LaneRefusal,
    PreparedCapsule, PriorityClass, WitnessDomain, WritableLane,
};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{PreparedTxnCapsuleId, TxId};

/// Mirrors the fixture slot the crate's other lane suites use, so this file
/// reads as native to the crate rather than importing a second convention.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;

const LANE: u16 = 7;
const OTHER_LANE: u16 = 9;

fn tx_id(tag: u8) -> TxId {
    TxId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

fn capsule_id(tag: u8) -> PreparedTxnCapsuleId {
    PreparedTxnCapsuleId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("32-byte corpus fixture body"),
    )
}

/// A capsule whose transaction identity is derived from `tag`.
///
/// Two capsules built with the same tag share a `transaction_id`, which is what
/// the duplicate probes rely on; two with different tags do not.
fn capsule(tag: u8) -> PreparedCapsule {
    let mut witnesses = BTreeSet::new();
    witnesses.insert(
        ConflictWitness::try_new(WitnessDomain::RepositoryHead, vec![tag])
            .expect("one-byte witness is valid"),
    );
    PreparedCapsule::try_new(
        capsule_id(tag),
        tx_id(tag),
        PriorityClass::Normal,
        0,
        vec![tag; 8],
        witnesses,
    )
    .expect("bounded capsule is valid")
}

/// A capsule sharing `other`'s transaction identity but carrying its own
/// capsule id, so an equal `transaction_id` is the only thing the two share.
fn capsule_reusing_transaction(capsule_tag: u8, transaction_tag: u8) -> PreparedCapsule {
    let mut witnesses = BTreeSet::new();
    witnesses.insert(
        ConflictWitness::try_new(WitnessDomain::RepositoryHead, vec![capsule_tag])
            .expect("one-byte witness is valid"),
    );
    PreparedCapsule::try_new(
        capsule_id(capsule_tag),
        tx_id(transaction_tag),
        PriorityClass::Normal,
        0,
        vec![capsule_tag; 8],
        witnesses,
    )
    .expect("bounded capsule is valid")
}

fn ledger() -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        ResourceVector::single(Grade::MemoryBytes, 64),
    )
}

fn slot(
    ledger: &ObligationLedger,
    lane: LaneId,
    transaction: TxId,
) -> ReservedObligation<PreparedTxnSlot> {
    let grant = ledger
        .grant(ResourceVector::single(Grade::MemoryBytes, 1))
        .expect("capacity has a ready slot");
    ledger
        .reserve::<PreparedTxnSlot>(
            LaneSlot {
                lane: lane.get(),
                transaction,
            },
            grant,
        )
        .expect("prepared slot reservation is well formed")
}

fn capacity() -> LaneCapacity {
    LaneCapacity::try_new(8, 4096).expect("a non-degenerate capacity")
}

/// A lane holding the capsules named by `tags`, appended in order.
fn lane_with(tags: &[u8]) -> WritableLane {
    let mut lane = WritableLane::new(LaneId::new(LANE), capacity());
    for &tag in tags {
        lane.append(capsule(tag))
            .unwrap_or_else(|_| panic!("appending distinct capsule {tag} must succeed"));
    }
    lane
}

// ---------------------------------------------------------------------------
// The permitted terminus, first
// ---------------------------------------------------------------------------

/// A lane whose slots match its capsules seals cleanly.
///
/// Every refusal below is measured against this. Without it they would be
/// unattributable — `seal` rejecting all input would satisfy each of them.
#[test]
fn a_lane_whose_slots_match_its_capsules_seals() {
    let ledger = ledger();
    let lane_id = LaneId::new(LANE);
    let lane = lane_with(&[1, 2]);
    let sealed = lane
        .seal(vec![
            slot(&ledger, lane_id, tx_id(1)),
            slot(&ledger, lane_id, tx_id(2)),
        ])
        .unwrap_or_else(|failure| panic!("matching slots must seal, got {:?}", failure.refusal()));
    assert_eq!(sealed.capsules().count(), 2);
}

/// The permitted twin for the append path: two distinct transactions append.
#[test]
fn appending_two_distinct_transactions_succeeds() {
    let mut lane = WritableLane::new(LaneId::new(LANE), capacity());
    lane.append(capsule(1)).expect("the first capsule appends");
    lane.append(capsule(2))
        .expect("a different transaction appends beside it");
    assert_eq!(lane.len(), 2);
}

/// The permitted twin for the direct-attempt path.
#[test]
fn a_direct_attempt_with_a_matching_slot_constructs() {
    let ledger = ledger();
    let lane_id = LaneId::new(LANE);
    let attempt = DirectAttempt::try_new(lane_id, capsule(1), slot(&ledger, lane_id, tx_id(1)))
        .unwrap_or_else(|refusal| {
            panic!("a matching slot must attach, got {:?}", refusal.refusal())
        });
    assert_eq!(attempt.capsule().transaction_id(), tx_id(1));
}

// ---------------------------------------------------------------------------
// DuplicateTransaction — the append site (the reachable one)
// ---------------------------------------------------------------------------

/// Appending a second capsule with an already-present transaction identity is
/// refused, and the capsule comes back rather than being swallowed.
///
/// This is §5.2's "key reuse with different semantics fails closed": the two
/// capsules carry different capsule ids and different bodies, and share only
/// the transaction identity.
#[test]
fn appending_a_duplicate_transaction_is_refused_and_returns_the_capsule() {
    let mut lane = WritableLane::new(LaneId::new(LANE), capacity());
    lane.append(capsule(1)).expect("the first capsule appends");

    let failure = lane
        .append(capsule_reusing_transaction(2, 1))
        .expect_err("a second capsule claiming transaction 1 must be refused");
    match failure {
        AppendFailure::Refused(refusal) => {
            assert_eq!(refusal.refusal(), LaneRefusal::DuplicateTransaction);
            assert_eq!(
                refusal.into_capsule().transaction_id(),
                tx_id(1),
                "the refused capsule is handed back, not dropped"
            );
        }
        AppendFailure::Overflow(_) => {
            panic!("a duplicate is a refusal, not an overflow — capacity is 8")
        }
    }
    assert_eq!(lane.len(), 1, "the lane is unchanged by a refused append");
}

// ---------------------------------------------------------------------------
// SlotCountMismatch — stage 1
// ---------------------------------------------------------------------------

/// Fewer slots than capsules is refused, and the count is reported both ways.
#[test]
fn sealing_with_too_few_slots_is_refused() {
    let ledger = ledger();
    let lane_id = LaneId::new(LANE);
    let failure = lane_with(&[1, 2])
        .seal(vec![slot(&ledger, lane_id, tx_id(1))])
        .expect_err("one slot cannot serve two capsules");
    assert_eq!(
        failure.refusal(),
        LaneRefusal::SlotCountMismatch {
            capsules: 2,
            slots: 1
        }
    );
}

/// More slots than capsules is the other direction of the same guard, and a
/// probe hitting only one leaves the other unexercised.
#[test]
fn sealing_with_too_many_slots_is_refused() {
    let ledger = ledger();
    let lane_id = LaneId::new(LANE);
    let failure = lane_with(&[1])
        .seal(vec![
            slot(&ledger, lane_id, tx_id(1)),
            slot(&ledger, lane_id, tx_id(2)),
        ])
        .expect_err("two slots cannot serve one capsule");
    assert_eq!(
        failure.refusal(),
        LaneRefusal::SlotCountMismatch {
            capsules: 1,
            slots: 2
        }
    );
}

// ---------------------------------------------------------------------------
// DuplicateSlotTransaction — stage 2
// ---------------------------------------------------------------------------

/// Two slots reserved for the same transaction cannot both attach.
///
/// The counts match, so this reaches stage 2 rather than stopping at stage 1.
#[test]
fn sealing_with_two_slots_for_one_transaction_is_refused() {
    let ledger = ledger();
    let lane_id = LaneId::new(LANE);
    let failure = lane_with(&[1, 2])
        .seal(vec![
            slot(&ledger, lane_id, tx_id(1)),
            slot(&ledger, lane_id, tx_id(1)),
        ])
        .expect_err("one transaction cannot own two ready slots");
    assert_eq!(failure.refusal(), LaneRefusal::DuplicateSlotTransaction);
}

// ---------------------------------------------------------------------------
// SlotLaneMismatch — stage 4, and the DirectAttempt site
// ---------------------------------------------------------------------------

/// A slot reserved against another lane cannot seal this one.
///
/// Passes through: counts match, slot transactions are distinct, capsule
/// transactions are distinct — so this reaches stage 4.
#[test]
fn sealing_with_a_slot_from_another_lane_is_refused() {
    let ledger = ledger();
    let other = LaneId::new(OTHER_LANE);
    let failure = lane_with(&[1])
        .seal(vec![slot(&ledger, other, tx_id(1))])
        .expect_err("a slot reserved against another lane must not seal this one");
    assert_eq!(
        failure.refusal(),
        LaneRefusal::SlotLaneMismatch {
            expected: LaneId::new(LANE),
            observed: other,
        },
        "the refusal names both lanes, so the two are distinguishable"
    );
}

/// **The second site.** `DirectAttempt::try_new` enforces the same lane binding
/// through a different code path, so it gets its own probe.
#[test]
fn a_direct_attempt_with_a_slot_from_another_lane_is_refused() {
    let ledger = ledger();
    let lane_id = LaneId::new(LANE);
    let other = LaneId::new(OTHER_LANE);
    let refusal = DirectAttempt::try_new(lane_id, capsule(1), slot(&ledger, other, tx_id(1)))
        .expect_err("a direct attempt must not accept another lane's slot");
    assert_eq!(
        refusal.refusal(),
        LaneRefusal::SlotLaneMismatch {
            expected: lane_id,
            observed: other,
        }
    );
}

// ---------------------------------------------------------------------------
// SlotTransactionMismatch — the DirectAttempt site only
// ---------------------------------------------------------------------------

/// `seal`'s site is already covered at `lanes_state.rs:158`; this is the other
/// one. A slot reserved for a different transaction cannot carry this capsule.
#[test]
fn a_direct_attempt_with_a_slot_for_another_transaction_is_refused() {
    let ledger = ledger();
    let lane_id = LaneId::new(LANE);
    let refusal = DirectAttempt::try_new(lane_id, capsule(1), slot(&ledger, lane_id, tx_id(2)))
        .expect_err("a slot reserved for transaction 2 must not carry transaction 1");
    assert_eq!(refusal.refusal(), LaneRefusal::SlotTransactionMismatch);
}

// ---------------------------------------------------------------------------
// Ordering — inputs wrong twice, reporting the earlier fault
// ---------------------------------------------------------------------------

/// Stage 1 outranks stage 2: a count mismatch reports before a duplicate slot.
///
/// The input is wrong twice — two slots for one capsule, and both slots
/// reserved for the same transaction. It must report `SlotCountMismatch`.
#[test]
fn a_count_mismatch_outranks_a_duplicate_slot() {
    let ledger = ledger();
    let lane_id = LaneId::new(LANE);
    let failure = lane_with(&[1])
        .seal(vec![
            slot(&ledger, lane_id, tx_id(1)),
            slot(&ledger, lane_id, tx_id(1)),
        ])
        .expect_err("an input wrong in two ways must still refuse");
    assert_eq!(
        failure.refusal(),
        LaneRefusal::SlotCountMismatch {
            capsules: 1,
            slots: 2
        },
        "the count check runs before the duplicate-slot scan"
    );
}

/// Stage 2 outranks stage 4: a duplicate slot reports before a lane mismatch.
///
/// Wrong twice again — both slots claim transaction 1, and both are reserved
/// against another lane. It must report `DuplicateSlotTransaction`, which is
/// the opposite end of the chain from the probe above, so the two together pin
/// the order rather than one boundary of it.
#[test]
fn a_duplicate_slot_outranks_a_lane_mismatch() {
    let ledger = ledger();
    let other = LaneId::new(OTHER_LANE);
    let failure = lane_with(&[1, 2])
        .seal(vec![
            slot(&ledger, other, tx_id(1)),
            slot(&ledger, other, tx_id(1)),
        ])
        .expect_err("an input wrong in two ways must still refuse");
    assert_eq!(
        failure.refusal(),
        LaneRefusal::DuplicateSlotTransaction,
        "the duplicate-slot scan runs before the lane check"
    );
}
