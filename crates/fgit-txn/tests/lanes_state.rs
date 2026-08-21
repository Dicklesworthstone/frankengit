#![forbid(unsafe_code)]
//! Ownership and cancellation coverage for preparation-lane type states.

use std::collections::BTreeSet;

use fgit_resource::kinds::{LaneSlot, PreparedTxnSlot};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionId, ReservedObligation, ResourceVector,
};
use fgit_txn::lanes::{
    AppendFailure, ConflictWitness, DirectAttempt, LaneCapacity, LaneId, LaneRefusal, LaneState,
    PreparedCapsule, PriorityClass, WitnessDomain, WritableLane,
};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{PreparedTxnCapsuleId, TxId};
use fgit_types::numeric::DecisionSequence;

fn tx_id(tag: u8) -> TxId {
    TxId::from_digest(
        DigestAlgorithmId::try_new(1).expect("one is a valid digest algorithm"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("a 32-byte digest is valid"),
    )
}

fn capsule_id(tag: u8) -> PreparedTxnCapsuleId {
    PreparedTxnCapsuleId::from_digest(
        DigestAlgorithmId::try_new(1).expect("one is a valid digest algorithm"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("a 32-byte digest is valid"),
    )
}

fn capsule(tag: u8, sequence: u64) -> PreparedCapsule {
    let mut witnesses = BTreeSet::new();
    witnesses.insert(
        ConflictWitness::try_new(WitnessDomain::RepositoryHead, vec![tag])
            .expect("one-byte witness is valid"),
    );
    PreparedCapsule::try_new(
        capsule_id(tag),
        tx_id(tag),
        DecisionSequence::try_new(sequence).expect("positive sequence is valid"),
        PriorityClass::Normal,
        sequence,
        vec![tag; 8],
        witnesses,
    )
    .expect("bounded capsule is valid")
}

fn ledger(region: u64) -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(region),
        LeakDisposition::RecordAndContinue,
        ResourceVector::single(Grade::MemoryBytes, 32),
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

#[test]
fn cancellation_at_each_lane_state_settles_all_slots() {
    let lane_id = LaneId::new(9);
    let capacity = LaneCapacity::try_new(2, 128).expect("bounded lane is valid");
    let ledger = ledger(901);

    let retired = WritableLane::new(lane_id, capacity).cancel();
    assert_eq!(retired.state(), LaneState::Retired);
    let mut writable = retired.reopen();
    assert_eq!(writable.state(), LaneState::Writable);
    let first = capsule(1, 1);
    writable.append(first.clone()).expect("first append fits");
    let sealed = writable
        .seal(vec![slot(&ledger, lane_id, first.transaction_id())])
        .expect("matching slot seals the lane");
    assert_eq!(sealed.state(), LaneState::Sealed);
    let retired = sealed.cancel();
    assert_eq!(retired.state(), LaneState::Retired);

    let mut writable = retired.reopen();
    let second = capsule(2, 2);
    writable.append(second.clone()).expect("second append fits");
    let combining = writable
        .seal(vec![slot(&ledger, lane_id, second.transaction_id())])
        .expect("matching slot seals the lane")
        .begin_combining();
    assert_eq!(combining.state(), LaneState::Combining);
    let retired = combining.cancel();
    assert_eq!(retired.cancel().state(), LaneState::Retired);

    assert!(ledger.leaks().is_empty());
    assert!(ledger.close().is_quiescent());
}

#[test]
fn overflow_is_explicit_and_direct_attempt_cancellation_returns_its_slot() {
    let lane_id = LaneId::new(10);
    let capacity = LaneCapacity::try_new(1, 8).expect("single-entry lane is valid");
    let ledger = ledger(902);
    let first = capsule(3, 1);
    let overflowed = capsule(4, 2);
    let mut lane = WritableLane::new(lane_id, capacity);
    lane.append(first).expect("first entry fits");
    let AppendFailure::Overflow(overflow) = lane
        .append(overflowed.clone())
        .expect_err("second entry must use an explicit overflow path")
    else {
        panic!("capacity overflow must not be reported as an invariant refusal");
    };

    let direct = DirectAttempt::try_new(
        lane_id,
        overflow.into_capsule(),
        slot(&ledger, lane_id, overflowed.transaction_id()),
    )
    .expect("matching overflow slot creates a direct attempt");
    let settled = direct.cancel();
    assert_eq!(
        settled.class(),
        fgit_resource::ObligationClass::PreparedTxnSlot
    );
    let _retired = lane.cancel();

    assert!(ledger.leaks().is_empty());
    assert!(ledger.close().is_quiescent());
}

#[test]
fn sealing_refuses_mismatched_slots_but_matching_slots_proceed() {
    let lane_id = LaneId::new(11);
    let capacity = LaneCapacity::try_new(1, 128).expect("bounded lane is valid");
    let ledger = ledger(903);
    let candidate = capsule(5, 1);
    let mut lane = WritableLane::new(lane_id, capacity);
    lane.append(candidate.clone()).expect("append fits");
    let mismatch = lane
        .seal(vec![slot(&ledger, lane_id, tx_id(6))])
        .expect_err("a slot for another transaction must fail closed");
    assert_eq!(mismatch.refusal(), LaneRefusal::SlotTransactionMismatch);
    let _writable = mismatch.abort_cancelled();

    let mut permitted = WritableLane::new(lane_id, capacity);
    permitted.append(candidate.clone()).expect("append fits");
    let sealed = permitted
        .seal(vec![slot(&ledger, lane_id, candidate.transaction_id())])
        .expect("near-identical matching slot must proceed");
    let _retired = sealed.cancel();

    assert!(ledger.leaks().is_empty());
    assert!(ledger.close().is_quiescent());
}
