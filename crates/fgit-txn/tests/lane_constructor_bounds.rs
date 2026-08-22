#![forbid(unsafe_code)]
//! frankengit-nxdy: the bounded-validation gate in front of the preparation lane.
//!
//! Six `LaneRefusal` variants across three public `try_new` constructors were
//! named by no test in the workspace. They are the gate every capsule passes
//! through before it can be sealed, and NPC §5.2 makes the capsule the unit
//! that owns one logical identity — so an unbounded witness set is a resource
//! ceiling with nothing behind it, and a zero capacity is a lane that can never
//! accept work.
//!
//! # Every guard here is `>` or `== 0`, so every twin sits on the boundary
//!
//! A refusal-only corpus cannot tell a correct bound from one tightened by one:
//! change any `>` to `>=` and every refusal probe stays green while legitimate
//! input starts being rejected. So each refusal below is paired with the
//! *exact* admitted value — a witness key of exactly `MAX_WITNESS_KEY_BYTES`, a
//! capsule of exactly `MAX_PREPARED_CAPSULE_BYTES`, a witness set of exactly
//! `MAX_CONFLICT_WITNESSES`, and a capacity of exactly one.
//!
//! # Ordering
//!
//! Each constructor checks its guards in a fixed order, and every case below
//! keeps the earlier guards satisfied so it proves its own refusal rather than
//! an earlier one. Each test says which.

use std::collections::BTreeSet;

use fgit_txn::lanes::{
    ConflictWitness, LaneCapacity, LaneRefusal, MAX_CONFLICT_WITNESSES, MAX_PREPARED_CAPSULE_BYTES,
    MAX_WITNESS_KEY_BYTES, PreparedCapsule, PriorityClass, WitnessDomain,
};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{PreparedTxnCapsuleId, TxId};

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;

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

fn witness(key: Vec<u8>) -> Result<ConflictWitness, LaneRefusal> {
    ConflictWitness::try_new(WitnessDomain::RepositoryHead, key)
}

/// A witness set of `count` distinct keys, each comfortably inside its bound.
fn witness_set(count: usize) -> BTreeSet<ConflictWitness> {
    (0..count)
        .map(|index| {
            let key = u32::try_from(index)
                .expect("fixture count fits u32")
                .to_be_bytes()
                .to_vec();
            witness(key).expect("a four-byte witness key is inside the bound")
        })
        .collect()
}

fn prepared(
    canonical_bytes: Vec<u8>,
    witnesses: BTreeSet<ConflictWitness>,
) -> Result<PreparedCapsule, LaneRefusal> {
    PreparedCapsule::try_new(
        capsule_id(1),
        tx_id(1),
        PriorityClass::Normal,
        0,
        canonical_bytes,
        witnesses,
    )
}

/// An empty witness key is refused; one byte is enough.
///
/// This is the first guard in `ConflictWitness::try_new`, so nothing earlier
/// can pre-empt it. The twin shows the guard is emptiness and not size.
#[test]
fn a_witness_key_must_not_be_empty() {
    assert_eq!(witness(Vec::new()), Err(LaneRefusal::EmptyWitnessKey));

    witness(vec![b'k']).expect("a one-byte witness key is admissible");
}

/// The witness-key bound refuses one byte over and admits exactly the maximum.
///
/// Earlier guard satisfied: both keys are non-empty, so `EmptyWitnessKey`
/// cannot fire first. The refusal must report what it saw and the bound it
/// enforced — a refusal naming the wrong maximum tells an operator something
/// false about why their key was rejected, and survives a variant-only check.
#[test]
fn a_witness_key_of_exactly_the_maximum_is_admitted_and_one_more_is_not() {
    let refusal = witness(vec![b'k'; MAX_WITNESS_KEY_BYTES + 1])
        .expect_err("one byte past the bound must refuse");
    assert!(
        matches!(
            refusal,
            LaneRefusal::WitnessKeyTooLarge { observed, maximum }
                if observed == MAX_WITNESS_KEY_BYTES + 1 && maximum == MAX_WITNESS_KEY_BYTES
        ),
        "the refusal must report its own observation and bound; got {refusal:?}",
    );

    witness(vec![b'k'; MAX_WITNESS_KEY_BYTES])
        .expect("a key of exactly the maximum is inside the bound");
}

/// The capsule-size bound refuses one byte over and admits exactly the maximum.
///
/// Earlier guards satisfied: the capsule-size check is first in
/// `PreparedCapsule::try_new`, and the witness set is a single valid witness so
/// `TooManyWitnesses` cannot fire in either half.
#[test]
fn a_capsule_of_exactly_the_maximum_size_is_admitted_and_one_more_is_not() {
    let refusal = prepared(vec![0_u8; MAX_PREPARED_CAPSULE_BYTES + 1], witness_set(1))
        .expect_err("one byte past the bound must refuse");
    assert!(
        matches!(
            refusal,
            LaneRefusal::CapsuleTooLarge { observed, maximum }
                if observed == MAX_PREPARED_CAPSULE_BYTES + 1
                    && maximum == MAX_PREPARED_CAPSULE_BYTES
        ),
        "the refusal must report its own observation and bound; got {refusal:?}",
    );

    prepared(vec![0_u8; MAX_PREPARED_CAPSULE_BYTES], witness_set(1))
        .expect("a capsule of exactly the maximum is inside the bound");
}

/// The witness-count bound refuses one over and admits exactly the maximum.
///
/// Earlier guard satisfied: the canonical bytes are eight in both halves, far
/// inside `MAX_PREPARED_CAPSULE_BYTES`, so `CapsuleTooLarge` cannot fire first.
/// The set is built from distinct keys, which matters because `BTreeSet`
/// deduplicates — an equal-keyed set would silently collapse below the bound
/// and the refusal would never be reached.
#[test]
fn a_witness_set_of_exactly_the_maximum_is_admitted_and_one_more_is_not() {
    let over = witness_set(MAX_CONFLICT_WITNESSES + 1);
    assert_eq!(
        over.len(),
        MAX_CONFLICT_WITNESSES + 1,
        "the fixture keys must be distinct or the set collapses and proves nothing",
    );

    let refusal =
        prepared(vec![0_u8; 8], over).expect_err("one witness past the bound must refuse");
    assert!(
        matches!(
            refusal,
            LaneRefusal::TooManyWitnesses { observed, maximum }
                if observed == MAX_CONFLICT_WITNESSES + 1 && maximum == MAX_CONFLICT_WITNESSES
        ),
        "the refusal must report its own observation and bound; got {refusal:?}",
    );

    prepared(vec![0_u8; 8], witness_set(MAX_CONFLICT_WITNESSES))
        .expect("a witness set of exactly the maximum is inside the bound");
}

/// A zero capsule capacity is refused, with the byte capacity valid.
///
/// The two zero-capacity arms are independent axes and are probed separately:
/// passing zero for both would leave the second arm unexercised, because the
/// capsule check runs first and returns.
#[test]
fn a_lane_capacity_of_zero_capsules_is_refused_with_bytes_valid() {
    assert_eq!(
        LaneCapacity::try_new(0, 1),
        Err(LaneRefusal::ZeroCapsuleCapacity),
    );

    LaneCapacity::try_new(1, 1).expect("a capacity of one capsule and one byte is admissible");
}

/// A zero byte capacity is refused, with the capsule capacity valid.
///
/// The capsule count is one, so `ZeroCapsuleCapacity` — which is checked first
/// — cannot fire. Without that, this test would pass on the wrong arm.
#[test]
fn a_lane_capacity_of_zero_bytes_is_refused_with_capsules_valid() {
    assert_eq!(
        LaneCapacity::try_new(1, 0),
        Err(LaneRefusal::ZeroByteCapacity),
    );

    LaneCapacity::try_new(1, 1).expect("a capacity of one capsule and one byte is admissible");
}
