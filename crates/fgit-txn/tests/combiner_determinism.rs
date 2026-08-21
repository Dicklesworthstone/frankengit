#![forbid(unsafe_code)]
//! Determinism, conflict, batch-cut, and handoff coverage for flat combining.

use std::collections::BTreeSet;

use fgit_resource::kinds::{LaneSlot, PreparedTxnSlot};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionId, ReservedObligation, ResourceVector,
};
use fgit_txn::combiner::{
    BatchBounds, BatchBoundsRefusal, BypassReason, CombinationParts, FlatCombiner,
};
use fgit_txn::lanes::{
    ConflictWitness, LaneCapacity, LaneId, PreparedAttemptOutcome, PreparedCapsule, PriorityClass,
    WitnessDomain, WritableLane,
};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{PreparedTxnCapsuleId, RepositoryDecisionBatchId, TxId};

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

fn batch_id(tag: u8) -> RepositoryDecisionBatchId {
    RepositoryDecisionBatchId::from_digest(
        DigestAlgorithmId::try_new(1).expect("one is a valid digest algorithm"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("a 32-byte digest is valid"),
    )
}

fn capsule(tag: u8, witness: u8) -> PreparedCapsule {
    let mut witnesses = BTreeSet::new();
    witnesses.insert(
        ConflictWitness::try_new(WitnessDomain::Reference, vec![witness])
            .expect("one-byte witness is valid"),
    );
    PreparedCapsule::try_new(
        capsule_id(tag),
        tx_id(tag),
        if tag.is_multiple_of(2) {
            PriorityClass::Interactive
        } else {
            PriorityClass::Normal
        },
        20,
        vec![tag; 8],
        witnesses,
    )
    .expect("bounded capsule is valid")
}

fn ledger(region: u64) -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(region),
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

fn combine(
    ledger: &ObligationLedger,
    lane_id: LaneId,
    capsules: Vec<PreparedCapsule>,
    bounds: BatchBounds,
) -> fgit_txn::combiner::Combination {
    let capacity = LaneCapacity::try_new(16, 4_096).expect("bounded lane is valid");
    let mut lane = WritableLane::new(lane_id, capacity);
    for capsule in &capsules {
        lane.append(capsule.clone()).expect("fixture fits lane");
    }
    let slots = capsules
        .iter()
        .map(|capsule| slot(ledger, lane_id, capsule.transaction_id()))
        .collect();
    FlatCombiner::new(bounds)
        .combine(
            lane.seal(slots)
                .expect("matching slots seal the lane")
                .begin_combining(),
            25,
        )
        .expect("bounded canonical inputs combine")
}

fn seeded_shuffle<T: Clone>(source: &[T], mut seed: u64) -> Vec<T> {
    let mut indices = (0..source.len()).collect::<Vec<_>>();
    for end in (1..indices.len()).rev() {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let modulus = u64::try_from(end + 1).expect("test permutation length fits u64");
        let index = usize::try_from(seed % modulus).expect("bounded index fits usize");
        indices.swap(end, index);
    }
    indices
        .into_iter()
        .map(|index| source[index].clone())
        .collect()
}

fn publication_inputs(
    combination: &fgit_txn::combiner::Combination,
) -> Vec<PreparedAttemptOutcome> {
    let mut inputs = combination
        .batch()
        .map_or_else(Vec::new, |batch| batch.canonical_attempt_outcomes());
    inputs.extend(
        combination
            .bypasses()
            .iter()
            .map(|bypass| bypass.attempt().canonical_attempt_outcome()),
    );
    inputs.sort_by_key(PreparedAttemptOutcome::transaction_id);
    inputs
}

#[test]
fn seed_shuffled_inputs_preserve_batch_composition_and_publication_inputs() {
    let bounds = BatchBounds::try_new(8, 4_096, 10).expect("valid bounds");
    let source = [capsule(5, 1), capsule(1, 2), capsule(4, 3), capsule(2, 4)];
    let seeds = [0x0D15_EA5E_u64, 0x0D15_EA5F, 0x0D15_EA60, 0x0D15_EA61];
    let mut expected = None;
    let mut observed_input_orders = BTreeSet::new();
    for (offset, seed) in seeds.into_iter().enumerate() {
        let ledger = ledger(1_000 + u64::try_from(offset).expect("small test offset"));
        let shuffled = seeded_shuffle(&source, seed);
        assert!(
            observed_input_orders.insert(
                shuffled
                    .iter()
                    .map(PreparedCapsule::transaction_id)
                    .collect::<Vec<_>>(),
            ),
            "each test seed must produce a distinct input permutation"
        );
        let combination = combine(&ledger, LaneId::new(20), shuffled, bounds);
        let batch = combination.batch().expect("all inputs fit the batch");
        let observed = (
            batch
                .capsules()
                .map(|capsule| capsule.transaction_id())
                .collect::<Vec<_>>(),
            batch.canonical_attempt_outcomes(),
            batch.conflict_graph().edges().to_vec(),
        );
        if let Some(expected) = &expected {
            assert_eq!(&observed, expected, "input order must not affect combining");
        } else {
            expected = Some(observed);
        }
        let cancellation = combination.cancel();
        assert_eq!(cancellation.settled_slots().len(), 4);
        assert_eq!(ledger.leaks(), Vec::new());
        assert!(ledger.close().is_quiescent());
    }
    assert!(
        observed_input_orders.len() > 1,
        "the test must exercise more than one seed-derived order"
    );
}

#[test]
fn schedule_permutations_preserve_publication_inputs_across_combined_and_bypass_paths() {
    let bounds = BatchBounds::try_new(2, 4_096, 10).expect("valid bounds");
    let source = [capsule(1, 1), capsule(2, 2), capsule(3, 3), capsule(4, 4)];
    let seeds = [0xA11C_E001_u64, 0xA11C_E002, 0xA11C_E003, 0xA11C_E004];
    let mut expected_inputs = None;
    let mut observed_input_orders = BTreeSet::new();
    for (offset, seed) in seeds.into_iter().enumerate() {
        let ledger = ledger(1_050 + u64::try_from(offset).expect("small test offset"));
        let shuffled = seeded_shuffle(&source, seed);
        observed_input_orders.insert(
            shuffled
                .iter()
                .map(PreparedCapsule::transaction_id)
                .collect::<Vec<_>>(),
        );
        let combination = combine(&ledger, LaneId::new(19), shuffled, bounds);
        let batch = combination
            .batch()
            .expect("two entries fit the combined path");
        assert_eq!(
            batch
                .capsules()
                .map(PreparedCapsule::transaction_id)
                .collect::<Vec<_>>(),
            vec![tx_id(2), tx_id(4)],
            "the derived schedule admits the two interactive capsules"
        );
        assert_eq!(
            combination
                .bypasses()
                .iter()
                .map(|bypass| bypass.attempt().capsule().transaction_id())
                .collect::<Vec<_>>(),
            vec![tx_id(1), tx_id(3)],
            "bypass output must not expose schedule order"
        );
        let observed_inputs = publication_inputs(&combination);
        if let Some(expected_inputs) = &expected_inputs {
            assert_eq!(
                &observed_inputs, expected_inputs,
                "pre-combiner permutations must hand publication byte-identical inputs"
            );
        } else {
            expected_inputs = Some(observed_inputs);
        }
        let cancellation = combination.cancel();
        assert_eq!(cancellation.settled_slots().len(), 4);
        assert_eq!(ledger.leaks(), Vec::new());
        assert!(ledger.close().is_quiescent());
    }
    assert!(
        observed_input_orders.len() > 1,
        "the test must exercise multiple pre-combiner permutations"
    );
}

#[test]
fn overlapping_witnesses_form_one_ordered_conflict_component() {
    let ledger = ledger(1_100);
    let bounds = BatchBounds::try_new(8, 4_096, 10).expect("valid bounds");
    let combination = combine(
        &ledger,
        LaneId::new(21),
        vec![capsule(1, 7), capsule(2, 7), capsule(3, 8)],
        bounds,
    );
    let batch = combination.batch().expect("all inputs fit the batch");
    let graph = batch.conflict_graph();
    assert_eq!(graph.edges().len(), 1);
    assert_eq!(graph.components().len(), 2);
    assert_eq!(
        graph.ordered_transaction_ids(),
        &[tx_id(1), tx_id(2), tx_id(3)],
        "the conflict graph must not reveal the internal scheduling order"
    );
    assert_eq!(
        graph.components()[0].transaction_ids(),
        &[tx_id(1), tx_id(2)],
        "members are exposed in canonical transaction-ID order"
    );

    let cancellation = combination.cancel();
    assert_eq!(cancellation.settled_slots().len(), 3);
    assert_eq!(ledger.leaks(), Vec::new());
    assert!(ledger.close().is_quiescent());
}

#[test]
fn direct_bypass_matches_the_same_capsule_on_the_combined_path() {
    let bounds = BatchBounds::try_new(1, 4_096, 10).expect("valid bounds");
    let candidate = capsule(9, 9);
    let higher_priority = capsule(8, 8);
    let bypass_ledger = ledger(1_200);
    let combination = combine(
        &bypass_ledger,
        LaneId::new(22),
        vec![candidate.clone(), higher_priority],
        bounds,
    );
    assert_eq!(combination.bypasses().len(), 1);
    let bypass_outcome = combination.bypasses()[0]
        .attempt()
        .canonical_attempt_outcome();

    let direct_ledger = ledger(1_201);
    let direct = combine(&direct_ledger, LaneId::new(23), vec![candidate], bounds);
    let combined_outcomes = direct
        .batch()
        .expect("one capsule fits a batch")
        .canonical_attempt_outcomes();
    assert_eq!(combined_outcomes.len(), 1);
    assert_eq!(
        bypass_outcome, combined_outcomes[0],
        "the real direct and combined paths must hand publication the same canonical prepared outcome"
    );

    let _cancelled = combination.cancel();
    let _cancelled = direct.cancel();
    assert_eq!(bypass_ledger.leaks(), Vec::new());
    assert_eq!(direct_ledger.leaks(), Vec::new());
    assert!(bypass_ledger.close().is_quiescent());
    assert!(direct_ledger.close().is_quiescent());
}

#[test]
fn byte_and_logical_age_cuts_are_explicit_bypasses() {
    let ledger = ledger(1_250);
    let byte_limited = combine(
        &ledger,
        LaneId::new(25),
        vec![capsule(11, 11), capsule(12, 12)],
        BatchBounds::try_new(8, 8, 10).expect("valid byte-bound batch"),
    );
    assert_eq!(
        byte_limited.batch().map(|batch| batch.capsules().len()),
        Some(1)
    );
    assert_eq!(byte_limited.bypasses().len(), 1);
    assert_eq!(byte_limited.bypasses()[0].reason(), BypassReason::ByteLimit);

    let age_limited = combine(
        &ledger,
        LaneId::new(26),
        vec![capsule(13, 13)],
        BatchBounds::try_new(8, 4_096, 4).expect("valid age-bound batch"),
    );
    assert!(age_limited.batch().is_none());
    assert_eq!(age_limited.bypasses().len(), 1);
    assert_eq!(
        age_limited.bypasses()[0].reason(),
        BypassReason::ReadyAgeLimit
    );

    let _cancelled = byte_limited.cancel();
    let _cancelled = age_limited.cancel();
    assert_eq!(ledger.leaks(), Vec::new());
    assert!(ledger.close().is_quiescent());
}

#[test]
fn invalid_batch_bound_refuses_and_matching_bound_hands_slots_to_batch() {
    assert_eq!(
        BatchBounds::try_new(0, 1, 1),
        Err(BatchBoundsRefusal::ZeroDecisionLimit),
        "a zero decision bound would make a fake combiner"
    );
    let ledger = ledger(1_300);
    let combination = combine(
        &ledger,
        LaneId::new(24),
        vec![capsule(10, 10)],
        BatchBounds::try_new(1, 16, 10).expect("matching non-zero bound proceeds"),
    );
    let CombinationParts {
        batch,
        bypasses,
        retired: _retired,
    } = combination.into_parts();
    assert!(bypasses.is_empty());
    let handed_off = batch
        .expect("one capsule is selected")
        .hand_off(batch_id(11))
        .expect("reserved internal slot can transfer to the batch attempt");
    assert_eq!(handed_off.settled_slots().len(), 1);
    assert_eq!(ledger.leaks(), Vec::new());
    assert!(ledger.close().is_quiescent());
}
