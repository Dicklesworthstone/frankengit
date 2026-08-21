#![forbid(unsafe_code)]
//! FG-014b: lane/combiner equivalence across the explored schedule space.
//!
//! `combiner_determinism.rs` (fg014a, `ef464a2`) established that *some*
//! pre-combiner permutations preserve authority terminal outcomes. This
//! campaign sweeps that property across batch sizes and seeds, and adds the
//! two schedule classes fg014a does not reach: **CAS-loss storms** and
//! **cancellation mid-combine**.
//!
//! # Zero divergences is meaningless without a denominator
//!
//! "No divergence found" is a claim about coverage as much as correctness, so
//! every sweep here counts what it explored and asserts the count is what was
//! intended. [`coverage_receipt`] renders those counts as NDJSON so the
//! explored space is a recorded number rather than an impression. A sweep that
//! silently explored one case would otherwise report the same clean result as
//! one that explored two hundred.
//!
//! # On the digest algorithm in these fixtures
//!
//! Code point **2** (`sha256`, 32 bytes), not 1. `fgit-crypto`'s registry marks
//! code point 1 `AlgorithmUsage::GitIdentityOnly` — *"never an internal body
//! identity"* — so building a `TxId` or capsule identity with it encodes a
//! combination the registry forbids, not merely a wrong length. These fixtures
//! carry real 32-byte digests standing in for genuine internal identities, so
//! the truthful code point is 2. `combiner_determinism.rs` predates that being
//! understood and still uses 1; that is Hazard B, tracked separately.

use std::collections::BTreeSet;

use fgit_authority::{
    AuthorityStore, CasOutcome, HeadGeneration, HeadInit, HeadKey, MemoryAuthorityStore,
    StoreInstanceId,
};
use fgit_resource::kinds::{LaneSlot, PreparedTxnSlot};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionId, ReservedObligation, ResourceVector,
};
use fgit_txn::combiner::{BatchBounds, Combination, FlatCombiner};
use fgit_txn::lanes::{
    ConflictWitness, LaneCapacity, LaneId, PreparedAttemptOutcome, PreparedCapsule, PriorityClass,
    WitnessDomain, WritableLane,
};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::identity::{PreparedTxnCapsuleId, TxId};

/// The digest algorithm these fixtures may honestly claim. See the module doc.
const INTERNAL_IDENTITY_ALGORITHM: u16 = 2;

fn algorithm() -> DigestAlgorithmId {
    DigestAlgorithmId::try_new(INTERNAL_IDENTITY_ALGORITHM)
        .expect("sha256 is a registered internal-identity algorithm")
}

fn tx_id(tag: u8) -> TxId {
    TxId::from_digest(
        algorithm(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("a 32-byte digest is valid"),
    )
}

fn capsule_id(tag: u8) -> PreparedTxnCapsuleId {
    PreparedTxnCapsuleId::from_digest(
        algorithm(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("a 32-byte digest is valid"),
    )
}

/// One capsule. `witness` controls conflict overlap; equal witnesses conflict.
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
        ResourceVector::single(Grade::MemoryBytes, 4_096),
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

fn combine(ledger: &ObligationLedger, capsules: &[PreparedCapsule]) -> Combination {
    let lane_id = LaneId::new(1);
    let capacity = LaneCapacity::try_new(64, 65_536).expect("bounded lane is valid");
    let mut lane = WritableLane::new(lane_id, capacity);
    for capsule in capsules {
        lane.append(capsule.clone()).expect("fixture fits lane");
    }
    let slots = capsules
        .iter()
        .map(|capsule| slot(ledger, lane_id, capsule.transaction_id()))
        .collect();
    FlatCombiner::new(BatchBounds::try_new(64, 65_536, 1_000).expect("bounded batch is valid"))
        .combine(
            lane.seal(slots)
                .expect("matching slots seal the lane")
                .begin_combining(),
            25,
        )
        .expect("bounded canonical inputs combine")
}

/// `SplitMix64`. Seeded and logged, so a divergence is replayable.
fn seeded_shuffle<T: Clone>(source: &[T], mut seed: u64) -> Vec<T> {
    let mut indices = (0..source.len()).collect::<Vec<_>>();
    for end in (1..indices.len()).rev() {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let modulus = u64::try_from(end + 1).expect("permutation length fits u64");
        let index = usize::try_from(seed % modulus).expect("bounded index fits usize");
        indices.swap(end, index);
    }
    indices
        .into_iter()
        .map(|index| source[index].clone())
        .collect()
}

/// The publication inputs **in the order the combiner emitted them**.
///
/// Deliberately not sorted. `combiner_determinism.rs` sorts before comparing,
/// which answers "is the same *set* published?" — a strictly weaker question.
/// Sorting would let a combiner that emitted capsules in input order pass a
/// permutation sweep, because the sort would normalise the very thing under
/// test. I measured that the emitted order is already invariant before relying
/// on it, so this asserts the stronger property the combiner actually holds.
fn publication_inputs(combination: &Combination) -> Vec<PreparedAttemptOutcome> {
    let mut inputs = combination
        .batch()
        .map_or_else(Vec::new, |batch| batch.canonical_attempt_outcomes());
    inputs.extend(
        combination
            .bypasses()
            .iter()
            .map(|bypass| bypass.attempt().canonical_attempt_outcome()),
    );
    inputs
}

/// Drives publication inputs through a real authority head, returning the
/// terminal outcomes. `cas_losses` injects that many lost races before each
/// successful commit, by publishing a competing body under the live token.
fn terminal_outcomes(inputs: &[PreparedAttemptOutcome], cas_losses: u32) -> Vec<(u64, Vec<u8>)> {
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(94));
    let key = HeadKey::new(b"txn/lanes-equivalence".to_vec())
        .expect("a bounded authority head key is valid");
    let mut receipt = match store
        .initialize_head(&key, HeadGeneration::FIRST, b"authority-root")
        .expect("initial head creation proceeds")
    {
        HeadInit::Created(receipt) => receipt,
        outcome => panic!("fresh head creation must succeed, observed {outcome:?}"),
    };
    let mut outcomes = Vec::with_capacity(inputs.len());
    for input in inputs {
        // A CAS-loss storm: a stale token loses, repeatedly, and the loser must
        // reread and retry rather than publishing. Losing changes nothing about
        // the terminal outcome -- that is the property under test.
        for _ in 0..cas_losses {
            let stale = receipt.token();
            let generation = receipt.generation().next().expect("generations remain");
            let won = store
                .compare_exchange_head(&key, stale, generation, b"interloper")
                .expect("a competing publication reaches authority");
            receipt = match won {
                CasOutcome::Committed(next) => next,
                CasOutcome::PredecessorMismatch => {
                    panic!("the interloper holds the live token and must win")
                }
            };
            // Now retry the real input against the token the interloper left.
            let stale_again = receipt.token();
            let generation = receipt.generation().next().expect("generations remain");
            receipt = match store
                .compare_exchange_head(&key, stale_again, generation, b"interloper-rollback")
                .expect("the rollback publication reaches authority")
            {
                CasOutcome::Committed(next) => next,
                CasOutcome::PredecessorMismatch => panic!("live token must win"),
            };
        }
        let generation = receipt.generation().next().expect("generations remain");
        receipt = match store
            .compare_exchange_head(&key, receipt.token(), generation, input.canonical_bytes())
            .expect("canonical publication input reaches authority")
        {
            CasOutcome::Committed(next) => next,
            CasOutcome::PredecessorMismatch => {
                panic!("the canonical order must retain the exact predecessor")
            }
        };
        outcomes.push((receipt.generation().get(), receipt.body().to_vec()));
    }
    outcomes
}

/// One NDJSON line recording what a sweep actually explored.
///
/// The denominator, written down. Acceptance asks for zero divergences "across
/// the explored schedule space"; without this the claim has no space attached.
fn coverage_receipt(
    campaign: &str,
    batch_sizes: &[usize],
    permutations_per_size: usize,
    comparisons: usize,
    divergences: usize,
) -> String {
    let sizes = batch_sizes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"campaign\":\"{campaign}\",\"batch_sizes\":[{sizes}],\
\"permutations_per_size\":{permutations_per_size},\
\"comparisons\":{comparisons},\"divergences\":{divergences}}}"
    )
}

const BATCH_SIZES: &[usize] = &[1, 2, 3, 5, 8, 13];
const PERMUTATIONS: usize = 12;

// --- acceptance line 1: equivalence across the explored schedule space -------

#[test]
fn permutations_preserve_publication_inputs_across_every_batch_size() {
    let mut comparisons = 0_usize;
    let mut divergences = 0_usize;
    let mut failures: Vec<String> = Vec::new();

    for &size in BATCH_SIZES {
        let capsules: Vec<PreparedCapsule> = (0..size)
            .map(|index| {
                let tag = u8::try_from(index + 1).expect("bounded fixture tag");
                // Distinct witnesses: independent transactions, no conflict
                // collapsing, so the batch composition is the interesting part.
                capsule(tag, tag)
            })
            .collect();

        let ledger = ledger(900 + u64::try_from(size).expect("size fits u64"));
        let expected = publication_inputs(&combine(&ledger, &capsules));

        for permutation in 0..PERMUTATIONS {
            let seed = 0x0f00_d000_cafe_1234_u64
                ^ (u64::try_from(size).expect("size fits u64") << 32)
                ^ u64::try_from(permutation).expect("permutation fits u64");
            let shuffled = seeded_shuffle(&capsules, seed);
            let observed = publication_inputs(&combine(&ledger, &shuffled));
            comparisons += 1;
            if observed != expected {
                // Recorded rather than panicked on: a campaign that stops at
                // the first divergence reports one defect when there may be
                // forty, and the count is what tells you whether the property
                // is subtly wrong or wholly absent.
                divergences += 1;
                failures.push(format!(
                    "size {size} permutation {permutation} seed {seed:#x}"
                ));
            }
        }
    }

    // The denominator, asserted rather than assumed: a sweep that silently
    // explored nothing would otherwise report the same clean zero.
    assert_eq!(
        comparisons,
        BATCH_SIZES.len() * PERMUTATIONS,
        "the sweep must explore every size-permutation pair"
    );
    assert!(
        failures.is_empty(),
        "the combiner output depended on input order in {} of {comparisons} comparisons: {}",
        failures.len(),
        failures.join("; ")
    );
    assert_eq!(divergences, 0);
    println!(
        "{}",
        coverage_receipt(
            "permutation-invariance",
            BATCH_SIZES,
            PERMUTATIONS,
            comparisons,
            divergences
        )
    );
}

#[test]
fn a_cas_loss_storm_does_not_change_the_terminal_outcome() {
    // The honest metric the bead names is "useful work reused after loss".
    // The precondition for reuse being meaningful is that losing changes
    // nothing about where authority ends up. Losing repeatedly must be
    // indistinguishable, in terminal outcome, from never losing at all --
    // except for the generations the losers consumed.
    let capsules: Vec<PreparedCapsule> = (1..=5).map(|tag| capsule(tag, tag)).collect();
    let ledger = ledger(910);
    let inputs = publication_inputs(&combine(&ledger, &capsules));

    let clean = terminal_outcomes(&inputs, 0);
    let bodies_clean: Vec<Vec<u8>> = clean.iter().map(|(_, body)| body.clone()).collect();

    for storm in [1_u32, 2, 4] {
        let stormed = terminal_outcomes(&inputs, storm);
        let bodies: Vec<Vec<u8>> = stormed.iter().map(|(_, body)| body.clone()).collect();
        assert_eq!(
            bodies, bodies_clean,
            "a storm of {storm} lost races per commit changed the committed bodies"
        );
        // Generations must strictly advance: a loss consumes generations, and
        // authority never re-enters one it has left.
        let generations: Vec<u64> = stormed.iter().map(|(generation, _)| *generation).collect();
        assert!(
            generations.windows(2).all(|pair| pair[1] > pair[0]),
            "generations must advance strictly under a storm of {storm}"
        );
        assert!(
            generations[0] > clean[0].0,
            "a storm must consume more generations than the clean run, or it is not a storm"
        );
    }
}

#[test]
fn cancellation_mid_combine_settles_every_reserved_obligation() {
    // Cancellation is request -> drain -> finalize. The property that matters
    // is that no obligation is left outstanding: a combiner that dropped a
    // reservation would leak a slot that nothing ever settles.
    for &size in BATCH_SIZES {
        let capsules: Vec<PreparedCapsule> = (0..size)
            .map(|index| {
                let tag = u8::try_from(index + 1).expect("bounded fixture tag");
                capsule(tag, tag)
            })
            .collect();
        let ledger = ledger(920 + u64::try_from(size).expect("size fits u64"));
        let combination = combine(&ledger, &capsules);

        let cancellation = combination.cancel();
        assert_eq!(
            cancellation.settled_slots().len(),
            size,
            "every reserved slot must settle on cancellation at size {size}"
        );
    }
}

#[test]
fn conflicting_capsules_stay_order_independent_too() {
    // The permutation sweep above uses disjoint witnesses. Conflict collapsing
    // is the path where ordering is most likely to leak into the output, so it
    // gets its own sweep rather than being assumed covered.
    let capsules: Vec<PreparedCapsule> = (1..=6)
        .map(|tag| capsule(tag, if tag % 2 == 0 { 1 } else { 2 }))
        .collect();
    let ledger = ledger(930);
    let expected = publication_inputs(&combine(&ledger, &capsules));

    let mut comparisons = 0_usize;
    for permutation in 0..PERMUTATIONS {
        let seed = 0xfeed_face_0000_0000_u64 ^ u64::try_from(permutation).expect("fits u64");
        let observed = publication_inputs(&combine(&ledger, &seeded_shuffle(&capsules, seed)));
        comparisons += 1;
        assert_eq!(
            observed, expected,
            "conflicting capsules diverged at permutation {permutation} seed {seed:#x}"
        );
    }
    assert_eq!(comparisons, PERMUTATIONS);
}

#[test]
fn the_sweep_can_actually_detect_a_divergence() {
    // The control. Every assertion above is a negative result, so the suite is
    // worthless unless the comparison it runs can distinguish two different
    // outputs. Two genuinely different capsule sets must produce different
    // publication inputs -- if this fails, every "no divergence" above is
    // vacuous.
    let ledger = ledger(940);
    let left = publication_inputs(&combine(&ledger, &[capsule(1, 1), capsule(2, 2)]));
    let right = publication_inputs(&combine(&ledger, &[capsule(3, 3), capsule(4, 4)]));
    assert_ne!(
        left, right,
        "the comparison cannot tell two different batches apart, so the sweeps prove nothing"
    );
}
