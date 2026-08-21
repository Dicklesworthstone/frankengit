//! Conservation evidence for the graded resource algebra.
//!
//! The property tests below are seeded from a fixed, checked-in seed list so a
//! failure is replayable: every assertion message names the seed and the step
//! that produced it. They are property tests over a bounded input space, which
//! is bounded-model evidence, not a proof.

use fgit_resource::algebra::{Grade, GradeDisposition, ResourceError, ResourceVector};
use fgit_resource::custody::{LeakDisposition, ObligationLedger, RegionCloseOutcome};
use fgit_resource::ids::RegionId;

/// Checked-in seeds. A failure reproduces by running this file unchanged.
const SEEDS: [u64; 8] = [
    0x0000_0000_0000_0001,
    0x0BAD_C0DE_DEAD_BEEF,
    0x1234_5678_9ABC_DEF0,
    0x5DEE_CE66_D000_0005,
    0x9E37_79B9_7F4A_7C15,
    0xC0FF_EE00_C0FF_EE00,
    0xFEED_FACE_CAFE_BEEF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// Deterministic `SplitMix64`. Seeded, reproducible, and dependency-free.
struct Prng(u64);

impl Prng {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}

fn random_vector(rng: &mut Prng, ceiling: u64) -> ResourceVector {
    let pairs: Vec<(Grade, u64)> = Grade::ALL
        .into_iter()
        .map(|grade| (grade, rng.below(ceiling)))
        .collect();
    ResourceVector::from_grades(&pairs)
}

fn total_of(vector: &ResourceVector) -> u128 {
    vector
        .pairs()
        .into_iter()
        .map(|(_, amount)| u128::from(amount))
        .sum()
}

#[test]
fn grade_list_is_closed_and_ordered() {
    assert_eq!(Grade::ALL.len(), 10, "the algebra declares ten grades");
    for (position, grade) in Grade::ALL.iter().enumerate() {
        assert_eq!(
            grade.index(),
            position,
            "grade {grade} must sit at its declaration index"
        );
    }
    let consumable = Grade::ALL
        .into_iter()
        .filter(|grade| grade.disposition() == GradeDisposition::Consumable)
        .count();
    let returnable = Grade::ALL
        .into_iter()
        .filter(|grade| grade.disposition() == GradeDisposition::Returnable)
        .count();
    assert_eq!(
        consumable + returnable,
        Grade::ALL.len(),
        "every grade has exactly one disposition"
    );
    assert!(
        consumable > 0 && returnable > 0,
        "both dispositions are used"
    );
}

#[test]
fn combine_is_a_commutative_monoid_with_zero() {
    for seed in SEEDS {
        let mut rng = Prng::new(seed);
        for step in 0..64_u32 {
            let a = random_vector(&mut rng, 1_000_000);
            let b = random_vector(&mut rng, 1_000_000);
            let c = random_vector(&mut rng, 1_000_000);

            assert_eq!(
                a.combine(&ResourceVector::ZERO),
                Ok(a),
                "seed {seed:#x} step {step}: zero is a right identity"
            );
            assert_eq!(
                ResourceVector::ZERO.combine(&a),
                Ok(a),
                "seed {seed:#x} step {step}: zero is a left identity"
            );
            assert_eq!(
                a.combine(&b),
                b.combine(&a),
                "seed {seed:#x} step {step}: combine is commutative"
            );
            let left = a.combine(&b).and_then(|ab| ab.combine(&c));
            let right = b.combine(&c).and_then(|bc| a.combine(&bc));
            assert_eq!(
                left, right,
                "seed {seed:#x} step {step}: combine is associative"
            );
        }
    }
}

#[test]
fn combine_refuses_overflow_instead_of_wrapping() {
    let brim = ResourceVector::single(Grade::Bytes, u64::MAX);
    let one = ResourceVector::single(Grade::Bytes, 1);
    assert_eq!(
        brim.combine(&one),
        Err(ResourceError::Overflow {
            grade: Grade::Bytes,
            left: u64::MAX,
            right: 1,
        }),
        "an overflowing combine is a refusal naming the grade"
    );

    // Near-identical permitted case: the same composition one unit lower.
    let almost = ResourceVector::single(Grade::Bytes, u64::MAX - 1);
    assert_eq!(
        almost.combine(&one),
        Ok(brim),
        "the same composition below the ceiling proceeds"
    );
}

#[test]
fn split_conserves_exactly_or_refuses() {
    for seed in SEEDS {
        let mut rng = Prng::new(seed);
        for step in 0..128_u32 {
            let total = random_vector(&mut rng, 100_000);
            let part = random_vector(&mut rng, 100_000);
            match total.split(&part) {
                Ok((taken, rest)) => {
                    assert!(
                        total.dominates(&part),
                        "seed {seed:#x} step {step}: split only succeeds when the whole dominates"
                    );
                    assert_eq!(
                        taken, part,
                        "seed {seed:#x} step {step}: the part is returned unchanged"
                    );
                    assert_eq!(
                        taken.combine(&rest),
                        Ok(total),
                        "seed {seed:#x} step {step}: part plus remainder reproduces the whole"
                    );
                    assert_eq!(
                        total_of(&taken) + total_of(&rest),
                        total_of(&total),
                        "seed {seed:#x} step {step}: no grade gained or lost a unit"
                    );
                }
                Err(error) => {
                    let ResourceError::Conservation {
                        grade,
                        available,
                        requested,
                    } = error
                    else {
                        panic!("seed {seed:#x} step {step}: split refused with {error:?}");
                    };
                    assert_eq!(
                        available,
                        total.get(grade),
                        "seed {seed:#x} step {step}: refusal reports the real available amount"
                    );
                    assert_eq!(
                        requested,
                        part.get(grade),
                        "seed {seed:#x} step {step}: refusal reports the real requested amount"
                    );
                    assert!(
                        available < requested,
                        "seed {seed:#x} step {step}: refusal names a real deficit"
                    );
                }
            }
        }
    }
}

#[test]
fn split_that_would_mint_budget_is_refused_and_its_twin_proceeds() {
    let whole = ResourceVector::from_grades(&[(Grade::Bytes, 100), (Grade::Objects, 4)]);

    // Planted negative: one unit more than exists in a single grade.
    let minting = ResourceVector::from_grades(&[(Grade::Bytes, 101), (Grade::Objects, 4)]);
    assert_eq!(
        whole.split(&minting),
        Err(ResourceError::Conservation {
            grade: Grade::Bytes,
            available: 100,
            requested: 101,
        }),
        "a split that would mint one byte is refused, not clamped"
    );

    // Near-identical permitted case: exactly what exists.
    let exact = ResourceVector::from_grades(&[(Grade::Bytes, 100), (Grade::Objects, 4)]);
    let (taken, rest) = whole.split(&exact).expect("an exact split proceeds");
    assert_eq!(taken, exact);
    assert_eq!(rest, ResourceVector::ZERO);
    assert_eq!(taken.combine(&rest), Ok(whole));
}

#[test]
fn repeated_splitting_never_changes_the_total() {
    for seed in SEEDS {
        let mut rng = Prng::new(seed);
        let root = random_vector(&mut rng, 50_000);
        let mut leaves = vec![root];
        for round in 0..24_u32 {
            let index =
                usize::try_from(rng.below(u64::try_from(leaves.len()).unwrap_or(0))).unwrap_or(0);
            let Some(target) = leaves.get(index).copied() else {
                continue;
            };
            let part = ResourceVector::from_grades(
                &Grade::ALL
                    .into_iter()
                    .map(|grade| {
                        let have = target.get(grade);
                        (grade, rng.below(have.saturating_add(1)))
                    })
                    .collect::<Vec<_>>(),
            );
            let (taken, rest) = target
                .split(&part)
                .unwrap_or_else(|error| panic!("seed {seed:#x} round {round}: {error}"));
            if let Some(slot) = leaves.get_mut(index) {
                *slot = rest;
            }
            leaves.push(taken);
            let sum = leaves.iter().fold(ResourceVector::ZERO, |acc, leaf| {
                acc.combine(leaf).expect("leaf sum stays representable")
            });
            assert_eq!(
                sum, root,
                "seed {seed:#x} round {round}: the leaves of a split tree still sum to its root"
            );
        }
    }
}

#[test]
fn masking_partitions_an_amount_by_disposition() {
    let amount = ResourceVector::from_grades(&[
        (Grade::Bytes, 7),
        (Grade::MemoryBytes, 11),
        (Grade::MoneyMicros, 13),
        (Grade::FileDescriptors, 3),
    ]);
    let consumable = amount.mask(GradeDisposition::Consumable);
    let returnable = amount.mask(GradeDisposition::Returnable);
    assert_eq!(
        consumable.combine(&returnable),
        Ok(amount),
        "the two dispositions partition the amount exactly"
    );
    assert_eq!(consumable.get(Grade::Bytes), 7);
    assert_eq!(consumable.get(Grade::MemoryBytes), 0);
    assert_eq!(returnable.get(Grade::MemoryBytes), 11);
    assert_eq!(returnable.get(Grade::MoneyMicros), 0);
}

#[test]
fn grant_split_and_absorb_preserve_the_pool_identity() {
    for seed in SEEDS {
        let mut rng = Prng::new(seed);
        let capacity = random_vector(&mut rng, 100_000);
        let ledger = ObligationLedger::root(
            RegionId::new(seed),
            LeakDisposition::RecordAndContinue,
            capacity,
        );
        let mut held = Vec::new();

        for step in 0..96_u32 {
            assert!(
                ledger.snapshot().is_conserved(),
                "seed {seed:#x} step {step}: pool identity before the step"
            );
            match rng.below(4) {
                0 => {
                    let want = ResourceVector::from_grades(
                        &Grade::ALL
                            .into_iter()
                            .map(|grade| {
                                let have = ledger.snapshot().available().get(grade);
                                (grade, rng.below(have.saturating_add(1)))
                            })
                            .collect::<Vec<_>>(),
                    );
                    if let Ok(grant) = ledger.grant(want) {
                        held.push(grant);
                    }
                }
                1 => {
                    if held.is_empty() {
                        continue;
                    }
                    let index = usize::try_from(rng.below(u64::try_from(held.len()).unwrap_or(0)))
                        .unwrap_or(0);
                    let Some(grant) = held.get_mut(index) else {
                        continue;
                    };
                    let amount = grant.amount();
                    let part = ResourceVector::from_grades(
                        &Grade::ALL
                            .into_iter()
                            .map(|grade| (grade, rng.below(amount.get(grade).saturating_add(1))))
                            .collect::<Vec<_>>(),
                    );
                    let expected = amount;
                    if let Ok(carved) = grant.split_off(&part) {
                        assert_eq!(
                            carved.amount().combine(&grant.amount()),
                            Ok(expected),
                            "seed {seed:#x} step {step}: a grant split conserves its amount"
                        );
                        held.push(carved);
                    }
                }
                2 => {
                    if held.len() < 2 {
                        continue;
                    }
                    let donor = held.pop().expect("checked length");
                    let donor_amount = donor.amount();
                    let index = usize::try_from(rng.below(u64::try_from(held.len()).unwrap_or(0)))
                        .unwrap_or(0);
                    let Some(target) = held.get_mut(index) else {
                        continue;
                    };
                    let before = target.amount();
                    target
                        .absorb(donor)
                        .unwrap_or_else(|error| panic!("seed {seed:#x} step {step}: {error}"));
                    assert_eq!(
                        target.amount(),
                        before.combine(&donor_amount).expect("sum stays in range"),
                        "seed {seed:#x} step {step}: absorbing composes grades"
                    );
                }
                _ => {
                    if held.is_empty() {
                        continue;
                    }
                    let index = usize::try_from(rng.below(u64::try_from(held.len()).unwrap_or(0)))
                        .unwrap_or(0);
                    if index < held.len() {
                        let before = ledger.snapshot().available();
                        let grant = held.swap_remove(index);
                        let expected_id = grant.id();
                        let expected_amount = grant.amount();
                        let released = grant.release();
                        assert_eq!(released.id(), expected_id);
                        assert_eq!(
                            released.amount(),
                            expected_amount,
                            "seed {seed:#x} step {step}: release returns exactly what was held"
                        );
                        assert_eq!(
                            ledger.snapshot().available(),
                            before
                                .combine(&expected_amount)
                                .expect("sum stays in range"),
                            "seed {seed:#x} step {step}: the pool grows by exactly the release"
                        );
                    }
                }
            }
            assert!(
                ledger.snapshot().is_conserved(),
                "seed {seed:#x} step {step}: pool identity after the step"
            );
        }

        for grant in held {
            let _receipt = grant.release();
        }
        let snapshot = ledger.snapshot();
        assert!(
            snapshot.is_conserved(),
            "seed {seed:#x}: final pool identity"
        );
        assert_eq!(
            snapshot.available(),
            capacity,
            "seed {seed:#x}: releasing everything restores the whole capacity"
        );
        let outcome = ledger.close();
        assert!(
            outcome.is_quiescent(),
            "seed {seed:#x}: a region that released everything closes quiescent, got {outcome:?}"
        );
    }
}

#[test]
fn a_dropped_grant_returns_its_budget_and_records_a_leak() {
    let capacity = ResourceVector::single(Grade::Bytes, 500);
    let ledger = ObligationLedger::root(
        RegionId::new(77),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    {
        let grant = ledger
            .grant(ResourceVector::single(Grade::Bytes, 300))
            .expect("capacity covers the grant");
        assert_eq!(grant.amount().get(Grade::Bytes), 300);
        // Dropped on purpose: this is the planted negative.
    }
    let snapshot = ledger.snapshot();
    assert!(
        snapshot.is_conserved(),
        "a leak is never an accounting hole"
    );
    assert_eq!(
        snapshot.available(),
        capacity,
        "the dropped grant's budget returns to the pool"
    );
    let leaks = ledger.leaks();
    assert_eq!(leaks.len(), 1, "the drop is recorded exactly once");
    let record = leaks.first().expect("checked length");
    assert_eq!(record.reclaimed().get(Grade::Bytes), 300);
    match ledger.close() {
        RegionCloseOutcome::ContainmentFailure(failure) => {
            assert_eq!(failure.leaks().len(), 1, "close reports the leak");
        }
        RegionCloseOutcome::Quiescent(receipt) => {
            panic!("a leaked grant must not close quiescent: {receipt:?}")
        }
    }
}

#[test]
fn a_child_region_cannot_mint_budget_and_returns_what_it_did_not_spend() {
    let capacity = ResourceVector::from_grades(&[(Grade::Bytes, 1_000), (Grade::CpuMicros, 400)]);
    let parent = ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        capacity,
    );
    let funding = ResourceVector::from_grades(&[(Grade::Bytes, 600), (Grade::CpuMicros, 100)]);
    let grant = parent.grant(funding).expect("parent can fund the child");
    let child = parent.child(RegionId::new(2), LeakDisposition::RecordAndContinue, grant);

    assert_eq!(
        child.snapshot().capacity(),
        funding,
        "a child's capacity is exactly the grant it was handed"
    );
    assert_eq!(
        child
            .grant(ResourceVector::single(Grade::Bytes, 601))
            .map(|grant| grant.amount()),
        Err(fgit_resource::algebra::ResourceError::Conservation {
            grade: Grade::Bytes,
            available: 600,
            requested: 601,
        }),
        "a child cannot hand out more than it was funded with"
    );

    // Near-identical permitted case: one unit less proceeds.
    let inner = child
        .grant(ResourceVector::single(Grade::Bytes, 600))
        .expect("the child can hand out exactly what it holds");
    let _receipt = inner.release();

    assert!(parent.snapshot().is_conserved());
    assert_eq!(
        parent.snapshot().delegated(),
        funding,
        "the parent records the child's capacity as delegated, not available"
    );

    let child_outcome = child.close();
    assert!(child_outcome.is_quiescent(), "{child_outcome:?}");
    let after = parent.snapshot();
    assert!(after.is_conserved(), "parent identity survives child close");
    assert_eq!(
        after.accounting_faults(),
        0,
        "returning a child's capacity completes without an accounting fault"
    );
    assert_eq!(
        after.available(),
        capacity,
        "an unspent child returns its whole capacity to the parent"
    );
    assert!(
        after.delegated().is_zero(),
        "delegation is cleared at close"
    );
    let outcome = parent.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}
