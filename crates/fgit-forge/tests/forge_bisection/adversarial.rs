//! FG-038b: unknown shapes, sparse publications, incomplete histories and cancellation.
use super::*;
use fgit_forge::bisection::{
    ProbeObservation, RefTargetPredicate, execute_bisection_with_control,
    search_published_positions,
};
use fgit_types::{GitOid, GitOidSha1};
use std::cell::Cell;

fn seq(value: u64) -> DecisionSequence {
    DecisionSequence::try_new(value).unwrap()
}
fn range(first: u64, last: u64) -> BisectionRange {
    BisectionRange::new(seq(first), seq(last)).unwrap()
}
fn observation(value: bool) -> ProbeObservation {
    ProbeObservation {
        outcome: Ok(if value {
            PredicateOutcome::Satisfied
        } else {
            PredicateOutcome::Unsatisfied
        }),
        head_id: fake_head_id(1),
        policy_epoch: PolicyEpoch::FIRST,
        replayed_batches: 1,
    }
}

#[test]
fn segmented_search_never_skips_transient_matches_and_matches_linear_oracle() {
    for bits in 0_u64..256 {
        check_pattern(&(0..8).map(|bit| bits & (1 << bit) != 0).collect::<Vec<_>>());
    }
    let mut random = 0x891ae747d94be155_u64;
    for _ in 0..128 {
        let values: Vec<_> = (0..97)
            .map(|_| {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                random & 15 == 0
            })
            .collect();
        check_pattern(&values);
    }
}
fn check_pattern(values: &[bool]) {
    let target = GitOid::from(GitOidSha1::from_bytes([1; 20]));
    let other = GitOid::from(GitOidSha1::from_bytes([2; 20]));
    let mut history = create_test_history(values.len() as u64, None);
    for (batch, value) in history.iter_mut().zip(values) {
        batch.ref_updates = vec![(
            b"refs/heads/main".to_vec(),
            Some(if *value { target } else { other }),
        )];
    }
    let head = dummy_head_body(test_repo_id(), values.len() as u64);
    let refs = BTreeMap::new();
    let context = BisectionContext {
        head_id: fake_head_id(4),
        head_body: &head,
        available_capsules: &[],
        historical_batches: &history,
        base_refs: &refs,
        disclosure_policy: None,
        snapshot_limits: SnapshotLimits::default(),
    };
    let predicate = RefTargetPredicate {
        reference_name: b"refs/heads/main".to_vec(),
        expected_oid: target,
    };
    let expected = values
        .iter()
        .position(|value| *value)
        .map(|i| seq(i as u64 + 1));
    assert_eq!(
        linear_scan_oracle(range(1, values.len() as u64), &predicate, &context)
            .unwrap()
            .0,
        expected
    );
    for segment_size in [0, 1, 2, 5, 128, usize::MAX] {
        let shape = MonotonicityShape::BoundedSegmented {
            segment_size,
            max_steps: values.len(),
        };
        let found = execute_bisection(range(1, values.len() as u64), shape, &predicate, &context);
        assert_eq!(
            found.transition_found, expected,
            "pattern={values:?} segment={segment_size}"
        );
        assert!(!matches!(
            found.termination,
            BisectionTermination::Refused { .. }
        ));
        assert_eq!(
            found.steps_taken,
            expected.map_or(values.len(), |at| at.get() as usize)
        );
        assert!(
            found
                .probes
                .windows(2)
                .all(|pair| pair[0].sequence.get() + 1 == pair[1].sequence.get())
        );
    }
}

#[test]
fn sparse_domain_probes_only_published_batch_endpoints_including_u64_max() {
    let positions = [seq(5), seq(19), seq(u64::MAX)];
    for shape in [
        MonotonicityShape::GuaranteedMonotone {
            expected_direction: Some(TransitionDirection::UnsatisfiedToSatisfied),
        },
        MonotonicityShape::BoundedSegmented {
            segment_size: usize::MAX,
            max_steps: 3,
        },
        MonotonicityShape::LinearOnly { max_steps: 3 },
    ] {
        let report = search_published_positions(
            test_repo_id(),
            range(5, u64::MAX),
            shape,
            &positions,
            |position| {
                assert!(positions.contains(&position));
                Ok(observation(position.get() >= 19))
            },
            &mut || true,
        );
        assert_eq!(report.transition_found, Some(seq(19)));
        assert!(
            report
                .probes
                .iter()
                .all(|probe| positions.contains(&probe.sequence))
        );
    }
    for positions in [
        vec![],
        vec![seq(5)],
        vec![seq(5), seq(5), seq(19)],
        vec![seq(19), seq(5)],
    ] {
        let report = search_published_positions(
            test_repo_id(),
            range(5, 19),
            MonotonicityShape::LinearOnly { max_steps: 10 },
            &positions,
            |_| panic!("invalid domain must not be read"),
            &mut || true,
        );
        assert!(matches!(
            report.termination,
            BisectionTermination::Refused {
                reason: BisectionRefusal::AmbiguousRange { .. }
            }
        ));
    }
}

#[test]
fn declared_monotonicity_is_an_assumption_not_sampling_evidence() {
    let positions: Vec<_> = (1..=17).map(seq).collect();
    let values: Vec<_> = (1..=17).map(|i| i == 2 || i == 17).collect();
    let search = |shape| {
        search_published_positions(
            test_repo_id(),
            range(1, 17),
            shape,
            &positions,
            |at| Ok(observation(values[at.get() as usize - 1])),
            &mut || true,
        )
    };
    let conditional = search(MonotonicityShape::GuaranteedMonotone {
        expected_direction: Some(TransitionDirection::UnsatisfiedToSatisfied),
    });
    let exact = search(MonotonicityShape::LinearOnly { max_steps: 17 });
    assert_eq!(conditional.transition_found, Some(seq(17)));
    assert_eq!(exact.transition_found, Some(seq(2)));
    assert!(matches!(
        conditional.monotonicity_shape,
        MonotonicityShape::GuaranteedMonotone { .. }
    ));
    assert_ne!(conditional.receipt_digest, exact.receipt_digest);
}

#[test]
fn snapshot_absence_corruption_and_atomic_interiors_have_typed_refusals() {
    let head = dummy_head_body(test_repo_id(), 3);
    let refs = BTreeMap::new();
    let mut history = create_test_history(3, None);
    let project = |history: &[HistoricalBatch], at| {
        BisectionContext {
            head_id: fake_head_id(4),
            head_body: &head,
            available_capsules: &[],
            historical_batches: history,
            base_refs: &refs,
            disclosure_policy: None,
            snapshot_limits: SnapshotLimits::default(),
        }
        .project_sequence(seq(at))
    };
    assert!(project(&history, 2).is_ok());
    assert!(matches!(
        project(&history, 4),
        Err(BisectionRefusal::MissingPosition { sequence: 4 })
    ));
    let removed = history.remove(1);
    assert!(matches!(
        project(&history, 2),
        Err(BisectionRefusal::MissingPosition { sequence: 2 })
    ));
    history.insert(1, removed);
    history[1].batch.repository_id = RepositoryId::from_bytes([9; 16]);
    assert!(matches!(
        project(&history, 2),
        Err(BisectionRefusal::CorruptSnapshot { sequence: 2, .. })
    ));
    history[1].batch.repository_id = test_repo_id();
    let third = history.pop().unwrap();
    history[1].batch.decisions.extend(third.batch.decisions);
    assert!(matches!(
        project(&history, 2),
        Err(BisectionRefusal::AmbiguousRange { .. })
    ));
    assert!(project(&history, 3).is_ok());
}

#[test]
fn cancellation_and_probe_exhaustion_cannot_become_a_no_match_answer() {
    let positions = [seq(1), seq(2)];
    for stop_at in 0..=4 {
        let checks = Cell::new(0);
        let reads = Cell::new(0);
        let report = search_published_positions(
            test_repo_id(),
            range(1, 2),
            MonotonicityShape::LinearOnly { max_steps: 2 },
            &positions,
            |at| {
                reads.set(reads.get() + 1);
                Ok(observation(at.get() == 2))
            },
            &mut || {
                let count = checks.get();
                checks.set(count + 1);
                count < stop_at
            },
        );
        if stop_at == 4 {
            assert_eq!(report.transition_found, Some(seq(2)));
        } else {
            assert!(matches!(
                report.termination,
                BisectionTermination::Refused {
                    reason: BisectionRefusal::Cancelled { .. }
                }
            ));
            assert!(report.transition_found.is_none());
        }
        assert!(reads.get() <= 2);
    }
    let report = search_published_positions(
        test_repo_id(),
        range(1, 2),
        MonotonicityShape::LinearOnly { max_steps: 1 },
        &positions,
        |_| Ok(observation(false)),
        &mut || true,
    );
    assert!(matches!(
        report.termination,
        BisectionTermination::Refused {
            reason: BisectionRefusal::BudgetExhausted {
                steps_taken: 1,
                max_budget: 1
            }
        }
    ));
    let history = create_test_history(2, None);
    let head = dummy_head_body(test_repo_id(), 2);
    let refs = BTreeMap::new();
    let context = BisectionContext {
        head_id: fake_head_id(4),
        head_body: &head,
        available_capsules: &[],
        historical_batches: &history,
        base_refs: &refs,
        disclosure_policy: None,
        snapshot_limits: SnapshotLimits::default(),
    };
    let predicate = |_: &ForgeSnapshot| Ok::<_, String>(PredicateOutcome::Satisfied);
    let stopped = execute_bisection_with_control(
        range(1, 2),
        MonotonicityShape::LinearOnly { max_steps: 2 },
        &predicate,
        &context,
        &mut || false,
    );
    assert!(matches!(
        stopped.termination,
        BisectionTermination::Refused {
            reason: BisectionRefusal::Cancelled { sequence: 1 }
        }
    ));
    assert!(stopped.probes.is_empty());
}
