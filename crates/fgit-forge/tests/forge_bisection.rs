#![forbid(unsafe_code)]

//! Unit, property, and acceptance tests for the forge-state bisection engine (FG-038b).

use std::collections::BTreeMap;

use fgit_codec::schema::{
    RepositoryAuthorityHeadBody, RepositoryDecision, RepositoryDecisionBatchBody,
};
use fgit_forge::aggregate::{AggregateId, AggregateVersion, PullRequestNumber};
use fgit_forge::bisection::{
    BisectionContext, BisectionRange, BisectionReceipt, BisectionRefusal, BisectionTermination,
    MonotonicityShape, PredicateOutcome, ProbeRecord, PullRequestStatePredicate,
    TransitionDirection, execute_bisection, linear_scan_oracle, logarithmic_probe_budget,
};
use fgit_forge::event::{ForgeEvent, ForgeEventPayload};
use fgit_forge::snapshot::{
    ForgeSnapshot, HistoricalBatch, PullRequestState, SnapshotDisclosurePolicy, SnapshotLimits,
};
use fgit_types::vocabulary::DecisionOutcome;
use fgit_types::{
    CodecVersion, DecisionSequence, Digest, DigestAlgorithmId, DigestBytes, HeadGeneration,
    PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryDecisionBatchId, RepositoryId, TxId,
};

fn fake_digest(byte: u8) -> Digest {
    let mut bytes = [0_u8; 32];
    bytes[0] = byte;
    Digest::new(
        DigestAlgorithmId::try_new(1).unwrap(),
        DigestBytes::try_new(&bytes).unwrap(),
    )
}

fn fake_head_id(byte: u8) -> RepositoryAuthorityHeadId {
    let mut bytes = [0_u8; 32];
    bytes[0] = byte;
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&bytes).unwrap(),
    )
}

fn fake_batch_id(byte: u8) -> RepositoryDecisionBatchId {
    let mut bytes = [0_u8; 32];
    bytes[0] = byte;
    RepositoryDecisionBatchId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&bytes).unwrap(),
    )
}

fn fake_commit_id(byte: u8) -> RepositoryCommitId {
    let mut bytes = [0_u8; 32];
    bytes[0] = byte;
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&bytes).unwrap(),
    )
}

fn fake_tx_id(byte: u8) -> TxId {
    let mut bytes = [0_u8; 32];
    bytes[0] = byte;
    TxId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&bytes).unwrap(),
    )
}

fn test_repo_id() -> RepositoryId {
    RepositoryId::from_bytes([0x42; 16])
}

fn dummy_head_body(repo_id: RepositoryId, latest_seq: u64) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repo_id,
        generation: HeadGeneration::try_new(1).unwrap(),
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: DecisionSequence::try_new(latest_seq).ok(),
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: fake_digest(0x11),
        forge_position_root: fake_digest(0x22),
        outcome_index_root: fake_digest(0x55),
        retention_root: fake_digest(0x33),
        outbox_root: fake_digest(0x44),
        configuration_root: fake_digest(0x66),
        policy_epoch: PolicyEpoch::try_new(1).unwrap(),
        format_registry_epoch: RegistryEpoch::try_new(1).unwrap(),
        last_checkpoint_id: None,
    }
}

fn create_test_history(total_decisions: u64, flip_at: Option<u64>) -> Vec<HistoricalBatch> {
    let mut batches = Vec::with_capacity(total_decisions as usize);
    let pr_num = PullRequestNumber::try_new(1).unwrap();

    for seq in 1..=total_decisions {
        let dec_seq = DecisionSequence::try_new(seq).unwrap();
        let events = if Some(seq) == flip_at {
            if seq == 1 {
                vec![
                    ForgeEvent {
                        aggregate: AggregateId::PullRequest(pr_num),
                        version: AggregateVersion::try_new(1).unwrap(),
                        payload: ForgeEventPayload::PullRequestOpened {
                            source_ref: b"refs/heads/feature".to_vec(),
                            target_ref: b"refs/heads/main".to_vec(),
                            source_tip: fake_digest(0x01),
                            target_tip: fake_digest(0x02),
                        },
                    },
                    ForgeEvent {
                        aggregate: AggregateId::PullRequest(pr_num),
                        version: AggregateVersion::try_new(2).unwrap(),
                        payload: ForgeEventPayload::MergeCommitted {
                            merge_commit: fake_digest(0x99),
                            target_ref: b"refs/heads/main".to_vec(),
                            target_tip_before: fake_digest(0x20),
                            target_tip_after: fake_digest(0xaa),
                        },
                    },
                ]
            } else {
                vec![ForgeEvent {
                    aggregate: AggregateId::PullRequest(pr_num),
                    version: AggregateVersion::try_new(seq + 1).unwrap(),
                    payload: ForgeEventPayload::MergeCommitted {
                        merge_commit: fake_digest(0x99),
                        target_ref: b"refs/heads/main".to_vec(),
                        target_tip_before: fake_digest(0x20),
                        target_tip_after: fake_digest(0xaa),
                    },
                }]
            }
        } else if seq == 1 {
            vec![ForgeEvent {
                aggregate: AggregateId::PullRequest(pr_num),
                version: AggregateVersion::try_new(1).unwrap(),
                payload: ForgeEventPayload::PullRequestOpened {
                    source_ref: b"refs/heads/feature".to_vec(),
                    target_ref: b"refs/heads/main".to_vec(),
                    source_tip: fake_digest(0x01),
                    target_tip: fake_digest(0x02),
                },
            }]
        } else {
            vec![ForgeEvent {
                aggregate: AggregateId::PullRequest(pr_num),
                version: AggregateVersion::try_new(seq).unwrap(),
                payload: ForgeEventPayload::PullRequestHeadAdvanced {
                    source_tip: fake_digest(seq as u8),
                },
            }]
        };

        batches.push(HistoricalBatch {
            batch_id: fake_batch_id(seq as u8),
            resulting_head_id: fake_head_id(seq as u8),
            resulting_head_generation: HeadGeneration::try_new(seq).unwrap(),
            batch: RepositoryDecisionBatchBody {
                repository_id: test_repo_id(),
                predecessor_head_id: fake_head_id((seq - 1) as u8),
                predecessor_head_generation: HeadGeneration::try_new((seq - 1).max(1)).unwrap(),
                first_decision_sequence: dec_seq,
                decisions: vec![RepositoryDecision {
                    tx_id: fake_tx_id(seq as u8),
                    decision_sequence: dec_seq,
                    outcome: DecisionOutcome::Committed {
                        repository_commit_id: fake_commit_id(seq as u8),
                    },
                }],
                committed_rcrs: Vec::new(),
                resulting_ref_root: fake_digest(0x11),
                resulting_forge_position_root: fake_digest(0x22),
                resulting_outcome_index_root: fake_digest(0x55),
                resulting_retention_root: fake_digest(0x33),
                resulting_outbox_root: fake_digest(0x44),
                resulting_policy_epoch: PolicyEpoch::try_new(1).unwrap(),
                batch_evidence_root: fake_digest(0x77),
                compaction_generation_link: None,
            },
            forge_events: events,
            ref_updates: Vec::new(),
        });
    }
    batches
}

#[test]
fn test_seeded_monotone_predicates_converge_in_logarithmic_bound() {
    let total_decisions = 128u64;
    let flip_point = 47u64;
    let history = create_test_history(total_decisions, Some(flip_point));
    let head_body = dummy_head_body(test_repo_id(), total_decisions);
    let head_id = fake_head_id(0x55);
    let base_refs = BTreeMap::new();

    let context = BisectionContext {
        head_id,
        head_body: &head_body,
        available_capsules: &[],
        historical_batches: &history,
        base_refs: &base_refs,
        disclosure_policy: None,
        snapshot_limits: SnapshotLimits::default(),
    };

    let pr_pred = PullRequestStatePredicate {
        pull_request: PullRequestNumber::try_new(1).unwrap(),
        expected_state: PullRequestState::Merged {
            merge_commit: fake_digest(0x99),
            target_tip_after: fake_digest(0xaa),
        },
    };

    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(total_decisions).unwrap(),
    )
    .unwrap();

    let max_log_budget = logarithmic_probe_budget(range.len());
    assert!(max_log_budget <= 10, "log2(128) + 2 = 9 probes");

    let receipt = execute_bisection(
        range,
        MonotonicityShape::GuaranteedMonotone {
            expected_direction: Some(TransitionDirection::UnsatisfiedToSatisfied),
        },
        &pr_pred,
        &context,
    );

    match receipt.termination {
        BisectionTermination::Converged {
            transition_sequence,
        } => {
            assert_eq!(
                transition_sequence.get(),
                flip_point,
                "Bisection must converge to exact transition point"
            );
        }
        other => panic!("Expected converged bisection, got: {other:?}"),
    }

    assert_eq!(
        receipt.transition_found,
        Some(DecisionSequence::try_new(flip_point).unwrap())
    );
    assert!(
        receipt.steps_taken <= max_log_budget,
        "Steps taken ({}) must not exceed logarithmic budget ({})",
        receipt.steps_taken,
        max_log_budget
    );
}

#[test]
fn test_deterministic_receipt_invariance() {
    let total_decisions = 64u64;
    let flip_point = 23u64;
    let history = create_test_history(total_decisions, Some(flip_point));
    let head_body = dummy_head_body(test_repo_id(), total_decisions);
    let head_id = fake_head_id(0x55);
    let base_refs = BTreeMap::new();

    let context = BisectionContext {
        head_id,
        head_body: &head_body,
        available_capsules: &[],
        historical_batches: &history,
        base_refs: &base_refs,
        disclosure_policy: None,
        snapshot_limits: SnapshotLimits::default(),
    };

    let pred = PullRequestStatePredicate {
        pull_request: PullRequestNumber::try_new(1).unwrap(),
        expected_state: PullRequestState::Merged {
            merge_commit: fake_digest(0x99),
            target_tip_after: fake_digest(0xaa),
        },
    };

    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(total_decisions).unwrap(),
    )
    .unwrap();

    let receipt1 = execute_bisection(
        range,
        MonotonicityShape::GuaranteedMonotone {
            expected_direction: None,
        },
        &pred,
        &context,
    );

    let receipt2 = execute_bisection(
        range,
        MonotonicityShape::GuaranteedMonotone {
            expected_direction: None,
        },
        &pred,
        &context,
    );

    assert_eq!(
        receipt1.receipt_digest, receipt2.receipt_digest,
        "Receipt digest must be byte-identical across runs"
    );
    assert_eq!(
        receipt1.probes, receipt2.probes,
        "Probe sequences must be identical"
    );
    assert_eq!(receipt1.steps_taken, receipt2.steps_taken);
    assert_eq!(receipt1.transition_found, receipt2.transition_found);
}

#[test]
fn test_bisection_vs_linear_oracle_across_all_flip_positions() {
    let total_decisions = 30u64;
    let base_refs = BTreeMap::new();

    for flip in 1..=total_decisions {
        let history = create_test_history(total_decisions, Some(flip));
        let head_body = dummy_head_body(test_repo_id(), total_decisions);
        let head_id = fake_head_id(0x55);

        let context = BisectionContext {
            head_id,
            head_body: &head_body,
            available_capsules: &[],
            historical_batches: &history,
            base_refs: &base_refs,
            disclosure_policy: None,
            snapshot_limits: SnapshotLimits::default(),
        };

        let pred = PullRequestStatePredicate {
            pull_request: PullRequestNumber::try_new(1).unwrap(),
            expected_state: PullRequestState::Merged {
                merge_commit: fake_digest(0x99),
                target_tip_after: fake_digest(0xaa),
            },
        };

        let range = BisectionRange::new(
            DecisionSequence::try_new(1).unwrap(),
            DecisionSequence::try_new(total_decisions).unwrap(),
        )
        .unwrap();

        // 1. Run Linear Oracle
        let (oracle_transition, oracle_outcomes) =
            linear_scan_oracle(range, &pred, &context).expect("oracle succeeds");

        // 2. Run Logarithmic Bisection
        let receipt = execute_bisection(
            range,
            MonotonicityShape::GuaranteedMonotone {
                expected_direction: None,
            },
            &pred,
            &context,
        );

        assert_eq!(
            receipt.transition_found, oracle_transition,
            "Bisection must match linear oracle exactly for flip={flip}"
        );
        assert_eq!(
            receipt.transition_found,
            Some(DecisionSequence::try_new(flip).unwrap())
        );
        assert_eq!(oracle_outcomes.len(), total_decisions as usize);
    }
}

#[test]
fn test_no_transition_boundary_conditions() {
    let total_decisions = 20u64;
    // No flip anywhere (never merged)
    let history = create_test_history(total_decisions, None);
    let head_body = dummy_head_body(test_repo_id(), total_decisions);
    let head_id = fake_head_id(0x55);
    let base_refs = BTreeMap::new();

    let context = BisectionContext {
        head_id,
        head_body: &head_body,
        available_capsules: &[],
        historical_batches: &history,
        base_refs: &base_refs,
        disclosure_policy: None,
        snapshot_limits: SnapshotLimits::default(),
    };

    let pred = PullRequestStatePredicate {
        pull_request: PullRequestNumber::try_new(1).unwrap(),
        expected_state: PullRequestState::Merged {
            merge_commit: fake_digest(0x99),
            target_tip_after: fake_digest(0xaa),
        },
    };

    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(total_decisions).unwrap(),
    )
    .unwrap();

    let receipt = execute_bisection(
        range,
        MonotonicityShape::GuaranteedMonotone {
            expected_direction: Some(TransitionDirection::UnsatisfiedToSatisfied),
        },
        &pred,
        &context,
    );

    assert_eq!(receipt.transition_found, None);
    assert_eq!(
        receipt.termination,
        BisectionTermination::NoTransition {
            uniform_outcome: PredicateOutcome::Unsatisfied,
        }
    );
}

#[test]
fn test_non_monotone_detection_and_typed_refusal() {
    let total_decisions = 10u64;
    let head_body = dummy_head_body(test_repo_id(), total_decisions);
    let head_id = fake_head_id(0x55);
    let base_refs = BTreeMap::new();
    let history = create_test_history(total_decisions, None);

    let context = BisectionContext {
        head_id,
        head_body: &head_body,
        available_capsules: &[],
        historical_batches: &history,
        base_refs: &base_refs,
        disclosure_policy: None,
        snapshot_limits: SnapshotLimits::default(),
    };

    // Construct a non-monotone oscillating predicate: satisfied at seq 1, unsatisfied at seq 10
    // but declared as UnsatisfiedToSatisfied
    let oscillating_pred =
        |snapshot: &ForgeSnapshot| -> Result<PredicateOutcome, core::convert::Infallible> {
            let seq = snapshot
                .effective_decision_sequence
                .map(|s| s.get())
                .unwrap_or(1);
            if seq == 1 {
                Ok(PredicateOutcome::Satisfied)
            } else {
                Ok(PredicateOutcome::Unsatisfied)
            }
        };

    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(total_decisions).unwrap(),
    )
    .unwrap();

    let receipt = execute_bisection(
        range,
        MonotonicityShape::GuaranteedMonotone {
            expected_direction: Some(TransitionDirection::UnsatisfiedToSatisfied),
        },
        &oscillating_pred,
        &context,
    );

    match receipt.termination {
        BisectionTermination::Refused {
            reason: BisectionRefusal::NonMonotoneDetected { sequence, .. },
        } => {
            assert_eq!(sequence, 1, "Must detect boundary violation immediately");
        }
        other => panic!("Expected NonMonotoneDetected refusal, got {other:?}"),
    }
}

#[test]
fn test_bounded_segmented_and_linear_search_fallback() {
    let total_decisions = 25u64;
    let flip_point = 17u64;
    let history = create_test_history(total_decisions, Some(flip_point));
    let head_body = dummy_head_body(test_repo_id(), total_decisions);
    let head_id = fake_head_id(0x55);
    let base_refs = BTreeMap::new();

    let context = BisectionContext {
        head_id,
        head_body: &head_body,
        available_capsules: &[],
        historical_batches: &history,
        base_refs: &base_refs,
        disclosure_policy: None,
        snapshot_limits: SnapshotLimits::default(),
    };

    let pred = PullRequestStatePredicate {
        pull_request: PullRequestNumber::try_new(1).unwrap(),
        expected_state: PullRequestState::Merged {
            merge_commit: fake_digest(0x99),
            target_tip_after: fake_digest(0xaa),
        },
    };

    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(total_decisions).unwrap(),
    )
    .unwrap();

    // Test BoundedSegmented search with segment_size = 5
    let receipt_seg = execute_bisection(
        range,
        MonotonicityShape::BoundedSegmented {
            segment_size: 5,
            max_steps: 30,
        },
        &pred,
        &context,
    );

    assert_eq!(
        receipt_seg.transition_found,
        Some(DecisionSequence::try_new(flip_point).unwrap())
    );

    // Test LinearOnly search
    let receipt_lin = execute_bisection(
        range,
        MonotonicityShape::LinearOnly { max_steps: 30 },
        &pred,
        &context,
    );

    assert_eq!(
        receipt_lin.transition_found,
        Some(DecisionSequence::try_new(flip_point).unwrap())
    );
}

#[test]
fn test_budget_exhaustion_refusal() {
    let total_decisions = 100u64;
    let history = create_test_history(total_decisions, Some(80));
    let head_body = dummy_head_body(test_repo_id(), total_decisions);
    let head_id = fake_head_id(0x55);
    let base_refs = BTreeMap::new();

    let context = BisectionContext {
        head_id,
        head_body: &head_body,
        available_capsules: &[],
        historical_batches: &history,
        base_refs: &base_refs,
        disclosure_policy: None,
        snapshot_limits: SnapshotLimits::default(),
    };

    let pred = PullRequestStatePredicate {
        pull_request: PullRequestNumber::try_new(1).unwrap(),
        expected_state: PullRequestState::Merged {
            merge_commit: fake_digest(0x99),
            target_tip_after: fake_digest(0xaa),
        },
    };

    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(total_decisions).unwrap(),
    )
    .unwrap();

    // Provide inadequate budget (e.g. max_steps = 3 for linear search)
    let receipt = execute_bisection(
        range,
        MonotonicityShape::LinearOnly { max_steps: 3 },
        &pred,
        &context,
    );

    match receipt.termination {
        BisectionTermination::Refused {
            reason:
                BisectionRefusal::BudgetExhausted {
                    steps_taken,
                    max_budget,
                },
        } => {
            assert_eq!(steps_taken, 3);
            assert_eq!(max_budget, 3);
        }
        other => panic!("Expected BudgetExhausted refusal, got {other:?}"),
    }
}

#[test]
fn test_revoked_disclosure_policy_filtering() {
    let total_decisions = 10u64;
    let history = create_test_history(total_decisions, Some(5));
    let head_body = dummy_head_body(test_repo_id(), total_decisions);
    let head_id = fake_head_id(0x55);
    let base_refs = BTreeMap::new();

    // Revoke all access for unauthorized actor
    let policy = SnapshotDisclosurePolicy::revoked_actor();

    let context = BisectionContext {
        head_id,
        head_body: &head_body,
        available_capsules: &[],
        historical_batches: &history,
        base_refs: &base_refs,
        disclosure_policy: Some(&policy),
        snapshot_limits: SnapshotLimits::default(),
    };

    let pred = PullRequestStatePredicate {
        pull_request: PullRequestNumber::try_new(1).unwrap(),
        expected_state: PullRequestState::Merged {
            merge_commit: fake_digest(0x99),
            target_tip_after: fake_digest(0xaa),
        },
    };

    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(total_decisions).unwrap(),
    )
    .unwrap();

    let receipt = execute_bisection(
        range,
        MonotonicityShape::GuaranteedMonotone {
            expected_direction: None,
        },
        &pred,
        &context,
    );

    match receipt.termination {
        BisectionTermination::Refused {
            reason: BisectionRefusal::RevokedDisclosure { sequence },
        } => {
            assert_eq!(sequence, 1);
        }
        other => panic!("Expected RevokedDisclosure refusal, got {other:?}"),
    }
}

#[test]
fn test_invalid_range_refusal() {
    let res = BisectionRange::new(
        DecisionSequence::try_new(10).unwrap(),
        DecisionSequence::try_new(5).unwrap(),
    );
    assert_eq!(
        res,
        Err(BisectionRefusal::InvalidRange { start: 10, end: 5 })
    );
}

#[test]
fn test_receipt_digest_binds_probe_outcomes() {
    let repo = RepositoryId::from_bytes([7u8; 16]);
    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(8).unwrap(),
    )
    .unwrap();
    let shape = MonotonicityShape::GuaranteedMonotone {
        expected_direction: Some(TransitionDirection::UnsatisfiedToSatisfied),
    };
    let termination = BisectionTermination::NoTransition {
        uniform_outcome: PredicateOutcome::Unsatisfied,
    };

    let probe = |outcome| ProbeRecord {
        step_index: 0,
        sequence: DecisionSequence::try_new(4).unwrap(),
        outcome,
        head_id: fake_head_id(3),
        policy_epoch: PolicyEpoch::FIRST,
        replayed_batches: 0,
    };

    let satisfied = BisectionReceipt::compute_digest(
        repo,
        &range,
        &shape,
        1,
        None,
        &termination,
        &[probe(Ok(PredicateOutcome::Satisfied))],
    );
    let unsatisfied = BisectionReceipt::compute_digest(
        repo,
        &range,
        &shape,
        1,
        None,
        &termination,
        &[probe(Ok(PredicateOutcome::Unsatisfied))],
    );
    assert_ne!(
        satisfied, unsatisfied,
        "two runs whose probes disagree must not share a receipt digest"
    );
}

#[test]
fn test_receipt_digest_binds_monotonicity_shape() {
    let repo = RepositoryId::from_bytes([8u8; 16]);
    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(8).unwrap(),
    )
    .unwrap();
    let termination = BisectionTermination::NoTransition {
        uniform_outcome: PredicateOutcome::Unsatisfied,
    };

    let monotone = BisectionReceipt::compute_digest(
        repo,
        &range,
        &MonotonicityShape::GuaranteedMonotone {
            expected_direction: None,
        },
        0,
        None,
        &termination,
        &[],
    );
    let segmented = BisectionReceipt::compute_digest(
        repo,
        &range,
        &MonotonicityShape::BoundedSegmented {
            segment_size: 2,
            max_steps: 9,
        },
        0,
        None,
        &termination,
        &[],
    );
    assert_ne!(
        monotone, segmented,
        "the declared search contract must participate in the receipt digest"
    );
}

#[test]
fn test_receipt_digest_binds_refusal_reason() {
    let repo = RepositoryId::from_bytes([9u8; 16]);
    let range = BisectionRange::new(
        DecisionSequence::try_new(1).unwrap(),
        DecisionSequence::try_new(8).unwrap(),
    )
    .unwrap();
    let shape = MonotonicityShape::LinearOnly { max_steps: 4 };

    let budget = BisectionReceipt::compute_digest(
        repo,
        &range,
        &shape,
        5,
        None,
        &BisectionTermination::Refused {
            reason: BisectionRefusal::BudgetExhausted {
                steps_taken: 5,
                max_budget: 4,
            },
        },
        &[],
    );
    let nonmonotone = BisectionReceipt::compute_digest(
        repo,
        &range,
        &shape,
        5,
        None,
        &BisectionTermination::Refused {
            reason: BisectionRefusal::NonMonotoneDetected {
                sequence: 4,
                expected: "unsatisfied".to_string(),
                observed: "satisfied".to_string(),
            },
        },
        &[],
    );
    assert_ne!(
        budget, nonmonotone,
        "different refusal reasons must not share a receipt digest"
    );
}
