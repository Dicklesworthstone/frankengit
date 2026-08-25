#![forbid(unsafe_code)]

//! Unit, property, and acceptance tests for the forge-state bisection engine (FG-038b).

use std::collections::{BTreeMap, BTreeSet};

use fgit_codec::schema::{RepositoryAuthorityHeadBody, RepositoryDecisionBatchBody};
use fgit_forge::bisection::{
    BisectionContext, BisectionRange, BisectionRefusal, BisectionTermination, MonotonicityShape,
    PredicateOutcome, PullRequestStatePredicate, TransitionDirection, execute_bisection,
    linear_scan_oracle, logarithmic_probe_budget,
};
use fgit_forge::event::{ForgeEvent, ForgeEventBatch, ForgeEventPayload};
use fgit_forge::snapshot::{
    ForgeSnapshot, HistoricalBatch, PullRequestState, SnapshotDisclosurePolicy, SnapshotLimits,
};
use fgit_types::{
    DecisionSequence, Digest, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch, PrincipalId,
    PullRequestNumber, RepositoryAuthorityHeadId, RepositoryDecisionBatchId, RepositoryId,
};

fn test_repo_id() -> RepositoryId {
    RepositoryId::from_bytes([0x42; 32])
}

fn dummy_head_body(repo_id: RepositoryId, latest_seq: u64) -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: repo_id,
        generation: HeadGeneration::try_new(1).unwrap(),
        policy_epoch: PolicyEpoch::try_new(1).unwrap(),
        latest_decision_sequence: DecisionSequence::try_new(latest_seq).ok(),
        latest_committed_rcr_id: None,
        last_checkpoint_id: None,
        ref_root: Digest::from([0x11; 32]),
        forge_position_root: Digest::from([0x22; 32]),
        retention_root: Digest::from([0x33; 32]),
        outbox_root: Digest::from([0x44; 32]),
        outcome_index_root: Digest::from([0x55; 32]),
        configuration_root: Digest::from([0x66; 32]),
    }
}

fn dummy_oid(byte: u8) -> GitOid {
    GitOid::new(GitHashAlgorithm::Sha1, &[byte; 20]).expect("valid 20-byte sha1")
}

fn create_test_history(total_decisions: u64, flip_at: Option<u64>) -> Vec<HistoricalBatch> {
    let mut batches = Vec::with_capacity(total_decisions as usize);
    let pr_num = PullRequestNumber::try_new(1).unwrap();
    let author = PrincipalId::from_bytes([0x01; 32]);

    for seq in 1..=total_decisions {
        let dec_seq = DecisionSequence::try_new(seq).unwrap();
        let payload = if Some(seq) == flip_at {
            // State transitions at flip_at
            ForgeEventPayload::PullRequestMerged {
                pull_request: pr_num,
                merged_by: author,
                merge_commit: Digest::from([0x99; 32]),
                target_tip_after: Digest::from([0xaa; 32]),
            }
        } else if seq == 1 {
            ForgeEventPayload::PullRequestOpened {
                pull_request: pr_num,
                author,
                source_ref: b"refs/heads/feature".to_vec(),
                target_ref: b"refs/heads/main".to_vec(),
                source_tip: dummy_oid(0x01),
                target_tip: dummy_oid(0x02),
            }
        } else {
            ForgeEventPayload::CheckReceiptRecorded {
                check_id: Digest::from([seq as u8; 32]),
                target_ref: b"refs/heads/feature".to_vec(),
                commit_oid: dummy_oid(seq as u8),
                passed: true,
            }
        };

        let event = ForgeEvent {
            aggregate_id: fgit_forge::AggregateId::PullRequest(pr_num),
            aggregate_version: fgit_forge::AggregateVersion::try_new(seq).unwrap(),
            payload,
        };

        let batch = ForgeEventBatch {
            repository_id: test_repo_id(),
            decision_sequence: dec_seq,
            events: vec![event],
        };

        batches.push(HistoricalBatch {
            batch_id: RepositoryDecisionBatchId::from_bytes([seq as u8; 32]),
            sequence: dec_seq,
            predecessor_head_id: RepositoryAuthorityHeadId::from_bytes([(seq - 1) as u8; 32]),
            batch_body: RepositoryDecisionBatchBody {
                repository_id: test_repo_id(),
                decision_sequence: dec_seq,
                predecessor_head_id: RepositoryAuthorityHeadId::from_bytes([(seq - 1) as u8; 32]),
                sealed_intents: Vec::new(),
                terminal_decisions: Vec::new(),
            },
            forge_batch: Some(batch),
            checkpoint_id: None,
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
    let head_id = RepositoryAuthorityHeadId::from_bytes([0x55; 32]);
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
            merge_commit: Digest::from([0x99; 32]),
            target_tip_after: Digest::from([0xaa; 32]),
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
    let head_id = RepositoryAuthorityHeadId::from_bytes([0x55; 32]);
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
            merge_commit: Digest::from([0x99; 32]),
            target_tip_after: Digest::from([0xaa; 32]),
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
        let head_id = RepositoryAuthorityHeadId::from_bytes([0x55; 32]);

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
                merge_commit: Digest::from([0x99; 32]),
                target_tip_after: Digest::from([0xaa; 32]),
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
    let head_id = RepositoryAuthorityHeadId::from_bytes([0x55; 32]);
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
            merge_commit: Digest::from([0x99; 32]),
            target_tip_after: Digest::from([0xaa; 32]),
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
    let head_id = RepositoryAuthorityHeadId::from_bytes([0x55; 32]);
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
    let head_id = RepositoryAuthorityHeadId::from_bytes([0x55; 32]);
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
            merge_commit: Digest::from([0x99; 32]),
            target_tip_after: Digest::from([0xaa; 32]),
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
    let head_id = RepositoryAuthorityHeadId::from_bytes([0x55; 32]);
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
            merge_commit: Digest::from([0x99; 32]),
            target_tip_after: Digest::from([0xaa; 32]),
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
    let head_id = RepositoryAuthorityHeadId::from_bytes([0x55; 32]);
    let base_refs = BTreeMap::new();

    // Revoke all access for unauthorized actor
    let unauthorized_actor = PrincipalId::from_bytes([0xfe; 32]);
    let policy = SnapshotDisclosurePolicy {
        actor: unauthorized_actor,
        allowed_refs: BTreeSet::new(),
        allowed_prs: BTreeSet::new(),
        is_authorized: false,
    };

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
            merge_commit: Digest::from([0x99; 32]),
            target_tip_after: Digest::from([0xaa; 32]),
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
