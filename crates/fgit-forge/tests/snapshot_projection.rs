#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use fgit_chronicle::{BackupProfile, RepositoryCapsuleBody};
use fgit_codec::schema::{
    RepositoryAuthorityHeadBody, RepositoryDecision, RepositoryDecisionBatchBody,
};
use fgit_forge::aggregate::{AggregateId, AggregateVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEvent, ForgeEventPayload};
use fgit_forge::snapshot::{
    CandidateCapsule, ForgeSnapshotDiff, HistoricalBatch, PositionTarget, PullRequestChange,
    PullRequestSnapshot, PullRequestState, RefChange, SnapshotDisclosurePolicy, SnapshotLimits,
    SnapshotRefusal, project_snapshot_from_history, verify_continuous_consistency,
};
use fgit_types::vocabulary::DecisionOutcome;
use fgit_types::{
    CodecVersion, DecisionSequence, Digest, DigestAlgorithmId, DigestBytes, GitOid, HeadGeneration,
    PolicyEpoch, RegistryEpoch, RepositoryAuthorityHeadId, RepositoryCapsuleId, RepositoryCommitId,
    RepositoryDecisionBatchId, RepositoryId, RepositorySequence, TxId,
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

fn fake_capsule_id(byte: u8) -> RepositoryCapsuleId {
    let mut bytes = [0_u8; 32];
    bytes[0] = byte;
    RepositoryCapsuleId::from_digest(
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

const fn fake_oid(byte: u8) -> GitOid {
    let mut bytes = [0_u8; 20];
    bytes[0] = byte;
    GitOid::Sha1(fgit_types::GitOidSha1::from_bytes(bytes))
}

#[test]
fn continuous_consistency_snapshot_at_latest_equals_live_projections() {
    let repo_id = RepositoryId::from_bytes([1_u8; 16]);
    let live_head_id = fake_head_id(5);
    let live_head = RepositoryAuthorityHeadBody {
        repository_id: repo_id,
        generation: HeadGeneration::try_new(5).unwrap(),
        predecessor_head_id: Some(fake_head_id(4)),
        decision_tail_id: Some(fake_batch_id(5)),
        latest_decision_sequence: Some(DecisionSequence::try_new(5).unwrap()),
        latest_committed_rcr_id: Some(fake_commit_id(5)),
        latest_repository_sequence: Some(RepositorySequence::try_new(5).unwrap()),
        ref_root: fake_digest(50),
        forge_position_root: fake_digest(60),
        outcome_index_root: fake_digest(70),
        retention_root: fake_digest(80),
        outbox_root: fake_digest(90),
        configuration_root: fake_digest(100),
        policy_epoch: PolicyEpoch::try_new(2).unwrap(),
        format_registry_epoch: RegistryEpoch::try_new(1).unwrap(),
        last_checkpoint_id: None,
    };

    let mut live_refs = BTreeMap::new();
    live_refs.insert(b"refs/heads/main".to_vec(), fake_oid(1));
    live_refs.insert(b"refs/heads/feature".to_vec(), fake_oid(2));

    let pr1 = PullRequestSnapshot {
        number: PullRequestNumber::try_new(1).unwrap(),
        source_ref: b"refs/heads/feature".to_vec(),
        target_ref: b"refs/heads/main".to_vec(),
        source_tip: fake_digest(10),
        target_tip: fake_digest(40),
        state: PullRequestState::Merged {
            merge_commit: fake_digest(30),
            target_tip_after: fake_digest(40),
        },
        version: AggregateVersion::try_new(2).unwrap(),
    };

    let mut live_prs = BTreeMap::new();
    live_prs.insert(pr1.number, pr1);

    // Build historical batches that lead to this state
    let batch1 = HistoricalBatch {
        batch_id: fake_batch_id(1),
        resulting_head_id: fake_head_id(1),
        resulting_head_generation: HeadGeneration::try_new(1).unwrap(),
        batch: RepositoryDecisionBatchBody {
            repository_id: repo_id,
            predecessor_head_id: fake_head_id(0),
            predecessor_head_generation: HeadGeneration::try_new(1).unwrap(),
            first_decision_sequence: DecisionSequence::try_new(1).unwrap(),
            decisions: vec![RepositoryDecision {
                tx_id: fake_tx_id(1),
                decision_sequence: DecisionSequence::try_new(1).unwrap(),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: fake_commit_id(1),
                },
            }],
            committed_rcrs: vec![],
            resulting_ref_root: fake_digest(10),
            resulting_forge_position_root: fake_digest(20),
            resulting_outcome_index_root: fake_digest(30),
            resulting_retention_root: fake_digest(40),
            resulting_outbox_root: fake_digest(50),
            resulting_policy_epoch: PolicyEpoch::try_new(1).unwrap(),
            batch_evidence_root: fake_digest(60),
            compaction_generation_link: None,
        },
        forge_events: vec![ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(1).unwrap()),
            version: AggregateVersion::try_new(1).unwrap(),
            payload: ForgeEventPayload::PullRequestOpened {
                source_ref: b"refs/heads/feature".to_vec(),
                target_ref: b"refs/heads/main".to_vec(),
                source_tip: fake_digest(10),
                target_tip: fake_digest(20),
            },
        }],
        ref_updates: vec![
            (b"refs/heads/main".to_vec(), Some(fake_oid(1))),
            (b"refs/heads/feature".to_vec(), Some(fake_oid(2))),
        ],
    };

    let batch2 = HistoricalBatch {
        batch_id: fake_batch_id(5),
        resulting_head_id: live_head_id,
        resulting_head_generation: HeadGeneration::try_new(5).unwrap(),
        batch: RepositoryDecisionBatchBody {
            repository_id: repo_id,
            predecessor_head_id: fake_head_id(1),
            predecessor_head_generation: HeadGeneration::try_new(1).unwrap(),
            first_decision_sequence: DecisionSequence::try_new(5).unwrap(),
            decisions: vec![RepositoryDecision {
                tx_id: fake_tx_id(5),
                decision_sequence: DecisionSequence::try_new(5).unwrap(),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: fake_commit_id(5),
                },
            }],
            committed_rcrs: vec![],
            resulting_ref_root: live_head.ref_root,
            resulting_forge_position_root: live_head.forge_position_root,
            resulting_outcome_index_root: live_head.outcome_index_root,
            resulting_retention_root: live_head.retention_root,
            resulting_outbox_root: live_head.outbox_root,
            resulting_policy_epoch: live_head.policy_epoch,
            batch_evidence_root: fake_digest(99),
            compaction_generation_link: None,
        },
        forge_events: vec![ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(1).unwrap()),
            version: AggregateVersion::try_new(2).unwrap(),
            payload: ForgeEventPayload::MergeCommitted {
                merge_commit: fake_digest(30),
                target_ref: b"refs/heads/main".to_vec(),
                target_tip_before: fake_digest(20),
                target_tip_after: fake_digest(40),
            },
        }],
        ref_updates: vec![],
    };

    let batches = vec![batch1, batch2];
    let genesis_refs = BTreeMap::new();
    let limits = SnapshotLimits::default();

    // Materialize snapshot at PositionTarget::Latest
    let snapshot = project_snapshot_from_history(
        PositionTarget::Latest,
        live_head_id,
        &live_head,
        &[],
        &batches,
        &genesis_refs,
        &limits,
    )
    .expect("materialization must succeed");

    // Continuous consistency verification
    verify_continuous_consistency(&snapshot, live_head_id, &live_head, &live_refs, &live_prs)
        .expect("continuous consistency check must succeed");
}

#[test]
fn replay_cost_bounded_via_checkpoint_seeking() {
    let repo_id = RepositoryId::from_bytes([2_u8; 16]);
    let total_decisions = 20_u64;

    let mut batches = Vec::new();
    let mut prev_head = fake_head_id(0);

    for i in 1..=total_decisions {
        let current_head = fake_head_id(i as u8);
        batches.push(HistoricalBatch {
            batch_id: fake_batch_id(i as u8),
            resulting_head_id: current_head,
            resulting_head_generation: HeadGeneration::try_new(i).unwrap(),
            batch: RepositoryDecisionBatchBody {
                repository_id: repo_id,
                predecessor_head_id: prev_head,
                predecessor_head_generation: HeadGeneration::try_new(i.saturating_sub(1).max(1))
                    .unwrap(),
                first_decision_sequence: DecisionSequence::try_new(i).unwrap(),
                decisions: vec![RepositoryDecision {
                    tx_id: fake_tx_id(i as u8),
                    decision_sequence: DecisionSequence::try_new(i).unwrap(),
                    outcome: DecisionOutcome::Committed {
                        repository_commit_id: fake_commit_id(i as u8),
                    },
                }],
                committed_rcrs: vec![],
                resulting_ref_root: fake_digest(i as u8),
                resulting_forge_position_root: fake_digest((i + 50) as u8),
                resulting_outcome_index_root: fake_digest(1),
                resulting_retention_root: fake_digest(1),
                resulting_outbox_root: fake_digest(1),
                resulting_policy_epoch: PolicyEpoch::try_new(1).unwrap(),
                batch_evidence_root: fake_digest(1),
                compaction_generation_link: None,
            },
            forge_events: vec![],
            ref_updates: vec![(
                format!("refs/heads/branch_{i}").into_bytes(),
                Some(fake_oid(i as u8)),
            )],
        });
        prev_head = current_head;
    }

    let live_head_id = fake_head_id(total_decisions as u8);
    let live_head = RepositoryAuthorityHeadBody {
        repository_id: repo_id,
        generation: HeadGeneration::try_new(total_decisions).unwrap(),
        predecessor_head_id: Some(fake_head_id((total_decisions - 1) as u8)),
        decision_tail_id: Some(fake_batch_id(total_decisions as u8)),
        latest_decision_sequence: Some(DecisionSequence::try_new(total_decisions).unwrap()),
        latest_committed_rcr_id: Some(fake_commit_id(total_decisions as u8)),
        latest_repository_sequence: Some(RepositorySequence::try_new(total_decisions).unwrap()),
        ref_root: fake_digest(total_decisions as u8),
        forge_position_root: fake_digest((total_decisions + 50) as u8),
        outcome_index_root: fake_digest(1),
        retention_root: fake_digest(1),
        outbox_root: fake_digest(1),
        configuration_root: fake_digest(1),
        policy_epoch: PolicyEpoch::try_new(1).unwrap(),
        format_registry_epoch: RegistryEpoch::try_new(1).unwrap(),
        last_checkpoint_id: None,
    };

    // Candidate capsule at decision 15
    let capsule_15_id = fake_capsule_id(15);
    let mut capsule_15_refs = BTreeMap::new();
    for i in 1..=15 {
        capsule_15_refs.insert(
            format!("refs/heads/branch_{i}").into_bytes(),
            fake_oid(i as u8),
        );
    }

    let capsule_15 = CandidateCapsule {
        capsule_id: capsule_15_id,
        capsule: RepositoryCapsuleBody {
            repository_id: repo_id,
            head_id: fake_head_id(15),
            head_generation: HeadGeneration::try_new(15).unwrap(),
            predecessor_capsule_id: None,
            decision_tail_id: Some(fake_batch_id(15)),
            latest_decision_sequence: Some(DecisionSequence::try_new(15).unwrap()),
            latest_committed_rcr_id: Some(fake_commit_id(15)),
            latest_repository_sequence: Some(RepositorySequence::try_new(15).unwrap()),
            ref_root: fake_digest(15),
            forge_position_root: fake_digest(65),
            object_closure_root: fake_digest(1),
            segment_manifest_root: fake_digest(1),
            retention_root: fake_digest(1),
            configuration_root: fake_digest(1),
            policy_epoch: PolicyEpoch::try_new(1).unwrap(),
            format_registry_epoch: RegistryEpoch::try_new(1).unwrap(),
            outcome_index_checkpoint_root: None,
            backup_profile: BackupProfile::FullClosure,
        },
        refs: capsule_15_refs,
        pull_requests: BTreeMap::new(),
    };

    let capsules = vec![capsule_15];
    let genesis_refs = BTreeMap::new();
    let limits = SnapshotLimits::default();

    // Query snapshot at decision 18
    let snapshot_18 = project_snapshot_from_history(
        PositionTarget::Decision(DecisionSequence::try_new(18).unwrap()),
        live_head_id,
        &live_head,
        &capsules,
        &batches,
        &genesis_refs,
        &limits,
    )
    .expect("materialization must succeed");

    // Acceptance: Replay cost is bounded by checkpoint seeking
    // Should replay ONLY batches 16, 17, 18 (3 batches), not 18 batches!
    assert_eq!(
        snapshot_18.used_capsule_id,
        Some(capsule_15_id),
        "must have sought to nearest capsule at decision 15"
    );
    assert_eq!(
        snapshot_18.replayed_batches_count, 3,
        "must only replay 3 batches (16..=18) from checkpoint"
    );
    assert_eq!(
        snapshot_18.refs.len(),
        18,
        "snapshot at decision 18 must contain exactly 18 branches"
    );
    assert_eq!(
        snapshot_18.effective_decision_sequence,
        Some(DecisionSequence::try_new(18).unwrap())
    );
}

#[test]
fn revoked_access_disclosure_fixture() {
    let repo_id = RepositoryId::from_bytes([3_u8; 16]);
    let live_head_id = fake_head_id(10);
    let live_head = RepositoryAuthorityHeadBody {
        repository_id: repo_id,
        generation: HeadGeneration::try_new(10).unwrap(),
        predecessor_head_id: Some(fake_head_id(9)),
        decision_tail_id: Some(fake_batch_id(10)),
        latest_decision_sequence: Some(DecisionSequence::try_new(10).unwrap()),
        latest_committed_rcr_id: Some(fake_commit_id(10)),
        latest_repository_sequence: Some(RepositorySequence::try_new(10).unwrap()),
        ref_root: fake_digest(10),
        forge_position_root: fake_digest(20),
        outcome_index_root: fake_digest(1),
        retention_root: fake_digest(1),
        outbox_root: fake_digest(1),
        configuration_root: fake_digest(1),
        policy_epoch: PolicyEpoch::try_new(5).unwrap(), // Current policy epoch 5
        format_registry_epoch: RegistryEpoch::try_new(1).unwrap(),
        last_checkpoint_id: None,
    };

    // At decision 3, historical policy was epoch 1, and confidential branch & PR 99 existed
    let confidential_ref = b"refs/heads/confidential_project".to_vec();
    let public_ref = b"refs/heads/public_project".to_vec();

    let batch = HistoricalBatch {
        batch_id: fake_batch_id(3),
        resulting_head_id: fake_head_id(3),
        resulting_head_generation: HeadGeneration::try_new(3).unwrap(),
        batch: RepositoryDecisionBatchBody {
            repository_id: repo_id,
            predecessor_head_id: fake_head_id(2),
            predecessor_head_generation: HeadGeneration::try_new(2).unwrap(),
            first_decision_sequence: DecisionSequence::try_new(3).unwrap(),
            decisions: vec![RepositoryDecision {
                tx_id: fake_tx_id(3),
                decision_sequence: DecisionSequence::try_new(3).unwrap(),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: fake_commit_id(3),
                },
            }],
            committed_rcrs: vec![],
            resulting_ref_root: fake_digest(30),
            resulting_forge_position_root: fake_digest(40),
            resulting_outcome_index_root: fake_digest(1),
            resulting_retention_root: fake_digest(1),
            resulting_outbox_root: fake_digest(1),
            resulting_policy_epoch: PolicyEpoch::try_new(1).unwrap(), // Historical epoch 1
            batch_evidence_root: fake_digest(1),
            compaction_generation_link: None,
        },
        forge_events: vec![ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(99).unwrap()),
            version: AggregateVersion::try_new(1).unwrap(),
            payload: ForgeEventPayload::PullRequestOpened {
                source_ref: confidential_ref.clone(),
                target_ref: public_ref.clone(),
                source_tip: fake_digest(99),
                target_tip: fake_digest(1),
            },
        }],
        ref_updates: vec![
            (public_ref.clone(), Some(fake_oid(1))),
            (confidential_ref.clone(), Some(fake_oid(99))),
        ],
    };

    let batches = vec![batch];
    let genesis_refs = BTreeMap::new();
    let limits = SnapshotLimits::default();

    // Materialize snapshot as of historical decision 3
    let snapshot_3 = project_snapshot_from_history(
        PositionTarget::Decision(DecisionSequence::try_new(3).unwrap()),
        live_head_id,
        &live_head,
        &[],
        &batches,
        &genesis_refs,
        &limits,
    )
    .expect("materialization must succeed");

    assert_eq!(snapshot_3.refs.len(), 2);
    assert_eq!(snapshot_3.pull_requests.len(), 1);
    assert_eq!(
        snapshot_3.historical_policy_epoch,
        PolicyEpoch::try_new(1).unwrap(),
        "historical policy epoch 1 must be displayed as data"
    );

    // Apply current policy where actor's access to confidential_ref was REVOKED
    let mut revoked_refs = BTreeSet::new();
    revoked_refs.insert(confidential_ref.clone());
    let current_policy = SnapshotDisclosurePolicy::with_revoked_refs(revoked_refs);

    let filtered_snapshot = current_policy
        .filter_snapshot(snapshot_3.clone())
        .expect("filtering allowed for active repo user");

    // Acceptance: Revoked access cannot see historical content
    assert!(
        !filtered_snapshot.refs.contains_key(&confidential_ref),
        "revoked confidential ref must be redacted from historical snapshot"
    );
    assert!(
        filtered_snapshot.refs.contains_key(&public_ref),
        "public ref must remain visible"
    );
    assert!(
        !filtered_snapshot
            .pull_requests
            .contains_key(&PullRequestNumber::try_new(99).unwrap()),
        "PR on revoked ref must be redacted from historical snapshot"
    );
    assert_eq!(
        filtered_snapshot.historical_policy_epoch,
        PolicyEpoch::try_new(1).unwrap(),
        "historical policy is still displayed as immutable data"
    );

    // If whole repository access is revoked under current policy
    let fully_revoked_policy = SnapshotDisclosurePolicy::revoked_actor();
    let err = fully_revoked_policy
        .filter_snapshot(snapshot_3)
        .unwrap_err();
    assert!(
        matches!(err, SnapshotRefusal::AccessDenied { .. }),
        "revoked repo access must yield AccessDenied refusal"
    );
}

#[test]
fn diff_snapshots_between_two_positions() {
    let repo_id = RepositoryId::from_bytes([4_u8; 16]);
    let live_head_id = fake_head_id(10);
    let live_head = RepositoryAuthorityHeadBody {
        repository_id: repo_id,
        generation: HeadGeneration::try_new(10).unwrap(),
        predecessor_head_id: Some(fake_head_id(9)),
        decision_tail_id: Some(fake_batch_id(10)),
        latest_decision_sequence: Some(DecisionSequence::try_new(10).unwrap()),
        latest_committed_rcr_id: Some(fake_commit_id(10)),
        latest_repository_sequence: Some(RepositorySequence::try_new(10).unwrap()),
        ref_root: fake_digest(10),
        forge_position_root: fake_digest(20),
        outcome_index_root: fake_digest(1),
        retention_root: fake_digest(1),
        outbox_root: fake_digest(1),
        configuration_root: fake_digest(1),
        policy_epoch: PolicyEpoch::try_new(2).unwrap(),
        format_registry_epoch: RegistryEpoch::try_new(1).unwrap(),
        last_checkpoint_id: None,
    };

    let batch1 = HistoricalBatch {
        batch_id: fake_batch_id(1),
        resulting_head_id: fake_head_id(1),
        resulting_head_generation: HeadGeneration::try_new(1).unwrap(),
        batch: RepositoryDecisionBatchBody {
            repository_id: repo_id,
            predecessor_head_id: fake_head_id(0),
            predecessor_head_generation: HeadGeneration::try_new(1).unwrap(),
            first_decision_sequence: DecisionSequence::try_new(1).unwrap(),
            decisions: vec![RepositoryDecision {
                tx_id: fake_tx_id(1),
                decision_sequence: DecisionSequence::try_new(1).unwrap(),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: fake_commit_id(1),
                },
            }],
            committed_rcrs: vec![],
            resulting_ref_root: fake_digest(10),
            resulting_forge_position_root: fake_digest(20),
            resulting_outcome_index_root: fake_digest(1),
            resulting_retention_root: fake_digest(1),
            resulting_outbox_root: fake_digest(1),
            resulting_policy_epoch: PolicyEpoch::try_new(1).unwrap(),
            batch_evidence_root: fake_digest(1),
            compaction_generation_link: None,
        },
        forge_events: vec![ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(1).unwrap()),
            version: AggregateVersion::try_new(1).unwrap(),
            payload: ForgeEventPayload::PullRequestOpened {
                source_ref: b"refs/heads/feature".to_vec(),
                target_ref: b"refs/heads/main".to_vec(),
                source_tip: fake_digest(1),
                target_tip: fake_digest(1),
            },
        }],
        ref_updates: vec![(b"refs/heads/main".to_vec(), Some(fake_oid(1)))],
    };

    let batch2 = HistoricalBatch {
        batch_id: fake_batch_id(2),
        resulting_head_id: fake_head_id(2),
        resulting_head_generation: HeadGeneration::try_new(2).unwrap(),
        batch: RepositoryDecisionBatchBody {
            repository_id: repo_id,
            predecessor_head_id: fake_head_id(1),
            predecessor_head_generation: HeadGeneration::try_new(1).unwrap(),
            first_decision_sequence: DecisionSequence::try_new(2).unwrap(),
            decisions: vec![RepositoryDecision {
                tx_id: fake_tx_id(2),
                decision_sequence: DecisionSequence::try_new(2).unwrap(),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: fake_commit_id(2),
                },
            }],
            committed_rcrs: vec![],
            resulting_ref_root: fake_digest(30),
            resulting_forge_position_root: fake_digest(40),
            resulting_outcome_index_root: fake_digest(1),
            resulting_retention_root: fake_digest(1),
            resulting_outbox_root: fake_digest(1),
            resulting_policy_epoch: PolicyEpoch::try_new(2).unwrap(),
            batch_evidence_root: fake_digest(1),
            compaction_generation_link: None,
        },
        forge_events: vec![ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(1).unwrap()),
            version: AggregateVersion::try_new(2).unwrap(),
            payload: ForgeEventPayload::MergeCommitted {
                merge_commit: fake_digest(99),
                target_ref: b"refs/heads/main".to_vec(),
                target_tip_before: fake_digest(1),
                target_tip_after: fake_digest(2),
            },
        }],
        ref_updates: vec![
            (b"refs/heads/main".to_vec(), Some(fake_oid(2))),
            (b"refs/heads/new_feature".to_vec(), Some(fake_oid(3))),
        ],
    };

    let batches = vec![batch1, batch2];
    let genesis_refs = BTreeMap::new();
    let limits = SnapshotLimits::default();

    let snap_1 = project_snapshot_from_history(
        PositionTarget::Decision(DecisionSequence::try_new(1).unwrap()),
        live_head_id,
        &live_head,
        &[],
        &batches,
        &genesis_refs,
        &limits,
    )
    .unwrap();

    let snap_2 = project_snapshot_from_history(
        PositionTarget::Decision(DecisionSequence::try_new(2).unwrap()),
        live_head_id,
        &live_head,
        &[],
        &batches,
        &genesis_refs,
        &limits,
    )
    .unwrap();

    let diff = ForgeSnapshotDiff::diff(&snap_1, &snap_2);

    assert_eq!(diff.ref_changes.len(), 2);
    assert_eq!(
        diff.ref_changes.get(&b"refs/heads/main".to_vec()),
        Some(&RefChange::Modified {
            before: fake_oid(1),
            after: fake_oid(2),
        })
    );
    assert_eq!(
        diff.ref_changes.get(&b"refs/heads/new_feature".to_vec()),
        Some(&RefChange::Created(fake_oid(3)))
    );

    assert_eq!(diff.pr_changes.len(), 1);
    assert!(matches!(
        diff.pr_changes.get(&PullRequestNumber::try_new(1).unwrap()),
        Some(PullRequestChange::Merged { .. })
    ));

    assert_eq!(
        diff.policy_epoch_change,
        Some((
            PolicyEpoch::try_new(1).unwrap(),
            PolicyEpoch::try_new(2).unwrap()
        ))
    );
}

#[test]
fn snapshot_refusals_target_ahead_and_exceeding_bound() {
    let repo_id = RepositoryId::from_bytes([5_u8; 16]);
    let live_head_id = fake_head_id(5);
    let live_head = RepositoryAuthorityHeadBody {
        repository_id: repo_id,
        generation: HeadGeneration::try_new(5).unwrap(),
        predecessor_head_id: Some(fake_head_id(4)),
        decision_tail_id: Some(fake_batch_id(5)),
        latest_decision_sequence: Some(DecisionSequence::try_new(5).unwrap()),
        latest_committed_rcr_id: Some(fake_commit_id(5)),
        latest_repository_sequence: Some(RepositorySequence::try_new(5).unwrap()),
        ref_root: fake_digest(1),
        forge_position_root: fake_digest(1),
        outcome_index_root: fake_digest(1),
        retention_root: fake_digest(1),
        outbox_root: fake_digest(1),
        configuration_root: fake_digest(1),
        policy_epoch: PolicyEpoch::try_new(1).unwrap(),
        format_registry_epoch: RegistryEpoch::try_new(1).unwrap(),
        last_checkpoint_id: None,
    };

    // Target sequence 10 is ahead of head sequence 5
    let ahead_err = project_snapshot_from_history(
        PositionTarget::Decision(DecisionSequence::try_new(10).unwrap()),
        live_head_id,
        &live_head,
        &[],
        &[],
        &BTreeMap::new(),
        &SnapshotLimits::default(),
    )
    .unwrap_err();

    assert!(matches!(
        ahead_err,
        SnapshotRefusal::TargetAheadOfAuthority { .. }
    ));

    // Exceeding replay batch bound
    let strict_limit = SnapshotLimits {
        max_replay_batches: 0,
    };
    let batch = HistoricalBatch {
        batch_id: fake_batch_id(1),
        resulting_head_id: fake_head_id(1),
        resulting_head_generation: HeadGeneration::try_new(1).unwrap(),
        batch: RepositoryDecisionBatchBody {
            repository_id: repo_id,
            predecessor_head_id: fake_head_id(0),
            predecessor_head_generation: HeadGeneration::try_new(1).unwrap(),
            first_decision_sequence: DecisionSequence::try_new(1).unwrap(),
            decisions: vec![RepositoryDecision {
                tx_id: fake_tx_id(1),
                decision_sequence: DecisionSequence::try_new(1).unwrap(),
                outcome: DecisionOutcome::Committed {
                    repository_commit_id: fake_commit_id(1),
                },
            }],
            committed_rcrs: vec![],
            resulting_ref_root: fake_digest(1),
            resulting_forge_position_root: fake_digest(1),
            resulting_outcome_index_root: fake_digest(1),
            resulting_retention_root: fake_digest(1),
            resulting_outbox_root: fake_digest(1),
            resulting_policy_epoch: PolicyEpoch::try_new(1).unwrap(),
            batch_evidence_root: fake_digest(1),
            compaction_generation_link: None,
        },
        forge_events: vec![],
        ref_updates: vec![],
    };

    let bound_err = project_snapshot_from_history(
        PositionTarget::Decision(DecisionSequence::try_new(1).unwrap()),
        live_head_id,
        &live_head,
        &[],
        &[batch],
        &BTreeMap::new(),
        &strict_limit,
    )
    .unwrap_err();

    assert!(matches!(
        bound_err,
        SnapshotRefusal::ReplayBoundExceeded { .. }
    ));
}
