use fgit_codec::{CryptoBodyIdentity, DecodeLimits, decode_body, encode_body};
use fgit_diff::{TreeEntry, TreeMode};
use fgit_forge::aggregate::{
    AggregateId, AggregateVersion, PullRequestNumber, QueueNumber,
};
use fgit_forge::event::queue::{DequeueReason, NativeQueueEvent, QueueAction};
use fgit_forge::event::{ForgeEvent, ForgeEventPayload};
use fgit_forge::merge::{MergedTree, RecordFrame};
use fgit_forge::merge_queue::{
    BatchStatus, MergeQueueSnapshot, QueueBatchEntry, QueueBatchId, QueueBatchReceipt, QueueRef,
    QueueRefKind, SpeculativeBatchPlan, SpeculativeMergeStep, assemble_batch_landing_package,
};
use fgit_forge::{ForgeRefusal, MergeSide, WorkspaceEpoch};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GitHashAlgorithm, GitOid, OPAQUE_ID_LEN, PolicyEpoch,
    PrincipalId, PrincipalSnapshotId, RefName, RepositoryId, RepositorySequence, TxId,
};

fn oid(format: GitHashAlgorithm, hex_byte: &str) -> GitOid {
    let width = match format {
        GitHashAlgorithm::Sha1 => 20,
        GitHashAlgorithm::Sha256 => 32,
    };
    GitOid::from_hex(format, &hex_byte.repeat(width)).unwrap()
}

fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; OPAQUE_ID_LEN])
}

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;

macro_rules! derived {
    ($ty:ty, $tag:expr) => {
        <$ty>::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[$tag; 32]).expect("32-byte corpus fixture body"),
        )
    };
}

fn dummy_record_frame() -> RecordFrame {
    let dummy_digest = Digest::new(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT).unwrap(),
        DigestBytes::try_new(&[0x11; 32]).unwrap(),
    );
    RecordFrame {
        repository_id: RepositoryId::from_bytes([7; OPAQUE_ID_LEN]),
        repository_sequence: RepositorySequence::FIRST,
        parent_rcr_id: None,
        tx_id: derived!(TxId, 0x60),
        principal_snapshot_id: derived!(PrincipalSnapshotId, 0x61),
        canonical_request_digest: dummy_digest,
        ref_delta_root: dummy_digest,
        resulting_ref_root: dummy_digest,
        object_closure_root: dummy_digest,
        resulting_forge_position_root: dummy_digest,
        policy_epoch: PolicyEpoch::FIRST,
        policy_decision_root: dummy_digest,
        invariant_evidence_root: dummy_digest,
        outbox_effect_root: dummy_digest,
        retention_delta_root: dummy_digest,
    }
}


#[test]
fn test_synthetic_queue_ref_namespace() {
    let target = RefName::try_new(b"refs/heads/main").unwrap();
    let head_ref = QueueRef::projected_head(&target).unwrap();
    assert_eq!(head_ref.as_bytes(), b"refs/queue/main/head");
    assert!(QueueRef::is_queue_ref(&head_ref));

    let parsed_head = QueueRef::parse(&head_ref).expect("parse projected head");
    assert_eq!(parsed_head, QueueRefKind::ProjectedHead { target_ref: target.clone() });

    let dummy_digest = Digest::new(
        fgit_crypto::InternalDigestAlgorithm::Sha256.id(),
        fgit_types::hash::DigestBytes::try_new(&[0xab; 32]).unwrap(),
    );
    let batch_id = QueueBatchId::from_digest(dummy_digest);
    let batch_ref = QueueRef::batch(&target, &batch_id).unwrap();
    assert!(QueueRef::is_queue_ref(&batch_ref));
    assert!(batch_ref.as_bytes().starts_with(b"refs/queue/main/batches/"));

    let parsed_batch = QueueRef::parse(&batch_ref).expect("parse batch ref");
    assert_eq!(
        parsed_batch,
        QueueRefKind::Batch {
            target_ref: target.clone(),
            batch_id,
        }
    );

    let pr = PullRequestNumber::try_new(42).unwrap();
    let entry_ref = QueueRef::entry(&target, pr).unwrap();
    assert_eq!(entry_ref.as_bytes(), b"refs/queue/main/entries/42");
    assert!(QueueRef::is_queue_ref(&entry_ref));

    let parsed_entry = QueueRef::parse(&entry_ref).expect("parse entry ref");
    assert_eq!(
        parsed_entry,
        QueueRefKind::Entry {
            target_ref: target.clone(),
            pull_request: pr,
        }
    );

    // Negative cases: non-queue refs
    assert!(!QueueRef::is_queue_ref(&target));
    assert!(QueueRef::parse(&target).is_none());

    let tag_ref = RefName::try_new(b"refs/tags/v1.0.0").unwrap();
    assert!(!QueueRef::is_queue_ref(&tag_ref));
    assert!(QueueRef::parse(&tag_ref).is_none());
}


#[test]
fn test_deterministic_batch_identity_and_receipt() {
    let target = RefName::try_new(b"refs/heads/main").unwrap();
    let base_tip = oid(GitHashAlgorithm::Sha256, "10");

    let pr1 = PullRequestNumber::try_new(101).unwrap();
    let pr2 = PullRequestNumber::try_new(102).unwrap();

    let entry1 = QueueBatchEntry {
        pull_request: pr1,
        source_ref: RefName::try_new(b"refs/heads/feature-a").unwrap(),
        head_tip: oid(GitHashAlgorithm::Sha256, "a1"),
    };
    let entry2 = QueueBatchEntry {
        pull_request: pr2,
        source_ref: RefName::try_new(b"refs/heads/feature-b").unwrap(),
        head_tip: oid(GitHashAlgorithm::Sha256, "b1"),
    };

    let batch_id1 = QueueBatchId::compute(&target, base_tip, &[entry1.clone(), entry2.clone()]).unwrap();
    let batch_id2 = QueueBatchId::compute(&target, base_tip, &[entry1.clone(), entry2.clone()]).unwrap();
    assert_eq!(batch_id1, batch_id2, "batch id must be deterministic");

    // Hex formatting and parsing roundtrip
    let hex_str = batch_id1.to_hex();
    let parsed_id = QueueBatchId::from_hex(&hex_str).unwrap();
    assert_eq!(batch_id1, parsed_id);

    // Collision freedom: changing base tip changes batch ID
    let moved_base = oid(GitHashAlgorithm::Sha256, "11");
    let batch_id_moved_base = QueueBatchId::compute(&target, moved_base, &[entry1.clone(), entry2.clone()]).unwrap();
    assert_ne!(batch_id1, batch_id_moved_base);

    // Collision freedom: changing candidate tip changes batch ID
    let mut modified_entry1 = entry1.clone();
    modified_entry1.head_tip = oid(GitHashAlgorithm::Sha256, "a2");
    let batch_id_modified = QueueBatchId::compute(&target, base_tip, &[modified_entry1, entry2.clone()]).unwrap();
    assert_ne!(batch_id1, batch_id_modified);

    // Collision freedom: reordering entries changes batch ID
    let batch_id_reordered = QueueBatchId::compute(&target, base_tip, &[entry2.clone(), entry1.clone()]).unwrap();
    assert_ne!(batch_id1, batch_id_reordered);

    // Receipt generation and attestation
    let resulting_tip = oid(GitHashAlgorithm::Sha256, "ff");
    let receipt = QueueBatchReceipt {
        batch_id: batch_id1,
        target_ref: target.clone(),
        base_tip,
        resulting_tip,
        entries: vec![entry1, entry2],
        status: BatchStatus::SpeculativePass,
        timestamp_epoch: 1700000000,
    };

    let receipt_digest1 = receipt.receipt_digest().unwrap();
    let receipt_digest2 = receipt.receipt_digest().unwrap();
    assert_eq!(receipt_digest1, receipt_digest2);

    assert!(receipt.check_validity(&target, base_tip).is_ok());
    assert!(receipt.check_validity(&target, moved_base).is_err());
}

#[test]
fn test_speculative_merge_binding_and_invalidation() {
    let pr = PullRequestNumber::try_new(50).unwrap();
    let source_ref = RefName::try_new(b"refs/heads/feature-x").unwrap();
    let candidate_tip = oid(GitHashAlgorithm::Sha256, "c1");
    let projected_base = oid(GitHashAlgorithm::Sha256, "b1");
    let merge_base = oid(GitHashAlgorithm::Sha256, "01");
    let speculative_tip = oid(GitHashAlgorithm::Sha256, "d1");
    let epoch = WorkspaceEpoch::from_u64(1);


    let step = SpeculativeMergeStep {
        pull_request: pr,
        candidate_source_ref: source_ref,
        candidate_tip,
        projected_base_tip: projected_base,
        merge_base_tip: merge_base,
        resulting_speculative_tip: speculative_tip,
        workspace_epoch: epoch,
        merged_tree: MergedTree {
            entries: vec![TreeEntry {
                mode: TreeMode(0o100644),
                path: b"file.txt".to_vec(),
                object: oid(GitHashAlgorithm::Sha256, "01"),
            }],
        },
    };

    // Valid when all coordinates match
    assert!(step.check_validity(candidate_tip, projected_base, epoch).is_ok());

    // Invalidation 1: Candidate tip moved
    let candidate_moved = oid(GitHashAlgorithm::Sha256, "c2");
    let err_source = step.check_validity(candidate_moved, projected_base, epoch).unwrap_err();
    assert_eq!(
        err_source,
        ForgeRefusal::MergeStale {
            reference: MergeSide::Source,
            tips: fgit_forge::StaleTips {
                computed_against: candidate_tip,
                observed: candidate_moved,
            }
        }
    );

    // Invalidation 2: Base tip moved
    let base_moved = oid(GitHashAlgorithm::Sha256, "b2");
    let err_target = step.check_validity(candidate_tip, base_moved, epoch).unwrap_err();
    assert_eq!(
        err_target,
        ForgeRefusal::MergeStale {
            reference: MergeSide::Target,
            tips: fgit_forge::StaleTips {
                computed_against: projected_base,
                observed: base_moved,
            }
        }
    );

    // Invalidation 3: Workspace epoch moved
    let epoch_moved = WorkspaceEpoch::from_u64(2);
    let err_workspace = step.check_validity(candidate_tip, projected_base, epoch_moved).unwrap_err();
    assert_eq!(
        err_workspace,
        ForgeRefusal::WorkspaceMoved {
            computed_in: epoch,
            observed: epoch_moved,
        }
    );
}

#[test]
fn test_single_decision_landing_and_per_pr_atomicity() {
    let target = RefName::try_new(b"refs/heads/main").unwrap();
    let base_tip = oid(GitHashAlgorithm::Sha256, "10");

    let pr1 = PullRequestNumber::try_new(10).unwrap();
    let pr2 = PullRequestNumber::try_new(20).unwrap();

    let pr1_tip = oid(GitHashAlgorithm::Sha256, "11");
    let pr2_tip = oid(GitHashAlgorithm::Sha256, "22");

    let spec_commit1 = oid(GitHashAlgorithm::Sha256, "31");
    let spec_commit2 = oid(GitHashAlgorithm::Sha256, "32");

    let step1 = SpeculativeMergeStep {
        pull_request: pr1,
        candidate_source_ref: RefName::try_new(b"refs/heads/feature-1").unwrap(),
        candidate_tip: pr1_tip,
        projected_base_tip: base_tip,
        merge_base_tip: oid(GitHashAlgorithm::Sha256, "01"),
        resulting_speculative_tip: spec_commit1,
        workspace_epoch: WorkspaceEpoch::from_u64(1),
        merged_tree: MergedTree { entries: vec![] },
    };

    let step2 = SpeculativeMergeStep {
        pull_request: pr2,
        candidate_source_ref: RefName::try_new(b"refs/heads/feature-2").unwrap(),
        candidate_tip: pr2_tip,
        projected_base_tip: spec_commit1, // Merged on top of PR 1's speculative commit
        merge_base_tip: oid(GitHashAlgorithm::Sha256, "02"),
        resulting_speculative_tip: spec_commit2,
        workspace_epoch: WorkspaceEpoch::from_u64(1),
        merged_tree: MergedTree { entries: vec![] },
    };


    let batch_entries = vec![
        QueueBatchEntry {
            pull_request: pr1,
            source_ref: step1.candidate_source_ref.clone(),
            head_tip: pr1_tip,
        },
        QueueBatchEntry {
            pull_request: pr2,
            source_ref: step2.candidate_source_ref.clone(),
            head_tip: pr2_tip,
        },
    ];
    let batch_id = QueueBatchId::compute(&target, base_tip, &batch_entries).unwrap();

    let plan = SpeculativeBatchPlan {
        batch_id,
        target_ref: target.clone(),
        initial_target_tip: base_tip,
        final_target_tip: spec_commit2,
        steps: vec![step1, step2],
    };

    let queue_num = QueueNumber::try_new(1).unwrap();
    let queue_ver = AggregateVersion::try_new(5).unwrap();

    let landing_pkg = assemble_batch_landing_package(
        &plan,
        queue_num,
        queue_ver,
        base_tip,
        vec![spec_commit1, spec_commit2],
    )
    .unwrap();

    // Verifications:
    // 1. Target ref intent moves from initial target tip to final target tip
    assert_eq!(landing_pkg.target_ref_intent.name, target.as_bytes());
    assert_eq!(landing_pkg.target_ref_intent.expected_tip, base_tip);
    assert_eq!(landing_pkg.target_ref_intent.new_tip, spec_commit2);

    // 2. Queue head ref intent moves to final target tip
    assert_eq!(landing_pkg.queue_head_intent.name, b"refs/queue/main/head");
    assert_eq!(landing_pkg.queue_head_intent.new_tip, spec_commit2);


    // 3. Event batch contains individual PR events + queue event
    assert_eq!(landing_pkg.event_batch.events.len(), 3);

    // Event 0: PR 1 NativeMerge
    assert_eq!(landing_pkg.event_batch.events[0].aggregate, AggregateId::PullRequest(pr1));
    if let ForgeEventPayload::MergeCommittedNative(merge) = &landing_pkg.event_batch.events[0].payload {
        assert_eq!(merge.source_tip, pr1_tip);
        assert_eq!(merge.target_tip_before, base_tip);
        assert_eq!(merge.merge_commit, spec_commit1);
    } else {
        panic!("expected NativeMerge event for PR 1");
    }

    // Event 1: PR 2 NativeMerge
    assert_eq!(landing_pkg.event_batch.events[1].aggregate, AggregateId::PullRequest(pr2));
    if let ForgeEventPayload::MergeCommittedNative(merge) = &landing_pkg.event_batch.events[1].payload {
        assert_eq!(merge.source_tip, pr2_tip);
        assert_eq!(merge.target_tip_before, spec_commit1);
        assert_eq!(merge.merge_commit, spec_commit2);
    } else {
        panic!("expected NativeMerge event for PR 2");
    }

    // Event 2: Queue BatchLanded
    assert_eq!(landing_pkg.event_batch.events[2].aggregate, AggregateId::MergeQueue(queue_num));
    assert_eq!(landing_pkg.event_batch.events[2].version, queue_ver);
    if let ForgeEventPayload::MergeQueueChangedNative(q_event) = &landing_pkg.event_batch.events[2].payload {
        assert_eq!(q_event.queue_number, queue_num);
        if let QueueAction::BatchLanded { batch_id: b_id, entries, target_tip } = &q_event.action {
            assert_eq!(b_id, plan.batch_id.digest());
            assert_eq!(entries, &[pr1, pr2]);
            assert_eq!(*target_tip, spec_commit2);
        } else {
            panic!("expected BatchLanded queue action");
        }
    } else {
        panic!("expected MergeQueueChangedNative payload");
    }

    // 4. Sealing into ONE single RepositoryCommitRecord
    let roots = landing_pkg.roots(&CryptoBodyIdentity).unwrap();
    assert!(!roots.ref_intent_root.bytes().is_empty());
    assert!(!roots.forge_event_batch_root.bytes().is_empty());

    let rcr = landing_pkg.seal_into_record(&CryptoBodyIdentity, dummy_record_frame()).unwrap();
    assert_eq!(rcr.forge_event_batch_root, roots.forge_event_batch_root);
}

#[test]
fn test_canonical_queue_events_codec_roundtrip() {
    let queue_num = QueueNumber::try_new(7).unwrap();
    let target = RefName::try_new(b"refs/heads/main").unwrap();
    let user = principal(0x42);

    let dummy_digest = Digest::new(
        fgit_crypto::InternalDigestAlgorithm::Sha256.id(),
        fgit_types::hash::DigestBytes::try_new(&[0x44; 32]).unwrap(),
    );

    let actions = vec![
        QueueAction::Enqueue {
            pull_request: PullRequestNumber::try_new(101).unwrap(),
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            head_tip: oid(GitHashAlgorithm::Sha256, "55"),
            enqueued_by: user,
            priority: 10,
        },
        QueueAction::Dequeue {
            pull_request: PullRequestNumber::try_new(101).unwrap(),
            dequeued_by: user,
            reason: DequeueReason::Withdrawn,
        },
        QueueAction::Reorder {
            order: vec![
                PullRequestNumber::try_new(202).unwrap(),
                PullRequestNumber::try_new(101).unwrap(),
            ],
            reordered_by: user,
        },
        QueueAction::BatchFormed {
            batch_id: dummy_digest,
            entries: vec![
                PullRequestNumber::try_new(202).unwrap(),
                PullRequestNumber::try_new(101).unwrap(),
            ],
        },
        QueueAction::BatchLanded {
            batch_id: dummy_digest,
            entries: vec![
                PullRequestNumber::try_new(202).unwrap(),
                PullRequestNumber::try_new(101).unwrap(),
            ],
            target_tip: oid(GitHashAlgorithm::Sha256, "99"),
        },
        QueueAction::BatchRejected {
            batch_id: dummy_digest,
            reason: DequeueReason::Conflict,
        },
    ];

    for (i, action) in actions.into_iter().enumerate() {
        let version = AggregateVersion::try_new(i as u64 + 1).unwrap();
        let event = ForgeEvent {
            aggregate: AggregateId::MergeQueue(queue_num),
            version,
            payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
                queue_number: queue_num,
                target_ref: target.clone(),
                action,
            }),
        };

        let encoded = encode_body(&event).expect("encode queue event");
        let decoded: ForgeEvent = decode_body(&encoded, DecodeLimits::DEFAULT).expect("decode queue event");
        assert_eq!(event, decoded, "event at version {version} must roundtrip identically");
    }
}

#[test]
fn test_merge_queue_snapshot_deterministic_ordering_and_lifecycle() {
    let queue_num = QueueNumber::try_new(3).unwrap();
    let target = RefName::try_new(b"refs/heads/main").unwrap();
    let mut snapshot = MergeQueueSnapshot::new(queue_num, target.clone());

    assert!(snapshot.is_empty());
    assert_eq!(snapshot.len(), 0);

    let alice = principal(0x01);
    let bob = principal(0x02);


    let pr10 = PullRequestNumber::try_new(10).unwrap();
    let pr20 = PullRequestNumber::try_new(20).unwrap();
    let pr30 = PullRequestNumber::try_new(30).unwrap();

    // Event 1: Enqueue PR 10 with priority 5
    let v1 = AggregateVersion::FIRST;
    snapshot
        .apply_event(&ForgeEvent {
            aggregate: AggregateId::MergeQueue(queue_num),
            version: v1,
            payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
                queue_number: queue_num,
                target_ref: target.clone(),
                action: QueueAction::Enqueue {
                    pull_request: pr10,
                    source_ref: RefName::try_new(b"refs/heads/pr-10").unwrap(),
                    head_tip: oid(GitHashAlgorithm::Sha256, "10"),
                    enqueued_by: alice,
                    priority: 5,
                },
            }),
        })
        .unwrap();

    // Event 2: Enqueue PR 20 with higher priority 10
    let v2 = v1.next().unwrap();
    snapshot
        .apply_event(&ForgeEvent {
            aggregate: AggregateId::MergeQueue(queue_num),
            version: v2,
            payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
                queue_number: queue_num,
                target_ref: target.clone(),
                action: QueueAction::Enqueue {
                    pull_request: pr20,
                    source_ref: RefName::try_new(b"refs/heads/pr-20").unwrap(),
                    head_tip: oid(GitHashAlgorithm::Sha256, "20"),
                    enqueued_by: bob,
                    priority: 10,
                },
            }),
        })
        .unwrap();

    // Event 3: Enqueue PR 30 with priority 5 (same as PR 10, but later version)
    let v3 = v2.next().unwrap();
    snapshot
        .apply_event(&ForgeEvent {
            aggregate: AggregateId::MergeQueue(queue_num),
            version: v3,
            payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
                queue_number: queue_num,
                target_ref: target.clone(),
                action: QueueAction::Enqueue {
                    pull_request: pr30,
                    source_ref: RefName::try_new(b"refs/heads/pr-30").unwrap(),
                    head_tip: oid(GitHashAlgorithm::Sha256, "30"),
                    enqueued_by: alice,
                    priority: 5,
                },
            }),
        })
        .unwrap();

    assert_eq!(snapshot.len(), 3);

    // Deterministic order:
    // 1. PR 20 (priority 10)
    // 2. PR 10 (priority 5, enqueued at v1)
    // 3. PR 30 (priority 5, enqueued at v3)
    let order = snapshot.deterministic_order();
    assert_eq!(order, vec![pr20, pr10, pr30]);

    // Explicit reorder: PR 30 moved before PR 10
    let v4 = v3.next().unwrap();
    snapshot
        .apply_event(&ForgeEvent {
            aggregate: AggregateId::MergeQueue(queue_num),
            version: v4,
            payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
                queue_number: queue_num,
                target_ref: target.clone(),
                action: QueueAction::Reorder {
                    order: vec![pr30, pr20, pr10],
                    reordered_by: alice,
                },
            }),
        })
        .unwrap();

    let raw_order: Vec<PullRequestNumber> = snapshot.entries.iter().map(|e| e.pull_request).collect();
    assert_eq!(raw_order, vec![pr30, pr20, pr10]);

    // Batch formed with PR 30 and PR 20
    let dummy_digest = Digest::new(
        fgit_crypto::InternalDigestAlgorithm::Sha256.id(),
        fgit_types::hash::DigestBytes::try_new(&[0x77; 32]).unwrap(),
    );
    let v5 = v4.next().unwrap();
    snapshot
        .apply_event(&ForgeEvent {
            aggregate: AggregateId::MergeQueue(queue_num),
            version: v5,
            payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
                queue_number: queue_num,
                target_ref: target.clone(),
                action: QueueAction::BatchFormed {
                    batch_id: dummy_digest,
                    entries: vec![pr30, pr20],
                },
            }),
        })
        .unwrap();
    assert_eq!(snapshot.active_batch, Some(QueueBatchId::from_digest(dummy_digest)));

    // Batch landed
    let v6 = v5.next().unwrap();
    snapshot
        .apply_event(&ForgeEvent {
            aggregate: AggregateId::MergeQueue(queue_num),
            version: v6,
            payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
                queue_number: queue_num,
                target_ref: target.clone(),
                action: QueueAction::BatchLanded {
                    batch_id: dummy_digest,
                    entries: vec![pr30, pr20],
                    target_tip: oid(GitHashAlgorithm::Sha256, "ff"),
                },
            }),
        })
        .unwrap();

    assert_eq!(snapshot.active_batch, None);
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.entries[0].pull_request, pr10);

    // Dequeue PR 10
    let v7 = v6.next().unwrap();
    snapshot
        .apply_event(&ForgeEvent {
            aggregate: AggregateId::MergeQueue(queue_num),
            version: v7,
            payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
                queue_number: queue_num,
                target_ref: target,
                action: QueueAction::Dequeue {
                    pull_request: pr10,
                    dequeued_by: bob,
                    reason: DequeueReason::Withdrawn,
                },
            }),
        })
        .unwrap();

    assert!(snapshot.is_empty());
}
