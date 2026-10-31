use super::*;
use crate::aggregate::{PullRequestNumber, QueueNumber};
use crate::event::queue::{DequeueReason, NativeQueueEvent};
use fgit_types::{Digest, GitHashAlgorithm, GitOid, PrincipalId, RefName};

fn oid(tag: u8) -> GitOid {
    GitOid::from_hex(GitHashAlgorithm::Sha1, &format!("{tag:02x}").repeat(20)).unwrap()
}
fn number(value: u64) -> PullRequestNumber {
    PullRequestNumber::try_new(value).unwrap()
}
fn snapshot() -> MergeQueueSnapshot {
    MergeQueueSnapshot::new(
        QueueNumber::FIRST,
        RefName::try_new(b"refs/heads/main").unwrap(),
    )
}
fn enqueue(value: u64, priority: u32) -> QueueAction {
    QueueAction::Enqueue {
        pull_request: number(value),
        source_ref: RefName::try_new(format!("refs/heads/topic-{value}").as_bytes()).unwrap(),
        head_tip: oid(2),
        enqueued_by: PrincipalId::from_bytes([3; 16]),
        priority,
    }
}
fn event(version: u64, action: QueueAction) -> ForgeEvent {
    ForgeEvent {
        aggregate: AggregateId::MergeQueue(QueueNumber::FIRST),
        version: AggregateVersion::try_new(version).unwrap(),
        payload: ForgeEventPayload::MergeQueueChangedNative(NativeQueueEvent {
            queue_number: QueueNumber::FIRST,
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            action,
        }),
    }
}
fn batch(tag: u8) -> Digest {
    Digest::new(
        fgit_crypto::InternalDigestAlgorithm::Sha256.id(),
        fgit_types::hash::DigestBytes::try_new(&[tag; 32]).unwrap(),
    )
}
fn refuses_unchanged(snapshot: &mut MergeQueueSnapshot, event: &ForgeEvent) {
    let before = snapshot.clone();
    assert!(snapshot.apply_event(event).is_err());
    assert_eq!(*snapshot, before);
}

#[test]
fn replay_requires_first_and_each_exact_successor_even_after_queue_becomes_empty() {
    let mut queue = snapshot();
    refuses_unchanged(&mut queue, &event(2, enqueue(1, 0)));
    let first = event(1, enqueue(1, 0));
    queue.apply_event(&first).unwrap();
    refuses_unchanged(&mut queue, &first);
    refuses_unchanged(&mut queue, &event(3, enqueue(2, 0)));
    queue
        .apply_event(&event(
            2,
            QueueAction::Dequeue {
                pull_request: number(1),
                dequeued_by: PrincipalId::from_bytes([3; 16]),
                reason: DequeueReason::Withdrawn,
            },
        ))
        .unwrap();
    assert!(queue.is_empty());
    refuses_unchanged(&mut queue, &first);
    queue.apply_event(&event(3, enqueue(2, 0))).unwrap();
    assert_eq!(queue.deterministic_order(), vec![number(2)]);
}

#[test]
fn queue_and_branch_bindings_cannot_change_or_start_with_non_enqueue() {
    let mut queue = snapshot();
    refuses_unchanged(
        &mut queue,
        &event(
            1,
            QueueAction::Reorder {
                order: vec![],
                reordered_by: PrincipalId::from_bytes([3; 16]),
            },
        ),
    );
    for mutation in 0..3 {
        let mut wrong = event(1, enqueue(1, 0));
        let ForgeEventPayload::MergeQueueChangedNative(change) = &mut wrong.payload else {
            unreachable!()
        };
        match mutation {
            0 => wrong.aggregate = AggregateId::MergeQueue(QueueNumber::try_new(2).unwrap()),
            1 => change.queue_number = QueueNumber::try_new(2).unwrap(),
            _ => change.target_ref = RefName::try_new(b"refs/heads/other").unwrap(),
        }
        refuses_unchanged(&mut queue, &wrong);
    }
    queue.apply_event(&event(1, enqueue(1, 0))).unwrap();
}

#[test]
fn explicit_reorder_controls_execution_and_preserves_unselected_relative_order() {
    let mut queue = snapshot();
    for (version, priority) in [(1, 0), (2, 10), (3, 0)] {
        queue
            .apply_event(&event(version, enqueue(version, priority)))
            .unwrap();
    }
    assert_eq!(
        queue.deterministic_order(),
        vec![number(2), number(1), number(3)]
    );
    queue
        .apply_event(&event(
            4,
            QueueAction::Reorder {
                order: vec![number(3)],
                reordered_by: PrincipalId::from_bytes([3; 16]),
            },
        ))
        .unwrap();
    assert_eq!(
        queue.deterministic_order(),
        vec![number(3), number(2), number(1)]
    );
    for order in [vec![number(8)], vec![number(2), number(2)]] {
        refuses_unchanged(
            &mut queue,
            &event(
                5,
                QueueAction::Reorder {
                    order,
                    reordered_by: PrincipalId::from_bytes([3; 16]),
                },
            ),
        );
    }
    queue.apply_event(&event(5, enqueue(4, 0))).unwrap();
    assert_eq!(
        queue.deterministic_order(),
        vec![number(3), number(2), number(1), number(4)]
    );
}

#[test]
fn replacing_a_queued_request_uses_new_coordinates_actor_and_fifo_position() {
    let mut queue = snapshot();
    queue.apply_event(&event(1, enqueue(1, 0))).unwrap();
    queue.apply_event(&event(2, enqueue(2, 0))).unwrap();
    let source_ref = RefName::try_new(b"refs/heads/replacement").unwrap();
    let actor = PrincipalId::from_bytes([8; 16]);
    queue
        .apply_event(&event(
            3,
            QueueAction::Enqueue {
                pull_request: number(1),
                source_ref: source_ref.clone(),
                head_tip: oid(9),
                enqueued_by: actor,
                priority: 0,
            },
        ))
        .unwrap();
    assert_eq!(queue.deterministic_order(), vec![number(2), number(1)]);
    let replacement = queue.find_entry(number(1)).unwrap();
    assert_eq!(replacement.source_ref, source_ref);
    assert_eq!(replacement.head_tip, oid(9));
    assert_eq!(replacement.enqueued_by, actor);
    assert_eq!(replacement.enqueued_version.get(), 3);
}

#[test]
fn active_batch_freezes_membership_and_requires_its_exact_ordered_landing() {
    let mut queue = snapshot();
    queue.apply_event(&event(1, enqueue(1, 0))).unwrap();
    queue.apply_event(&event(2, enqueue(2, 0))).unwrap();
    refuses_unchanged(
        &mut queue,
        &event(
            3,
            QueueAction::BatchFormed {
                batch_id: batch(1),
                entries: vec![number(2)],
            },
        ),
    );
    queue
        .apply_event(&event(
            3,
            QueueAction::BatchFormed {
                batch_id: batch(1),
                entries: vec![number(1), number(2)],
            },
        ))
        .unwrap();
    for action in [
        enqueue(3, 0),
        QueueAction::Reorder {
            order: vec![number(2), number(1)],
            reordered_by: PrincipalId::from_bytes([3; 16]),
        },
        QueueAction::Dequeue {
            pull_request: number(1),
            dequeued_by: PrincipalId::from_bytes([3; 16]),
            reason: DequeueReason::Withdrawn,
        },
        QueueAction::BatchFormed {
            batch_id: batch(2),
            entries: vec![number(1)],
        },
        QueueAction::BatchRejected {
            batch_id: batch(2),
            reason: DequeueReason::Conflict,
        },
        QueueAction::BatchLanded {
            batch_id: batch(2),
            entries: vec![number(1), number(2)],
            target_tip: oid(4),
        },
        QueueAction::BatchLanded {
            batch_id: batch(1),
            entries: vec![number(2), number(1)],
            target_tip: oid(4),
        },
        QueueAction::BatchLanded {
            batch_id: batch(1),
            entries: vec![number(1)],
            target_tip: oid(4),
        },
    ] {
        refuses_unchanged(&mut queue, &event(4, action));
    }
    queue
        .apply_event(&event(
            4,
            QueueAction::BatchLanded {
                batch_id: batch(1),
                entries: vec![number(1), number(2)],
                target_tip: oid(4),
            },
        ))
        .unwrap();
    assert!(queue.is_empty());
    refuses_unchanged(
        &mut queue,
        &event(
            5,
            QueueAction::BatchRejected {
                batch_id: batch(1),
                reason: DequeueReason::Conflict,
            },
        ),
    );
}

#[test]
fn entry_limit_is_enforced_but_replacement_and_dequeue_release_capacity() {
    let mut queue = snapshot();
    for i in 1..=MAX_QUEUE_ENTRIES as u64 {
        queue.apply_event(&event(i, enqueue(i, 0))).unwrap();
    }
    let next = MAX_QUEUE_ENTRIES as u64 + 1;
    refuses_unchanged(&mut queue, &event(next, enqueue(next, 0)));
    queue.apply_event(&event(next, enqueue(1, 1))).unwrap();
    assert_eq!(queue.len(), MAX_QUEUE_ENTRIES);
    queue
        .apply_event(&event(
            next + 1,
            QueueAction::Dequeue {
                pull_request: number(1),
                dequeued_by: PrincipalId::from_bytes([3; 16]),
                reason: DequeueReason::Withdrawn,
            },
        ))
        .unwrap();
    queue
        .apply_event(&event(next + 2, enqueue(next, 0)))
        .unwrap();
    assert_eq!(queue.len(), MAX_QUEUE_ENTRIES);
}
