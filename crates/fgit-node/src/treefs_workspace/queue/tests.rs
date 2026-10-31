//! Real file-backed authority, native loose-object import and queue commands.
//! No Git subprocess, in-memory authority substitute, or synthetic batch result.
use super::*;
use crate::{MaterializedAdmission, NodeConfig};
use fgit_admission::merge::native::settlement::{DeliveryRequest, OutboxDestination};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::merge_queue::{DequeueReason, QueueCommandAction};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_resource::settlement::{DeliveryVerdict, ProbeVerdict};
use fgit_resource::{DownstreamIdempotency, ObligationState, ReconcilePolicy};
use fgit_types::{
    AsciiSlug, DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId,
    RepositoryId, TenantId,
};
use fsqlite_types::cx::Cx;
use std::{
    fs,
    future::Future,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct Scratch(pub(super) PathBuf);
impl Scratch {
    pub(super) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-native-queue-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub(super) fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0x81; 16]),
            RepositoryId::from_bytes([0x82; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
pub(super) fn actor() -> PrincipalId {
    PrincipalId::from_bytes([0x83; 16])
}
pub(super) fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        actor(),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    label: &str,
    body: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let len = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(len.to_le_bytes());
    encoded.extend((!len).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let dir = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&hex[2..]), encoded).unwrap();
    id
}
pub(super) fn initialize(
    scratch: &Scratch,
    format: GitHashAlgorithm,
) -> (OneNode, [PullRequestCommand; 3], GitOid) {
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let root = scratch.0.join("source");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let tree = loose(&root, format, GitObjectKind::Tree, "tree", b"");
    let commit = |name: &str, parent: Option<GitOid>| {
        let parent = parent.map_or_else(String::new, |oid| format!("parent {oid}\n"));
        let body = format!(
            "tree {tree}\n{parent}author Fixture <queue@example.invalid> 1 +0000\ncommitter Fixture <queue@example.invalid> 1 +0000\n\n{name}\n"
        );
        let oid = loose(
            &root,
            format,
            GitObjectKind::Commit,
            "commit",
            body.as_bytes(),
        );
        fs::write(root.join("refs/heads").join(name), format!("{oid}\n")).unwrap();
        oid
    };
    let target_tip = commit("main", None);
    let advanced = commit("advance", Some(target_tip));
    let pulls = [7, 9, 11].map(|number| PullRequestCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: RefName::try_new(format!("refs/heads/topic-{number}").as_bytes()).unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: commit(&format!("topic-{number}"), Some(target_tip)),
            target_tip,
            title: format!("Queue candidate {number}"),
            body: "Preserved candidate metadata é".into(),
        },
    });
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &root,
            actor(),
            b"queue-fixture-import",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    for pull in &pulls {
        apply_pull(&node, pull, &format!("open-{}", pull.number.get()));
    }
    (node, pulls, advanced)
}
pub(super) fn apply_pull(node: &OneNode, command: &PullRequestCommand, key: &str) {
    let request = node.request_context();
    accepted(node.runtime().block_on(node.admit_pull_request_durable_in(
        &request,
        &session(key),
        command,
        AdmissionLimits::default(),
    )));
}
pub(super) fn enqueue(
    number: u64,
    version: u64,
    pull: &PullRequestCommand,
    priority: u32,
) -> QueueCommand {
    command(
        number,
        version,
        QueueCommandAction::Enqueue {
            pull_request: pull.number,
            expected_pull_request_version: AggregateVersion::FIRST,
            source_ref: pull.data.source_ref.clone(),
            head_tip: pull.data.source_tip,
            expected_target_tip: pull.data.target_tip,
            priority,
        },
    )
}
pub(super) fn command(number: u64, version: u64, action: QueueCommandAction) -> QueueCommand {
    QueueCommand {
        number: QueueNumber::try_new(number).unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        action,
    }
}
pub(super) fn dequeue(number: u64, version: u64, pull: PullRequestNumber) -> QueueCommand {
    command(
        number,
        version,
        QueueCommandAction::Dequeue {
            pull_request: pull,
            reason: DequeueReason::Withdrawn,
        },
    )
}
pub(super) fn apply(
    node: &OneNode,
    command: &QueueCommand,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.admit_queue_durable_in(
        &request,
        &session(key),
        command,
        AdmissionLimits::default(),
    ))
}
pub(super) fn accepted(
    result: Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal>,
) -> (TxId, TerminalOutcome) {
    let result = result.unwrap();
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
    result
}
pub(super) fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
}
pub(super) fn read(
    node: &OneNode,
    number: u64,
    pin: Option<RepositoryAuthorityHeadId>,
) -> QueueRead {
    let request = node.request_context();
    node.runtime()
        .block_on(node.read_queue_in(
            &request,
            &RefVisibility::default(),
            QueueNumber::try_new(number).unwrap(),
            pin,
        ))
        .unwrap()
}
fn no_code_changes(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(
        before.basis().body().ref_root,
        after.basis().body().ref_root
    );
    assert_eq!(
        before.basis().body().retention_root,
        after.basis().body().retention_root
    );
    assert_eq!(
        before.basis().body().policy_epoch,
        after.basis().body().policy_epoch
    );
    assert_eq!(
        before.selected_closure().closure(),
        after.selected_closure().closure()
    );
}
fn refused(
    node: &OneNode,
    command: &QueueCommand,
    key: &str,
    expected: RefusalCode,
) -> (TxId, TerminalOutcome) {
    let before = snapshot(node);
    let result = apply(node, command, key).unwrap();
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
        "{result:?}"
    );
    let after = snapshot(node);
    no_code_changes(&before, &after);
    assert_eq!(
        before.basis().body().forge_position_root,
        after.basis().body().forge_position_root
    );
    assert_eq!(
        before.basis().body().outbox_root,
        after.basis().body().outbox_root
    );
    assert_eq!(
        before.snapshot().outbox.len(),
        after.snapshot().outbox.len()
    );
    result
}

#[test]
fn queue_lifecycle_is_atomic_metadata_and_rebuilds_with_exact_retries_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        let before = snapshot(&node);
        let first = enqueue(1, 0, &pulls[0], 0);
        let original = accepted(apply(&node, &first, "enqueue-first"));
        let pinned = read(&node, 1, None);
        accepted(apply(
            &node,
            &enqueue(1, 1, &pulls[1], 10),
            "enqueue-second",
        ));
        assert_eq!(
            read(&node, 1, None).queue.unwrap().deterministic_order(),
            vec![pulls[1].number, pulls[0].number]
        );
        let order = vec![pulls[0].number, pulls[1].number];
        accepted(apply(
            &node,
            &command(
                1,
                2,
                QueueCommandAction::Reorder {
                    order: order.clone(),
                },
            ),
            "reorder",
        ));
        let reordered = read(&node, 1, None).queue.unwrap();
        assert_eq!(
            reordered.deterministic_order(),
            order,
            "an explicit reorder changes execution order"
        );
        assert!(
            reordered
                .entries
                .iter()
                .all(|entry| entry.enqueued_by == actor())
        );
        assert!(reordered.active_batch.is_none());
        accepted(apply(
            &node,
            &dequeue(1, 3, pulls[0].number),
            "dequeue-first",
        ));
        accepted(apply(
            &node,
            &dequeue(1, 4, pulls[1].number),
            "dequeue-second",
        ));
        let empty = read(&node, 1, None);
        assert!(empty.queue.as_ref().unwrap().entries.is_empty());
        assert_eq!(empty.queue.as_ref().unwrap().version.get(), 5);
        assert_eq!(read(&node, 1, Some(pinned.source_head)), pinned);
        let after = snapshot(&node);
        no_code_changes(&before, &after);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 5
        );
        assert_ne!(
            before.basis().body().forge_position_root,
            after.basis().body().forge_position_root
        );
        assert_ne!(
            before.basis().body().outbox_root,
            after.basis().body().outbox_root
        );
        assert_eq!(apply(&node, &first, "enqueue-first").unwrap(), original);
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // Outcome recovery precedes service/quota gates and cannot re-enqueue a removed PR.
        assert_eq!(apply(&reopened, &first, "enqueue-first").unwrap(), original);
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(read(&reopened, 1, None), empty);
        assert_eq!(read(&reopened, 1, Some(pinned.source_head)), pinned);
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        reopened.push_quota.limit.max_events = 0;
        assert_eq!(apply(&reopened, &first, "enqueue-first").unwrap(), original);
        assert!(matches!(
            apply(&reopened, &enqueue(2, 0, &pulls[0], 0), "quota"),
            Err(NodeReceiveTransportRefusal::QuotaContained { .. })
        ));
        reopened.shutdown().unwrap();
    }
}

#[test]
fn enqueue_requires_exact_open_pull_request_and_live_candidate_coordinates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, mut pulls, advanced) = initialize(&scratch, format);
        let mut absent = enqueue(1, 0, &pulls[0], 0);
        if let QueueCommandAction::Enqueue { pull_request, .. } = &mut absent.action {
            *pull_request = PullRequestNumber::try_new(99).unwrap();
        }
        let missing = refused(
            &node,
            &absent,
            "missing",
            RefusalCode::ProtectedRefTransitionDenied,
        );
        assert!(read(&node, 1, None).queue.is_none());
        accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
        refused(
            &node,
            &enqueue(1, 0, &pulls[1], 0),
            "stale-queue",
            RefusalCode::EvidenceStale,
        );
        let pinned_pull = enqueue(1, 1, &pulls[1], 0);
        pulls[1].action = PullRequestAction::Update;
        pulls[1].expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        pulls[1].data.title = "Review scope changed".into();
        apply_pull(&node, &pulls[1], "update-pull");
        refused(
            &node,
            &pinned_pull,
            "stale-pull",
            RefusalCode::EvidenceStale,
        );
        let mut current_pull = pinned_pull;
        if let QueueCommandAction::Enqueue {
            expected_pull_request_version,
            ..
        } = &mut current_pull.action
        {
            *expected_pull_request_version = AggregateVersion::try_new(2).unwrap();
        }
        let mut wrong_head = current_pull.clone();
        if let QueueCommandAction::Enqueue { head_tip, .. } = &mut wrong_head.action {
            *head_tip = pulls[0].data.source_tip;
        }
        refused(&node, &wrong_head, "wrong-head", RefusalCode::EvidenceStale);
        accepted(apply(&node, &current_pull, "current-pull"));
        let candidate = enqueue(1, 2, &pulls[2], 0);
        let request = node.request_context();
        let moved = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &request,
                &session("move-target"),
                &[RefCommand {
                    name: pulls[2].data.target_ref.clone(),
                    expected_old: ExpectedOld::Exactly(pulls[2].data.target_tip),
                    proposed_new: ProposedNew::Update(advanced),
                    force: false,
                }],
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(
            moved.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let moved_refusal = refused(
            &node,
            &candidate,
            "moved-target",
            RefusalCode::TargetRefMoved,
        );
        pulls[2].action = PullRequestAction::Update;
        pulls[2].expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        pulls[2].data.target_tip = advanced;
        apply_pull(&node, &pulls[2], "refresh-target");
        let mut refreshed = enqueue(1, 2, &pulls[2], 0);
        if let QueueCommandAction::Enqueue {
            expected_pull_request_version,
            ..
        } = &mut refreshed.action
        {
            *expected_pull_request_version = AggregateVersion::try_new(2).unwrap();
        }
        accepted(apply(&node, &refreshed, "fresh-target"));
        pulls[2].action = PullRequestAction::Close;
        pulls[2].expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        apply_pull(&node, &pulls[2], "close-pull");
        let mut closed = enqueue(2, 0, &pulls[2], 0);
        if let QueueCommandAction::Enqueue {
            expected_pull_request_version,
            ..
        } = &mut closed.action
        {
            *expected_pull_request_version = AggregateVersion::try_new(3).unwrap();
        }
        refused(
            &node,
            &closed,
            "closed-pull",
            RefusalCode::ProtectedRefTransitionDenied,
        );
        let after = snapshot(&node);
        assert_eq!(apply(&node, &absent, "missing").unwrap(), missing);
        assert_eq!(
            apply(&node, &candidate, "moved-target").unwrap(),
            moved_refusal
        );
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn overlapping_queue_creation_decides_one_winner_without_losing_or_duplicating_entries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        let before = snapshot(&node);
        let (a, b) = (enqueue(1, 0, &pulls[0], 0), enqueue(1, 0, &pulls[1], 0));
        let (ra, rb) = (node.request_context(), node.request_context());
        let (sa, sb) = (session("a"), session("b"));
        let mut fa =
            Box::pin(node.admit_queue_durable_in(&ra, &sa, &a, AdmissionLimits::default()));
        let mut fb =
            Box::pin(node.admit_queue_durable_in(&rb, &sb, &b, AdmissionLimits::default()));
        let (mut left, mut right, mut overlap) = (None, None, false);
        let (a_result, b_result) = node.runtime().block_on(std::future::poll_fn(|cx| {
            if left.is_none()
                && let Poll::Ready(value) = fa.as_mut().poll(cx)
            {
                left = Some(value);
            }
            if right.is_none()
                && let Poll::Ready(value) = fb.as_mut().poll(cx)
            {
                right = Some(value);
            }
            overlap |= left.is_none() && right.is_none();
            if left.is_some() && right.is_some() {
                Poll::Ready((
                    left.take().unwrap().unwrap(),
                    right.take().unwrap().unwrap(),
                ))
            } else {
                Poll::Pending
            }
        }));
        drop(fa);
        drop(fb);
        assert!(
            overlap,
            "both real authority operations must be pending together"
        );
        let outcomes = [&a_result.1.outcome, &b_result.1.outcome];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, DecisionOutcome::Committed { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::EvidenceStale,
                        ..
                    }
                ))
                .count(),
            1
        );
        let queue = read(&node, 1, None).queue.unwrap();
        assert_eq!(queue.version.get(), 1);
        assert_eq!(queue.entries.len(), 1);
        let winner = if matches!(a_result.1.outcome, DecisionOutcome::Committed { .. }) {
            pulls[0].number
        } else {
            pulls[1].number
        };
        assert_eq!(queue.entries[0].pull_request, winner);
        let after = snapshot(&node);
        no_code_changes(&before, &after);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        assert_eq!(apply(&node, &a, "a").unwrap(), a_result);
        assert_eq!(apply(&node, &b, "b").unwrap(), b_result);
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn queue_reads_are_numeric_snapshot_pinned_and_hide_complete_source_scopes() {
    let scratch = Scratch::new();
    let (node, pulls, _) = initialize(&scratch, GitHashAlgorithm::Sha256);
    for number in [10, 2, 1] {
        accepted(apply(
            &node,
            &enqueue(number, 0, &pulls[0], 0),
            &format!("enqueue-{number}"),
        ));
    }
    let request = node.request_context();
    let visible = RefVisibility::default();
    let first = node
        .runtime()
        .block_on(node.read_queues_in(&request, &visible, 0, 2, None))
        .unwrap();
    assert_eq!(
        first
            .queues
            .iter()
            .map(|queue| queue.queue_number.get())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(first.next_after, Some(2));
    assert!(matches!(
        node.runtime()
            .block_on(node.read_queues_in(&request, &visible, 2, 2, None)),
        Err(QueueReadRefusal::SnapshotRequired)
    ));
    let second = node
        .runtime()
        .block_on(node.read_queues_in(&request, &visible, 2, 2, Some(first.source_head)))
        .unwrap();
    assert_eq!(second.queues[0].queue_number.get(), 10);
    assert_eq!(second.next_after, None);
    accepted(apply(&node, &dequeue(10, 1, pulls[0].number), "empty-ten"));
    let before_reads = snapshot(&node);
    assert_eq!(
        node.runtime()
            .block_on(node.read_queues_in(&request, &visible, 2, 2, Some(first.source_head)))
            .unwrap(),
        second
    );
    assert!(read(&node, 10, None).queue.unwrap().entries.is_empty());
    for reference in [&pulls[0].data.source_ref, &pulls[0].data.target_ref] {
        let mut hidden = RefVisibility::default();
        hidden
            .push_rule(reference.as_bytes(), &Default::default())
            .unwrap();
        for pin in [None, Some(first.source_head)] {
            let one = node
                .runtime()
                .block_on(node.read_queue_in(&request, &hidden, QueueNumber::FIRST, pin))
                .unwrap();
            assert!(
                one.queue.is_none(),
                "a retained snapshot grants no source visibility"
            );
        }
        let hidden_page = node
            .runtime()
            .block_on(node.read_queues_in(&request, &hidden, 0, 100, Some(first.source_head)))
            .unwrap();
        assert!(hidden_page.queues.is_empty());
        assert_eq!(hidden_page.next_after, None);
    }
    assert!(read(&node, 99, None).queue.is_none());
    for limit in [0, 101] {
        assert!(matches!(
            node.runtime()
                .block_on(node.read_queues_in(&request, &visible, 0, limit, None)),
            Err(QueueReadRefusal::InvalidLimit)
        ));
    }
    assert_eq!(snapshot(&node).basis(), before_reads.basis());
    node.shutdown().unwrap();
}

#[test]
fn invalid_transitions_reused_keys_and_cancelled_requests_preserve_the_queue() {
    let scratch = Scratch::new();
    let (node, pulls, _) = initialize(&scratch, GitHashAlgorithm::Sha1);
    let initial = enqueue(1, 0, &pulls[0], 0);
    accepted(apply(&node, &initial, "enqueue"));
    refused(
        &node,
        &dequeue(1, 1, pulls[1].number),
        "absent-entry",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    refused(
        &node,
        &command(
            1,
            1,
            QueueCommandAction::Reorder {
                order: vec![pulls[1].number],
            },
        ),
        "unknown-order",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    let mut retarget = dequeue(1, 1, pulls[0].number);
    retarget.target_ref = RefName::try_new(b"refs/heads/advance").unwrap();
    refused(
        &node,
        &retarget,
        "retarget",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    let before = snapshot(&node);
    let next = enqueue(1, 1, &pulls[1], 0);
    assert!(
        apply(&node, &next, "enqueue").is_err(),
        "same key cannot seal a different candidate"
    );
    let request = node.request_context();
    request.authority().cancel();
    assert!(
        node.runtime()
            .block_on(node.admit_queue_durable_in(
                &request,
                &session("cancel"),
                &next,
                AdmissionLimits::default()
            ))
            .is_err()
    );
    let request = node.request_context();
    assert!(matches!(
        node.runtime().block_on(node.admit_queue_durable_in(
            &request,
            &LoopbackReceiveSession::anonymous(),
            &next,
            AdmissionLimits::default()
        )),
        Err(NodeReceiveTransportRefusal::Unauthenticated)
    ));
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert_eq!(read(&node, 1, None).queue.unwrap().entries.len(), 1);
    accepted(apply(&node, &next, "permitted-twin"));
    assert_eq!(read(&node, 1, None).queue.unwrap().entries.len(), 2);
    refused(
        &node,
        &command(
            1,
            2,
            QueueCommandAction::Reorder {
                order: vec![pulls[0].number],
            },
        ),
        "incomplete-order",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    // A new version-pinned enqueue refreshes a PR's entry; an identical retry
    // remains a historical observation and cannot duplicate that entry.
    let replacement = enqueue(1, 2, &pulls[0], 5);
    let replaced = accepted(apply(&node, &replacement, "replace-entry"));
    let refreshed = read(&node, 1, None).queue.unwrap();
    assert_eq!(refreshed.version.get(), 3);
    assert_eq!(refreshed.entries.len(), 2);
    let entry = refreshed
        .entries
        .iter()
        .find(|entry| entry.pull_request == pulls[0].number)
        .unwrap();
    assert_eq!(entry.priority, 5);
    assert_eq!(entry.enqueued_version.get(), 3);
    let after = snapshot(&node);
    assert_eq!(
        apply(&node, &replacement, "replace-entry").unwrap(),
        replaced
    );
    assert_eq!(snapshot(&node).basis(), after.basis());
    node.shutdown().unwrap();
}

/// A real local receiver with synced, immutable receipts. Only its transport
/// observation is test-owned: normal node settlement publishes every authority
/// transition and removes the acknowledged obligation from the active outbox.
struct QueueReceiptDestination {
    root: PathBuf,
    probes: usize,
    sends: usize,
}

impl QueueReceiptDestination {
    fn bytes(&self, request: &DeliveryRequest<'_>) -> Result<Vec<u8>, RefusalCode> {
        if request.destination != self.destination() {
            return Err(RefusalCode::PublicationPolicyRefused);
        }
        if fgit_admission::evidence::evidence_root(request.events)? != request.payload_root {
            return Err(RefusalCode::EvidenceInvalid);
        }
        fgit_codec::encode_body(request.events).map_err(|_| RefusalCode::CanonicalFramingInvalid)
    }

    fn sync_directory(&self) -> Result<(), RefusalCode> {
        fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| RefusalCode::EvidenceMissing)
    }
}

fn deferred_once<T>(
    work: impl FnOnce() -> T + Send,
) -> impl std::future::Future<Output = T> + Send {
    let mut work = Some(work);
    std::future::poll_fn(move |_| match work.take() {
        Some(work) => std::task::Poll::Ready(work()),
        None => std::task::Poll::Pending,
    })
}

impl OutboxDestination<Cx> for QueueReceiptDestination {
    fn destination(&self) -> AsciiSlug {
        AsciiSlug::from_static("forge-projection")
    }

    fn idempotency(&self) -> DownstreamIdempotency {
        DownstreamIdempotency::Strong
    }

    fn probe<'a>(
        &'a mut self,
        _cx: &'a Cx,
        request: &'a DeliveryRequest<'_>,
    ) -> impl std::future::Future<Output = Result<(ProbeVerdict, Vec<u8>), RefusalCode>> + Send + 'a
    {
        deferred_once(move || {
            self.probes += 1;
            let expected = self.bytes(request)?;
            match fs::read(self.root.join(request.key.to_string())) {
                Ok(bytes) if bytes == expected => {
                    self.sync_directory()?;
                    Ok((
                        ProbeVerdict::Delivered,
                        b"synced queue receiver receipt".to_vec(),
                    ))
                }
                Ok(_) => Err(RefusalCode::EvidenceInvalid),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok((ProbeVerdict::NotDelivered, Vec::new()))
                }
                Err(_) => Err(RefusalCode::EvidenceMissing),
            }
        })
    }

    fn deliver<'a>(
        &'a mut self,
        _cx: &'a Cx,
        request: &'a DeliveryRequest<'_>,
        _attempt: u32,
    ) -> impl std::future::Future<Output = Result<(DeliveryVerdict, Vec<u8>), RefusalCode>> + Send + 'a
    {
        deferred_once(move || {
            use std::io::Write;
            self.sends += 1;
            let bytes = self.bytes(request)?;
            fs::create_dir_all(&self.root).map_err(|_| RefusalCode::EvidenceMissing)?;
            fs::File::open(self.root.parent().ok_or(RefusalCode::EvidenceMissing)?)
                .and_then(|parent| parent.sync_all())
                .map_err(|_| RefusalCode::EvidenceMissing)?;
            let staging = self
                .root
                .join(format!(".pending-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&staging)
                .map_err(|_| RefusalCode::EvidenceMissing)?;
            let result = (|| {
                file.write_all(&bytes)
                    .map_err(|_| RefusalCode::EvidenceMissing)?;
                file.sync_all().map_err(|_| RefusalCode::EvidenceMissing)?;
                let target = self.root.join(request.key.to_string());
                match fs::hard_link(&staging, &target) {
                    Ok(()) => Ok(DeliveryVerdict::Accepted),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        if fs::read(&target).map_err(|_| RefusalCode::EvidenceMissing)? == bytes {
                            Ok(DeliveryVerdict::DuplicateSuppressed)
                        } else {
                            Err(RefusalCode::EvidenceInvalid)
                        }
                    }
                    Err(_) => Err(RefusalCode::EvidenceMissing),
                }
            })();
            drop(file);
            fs::remove_file(&staging).map_err(|_| RefusalCode::EvidenceMissing)?;
            self.sync_directory()?;
            Ok((result?, b"synced queue receiver receipt".to_vec()))
        })
    }
}

#[test]
fn settled_queue_events_remain_replayable_after_retirement_restart_and_later_mutation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        let before = snapshot(&node);
        let first = enqueue(1, 0, &pulls[0], 0);
        let original = accepted(apply(&node, &first, "retirement-first"));
        let first_head = read(&node, 1, None);
        let after_first = snapshot(&node);
        let added: Vec<_> = after_first
            .snapshot()
            .outbox
            .keys()
            .filter(|key| !before.snapshot().outbox.contains_key(*key))
            .collect();
        assert_eq!(added.len(), 1);
        let key = added[0].label();
        accepted(apply(
            &node,
            &enqueue(1, 1, &pulls[1], 0),
            "retirement-second",
        ));
        let expected = read(&node, 1, None);
        assert_eq!(expected.queue.as_ref().unwrap().version.get(), 2);
        let before_delivery = snapshot(&node);
        let mut receiver = QueueReceiptDestination {
            root: scratch.0.join("receiver"),
            probes: 0,
            sends: 0,
        };
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.select_forge_delivery_in(
                &request,
                key,
                receiver.destination(),
                Some(before_delivery.basis().id()),
            ))
            .unwrap();
        let delivered_events = selected.as_request();
        assert_eq!(delivered_events.events.events.len(), 1);
        assert_eq!(
            delivered_events.events.events[0].aggregate,
            fgit_forge::aggregate::AggregateId::MergeQueue(QueueNumber::FIRST)
        );
        assert_eq!(
            delivered_events.events.events[0].version,
            AggregateVersion::FIRST
        );
        let payload_root = delivered_events.payload_root;
        let request = node.outbox_delivery_context();
        let acknowledged = node
            .runtime()
            .block_on(node.deliver_forge_outbox_in(
                &request,
                &session("queue-delivery-worker"),
                key,
                &mut receiver,
                ReconcilePolicy::new(std::num::NonZeroU32::new(4).unwrap()),
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert_eq!(acknowledged.state(), ObligationState::Acknowledged);
        assert_eq!((receiver.probes, receiver.sends), (1, 1));
        let retired = snapshot(&node);
        assert_eq!(
            retired.snapshot().outbox.len() + 1,
            before_delivery.snapshot().outbox.len()
        );
        assert!(
            !retired
                .snapshot()
                .outbox
                .keys()
                .any(|entry| entry.label() == key)
        );
        assert_eq!(
            retired.basis().body().forge_position_root,
            before_delivery.basis().body().forge_position_root
        );
        no_code_changes(&before_delivery, &retired);
        let request = node.request_context();
        let receipt = node
            .runtime()
            .block_on(node.read_retired_forge_receipt_in(
                &request,
                key,
                receiver.destination(),
                Some(retired.basis().id()),
            ))
            .unwrap();
        assert_eq!(receipt.effect(), &acknowledged);
        assert_eq!(receipt.receipt().payload_root(), payload_root);
        // v2 is still pending, but v1 has disappeared from the active outbox.
        // Only authenticated canonical history can reconstruct the full queue.
        assert_eq!(read(&node, 1, None).queue, expected.queue);
        assert_eq!(read(&node, 1, Some(expected.source_head)), expected);
        assert_eq!(read(&node, 1, Some(first_head.source_head)), first_head);
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(read(&reopened, 1, None).queue, expected.queue);
        assert_eq!(
            apply(&reopened, &first, "retirement-first").unwrap(),
            original
        );
        assert_eq!(snapshot(&reopened).basis(), retired.basis());
        accepted(apply(
            &reopened,
            &enqueue(1, 2, &pulls[2], 0),
            "after-retirement",
        ));
        let current = read(&reopened, 1, None).queue.unwrap();
        assert_eq!(current.version.get(), 3);
        assert_eq!(
            current.deterministic_order(),
            pulls.iter().map(|pull| pull.number).collect::<Vec<_>>()
        );
        no_code_changes(&retired, &snapshot(&reopened));
        reopened.shutdown().unwrap();
    }
}
