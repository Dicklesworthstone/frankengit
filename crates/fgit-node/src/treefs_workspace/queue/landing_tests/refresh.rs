//! Queue continuity through the real durable authority. Refreshing advances one
//! PR stream, preserves FIFO state and requires a newly prepared exact subject.
use super::*;
use crate::NodeWorkspaceRefusal;
use fgit_admission::merge::native::queue::{
    QueueCandidateLandingCommand, QueueHeadRefreshCommand,
};
use fgit_forge::preparation::{
    MergeCommitStyle, MergeMetadata, MergePreparation, PreparationLimits,
};

fn refresh_command(
    pull: &PullRequestCommand,
    queue_version: u64,
    new_target: GitOid,
) -> QueueHeadRefreshCommand {
    let mut update = pull.clone();
    update.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    update.action = PullRequestAction::Update;
    update.data.target_tip = new_target;
    QueueHeadRefreshCommand {
        number: QueueNumber::FIRST,
        expected_queue_version: version(queue_version),
        expected_policy_epoch: PolicyEpoch::FIRST,
        expected_recorded_target_tip: pull.data.target_tip,
        pull_request: update,
    }
}

fn refresh(
    node: &OneNode,
    offered: &QueueHeadRefreshCommand,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    node.runtime().block_on(node.refresh_queue_head_durable_in(
        &node.request_context(),
        &session(key),
        offered,
        AdmissionLimits::default(),
    ))
}

fn refuse_refresh(
    node: &OneNode,
    offered: &QueueHeadRefreshCommand,
    key: &str,
    expected: RefusalCode,
) -> (TxId, TerminalOutcome) {
    let before = snapshot(node);
    let queued = read(node, 1, None).queue;
    let result = refresh(node, offered, key).unwrap();
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
        "expected {expected:?}: {result:?}"
    );
    unchanged_publication(&before, &snapshot(node));
    assert_eq!(read(node, 1, None).queue, queued);
    result
}

fn subject(pull: &PullRequestCommand, pull_version: u64) -> ReviewSubject {
    ReviewSubject {
        pull_request: pull.number,
        pull_request_version: version(pull_version),
        source_ref: pull.data.source_ref.clone(),
        target_ref: pull.data.target_ref.clone(),
        source_tip: pull.data.source_tip,
        target_tip: pull.data.target_tip,
        policy_epoch: PolicyEpoch::FIRST,
    }
}

fn prepare(
    node: &OneNode,
    selected: &ReviewSubject,
    queue_version: u64,
) -> Result<PreparedQueueHeadBundle, NodeWorkspaceRefusal> {
    node.runtime().block_on(node.prepare_queue_head_bundle_in(
        &node.request_context(),
        QueueNumber::FIRST,
        version(queue_version),
        selected,
        &RefVisibility::default(),
        &MergeMetadata {
            author: "Queue operator <queue@example.invalid>".into(),
            committer: "Queue operator <queue@example.invalid>".into(),
            timestamp: 3,
            message: b"Integrate the refreshed queue head\n".to_vec(),
        },
        PreparationLimits::default(),
    ))
}

#[test]
fn refreshed_second_head_lands_without_reenqueue_and_recovers_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, pulls, _) = initialize(&scratch, format);
        accepted(apply(&node, &enqueue(1, 0, &pulls[0], 7), "first"));
        accepted(apply(&node, &enqueue(1, 1, &pulls[1], 7), "second"));
        accepted(land(&node, &landing(&pulls[0], 2), "land-first"));
        let queued = read(&node, 1, None).queue.unwrap();
        assert_eq!(queued.version, version(4));
        assert_eq!(queued.deterministic_order(), vec![pulls[1].number]);

        let stale_subject = subject(&pulls[1], 1);
        assert!(matches!(
            prepare(&node, &stale_subject, 4),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        let offered = refresh_command(&pulls[1], 4, pulls[0].data.source_tip);
        let before = snapshot(&node);
        let original = accepted(refresh(&node, &offered, "refresh-second"));
        let after = snapshot(&node);
        assert_eq!(read(&node, 1, None).queue, Some(queued.clone()));
        assert_eq!(after.snapshot().refs, before.snapshot().refs);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(after.basis().body().ref_root, before.basis().body().ref_root);
        assert_eq!(
            after.basis().body().retention_root,
            before.basis().body().retention_root
        );
        assert_eq!(
            after.selected_closure().closure(),
            before.selected_closure().closure()
        );
        assert_eq!(after.snapshot().outbox.len(), before.snapshot().outbox.len() + 1);
        assert_eq!(
            after.basis().body().latest_repository_sequence.unwrap().get(),
            before.basis().body().latest_repository_sequence.unwrap().get() + 1
        );
        let history = node
            .runtime()
            .block_on(node.snapshot_history_in(&node.request_context()))
            .unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.batch.decisions.len(), 1);
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        assert_eq!(last.forge_events.len(), 1);
        assert_eq!(
            last.forge_events[0],
            offered.proposed_event(actor(), format).unwrap()
        );
        let page = node
            .runtime()
            .block_on(node.read_pull_requests_in(
                &node.request_context(),
                &RefVisibility::default(),
                0,
                100,
                None,
            ))
            .unwrap();
        let refreshed = page
            .pull_requests
            .iter()
            .find(|row| row.number == pulls[1].number)
            .unwrap();
        assert_eq!(refreshed.event.version, version(2));
        assert_eq!(refreshed.data.as_ref(), Some(&offered.pull_request.data));
        assert!(matches!(
            prepare(&node, &stale_subject, 4),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        assert!(matches!(
            prepare(&node, &subject(&offered.pull_request, 1), 4),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        let selected = subject(&offered.pull_request, 2);
        let prepared = prepare(&node, &selected, 4).unwrap();
        let MergePreparation::Clean(plan) = &prepared.outcome else {
            panic!("the independent children of an empty tree merge cleanly");
        };
        assert_eq!(plan.style, MergeCommitStyle::TwoParent);
        let candidate = QueueCandidateLandingCommand {
            number: QueueNumber::FIRST,
            expected_version: version(4),
            expected_policy_epoch: PolicyEpoch::FIRST,
            pull_request: selected.pull_request,
            expected_pull_request_version: selected.pull_request_version,
            merge: CandidateBinding {
                merge_base: plan.base,
                commit: plan.commit,
            }
            .merge(&selected),
        };
        let landed = node
            .runtime()
            .block_on(node.land_queue_head_bundle_durable_in(
                &node.request_context(),
                &session("land-second"),
                &candidate,
                prepared.bundle.as_deref().unwrap(),
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(matches!(landed.1.outcome, DecisionOutcome::Committed { .. }));
        let queue = read(&node, 1, None).queue.unwrap();
        assert_eq!(queue.version, version(6));
        assert!(queue.entries.is_empty());
        assert!(queue.active_batch.is_none());
        assert_eq!(
            snapshot(&node).snapshot().refs[&candidate.merge.target_ref],
            candidate.merge.merge_commit
        );
        let final_head = snapshot(&node).basis().id();
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(refresh(&reopened, &offered, "refresh-second").unwrap(), original);
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let mut changed = offered.clone();
        changed.pull_request.data.title.push('!');
        assert!(refresh(&reopened, &changed, "refresh-second").is_err());
        reopened.push_quota.limit.max_events = 0;
        assert_eq!(refresh(&reopened, &offered, "refresh-second").unwrap(), original);
        assert_eq!(snapshot(&reopened).basis().id(), final_head);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn refresh_preserves_exact_queue_pr_policy_source_and_metadata_guards() {
    let scratch = Scratch::new();
    let (node, pulls, advanced) = initialize(&scratch, GitHashAlgorithm::Sha256);
    for (index, pull) in pulls.iter().enumerate() {
        accepted(apply(
            &node,
            &enqueue(1, index as u64, pull, 0),
            &format!("enqueue-{index}"),
        ));
    }
    accepted(land(&node, &landing(&pulls[0], 3), "land-first"));
    let offered = refresh_command(&pulls[1], 5, pulls[0].data.source_tip);
    let mut stale_queue = offered.clone();
    stale_queue.expected_queue_version = version(4);
    let refused = refuse_refresh(
        &node,
        &stale_queue,
        "stale-queue",
        RefusalCode::EvidenceStale,
    );
    let mut changed = offered.clone();
    changed.expected_policy_epoch = PolicyEpoch::FIRST.next().unwrap();
    refuse_refresh(&node, &changed, "stale-policy", RefusalCode::EvidenceStale);
    let mut changed = offered.clone();
    changed.pull_request.expected_version = ExpectedVersion::Exactly(version(2));
    refuse_refresh(&node, &changed, "stale-pr", RefusalCode::EvidenceStale);
    let mut changed = offered.clone();
    changed.expected_recorded_target_tip = advanced;
    refuse_refresh(&node, &changed, "wrong-recorded-target", RefusalCode::EvidenceStale);
    let mut changed = offered.clone();
    changed.pull_request.data.title.push('!');
    refuse_refresh(&node, &changed, "changed-title", RefusalCode::EvidenceStale);
    let mut changed = offered.clone();
    changed.pull_request.data.body.push('!');
    refuse_refresh(&node, &changed, "changed-body", RefusalCode::EvidenceStale);
    let mut changed = offered.clone();
    changed.pull_request.data.source_tip = advanced;
    refuse_refresh(&node, &changed, "changed-source", RefusalCode::EvidenceStale);
    let mut changed = offered.clone();
    changed.pull_request.data.target_tip = advanced;
    refuse_refresh(&node, &changed, "target-moved", RefusalCode::TargetRefMoved);
    refuse_refresh(
        &node,
        &refresh_command(&pulls[2], 5, pulls[0].data.source_tip),
        "skip-head",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    let queue = read(&node, 1, None).queue;
    accepted(refresh(&node, &offered, "valid-refresh"));
    assert_eq!(read(&node, 1, None).queue, queue);
    let settled = snapshot(&node).basis().id();
    assert_eq!(refresh(&node, &stale_queue, "stale-queue").unwrap(), refused);
    assert_eq!(snapshot(&node).basis().id(), settled);
    node.shutdown().unwrap();
}

#[test]
fn cancelled_anonymous_and_dequeued_refreshes_cannot_update_the_pr() {
    let scratch = Scratch::new();
    let (node, pulls, advanced) = initialize(&scratch, GitHashAlgorithm::Sha1);
    accepted(apply(&node, &enqueue(1, 0, &pulls[0], 0), "first"));
    accepted(apply(&node, &enqueue(1, 1, &pulls[1], 0), "second"));
    let moved = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &node.request_context(),
            &session("advance-target"),
            &[RefCommand {
                name: pulls[0].data.target_ref.clone(),
                expected_old: ExpectedOld::Exactly(pulls[0].data.target_tip),
                proposed_new: ProposedNew::Update(advanced),
                force: false,
            }],
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(moved.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
    let offered = refresh_command(&pulls[0], 2, advanced);
    let before = snapshot(&node);
    let cancelled = node.request_context();
    cancelled.authority().cancel();
    assert!(
        node.runtime()
            .block_on(node.refresh_queue_head_durable_in(
                &cancelled,
                &session("cancelled"),
                &offered,
                AdmissionLimits::default(),
            ))
            .is_err()
    );
    assert!(matches!(
        node.runtime().block_on(node.refresh_queue_head_durable_in(
            &node.request_context(),
            &LoopbackReceiveSession::anonymous(),
            &offered,
            AdmissionLimits::default(),
        )),
        Err(NodeReceiveTransportRefusal::Unauthenticated)
    ));
    let mut noop = offered.clone();
    noop.expected_recorded_target_tip = noop.pull_request.data.target_tip;
    assert!(refresh(&node, &noop, "noop").is_err());
    assert_eq!(snapshot(&node).basis(), before.basis());
    accepted(apply(&node, &dequeue(1, 2, pulls[0].number), "withdraw-head"));
    refuse_refresh(&node, &offered, "captured-before-dequeue", RefusalCode::EvidenceStale);
    let mut current_queue = offered;
    current_queue.expected_queue_version = version(3);
    refuse_refresh(
        &node,
        &current_queue,
        "removed-head",
        RefusalCode::ProtectedRefTransitionDenied,
    );
    let page = node
        .runtime()
        .block_on(node.read_pull_requests_in(
            &node.request_context(),
            &RefVisibility::default(),
            0,
            100,
            None,
        ))
        .unwrap();
    let untouched = page
        .pull_requests
        .iter()
        .find(|row| row.number == pulls[0].number)
        .unwrap();
    assert_eq!(untouched.event.version, AggregateVersion::FIRST);
    assert_eq!(untouched.data.as_ref(), Some(&pulls[0].data));
    node.shutdown().unwrap();
}
